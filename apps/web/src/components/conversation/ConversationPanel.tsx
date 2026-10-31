"use client";

/* The run as a group conversation.
 *
 * One view for both halves of a run's life. While the pipeline runs it is fed
 * by the socket the run store holds; afterwards the same store replays the
 * recorded feed into the same components, so a run and its replay cannot
 * disagree about who said what. Nothing here fetches the feed: the store is
 * its only reader, and this draws what it holds. (A tool call opened to its
 * full result reads that one record from the evidence ledger.)
 *
 * It reads like a group chat of the agents: each agent an avatar, a name and
 * a role, its consecutive messages grouped under them; the judge and the
 * mediator drawn apart as the room's moderators; an answer quoting the
 * question it answers; tool calls folded into one strip per run of calls
 * (`lib/chatLayout.ts`); stages and rounds as small centred chips.
 *
 * The stream follows the newest message while the reader is at the bottom and
 * stops the moment they scroll up — scrolling a conversation out from under
 * somebody reading it is worse than making them press a button to come back.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ListFilter, Radio } from "lucide-react";

import {
  chatBlocks,
  replyTargets,
  type ChatBlock,
  type SpeakerGroup,
} from "@/lib/chatLayout";
import {
  buildConversation,
  emptyConversationText,
  filterConversation,
  moderatorOf,
  type ConversationItem,
  type FilterKey,
} from "@/lib/conversation";
import type { RunConnection, RunEvent } from "@/lib/runStore";
import { useToolCounts } from "@/lib/useToolCounts";
import type { JobRoster } from "@/types";
import { agentInitials, agentTones, toneOf, type AgentTone } from "./agentIdentity";
import Avatar from "./Avatar";
import FailureRow from "./FailureRow";
import MessageBubble, { lineAnchor, type ReplyRef } from "./MessageBubble";
import NoticeRow from "./NoticeRow";
import ParticipantsBar from "./ParticipantsBar";
import StageHeader from "./StageHeader";
import ToolStrip from "./ToolStrip";

const FILTERS: { key: FilterKey; label: string }[] = [
  { key: "says", label: "Messages" },
  { key: "tools", label: "Tool calls" },
  { key: "notices", label: "Notices" },
  { key: "failures", label: "Failures" },
];

const CONNECTION_LABEL: Record<RunConnection, string> = {
  idle: "Connecting",
  connecting: "Connecting",
  open: "Live",
  reconnecting: "Reconnecting",
  closed: "Feed closed",
  unauthorized: "Sign in again to follow this run",
  refused: "The server refused to stream this run",
};

/** How far from the bottom still counts as following the conversation. */
const TAIL_SLACK_PX = 64;

/** The page's one scroller, which the conversation scrolls with. */
function scroller(): HTMLElement | null {
  return typeof document === "undefined" ? null : document.getElementById("main-content");
}

/** Whether the reader asked for less motion. */
function reducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
}

/** The key a line's speaker is drawn under: the agent, or the moderator by
 *  the name it introduced itself with. */
function speakerKeyOf(item: ConversationItem): string {
  const moderator = moderatorOf(item);
  return moderator ? `moderator:${moderator.name}` : item.speaker;
}

/** "A is writing…", "A and B are writing…", "A, B and 2 others are writing…". */
export function writingLine(names: readonly string[]): string {
  if (names.length === 0) return "";
  if (names.length === 1) return `${names[0]} is writing…`;
  if (names.length === 2) return `${names[0]} and ${names[1]} are writing…`;
  const rest = names.length - 2;
  return `${names[0]}, ${names[1]} and ${rest} ${rest === 1 ? "other" : "others"} are writing…`;
}

export default function ConversationPanel({
  jobId,
  events,
  lastSeq,
  roster,
  connection,
  feedError,
  live,
  jobStatus,
}: {
  jobId: string;
  events: RunEvent[];
  /** The number of the newest event held, which is half of "something new". */
  lastSeq: number;
  roster: JobRoster | null;
  connection: RunConnection;
  feedError: string | null;
  live: boolean;
  /** The job's own status, which is what says whether a silent feed is a
   *  finished one. */
  jobStatus: string | null;
}) {
  const [agents, setAgents] = useState<ReadonlySet<string>>(new Set<string>());
  const [groups, setGroups] = useState<ReadonlySet<FilterKey>>(new Set<FilterKey>());
  const [pinned, setPinned] = useState(true);
  /* The tail as it stood when the reader scrolled away, which is what tells
   * "there is more since you left" from "you are reading further up". */
  const [awayAt, setAwayAt] = useState<string | null>(null);
  const [pendingJump, setPendingJump] = useState<string | null>(null);
  const streamRef = useRef<HTMLDivElement | null>(null);
  const tailRef = useRef("");
  const pinnedRef = useRef(true);

  const conversation = useMemo(() => buildConversation(events, roster), [events, roster]);
  const stages = useMemo(
    () => filterConversation(conversation.stages, { agents, groups }),
    [conversation.stages, agents, groups],
  );

  /* Who is in the room, and how each of them is drawn: the team, and the
   * moderators — a speaker that gave a verdict or asked the judge's question,
   * an agent the roster calls the judge, and the room's own mediator. */
  const cast = useMemo(() => {
    const names: Record<string, string> = {};
    const moderators = new Set<string>();
    const roles: Record<string, string> = {};
    for (const p of conversation.participants) {
      names[p.key] = p.name;
      if (p.role) roles[p.key] = p.role;
      if (p.role === "judge") moderators.add(p.key);
    }
    const writing: string[] = [];
    const working = new Set(conversation.participants.filter((p) => p.state === "working").map((p) => p.key));
    for (const stage of conversation.stages) {
      for (const round of stage.rounds) {
        for (const item of round.items) {
          const moderator = moderatorOf(item);
          if (moderator) {
            const key = `moderator:${moderator.name}`;
            names[key] = moderator.name;
            moderators.add(key);
            roles[key] ??= "moderator";
          } else if (item.speaker && (item.kind === "verdict" || item.kind === "judge_question")) {
            moderators.add(item.speaker);
            names[item.speaker] ??= item.displayName;
          }
          /* A speaker the roster does not list still gets a face: the
           * pipeline's own calls, an agent recorded before rosters. */
          if (item.speaker && !(item.speaker in names)) names[item.speaker] = item.displayName;
          if (item.speaker && !roles[item.speaker] && item.role) roles[item.speaker] = item.role;
          /* Writing is a turn still arriving from an agent still at work: a
           * streamed turn whose closing line never came is not somebody
           * typing. */
          if (item.streaming && item.speaker && working.has(item.speaker) && !writing.includes(item.speaker)) {
            writing.push(item.speaker);
          }
        }
      }
    }
    return {
      names,
      roles,
      writing,
      tones: agentTones(Object.keys(names), moderators),
      initials: agentInitials(names),
    };
  }, [conversation]);

  const replies = useMemo(() => {
    const out = new Map<string, ReplyRef>();
    for (const [answer, question] of replyTargets(conversation.stages)) {
      const moderator = moderatorOf(question);
      out.set(answer, {
        item: question,
        author: moderator?.name ?? question.displayName,
        text: moderator?.text ?? question.text,
        tone: toneOf(cast.tones, speakerKeyOf(question)),
      });
    }
    return out;
  }, [conversation.stages, cast.tones]);

  const laidOut = useMemo(
    () =>
      stages.map((stage) => ({
        stage,
        rounds: stage.rounds.map((round) => ({ round: round.round, blocks: chatBlocks(round.items) })),
      })),
    [stages],
  );

  const { counts, partial, unavailable } = useToolCounts(jobId, events, jobStatus);

  const count = (list: typeof stages) =>
    list.reduce(
      (running, stage) => running + stage.rounds.reduce((n, round) => n + round.items.length, 0),
      0,
    );
  const shown = count(stages);
  const total = count(conversation.stages);
  const filtered = agents.size > 0 || groups.size > 0;
  /* A reader who asked for the tool calls or the failures is shown them, not
   * a closed strip standing for them. */
  const toolsOpen = groups.has("tools") || groups.has("failures");

  /* What "there is more to see" means.
   *
   * The number of the last event and the number of characters the
   * conversation holds: a streamed turn appends into a bubble that is already
   * on screen, so it moves the second and not the first, and a follow that
   * watched the line count alone stopped following exactly during the turns
   * the delta channel exists for. */
  const tail = `${lastSeq}:${conversation.textLength}`;
  useEffect(() => {
    tailRef.current = tail;
  }, [tail]);

  /* Follow the tail only while the run is talking. A finished run is opened to
   * be read from the start, and a replay that lands on its own last line hides
   * the argument that produced it. The conversation scrolls with the page,
   * never in a box of its own: a nested scroller trapped the wheel at its ends
   * and gave the page two scrollbars. */
  useEffect(() => {
    if (!live || !pinned) return;
    const page = scroller();
    if (page && streamRef.current) page.scrollTop = page.scrollHeight;
  }, [tail, pinned, live]);

  useEffect(() => {
    const page = scroller();
    if (!page) return;
    const onScroll = () => {
      const stream = streamRef.current;
      if (!stream) return;
      const end = stream.getBoundingClientRect().bottom;
      const atEnd = end - page.getBoundingClientRect().bottom <= TAIL_SLACK_PX;
      if (pinnedRef.current && !atEnd) setAwayAt(tailRef.current);
      pinnedRef.current = atEnd;
      setPinned(atEnd);
    };
    page.addEventListener("scroll", onScroll, { passive: true });
    return () => page.removeEventListener("scroll", onScroll);
  }, []);

  function jumpToLatest() {
    const page = scroller();
    if (!page) return;
    page.scrollTo({ top: page.scrollHeight, behavior: reducedMotion() ? "auto" : "smooth" });
    pinnedRef.current = true;
    setPinned(true);
  }

  /* Take the reader to a line a reply quotes. A filter can have hidden it, and
   * then the filters are cleared first: the reader asked for that line. */
  const reveal = useCallback((id: string): boolean => {
    const target = document.getElementById(lineAnchor(id));
    if (!target) return false;
    target.scrollIntoView({ block: "center", behavior: reducedMotion() ? "auto" : "smooth" });
    target.focus({ preventScroll: true });
    return true;
  }, []);

  const jumpTo = useCallback(
    (id: string) => {
      if (reveal(id)) return;
      setAgents(new Set<string>());
      setGroups(new Set<FilterKey>());
      setPendingJump(id);
    },
    [reveal],
  );

  useEffect(() => {
    if (!pendingJump) return;
    reveal(pendingJump);
    // eslint-disable-next-line react-hooks/set-state-in-effect -- one-shot: the jump has been made
    setPendingJump(null);
  }, [pendingJump, laidOut, reveal]);

  function toggle<T>(set: ReadonlySet<T>, value: T): Set<T> {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    return next;
  }

  const writers = cast.writing.map((key) => cast.names[key] ?? key);
  const working = conversation.participants.filter((p) => p.state === "working");
  const hasNew = !pinned && awayAt !== null && awayAt !== tail;

  return (
    <section className="flex flex-col gap-3">
      <ParticipantsBar
        participants={conversation.participants}
        toolCounts={counts}
        countsArePartial={partial}
        countsUnavailable={unavailable}
        selected={agents}
        onToggle={(key) => setAgents((current) => toggle(current, key))}
        tones={cast.tones}
        initials={cast.initials}
      />

      <div className="flex flex-wrap items-center gap-2">
        <ListFilter size={13} aria-hidden="true" className="text-text-muted" />
        {FILTERS.map((filter) => {
          const active = groups.size === 0 || groups.has(filter.key);
          /* "Failures" narrows rather than adds a group of its own, so with no
           * filter set it reads as off rather than on. */
          const pressed = filter.key === "failures" ? groups.has("failures") : active;
          return (
            <button
              key={filter.key}
              type="button"
              aria-pressed={pressed}
              onClick={() => setGroups((current) => toggle(current, filter.key))}
              className={`rounded-full border px-2.5 py-0.5 text-[11px] focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent ${
                pressed
                  ? filter.key === "failures"
                    ? "border-status-red/60 bg-status-red/10 text-status-red"
                    : "border-accent text-accent-strong"
                  : "border-border text-text-secondary"
              }`}
            >
              {filter.label}
            </button>
          );
        })}
        {filtered && (
          <>
            <button
              type="button"
              onClick={() => {
                setAgents(new Set<string>());
                setGroups(new Set<FilterKey>());
              }}
              className="text-[11px] text-accent-strong hover:underline"
            >
              Clear filters
            </button>
            {/* What the filter did, in one short sentence, rather than the
                whole stream read out again. */}
            <span role="status" className="text-[11px] text-text-secondary">
              {shown} of {total} shown
            </span>
          </>
        )}
        <span className="ml-auto flex items-center gap-1.5 text-[11px] text-text-secondary">
          <Radio
            size={12}
            aria-hidden="true"
            className={connection === "open" ? "text-status-green" : "text-text-disabled"}
          />
          {live ? CONNECTION_LABEL[connection] : "Replay"}
        </span>
      </div>

      {feedError && (
        <p
          role="alert"
          className="rounded border border-status-orange/20 bg-status-orange/10 px-2 py-1.5 text-xs text-status-orange"
        >
          {feedError}
        </p>
      )}

      <div className="relative">
        <div
          ref={streamRef}
          data-testid="conversation-stream"
          /* A log: lines in the order they were said. While the run talks a
           * screen reader is told about the lines that arrive; on a finished
           * run nothing arrives, and leaving it live meant every filter change
           * queued the whole transcript for re-announcement. */
          role="log"
          aria-live={live ? "polite" : "off"}
          aria-relevant={live ? "additions text" : undefined}
          aria-label="Conversation"
          className="min-h-80 space-y-1 pb-2"
        >
          {shown === 0 ? (
            <p className="p-6 text-center text-xs text-text-muted">
              {emptyConversationText({ live, eventCount: events.length, feedError })}
            </p>
          ) : (
            /* Keyed by what the section is, never by where it sits: a filter
               chip drops whole sections, and a closing line that changed
               identity would be redrawn from nothing every time one did. */
            laidOut.map(({ stage, rounds }) => (
              <section key={stage.id} aria-label={stage.key ? stage.label || stage.key : undefined} className="space-y-1">
                {stage.key && (
                  <StageHeader
                    label={stage.label || stage.key}
                    kind={stage.kind}
                    state={stage.state}
                    reason={stage.reason}
                    durationMs={stage.durationMs}
                  />
                )}
                {rounds.map((round, index) => (
                  <div key={`${stage.key}-${round.round}-${index}`} className="space-y-1">
                    {rounds.length > 1 && (
                      <p className="flex justify-center pt-2">
                        <span className="rounded-full bg-bg-active px-2.5 py-0.5 text-[11px] text-text-secondary">
                          {round.round === 0 ? "Opening" : `Round ${round.round}`}
                        </span>
                      </p>
                    )}
                    {round.blocks.map((block) => (
                      <Block
                        key={block.id}
                        block={block}
                        jobId={jobId}
                        cast={cast}
                        replies={replies}
                        toolsOpen={toolsOpen}
                        onJump={jumpTo}
                      />
                    ))}
                  </div>
                ))}
              </section>
            ))
          )}

          {live && shown > 0 && (writers.length > 0 || working.length > 0) && (
            <div className="flex items-center gap-2 pl-1 pt-3 text-[11px] text-text-secondary">
              <span className="flex -space-x-1.5">
                {(writers.length > 0 ? cast.writing : working.map((p) => p.key)).slice(0, 3).map((key) => (
                  <Avatar
                    key={key}
                    initials={cast.initials[key] ?? "?"}
                    tone={toneOf(cast.tones, key)}
                    size="sm"
                  />
                ))}
              </span>
              <span>{writers.length > 0 ? writingLine(writers) : `${working.map((p) => p.name).join(", ")} working`}</span>
              <span aria-hidden="true" className="flex gap-0.5">
                {[0, 1, 2].map((dot) => (
                  <span
                    key={dot}
                    className="h-1 w-1 rounded-full bg-text-muted motion-safe:animate-pulse"
                    style={{ animationDelay: `${dot * 200}ms` }}
                  />
                ))}
              </span>
            </div>
          )}
        </div>

        {/* Held at the bottom of the window while a live run talks below it. */}
        {live && !pinned && shown > 0 && (
          <div className="pointer-events-none sticky bottom-4 flex justify-center">
            <button
              type="button"
              onClick={jumpToLatest}
              className={`pointer-events-auto flex items-center gap-1.5 rounded-full border px-3 py-1 text-[11px] shadow-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent ${
                hasNew ? "border-accent bg-accent-fill text-white" : "border-border bg-bg-elevated text-text-primary"
              }`}
            >
              <ArrowDown size={12} aria-hidden="true" />
              {hasNew ? "New messages" : "Jump to latest"}
            </button>
          </div>
        )}
      </div>
    </section>
  );
}

interface Cast {
  names: Record<string, string>;
  roles: Record<string, string>;
  tones: Record<string, AgentTone>;
  initials: Record<string, string>;
}

function Block({
  block,
  jobId,
  cast,
  replies,
  toolsOpen,
  onJump,
}: {
  block: ChatBlock;
  jobId: string;
  cast: Cast;
  replies: Map<string, ReplyRef>;
  toolsOpen: boolean;
  onJump: (id: string) => void;
}) {
  if (block.type === "room") {
    return (
      <div className="py-1">
        {block.item.kind === "run_failed" ? <FailureRow item={block.item} /> : <NoticeRow item={block.item} />}
      </div>
    );
  }
  return (
    <SpeakerBlock
      group={block}
      jobId={jobId}
      cast={cast}
      replies={replies}
      toolsOpen={toolsOpen}
      onJump={onJump}
    />
  );
}

/** One speaker's consecutive lines and calls, under one avatar and name. */
function SpeakerBlock({
  group,
  jobId,
  cast,
  replies,
  toolsOpen,
  onJump,
}: {
  group: SpeakerGroup;
  jobId: string;
  cast: Cast;
  replies: Map<string, ReplyRef>;
  toolsOpen: boolean;
  onJump: (id: string) => void;
}) {
  const tone = toneOf(cast.tones, group.speaker);
  const name = group.displayName || cast.names[group.speaker] || "Unknown";
  const role = cast.roles[group.speaker];
  const firstMessage = group.entries.find((e) => e.type === "message");
  const addressee = firstMessage?.type === "message" ? firstMessage.item.addressedToName : undefined;
  const isQuestion = firstMessage?.type === "message" && firstMessage.item.kind === "judge_question";

  return (
    <div className="flex gap-2.5 pt-2.5">
      <Avatar initials={cast.initials[group.speaker] ?? "?"} tone={tone} />
      <div className="min-w-0 flex-1 space-y-1">
        <p className="flex flex-wrap items-baseline gap-x-2 text-xs">
          <span className="font-semibold" style={{ color: tone.ink }}>
            {name}
          </span>
          {role && <span className="text-[11px] text-text-secondary">{role}</span>}
          {/* A question names its addressee in its own bubble. */}
          {addressee && !isQuestion && (
            <span className="text-[11px] text-text-secondary">
              <span aria-hidden="true">→ </span>
              <span className="sr-only">to </span>
              {addressee}
            </span>
          )}
        </p>
        {group.entries.map((entry, index) =>
          entry.type === "message" ? (
            <MessageBubble
              key={entry.item.id}
              item={entry.item}
              speakerName={name}
              text={moderatorOf(entry.item)?.text ?? entry.item.text}
              tone={tone}
              first={index === 0}
              replyTo={replies.get(entry.item.id)}
              onJump={onJump}
            />
          ) : (
            <ToolStrip key={entry.id} calls={entry.calls} jobId={jobId} tone={tone} defaultOpen={toolsOpen} />
          ),
        )}
      </div>
    </div>
  );
}
