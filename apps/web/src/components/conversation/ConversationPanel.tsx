"use client";

/* The run as a group conversation.
 *
 * One view for both halves of a run's life. While the pipeline runs it is fed
 * by the socket the run store holds; afterwards the same store replays the
 * recorded feed into the same components, so a run and its replay cannot
 * disagree about who said what. Nothing here fetches: the store is the only
 * reader of the network, and this draws what it holds.
 *
 * The stream follows the newest message while the reader is at the bottom and
 * stops the moment they scroll up — scrolling a conversation out from under
 * somebody reading it is worse than making them press a button to come back.
 */

import { memo, useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ListFilter, Radio } from "lucide-react";

import {
  buildConversation,
  filterConversation,
  groupOf,
  type ConversationItem,
  type ItemGroup,
} from "@/lib/conversation";
import type { RunConnection, RunEvent } from "@/lib/runStore";
import { useToolCounts } from "@/lib/useToolCounts";
import type { JobRoster } from "@/types";
import { agentInitials } from "./agentIdentity";
import MessageBubble from "./MessageBubble";
import NoticeRow from "./NoticeRow";
import ParticipantsBar from "./ParticipantsBar";
import StageHeader from "./StageHeader";
import ToolCallRow from "./ToolCallRow";

const GROUPS: { key: ItemGroup; label: string }[] = [
  { key: "says", label: "Messages" },
  { key: "tools", label: "Tool calls" },
  { key: "notices", label: "Notices" },
];

const CONNECTION_LABEL: Record<RunConnection, string> = {
  idle: "Connecting",
  connecting: "Connecting",
  open: "Live",
  reconnecting: "Reconnecting",
  closed: "Feed closed",
  unauthorized: "Sign in again to follow this run",
};

/** How far from the bottom still counts as following the conversation. */
const TAIL_SLACK_PX = 64;

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
  const [groups, setGroups] = useState<ReadonlySet<ItemGroup>>(new Set<ItemGroup>());
  const [pinned, setPinned] = useState(true);
  const streamRef = useRef<HTMLDivElement | null>(null);

  const conversation = useMemo(() => buildConversation(events, roster), [events, roster]);
  const stages = useMemo(
    () => filterConversation(conversation.stages, { agents, groups }),
    [conversation.stages, agents, groups],
  );
  const initials = useMemo(
    () => agentInitials(Object.fromEntries(conversation.participants.map((p) => [p.key, p.name]))),
    [conversation.participants],
  );

  const { counts, partial } = useToolCounts(jobId, events, jobStatus);

  const shown = stages.reduce(
    (total, stage) => total + stage.rounds.reduce((n, round) => n + round.items.length, 0),
    0,
  );

  /* What "there is more to see" means.
   *
   * The number of the last event and the number of characters the
   * conversation holds: a streamed turn appends into a bubble that is already
   * on screen, so it moves the second and not the first, and a follow that
   * watched the line count alone stopped following exactly during the turns
   * the delta channel exists for. */
  const tail = `${lastSeq}:${conversation.textLength}`;

  /* Follow the tail only while the run is talking. A finished run is opened to
   * be read from the start, and a replay that lands on its own last line hides
   * the argument that produced it. */
  useEffect(() => {
    if (!live || !pinned) return;
    const stream = streamRef.current;
    if (stream) stream.scrollTop = stream.scrollHeight;
  }, [tail, pinned, live]);

  function onScroll() {
    const stream = streamRef.current;
    if (!stream) return;
    const atTail =
      stream.scrollHeight - stream.scrollTop - stream.clientHeight <= TAIL_SLACK_PX;
    setPinned(atTail);
  }

  function jumpToLatest() {
    const stream = streamRef.current;
    if (!stream) return;
    stream.scrollTop = stream.scrollHeight;
    setPinned(true);
  }

  function toggle<T>(set: ReadonlySet<T>, value: T): Set<T> {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    return next;
  }

  const speaking = conversation.participants.filter((p) => p.state === "working");

  return (
    <section className="flex flex-col gap-3">
      <ParticipantsBar
        participants={conversation.participants}
        toolCounts={counts}
        countsArePartial={partial}
        selected={agents}
        onToggle={(key) => setAgents((current) => toggle(current, key))}
      />

      <div className="flex flex-wrap items-center gap-2">
        <ListFilter size={13} aria-hidden="true" className="text-text-muted" />
        {GROUPS.map((group) => {
          const active = groups.size === 0 || groups.has(group.key);
          return (
            <button
              key={group.key}
              type="button"
              aria-pressed={active}
              onClick={() => setGroups((current) => toggle(current, group.key))}
              className={`rounded border px-2 py-0.5 text-[11px] ${
                active
                  ? "border-accent text-accent"
                  : "border-border text-text-muted"
              }`}
            >
              {group.label}
            </button>
          );
        })}
        {(agents.size > 0 || groups.size > 0) && (
          <button
            type="button"
            onClick={() => {
              setAgents(new Set<string>());
              setGroups(new Set<ItemGroup>());
            }}
            className="text-[11px] text-accent-strong hover:underline"
          >
            Clear filters
          </button>
        )}
        <span className="ml-auto flex items-center gap-1.5 text-[11px] text-text-muted">
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
          onScroll={onScroll}
          data-testid="conversation-stream"
          /* A log rather than a region: a screen reader following a live run
           * is told about the lines that arrive, and nothing else. */
          role="log"
          aria-live="polite"
          aria-relevant="additions text"
          aria-label="Conversation"
          /* A scrollable region has to be reachable by keyboard, or the only
           * way through a long run is a pointer. */
          tabIndex={0}
          className="h-[62vh] min-h-80 space-y-3 overflow-y-auto rounded border border-border bg-bg-deep p-3"
        >
          {shown === 0 ? (
            <p className="p-6 text-center text-xs text-text-muted">
              {live
                ? "Waiting for the first agent to speak."
                : events.length === 0
                  ? "This run kept no conversation. Its feed has passed the retention window."
                  : "No message matches the current filters."}
            </p>
          ) : (
            stages.map((stage) => (
              <section key={stage.key || "run"} className="space-y-3">
                {stage.key && (
                  <StageHeader
                    label={stage.label || stage.key}
                    kind={stage.kind}
                    state={stage.state}
                    reason={stage.reason}
                    durationMs={stage.durationMs}
                  />
                )}
                {stage.rounds.map((round, index) => (
                  <div key={`${stage.key}-${round.round}-${index}`} className="space-y-2">
                    {stage.rounds.length > 1 && (
                      <p className="text-center text-[11px] uppercase tracking-wider text-text-tertiary">
                        {round.round === 0 ? "Opening" : `Round ${round.round}`}
                      </p>
                    )}
                    {/* The exchange is a list, so it can be navigated as one. */}
                    <ul className="space-y-2">
                      {round.items.map((item, position) => (
                        <li key={item.id}>
                          <Item
                            item={item}
                            jobId={jobId}
                            initials={initials[item.speaker] ?? "?"}
                            first={isFirstOfSpeaker(round.items, position)}
                          />
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </section>
            ))
          )}

          {live && shown > 0 && (
            <div className="sticky bottom-0 flex items-center gap-2 bg-bg-deep pt-2 text-[11px] text-text-muted">
              <span aria-hidden="true" className="h-px flex-1 bg-accent/40" />
              <span className="flex items-center gap-1.5">
                <span
                  aria-hidden="true"
                  className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse"
                />
                {speaking.length > 0
                  ? `${speaking.map((p) => p.name).join(", ")} working`
                  : "Now"}
              </span>
              <span aria-hidden="true" className="h-px flex-1 bg-accent/40" />
            </div>
          )}
        </div>

        {!pinned && shown > 0 && (
          <button
            type="button"
            onClick={jumpToLatest}
            className="absolute bottom-4 right-4 flex items-center gap-1.5 rounded border border-accent bg-bg-elevated px-2.5 py-1 text-[11px] text-accent"
          >
            <ArrowDown size={12} aria-hidden="true" />
            Jump to latest
          </button>
        )}
      </div>
    </section>
  );
}

/**
 * Whether this line opens a speaker's block, and so carries the header.
 *
 * Consecutive lines of one kind from one speaker share a header, the way a
 * group thread groups a burst of messages. Three things break the block: a
 * different speaker, a different addressee — who a line was said to is part of
 * what it is — and a change between speech, machine work and a room note, so a
 * message after a run of tool calls is introduced rather than left floating.
 */
function isFirstOfSpeaker(items: ConversationItem[], position: number): boolean {
  if (position === 0) return true;
  const previous = items[position - 1];
  const item = items[position];
  return (
    previous.speaker !== item.speaker ||
    previous.addressedTo !== item.addressedTo ||
    groupOf(previous.kind) !== groupOf(item.kind)
  );
}

/* One row, drawn once.
 *
 * Memoised on the item, which the conversation builder keeps identical for a
 * line nothing has changed — so a three-thousand-line replay redraws the line
 * that just arrived rather than every line before it. */
const Item = memo(function Item({
  item,
  jobId,
  initials,
  first,
}: {
  item: ConversationItem;
  jobId: string;
  initials: string;
  first: boolean;
}) {
  const group = groupOf(item.kind);
  if (group === "tools") {
    return <ToolCallRow item={item} jobId={jobId} showSpeaker={first} />;
  }
  if (group === "notices") {
    return <NoticeRow item={item} />;
  }
  return <MessageBubble item={item} initials={initials} showHeader={first} />;
});
