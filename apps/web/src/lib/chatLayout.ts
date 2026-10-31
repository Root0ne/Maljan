/* The conversation laid out as a group chat.
 *
 * `buildConversation` decides what each line is; this decides how lines sit
 * together on screen. Two rules carry the layout, and both are pure so they
 * can be tested without a browser:
 *
 * - A speaker's consecutive lines share one avatar and one name, and a run of
 *   tool calls is folded into a single strip under that speaker instead of a
 *   row per call. Parallel agents interleave their calls in the feed, so a
 *   strip stays open across another agent's calls and closes only when
 *   somebody says something: the strip never moves a call past a message.
 * - A line that answers a question points back at it. A directed line (the
 *   judge's question, a delegated ask, a moderator addressing one agent) is
 *   answered by the addressee's next line in the stage; a moderator line to
 *   the whole room is answered by each participant's next line, until the
 *   moderator speaks again.
 */

import {
  isFailure,
  itemGroup,
  moderatorOf,
  type ConversationItem,
  type ConversationStage,
} from "@/lib/conversation";

/** One thing drawn inside a speaker's group. */
export type ChatEntry =
  | { type: "message"; item: ConversationItem }
  | { type: "tools"; id: string; calls: ConversationItem[] };

/** Consecutive entries from one speaker, under one avatar. */
export interface SpeakerGroup {
  type: "speaker";
  id: string;
  /** The agent key, or `moderator:<name>` for the room's moderator. */
  speaker: string;
  displayName: string;
  moderator: boolean;
  entries: ChatEntry[];
}

/** A line the room said: a correction, a notice, the failure that ended the
 *  run. Drawn centred, never under an avatar. */
export interface RoomLine {
  type: "room";
  id: string;
  item: ConversationItem;
}

export type ChatBlock = SpeakerGroup | RoomLine;

/** Whose group a spoken line belongs to. */
function speakerKey(item: ConversationItem): { key: string; name: string; moderator: boolean } {
  const moderator = moderatorOf(item);
  if (moderator) return { key: `moderator:${moderator.name}`, name: moderator.name, moderator: true };
  return { key: item.speaker, name: item.displayName, moderator: false };
}

/** The lines of one round, as the chat draws them. */
export function chatBlocks(items: readonly ConversationItem[]): ChatBlock[] {
  const blocks: ChatBlock[] = [];
  /* The strip each speaker is still adding calls to. */
  const open = new Map<string, { type: "tools"; id: string; calls: ConversationItem[] }>();

  const groupFor = (key: string, name: string, moderator: boolean, id: string): SpeakerGroup => {
    const last = blocks[blocks.length - 1];
    if (last && last.type === "speaker" && last.speaker === key) return last;
    const created: SpeakerGroup = { type: "speaker", id, speaker: key, displayName: name, moderator, entries: [] };
    blocks.push(created);
    return created;
  };

  for (const item of items) {
    const group = itemGroup(item);
    if (group === "tools") {
      const strip = open.get(item.speaker);
      if (strip) {
        strip.calls.push(item);
        continue;
      }
      const created = { type: "tools" as const, id: `tools:${item.id}`, calls: [item] };
      open.set(item.speaker, created);
      groupFor(item.speaker, item.displayName, false, item.id).entries.push(created);
      continue;
    }
    open.clear();
    if (group === "notices") {
      blocks.push({ type: "room", id: item.id, item });
      continue;
    }
    const who = speakerKey(item);
    const last = blocks[blocks.length - 1];
    /* Who a line is said to is part of what it is: a change of addressee
     * opens a new group, so the arrow in its header stays true. */
    const lastMessage =
      last && last.type === "speaker"
        ? [...last.entries].reverse().find((e) => e.type === "message")
        : undefined;
    const readdressed =
      lastMessage?.type === "message" && lastMessage.item.addressedTo !== item.addressedTo;
    if (readdressed) {
      const created: SpeakerGroup = {
        type: "speaker",
        id: item.id,
        speaker: who.key,
        displayName: who.name,
        moderator: who.moderator,
        entries: [],
      };
      blocks.push(created);
      created.entries.push({ type: "message", item });
      continue;
    }
    groupFor(who.key, who.name, who.moderator, item.id).entries.push({ type: "message", item });
  }
  return blocks;
}

/** What one strip of calls adds up to. */
export interface StripSummary {
  calls: number;
  failed: number;
  running: number;
  durationMs: number;
}

export function stripSummary(calls: readonly ConversationItem[]): StripSummary {
  let failed = 0;
  let running = 0;
  let durationMs = 0;
  for (const call of calls) {
    if (call.tool?.ok === null) running += 1;
    else if (isFailure(call)) failed += 1;
    durationMs += call.tool?.durationMs ?? 0;
  }
  return { calls: calls.length, failed, running, durationMs };
}

/** A strip's duration, in the units its calls are read in. */
export function stripDuration(ms: number): string {
  if (ms <= 0) return "";
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${Math.round(ms / 1000)} s`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.round((ms % 60_000) / 1000);
  return seconds ? `${minutes} min ${seconds} s` : `${minutes} min`;
}

/** The strip's one line: how many calls, how long, and what went wrong. */
export function stripLabel(summary: StripSummary): string {
  const parts = [`${summary.calls} ${summary.calls === 1 ? "tool" : "tools"}`];
  const took = stripDuration(summary.durationMs);
  if (took) parts.push(took);
  if (summary.failed) parts.push(`${summary.failed} failed`);
  if (summary.running) parts.push(`${summary.running} running`);
  return parts.join(" · ");
}

/** Whether a line asks something of somebody, and of whom. */
function asks(item: ConversationItem): { to: string } | { room: true } | null {
  if (item.kind === "judge_question" || item.kind === "delegation_ask") {
    return item.addressedTo ? { to: item.addressedTo } : null;
  }
  if (moderatorOf(item)) return item.addressedTo ? { to: item.addressedTo } : { room: true };
  return null;
}

/**
 * The question each answering line replies to, by the answer's id.
 *
 * Read over the whole conversation rather than what a filter left, so an
 * answer keeps its reference while its question is filtered out.
 */
export function replyTargets(
  stages: readonly ConversationStage[],
): Map<string, ConversationItem> {
  const replies = new Map<string, ConversationItem>();
  for (const stage of stages) {
    const directed = new Map<string, ConversationItem>();
    let roomQuestion: ConversationItem | null = null;
    const answeredRoom = new Set<string>();
    for (const round of stage.rounds) {
      for (const item of round.items) {
        const question = asks(item);
        if (item.speaker && !question && itemGroup(item) === "says") {
          const target = directed.get(item.speaker);
          if (target) {
            replies.set(item.id, target);
            directed.delete(item.speaker);
          } else if (roomQuestion && !answeredRoom.has(item.speaker)) {
            replies.set(item.id, roomQuestion);
            answeredRoom.add(item.speaker);
          }
        }
        if (question && "to" in question) directed.set(question.to, item);
        if (question && "room" in question) {
          roomQuestion = item;
          answeredRoom.clear();
        }
      }
    }
  }
  return replies;
}
