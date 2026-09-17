"use client";

/* Who is in the room.
 *
 * Every participant the team declares, named by the label an operator gave it
 * — a reader who cannot open the admin settings still sees "Ahmet" rather
 * than `ahmet_1`. A specialist no stage names is drawn with the agents that
 * can task it, because "reached through the lead" is the only thing that
 * explains why it is here at all.
 *
 * The strip doubles as the by-agent filter: clicking a participant narrows
 * the conversation to that participant, clicking again widens it back. One
 * control, in the place a reader is already looking.
 */

import { CornerDownRight } from "lucide-react";

import type { Participant, ParticipantState } from "@/lib/conversation";
import { agentColor, agentInitials } from "./agentIdentity";

const STATE_LABEL: Record<ParticipantState, string> = {
  waiting: "Waiting",
  working: "Working",
  done: "Done",
};

const STATE_DOT: Record<ParticipantState, string> = {
  waiting: "bg-text-disabled",
  working: "bg-status-blue animate-pulse",
  done: "bg-status-green",
};

/** What this participant has done, in the fewest words that stay true. */
function work(
  participant: Participant,
  toolCounts: Record<string, number>,
  partial: boolean,
): string {
  const said = participant.messages;
  const tools = toolCounts[participant.key] ?? 0;
  const floor = partial ? "+" : "";
  return `${said} said · ${tools}${floor} tool${tools === 1 && !partial ? "" : "s"}`;
}

export default function ParticipantsBar({
  participants,
  toolCounts,
  countsArePartial,
  selected,
  onToggle,
}: {
  participants: Participant[];
  /** Answered calls per agent, from the one selector that counts them. */
  toolCounts: Record<string, number>;
  countsArePartial: boolean;
  selected: ReadonlySet<string>;
  onToggle: (key: string) => void;
}) {
  if (participants.length === 0) return null;
  const initials = agentInitials(
    Object.fromEntries(participants.map((p) => [p.key, p.name])),
  );

  return (
    <div className="flex flex-wrap gap-1.5">
      {participants.map((participant) => {
        const color = agentColor(participant.key);
        const active = selected.has(participant.key);
        const via = participant.stages.length === 0 ? participant.via : [];
        return (
          <button
            key={participant.key}
            type="button"
            onClick={() => onToggle(participant.key)}
            aria-pressed={active}
            title={
              via.length > 0
                ? `${participant.name} — tasked by ${via.join(", ")}`
                : `${participant.name} — ${STATE_LABEL[participant.state].toLowerCase()}`
            }
            className={`flex items-center gap-2 rounded border px-2 py-1 text-left ${
              active ? "border-accent bg-bg-active" : "border-border bg-bg-surface"
            }`}
          >
            <span
              aria-hidden="true"
              className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-[11px] font-semibold"
              style={{ borderColor: color, color }}
            >
              {initials[participant.key]}
            </span>
            <span className="min-w-0">
              <span className="flex items-center gap-1.5">
                <span className="truncate text-xs text-text-primary">{participant.name}</span>
                <span
                  aria-hidden="true"
                  className={`h-1.5 w-1.5 shrink-0 rounded-full ${STATE_DOT[participant.state]}`}
                />
              </span>
              <span className="flex items-center gap-1 text-[11px] text-text-muted">
                {via.length > 0 && <CornerDownRight size={11} aria-hidden="true" />}
                <span className="truncate">
                  {via.length > 0 ? `via ${via.join(", ")}` : work(participant, toolCounts, countsArePartial)}
                </span>
              </span>
            </span>
          </button>
        );
      })}
    </div>
  );
}
