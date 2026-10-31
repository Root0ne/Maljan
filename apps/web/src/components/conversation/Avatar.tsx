/* A participant's face in the conversation: two initials on a wash of the
 * participant's colour. Agents are round; the room's moderators (the judge,
 * the mediator) are squared off as well as coloured apart, so the difference
 * survives a reader who cannot tell the colours apart. Decorative: the name
 * beside it, or the label of the line it heads, says who it is. */

import type { AgentTone } from "./agentIdentity";

const SIZE = {
  sm: "h-6 w-6 text-[10px]",
  md: "h-8 w-8 text-[11px]",
};

export default function Avatar({
  initials,
  tone,
  size = "md",
}: {
  initials: string;
  tone: AgentTone;
  size?: keyof typeof SIZE;
}) {
  return (
    <span
      aria-hidden="true"
      className={`flex shrink-0 items-center justify-center border font-semibold ${SIZE[size]} ${
        tone.moderator ? "rounded-md" : "rounded-full"
      }`}
      style={{ backgroundColor: tone.wash, borderColor: tone.color, color: tone.ink }}
    >
      {initials}
    </span>
  );
}
