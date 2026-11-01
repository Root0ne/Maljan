/* Telling one agent from another, at a glance.
 *
 * A team is user-defined, so nothing here may assume a known name: an
 * operator's `ahmet` has to be as legible as the built-in `static`. Identity
 * is therefore derived, never looked up — a colour hashed from the key so one
 * agent keeps one colour across reloads and runs, and two initials assigned
 * over the whole cast so `static`, `static_r2` and `strings` cannot all draw
 * the same circle.
 *
 * The palette is the console's own status ramp. Colour here is identity, not
 * meaning: none of these say "good" or "bad", which is what keeps an agent's
 * colour from being read as its verdict — so red, the failure colour, is not
 * in it, and the accent is kept for the room's moderators (the judge, the
 * mediator), who are drawn apart from the team they moderate.
 *
 * Each tone is three values from one token: the token itself for rings and
 * rules, a 15% wash of it for the avatar's fill, and an ink — the token mixed
 * 70/30 with the theme's primary text — for initials and names. Mixing toward
 * the primary text darkens the ink on the light theme and lightens it on the
 * dark one. Measured on its own wash and bare, over each of the four
 * surfaces (deep, surface, elevated, active), the lowest ink is 5.13:1 on the
 * light theme (purple on its wash over the active surface; blue is 5.21:1
 * there) and 5.86:1 on the dark one (the moderator's accent on its wash over
 * the active surface) — AA for small text everywhere.
 */

const PALETTE = [
  "var(--status-blue)",
  "var(--status-green)",
  "var(--status-purple)",
  "var(--status-orange)",
  "var(--text-secondary)",
];

const MODERATOR = "var(--accent-strong)";

export interface AgentTone {
  /** The token, for rings and rules. */
  color: string;
  /** The avatar's fill. */
  wash: string;
  /** Initials and names: AA on the wash and on every surface. */
  ink: string;
  moderator: boolean;
}

/* One object per tone for the life of the page. A bubble is memoised on the
 * tone it is drawn in, and a tone rebuilt on every event would redraw every
 * bubble of a long run each time somebody spoke. */
const TONES = new Map<string, AgentTone>();

function tone(color: string, moderator: boolean): AgentTone {
  const key = `${color}|${moderator}`;
  const held = TONES.get(key);
  if (held) return held;
  const made: AgentTone = {
    color,
    wash: `color-mix(in srgb, ${color} 15%, transparent)`,
    ink: `color-mix(in srgb, ${color} 70%, var(--text-primary))`,
    moderator,
  };
  TONES.set(key, made);
  return made;
}

const UNKNOWN_TONE = tone("var(--text-muted)", false);
export const MODERATOR_TONE = tone(MODERATOR, true);

function hashIndex(key: string, buckets: number): number {
  let hash = 0;
  for (let i = 0; i < key.length; i += 1) {
    hash = (hash * 31 + key.charCodeAt(i)) | 0;
  }
  return Math.abs(hash) % buckets;
}

/**
 * One tone per participant of this run.
 *
 * Each agent starts at the colour its key hashes to, so the same agent keeps
 * its colour from run to run; where two agents of one run would share a
 * colour, the later one in the sorted cast takes the next free one. Past five
 * agents colours repeat, and the initials — unique within the run — still
 * tell them apart. `moderators` are the keys drawn in the moderator's tone.
 */
export function agentTones(
  keys: readonly string[],
  moderators: ReadonlySet<string> = new Set(),
): Record<string, AgentTone> {
  const out: Record<string, AgentTone> = {};
  const used = new Set<number>();
  for (const key of [...new Set(keys)].sort()) {
    const normalized = key.toLowerCase().trim();
    if (!normalized) {
      out[key] = UNKNOWN_TONE;
      continue;
    }
    if (moderators.has(key)) {
      out[key] = MODERATOR_TONE;
      continue;
    }
    let index = hashIndex(normalized, PALETTE.length);
    if (used.size < PALETTE.length) {
      while (used.has(index)) index = (index + 1) % PALETTE.length;
    }
    used.add(index);
    out[key] = tone(PALETTE[index], false);
  }
  return out;
}

/** The tone of a key no cast lists. */
export function toneOf(tones: Record<string, AgentTone>, key: string): AgentTone {
  return tones[key] ?? UNKNOWN_TONE;
}

/**
 * Two letters per participant, unique within this run.
 *
 * The first choice is the first two characters of the name a reader sees. A
 * name that would collide takes its first letter plus the first later
 * character nothing has claimed, preferring the one just after a separator,
 * which is where a variant's name usually differs (`static_r2` gives "Sr").
 * Assigned over the sorted cast, so one team always produces the same
 * initials whatever order its members spoke in.
 */
export function agentInitials(names: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  const taken = new Set<string>();
  for (const key of Object.keys(names).sort()) {
    const label = (names[key] || key).trim();
    if (!label) {
      out[key] = "?";
      continue;
    }
    const head = label.charAt(0).toUpperCase();
    const rest = label.slice(1);
    const candidates = [(label.slice(0, 2).charAt(0).toUpperCase() + label.charAt(1)).slice(0, 2)];
    for (let i = 0; i < rest.length; i += 1) {
      // A letter or digit after a separator: "(scanner)" offers its "s", never its "(".
      if (/[^a-z0-9]/i.test(rest[i]) && /[a-z0-9]/i.test(rest[i + 1] ?? "")) {
        candidates.push(head + rest[i + 1]);
      }
    }
    for (const ch of rest) if (/[a-z0-9]/i.test(ch)) candidates.push(head + ch);
    for (let n = 2; n <= 9; n += 1) candidates.push(head + String(n));
    out[key] = candidates.find((c) => c.length === 2 && !taken.has(c)) ?? head;
    taken.add(out[key]);
  }
  return out;
}
