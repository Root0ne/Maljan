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
 * colour from being read as its verdict.
 */

const PALETTE = [
  "var(--status-blue)",
  "var(--status-green)",
  "var(--status-purple)",
  "var(--status-orange)",
  "var(--accent-strong)",
  "var(--text-secondary)",
];

function hashIndex(key: string, buckets: number): number {
  let hash = 0;
  for (let i = 0; i < key.length; i += 1) {
    hash = (hash * 31 + key.charCodeAt(i)) | 0;
  }
  return Math.abs(hash) % buckets;
}

/** The colour that stands for this agent, wherever it appears. */
export function agentColor(key: string): string {
  const normalized = key.toLowerCase().trim();
  if (!normalized) return "var(--text-muted)";
  return PALETTE[hashIndex(normalized, PALETTE.length)];
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
      if (/[^a-z0-9]/i.test(rest[i]) && rest[i + 1]) candidates.push(head + rest[i + 1]);
    }
    for (const ch of rest) if (/[a-z0-9]/i.test(ch)) candidates.push(head + ch);
    for (let n = 2; n <= 9; n += 1) candidates.push(head + String(n));
    out[key] = candidates.find((c) => c.length === 2 && !taken.has(c)) ?? head;
    taken.add(out[key]);
  }
  return out;
}
