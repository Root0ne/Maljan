import { deepEqual } from "./mapEditorHelpers";

/**
 * The model-calling roles that are no agent definition, each configured by an
 * `llm.agents` entry under its own key. Mirrors
 * `maljan.core.config.ROLE_ENTRY_KEYS`, in its order, which
 * `tests/unit/core/test_the_console_lists_every_role_entry.py` checks: the
 * debate stage's mediator and the function summariser. With no entry either
 * runs on the global expert model.
 */
export interface RoleEntry {
  key: string;
  label: string;
  description: string;
}

export const ROLE_ENTRIES: readonly RoleEntry[] = [
  {
    key: "mediator",
    label: "Mediator",
    description:
      "Mediates the debate stage over the analysts' reports. With no entry it runs on the " +
      "global expert model; the judge's entry does not move it.",
  },
  {
    key: "summarizer",
    label: "Function summariser",
    description:
      "Summarises large function lists and decompiled blocks before the analysts read them, " +
      "while Use function summarizer is on. With no entry it runs on the global expert model.",
  },
];

export const ROLE_ENTRY_KEYS: ReadonlySet<string> = new Set(ROLE_ENTRIES.map((role) => role.key));

/** Why an agent may not take `key`, or `null`: a role's key is its model entry. */
export function roleKeyError(key: string): string | null {
  const role = ROLE_ENTRIES.find((entry) => entry.key === key);
  if (!role) return null;
  return `'${key}' is the ${role.label.toLowerCase()}'s model entry; pick another name.`;
}

/** Whether the staged entry for `key` differs from the saved one. */
export function roleEntryChanged(
  key: string,
  staged: Record<string, unknown>,
  saved: Record<string, unknown>
): boolean {
  return !deepEqual(staged[key], saved[key]);
}
