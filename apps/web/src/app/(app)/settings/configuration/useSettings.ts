"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { SettingsValidationError } from "@/types/settings";
import { deepEqual } from "./deepEqual";
import type {
  CatalogEntry,
  PatchResult,
  ProbeResult,
  SettingValue,
  SettingsSchema,
} from "@/types/settings";

/** key -> staged value; `null` means "clear this secret". */
export type Pending = Record<string, unknown>;

/**
 * Loads the settings schema + current values, tracks in-flight edits, and
 * wraps the seven settings endpoints. Deliberately self-contained: the
 * Configuration tab renders nothing else while this is loading, so every
 * consumer of the hook can assume `schema` is non-null past `loading`.
 */
export function useSettings() {
  const [schema, setSchema] = useState<SettingsSchema | null>(null);
  const [values, setValues] = useState<Record<string, SettingValue>>({});
  const [pending, setPending] = useState<Pending>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [forbidden, setForbidden] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  // Distinct from `loadError`: `loadError` means "the schema/values could not
  // be loaded at all" and tears down the whole tab; `actionError` is a
  // recoverable failure of a single mutating action (reset/resetGroup/a
  // non-validation apply failure) surfaced as a dismissible inline banner
  // while the rest of the tab stays usable.
  const [actionError, setActionError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [lastResult, setLastResult] = useState<PatchResult | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const [s, v] = await Promise.all([
        api.getSettingsSchema(),
        api.getSettingsValues(),
      ]);
      setSchema(s);
      setValues(v.values);
    } catch (e) {
      const msg = getErrorMessage(e);
      if (/403|admin/i.test(msg)) setForbidden(true);
      else setLoadError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Mount-time data fetch: `reload`'s state transitions reflect the
    // in-flight request, not something derivable from props — the same
    // pattern (and the same lint warning) as the profile fetch in
    // settings/page.tsx and AuthProvider's session hydration.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void reload();
  }, [reload]);

  const entries = useMemo(() => {
    const m = new Map<string, CatalogEntry>();
    schema?.groups.forEach((g) => g.entries.forEach((e) => m.set(e.key, e)));
    return m;
  }, [schema]);

  const entriesByKey = useMemo(() => {
    const m: Record<string, CatalogEntry> = {};
    entries.forEach((entry, key) => {
      m[key] = entry;
    });
    return m;
  }, [entries]);

  // Pending-key count per backend group, for the rail's dirty badges. Keyed
  // by `entries[key].group` — a virtual group (e.g. "profiles") is not a real
  // catalog group, so the rail derives its own count from the two keys it
  // covers and subtracts them back out of "agents" itself.
  const stagedCountByGroup = useMemo(() => {
    const m: Record<string, number> = {};
    for (const key of Object.keys(pending)) {
      const group = entries.get(key)?.group;
      if (!group) continue;
      m[group] = (m[group] ?? 0) + 1;
    }
    return m;
  }, [pending, entries]);

  /**
   * Stage an edit — unless it puts the key back where it started.
   *
   * B3 (dev audit 2026-09-06): this always wrote `pending[key]`, so setting a
   * select to another value and back left the row marked MODIFIED and the
   * apply bar counting a change that would send the stored value back
   * unchanged. Only "Discard change" cleared it, which nobody looks for on a
   * field they believe they never edited.
   *
   * A secret is exempt: its stored value is always `null` on the wire (the API
   * never returns one), so "clear this secret" stages a value that deep-equals
   * what is saved and would be swallowed by the rule.
   */
  const stage = useCallback(
    (key: string, value: unknown) => {
      const entry = entries.get(key);
      const saved = key in values ? values[key].value : entry?.default;
      const revert = !entry?.secret && deepEqual(value, saved);
      setPending((p) => {
        if (!revert) return { ...p, [key]: value };
        if (!(key in p)) return p;
        const n = { ...p };
        delete n[key];
        return n;
      });
      setErrors((e) => {
        if (!(key in e)) return e;
        const n = { ...e };
        delete n[key];
        return n;
      });
    },
    [entries, values]
  );

  const unstage = useCallback((key: string) => {
    setPending((p) => {
      const n = { ...p };
      delete n[key];
      return n;
    });
    setErrors((e) => {
      if (!(key in e)) return e;
      const n = { ...e };
      delete n[key];
      return n;
    });
  }, []);

  const apply = useCallback(async () => {
    setSaving(true);
    setErrors({});
    setActionError(null);
    try {
      const res = await api.patchSettings(pending);
      setLastResult(res);
      setPending({});
      await reload();
      return res;
    } catch (e) {
      if (e instanceof SettingsValidationError) {
        setErrors(e.errors);
        // The server validates the whole merged set, so a stored override
        // that stopped validating (a later deploy narrowed its field) blocks
        // every save and blames a row the user never touched. Name it.
        //
        // A composite leaf (agent definitions, the server map, ...) stages
        // as one pending key but the server can point at a field nested
        // inside it (`core.agents.definitions.<key>.prompt`) — that still
        // belongs to a key the user just edited, not a stored override, so
        // it is matched by prefix rather than exact key.
        const foreign = Object.keys(e.errors).filter(
          (k) => !Object.keys(pending).some((p) => k === p || k.startsWith(`${p}.`))
        );
        if (foreign.length > 0) {
          setActionError(
            `Stored override${foreign.length > 1 ? "s" : ""} no longer valid: ${foreign.join(
              ", "
            )}. Reset ${foreign.length > 1 ? "them" : "it"} to default to save again.`
          );
        }
      } else setActionError(getErrorMessage(e));
      return null;
    } finally {
      setSaving(false);
    }
  }, [pending, reload]);

  // Callers fire-and-forget these (`void s.reset(key)`), so a rejected
  // promise here would surface only as an unhandled-rejection console entry
  // with no on-page feedback. Both are caught and routed to `actionError`,
  // NOT `loadError` — `loadError` blanks the whole tab, which is correct for
  // "the schema could not be loaded" but was wrong here: a failed DELETE was
  // tearing down the entire form (search box, rail, every row, any other
  // pending edits) over one row's reset failing.
  const reset = useCallback(
    async (key: string) => {
      setActionError(null);
      try {
        await api.resetSetting(key);
        unstage(key);
        await reload();
      } catch (e) {
        setActionError(getErrorMessage(e));
      }
    },
    [reload, unstage]
  );

  const resetGroup = useCallback(
    async (group: string) => {
      setActionError(null);
      try {
        await api.resetSettingsGroup(group);
        // Only unstage the keys that belong to *this* group — `setPending({})`
        // used to wipe every group's pending edits, so resetting one group's
        // overrides silently discarded unrelated in-flight edits elsewhere.
        const keys = schema?.groups.find((g) => g.key === group)?.entries.map((e) => e.key) ?? [];
        setPending((p) => {
          const n = { ...p };
          for (const k of keys) delete n[k];
          return n;
        });
        setErrors((e) => {
          const n = { ...e };
          for (const k of keys) delete n[k];
          return n;
        });
        await reload();
      } catch (e) {
        setActionError(getErrorMessage(e));
      }
    },
    [reload, schema]
  );

  const probe = useCallback(
    async (name: string, keys: string[]): Promise<ProbeResult> => {
      const body: Record<string, unknown> = {};
      for (const k of keys) if (k in pending) body[k] = pending[k];
      return api.testSettingsProbe(name, body);
    },
    [pending]
  );

  return {
    schema,
    values,
    entries,
    entriesByKey,
    stagedCountByGroup,
    pending,
    errors,
    loading,
    forbidden,
    loadError,
    actionError,
    clearActionError: () => setActionError(null),
    saving,
    lastResult,
    stage,
    unstage,
    apply,
    reset,
    resetGroup,
    probe,
    reload,
  };
}
