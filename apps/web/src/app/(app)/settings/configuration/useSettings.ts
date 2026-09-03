"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { SettingsValidationError } from "@/types/settings";
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

  const stage = useCallback((key: string, value: unknown) => {
    setPending((p) => ({ ...p, [key]: value }));
    setErrors((e) => {
      const n = { ...e };
      delete n[key];
      return n;
    });
  }, []);

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
      if (e instanceof SettingsValidationError) setErrors(e.errors);
      else setActionError(getErrorMessage(e));
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
