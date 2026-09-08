"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { CatalogEntry, SettingValue } from "@/types/settings";
import { useSettings } from "./useSettings";

/** The value a dependency currently holds: what the user staged, else what the
 *  server reports. Staged wins so the form reacts to the switch immediately,
 *  before anything is applied. */
function effectiveValueOf(
  key: string,
  values: Record<string, SettingValue>,
  pending: Record<string, unknown>
): unknown {
  return key in pending ? pending[key] : values[key]?.value;
}

function isVisibleOf(
  entry: CatalogEntry,
  values: Record<string, SettingValue>,
  pending: Record<string, unknown>
): boolean {
  if (!entry.applies_when) return true;
  return Object.entries(entry.applies_when).every(([key, allowed]) =>
    allowed.includes(String(effectiveValueOf(key, values, pending) ?? ""))
  );
}

export type SettingsContextValue = ReturnType<typeof useSettings> & {
  models: string[];
  setModels: (m: string[]) => void;
  /** Staged keys whose owning entry is currently hidden by a governing
   *  selector elsewhere in the group — still sent on Apply, just not visible
   *  to point at. */
  hiddenKeys: string[];
  effectiveValue: (key: string) => unknown;
  isVisible: (entry: CatalogEntry) => boolean;
  /** Staged values of every catalog key with the given probe id, across every
   *  group — the body a probe call sends. */
  probeValues: (probeId: string) => Record<string, unknown>;
  onlyChanged: boolean;
  setOnlyChanged: (v: boolean) => void;
};

const SettingsCtx = createContext<SettingsContextValue | null>(null);

export function SettingsProvider({ children }: { children: React.ReactNode }) {
  const s = useSettings();
  const [models, setModels] = useState<string[]>([]);
  const [onlyChanged, setOnlyChanged] = useState(false);

  useEffect(() => {
    const dirty = Object.keys(s.pending).length > 0;
    const handler = (e: BeforeUnloadEvent) => {
      if (dirty) e.preventDefault();
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [s.pending]);

  const effectiveValue = useCallback(
    (key: string) => effectiveValueOf(key, s.values, s.pending),
    [s.values, s.pending]
  );

  const isVisible = useCallback(
    (entry: CatalogEntry) => isVisibleOf(entry, s.values, s.pending),
    [s.values, s.pending]
  );

  const hiddenKeys = useMemo(() => {
    return Object.keys(s.pending).filter((k) => {
      const entry = s.entriesByKey[k];
      return entry !== undefined && !isVisibleOf(entry, s.values, s.pending);
    });
  }, [s.pending, s.entriesByKey, s.values]);

  const probeValues = useCallback(
    (probeId: string): Record<string, unknown> => {
      const body: Record<string, unknown> = {};
      for (const entry of s.entries.values()) {
        if (entry.probe === probeId && entry.key in s.pending) {
          body[entry.key] = s.pending[entry.key];
        }
      }
      return body;
    },
    [s.entries, s.pending]
  );

  const value = useMemo<SettingsContextValue>(
    () => ({
      ...s,
      models,
      setModels,
      hiddenKeys,
      effectiveValue,
      isVisible,
      probeValues,
      onlyChanged,
      setOnlyChanged,
    }),
    [s, models, hiddenKeys, effectiveValue, isVisible, probeValues, onlyChanged]
  );

  if (s.loading) {
    return <div className="text-sm text-text-secondary">Loading configuration…</div>;
  }
  if (s.forbidden) {
    return (
      <div className="text-sm text-text-secondary" role="alert">
        Configuration is available to administrators only (admin role required).
      </div>
    );
  }
  if (s.loadError) {
    return (
      <div className="text-sm text-status-red" role="alert">
        {s.loadError}
      </div>
    );
  }
  if (!s.schema) return null;

  return <SettingsCtx.Provider value={value}>{children}</SettingsCtx.Provider>;
}

export function useSettingsContext(): SettingsContextValue {
  const ctx = useContext(SettingsCtx);
  if (!ctx) {
    throw new Error("useSettingsContext must be used within a SettingsProvider");
  }
  return ctx;
}
