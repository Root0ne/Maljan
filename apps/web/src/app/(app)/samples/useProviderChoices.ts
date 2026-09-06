"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

/**
 * The provider lists the submit dialog offers, read from the settings catalog.
 *
 * They used to be two `as const` arrays in `samples/page.tsx`, which is one
 * more place than there should be for "which providers exist": adding one to
 * the registry left the dialog offering yesterday's list. The catalog already
 * carries them, resolved server-side from the registry itself.
 *
 * A failure here is not worth an error banner on a page about samples: the
 * dialog falls back to offering only "Inherit from settings", which is the
 * safe answer — the job then uses whatever the settings say.
 */
export function useProviderChoices(): {
  staticProviders: string[];
  sandboxProviders: string[];
} {
  const [choices, setChoices] = useState<{ staticProviders: string[]; sandboxProviders: string[] }>(
    { staticProviders: [], sandboxProviders: [] }
  );

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const schema = await api.getSettingsSchema();
        const entries = schema.groups.flatMap((g) => g.entries);
        const find = (key: string) =>
          entries.find((e) => e.key === key)?.choices ?? [];
        if (!cancelled) {
          setChoices({
            staticProviders: find("core.static.provider"),
            sandboxProviders: find("core.sandbox.provider"),
          });
        }
      } catch {
        // Left empty on purpose: see the doc comment above.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return choices;
}
