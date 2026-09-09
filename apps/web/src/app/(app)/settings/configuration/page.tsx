"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { firstGroupPath } from "./sections";
import { useSettingsContext } from "./SettingsContext";
import { llmLooksConfigured } from "../setup/status";

/**
 * The bare `/settings/configuration` route has nothing of its own to show —
 * it forwards to the first rail group, or, when no language model is usable
 * yet (no key for a hosted provider, or Ollama with no base URL), to the
 * guide hub: there is nothing worth configuring before the analysts can talk
 * to a model. `SettingsProvider` (the parent layout) already blocks rendering
 * until the schema is loaded, forbidden, or errored, so by the time this
 * mounts `schema` is set.
 */
export default function ConfigurationIndexPage() {
  const router = useRouter();
  const ctx = useSettingsContext();
  const { schema, effectiveValue, values } = ctx;

  useEffect(() => {
    if (!schema) return;
    const isSet = (key: string) => values[key]?.is_set === true;
    if (!llmLooksConfigured(effectiveValue, isSet)) {
      router.replace("/settings/setup");
      return;
    }
    const path = firstGroupPath(schema);
    if (path) router.replace(path);
  }, [schema, effectiveValue, values, router]);

  return <div className="text-sm text-text-secondary">Loading configuration…</div>;
}
