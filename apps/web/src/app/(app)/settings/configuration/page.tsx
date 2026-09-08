"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { firstGroupPath } from "./sections";
import { useSettingsContext } from "./SettingsContext";

/**
 * The bare `/settings/configuration` route has nothing of its own to show —
 * it always forwards to the first rail group. `SettingsProvider` (the parent
 * layout) already blocks rendering until the schema is loaded, forbidden, or
 * errored, so by the time this mounts `schema` is set.
 */
export default function ConfigurationIndexPage() {
  const router = useRouter();
  const { schema } = useSettingsContext();

  useEffect(() => {
    if (!schema) return;
    const path = firstGroupPath(schema);
    if (path) router.replace(path);
  }, [schema, router]);

  return <div className="text-sm text-text-secondary">Loading configuration…</div>;
}
