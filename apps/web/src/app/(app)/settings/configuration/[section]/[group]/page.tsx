"use client";

import { useParams } from "next/navigation";
import { useMemo } from "react";
import FieldRow from "../../FieldRow";
import { buildFieldRowProps } from "../../fieldRowProps";
import RestSandboxEditor from "../../RestSandboxEditor";
import { resolveGroup } from "../../sections";
import { useSettingsContext } from "../../SettingsContext";

/**
 * The rail's leaf route. Task 7 replaces this body with the full `GroupPage`
 * (probes, group reset, review list); this is deliberately minimal — title,
 * description, and the visible fields, wired the same way `ConfigurationTab`
 * wired them.
 */
export default function ConfigurationGroupPage() {
  const params = useParams<{ section: string; group: string }>();
  const ctx = useSettingsContext();
  const { schema } = ctx;

  const resolved = useMemo(() => {
    if (!schema) return null;
    const section = Array.isArray(params.section) ? params.section[0] : params.section;
    const group = Array.isArray(params.group) ? params.group[0] : params.group;
    if (!section || !group) return null;
    return resolveGroup(schema, section, group);
  }, [schema, params.section, params.group]);

  if (!resolved) {
    return <p role="alert">No such settings group.</p>;
  }

  const visibleEntries = resolved.entries
    .filter((e) => ctx.isVisible(e))
    .sort((a, b) => a.order - b.order || a.key.localeCompare(b.key));

  const rest = visibleEntries.filter((e) => e.editor === "rest_sandbox");
  const others = visibleEntries.filter((e) => e.editor !== "rest_sandbox");

  return (
    <section>
      <h2 className="text-base font-semibold text-text-primary mb-1">{resolved.title}</h2>
      {resolved.description && (
        <p className="text-xs text-text-secondary mb-4">{resolved.description}</p>
      )}
      {others.map((entry) => (
        <FieldRow key={entry.key} {...buildFieldRowProps(ctx, entry)} />
      ))}
      {rest.length > 0 && (
        <RestSandboxEditor
          entries={rest}
          values={ctx.values}
          pending={ctx.pending}
          errors={ctx.errors}
          onChange={ctx.stage}
          onUnstage={ctx.unstage}
          onReset={(k) => void ctx.reset(k)}
        />
      )}
    </section>
  );
}
