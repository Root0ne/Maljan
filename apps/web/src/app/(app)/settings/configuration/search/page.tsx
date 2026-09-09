"use client";

import { Suspense, useMemo } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import type { CatalogEntry } from "@/types/settings";
import FieldRow from "../FieldRow";
import { buildFieldRowProps } from "../fieldRowProps";
import RestSandboxEditor from "../RestSandboxEditor";
import { groupsBySection, pathForKey } from "../sections";
import { useSettingsContext } from "../SettingsContext";

interface ResultBlock {
  path: string;
  heading: string;
  entries: CatalogEntry[];
}

function SearchResults() {
  const ctx = useSettingsContext();
  const searchParams = useSearchParams();
  const query = searchParams.get("q") ?? "";
  const { schema } = ctx;

  const blocks = useMemo<ResultBlock[]>(() => {
    const q = query.trim().toLowerCase();
    if (!schema || !q) return [];

    // The rail's own order, so results read in the same sequence as the nav.
    const headings = new Map<string, string>();
    const order: string[] = [];
    for (const { section, groups } of groupsBySection(schema)) {
      for (const group of groups) {
        headings.set(group.path, `${section.title} › ${group.title}`);
        order.push(group.path);
      }
    }

    const matches = schema.groups
      .flatMap((g) => g.entries)
      .filter((e) => [e.key, e.title, e.description].some((t) => t.toLowerCase().includes(q)))
      .filter((e) => ctx.isVisible(e))
      .sort((a, b) => a.order - b.order || a.key.localeCompare(b.key));

    const byPath = new Map<string, CatalogEntry[]>();
    for (const entry of matches) {
      const path = pathForKey(schema, entry.key);
      if (!path) continue;
      const bucket = byPath.get(path);
      if (bucket) bucket.push(entry);
      else byPath.set(path, [entry]);
    }

    return order
      .filter((path) => byPath.has(path))
      .map((path) => ({
        path,
        heading: headings.get(path) ?? path,
        entries: byPath.get(path) ?? [],
      }));
  }, [schema, query, ctx]);

  if (!query.trim()) {
    return <p className="text-sm text-text-muted">Type to search settings</p>;
  }

  if (blocks.length === 0) {
    return (
      <p className="text-sm text-text-muted">
        No settings match &ldquo;{query}&rdquo;.
      </p>
    );
  }

  return (
    <div>
      {blocks.map((block) => {
        const rest = block.entries.filter((e) => e.editor === "rest_sandbox");
        const rows = block.entries.filter((e) => e.editor !== "rest_sandbox");
        return (
          <section key={block.path} className="mb-6">
            <div className="flex items-center justify-between gap-4 flex-wrap mb-1">
              <h3 className="text-[11px] uppercase tracking-wider text-text-muted">
                {block.heading}
              </h3>
              <Link href={block.path} className="text-xs text-accent-strong">
                Open group
              </Link>
            </div>
            {rows.map((entry) => (
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
      })}
    </div>
  );
}

export default function ConfigurationSearchPage() {
  return (
    <Suspense fallback={<p className="text-sm text-text-secondary">Searching…</p>}>
      <SearchResults />
    </Suspense>
  );
}
