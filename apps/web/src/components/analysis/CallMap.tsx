"use client";

import { useEffect, useId, useMemo, useState, type KeyboardEvent } from "react";
import { flushSync } from "react-dom";
import Link from "next/link";
import { ChevronRight, CornerLeftUp } from "lucide-react";

import Section from "@/components/ui/Section";
import ShowMoreRows from "@/components/ui/ShowMoreRows";
import Th from "@/components/ui/Th";
import { scrollRegion, SCROLL_REGION_FOCUS } from "@/components/ui/scrollRegion";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type { CallMapFunction, CallMapResponse } from "@/types/evidence";
import { CiteMark } from "./CitedProse";
import {
  LIST_STEP,
  PATH_SEP,
  ROOTS_FIRST,
  byAddress,
  filterFunctions,
  functionLabel,
  pathParent,
  readCounts,
  treeRows,
  type ReadFilter,
  type TreeRow,
} from "./callMap";
import { evidenceRecordHref } from "./overview";

/**
 * The functions the run's code reading touched: what each calls, what calls
 * it, whether an analyst read its listing or a call only named it, and the
 * evidence records that hold the listing. Derived from the stored ledger by
 * the API (`GET /jobs/{id}/evidence/call-map`), so a stored run has one too.
 *
 * Two views of one map: a tree from the functions nothing calls, opened one
 * function at a time with the keyboard as with the pointer (the tree
 * pattern), and a flat list searched by address, offset or name.
 */
export default function CallMap({ jobId }: { jobId: string }) {
  const [map, setMap] = useState<CallMapResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"tree" | "list">("tree");

  useEffect(() => {
    if (!jobId) return;
    let live = true;
    api
      .getJobCallMap(jobId)
      .then((data) => {
        if (!live) return;
        setMap(data);
        setError(null);
      })
      .catch((err: unknown) => live && setError(getErrorMessage(err)));
    return () => {
      live = false;
    };
  }, [jobId]);

  const functions = map?.functions ?? [];
  const counts = readCounts(functions);

  if (error) {
    return (
      <Section title="Call map">
        <p className="text-xs text-status-red" role="alert">
          The call map could not be read: {error}
        </p>
      </Section>
    );
  }
  if (!map) {
    return (
      <Section title="Call map">
        <p className="text-xs text-text-muted" aria-live="polite">
          Reading the call map…
        </p>
      </Section>
    );
  }

  return (
    <Section
      title="Call map"
      count={functions.length || null}
      empty={functions.length === 0}
      emptyText="No code was read"
      actions={
        <div role="group" aria-label="How the call map is shown" className="inline-flex overflow-hidden rounded border border-border">
          {(["tree", "list"] as const).map((v) => (
            <button
              key={v}
              type="button"
              aria-pressed={view === v}
              onClick={() => setView(v)}
              className={`min-h-6 border-l border-border px-2.5 py-1 text-xs first:border-l-0 ${
                view === v ? "bg-bg-active font-medium text-text-primary" : "text-text-secondary hover:bg-bg-hover hover:text-text-primary"
              }`}
            >
              {v === "tree" ? "Tree" : "List"}
            </button>
          ))}
        </div>
      }
    >
      <div className="space-y-3">
        <p className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-secondary">
          <span className="inline-flex items-center gap-1.5">
            <ReadGlyph read />
            {counts.read.toLocaleString("en-US")} read
          </span>
          <span className="inline-flex items-center gap-1.5">
            <ReadGlyph read={false} />
            {counts.named.toLocaleString("en-US")} named in a call, not read
          </span>
          {map.image_base && (
            <span className="text-text-muted">
              Image base <code className="font-mono">{map.image_base}</code>
            </span>
          )}
        </p>
        {view === "tree" ? <CallTree map={map} /> : <CallList jobId={jobId} functions={functions} />}
      </div>
    </Section>
  );
}

/** Read or only named: a filled square for a listing read, an empty one for a
 *  function a call names. Square, so it never reads as the seen-in-sandbox dot. */
function ReadGlyph({ read }: { read: boolean }) {
  return (
    <span
      aria-hidden="true"
      className={`inline-block h-2 w-2 shrink-0 rounded-[2px] border ${
        read ? "border-text-secondary bg-text-secondary" : "border-text-muted bg-transparent"
      }`}
    />
  );
}

function readWord(fn: CallMapFunction): string {
  return fn.read ? "read" : "named in a call, not read";
}

function CallTree({ map }: { map: CallMapResponse }) {
  const index = useMemo(() => byAddress(map), [map]);
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());
  const [whole, setWhole] = useState<ReadonlySet<string>>(new Set());
  const [rootLimit, setRootLimit] = useState(ROOTS_FIRST);
  const roots = useMemo(() => map.roots.slice(0, rootLimit), [map, rootLimit]);
  const rows = useMemo(() => treeRows(roots, index, { open, whole }), [roots, index, open, whole]);
  const [focus, setFocus] = useState<string | null>(null);
  const focusKey = rows.some((r) => r.key === focus) ? focus : (rows[0]?.key ?? null);
  const treeId = useId();

  const toggle = (key: string, to?: boolean) =>
    setOpen((s) => {
      const next = new Set(s);
      if (to ?? !next.has(key)) next.add(key);
      else next.delete(key);
      return next;
    });
  // Focus follows the keyboard only, so a reader arriving on the page keeps
  // theirs; it moves at once, so the next key lands on the row it names.
  const go = (key: string | undefined) => {
    if (!key) return;
    flushSync(() => setFocus(key));
    document
      .getElementById(treeId)
      ?.querySelector<HTMLElement>(`[data-key="${CSS.escape(key)}"]`)
      ?.focus();
  };
  const activate = (row: TreeRow) => {
    if (row.kind === "function" && row.callees > 0) toggle(row.key);
    if (row.kind === "more") setWhole((s) => new Set([...s, row.parent]));
    if (row.kind === "back") {
      // The function it calls back to is the row of the same address up the path.
      const path = row.key.split(PATH_SEP);
      go(path.slice(0, path.indexOf(row.address) + 1).join(PATH_SEP));
    }
  };

  const onKey = (e: KeyboardEvent<HTMLElement>, row: TreeRow, i: number) => {
    const opened = row.kind === "function" && row.open;
    switch (e.key) {
      case "ArrowDown":
        go(rows[i + 1]?.key);
        break;
      case "ArrowUp":
        go(rows[i - 1]?.key);
        break;
      case "Home":
        go(rows[0]?.key);
        break;
      case "End":
        go(rows[rows.length - 1]?.key);
        break;
      case "ArrowRight":
        if (row.kind === "function" && row.callees > 0) {
          if (opened) go(rows[i + 1]?.key);
          else toggle(row.key, true);
        }
        break;
      case "ArrowLeft":
        if (opened) toggle(row.key, false);
        else go(pathParent(row.key) || undefined);
        break;
      case "Enter":
      case " ":
        activate(row);
        break;
      default:
        return;
    }
    e.preventDefault();
  };

  return (
    <div className="overflow-hidden rounded border border-border-light">
      <div {...scrollRegion("Call tree")} className={`max-h-[36rem] overflow-auto ${SCROLL_REGION_FOCUS}`}>
        <ul id={treeId} role="tree" aria-label="Call tree from the functions nothing calls" className="min-w-max py-1 text-xs">
          {rows.map((row, i) => {
            const common = {
              "data-key": row.key,
              role: "treeitem",
              "aria-level": row.level,
              "aria-setsize": row.setsize,
              "aria-posinset": row.posinset,
              tabIndex: row.key === focusKey ? 0 : -1,
              onKeyDown: (e: KeyboardEvent<HTMLElement>) => onKey(e, row, i),
              onFocus: () => setFocus(row.key),
              style: { paddingLeft: (row.level - 1) * 18 + 8 },
              className:
                "flex items-center gap-2 py-1 pr-3 outline-none hover:bg-bg-hover focus-visible:bg-bg-active focus-visible:outline focus-visible:outline-1 focus-visible:-outline-offset-1 focus-visible:outline-accent",
            } as const;
            if (row.kind === "more") {
              return (
                <li key={row.key} {...common} aria-label={`Show ${row.hidden} more callees`} onClick={() => activate(row)}>
                  <span className="w-3.5" />
                  <span className="cursor-pointer text-[11px] text-accent-strong hover:underline">
                    Show {row.hidden.toLocaleString("en-US")} more callee{row.hidden === 1 ? "" : "s"}
                  </span>
                </li>
              );
            }
            if (row.kind === "back") {
              const name = row.fn && row.fn.names.length > 0 ? row.fn.names.join(", ") : "";
              return (
                <li
                  key={row.key}
                  {...common}
                  aria-label={`Calls back to ${row.address}${name ? ` (${name})` : ""}, already open above`}
                  onClick={() => activate(row)}
                  className={`${common.className} cursor-pointer text-text-muted`}
                >
                  <span className="w-3.5" />
                  <CornerLeftUp aria-hidden="true" className="h-3.5 w-3.5 shrink-0" />
                  <span>calls back to</span>
                  <span className="font-mono text-text-secondary">{row.address}</span>
                  {name && <span className="font-mono">{name}</span>}
                </li>
              );
            }
            const { fn } = row;
            return (
              <li
                key={row.key}
                {...common}
                aria-expanded={row.callees > 0 ? row.open : undefined}
                aria-label={`${fn.address}${fn.names.length ? ` ${fn.names.join(", ")}` : ""}, ${readWord(fn)}, calls ${row.callees}`}
                data-read={fn.read ? "true" : "false"}
              >
                {row.callees > 0 ? (
                  <ChevronRight
                    aria-hidden="true"
                    onClick={() => toggle(row.key)}
                    className={`h-3.5 w-3.5 shrink-0 cursor-pointer text-text-muted ${row.open ? "rotate-90" : ""}`}
                  />
                ) : (
                  <span className="w-3.5 shrink-0" />
                )}
                <span title={readWord(fn)} className="inline-flex">
                  <ReadGlyph read={fn.read} />
                </span>
                <span
                  onClick={() => row.callees > 0 && toggle(row.key)}
                  className={`font-mono ${fn.read ? "text-text-primary" : "text-text-secondary"} ${row.callees > 0 ? "cursor-pointer" : ""}`}
                >
                  {fn.address}
                </span>
                {fn.names.length > 0 && <span className="font-mono text-status-purple">{fn.names.join(", ")}</span>}
                {row.callees > 0 && (
                  <span className="text-[11px] text-text-muted">
                    calls {row.callees.toLocaleString("en-US")}
                  </span>
                )}
                {fn.listed_in.length > 0 && <CiteMark ids={fn.listed_in} title={`Listing of ${fn.address}`} />}
              </li>
            );
          })}
        </ul>
      </div>
      <ShowMoreRows shown={roots.length} total={map.roots.length} onShow={setRootLimit} step={ROOTS_FIRST} />
    </div>
  );
}

function AddressList({ addresses, onPick }: { addresses: string[]; onPick: (a: string) => void }) {
  if (addresses.length === 0) return <span className="text-text-muted">-</span>;
  const shown = addresses.slice(0, 3);
  return (
    <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
      {shown.map((a) => (
        <button
          key={a}
          type="button"
          onClick={() => onPick(a)}
          title={`Find ${a} in the list`}
          className="font-mono text-text-secondary hover:text-accent-strong hover:underline"
        >
          {a}
        </button>
      ))}
      {addresses.length > shown.length && (
        <span className="text-text-muted">+{(addresses.length - shown.length).toLocaleString("en-US")}</span>
      )}
    </span>
  );
}

function CallList({ jobId, functions }: { jobId: string; functions: CallMapFunction[] }) {
  const [filter, setFilter] = useState<ReadFilter>("all");
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(LIST_STEP);
  const shown = useMemo(() => filterFunctions(functions, filter, query), [functions, filter, query]);
  const counts = readCounts(functions);
  const pick = (a: string) => {
    setFilter("all");
    setQuery(a);
    setLimit(LIST_STEP);
  };
  const facets: { key: ReadFilter; label: string; count: number }[] = [
    { key: "all", label: "All", count: functions.length },
    { key: "read", label: "Read", count: counts.read },
    { key: "named", label: "Not read", count: counts.named },
  ];

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="search"
          aria-label="Search functions"
          placeholder="Address, offset or name"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setLimit(LIST_STEP);
          }}
          className="h-7 w-56 max-w-full rounded border border-border bg-bg-deep px-2.5 font-mono text-xs text-text-primary placeholder:font-sans placeholder:text-text-tertiary focus:border-accent focus:outline-none"
        />
        <div role="group" aria-label="Read or not" className="flex flex-wrap gap-1">
          {facets.map((f) => (
            <button
              key={f.key}
              type="button"
              aria-pressed={filter === f.key}
              onClick={() => {
                setFilter(f.key);
                setLimit(LIST_STEP);
              }}
              className={`rounded border px-2 py-0.5 text-[11px] ${
                filter === f.key ? "border-accent text-accent-strong" : "border-border text-text-secondary hover:text-text-primary"
              }`}
            >
              {f.label} {f.count.toLocaleString("en-US")}
            </button>
          ))}
        </div>
      </div>
      {shown.length === 0 ? (
        <p className="text-xs text-text-muted">No function matches.</p>
      ) : (
        <div {...scrollRegion("Functions in the call map")} className={`overflow-x-auto rounded border border-border-light ${SCROLL_REGION_FOCUS}`}>
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <Th>Function</Th>
                <Th>Read</Th>
                <Th>Calls</Th>
                <Th>Called by</Th>
                <Th>Listing</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {shown.slice(0, limit).map((fn) => (
                <tr key={fn.address ?? `name:${functionLabel(fn)}`} className="align-top hover:bg-bg-hover" data-read={fn.read ? "true" : "false"}>
                  <td className="px-4 py-2 text-xs">
                    <span className={`font-mono ${fn.read ? "text-text-primary" : "text-text-secondary"}`}>{fn.address ?? functionLabel(fn)}</span>
                    {fn.address && fn.names.length > 0 && <span className="ml-2 font-mono text-status-purple">{fn.names.join(", ")}</span>}
                    {fn.offset && <span className="ml-2 font-mono text-[11px] text-text-muted">offset {fn.offset}</span>}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2 text-xs text-text-secondary">
                    <span className="inline-flex items-center gap-1.5">
                      <ReadGlyph read={fn.read} />
                      {fn.read ? "read" : "not read"}
                    </span>
                    {fn.read_by.length > 0 && <div className="mt-0.5 text-[11px] text-text-muted">by {fn.read_by.join(", ")}</div>}
                  </td>
                  <td className="px-4 py-2 text-xs">
                    <AddressList addresses={fn.calls} onPick={pick} />
                  </td>
                  <td className="px-4 py-2 text-xs">
                    <AddressList addresses={fn.called_by} onPick={pick} />
                  </td>
                  <td className="px-4 py-2 text-xs">
                    {fn.listed_in.length === 0 ? (
                      <span className="text-text-muted">-</span>
                    ) : (
                      <span className="flex flex-wrap gap-x-2">
                        {fn.listed_in.map((id) => (
                          <Link
                            key={id}
                            href={evidenceRecordHref(jobId, id)}
                            className="font-mono text-accent-strong hover:underline"
                            title={`The evidence record that holds the listing of ${fn.address ?? functionLabel(fn)}`}
                          >
                            {id}
                          </Link>
                        ))}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <ShowMoreRows shown={Math.min(limit, shown.length)} total={shown.length} onShow={setLimit} step={LIST_STEP} />
        </div>
      )}
    </div>
  );
}
