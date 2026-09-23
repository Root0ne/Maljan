"use client";

/**
 * Two stored runs side by side: what the second run's record says that the
 * first one's does not, and the reverse.
 *
 * `?a=<job>` alone asks which run to compare with, offering the same sample's
 * runs first and then any run by id, file name or digest; `?a=<job>&b=<job>`
 * shows the diff the API computed from the two stored records.
 */

import Link from "next/link";
import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ArrowLeftRight, Printer } from "lucide-react";
import { api } from "@/lib/api";
import type { JobDTO } from "@/lib/api";
import { getErrorMessage, isApiStatus } from "@/lib/errors";
import { formatDateTime } from "@/lib/report-utils";
import RunDiffView from "@/components/compare/RunDiffView";
import { isRunId, searchRuns, siblingRuns } from "@/components/compare/runDiff";
import type { RunDiff } from "@/types/runDiff";

function compareHref(a: string, b?: string): string {
  const params = new URLSearchParams({ a });
  if (b) params.set("b", b);
  return `/compare?${params}`;
}

function RunLink({ a, run }: { a: string; run: JobDTO }) {
  return (
    <Link
      href={compareHref(a, run.id)}
      className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 rounded border border-border px-3 py-2 text-xs hover:border-text-muted focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
    >
      <span className="font-semibold text-text-primary">{run.sample_filename || "File name not recorded"}</span>
      <span className="font-mono text-text-secondary">{run.id}</span>
      <span className="text-text-muted">{formatDateTime(run.created_at)}</span>
    </Link>
  );
}

function RunPicker({ a }: { a: string }) {
  const [self, setSelf] = useState<JobDTO | null>(null);
  const [siblings, setSiblings] = useState<JobDTO[]>([]);
  const [recent, setRecent] = useState<JobDTO[]>([]);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const job = await api.getJob(a);
        if (cancelled) return;
        setSelf(job);
        const [same, any] = await Promise.all([
          api.getJobs(1, 100, "completed", job.sample_id),
          api.getJobs(1, 100, "completed"),
        ]);
        if (cancelled) return;
        setSiblings(siblingRuns(same.items, job));
        setRecent(any.items);
      } catch (err) {
        if (!cancelled) {
          setError(isApiStatus(err, 404) ? "No run exists with this id." : getErrorMessage(err));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [a]);

  const matches = useMemo(() => searchRuns(recent, query, a), [recent, query, a]);
  const typedId = query.trim();

  if (error) {
    return (
      <p role="alert" className="text-sm text-status-red">
        {error}
      </p>
    );
  }

  return (
    <div className="space-y-6">
      <p className="text-sm text-text-secondary">
        Comparing from{" "}
        <Link href={`/analysis/${a}`} className="text-accent-strong hover:underline">
          {self?.sample_filename || a}
        </Link>
        . Choose the run to compare it with.
      </p>

      <section aria-labelledby="same-sample-heading">
        <h2 id="same-sample-heading" className="mb-2 text-sm font-semibold text-text-primary">
          Runs of the same sample
        </h2>
        {siblings.length === 0 ? (
          <p className="text-xs text-text-muted">No other completed run of this sample.</p>
        ) : (
          <ul className="space-y-1.5">
            {siblings.map((run) => (
              <li key={run.id}>
                <RunLink a={a} run={run} />
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="any-run-heading">
        <h2 id="any-run-heading" className="mb-2 text-sm font-semibold text-text-primary">
          Any run
        </h2>
        <label htmlFor="run-search" className="mb-1 block text-xs text-text-secondary">
          Run id, file name or SHA-256
        </label>
        <input
          id="run-search"
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="mb-2 w-full max-w-xl rounded border border-border bg-bg-deep px-2.5 py-1.5 text-sm text-text-primary focus:border-accent focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
        />
        {isRunId(typedId) && typedId !== a && !matches.some((r) => r.id === typedId) && (
          <p className="mb-2 text-xs">
            <Link href={compareHref(a, typedId)} className="text-accent-strong hover:underline">
              Compare with run {typedId}
            </Link>
          </p>
        )}
        {matches.length === 0 ? (
          <p className="text-xs text-text-muted">No completed run matches among the latest hundred.</p>
        ) : (
          <ul className="space-y-1.5">
            {matches.slice(0, 50).map((run) => (
              <li key={run.id}>
                <RunLink a={a} run={run} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function DiffLoader({ a, b }: { a: string; b: string }) {
  const [diff, setDiff] = useState<RunDiff | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // The loader is keyed by the pair, so a new pair starts from empty state.
    let cancelled = false;
    api
      .getRunDiff(a, b)
      .then((d) => {
        if (!cancelled) setDiff(d);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(
          isApiStatus(err, 404)
            ? "One of the two runs has no report you can read."
            : getErrorMessage(err) || "Could not load the comparison.",
        );
      });
    return () => {
      cancelled = true;
    };
  }, [a, b]);

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-3 text-xs print:hidden">
        <Link href={compareHref(a)} className="text-accent-strong hover:underline">
          Choose another run
        </Link>
        <Link
          href={compareHref(b, a)}
          className="inline-flex items-center gap-1 text-accent-strong hover:underline"
        >
          <ArrowLeftRight size={16} aria-hidden="true" />
          Swap A and B
        </Link>
        <button
          type="button"
          onClick={() => window.print()}
          className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-text-secondary hover:border-text-muted hover:text-text-primary"
        >
          <Printer size={16} aria-hidden="true" />
          Print
        </button>
      </div>
      {error && (
        <p role="alert" className="text-sm text-status-red">
          {error}
        </p>
      )}
      {!error && !diff && <p className="text-sm text-text-secondary">Comparing the two records…</p>}
      {diff && <RunDiffView diff={diff} />}
    </div>
  );
}

function ComparePage() {
  const params = useSearchParams();
  const a = params.get("a")?.trim() ?? "";
  const b = params.get("b")?.trim() ?? "";

  return (
    <div className="max-w-7xl print-light">
      <h1 className="mb-3 text-lg font-semibold text-text-primary">Compare two runs</h1>
      {!a ? (
        <p className="text-sm text-text-secondary">
          Open an analysis and choose Compare, or pick a run from{" "}
          <Link href="/jobs" className="text-accent-strong hover:underline">
            the analyses list
          </Link>
          .
        </p>
      ) : !b ? (
        <RunPicker a={a} />
      ) : (
        <DiffLoader key={`${a}|${b}`} a={a} b={b} />
      )}
    </div>
  );
}

/* `useSearchParams` needs a Suspense boundary for the static build. */
export default function Page() {
  return (
    <Suspense fallback={<div className="text-sm text-text-secondary">Loading…</div>}>
      <ComparePage />
    </Suspense>
  );
}
