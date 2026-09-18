"use client";

import { getErrorMessage } from "@/lib/errors";
import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import type { AuditLogDTO } from "@/lib/api";
import { countLabel, formatDateTime } from "@/lib/report-utils";
import { auditColumns, auditRows } from "./auditRows";

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLogDTO[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  /* What the reader typed, and what has been asked for. The endpoint filters
   * on the action across the whole log, which is the difference between
   * narrowing 1766 entries and narrowing the twenty on screen. */
  const [draft, setDraft] = useState("");
  const [action, setAction] = useState("");
  const pageSize = 20;

  useEffect(() => {
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await api.getAuditLogs(page, pageSize, action || undefined);
        setLogs(res.items);
        setTotal(res.total);
      } catch (err) {
        if (getErrorMessage(err)?.includes("403") || getErrorMessage(err)?.toLowerCase().includes("forbidden") || getErrorMessage(err)?.toLowerCase().includes("access denied")) {
          setError("Access denied. Audit logs are restricted to administrators.");
        } else {
          setError(getErrorMessage(err) || "Failed to load audit logs.");
        }
      } finally {
        setLoading(false);
      }
    })();
  }, [page, action]);

  const totalPages = Math.ceil(total / pageSize);
  const rows = auditRows(logs);
  /* A column every row on this page leaves empty is not a column: RESOURCE
   * read "settings" on all twenty rows and IP ADDRESS was an em dash on all
   * twenty, between them spending a third of the table on nothing. */
  const columns = auditColumns(rows);
  const columnCount = 3 + (columns.resource ? 1 : 0) + (columns.ip ? 1 : 0);
  const th =
    "text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider";

  return (
    <div>
      <div className="flex items-center justify-between gap-3 mb-4 flex-wrap">
        <h1 className="text-sm font-semibold text-text-primary uppercase tracking-wider">
          Audit Logs
        </h1>
        <span className="text-xs text-text-muted">
          {action
            ? `${countLabel(total, "entry", "entries")} matching “${action}”`
            : countLabel(total, "total entry", "total entries")}
        </span>
      </div>

      <form
        className="flex items-end gap-2 mb-4 flex-wrap"
        onSubmit={(e) => {
          e.preventDefault();
          setPage(1);
          setAction(draft.trim());
        }}
      >
        <div>
          <label htmlFor="audit-action" className="block text-xs text-text-secondary mb-1.5">
            Action
          </label>
          <input
            id="audit-action"
            name="action"
            type="search"
            value={draft}
            placeholder="settings, login, api_key…"
            onChange={(e) => setDraft(e.target.value)}
            className="h-8 w-64 max-w-full px-3 text-xs bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
          />
        </div>
        <button
          type="submit"
          className="h-8 px-3 text-xs font-medium bg-accent-fill text-white rounded hover:bg-accent-fill-hover"
        >
          Filter
        </button>
        {action && (
          <button
            type="button"
            className="h-8 px-2 text-xs text-text-secondary hover:text-text-primary"
            onClick={() => {
              setDraft("");
              setPage(1);
              setAction("");
            }}
          >
            Clear
          </button>
        )}
      </form>

      {error && (
        <div role="alert" className="mb-4 p-3 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded">
          {error}
        </div>
      )}

      <div className="bg-bg-surface border border-border rounded">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th scope="col" className={`${th} w-48`}>Time</th>
                <th scope="col" className={th}>Action</th>
                {columns.resource && <th scope="col" className={th}>Resource</th>}
                <th scope="col" className={th}>Who</th>
                {columns.ip && <th scope="col" className={th}>IP address</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {loading ? (
                <tr>
                  <td colSpan={columnCount} className="px-4 py-6 text-center text-xs text-text-muted">
                    Loading...
                  </td>
                </tr>
              ) : error ? (
                /* Without this branch the table said "No audit logs found."
                 * directly underneath the error banner — a failed request and
                 * an genuinely empty log rendered identically, so anything
                 * asserting on the empty state passed on a broken page. */
                <tr>
                  <td colSpan={columnCount} className="px-4 py-6 text-center text-xs text-text-muted">
                    Log entries could not be loaded — see the message above.
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={columnCount} className="px-4 py-6 text-center text-xs text-text-muted">
                    {action
                      ? `No entry matches “${action}”.`
                      : "No audit logs found."}
                  </td>
                </tr>
              ) : (
                rows.map((row) => (
                  <tr key={row.id} className="hover:bg-bg-hover">
                    <td className="px-4 py-2.5">
                      <span className="text-xs text-text-secondary font-mono">
                        {formatDateTime(row.at)}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="text-xs text-text-primary">{row.action}</span>
                    </td>
                    {columns.resource && (
                      <td className="px-4 py-2.5">
                        <span className="text-xs text-text-secondary">{row.resource || "—"}</span>
                      </td>
                    )}
                    <td className="px-4 py-2.5">
                      <span
                        className={`text-xs text-text-secondary${row.actorId ? "" : " font-mono"}`}
                        title={row.actorId || undefined}
                      >
                        {row.actor}
                      </span>
                    </td>
                    {columns.ip && (
                      <td className="px-4 py-2.5">
                        <span className="text-xs text-text-secondary font-mono">
                          {row.ip || "—"}
                        </span>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-border">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="px-3 py-1 text-xs border border-border rounded text-text-secondary hover:bg-bg-hover disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <span className="text-xs text-text-muted">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-3 py-1 text-xs border border-border rounded text-text-secondary hover:bg-bg-hover disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
