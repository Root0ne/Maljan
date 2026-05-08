"use client";

import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import type { AuditLogDTO } from "@/lib/api";

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLogDTO[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const pageSize = 20;

  useEffect(() => {
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await api.getAuditLogs(page, pageSize);
        setLogs(res.items);
        setTotal(res.total);
      } catch (err: any) {
        if (err.message?.includes("403") || err.message?.toLowerCase().includes("forbidden") || err.message?.toLowerCase().includes("access denied")) {
          setError("Access denied. Audit logs are restricted to administrators.");
        } else {
          setError(err.message || "Failed to load audit logs.");
        }
      } finally {
        setLoading(false);
      }
    })();
  }, [page]);

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-sm font-semibold text-text-primary uppercase tracking-wider">
          Audit Logs
        </h1>
        <span className="text-xs text-text-muted">
          {total} total entries
        </span>
      </div>

      {error && (
        <div className="mb-4 p-3 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded">
          {error}
        </div>
      )}

      <div className="bg-bg-surface border border-border rounded">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-48">Time</th>
                <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider">Action</th>
                <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider">Resource</th>
                <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider">IP Address</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {loading ? (
                <tr>
                  <td colSpan={4} className="px-4 py-6 text-center text-xs text-text-muted">
                    Loading...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-6 text-center text-xs text-text-muted">
                    No audit logs found.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-bg-hover transition-colors">
                    <td className="px-4 py-2.5">
                      <span className="text-xs text-text-secondary font-mono">
                        {formatDate(log.created_at)}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="text-xs text-text-primary">{log.action}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="text-xs text-text-secondary">
                        {log.resource_type || "—"}
                        {log.resource_id ? ` (${log.resource_id.slice(0, 8)}...)` : ""}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="text-xs text-text-secondary font-mono">
                        {log.ip_address || "—"}
                      </span>
                    </td>
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
              className="px-3 py-1 text-xs border border-border rounded text-text-secondary hover:bg-bg-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              Previous
            </button>
            <span className="text-xs text-text-muted">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-3 py-1 text-xs border border-border rounded text-text-secondary hover:bg-bg-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
