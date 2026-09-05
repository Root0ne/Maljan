"use client";

import { Suspense, useState, useRef, useCallback, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import type { SampleDTO, SandboxReportDTO } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { formatDateTime } from "@/lib/report-utils";
import { useProviderChoices } from "./useProviderChoices";

/* ── Display interface (maps from SampleDTO) ───────── */
interface SampleRow {
  id: string;
  filename: string;
  sha256: string;
  file_size: number;
  created_at: string;
}

function mapSample(s: SampleDTO): SampleRow {
  return {
    id: s.id,
    filename: s.original_filename,
    sha256: s.sha256,
    file_size: s.file_size_bytes,
    created_at: s.uploaded_at,
  };
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function SamplesPageContent() {
  const { staticProviders, sandboxProviders } = useProviderChoices();
  const [samples, setSamples] = useState<SampleRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [detailSample, setDetailSample] = useState<SampleDTO | null>(null);
  /* audit 2026-07-26 (T5 + §4): native alert() replaced by the same in-page
   * banner + toast pattern jobs/page.tsx uses, and the previously silent
   * deep-link failure now reports itself here too. */
  const [actionError, setActionError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  /* ── Task 22: the submit dialog ─────────────────────── */
  const [submitFor, setSubmitFor] = useState<SampleRow | null>(null);
  const [staticProvider, setStaticProvider] = useState("");
  const [sandboxProvider, setSandboxProvider] = useState("");
  const [attachedReport, setAttachedReport] = useState<SandboxReportDTO | null>(null);
  const [reportUploading, setReportUploading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const firstFieldRef = useRef<HTMLSelectElement>(null);
  /* M9 (final review): the target sample of the *in-flight* report upload,
   * updated synchronously (a ref, not state) wherever the dialog's target
   * sample changes — opened, reopened for a different sample, or closed —
   * so a response that resolves after the target moved on can tell it is
   * stale instead of attaching the previous sample's report to this one. */
  const activeSubmitSampleIdRef = useRef<string | null>(null);

  const resetSubmitDialogFields = useCallback(() => {
    setStaticProvider("");
    setSandboxProvider("");
    setAttachedReport(null);
    setReportError(null);
    setSubmitError(null);
  }, []);

  const openSubmitDialog = useCallback(
    (sample: SampleRow) => {
      activeSubmitSampleIdRef.current = sample.id;
      resetSubmitDialogFields();
      setSubmitFor(sample);
    },
    [resetSubmitDialogFields]
  );

  const closeSubmitDialog = useCallback(() => {
    activeSubmitSampleIdRef.current = null;
    setSubmitFor(null);
    resetSubmitDialogFields();
  }, [resetSubmitDialogFields]);

  async function handleReportChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file || !submitFor) return;
    const requestSampleId = submitFor.id;
    setReportUploading(true);
    setReportError(null);
    try {
      const report = await api.uploadSandboxReport(requestSampleId, file);
      // The dialog may have closed, or reopened for a different sample,
      // while this request was in flight — a stale response must not
      // attach the previous sample's report to whatever is open now.
      if (activeSubmitSampleIdRef.current !== requestSampleId) return;
      setAttachedReport(report);
    } catch (err) {
      if (activeSubmitSampleIdRef.current !== requestSampleId) return;
      setReportError(getErrorMessage(err) || "Failed to upload the report.");
    } finally {
      if (activeSubmitSampleIdRef.current === requestSampleId) setReportUploading(false);
    }
  }

  async function startAnalysis(sampleId: string) {
    setSubmitting(true);
    setSubmitError(null);
    try {
      // Omitted keys mean "inherit from settings", so a submission that
      // touches nothing sends the payload this page has always sent.
      const config: Record<string, unknown> = {};
      if (staticProvider) config.static_provider = staticProvider;
      if (attachedReport) {
        config.sandbox_report_id = attachedReport.id;
        config.sandbox_provider = "upload";
      } else if (sandboxProvider) {
        config.sandbox_provider = sandboxProvider;
      }
      const job = await api.createJob(
        sampleId,
        Object.keys(config).length > 0 ? config : undefined
      );
      window.location.href = `/analysis/${job.id}/live`;
    } catch (err) {
      setSubmitError(getErrorMessage(err) || "Failed to start analysis.");
      setSubmitting(false);
    }
  }
  const searchParams = useSearchParams();
  const sampleParam = searchParams.get("sample");

  /* Fetch real samples on mount */
  useEffect(() => {
    (async () => {
      try {
        const res = await api.getSamples();
        setSamples(res.items.map(mapSample));
      } catch (err) {
        setError(getErrorMessage(err) || "Failed to load samples.");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(t);
  }, [toast]);

  /* Deep-link: open the detail modal when ?sample={id} is present. */
  useEffect(() => {
    if (!sampleParam) return;
    let cancelled = false;
    (async () => {
      try {
        const detail = await api.getSample(sampleParam);
        if (!cancelled) setDetailSample(detail);
      } catch (err) {
        if (!cancelled) {
          setActionError(
            `Could not open the linked sample ${sampleParam.slice(0, 12)}: ${getErrorMessage(err)}`,
          );
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [sampleParam]);

  const handleUpload = useCallback(async (file: File) => {
    setUploading(true);
    setActionError(null);
    try {
      await api.uploadSample(file);
      const res = await api.getSamples();
      setSamples(res.items.map(mapSample));
      setToast(`Uploaded ${file.name}.`);
    } catch (err) {
      setActionError(`Upload failed: ${getErrorMessage(err) || "Unknown error"}`);
    } finally {
      setUploading(false);
    }
  }, []);

  /* Escape closes the detail modal (pattern copied from SearchPalette). */
  useEffect(() => {
    if (!detailSample) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      setDetailSample(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [detailSample]);

  /* Escape closes the submit dialog, and focus lands on its first field. */
  useEffect(() => {
    if (!submitFor) return;
    firstFieldRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      closeSubmitDialog();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [submitFor, closeSubmitDialog]);

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleUpload(file);
  };

  if (loading) {
    return (
      <div className="animate-pulse space-y-6">
        <div className="h-32 bg-bg-surface border border-border rounded" />
        <div className="bg-bg-surface border border-border rounded">
          <div className="h-10 border-b border-border" />
          <div className="p-4 space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-10 bg-bg-active rounded" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div role="alert" className="p-4 text-sm text-status-red bg-status-red/10 border border-status-red/20 rounded">
        {error}
      </div>
    );
  }

  return (
    <div>
      {actionError && (
        <div
          role="alert"
          className="mb-4 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded px-2 py-1.5"
        >
          {actionError}
        </div>
      )}
      {toast && (
        <div className="mb-4 text-xs text-status-green bg-status-green/10 border border-status-green/20 rounded px-2 py-1.5">
          {toast}
        </div>
      )}

      {/* Upload Area */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        onClick={() => fileRef.current?.click()}
        className={`mb-6 border border-dashed rounded p-6 text-center cursor-pointer transition-colors ${
          dragOver
            ? "border-accent bg-accent/5"
            : "border-border hover:border-text-muted"
        }`}
      >
        <svg
          className="mx-auto mb-2 text-text-muted"
          width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"
        >
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="17 8 12 3 7 8" />
          <line x1="12" y1="3" x2="12" y2="15" />
        </svg>
        <p className="text-sm text-text-secondary">
          {uploading
            ? "Uploading..."
            : "Drop a file here or click to upload"}
        </p>
        <p className="text-xs text-text-muted mt-1">
          PE, ELF, Mach-O, scripts, documents
        </p>
        <input
          ref={fileRef}
          type="file"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleUpload(file);
          }}
        />
      </div>

      {/* Samples Table */}
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Samples &mdash; {samples.length} files
          </h2>
        </div>
        {samples.length === 0 ? (
          <div className="px-4 py-8 text-center text-xs text-text-muted">
            No samples uploaded yet.
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider">Filename</th>
                <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider">SHA256</th>
                <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-24">Size</th>
                <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-36">Uploaded</th>
                <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-32">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {samples.map((s) => (
                <tr key={s.id} className="hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-2.5">
                    <span className="text-sm text-text-primary">{s.filename}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <code className="text-xs text-text-secondary font-mono">
                      {s.sha256.slice(0, 16)}...
                    </code>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-xs text-text-secondary">{formatSize(s.file_size)}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-xs text-text-secondary">{formatDateTime(s.created_at)}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-1.5">
                      <button
                        onClick={async () => {
                          setActionError(null);
                          try {
                            const detail = await api.getSample(s.id);
                            setDetailSample(detail);
                          } catch (err) {
                            setActionError(getErrorMessage(err) || "Failed to load sample details.");
                          }
                        }}
                        className="px-2.5 py-1 text-xs border border-border text-text-secondary rounded hover:bg-bg-hover transition-colors"
                      >
                        Details
                      </button>
                      <button
                        onClick={() => {
                          setActionError(null);
                          openSubmitDialog(s);
                        }}
                        className="px-2.5 py-1 text-xs bg-accent text-white rounded hover:bg-accent-hover transition-colors"
                      >
                        Analyze
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Sample Detail Modal */}
      {detailSample && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={() => setDetailSample(null)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="sample-detail-title"
            className="bg-bg-surface border border-border rounded w-full max-w-lg p-5 shadow-lg"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 id="sample-detail-title" className="text-sm font-semibold text-text-primary">Sample Details</h3>
              <button
                type="button"
                aria-label="Close"
                onClick={() => setDetailSample(null)}
                className="text-text-muted hover:text-text-primary"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>
            <div className="space-y-3 text-xs">
              <div>
                <span className="text-text-muted uppercase tracking-wider">Filename</span>
                <p className="text-text-primary mt-0.5">{detailSample.original_filename}</p>
              </div>
              <div>
                <span className="text-text-muted uppercase tracking-wider">SHA-256</span>
                <code className="block text-text-secondary font-mono mt-0.5 break-all">{detailSample.sha256}</code>
              </div>
              {detailSample.md5 && (
                <div>
                  <span className="text-text-muted uppercase tracking-wider">MD5</span>
                  <code className="block text-text-secondary font-mono mt-0.5 break-all">{detailSample.md5}</code>
                </div>
              )}
              <div className="flex gap-6">
                <div>
                  <span className="text-text-muted uppercase tracking-wider">Size</span>
                  <p className="text-text-primary mt-0.5">{formatSize(detailSample.file_size_bytes)}</p>
                </div>
                {detailSample.mime_type && (
                  <div>
                    <span className="text-text-muted uppercase tracking-wider">MIME Type</span>
                    <p className="text-text-primary mt-0.5">{detailSample.mime_type}</p>
                  </div>
                )}
              </div>
              <div>
                <span className="text-text-muted uppercase tracking-wider">Uploaded</span>
                <p className="text-text-primary mt-0.5">{formatDateTime(detailSample.uploaded_at)}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Submit-analysis dialog */}
      {submitFor && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={closeSubmitDialog}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="submit-analysis-title"
            className="bg-bg-surface border border-border rounded w-full max-w-lg p-5 shadow-lg"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 id="submit-analysis-title" className="text-sm font-semibold text-text-primary">
                Analyze {submitFor.filename}
              </h3>
              <button
                type="button"
                aria-label="Close"
                onClick={closeSubmitDialog}
                className="text-text-muted hover:text-text-primary"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            <div className="space-y-4 text-xs">
              {submitError && (
                <div
                  role="alert"
                  className="text-status-red bg-status-red/10 border border-status-red/20 rounded px-2 py-1.5"
                >
                  {submitError}
                </div>
              )}

              <div>
                <label htmlFor="static-provider" className="block text-text-muted uppercase tracking-wider mb-1">
                  Static provider
                </label>
                <select
                  id="static-provider"
                  ref={firstFieldRef}
                  value={staticProvider}
                  onChange={(e) => setStaticProvider(e.target.value)}
                  className="w-full border border-border rounded px-2 py-1.5 bg-bg-surface text-text-primary"
                >
                  <option value="">Inherit from settings</option>
                  {staticProviders.map((p) => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="sandbox-provider" className="block text-text-muted uppercase tracking-wider mb-1">
                  Sandbox provider
                </label>
                <select
                  id="sandbox-provider"
                  value={sandboxProvider}
                  onChange={(e) => setSandboxProvider(e.target.value)}
                  disabled={!!attachedReport}
                  className="w-full border border-border rounded px-2 py-1.5 bg-bg-surface text-text-primary disabled:opacity-50"
                >
                  <option value="">Inherit from settings</option>
                  {sandboxProviders.map((p) => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
                {attachedReport && (
                  <p className="text-text-muted mt-1">
                    Sandbox: upload (from the attached report)
                  </p>
                )}
              </div>

              <div>
                <label htmlFor="sandbox-report" className="block text-text-muted uppercase tracking-wider mb-1">
                  Attach sandbox report
                </label>
                <input
                  id="sandbox-report"
                  type="file"
                  accept=".json,.json.gz"
                  onChange={handleReportChange}
                  disabled={reportUploading}
                  className="w-full text-text-secondary"
                />
                {reportUploading && (
                  <p className="text-text-muted mt-1">Uploading...</p>
                )}
                {reportError && (
                  <p className="text-status-red mt-1">{reportError}</p>
                )}
                {attachedReport && (
                  <p className="text-text-secondary mt-1">
                    {attachedReport.format} · task {attachedReport.task_id ?? "unknown"}
                  </p>
                )}
                {attachedReport && !attachedReport.sample_sha256_match && attachedReport.warning && (
                  <div
                    role="alert"
                    className="mt-2 text-status-red bg-status-red/10 border border-status-red/20 rounded px-2 py-1.5"
                  >
                    {attachedReport.warning}
                  </div>
                )}
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={closeSubmitDialog}
                  className="px-2.5 py-1 text-xs border border-border text-text-secondary rounded hover:bg-bg-hover transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={submitting}
                  onClick={() => startAnalysis(submitFor.id)}
                  className="px-2.5 py-1 text-xs bg-accent text-white rounded hover:bg-accent-hover transition-colors disabled:opacity-50"
                >
                  Start analysis
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* useSearchParams requires a Suspense boundary for prerendering
   (missing-suspense-with-csr-bailout). */
export default function SamplesPage() {
  return (
    <Suspense fallback={null}>
      <SamplesPageContent />
    </Suspense>
  );
}
