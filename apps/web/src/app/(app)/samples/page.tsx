"use client";

import { useState, useRef, useCallback, useEffect } from "react";
import { api } from "@/lib/api";
import type { SampleDTO } from "@/lib/api";

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

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function SamplesPage() {
  const [samples, setSamples] = useState<SampleRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [detailSample, setDetailSample] = useState<SampleDTO | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  /* Fetch real samples on mount */
  useEffect(() => {
    (async () => {
      try {
        const res = await api.getSamples();
        setSamples(res.items.map(mapSample));
      } catch (err: any) {
        setError(err.message || "Failed to load samples.");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const handleUpload = useCallback(async (file: File) => {
    setUploading(true);
    try {
      await api.uploadSample(file);
      const res = await api.getSamples();
      setSamples(res.items.map(mapSample));
    } catch (error: any) {
      alert(`Upload failed: ${error.message || "Unknown error"}`);
    } finally {
      setUploading(false);
    }
  }, []);

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
      <div className="p-4 text-sm text-status-red bg-status-red/10 border border-status-red/20 rounded">
        {error}
      </div>
    );
  }

  return (
    <div>
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
                <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-20">Size</th>
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
                    <span className="text-xs text-text-secondary">{formatDate(s.created_at)}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-1.5">
                      <button
                        onClick={async () => {
                          try {
                            const detail = await api.getSample(s.id);
                            setDetailSample(detail);
                          } catch (err: any) {
                            alert(err.message || "Failed to load sample details.");
                          }
                        }}
                        className="px-2.5 py-1 text-xs border border-border text-text-secondary rounded hover:bg-bg-hover transition-colors"
                      >
                        Details
                      </button>
                      <button
                        onClick={async () => {
                          try {
                            const job = await api.createJob(s.id);
                            window.location.href = `/analysis/${job.id}/live`;
                          } catch (err: any) {
                            alert(err.message || "Failed to start analysis.");
                          }
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
            className="bg-bg-surface border border-border rounded w-full max-w-lg p-5 shadow-lg"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-text-primary">Sample Details</h3>
              <button
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
                <p className="text-text-primary mt-0.5">{formatDate(detailSample.uploaded_at)}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
