"use client";

import { useState } from "react";

import { useReport } from "../layout";
import { copyToClipboard, formatBytes } from "@/lib/report-utils";
import type { SampleIdentity } from "@/types/malware-report";

export default function IdentityTab() {
  const { report, loading } = useReport();

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  const identity: SampleIdentity | undefined = report?.malware_report?.identity;
  if (!identity) {
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        No identity payload available for this report.
      </div>
    );
  }

  const sig = identity.signing;
  const sigState = sig.is_signed
    ? sig.signature_valid === false
      ? { label: "SIGNED (INVALID)", cls: "text-status-red bg-status-red/10 border-status-red/30" }
      : { label: "SIGNED", cls: "text-status-green bg-status-green/10 border-status-green/30" }
    : { label: "UNSIGNED", cls: "text-text-muted bg-bg-active border-border" };

  return (
    <div className="space-y-4">
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Sample Identification
          </h2>
          <span
            className={`text-[10px] uppercase tracking-wider font-medium px-2 py-0.5 rounded border ${sigState.cls}`}
          >
            {sigState.label}
          </span>
        </div>
        <div className="p-4 grid grid-cols-2 gap-4">
          <Field label="File Name" value={identity.file_name || "(unknown)"} />
          <Field label="File Type" value={identity.file_type} />
          <Field
            label="Platform"
            value={
              identity.platform && identity.platform !== "unknown"
                ? identity.platform.toUpperCase()
                : "(unknown)"
            }
          />
          <Field label="Size" value={formatBytes(identity.file_size_bytes)} />
          <Field label="MIME Type" value={identity.mime_type || "(unknown)"} />
          <Field
            label="Compile Timestamp"
            value={
              identity.compile_timestamp
                ? new Date(identity.compile_timestamp).toLocaleString()
                : "(unknown)"
            }
          />
          <Field
            label="Language / Compiler"
            value={identity.language_or_compiler || "(unknown)"}
          />
        </div>
      </div>

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            File Hashes
          </h2>
        </div>
        <div className="p-4 space-y-2">
          <HashRow label="MD5" value={identity.hashes.md5} />
          <HashRow label="SHA-1" value={identity.hashes.sha1} />
          <HashRow label="SHA-256" value={identity.hashes.sha256} />
          <HashRow label="SHA-512" value={identity.hashes.sha512} />
          <HashRow label="Imphash" value={identity.hashes.imphash} />
          <HashRow label="SSDeep" value={identity.hashes.ssdeep} />
          <HashRow label="TLSH" value={identity.hashes.tlsh} />
        </div>
      </div>

      {identity.signing.is_signed && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Code Signing
            </h2>
          </div>
          <div className="p-4 grid grid-cols-2 gap-4">
            <Field label="Signer Subject" value={identity.signing.signer_subject || "-"} />
            <Field label="Issuer" value={identity.signing.signer_issuer || "-"} />
            <Field
              label="Signature Valid"
              value={
                identity.signing.signature_valid === null
                  ? "unverified"
                  : identity.signing.signature_valid
                    ? "yes"
                    : "no"
              }
            />
          </div>
        </div>
      )}

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Magic Bytes (first 16)
          </h2>
        </div>
        <div className="p-4">
          {identity.magic_bytes ? (
            <code className="block font-mono text-xs text-status-blue break-all">
              {identity.magic_bytes}
            </code>
          ) : (
            <span className="text-xs text-text-muted">(no magic bytes captured)</span>
          )}
        </div>
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] text-text-muted uppercase tracking-wider mb-1">
        {label}
      </div>
      <div className="text-sm text-text-primary break-all">{value}</div>
    </div>
  );
}

function HashRow({ label, value }: { label: string; value: string | null }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-3">
      <span className="text-[10px] text-text-muted uppercase tracking-wider w-20 shrink-0">
        {label}
      </span>
      {value ? (
        <>
          <code className="flex-1 font-mono text-xs text-status-blue truncate" title={value}>
            {value}
          </code>
          <button
            onClick={async () => {
              if (await copyToClipboard(value)) {
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              }
            }}
            className="text-[10px] px-2 py-0.5 border border-border rounded text-text-secondary hover:text-text-primary hover:border-text-muted transition-colors"
          >
            {copied ? "copied" : "copy"}
          </button>
        </>
      ) : (
        <span className="text-xs text-text-muted">-</span>
      )}
    </div>
  );
}
