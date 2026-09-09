"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { ApiKeyDTO, ApiKeyCreateDTO } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { formatDateTime } from "@/lib/report-utils";

export default function SettingsApiKeysPage() {
  const [apiKeys, setApiKeys] = useState<ApiKeyDTO[]>([]);
  const [apiKeysLoading, setApiKeysLoading] = useState(false);
  const [apiKeysError, setApiKeysError] = useState<string | null>(null);
  const [newKeyName, setNewKeyName] = useState("");
  const [createdKey, setCreatedKey] = useState<ApiKeyCreateDTO | null>(null);
  /* audit 2026-07-26 (T5): native alert()/confirm() replaced by the in-page
   * banner + toast + confirm-modal pattern already used by jobs/page.tsx. */
  const [keyActionError, setKeyActionError] = useState<string | null>(null);
  const [keyToast, setKeyToast] = useState<string | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<ApiKeyDTO | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "unavailable">("idle");

  useEffect(() => {
    if (!keyToast) return;
    const t = setTimeout(() => setKeyToast(null), 4000);
    return () => clearTimeout(t);
  }, [keyToast]);

  /* Escape closes the revoke dialog (pattern copied from SearchPalette). */
  useEffect(() => {
    if (!confirmRevoke) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      if (revoking) return;
      setConfirmRevoke(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [confirmRevoke, revoking]);

  useEffect(() => {
    if (!copyState || copyState === "idle") return;
    if (copyState !== "copied") return;
    const t = setTimeout(() => setCopyState("idle"), 2000);
    return () => clearTimeout(t);
  }, [copyState]);

  useEffect(() => {
    loadApiKeys();
  }, []);

  function loadApiKeys() {
    setApiKeysLoading(true);
    setApiKeysError(null);
    api.getApiKeys(1, 50)
      .then((res) => setApiKeys(res.items))
      .catch((err: unknown) => {
        setApiKeysError(getErrorMessage(err) || "Failed to load API keys.");
      })
      .finally(() => setApiKeysLoading(false));
  }

  async function handleCreateKey(e: React.FormEvent) {
    e.preventDefault();
    if (!newKeyName.trim()) return;
    setKeyActionError(null);
    try {
      const key = await api.createApiKey(newKeyName.trim());
      setCreatedKey(key);
      setCopyState("idle");
      setNewKeyName("");
      loadApiKeys();
    } catch (err: unknown) {
      setKeyActionError(getErrorMessage(err) || "Failed to create API key.");
    }
  }

  async function handleCopyKey(key: string) {
    try {
      if (!navigator.clipboard) throw new Error("Clipboard API unavailable.");
      await navigator.clipboard.writeText(key);
      setCopyState("copied");
    } catch {
      setCopyState("unavailable");
    }
  }

  async function handleConfirmRevoke() {
    if (!confirmRevoke) return;
    setRevoking(true);
    setKeyActionError(null);
    try {
      await api.revokeApiKey(confirmRevoke.id);
      setKeyToast(`API key "${confirmRevoke.name}" revoked.`);
      setConfirmRevoke(null);
      loadApiKeys();
    } catch (err: unknown) {
      setKeyActionError(getErrorMessage(err) || "Failed to revoke API key.");
    } finally {
      setRevoking(false);
    }
  }

  function closeRevokeModal() {
    if (revoking) return;
    setConfirmRevoke(null);
  }

  return (
    <div className="space-y-4 max-w-3xl">
      {/* Create new key */}
      <div className="bg-bg-surface border border-border rounded p-4">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider mb-3">
          Create API Key
        </h2>
        <form onSubmit={handleCreateKey} className="flex items-end gap-2">
          <div className="flex-1">
            <label htmlFor="settings-api-key-name" className="block text-xs text-text-secondary mb-1.5">
              Key name
            </label>
            <input
              id="settings-api-key-name"
              name="api_key_name"
              type="text"
              placeholder="Key name (e.g., CI/CD integration)"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              className="w-full h-9 px-3 text-sm bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
            />
          </div>
          <button
            type="submit"
            className="h-9 px-4 text-xs bg-accent text-white rounded hover:bg-accent-hover transition-colors"
          >
            Create
          </button>
        </form>
        {createdKey && (
          <div className="mt-3 p-3 bg-status-green/10 border border-status-green/20 rounded">
            <p className="text-xs text-status-green font-medium mb-1">API key created successfully. Copy it now — it will not be shown again.</p>
            <div className="flex items-start gap-2">
              <code className="flex-1 text-xs font-mono text-text-primary bg-bg-deep px-2 py-1 rounded block break-all">
                {createdKey.raw_key}
              </code>
              <button
                type="button"
                onClick={() => handleCopyKey(createdKey.raw_key)}
                className="shrink-0 h-7 px-2 text-xs text-text-secondary border border-border rounded hover:text-text-primary transition-colors"
              >
                {copyState === "copied" ? "Copied" : "Copy"}
              </button>
            </div>
            {copyState === "unavailable" && (
              <p className="mt-1 text-xs text-status-orange">Select and copy the key</p>
            )}
            <button
              onClick={() => {
                setCreatedKey(null);
                setCopyState("idle");
              }}
              className="mt-2 text-xs text-text-secondary hover:text-text-primary"
            >
              Dismiss
            </button>
          </div>
        )}
      </div>

      {keyActionError && (
        <div
          role="alert"
          className="text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded px-2 py-1.5"
        >
          {keyActionError}
        </div>
      )}
      {keyToast && (
        <div className="text-xs text-status-green bg-status-green/10 border border-status-green/20 rounded px-2 py-1.5">
          {keyToast}
        </div>
      )}

      {apiKeysError && (
        <div role="alert" className="p-3 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded">
          {apiKeysError}
        </div>
      )}

      {/* Key list */}
      {apiKeysLoading ? (
        <div className="text-xs text-text-muted">Loading API keys...</div>
      ) : apiKeysError ? (
        /* Same trap as /audit: "No API keys found." used to render right
         * under the error banner, so a failed fetch looked like an account
         * that simply has no keys. */
        <div className="text-xs text-text-muted">
          Keys could not be loaded — see the message above.
        </div>
      ) : apiKeys.length === 0 ? (
        <div className="text-xs text-text-muted">No API keys found.</div>
      ) : (
        <div className="space-y-3">
          {apiKeys.map((key) => (
            <div key={key.id} className="bg-bg-surface border border-border rounded">
              <div className="flex items-center justify-between p-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-sm font-medium text-text-primary">{key.name}</span>
                    <span
                      className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-xs rounded ${
                        key.is_active
                          ? "bg-status-green/10 text-status-green"
                          : "bg-status-red/10 text-status-red"
                      }`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${key.is_active ? "bg-status-green" : "bg-status-red"}`} />
                      {key.is_active ? "Active" : "Revoked"}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs text-text-muted font-mono bg-bg-deep px-1.5 py-0.5 rounded">
                      {key.key_prefix}***
                    </span>
                    <span className="text-xs text-text-muted">Created {formatDateTime(key.created_at)}</span>
                    {key.expires_at && (
                      <span className="text-xs text-status-orange">Expires {formatDateTime(key.expires_at)}</span>
                    )}
                  </div>
                </div>
                <div className="flex gap-2 ml-4 shrink-0">
                  {key.is_active && (
                    <button
                      onClick={() => {
                        setKeyActionError(null);
                        setConfirmRevoke(key);
                      }}
                      className="h-7 px-3 text-xs text-text-secondary border border-border rounded hover:text-status-red hover:border-status-red/30 transition-colors"
                    >
                      Revoke
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Revoke Confirmation Modal */}
      {confirmRevoke && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={closeRevokeModal}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="revoke-key-title"
            className="bg-bg-surface border border-border rounded w-full max-w-md p-5 shadow-lg"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 id="revoke-key-title" className="text-sm font-semibold text-text-primary">Revoke API Key</h3>
              <button
                type="button"
                aria-label="Close"
                onClick={closeRevokeModal}
                disabled={revoking}
                className="text-text-muted hover:text-text-primary disabled:text-text-disabled"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>
            <p className="text-sm text-text-secondary mb-4 leading-relaxed">
              Revoke &ldquo;{confirmRevoke.name}&rdquo;? Anything still using this key will
              stop working. Cannot be undone.
            </p>
            {keyActionError && (
              <div role="alert" className="mb-3 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded px-2 py-1.5">
                {keyActionError}
              </div>
            )}
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={closeRevokeModal}
                disabled={revoking}
                className="px-3 py-1 text-xs border border-border text-text-secondary rounded hover:bg-bg-hover transition-colors disabled:text-text-disabled"
              >
                Keep it
              </button>
              <button
                type="button"
                onClick={handleConfirmRevoke}
                disabled={revoking}
                className="px-3 py-1 text-xs bg-status-red text-bg-deep rounded hover:bg-status-red/90 transition-colors disabled:opacity-50"
              >
                {revoking ? "Revoking..." : "Revoke key"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
