"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { ApiKeyDTO, ApiKeyCreateDTO } from "@/lib/api";

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<"general" | "apikeys">("general");

  // General tab state
  const [user, setUser] = useState<{ full_name: string; email: string } | null>(null);
  const [userLoading, setUserLoading] = useState(false);
  const [userError, setUserError] = useState<string | null>(null);

  // API Keys tab state
  const [apiKeys, setApiKeys] = useState<ApiKeyDTO[]>([]);
  const [apiKeysLoading, setApiKeysLoading] = useState(false);
  const [apiKeysError, setApiKeysError] = useState<string | null>(null);
  const [newKeyName, setNewKeyName] = useState("");
  const [createdKey, setCreatedKey] = useState<ApiKeyCreateDTO | null>(null);

  const tabs = [
    { key: "general" as const, label: "General" },
    { key: "apikeys" as const, label: "API Keys" },
  ];

  useEffect(() => {
    if (activeTab === "general") {
      setUserLoading(true);
      setUserError(null);
      api.getMe()
        .then((me) => setUser(me))
        .catch((err: any) => setUserError(err.message || "Failed to load user profile."))
        .finally(() => setUserLoading(false));
    }
    if (activeTab === "apikeys") {
      loadApiKeys();
    }
  }, [activeTab]);

  function loadApiKeys() {
    setApiKeysLoading(true);
    setApiKeysError(null);
    api.getApiKeys(1, 50)
      .then((res) => setApiKeys(res.items))
      .catch((err: any) => setApiKeysError(err.message || "Failed to load API keys."))
      .finally(() => setApiKeysLoading(false));
  }

  async function handleCreateKey(e: React.FormEvent) {
    e.preventDefault();
    if (!newKeyName.trim()) return;
    try {
      const key = await api.createApiKey(newKeyName.trim());
      setCreatedKey(key);
      setNewKeyName("");
      loadApiKeys();
    } catch (err: any) {
      alert(err.message || "Failed to create API key.");
    }
  }

  async function handleRevokeKey(keyId: string) {
    if (!confirm("Revoke this API key? It cannot be undone.")) return;
    try {
      await api.revokeApiKey(keyId);
      loadApiKeys();
    } catch (err: any) {
      alert(err.message || "Failed to revoke API key.");
    }
  }

  function formatDate(iso: string | null) {
    if (!iso) return "Never";
    return new Date(iso).toLocaleDateString("en-US", {
      month: "short", day: "numeric", year: "numeric",
    });
  }

  return (
    <div>
      <h1 className="text-lg font-semibold text-text-primary mb-4">Settings</h1>

      {/* Tab Bar */}
      <div className="flex border-b border-border mb-6">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2.5 text-xs font-medium uppercase tracking-wider border-b-2 transition-colors ${
              activeTab === tab.key
                ? "border-accent text-accent"
                : "border-transparent text-text-secondary hover:text-text-primary"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* General Tab */}
      {activeTab === "general" && (
        <div className="space-y-4 max-w-2xl">
          <div className="bg-bg-surface border border-border rounded">
            <div className="px-4 py-3 border-b border-border">
              <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
                User Profile
              </h2>
            </div>
            <div className="p-4 space-y-4">
              {userLoading ? (
                <div className="text-xs text-text-muted">Loading...</div>
              ) : userError ? (
                <div className="text-xs text-status-red">{userError}</div>
              ) : user ? (
                <>
                  <div>
                    <label className="block text-xs text-text-secondary mb-1.5">Full Name</label>
                    <input
                      type="text"
                      defaultValue={user.full_name || ""}
                      readOnly
                      className="w-full h-9 px-3 text-sm bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-text-secondary mb-1.5">Email</label>
                    <input
                      type="email"
                      defaultValue={user.email || ""}
                      readOnly
                      className="w-full h-9 px-3 text-sm bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
                    />
                  </div>
                </>
              ) : (
                <div className="text-xs text-text-muted">No user data available.</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* API Keys Tab */}
      {activeTab === "apikeys" && (
        <div className="space-y-4 max-w-3xl">
          {/* Create new key */}
          <div className="bg-bg-surface border border-border rounded p-4">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider mb-3">
              Create API Key
            </h2>
            <form onSubmit={handleCreateKey} className="flex gap-2">
              <input
                type="text"
                placeholder="Key name (e.g., CI/CD integration)"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                className="flex-1 h-9 px-3 text-sm bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
              />
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
                <code className="text-xs font-mono text-text-primary bg-bg-deep px-2 py-1 rounded block break-all">
                  {createdKey.raw_key}
                </code>
                <button
                  onClick={() => setCreatedKey(null)}
                  className="mt-2 text-xs text-text-secondary hover:text-text-primary"
                >
                  Dismiss
                </button>
              </div>
            )}
          </div>

          {apiKeysError && (
            <div className="p-3 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded">
              {apiKeysError}
            </div>
          )}

          {/* Key list */}
          {apiKeysLoading ? (
            <div className="text-xs text-text-muted">Loading API keys...</div>
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
                        <span className="text-xs text-text-muted">Created {formatDate(key.created_at)}</span>
                        {key.expires_at && (
                          <span className="text-xs text-status-orange">Expires {formatDate(key.expires_at)}</span>
                        )}
                      </div>
                    </div>
                    <div className="flex gap-2 ml-4 shrink-0">
                      {key.is_active && (
                        <button
                          onClick={() => handleRevokeKey(key.id)}
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
        </div>
      )}
    </div>
  );
}
