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

  // General tab form state
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

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
        .then((me) => {
          setUser(me);
          setFullName(me.full_name || "");
        })
        .catch((err: unknown) => {
          const msg = err instanceof Error ? err.message : "Failed to load user profile.";
          setUserError(msg);
        })
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
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : "Failed to load API keys.";
        setApiKeysError(msg);
      })
      .finally(() => setApiKeysLoading(false));
  }

  const passwordsMatch = password === passwordConfirm;
  const passwordRequested = password.length > 0 || passwordConfirm.length > 0;
  const passwordValid = !passwordRequested || (password.length >= 8 && passwordsMatch);
  const canSave = !saving && !!user && passwordValid;

  async function handleSaveProfile(e: React.FormEvent) {
    e.preventDefault();
    if (!user) return;
    if (passwordRequested && !passwordsMatch) return;

    setSaving(true);
    setSaveSuccess(null);
    setSaveError(null);

    const body: { full_name?: string; password?: string } = {};
    if (fullName !== user.full_name) {
      body.full_name = fullName;
    }
    if (passwordRequested) {
      body.password = password;
    }

    if (Object.keys(body).length === 0) {
      setSaving(false);
      setSaveSuccess("No changes to save.");
      return;
    }

    try {
      const updated = await api.updateMe(body);
      setUser({ full_name: updated.full_name, email: updated.email });
      setFullName(updated.full_name);
      setPassword("");
      setPasswordConfirm("");
      setSaveSuccess("Profile updated successfully.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to update profile.";
      setSaveError(msg);
    } finally {
      setSaving(false);
    }
  }

  async function handleCreateKey(e: React.FormEvent) {
    e.preventDefault();
    if (!newKeyName.trim()) return;
    try {
      const key = await api.createApiKey(newKeyName.trim());
      setCreatedKey(key);
      setNewKeyName("");
      loadApiKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to create API key.";
      alert(msg);
    }
  }

  async function handleRevokeKey(keyId: string) {
    if (!confirm("Revoke this API key? It cannot be undone.")) return;
    try {
      await api.revokeApiKey(keyId);
      loadApiKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to revoke API key.";
      alert(msg);
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
                <form onSubmit={handleSaveProfile} className="space-y-4">
                  <div>
                    <label className="block text-xs text-text-secondary mb-1.5">Full Name</label>
                    <input
                      type="text"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
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

                  <div className="pt-2 border-t border-border">
                    <h3 className="text-xs font-medium text-text-primary uppercase tracking-wider mb-3">
                      Change password (optional)
                    </h3>
                    <div className="space-y-3">
                      <div>
                        <label className="block text-xs text-text-secondary mb-1.5">New password</label>
                        <input
                          type="password"
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          autoComplete="new-password"
                          minLength={8}
                          className="w-full h-9 px-3 text-sm bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
                        />
                        {passwordRequested && password.length > 0 && password.length < 8 && (
                          <p className="mt-1 text-xs text-status-red">Must be at least 8 characters.</p>
                        )}
                      </div>
                      <div>
                        <label className="block text-xs text-text-secondary mb-1.5">Confirm new password</label>
                        <input
                          type="password"
                          value={passwordConfirm}
                          onChange={(e) => setPasswordConfirm(e.target.value)}
                          autoComplete="new-password"
                          className="w-full h-9 px-3 text-sm bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
                        />
                        {passwordRequested && !passwordsMatch && (
                          <p className="mt-1 text-xs text-status-red">Passwords do not match.</p>
                        )}
                      </div>
                    </div>
                  </div>

                  {saveSuccess && (
                    <div className="p-3 bg-status-green/10 border border-status-green/20 rounded">
                      <p className="text-xs text-status-green font-medium">{saveSuccess}</p>
                    </div>
                  )}
                  {saveError && (
                    <div className="p-3 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded">
                      {saveError}
                    </div>
                  )}

                  <div className="flex justify-end pt-2">
                    <button
                      type="submit"
                      disabled={!canSave}
                      className="h-9 px-4 text-xs bg-accent text-white rounded hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {saving ? "Saving..." : "Save changes"}
                    </button>
                  </div>
                </form>
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
