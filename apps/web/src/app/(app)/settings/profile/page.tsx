"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";

export default function SettingsProfilePage() {
  const [user, setUser] = useState<{ full_name: string; email: string } | null>(null);
  const [userLoading, setUserLoading] = useState(false);
  const [userError, setUserError] = useState<string | null>(null);

  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    // Legitimate data-fetch initialization
    // for an async API call. The state transitions
    // (loading=true → fetch → setUser + setLoading=false) cannot be
    // derived from props alone — they reflect the in-flight request
    // status, which is the correct use case for setState in an effect.
    setUserLoading(true);
    setUserError(null);
    api.getMe()
      .then((me) => {
        setUser(me);
        setFullName(me.full_name || "");
      })
      .catch((err: unknown) => {
        setUserError(getErrorMessage(err) || "Failed to load user profile.");
      })
      .finally(() => setUserLoading(false));
  }, []);

  const passwordsMatch = password === passwordConfirm;
  const passwordRequested = password.length > 0 || passwordConfirm.length > 0;
  const passwordValid = !passwordRequested || (password.length >= 8 && passwordsMatch);
  // Hoisted so the inputs can point `aria-describedby` at the messages only
  // while they are actually rendered.
  const passwordTooShort = passwordRequested && password.length > 0 && password.length < 8;
  const passwordMismatch = passwordRequested && !passwordsMatch;
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
      setSaveError(getErrorMessage(err) || "Failed to update profile.");
    } finally {
      setSaving(false);
    }
  }

  return (
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
            <div role="alert" className="text-xs text-status-red">{userError}</div>
          ) : user ? (
            <form onSubmit={handleSaveProfile} className="space-y-4">
              <div>
                <label htmlFor="settings-full-name" className="block text-xs text-text-secondary mb-1.5">Full Name</label>
                <input
                  id="settings-full-name"
                  name="full_name"
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  className="w-full h-9 px-3 text-sm bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
                />
              </div>
              <div>
                <label htmlFor="settings-email" className="block text-xs text-text-secondary mb-1.5">Email</label>
                <input
                  id="settings-email"
                  name="email"
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
                    <label htmlFor="settings-new-password" className="block text-xs text-text-secondary mb-1.5">New password</label>
                    <input
                      id="settings-new-password"
                      name="new_password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="new-password"
                      minLength={8}
                      aria-describedby={passwordTooShort ? "settings-new-password-error" : undefined}
                      className="w-full h-9 px-3 text-sm bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
                    />
                    {passwordTooShort && (
                      <p id="settings-new-password-error" className="mt-1 text-xs text-status-red">Must be at least 8 characters.</p>
                    )}
                  </div>
                  <div>
                    <label htmlFor="settings-confirm-password" className="block text-xs text-text-secondary mb-1.5">Confirm new password</label>
                    <input
                      id="settings-confirm-password"
                      name="confirm_password"
                      type="password"
                      value={passwordConfirm}
                      onChange={(e) => setPasswordConfirm(e.target.value)}
                      autoComplete="new-password"
                      aria-describedby={passwordMismatch ? "settings-confirm-password-error" : undefined}
                      className="w-full h-9 px-3 text-sm bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
                    />
                    {passwordMismatch && (
                      <p id="settings-confirm-password-error" className="mt-1 text-xs text-status-red">Passwords do not match.</p>
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
  );
}
