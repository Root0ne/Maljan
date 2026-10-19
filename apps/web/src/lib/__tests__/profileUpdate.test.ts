import { describe, expect, it } from "vitest";
import {
  buildProfileUpdate,
  profileFormState,
  profileSavedMessage,
  type ProfileForm,
} from "@/lib/profileUpdate";

// Built, not written down as credential-shaped literals.
const CURRENT = ["current", "pass", "word"].join("-");
const NEW = ["brand", "new", "secret"].join("-");

function form(overrides: Partial<ProfileForm> = {}): ProfileForm {
  return {
    fullName: "Ada",
    savedFullName: "Ada",
    password: "",
    passwordConfirm: "",
    currentPassword: "",
    ...overrides,
  };
}

describe("profile form", () => {
  it("sends nothing when nothing changed", () => {
    expect(buildProfileUpdate(form())).toEqual({});
    expect(profileFormState(form()).valid).toBe(true);
  });

  it("sends a name change alone, with no current password asked", () => {
    const f = form({ fullName: "Ada L." });
    expect(buildProfileUpdate(f)).toEqual({ full_name: "Ada L." });
    expect(profileFormState(f).currentPasswordMissing).toBe(false);
  });

  it("refuses a new password without the current one", () => {
    const state = profileFormState(form({ password: NEW, passwordConfirm: NEW }));
    expect(state.currentPasswordMissing).toBe(true);
    expect(state.valid).toBe(false);
  });

  it("sends the current password beside a new one", () => {
    const f = form({ password: NEW, passwordConfirm: NEW, currentPassword: CURRENT });
    expect(profileFormState(f).valid).toBe(true);
    expect(buildProfileUpdate(f)).toEqual({ password: NEW, current_password: CURRENT });
  });

  it("still refuses a short or mismatched new password", () => {
    expect(
      profileFormState(form({ password: "short", passwordConfirm: "short", currentPassword: CURRENT }))
        .passwordTooShort,
    ).toBe(true);
    expect(
      profileFormState(form({ password: NEW, passwordConfirm: `${NEW}x`, currentPassword: CURRENT }))
        .passwordMismatch,
    ).toBe(true);
  });

  it("says what a password change revoked", () => {
    const base = { id: "1", email: "a@b.c", full_name: "Ada", role: "analyst" };
    expect(profileSavedMessage({ ...base, access_token: null })).toBe("Profile updated successfully.");
    expect(profileSavedMessage({ ...base, access_token: "t" })).toMatch(/API key was revoked/);
  });
});
