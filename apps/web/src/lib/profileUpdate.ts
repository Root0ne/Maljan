/**
 * The profile form's rules and the body it sends to `PATCH /auth/me`.
 *
 * A new password needs the current one beside it: the API refuses a password
 * change without `current_password` (422) or with a wrong one (400), and a
 * change it accepts revokes every other session and every API key of the
 * account. Kept apart from the page so the rules are tested on their own.
 */

/** The API's minimum (`UserUpdateRequest.password`, `min_length=8`). */
export const PASSWORD_MIN_LENGTH = 8;

export interface ProfileUpdateBody {
  full_name?: string;
  password?: string;
  current_password?: string;
}

export interface ProfileUpdateResponse {
  id: string;
  email: string;
  full_name: string;
  role: string;
  /** This session's replacement after a password change; `null` otherwise. */
  access_token?: string | null;
}

export interface ProfileForm {
  fullName: string;
  savedFullName: string;
  password: string;
  passwordConfirm: string;
  currentPassword: string;
}

export interface ProfileFormState {
  passwordRequested: boolean;
  passwordTooShort: boolean;
  passwordMismatch: boolean;
  currentPasswordMissing: boolean;
  valid: boolean;
}

export function profileFormState(form: ProfileForm): ProfileFormState {
  const passwordRequested = form.password.length > 0 || form.passwordConfirm.length > 0;
  const passwordTooShort =
    passwordRequested && form.password.length > 0 && form.password.length < PASSWORD_MIN_LENGTH;
  const passwordMismatch = passwordRequested && form.password !== form.passwordConfirm;
  const currentPasswordMissing = passwordRequested && form.currentPassword.length === 0;
  const valid =
    !passwordRequested ||
    (form.password.length >= PASSWORD_MIN_LENGTH && !passwordMismatch && !currentPasswordMissing);
  return { passwordRequested, passwordTooShort, passwordMismatch, currentPasswordMissing, valid };
}

/** The changed fields only; a password always travels with the current one. */
export function buildProfileUpdate(form: ProfileForm): ProfileUpdateBody {
  const body: ProfileUpdateBody = {};
  if (form.fullName !== form.savedFullName) {
    body.full_name = form.fullName;
  }
  if (profileFormState(form).passwordRequested) {
    body.password = form.password;
    body.current_password = form.currentPassword;
  }
  return body;
}

/** What the page says after a save the API accepted. */
export function profileSavedMessage(updated: ProfileUpdateResponse): string {
  return updated.access_token
    ? "Password changed. Every other session was signed out and every API key was revoked; create new keys where you need them."
    : "Profile updated successfully.";
}
