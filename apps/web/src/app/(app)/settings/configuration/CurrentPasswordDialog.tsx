"use client";

import { useEffect, useRef, useState } from "react";
import { buttonClass } from "@/components/ui/Button";
import type { PasswordAsk } from "./useSettings";

/** Asks for the admin's current password before a save or a reset that
 *  changes how accounts sign in (a setting the API marks
 *  `needs_current_password`). Opened by `useSettings` wherever the save or the
 *  reset starts (a guide's apply, a row's or a group's reset); the changes
 *  bar asks in its own review instead. Escape or Cancel answers `null`, and
 *  nothing is sent. */
export default function CurrentPasswordDialog({ ask }: { ask: PasswordAsk }) {
  const [password, setPassword] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    inputRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") ask.answer(null);
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      opener?.focus();
    };
  }, [ask]);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/40 px-4 pt-20">
      <form
        role="dialog"
        aria-modal="true"
        aria-label="Confirm with your current password"
        className="w-full max-w-md border border-border rounded bg-bg-surface shadow-lg px-4 py-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (password !== "") ask.answer(password);
        }}
      >
        <label htmlFor="policy-current-password" className="block text-xs text-text-secondary">
          {ask.keys.join(", ")} change how accounts sign in. Confirm with your current password.
        </label>
        <input
          id="policy-current-password"
          ref={inputRef}
          name="current_password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mt-2 w-full rounded border border-border bg-bg-deep px-2 py-1 text-sm text-text-primary"
        />
        <div className="flex items-center gap-4 mt-4">
          <button
            type="submit"
            disabled={password === ""}
            className={buttonClass("primary", "sm")}
          >
            Confirm
          </button>
          <button
            type="button"
            className="text-xs text-text-secondary hover:text-text-primary"
            onClick={() => ask.answer(null)}
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
