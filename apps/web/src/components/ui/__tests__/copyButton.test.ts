/**
 * The copy control a row carries.
 *
 * What is under test is what a reader who cannot see the button's word flip
 * is told: the name says what is copied and holds the visible word, and the
 * live region is on the page before anything is copied and says which value
 * was.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import CopyButton from "@/components/ui/CopyButton";
import {
  copyAnnouncement,
  copyButtonName,
  copyButtonText,
  type CopyState,
} from "@/components/ui/copyState";

describe("the copy control", () => {
  it("is a named button with an empty polite live region beside it", () => {
    const markup = renderToStaticMarkup(
      createElement(CopyButton, {
        value: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        what: "SHA-256 of invoice_scan.exe",
        label: "SHA-256",
      }),
    );
    expect(markup).toContain('type="button"');
    expect(markup).toContain('aria-label="Copy SHA-256 of invoice_scan.exe"');
    expect(markup).toContain(">SHA-256</button>");
    expect(markup).toContain('<span role="status" class="sr-only"></span>');
  });

  it("keeps the visible word inside the accessible name in every state", () => {
    const states: CopyState[] = ["idle", "copied", "failed"];
    for (const state of states) {
      const shown = copyButtonText(state, "copy").toLowerCase();
      const name = copyButtonName(state, "job id").toLowerCase();
      expect(name).toContain(shown);
    }
  });

  it("announces which value was copied, and says nothing at rest", () => {
    expect(copyAnnouncement("idle", "job id")).toBe("");
    expect(copyAnnouncement("copied", "job id of invoice_scan.exe")).toBe(
      "Copied job id of invoice_scan.exe",
    );
    expect(copyAnnouncement("failed", "job id")).toContain("Could not copy job id");
  });
});
