/**
 * The copy control a row carries.
 *
 * What is under test is what a reader who cannot see the confirmation is
 * told: the name says what is copied, holds the visible word and does not
 * change, and the live region is on the page before anything is copied and
 * is the one place that says which value was.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import CopyButton from "@/components/ui/CopyButton";
import { copyAnnouncement, copyButtonName, copyConfirmation } from "@/components/ui/copyState";

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

  it("is at least 24 px tall by default", () => {
    const markup = renderToStaticMarkup(createElement(CopyButton, { value: "x", what: "job id" }));
    expect(markup).toContain("min-h-6");
  });

  it("keeps one name, which holds the visible word", () => {
    expect(copyButtonName("job id of invoice.exe").toLowerCase()).toContain("job id");
    expect(copyButtonName("SHA-256").toLowerCase()).toContain("copy");
  });

  it("announces which value was copied, and says nothing at rest", () => {
    expect(copyAnnouncement("idle", "job id")).toBe("");
    expect(copyAnnouncement("copied", "job id of invoice_scan.exe")).toBe(
      "Copied job id of invoice_scan.exe",
    );
    expect(copyAnnouncement("failed", "job id")).toContain("Could not copy job id");
  });

  it("shows a sighted confirmation only once something happened", () => {
    expect(copyConfirmation("idle")).toBe("");
    expect(copyConfirmation("copied")).toBe("Copied");
    expect(copyConfirmation("failed")).toBe("Copy failed");
  });
});
