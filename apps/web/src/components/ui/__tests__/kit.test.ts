/**
 * The shared kit: Button, Section, Tabs, Pill, KpiTile and Drawer.
 *
 * Each is rendered to markup and read the way a reader and a screen reader
 * would: what the control is called, what state it says it is in, and what
 * an empty or unknown value is drawn as. The pure rules beside each
 * component (which tab is current, when a section starts open, what a KPI
 * of zero says) are pinned directly.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import Button, { buttonClass } from "@/components/ui/Button";
import Drawer from "@/components/ui/Drawer";
import KpiTile, { kpiState } from "@/components/ui/KpiTile";
import { SeverityPill, VerdictPill, severityPillText } from "@/components/ui/Pill";
import Section, { sectionStartsOpen } from "@/components/ui/Section";
import Tabs, { activeTabKey, type TabItem } from "@/components/ui/Tabs";

const html = (el: ReturnType<typeof createElement>) => renderToStaticMarkup(el);

describe("Button", () => {
  it("is a typed button that names its weight for a count", () => {
    const out = html(createElement(Button, { variant: "primary" }, "Start analysis"));
    expect(out).toContain('type="button"');
    expect(out).toContain('data-variant="primary"');
    expect(out).toContain(">Start analysis</button>");
  });

  it("defaults to secondary, and each weight has its own look", () => {
    expect(html(createElement(Button, null, "Cancel"))).toContain('data-variant="secondary"');
    const looks = new Set([buttonClass("primary"), buttonClass("secondary"), buttonClass("ghost")]);
    expect(looks.size).toBe(3);
    expect(buttonClass("primary")).toContain("bg-accent-fill");
  });

  it("is at least 24 px tall at the small size", () => {
    expect(buttonClass("ghost", "sm")).toContain("min-h-6");
  });
});

describe("Section", () => {
  it("draws its title and count, and its body when there is something to show", () => {
    const out = html(createElement(Section, { title: "Top findings", count: 12 }, "rows"));
    expect(out).toContain("Top findings");
    expect(out).toContain(">12<");
    expect(out).toContain("rows");
    expect(out).not.toContain("data-empty");
  });

  it("stays in place when empty, greyed, saying Not found, with no body", () => {
    const out = html(createElement(Section, { title: "Extracted configuration", count: 0, empty: true }, "never"));
    expect(out).toContain('data-empty="true"');
    expect(out).toContain("Not found");
    expect(out).not.toContain("never");
  });

  it("is a disclosure when collapsible, and an empty one starts closed", () => {
    const open = html(createElement(Section, { title: "Strings", collapsible: true }, "body"));
    expect(open).toContain('aria-expanded="true"');
    const closed = html(createElement(Section, { title: "Strings", collapsible: true, defaultOpen: false }, "body"));
    expect(closed).toContain('aria-expanded="false"');
    expect(closed).not.toContain("body");
    expect(sectionStartsOpen(true, true, true)).toBe(false);
    expect(sectionStartsOpen(false, false, false)).toBe(true);
  });
});

describe("Tabs", () => {
  const tabs: TabItem[] = [
    { key: "overview", label: "Overview", href: "/analysis/j" },
    { key: "network", label: "Network", href: "/analysis/j/network", count: 7 },
  ];

  it("picks the longest matching href, so the parent tab is not current on a child", () => {
    expect(activeTabKey(tabs, "/analysis/j")).toBe("overview");
    expect(activeTabKey(tabs, "/analysis/j/network")).toBe("network");
    expect(activeTabKey(tabs, "/elsewhere")).toBeNull();
  });

  it("draws links in a named landmark, the current one marked, counts said in words", () => {
    const out = html(createElement(Tabs, { tabs, active: "network", label: "Analysis sections" }));
    expect(out).toContain('aria-label="Analysis sections"');
    expect(out).toContain('href="/analysis/j/network"');
    expect(out.match(/aria-current="page"/g)).toHaveLength(1);
    expect(out).toMatch(/Network.*7.*items/);
  });
});

describe("Pill", () => {
  it("reads every rung on one n/5 scale", () => {
    expect(severityPillText("Critical")).toBe("Critical 5/5");
    expect(severityPillText("high")).toBe("High 4/5");
    expect(severityPillText("Informational")).toBe("Informational 1/5");
  });

  it("calls a word off the ladder Unrated, never a guessed rung", () => {
    expect(severityPillText(null)).toBe("Unrated");
    expect(severityPillText("severe")).toBe("Unrated");
    expect(html(createElement(SeverityPill, { severity: null }))).toContain("text-text-secondary");
  });

  it("fills as many ticks as the rung and prints the word", () => {
    const out = html(createElement(SeverityPill, { severity: "Medium" }));
    expect(out).toContain("Medium 3/5");
    expect(out.match(/bg-status-purple"/g)).toHaveLength(3);
  });

  it("prints the verdict in the reader's word and its colour", () => {
    const out = html(createElement(VerdictPill, { verdict: "Malware" }));
    expect(out).toContain(">Malicious<");
    expect(out).toContain("text-status-red");
  });
});

describe("KpiTile", () => {
  it("tells found, none found and never measured apart", () => {
    expect(kpiState(3)).toBe("found");
    expect(kpiState(0)).toBe("not-found");
    expect(kpiState(null)).toBe("not-measured");
  });

  it("draws a zero as Not found, never as a large 0", () => {
    const out = html(createElement(KpiTile, { label: "Detection rules", value: 0, href: "/x" }));
    expect(out).toContain("Not found");
    expect(out).not.toContain("<a ");
  });

  it("links a found count to its list", () => {
    const out = html(createElement(KpiTile, { label: "Indicators", value: 1234, href: "/x" }));
    expect(out).toContain('href="/x"');
    expect(out).toContain("1,234");
  });
});

describe("Drawer", () => {
  it("draws nothing while closed", () => {
    expect(html(createElement(Drawer, { open: false, title: "t", onClose: () => {} }, "body"))).toBe("");
  });

  it("is a labelled modal dialog with a named close button when open", () => {
    const out = html(createElement(Drawer, { open: true, title: "Process injection", onClose: () => {} }, "body"));
    expect(out).toContain('role="dialog"');
    expect(out).toContain('aria-modal="true"');
    expect(out).toMatch(/aria-labelledby="([^"]+)".*id="\1"[^>]*>Process injection/);
    expect(out).toContain('aria-label="Close details"');
    expect(out).toContain("body");
  });
});
