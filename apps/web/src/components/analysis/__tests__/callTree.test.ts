// @vitest-environment jsdom
/**
 * The call tree's keyboard behaviour, in a DOM (T-485).
 *
 * The tree keeps one tab stop: the arrows, Home and End move between rows,
 * Right and Enter open a function, Left closes it or goes to its caller, a
 * call back up the tree jumps to the function it returns to, the "more" row
 * draws the rest of a wide function's callees, and O opens the records that
 * hold the focused function's listing. The citation mark on a row takes no
 * tab stop, and a key pressed on it is its own, never the row's.
 */

import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AnalysisContext, type AnalysisCtx } from "@/components/analysis/AnalysisContext";
import { CallTree } from "@/components/analysis/CallMap";
import { CALLEES_FIRST } from "@/components/analysis/callMap";
import type { CallMapFunction, CallMapResponse } from "@/types/evidence";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const fn = (address: string, calls: string[] = [], over: Partial<CallMapFunction> = {}): CallMapFunction => ({
  address,
  offset: null,
  names: [],
  read: true,
  listed_in: ["ev_0001"],
  read_by: [],
  calls,
  called_by: [],
  ...over,
});

// 0x10 → 0x20 → (0x30, back to 0x10); 0x40 is a second root.
const MAP: CallMapResponse = {
  job_id: "j",
  image_base: null,
  functions: [
    fn("0x10", ["0x20"], { names: ["entry"] }),
    fn("0x20", ["0x30", "0x10"]),
    fn("0x30", [], { read: false, listed_in: [] }),
    fn("0x40"),
  ],
  roots: ["0x10", "0x40"],
};

let mount: HTMLDivElement;
let root: Root;
let showEvidence: ReturnType<typeof vi.fn<NonNullable<AnalysisCtx["showEvidence"]>>>;

beforeEach(() => {
  mount = document.createElement("div");
  document.body.append(mount);
  root = createRoot(mount);
  showEvidence = vi.fn<NonNullable<AnalysisCtx["showEvidence"]>>();
});

afterEach(() => {
  act(() => root.unmount());
  mount.remove();
});

function render(map: CallMapResponse = MAP) {
  const ctx: AnalysisCtx = { jobId: "j", report: null, job: null, loading: false, reportError: null, showEvidence };
  act(() => root.render(createElement(AnalysisContext.Provider, { value: ctx }, createElement(CallTree, { map }))));
}

function key(k: string, target: Element | null = document.activeElement) {
  act(() => {
    (target ?? document.body).dispatchEvent(new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true }));
  });
}

const row = (k: string) => mount.querySelector<HTMLElement>(`[data-key="${k}"]`)!;
const keys = () => [...mount.querySelectorAll<HTMLElement>('[role="treeitem"]')].map((el) => el.dataset.key);

describe("the call tree", () => {
  it("keeps one tab stop, the first root's, and no tab stop on a citation", () => {
    render();
    const stops = [...mount.querySelectorAll<HTMLElement>('[role="treeitem"]')].filter((el) => el.tabIndex === 0);
    expect(stops.map((el) => el.dataset.key)).toEqual(["0x10"]);
    expect([...mount.querySelectorAll<HTMLElement>("[data-citation]")].every((el) => el.tabIndex === -1)).toBe(true);
  });

  it("moves with the arrows, Home and End, and opens and closes with Right and Left", () => {
    render();
    row("0x10").focus();
    key("ArrowDown");
    expect(document.activeElement).toBe(row("0x40"));
    key("Home");
    expect(document.activeElement).toBe(row("0x10"));
    key("ArrowRight");
    expect(row("0x10").getAttribute("aria-expanded")).toBe("true");
    expect(keys()).toEqual(["0x10", "0x10>0x20", "0x40"]);
    key("ArrowRight");
    expect(document.activeElement).toBe(row("0x10>0x20"));
    expect(row("0x10>0x20").getAttribute("aria-level")).toBe("2");
    key("End");
    expect(document.activeElement).toBe(row("0x40"));
    key("ArrowUp");
    expect(document.activeElement).toBe(row("0x10>0x20"));
    key("ArrowLeft");
    expect(document.activeElement).toBe(row("0x10"));
    key("ArrowLeft");
    expect(row("0x10").getAttribute("aria-expanded")).toBe("false");
    expect(keys()).toEqual(["0x10", "0x40"]);
  });

  it("draws a call back up the tree once, and Enter on it jumps to the function it returns to", () => {
    render();
    row("0x10").focus();
    key("Enter");
    key("ArrowDown");
    key("Enter");
    expect(keys()).toEqual(["0x10", "0x10>0x20", "0x10>0x20>0x30", "0x10>0x20>0x10", "0x40"]);
    const back = row("0x10>0x20>0x10");
    expect(back.getAttribute("aria-label")).toMatch(/^Calls back to 0x10 \(entry\)/);
    expect(back.hasAttribute("aria-expanded")).toBe(false);
    back.focus();
    key("Enter");
    expect(document.activeElement).toBe(row("0x10"));
  });

  it("draws the rest of a wide function's callees from its more row", () => {
    const callees = Array.from({ length: CALLEES_FIRST + 3 }, (_, i) => `0x${(0x1000 + i).toString(16)}`);
    render({ ...MAP, functions: [fn("0x10", callees), ...callees.map((a) => fn(a))], roots: ["0x10"] });
    row("0x10").focus();
    key("ArrowRight");
    key("End");
    const more = row("0x10>+");
    expect(document.activeElement).toBe(more);
    expect(more.getAttribute("aria-label")).toBe("Show 3 more callees");
    key("Enter");
    expect(keys()).toHaveLength(1 + CALLEES_FIRST + 3);
    expect(row("0x10>+")).toBeNull();
  });

  it("opens the listing records with O from the row, and leaves the row as it was", () => {
    render();
    const entry = row("0x10");
    expect(entry.getAttribute("aria-keyshortcuts")).toBe("O");
    entry.focus();
    key("o");
    expect(showEvidence).toHaveBeenCalledTimes(1);
    expect(showEvidence.mock.calls[0][0]).toMatchObject({ evidenceIds: ["ev_0001"], title: "Listing of 0x10" });
    expect(showEvidence.mock.calls[0][1]).toBe(entry);
    expect(entry.getAttribute("aria-expanded")).toBe("false");
    // A function nobody read has no listing to open, and announces no key.
    key("Enter");
    key("ArrowDown");
    key("Enter");
    const unread = row("0x10>0x20>0x30");
    expect(unread.hasAttribute("aria-keyshortcuts")).toBe(false);
    unread.focus();
    key("o");
    expect(showEvidence).toHaveBeenCalledTimes(1);
  });

  it("leaves a key pressed on the citation to the citation", () => {
    render();
    const cite = row("0x10").querySelector<HTMLElement>("[data-citation]")!;
    key("Enter", cite);
    key("ArrowDown", cite);
    expect(row("0x10").getAttribute("aria-expanded")).toBe("false");
    expect(keys()).toEqual(["0x10", "0x40"]);
    act(() => cite.click());
    expect(showEvidence).toHaveBeenCalledTimes(1);
    expect(row("0x10").getAttribute("aria-expanded")).toBe("false");
  });
});
