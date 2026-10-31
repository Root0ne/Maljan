// @vitest-environment jsdom
/**
 * The file-structure sub-tabs, in a DOM: the ARIA tabs pattern a keyboard
 * user relies on. Tab reaches only the selected tab; Up, Down, Home and End
 * move focus and selection together.
 */

import { act, createElement, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import VerticalTabs, { nextTabIndex } from "@/components/ui/VerticalTabs";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const ITEMS = [
  { key: "sections", label: "Sections", count: 3 },
  { key: "imports", label: "Imports", count: 0 },
  { key: "exports", label: "Exports" },
  { key: "resources", label: "Resources" },
] as const;

function Harness() {
  const [selected, setSelected] = useState<(typeof ITEMS)[number]["key"]>("sections");
  return createElement(VerticalTabs<(typeof ITEMS)[number]["key"]>, {
    items: ITEMS,
    selected,
    onSelect: setSelected,
    label: "PE details",
    panelId: "panel",
    idPrefix: "tab",
  });
}

let mount: HTMLDivElement;
let root: Root;

beforeEach(() => {
  mount = document.createElement("div");
  document.body.append(mount);
  root = createRoot(mount);
  act(() => root.render(createElement(Harness)));
});

afterEach(() => {
  act(() => root.unmount());
  mount.remove();
});

const tabs = () => Array.from(mount.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
const selected = () => tabs().find((t) => t.getAttribute("aria-selected") === "true")?.textContent;
const press = (key: string) =>
  act(() => {
    (document.activeElement ?? tabs()[0]).dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true }));
  });

describe("the structure sub-tabs follow the ARIA tabs pattern (T-465)", () => {
  it("is a vertical tab list whose tabs control the one panel", () => {
    const list = mount.querySelector('[role="tablist"]')!;
    expect(list.getAttribute("aria-orientation")).toBe("vertical");
    expect(list.getAttribute("aria-label")).toBe("PE details");
    expect(tabs().every((t) => t.getAttribute("aria-controls") === "panel")).toBe(true);
  });

  it("puts only the selected tab in the Tab order", () => {
    expect(tabs().map((t) => t.tabIndex)).toEqual([0, -1, -1, -1]);
  });

  it("moves focus and selection with Down, Up, End and Home, wrapping at the ends", () => {
    act(() => tabs()[0].focus());
    press("ArrowDown");
    expect(selected()).toMatch(/^Imports/);
    expect(document.activeElement).toBe(tabs()[1]);
    expect(tabs().map((t) => t.tabIndex)).toEqual([-1, 0, -1, -1]);
    press("End");
    expect(selected()).toBe("Resources");
    expect(document.activeElement).toBe(tabs()[3]);
    press("ArrowDown");
    expect(selected()).toMatch(/^Sections/);
    press("ArrowUp");
    expect(selected()).toBe("Resources");
    press("Home");
    expect(selected()).toMatch(/^Sections/);
    expect(document.activeElement).toBe(tabs()[0]);
  });

  it("leaves every other key alone", () => {
    expect(nextTabIndex("Enter", 1, 4)).toBeNull();
    expect(nextTabIndex("ArrowRight", 3, 4)).toBe(0);
    expect(nextTabIndex("ArrowDown", 0, 0)).toBeNull();
  });
});
