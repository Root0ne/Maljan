// @vitest-environment jsdom
/**
 * The keyboard behaviour of the Drawer and the Export menu, in a DOM.
 *
 * Markup tests cannot see focus. These mount the components in jsdom and
 * drive them the way a keyboard user does: the Drawer keeps Tab inside
 * itself, makes the page behind it inert, and gives focus back to the
 * control that opened it; the Export menu walks its items with the arrows,
 * Home and End, keeps an unavailable item reachable with its reason, refuses
 * to run it, and returns focus to the first item when an export fails.
 */

import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import Drawer from "@/components/ui/Drawer";
import ExportMenu from "@/components/ui/ExportMenu";
import type { ExportGroup } from "@/components/ui/exportActions";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement;
let mount: HTMLDivElement;
let opener: HTMLButtonElement;
let root: Root;

beforeEach(() => {
  host = document.createElement("div");
  opener = document.createElement("button");
  opener.textContent = "Show evidence";
  mount = document.createElement("div");
  host.append(opener, mount);
  document.body.append(host);
  root = createRoot(mount);
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

function key(target: Element | null, k: string, shiftKey = false) {
  act(() => {
    (target ?? document.body).dispatchEvent(new KeyboardEvent("keydown", { key: k, shiftKey, bubbles: true }));
  });
}

const active = () => document.activeElement;

describe("the Drawer", () => {
  const drawer = (open: boolean, onClose = () => {}) =>
    createElement(
      Drawer,
      { open, title: "Process injection", onClose, returnFocusTo: opener },
      createElement("a", { href: "/a" }, "Record 1"),
      createElement("a", { href: "/b" }, "Record 2"),
    );

  it("takes focus, keeps Tab inside, and makes the page behind it inert", () => {
    opener.focus();
    act(() => root.render(drawer(true)));
    const close = document.querySelector<HTMLButtonElement>('[aria-label="Close details"]')!;
    const links = document.querySelectorAll<HTMLAnchorElement>('[role="dialog"] a');
    expect(active()).toBe(close);
    expect(opener.hasAttribute("inert")).toBe(true);

    links[1].focus();
    key(active(), "Tab");
    expect(active()).toBe(close);

    key(active(), "Tab", true);
    expect(active()).toBe(links[1]);
  });

  it("closes on Escape and gives focus back to its opener, no longer inert", () => {
    const onClose = vi.fn();
    act(() => root.render(drawer(true, onClose)));
    key(active(), "Escape");
    expect(onClose).toHaveBeenCalledTimes(1);

    act(() => root.render(drawer(false, onClose)));
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(opener.hasAttribute("inert")).toBe(false);
    expect(active()).toBe(opener);
  });
});

describe("the Export menu", () => {
  const ran: string[] = [];
  const item = (k: string, extra: Partial<ExportGroup["items"][number]> = {}) => ({
    key: k,
    label: k.toUpperCase(),
    run: async () => {
      ran.push(k);
    },
    ...extra,
  });
  const groups = (failing = false): ExportGroup[] => [
    { key: "quick", label: "Quick", items: [item("pdf"), item("html")] },
    {
      key: "deep",
      label: "Deep",
      items: [
        item("misp", { unavailable: "None were generated for this analysis" }),
        item("stix", failing ? { run: async () => Promise.reject(new Error("503")) } : {}),
      ],
    },
  ];

  beforeEach(() => {
    ran.length = 0;
  });

  const open = (g: ExportGroup[]) => {
    act(() => root.render(createElement(ExportMenu, { groups: g })));
    const button = document.querySelector<HTMLButtonElement>('[aria-haspopup="menu"]')!;
    act(() => button.click());
    return { button, items: () => Array.from(document.querySelectorAll<HTMLButtonElement>('[role="menuitem"]')) };
  };

  it("focuses the first item, and walks with the arrows, Home and End", () => {
    const { items } = open(groups());
    const [pdf, html, misp, stix] = items();
    expect(active()).toBe(pdf);
    key(active(), "ArrowDown");
    expect(active()).toBe(html);
    key(active(), "ArrowDown");
    expect(active()).toBe(misp);
    key(active(), "End");
    expect(active()).toBe(stix);
    key(active(), "ArrowDown");
    expect(active()).toBe(pdf);
    key(active(), "ArrowUp");
    expect(active()).toBe(stix);
    key(active(), "Home");
    expect(active()).toBe(pdf);
  });

  it("keeps an unavailable item reachable with its reason, and does not run it", () => {
    const { items } = open(groups());
    const misp = items()[2];
    expect(misp.hasAttribute("disabled")).toBe(false);
    expect(misp.getAttribute("aria-disabled")).toBe("true");
    const note = document.getElementById(misp.getAttribute("aria-describedby")!);
    expect(note?.textContent).toBe("None were generated for this analysis");
    act(() => misp.click());
    expect(ran).toEqual([]);
  });

  it("closes on Escape with focus back on the button", () => {
    const { button } = open(groups());
    key(active(), "Escape");
    expect(document.querySelector('[role="menu"]')).toBeNull();
    expect(active()).toBe(button);
  });

  it("says what failed and puts focus back on the first item", async () => {
    const { items } = open(groups(true));
    await act(async () => {
      items()[3].click();
    });
    expect(document.querySelector('[role="alert"]')?.textContent).toBe("Could not export STIX: 503");
    expect(active()).toBe(items()[0]);
  });
});
