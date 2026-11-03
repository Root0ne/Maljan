// @vitest-environment jsdom
/**
 * The Behaviour tab's signatures, mounted (T-475): by severity by default,
 * per process on the reader's asking where the sandbox named the processes,
 * and with no such choice where it named none.
 */

import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useParams: () => ({ id: "J1" }), usePathname: () => "/analysis/J1/behaviour" }));

import type { ReportDetailDTO } from "@/lib/api";
import type { SandboxSignature } from "@/types/malware-report";
import { BehavioursBlock } from "../tabs/DynamicContent";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let mount: HTMLDivElement;
let root: Root;

beforeEach(() => {
  mount = document.createElement("div");
  document.body.append(mount);
  root = createRoot(mount);
});

afterEach(() => {
  act(() => root.unmount());
  mount.remove();
});

const sig = (name: string, severity: number, pids?: string[]): SandboxSignature => ({
  name,
  description: "",
  severity,
  technique_ids: [],
  marks: [],
  ...(pids ? { pids } : {}),
});

function report(signatures: SandboxSignature[]): ReportDetailDTO {
  return {
    malware_report: {
      dynamic: {
        process_tree: [
          { pid: 2100, ppid: 900, name: "invoice.exe", command_line: "", children: [], injected_into: [] },
        ],
        registry_mods: [],
        file_operations: [],
        notable_apis: [],
        sandbox_signatures: signatures,
      },
    },
  } as unknown as ReportDetailDTO;
}

function render(signatures: SandboxSignature[]) {
  act(() => root.render(createElement(BehavioursBlock, { report: report(signatures), view: "all", tactics: new Map() })));
}

const toggle = (label: string) =>
  [...mount.querySelectorAll<HTMLButtonElement>('[aria-label="Signatures listed"] button')].find(
    (b) => b.textContent === label,
  );

// The groups the signatures are listed in per process: every group of the
// block but the toggle's own.
const processGroupElements = () =>
  [...mount.querySelectorAll<HTMLElement>('[aria-label="Sandbox signatures"] > div[role="group"]')].filter(
    (g) => g.getAttribute("aria-label") !== "Signatures listed",
  );
const processGroupLabels = () => processGroupElements().map((g) => g.getAttribute("aria-label"));

describe("the Behaviour tab's signatures", () => {
  it("has no per-process choice where no signature names a process, and lists by severity", () => {
    render([sig("a", 8), sig("b", 2)]);
    expect(mount.querySelector('[aria-label="Signatures listed"]')).toBeNull();
    expect(mount.querySelector('[aria-label="Sandbox signatures"] h3')).not.toBeNull();
    expect(mount.querySelector('[aria-label="Sandbox signatures"] h4')).toBeNull();
  });

  it("lists by severity by default, and per process on asking, the severities one level down", () => {
    render([
      sig("inject", 8, ["2100"]),
      sig("wide", 3, ["1", "2", "3", "4"]),
      sig("odd", 2),
    ]);
    expect(toggle("By severity")?.getAttribute("aria-pressed")).toBe("true");
    expect(processGroupLabels()).toEqual([]);

    act(() => toggle("By process")!.click());
    expect(toggle("By process")?.getAttribute("aria-pressed")).toBe("true");
    const groups = processGroupElements();
    expect(processGroupLabels()).toEqual([
      "Process 2100 (invoice.exe)",
      "Seen in 4 processes",
      "No process named",
    ]);
    // Each signature once: the wide one under its span, not under four processes.
    expect(mount.textContent?.match(/wide/g)).toHaveLength(1);
    expect(groups[0].querySelector("h3")?.textContent).toContain("invoice.exe");
    expect(groups[0].querySelector("h4")).not.toBeNull();
  });
});
