import { describe, expect, it } from "vitest";

import { TOOLS_SHOWN, toolBars } from "../toolBars";

describe("the tools-used bars", () => {
  it("draw nothing when no run called anything", () => {
    expect(toolBars(null)).toBeNull();
    expect(toolBars({ limit: 20, runs: 4, tools: [] })).toBeNull();
    expect(toolBars({ limit: 20, runs: 1, tools: [{ tool: "pe_info", calls: 0, runs: 0 }] })).toBeNull();
  });

  it("measure each bar against the busiest tool and say the row in words", () => {
    const bars = toolBars({
      limit: 20,
      runs: 12,
      tools: [
        { tool: "pe_info", calls: 40, runs: 12 },
        { tool: "sandbox_network", calls: 10, runs: 1 },
      ],
    });
    expect(bars?.window).toBe("12 completed runs");
    expect(bars?.rows.map((r) => r.width)).toEqual([100, 25]);
    expect(bars?.rows[1].spoken).toBe("sandbox_network: 10 calls in 1 of 12 runs");
  });

  it("stand on the runs that carry the record and say how many read carry none", () => {
    const bars = toolBars({
      limit: 20,
      read: 12,
      runs: 3,
      tools: [{ tool: "pe_info", calls: 9, runs: 3 }],
    });
    expect(bars?.window).toBe("3 completed runs");
    expect(bars?.unrecorded).toBe(9);
    expect(bars?.rows[0].spoken).toBe("pe_info: 9 calls in 3 of 3 runs");
  });

  it("say nothing about unrecorded runs to an API that does not report reads", () => {
    const bars = toolBars({ limit: 20, runs: 3, tools: [{ tool: "pe_info", calls: 1, runs: 1 }] });
    expect(bars?.unrecorded).toBe(0);
  });

  it("keep a tool called once visible rather than drawing a zero-width bar", () => {
    const bars = toolBars({
      limit: 20,
      runs: 1,
      tools: [
        { tool: "pe_info", calls: 1000, runs: 1 },
        { tool: "yara_scan", calls: 1, runs: 1 },
      ],
    });
    expect(bars?.rows[1].width).toBeGreaterThan(0);
    expect(bars?.rows[1].spoken).toBe("yara_scan: 1 call in 1 of 1 run");
  });

  it("say how many tools are past the ones drawn rather than dropping them", () => {
    const tools = Array.from({ length: TOOLS_SHOWN + 3 }, (_, i) => ({
      tool: `tool_${i}`,
      calls: 100 - i,
      runs: 1,
    }));
    const bars = toolBars({ limit: 20, runs: 5, tools });
    expect(bars?.rows).toHaveLength(TOOLS_SHOWN);
    expect(bars?.more).toBe(3);
  });
});
