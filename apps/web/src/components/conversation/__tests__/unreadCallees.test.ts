/**
 * The question about the unread callees of what an agent described, in that
 * agent's own conversation (T-558).
 *
 * The platform publishes the step on the path every analyst question takes:
 * the list it gave the agent as a correction line (`retried`), the reads that
 * followed as the agent's own tool calls, and what the agent chose as the
 * same line's `answered` state. Where it could not ask, the agent's
 * conversation carries a note saying why. Every address and name here is made
 * up for the test, and so is the agent: any agent and any tool take this path.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import NoticeRow from "@/components/conversation/NoticeRow";
import { buildConversation } from "@/lib/conversation";
import type { RunEvent } from "@/lib/runStore";
import type { JobRoster } from "@/types";

let seq = 0;
function event(type: string, data: Record<string, unknown> = {}): RunEvent {
  seq += 1;
  return { type, data, ts: "2026-11-04T10:00:00Z", seq, order: seq, sortKey: seq };
}

const ROSTER: JobRoster = {
  agents: [{ key: "my_code_reader", label: "My code reader", role: "analyst", stages: ["analysis"] }],
  stages: [{ key: "analysis", label: "Analysis", kind: "analysis", agents: ["my_code_reader"] }],
};

const LIST =
  "Routines your claims describe call 3 function(s) whose code none of your listings holds. " +
  "Where the code starts: the entry point, the exports and the thread starts the run's answers " +
  "state. Ranked by distance from those starts (the calls between, plus one for each further " +
  "function calling it, since a routine called from many places is a shared helper): " +
  "0x180003000 (called by 0x180002000; 2 call(s) from the start 0x180001000; 1 caller(s); " +
  "calls 2); 0x180004000 (called by 0x180002000; 2 call(s) from the start 0x180001000; " +
  "1 caller(s); calls 0); 0x180009000 (called by 0x180002000; 2 call(s) from the start " +
  "0x180001000; 6 caller(s); calls 0). Each is a step of what your claims describe that you " +
  "have not read. Decide whether any matters to this analysis: you may read any of them with " +
  "your tools and add or change claims for what their code does, citing the entries that list " +
  "it, or leave them unread and change nothing. This is asked once.";
const ANSWER =
  "Asked once about 3 unread callee(s) of the routines its claims describe (3 listed), the " +
  "analyst read 1 of those listed (0x180003000) and left 2 unread by its own choice.";

function step(state: string, message: string) {
  return event("validation_feedback", {
    stage: "analysis",
    agent: "my_code_reader",
    code: "isr.callees_not_read",
    message,
    retry_index: 1,
    state,
    path: "",
  });
}

describe("the unread-callees step in the agent's conversation", () => {
  const { stages } = buildConversation(
    [
      step("retried", LIST),
      event("tool_call_started", {
        stage: "analysis",
        agent: "my_code_reader",
        tool: "lift_routines",
        server: "acme",
        args_summary: "0x180003000",
      }),
      event("tool_call_finished", {
        stage: "analysis",
        agent: "my_code_reader",
        tool: "lift_routines",
        server: "acme",
        evidence_id: "ev_0007",
        ok: true,
        duration_ms: 90,
        summary: "1 function listed",
      }),
      step("answered", ANSWER),
    ],
    ROSTER,
  );
  const items = stages[0].rounds[0].items;

  it("shows the list, the reads that followed and what the agent chose, in order", () => {
    expect(items.map((i) => i.kind)).toEqual(["validation_feedback", "tool_call"]);
    expect(items[0].speaker).toBe("my_code_reader");
    expect(items[0].feedback?.map((f) => f.state)).toEqual(["retried", "answered"]);
    expect(items[0].feedback?.[0].message).toBe(LIST);
    expect(items[0].text).toBe(ANSWER);
    expect(items[1].tool).toMatchObject({ name: "lift_routines", evidenceId: "ev_0007", ok: true });
  });

  it("draws the line as answered, with the list under it, never as a failure", () => {
    const markup = renderToStaticMarkup(createElement(NoticeRow, { item: items[0] }));

    expect(markup).toContain("answered by the agent");
    expect(markup).not.toContain("not fixed");
    expect(markup).toContain("read 1 of those listed (0x180003000)");
    expect(markup).toContain(
      "retry 1 · sent back for correction — Routines your claims describe call 3 function(s)",
    );
    expect(markup).toContain("0x180009000 (called by 0x180002000; 2 call(s) from the start");
    expect(markup).toMatchInlineSnapshot(`"<div class="flex justify-center"><div title="isr.callees_not_read" class="max-w-[min(46rem,100%)] rounded-lg border px-2.5 py-1 text-[11px] border-status-blue/30 bg-status-blue/10 text-status-blue"><div class="flex flex-wrap items-center gap-x-2"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-message-square-reply" aria-hidden="true"><path d="M22 17a2 2 0 0 1-2 2H6.828a2 2 0 0 0-1.414.586l-2.202 2.202A.71.71 0 0 1 2 21.286V5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2z"></path><path d="m10 8-3 3 3 3"></path><path d="M17 14v-1a2 2 0 0 0-2-2H7"></path></svg><span class="font-medium">answered by the agent</span><span>retry 1</span><span class="text-text-primary">My code reader</span></div><p class="whitespace-pre-wrap break-words text-text-secondary ">Asked once about 3 unread callee(s) of the routines its claims describe (3 listed), the analyst read 1 of those listed (0x180003000) and left 2 unread by its own choice.</p><ul class="mt-1 space-y-0.5 pl-5 text-text-muted"><li>retry 1 · sent back for correction — Routines your claims describe call 3 function(s) whose code none of your listings holds. Where the code starts: the entry point, the exports and the thread starts the run&#x27;s answers state. Ranked by distance from those starts (the calls between, plus one for each further function calling it, since a routine called from many places is a shared helper): 0x180003000 (called by 0x180002000; 2 call(s) from the start 0x180001000; 1 caller(s); calls 2); 0x180004000 (called by 0x180002000; 2 call(s) from the start 0x180001000; 1 caller(s); calls 0); 0x180009000 (called by 0x180002000; 2 call(s) from the start 0x180001000; 6 caller(s); calls 0). Each is a step of what your claims describe that you have not read. Decide whether any matters to this analysis: you may read any of them with your tools and add or change claims for what their code does, citing the entries that list it, or leave them unread and change nothing. This is asked once.</li></ul></div></div>"`);
  });

  it("carries the note saying why the platform did not ask", () => {
    const note = buildConversation(
      [
        event("agent_message", {
          stage: "analysis",
          speaker: "my_code_reader",
          role: "system",
          kind: "system",
          text:
            "The platform did not ask about the unread callees of the routines this answer " +
            "describes: no entry of this analyst lists code.",
        }),
      ],
      ROSTER,
    ).stages[0].rounds[0].items[0];

    expect(note.kind).toBe("system");
    const markup = renderToStaticMarkup(createElement(NoticeRow, { item: note }));
    expect(markup).toContain("did not ask about the unread callees");
  });
});
