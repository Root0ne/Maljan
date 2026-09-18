/**
 * The line a failed run ends on.
 *
 * What is under test is that the id an operator needs is drawn as a value of
 * its own rather than as part of a sentence, and that a failure carrying no id
 * still reads as a failure.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import FailureRow from "@/components/conversation/FailureRow";
import type { ConversationItem } from "@/lib/conversation";
import { FAILURE_LOG_NOTE } from "@/lib/runFailure";

const ID = "5f3a9c1d4e2b48f7a0c6d8e1b3f5a7c9";

function failed(text: string, errorId?: string): ConversationItem {
  return {
    id: "seq:42",
    kind: "run_failed",
    stage: "",
    round: 0,
    speaker: "",
    displayName: "",
    text,
    ts: "2026-09-17T10:00:00Z",
    claims: [],
    dissent: [],
    errorId,
  };
}

function render(item: ConversationItem): string {
  return renderToStaticMarkup(createElement(FailureRow, { item }));
}

describe("a failed run's closing line", () => {
  it("labels the error id, keeps it selectable and offers to copy it", () => {
    const markup = render(failed("Analysis failed. See server logs for details.", ID));

    expect(markup).toContain("Analysis failed. See server logs for details.");
    expect(markup).toContain("Error id");
    expect(markup).toContain(`<code class="select-all break-all font-mono text-text-primary">${ID}</code>`);
    expect(markup).toContain(">Copy<");
    expect(markup).toContain(FAILURE_LOG_NOTE);
  });

  it("draws a failure the run filed under no id", () => {
    const markup = render(failed("The run failed."));

    expect(markup).toContain("The run failed.");
    expect(markup).not.toContain("Error id");
    expect(markup).not.toContain(FAILURE_LOG_NOTE);
  });
});
