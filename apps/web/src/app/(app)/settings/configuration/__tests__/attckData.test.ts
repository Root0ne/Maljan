/**
 * The ATT&CK cache panel: its status table, the outdated dialog's two choices,
 * and the error states, rendered from the shapes the API serves.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import served from "@/test-fixtures/settings-schema.json";
import { formatDateTime } from "@/lib/report-utils";
import type { AttckCheckResult, AttckStatus, AttckUpdateResult, SettingsSchema } from "@/types/settings";
import { AttckDataView, type AttckDataViewProps } from "../AttckDataPanel";
import {
  ATTCK_REFRESH_KEY,
  ageLabel,
  lostContactText,
  releaseDate,
  statusIsStale,
  lastCheckLine,
  lastUpdateLine,
  nextCheckSentence,
  readCheck,
  statusRows,
  updateOutcome,
  waitSentence,
} from "../attckData";

const NEXT = "2026-10-21T09:00:00+00:00";

const STATUS: AttckStatus = {
  refresh_days: 7,
  next_check_at: NEXT,
  domains: [
    {
      domain: "enterprise",
      label: "Enterprise",
      present: true,
      readable: true,
      version: "19.2",
      released: "2026-08-05T21:33:58Z",
      techniques: 691,
      cached_at: "2026-10-14T09:00:00+00:00",
      age_days: 2.4,
      next_check_at: NEXT,
    },
    { domain: "mobile", label: "Mobile", present: false, next_check_at: null },
    {
      domain: "ics",
      label: "ICS",
      present: true,
      readable: false,
      reason: "the cached file does not parse",
      cached_at: "2026-10-14T09:00:00+00:00",
      next_check_at: NEXT,
    },
  ],
  last_check: null,
  last_update: null,
  running: null,
};

const OUTDATED: AttckCheckResult = {
  ok: true,
  outcome: "outdated",
  reason: "",
  checked_at: "2026-10-14T10:00:00+00:00",
  triggered_by: { user_id: "u1", name: "Ada Admin" },
  refresh_days: 7,
  next_check_at: NEXT,
  domains: [
    {
      domain: "enterprise",
      label: "Enterprise",
      cached: { present: true, version: "19.2" },
      latest: { version: "20.0", released: "2026-10-13T17:53:10Z" },
      state: "outdated",
    },
    {
      domain: "mobile",
      label: "Mobile",
      cached: { present: true, version: "20.0" },
      latest: { version: "20.0", released: "2026-10-13T17:54:40Z" },
      state: "current",
    },
  ],
};

const UP_TO_DATE: AttckCheckResult = {
  ...OUTDATED,
  outcome: "up_to_date",
  domains: OUTDATED.domains.map((d) => ({
    ...d,
    cached: { present: true, version: "20.0" },
    state: "current",
  })),
};

const FAILED: AttckCheckResult = {
  ...OUTDATED,
  ok: false,
  outcome: "failed",
  reason: "the ATT&CK release index could not be read: Network is unreachable",
  domains: OUTDATED.domains.map((d) => ({ ...d, latest: null, state: undefined })),
};

const UPDATED: AttckUpdateResult = {
  ok: true,
  outcome: "updated",
  reason: "",
  finished_at: "2026-10-14T10:05:00+00:00",
  triggered_by: { user_id: "u1", name: "Ada Admin" },
  trigger: "console",
  changes: [
    {
      domain: "enterprise",
      label: "Enterprise",
      from: "19.2",
      to: "20.0",
      released: "2026-10-13T17:53:10Z",
      techniques: 700,
    },
  ],
};

function render(overrides: Partial<AttckDataViewProps> = {}): string {
  const props: AttckDataViewProps = {
    status: STATUS,
    statusError: null,
    checking: false,
    check: null,
    checkError: null,
    choosing: false,
    waited: false,
    updating: false,
    update: null,
    updateError: null,
    onCheck: () => undefined,
    onUpdate: () => undefined,
    onWait: () => undefined,
    ...overrides,
  };
  return renderToStaticMarkup(createElement(AttckDataView, props));
}

describe("the setting the panel sits under", () => {
  it("is served in the analysis group under its own heading", () => {
    const schema = served as unknown as SettingsSchema;
    const entry = schema.groups
      .flatMap((g) => g.entries)
      .find((e) => e.key === ATTCK_REFRESH_KEY);
    expect(entry?.group).toBe("analysis");
    expect(entry?.subgroup).toBe("ATT&CK data");
    expect(entry?.type).toBe("int");
    expect(entry?.minimum).toBe(0);
  });
});

describe("status", () => {
  it("shows each domain's version, release date, age and next check", () => {
    const html = render();
    expect(html).toContain("Check now");
    const [enterprise, mobile, ics] = statusRows(STATUS);
    expect(enterprise.version).toBe("19.2");
    expect(enterprise.age).toBe("2 days");
    expect(enterprise.nextCheck).toBe(formatDateTime(NEXT));
    expect(html).toContain(enterprise.released);
    expect(mobile.version).toBe("not cached");
    expect(ics.version).toBe("unreadable");
    expect(html).toContain(`The next automatic check is due on ${formatDateTime(NEXT)}.`);
    expect(html).toContain("Last check: never.");
    expect(html).toContain("Last update: never.");
  });

  it("says when the automatic check is off", () => {
    expect(nextCheckSentence(0, null)).toContain("Automatic checks are off (the interval is 0)");
    expect(statusRows({ ...STATUS, refresh_days: 0 })[1].nextCheck).toBe("");
    expect(ageLabel(0.3)).toBe("less than a day");
    expect(ageLabel(1.2)).toBe("1 day");
  });

  it("names who checked and who updated, and how it went", () => {
    expect(lastCheckLine(FAILED)).toContain("failed: the ATT&CK release index could not be read");
    expect(lastCheckLine(OUTDATED)).toContain("by Ada Admin, a newer release was available");
    expect(lastUpdateLine(UPDATED)).toContain("by Ada Admin, Enterprise 19.2 → 20.0");
    expect(lastUpdateLine({ ...UPDATED, trigger: "schedule", triggered_by: {} })).toContain(
      "by the automatic check"
    );
    expect(lastUpdateLine({ ...UPDATED, ok: false, reason: "Mobile: the download carries no techniques", changes: [], kept_previous: true })).toContain(
      "The previous cache was kept."
    );
  });

  it("says plainly when the worker did not answer", () => {
    const html = render({
      status: null,
      statusError: "The analysis worker, which holds the ATT&CK cache, did not answer within 15 seconds.",
    });
    expect(html).toContain('role="alert"');
    expect(html).toContain("The cache status could not be read: The analysis worker");
  });
});

describe("check now", () => {
  it("says up to date with the versions", () => {
    const view = readCheck(UP_TO_DATE);
    expect(view).toEqual({ kind: "up_to_date", text: "Up to date: Enterprise 20.0, Mobile 20.0." });
    expect(render({ check: UP_TO_DATE })).toContain("Up to date: Enterprise 20.0, Mobile 20.0.");
  });

  it("never calls a failed check up to date", () => {
    const html = render({ check: FAILED });
    expect(html).not.toContain("Up to date");
    expect(html).toContain("The check failed: the ATT&amp;CK release index could not be read: Network is unreachable.");
    expect(html).toContain("Whether a newer release exists is not known");
    expect(readCheck({ ...UP_TO_DATE, ok: false }).kind).toBe("failed");
  });

  it("shows the request error when the check could not be run at all", () => {
    expect(render({ checkError: "Request failed: 503" })).toContain(
      "The check could not be run: Request failed: 503"
    );
  });
});

describe("the outdated dialog", () => {
  const html = render({ check: OUTDATED, choosing: true });

  it("states the cached and latest versions with the release date", () => {
    expect(html).toContain('role="dialog"');
    expect(html).toContain("A newer ATT&amp;CK release is available.");
    expect(html).toContain("Enterprise: cached 19.2, latest 20.0 (released Oct 13, 2026)");
    expect(html).not.toContain("Mobile: cached");
  });

  it("offers the two choices, and waiting names the next automatic check", () => {
    expect(html).toContain(">Update now<");
    expect(html).toContain(">Wait for the scheduled update<");
    expect(html).toContain(`The next automatic check is due on ${formatDateTime(NEXT)}.`);
  });

  it("closes on a choice: waiting keeps the cache until that date", () => {
    const waited = render({ check: OUTDATED, waited: true });
    expect(waited).not.toContain('role="dialog"');
    expect(waited).toContain(
      `The cache stays at Enterprise 19.2 until the automatic check on ${formatDateTime(NEXT)}.`
    );
    expect(waitSentence({ ...OUTDATED, refresh_days: 0, next_check_at: null })).toContain(
      "Automatic checks are off"
    );
  });

  it("shows the update in progress, then its outcome", () => {
    expect(render({ check: OUTDATED, updating: true })).toContain(
      "Downloading and checking the new release…"
    );
    const done = render({ check: OUTDATED, update: UPDATED });
    expect(done).toContain("Updated: Enterprise 19.2 → 20.0. The previous files are kept as a backup.");
    expect(done).toContain('role="status"');
  });

  it("reports a failed update with its reason and the cache kept", () => {
    const failed = { ...UPDATED, ok: false, outcome: "failed", reason: "Enterprise: the download carries no techniques", changes: [], kept_previous: true };
    expect(updateOutcome(failed)).toEqual({
      ok: false,
      text: "The update failed: Enterprise: the download carries no techniques. The previous cache is unchanged.",
    });
    expect(render({ check: OUTDATED, update: failed })).toContain('role="alert"');
    expect(render({ updateError: "Request failed: 503" })).toContain(
      "The update could not be run: Request failed: 503"
    );
  });
});

describe("review fixes", () => {
  it("shows MITRE's release day as stamped, in UTC, wherever the viewer is", () => {
    expect(releaseDate("2026-10-13T23:30:00Z")).toBe("Oct 13, 2026");
    expect(releaseDate("2026-10-14T00:00:00Z")).toBe("Oct 14, 2026");
  });

  it("an update whose process stopped reads as not finished, with when and who", () => {
    const line = lastUpdateLine({
      ok: false,
      outcome: "interrupted",
      reason:
        "the update started 2026-10-14T10:00:00+00:00 by Ada Admin did not finish: " +
        "the process running it stopped",
      started_at: "2026-10-14T10:00:00+00:00",
      triggered_by: { name: "Ada Admin" },
      changes: [],
      kept_previous: null,
    });
    expect(line).toContain("Last update: did not finish.");
    expect(line).toContain("started 2026-10-14T10:00:00+00:00 by Ada Admin");
    expect(line).toContain("What the cache holds now is shown in the table above.");
  });

  it("a failed swap that replaced a domain names it and claims nothing kept", () => {
    const partial = {
      ...UPDATED,
      ok: false,
      outcome: "failed",
      reason: "ICS: the new file could not be moved into place (disk full)",
      kept_previous: false,
    };
    const text = updateOutcome(partial).text;
    expect(text).toContain("Replaced: Enterprise 19.2 → 20.0; every other domain is unchanged.");
    expect(text).not.toContain("The previous cache is unchanged");
  });

  it("an update arq gave up on says stopped and does not guess the result", () => {
    const stopped = {
      ok: false,
      outcome: "stopped",
      reason: "the worker stopped the update (TimeoutError)",
      changes: [],
      kept_previous: null,
    };
    expect(updateOutcome(stopped).text).toBe(
      "The update stopped: the worker stopped the update (TimeoutError). " +
        "What the cache holds now is shown in the table above."
    );
  });

  it("keeps tracking through failed polls and says so", () => {
    const text = lostContactText(2, "Request failed: 503");
    expect(text).toContain("2 attempts in a row: Request failed: 503");
    expect(text).toContain("still asking");
    expect(render({ updating: true, pollTrouble: text })).toContain("still asking");
  });

  it("the dialog takes focus and does not claim to be modal", () => {
    const html = render({ check: OUTDATED, choosing: true });
    expect(html).toContain('role="dialog"');
    expect(html).toContain('tabindex="-1"');
    expect(html).not.toContain("aria-modal");
  });

  it("reads the status again once the interval is saved", () => {
    expect(statusIsStale(STATUS, 7)).toBe(false);
    expect(statusIsStale(STATUS, 30)).toBe(true);
    expect(statusIsStale(STATUS, undefined)).toBe(false);
    expect(statusIsStale(null, 30)).toBe(false);
  });
});
