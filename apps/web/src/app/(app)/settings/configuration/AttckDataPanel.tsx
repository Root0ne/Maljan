"use client";

import { useCallback, useEffect, useRef, useState, type RefObject } from "react";
import { api } from "@/lib/api";
import { pollFailure } from "@/components/analysis/polling";
import type { AttckCheckResult, AttckStatus, AttckUpdateResult } from "@/types/settings";
import {
  UPDATE_POLL_MS,
  lastCheckLine,
  lastUpdateLine,
  lostContactText,
  pollStoppedText,
  nextCheckSentence,
  readCheck,
  shouldRefetch,
  statusRows,
  updateOutcome,
  waitSentence,
} from "./attckData";

export interface AttckDataViewProps {
  status: AttckStatus | null;
  statusError: string | null;
  checking: boolean;
  check: AttckCheckResult | null;
  checkError: string | null;
  /** The outdated dialog is open: the admin has not chosen yet. */
  choosing: boolean;
  /** The admin chose to wait for the automatic check. */
  waited: boolean;
  updating: boolean;
  update: AttckUpdateResult | null;
  updateError: string | null;
  /** A poll of the running update keeps failing; tracking goes on. */
  pollTrouble?: string | null;
  /** Where focus goes when the dialog opens, and comes back to after it. */
  dialogRef?: RefObject<HTMLDivElement | null>;
  checkRef?: RefObject<HTMLButtonElement | null>;
  onCheck: () => void;
  onUpdate: () => void;
  onWait: () => void;
}

/** The cache's status, the check button, the outdated dialog and the update's outcome. */
export function AttckDataView({ dialogRef, checkRef, ...props }: AttckDataViewProps) {
  const { status, check } = props;
  const view = check ? readCheck(check) : null;
  const busy = props.checking || props.updating;
  return (
    <div data-testid="attck-data" className="mt-2 border border-border rounded px-3 py-2">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <p className="text-xs text-text-secondary">
          The cached ATT&amp;CK bundles the technique index is built from, as the worker that keeps
          them reads them.
        </p>
        <button
          ref={checkRef}
          type="button"
          className="h-6 rounded border border-border px-2 text-[11px] text-accent-strong disabled:opacity-50"
          disabled={busy}
          onClick={props.onCheck}
        >
          {props.checking ? "Checking…" : "Check now"}
        </button>
      </div>

      {props.statusError && (
        <p role="alert" className="text-[11px] text-status-red mt-2">
          The cache status could not be read: {props.statusError}
        </p>
      )}

      {status && (
        <>
          <table className="w-full text-[11px] mt-2">
            <thead className="text-text-muted text-left">
              <tr>
                <th className="font-normal pr-2">Domain</th>
                <th className="font-normal pr-2">Cached version</th>
                <th className="font-normal pr-2">Released</th>
                <th className="font-normal pr-2">Cached at</th>
                <th className="font-normal pr-2">Age</th>
                <th className="font-normal">Next automatic check</th>
              </tr>
            </thead>
            <tbody className="text-text-secondary">
              {statusRows(status).map((row) => (
                <tr key={row.domain} data-attck-domain={row.domain}>
                  <td className="pr-2 text-text-primary">{row.label}</td>
                  <td className="pr-2 font-mono">{row.version}</td>
                  <td className="pr-2">{row.released}</td>
                  <td className="pr-2">{row.cachedAt}</td>
                  <td className="pr-2">{row.age}</td>
                  <td>{row.nextCheck}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="text-[11px] text-text-muted mt-2">
            {nextCheckSentence(status.refresh_days, status.next_check_at)}
          </p>
          <p className="text-[11px] text-text-muted">{lastCheckLine(status.last_check)}</p>
          <p className="text-[11px] text-text-muted">{lastUpdateLine(status.last_update)}</p>
          {status.running && (
            <p className="text-[11px] text-text-muted">An update is running now.</p>
          )}
        </>
      )}

      {props.checkError && (
        <p role="alert" className="text-[11px] text-status-red mt-2">
          The check could not be run: {props.checkError}
        </p>
      )}

      {view?.kind === "up_to_date" && (
        <p role="status" className="text-[11px] text-status-green mt-2">
          {view.text}
        </p>
      )}

      {view?.kind === "failed" && (
        <p role="alert" className="text-[11px] text-status-red mt-2">
          {view.text}
        </p>
      )}

      {view?.kind === "outdated" && check && props.choosing && (
        <div
          ref={dialogRef}
          role="dialog"
          tabIndex={-1}
          aria-label="A newer ATT&CK release is available"
          className="mt-3 border border-border rounded bg-bg-deep px-3 py-2"
          onKeyDown={(e) => {
            if (e.key === "Escape") props.onWait();
          }}
        >
          <p className="text-xs text-text-primary">A newer ATT&amp;CK release is available.</p>
          <ul className="text-[11px] text-text-secondary mt-1">
            {view.rows.map((row) => (
              <li key={row.label}>
                {row.label}: cached {row.cached}, latest {row.latest}
                {row.released ? ` (released ${row.released})` : ""}
              </li>
            ))}
          </ul>
          <p className="text-[11px] text-text-muted mt-1">
            Update now downloads the new release, checks it and swaps it in, keeping the current
            files as a backup. {nextCheckSentence(check.refresh_days, check.next_check_at)}
          </p>
          <div className="flex gap-3 mt-2">
            <button
              type="button"
              className="text-xs text-accent-strong disabled:opacity-50"
              disabled={busy}
              onClick={props.onUpdate}
            >
              Update now
            </button>
            <button
              type="button"
              className="text-xs text-text-secondary"
              onClick={props.onWait}
            >
              Wait for the scheduled update
            </button>
          </div>
        </div>
      )}

      {view?.kind === "outdated" && check && props.waited && !props.updating && !props.update && (
        <p role="status" className="text-[11px] text-text-secondary mt-2">
          {waitSentence(check)}
        </p>
      )}

      {props.updating && (
        <p role="status" className="text-[11px] text-text-muted mt-2">
          Downloading and checking the new release…
        </p>
      )}

      {props.pollTrouble && (
        <p role="status" className="text-[11px] text-status-orange mt-2">
          {props.pollTrouble}
        </p>
      )}

      {props.updateError && (
        <p role="alert" className="text-[11px] text-status-red mt-2">
          The update could not be run: {props.updateError}
        </p>
      )}

      {props.update && (
        <p
          role={props.update.ok ? "status" : "alert"}
          className={`text-[11px] mt-2 ${props.update.ok ? "text-status-green" : "text-status-red"}`}
        >
          {updateOutcome(props.update).text}
        </p>
      )}
    </div>
  );
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** The panel under the "ATT&CK data" settings: reads the status, runs the check and the update. */
export default function AttckDataPanel({ savedInterval }: { savedInterval?: unknown }) {
  const [status, setStatus] = useState<AttckStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [check, setCheck] = useState<AttckCheckResult | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [choosing, setChoosing] = useState(false);
  const [waited, setWaited] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [update, setUpdate] = useState<AttckUpdateResult | null>(null);
  const [updateError, setUpdateError] = useState<string | null>(null);
  const [pollTrouble, setPollTrouble] = useState<string | null>(null);
  const alive = useRef(true);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const checkRef = useRef<HTMLButtonElement | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const next = await api.getAttckStatus();
      if (!alive.current) return;
      setStatus(next);
      setStatusError(null);
    } catch (e) {
      if (alive.current) setStatusError(message(e));
    }
  }, []);

  useEffect(() => {
    alive.current = true;
    api
      .getAttckStatus()
      .then((next) => {
        if (!alive.current) return;
        setStatus(next);
        setStatusError(null);
      })
      .catch((e) => {
        if (alive.current) setStatusError(message(e));
      });
    return () => {
      alive.current = false;
    };
  }, []);

  // The interval was saved since the status was read: the next-check line is
  // read again under the new one.
  // Once per saved value: another API replica can still answer with the old
  // interval for a few seconds, and asking again on each such answer would loop.
  const askedFor = useRef<unknown>(undefined);
  useEffect(() => {
    if (!shouldRefetch(status, savedInterval, askedFor.current)) return;
    askedFor.current = savedInterval;
    api
      .getAttckStatus()
      .then((next) => {
        if (alive.current) setStatus(next);
      })
      .catch((e) => {
        if (alive.current) setStatusError(message(e));
      });
  }, [status, savedInterval]);

  // Focus moves into the dialog when it opens.
  useEffect(() => {
    if (choosing) dialogRef.current?.focus();
  }, [choosing]);

  const onCheck = useCallback(async () => {
    setChecking(true);
    setCheck(null);
    setCheckError(null);
    setChoosing(false);
    setWaited(false);
    setUpdate(null);
    setUpdateError(null);
    try {
      const result = await api.checkAttck();
      if (!alive.current) return;
      setCheck(result);
      setChoosing(result.ok && result.outcome === "outdated");
    } catch (e) {
      if (alive.current) setCheckError(message(e));
    } finally {
      if (alive.current) setChecking(false);
      void loadStatus();
    }
  }, [loadStatus]);

  const onWait = useCallback(() => {
    setChoosing(false);
    setWaited(true);
    checkRef.current?.focus();
  }, []);

  const onUpdate = useCallback(async () => {
    setChoosing(false);
    setUpdating(true);
    setUpdate(null);
    setUpdateError(null);
    try {
      const { job_id } = await api.startAttckUpdate();
      let failures = 0;
      for (;;) {
        await new Promise((resolve) => setTimeout(resolve, UPDATE_POLL_MS));
        if (!alive.current) return;
        let progress;
        try {
          progress = await api.getAttckUpdate(job_id);
        } catch (e) {
          // A refusal asking again cannot change ends the tracking, and says
          // so; any other failed poll is not a failed update: keep asking.
          const failure = pollFailure(e);
          if (failure.kind !== "retry") {
            setUpdateError(
              pollStoppedText(failure.kind === "stop" ? failure.message : "the update was not found"),
            );
            break;
          }
          failures += 1;
          setPollTrouble(lostContactText(failures, message(e)));
          continue;
        }
        failures = 0;
        setPollTrouble(null);
        if (progress.state === "done" && progress.result) {
          setUpdate(progress.result);
          break;
        }
        if (progress.state === "unknown") {
          setUpdateError(
            "the worker has no record of this update: it was not started within ten minutes, " +
              "or its result has expired"
          );
          break;
        }
      }
    } catch (e) {
      if (alive.current) setUpdateError(message(e));
    } finally {
      if (alive.current) {
        setUpdating(false);
        setPollTrouble(null);
      }
      void loadStatus().then(() => checkRef.current?.focus());
    }
  }, [loadStatus]);

  return (
    <AttckDataView
      status={status}
      statusError={statusError}
      checking={checking}
      check={check}
      checkError={checkError}
      choosing={choosing}
      waited={waited}
      updating={updating}
      update={update}
      updateError={updateError}
      pollTrouble={pollTrouble}
      dialogRef={dialogRef}
      checkRef={checkRef}
      onCheck={() => void onCheck()}
      onUpdate={() => void onUpdate()}
      onWait={onWait}
    />
  );
}
