"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import type { CatalogEntry, PatchResult, ProbeResult } from "@/types/settings";
import FieldRow from "../configuration/FieldRow";
import { buildFieldRowProps } from "../configuration/fieldRowProps";
import { probeLabel } from "../configuration/GroupHeader";
import { buildReviewItems, ReviewList } from "../configuration/ReviewList";
import { useSettingsContext, type SettingsContextValue } from "../configuration/SettingsContext";
import { appliesSummary } from "../configuration/vocabulary";
import { isProbeStale, probeFingerprint } from "./probeStale";
import AgentFormStep, { agentStepSection } from "./steps/AgentFormStep";
import ProfilePickerStep from "./steps/ProfilePickerStep";
import RestMappingStep from "./steps/RestMappingStep";
import ServerFormStep, { serverStepSection } from "./steps/ServerFormStep";
import {
  PROVIDER_CHOICE_KEY,
  providerChoiceCopy,
  type GuideContext,
  type GuideDef,
  type GuideStep,
} from "./guides";

/** A finished probe result, plus a fingerprint of the values the probe read
 *  when it ran: the result stops being shown as soon as those values move,
 *  because it no longer describes what a press would do now. */
interface ProbeEntry {
  result: ProbeResult | "running";
  inputsWhenRun: string;
}

function Row({ ctx, entry }: { ctx: SettingsContextValue; entry: CatalogEntry }) {
  return <FieldRow {...buildFieldRowProps(ctx, entry)} variant="guide" />;
}

/** The provider radio cards: the selector entry's own choices, one line of
 *  plain language each, staged into the same catalog key the console edits. */
function ProviderChoice({
  ctx,
  selectorKey,
}: {
  ctx: SettingsContextValue;
  selectorKey: string;
}) {
  const entry = ctx.entriesByKey[selectorKey];
  if (!entry) {
    return <p role="alert">This provider setting is not in the catalog.</p>;
  }
  const current = String(ctx.effectiveValue(selectorKey) ?? "");
  const choices = entry.choices ?? [];

  return (
    <fieldset className="border-0 p-0 m-0">
      <legend className="sr-only">{entry.title}</legend>
      <div className="grid gap-2 sm:grid-cols-2">
        {choices.map((choice) => {
          const copy = providerChoiceCopy(selectorKey, choice);
          return (
            <label
              key={choice}
              className={`flex gap-3 items-start border rounded px-3 py-2 cursor-pointer ${
                current === choice ? "border-accent bg-bg-surface" : "border-border"
              }`}
            >
              <input
                type="radio"
                name={selectorKey}
                value={choice}
                checked={current === choice}
                onChange={() => ctx.stage(selectorKey, choice)}
                className="mt-1"
              />
              <span>
                <span className="block text-sm text-text-primary">{copy.title}</span>
                {copy.blurb && (
                  <span className="block text-xs text-text-secondary">{copy.blurb}</span>
                )}
              </span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}

/** The step's fields: the plain ones, then whatever the catalog or the step
 *  itself calls advanced, behind a disclosure. */
function StepFields({
  ctx,
  step,
}: {
  ctx: SettingsContextValue;
  step: GuideStep;
}) {
  const entries = (step.keys ?? [])
    .map((key) => ctx.entriesByKey[key])
    .filter((e): e is CatalogEntry => e !== undefined)
    .filter((e) => step.respectAppliesWhen === false || ctx.isVisible(e));

  const isAdvanced = (e: CatalogEntry) => e.advanced || (step.advancedKeys ?? []).includes(e.key);
  const plain = entries.filter((e) => !isAdvanced(e));
  const advanced = entries.filter(isAdvanced);

  if (entries.length === 0) {
    return <p className="text-sm text-text-secondary">Nothing to fill in for this choice.</p>;
  }

  return (
    <div>
      {plain.map((entry) => (
        <Row key={entry.key} ctx={ctx} entry={entry} />
      ))}
      {advanced.length > 0 && (
        <details data-testid={`advanced-${step.id}`} className="mt-2">
          <summary className="text-xs text-text-secondary cursor-pointer py-1">
            Advanced ({advanced.length})
          </summary>
          <div>
            {advanced.map((entry) => (
              <Row key={entry.key} ctx={ctx} entry={entry} />
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

export default function GuidePage({ guide }: { guide: GuideDef }) {
  const ctx = useSettingsContext();
  const router = useRouter();
  const searchParams = useSearchParams();
  // Per-guide scratch: choices no catalog key holds (a selected server key, a
  // clone source, whether the new agent resolved). The language-model guide
  // needs none; the tool-server and agent guides fill it in. A step patches
  // it through `setGuideState`, which re-renders the guide so the step's own
  // `canContinue` reads what the body just stored.
  const [state, setState] = useState<Record<string, unknown>>({});
  const setGuideState = useCallback(
    (patch: Record<string, unknown>) => setState((s) => ({ ...s, ...patch })),
    []
  );
  const [probes, setProbes] = useState<Record<string, ProbeEntry | undefined>>({});
  const [applied, setApplied] = useState<PatchResult | null>(null);
  // Every key any step of this guide has offered so far — the review step
  // shows this guide's changes only, and a provider switch must not drop the
  // keys the previous choice staged.
  const [touched, setTouched] = useState<string[]>([]);

  const probeInputs = useCallback(
    (probeId: string) => probeFingerprint(ctx.probeValues(probeId)),
    [ctx]
  );

  const probeResult = useCallback(
    (probeId: string): ProbeResult | "running" | undefined => {
      const entry = probes[probeId];
      if (!entry) return undefined;
      if (entry.result === "running") return "running";
      return isProbeStale(entry.inputsWhenRun, probeInputs(probeId)) ? undefined : entry.result;
    },
    [probes, probeInputs]
  );

  const guideCtx = useMemo<GuideContext>(
    () => ({
      effective: ctx.effectiveValue,
      staged: ctx.pending,
      probeOk: (probeId: string) => {
        const result = probeResult(probeId);
        return result !== undefined && result !== "running" && result.ok;
      },
      schema: ctx.schema!,
      state,
    }),
    [ctx.effectiveValue, ctx.pending, ctx.schema, probeResult, state]
  );

  const steps = useMemo(() => guide.steps(guideCtx), [guide, guideCtx]);
  const selectorKey = PROVIDER_CHOICE_KEY[guide.id];

  const stepKeys = useMemo(() => {
    const keys = steps.flatMap((s) => [...(s.keys ?? []), ...(s.reviewKeys ?? [])]);
    if (selectorKey && steps.some((s) => s.component === "provider-choice")) keys.push(selectorKey);
    return keys;
  }, [steps, selectorKey]);

  useEffect(() => {
    // Accumulated, not derived: which keys the steps offer depends on the
    // provider chosen, and a key staged under the previous choice still
    // belongs to this guide's review list.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setTouched((prev) => {
      const merged = new Set(prev);
      stepKeys.forEach((k) => merged.add(k));
      return merged.size === prev.length ? prev : Array.from(merged);
    });
  }, [stepKeys]);

  useEffect(() => {
    // A finished apply leaves its summary on the review step. The moment the
    // operator stages anything again, that summary is describing the previous
    // round: drop it so the review list and the Apply button come back.
    if (Object.keys(ctx.pending).length === 0) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setApplied((previous) => (previous === null ? previous : null));
  }, [ctx.pending]);

  const requested = searchParams.get("step");
  const index = Math.max(
    0,
    steps.findIndex((s) => s.id === requested)
  );
  const step = steps[index];

  const goTo = useCallback(
    (id: string) => router.push(`/settings/setup/${guide.id}?step=${id}`),
    [router, guide.id]
  );

  const onProbe = useCallback(
    async (name: string) => {
      // The probe reads keys from more than one group (the provider selector
      // and the vendor's endpoint live apart), so every catalog key carrying
      // this probe id travels with it — the same rule the console uses.
      const keys = Array.from(ctx.entries.values())
        .filter((e) => e.probe === name)
        .map((e) => e.key);
      const inputsWhenRun = probeInputs(name);
      setProbes((p) => ({ ...p, [name]: { result: "running", inputsWhenRun } }));
      const result = await ctx.probe(name, keys).catch((e) => ({
        ok: false,
        latency_ms: 0,
        detail: String(e),
        models: null,
        tools: null,
        details: null,
      }));
      if (result.models) ctx.setModels(result.models);
      setProbes((p) => ({ ...p, [name]: { result, inputsWhenRun } }));
    },
    [ctx, probeInputs]
  );

  if (!step) {
    return <p role="alert">This guide has no steps.</p>;
  }

  const blockedReason = step.canContinue?.(guideCtx) ?? null;
  const allItems = buildReviewItems(ctx);
  const lines = allItems.filter((item) => touched.includes(item.key));
  // Apply PATCHes the whole pending map, not this guide's slice of it, so a
  // value staged in the console before the guide was opened travels with it.
  // The review step names those too rather than sending them unannounced.
  const alsoStaged = allItems.filter((item) => !touched.includes(item.key));
  const stagedCount = lines.length + alsoStaged.length;
  // Counted as rows of the two lists above, not as raw error entries: one
  // composite leaf can carry several field-level errors and still be one row.
  const errorCount = [...lines, ...alsoStaged].filter((item) => item.error).length;
  const probeId = step.probe;
  const result = probeId ? probeResult(probeId) : undefined;

  const onApply = async () => {
    const res = await ctx.apply();
    if (res) setApplied(res);
  };

  return (
    <section>
      <div className="flex items-start justify-between gap-4 flex-wrap mb-3">
        <div className="min-w-0">
          <h2 className="text-base font-semibold text-text-primary">{guide.title}</h2>
          <p className="text-xs text-text-secondary mt-1">{guide.blurb}</p>
        </div>
        <Link href={guide.groupHref} className="text-xs text-accent-strong">
          Open in the full settings
        </Link>
      </div>

      <ol aria-label="Steps" className="flex flex-wrap gap-2 mb-4">
        {steps.map((s, i) => (
          <li key={s.id} aria-current={i === index ? "step" : undefined}>
            <button
              type="button"
              onClick={() => goTo(s.id)}
              className={`text-xs px-2 py-1 rounded border ${
                i === index
                  ? "border-accent text-accent"
                  : "border-border text-text-secondary hover:text-text-primary"
              }`}
            >
              {i + 1}. {s.title}
            </button>
          </li>
        ))}
      </ol>

      <h3 className="text-sm font-medium text-text-primary">{step.title}</h3>
      {step.intro && <p className="text-xs text-text-secondary mt-1 mb-2">{step.intro}</p>}
      {step.link && (
        <p className="text-xs mb-2">
          <Link href={step.link.href} className="text-accent-strong">
            {step.link.label}
          </Link>
        </p>
      )}

      {step.keys !== undefined && <StepFields ctx={ctx} step={step} />}

      {step.component === "provider-choice" && selectorKey && (
        <ProviderChoice ctx={ctx} selectorKey={selectorKey} />
      )}

      {step.component === "server-form" && (
        <ServerFormStep
          section={serverStepSection(step.section)}
          state={state}
          setState={setGuideState}
        />
      )}

      {step.component === "agent-form" && (
        <AgentFormStep
          section={agentStepSection(step.section)}
          state={state}
          setState={setGuideState}
        />
      )}

      {step.component === "profile-picker" && (
        <ProfilePickerStep state={state} setState={setGuideState} />
      )}

      {step.component === "rest-mapping" && <RestMappingStep />}

      {probeId && (
        <div className="flex items-center gap-3 flex-wrap mt-2">
          <button
            type="button"
            className="text-xs text-accent-strong disabled:opacity-50"
            disabled={result === "running"}
            onClick={() => void onProbe(probeId)}
          >
            {probeLabel(probeId)}
          </button>
          {result === "running" && <span className="text-[11px] text-text-muted">testing…</span>}
          {result && result !== "running" && (
            <span
              className={`text-[11px] ${result.ok ? "text-status-green" : "text-status-red"}`}
              role="status"
            >
              {result.ok ? "ok" : "failed"} · {result.latency_ms} ms · {result.detail}
            </span>
          )}
        </div>
      )}

      {step.component === "review" && (
        <div className="mt-2">
          {applied ? (
            <div className="text-sm text-status-green" role="status">
              <p>{appliesSummary(applied.applies, applied.applied.length)}</p>
              <p className="mt-2 text-xs">
                <Link href={guide.groupHref} className="text-accent-strong">
                  See these settings in the console
                </Link>{" "}
                ·{" "}
                <Link href="/settings/setup" className="text-accent-strong">
                  Run another guide
                </Link>
              </p>
            </div>
          ) : stagedCount === 0 ? (
            <p className="text-sm text-text-secondary">Nothing to apply.</p>
          ) : (
            <>
              {errorCount > 0 && (
                <p className="text-xs text-status-red mb-2" role="alert">
                  {errorCount} field{errorCount === 1 ? " needs" : "s need"} attention
                </p>
              )}
              <ReviewList lines={lines} />
              {alsoStaged.length > 0 && (
                <div className="mt-4 pt-3 border-t border-border">
                  <h4 className="text-xs font-medium text-text-primary mb-2">
                    Also staged elsewhere
                  </h4>
                  <ReviewList lines={alsoStaged} />
                </div>
              )}
            </>
          )}
        </div>
      )}

      <div className="flex items-center gap-4 flex-wrap mt-6 pt-3 border-t border-border">
        <button
          type="button"
          className="text-xs text-text-secondary hover:text-text-primary disabled:opacity-50"
          disabled={index === 0}
          onClick={() => {
            const previous = steps[index - 1];
            if (previous) goTo(previous.id);
          }}
        >
          Back
        </button>
        {step.component === "review" ? (
          <>
            <button
              type="button"
              disabled={ctx.saving || stagedCount === 0 || applied !== null}
              className="px-3 py-1.5 text-xs font-medium uppercase tracking-wider bg-accent text-white rounded hover:bg-accent-hover transition-colors disabled:opacity-50"
              onClick={onApply}
            >
              {ctx.saving ? "Saving…" : "Apply"}
            </button>
            {applied === null && alsoStaged.length > 0 && (
              <span className="text-xs text-text-muted">
                Apply also sends the {alsoStaged.length} change
                {alsoStaged.length === 1 ? "" : "s"} staged elsewhere.
              </span>
            )}
          </>
        ) : (
          <>
            <button
              type="button"
              disabled={blockedReason !== null || index >= steps.length - 1}
              className="px-3 py-1.5 text-xs font-medium uppercase tracking-wider bg-accent text-white rounded hover:bg-accent-hover transition-colors disabled:opacity-50"
              onClick={() => {
                const next = steps[index + 1];
                if (next) goTo(next.id);
              }}
            >
              Continue
            </button>
            {blockedReason && <span className="text-xs text-text-muted">{blockedReason}</span>}
          </>
        )}
        <Link href={guide.groupHref} className="text-xs text-accent-strong">
          Open in the full settings
        </Link>
      </div>
    </section>
  );
}
