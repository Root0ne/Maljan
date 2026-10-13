"use client";

import { useOptionalSettingsContext } from "./SettingsContext";
import { LEFT_OUT_HEADLINE, leftOutSteps } from "./packStepsLeftOut";

/**
 * Beside the triage pack's steps: each stored step the API leaves out, with
 * why, so a stored value is never shown as in force when it does not run.
 */
export default function PackStepsLeftOutNote() {
  const schema = useOptionalSettingsContext()?.schema;
  const steps = leftOutSteps(schema?.pack_steps_left_out);
  if (steps.length === 0) return null;
  return (
    <div className="mt-1 text-[11px] text-status-orange" data-pack-steps-left-out>
      <p>{LEFT_OUT_HEADLINE}</p>
      <ul className="mt-1 space-y-0.5">
        {steps.map(({ step, reason }) => (
          <li key={step} data-pack-step-left-out={step}>
            <span className="font-mono">{step}</span>
            {reason && <span>: {reason}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}
