"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { EffortOptions } from "@/types/settings";
import { effortField } from "./modelList";

/**
 * One model's reasoning effort, drawn from the levels the backend serves for
 * its provider and model (`GET /settings/effort-options`): a select where the
 * backend names the levels, a text box where the endpoint names its own, and
 * nothing for a provider that sends none. Blank inherits the provider's
 * global setting, which the blank choice names.
 */
export default function EffortField({
  provider,
  model,
  value,
  label,
  inputClass,
  onChange,
}: {
  provider: string;
  model: string;
  value: string;
  label: string;
  inputClass: string;
  onChange: (effort: string | null) => void;
}) {
  // The answer is kept with the pair it was asked for, so a field whose
  // provider or model has since changed reads as not yet answered.
  const [answer, setAnswer] = useState<{ key: string; options: EffortOptions | null } | null>(
    null,
  );
  const key = `${provider}\u0000${model}`;

  useEffect(() => {
    if (!provider) return;
    let live = true;
    // A short wait so a model name being typed asks once, not per keystroke.
    const timer = setTimeout(() => {
      Promise.resolve()
        .then(() => api.getEffortOptions(provider, model))
        .then((options) => {
          if (live) setAnswer({ key: `${provider}\u0000${model}`, options });
        })
        .catch(() => {
          if (live) setAnswer({ key: `${provider}\u0000${model}`, options: null });
        });
    }, 250);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [provider, model]);

  const options = answer && answer.key === key ? answer.options : null;
  const field = effortField(options, value);
  if (field.kind === "hidden") return null;
  const put = (raw: string) => onChange(raw.trim() === "" ? null : raw);
  return field.kind === "select" ? (
    <select
      className={inputClass}
      aria-label={label}
      value={value}
      onChange={(e) => put(e.target.value)}
    >
      {field.choices.map((c) => (
        <option key={c.value} value={c.value}>
          {c.label}
        </option>
      ))}
    </select>
  ) : (
    <input
      className={inputClass}
      aria-label={label}
      placeholder={field.placeholder}
      value={value}
      onChange={(e) => put(e.target.value)}
    />
  );
}
