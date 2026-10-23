import type { ReportAbsence } from "./reportAbsence";

/** A tab with no report behind it, saying which absence it is (`reportAbsence`). */
export default function ReportAbsent({ absence }: { absence: ReportAbsence }) {
  return (
    <div
      role="status"
      className={`p-8 text-center text-sm ${
        absence.kind === "unreadable" ? "text-status-red" : "text-text-secondary"
      } ${absence.kind === "running" ? "animate-pulse" : ""}`}
    >
      {absence.text}
    </div>
  );
}
