/* Shared label/value pair used by the report detail tabs.
 *
 * audit 2026-07-26 (§5 "yinelenen yardımcılar"): IDENTITY and ATTRIBUTION each
 * carried their own copy; the ATTRIBUTION one was a superset (it accepts
 * `valueClassName` so an ungrounded family can render muted + struck through).
 * That superset is kept here as the single definition.
 */
export default function Field({
  label,
  value,
  valueClassName,
}: {
  label: string;
  value: string;
  valueClassName?: string;
}) {
  return (
    <div>
      <div className="text-[11px] text-text-muted uppercase tracking-wider mb-1">
        {label}
      </div>
      <div
        className={`text-sm text-text-primary break-all ${valueClassName ?? ""}`}
      >
        {value}
      </div>
    </div>
  );
}
