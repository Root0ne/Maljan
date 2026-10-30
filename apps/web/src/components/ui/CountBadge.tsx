/** A count beside a title or a tab label; `label` names what is counted for a screen reader. */
export default function CountBadge({ count, label }: { count: number; label?: string }) {
  return (
    <span className="inline-flex min-w-5 items-center justify-center rounded-full bg-bg-active px-1.5 text-[11px] font-medium leading-4 text-text-secondary">
      {count.toLocaleString("en-US")}
      {label && <span className="sr-only"> {label}</span>}
    </span>
  );
}
