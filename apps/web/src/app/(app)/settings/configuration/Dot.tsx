/** One of the small state dots the master–detail editors put in their lists. */
export default function Dot({ label, className }: { label: string; className: string }) {
  return (
    <span
      role="img"
      aria-label={label}
      title={label}
      className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${className}`}
    />
  );
}
