import CopyButton from "./CopyButton";
import { scrollRegion, SCROLL_REGION_FOCUS } from "./scrollRegion";

/**
 * A listing: a rule's source, a script, a configuration file.
 *
 * A bar names what it is and how long, with the copy beside it; the body is
 * the text exactly as written, with line numbers a reader can quote, in a
 * named region that scrolls sideways so a long line never widens the page.
 * The numbers are not part of the text a selection or the copy takes.
 */
export default function CodeBlock({
  code,
  label,
  name,
}: {
  code: string;
  /** What the listing is in ("YARA", "Sigma"). */
  label: string;
  /** Unique on the page: the region's and the copy's name. */
  name: string;
}) {
  const lines = code.replace(/\n$/, "").split("\n");
  return (
    <div className="overflow-hidden rounded border border-border-light bg-bg-deep">
      <div className="flex items-center gap-3 border-b border-border-light px-3 py-1.5 text-[11px] text-text-muted">
        <span className="font-medium text-text-secondary">{label}</span>
        <span>
          {lines.length} line{lines.length === 1 ? "" : "s"}
        </span>
        <span className="ml-auto">
          <CopyButton value={code} what={name} />
        </span>
      </div>
      <div {...scrollRegion(name)} className={`overflow-x-auto ${SCROLL_REGION_FOCUS}`}>
        <pre className="grid min-w-max grid-cols-[auto_1fr] py-2 font-mono text-xs leading-5">
          {lines.map((line, i) => (
            <code key={i} className="contents">
              <span aria-hidden="true" className="select-none px-3 text-right text-text-muted tabular-nums">
                {i + 1}
              </span>
              <span className="whitespace-pre pr-4 text-text-primary">{line || " "}</span>
            </code>
          ))}
        </pre>
      </div>
    </div>
  );
}
