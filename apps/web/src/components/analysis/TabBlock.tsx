import type { ReactNode } from "react";
import Section from "@/components/ui/Section";

/**
 * One block of a tab that gathers what several older pages drew: a heading
 * with an anchor a link can land on, then the block's own content.
 *
 * A block with nothing in it keeps its place, greyed and saying so (the
 * kit's empty `Section`), so the tab's order never moves and an absence reads
 * as an answer.
 */
export default function TabBlock({
  id,
  title,
  empty = false,
  emptyText,
  children,
}: {
  /** The anchor (`#persistence`) a link or an old route lands on. */
  id: string;
  title: string;
  empty?: boolean;
  emptyText?: string;
  children?: ReactNode;
}) {
  if (empty) {
    return (
      <div id={id} className="scroll-mt-16">
        <Section title={title} empty emptyText={emptyText} />
      </div>
    );
  }
  return (
    <section id={id} aria-labelledby={`${id}-heading`} className="scroll-mt-16 space-y-3">
      <h2 id={`${id}-heading`} className="text-sm font-semibold text-text-primary">
        {title}
      </h2>
      {children}
    </section>
  );
}
