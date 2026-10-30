import { notFound } from "next/navigation";
import PreviewFrame from "@/components/preview/PreviewFrame";
import { previewEnabled } from "@/components/preview/flag";
import { THEME_BOOT_SCRIPT } from "@/components/preview/themeScript";

/**
 * The new analysis page, behind `NEXT_PUBLIC_UI_NEXT`.
 *
 * A route of its own so today's `/analysis/[id]` pages and their layout are
 * untouched: with the flag off this answers 404 and nothing else changes.
 * The inline script puts the reader's theme on <html> before the first paint
 * (see `themeScript.ts`); a client-side visit gets it from `useUiTheme`.
 */
export default async function AnalysisPreviewLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ id: string }>;
}) {
  if (!previewEnabled()) notFound();
  const { id } = await params;
  return (
    <>
      <script dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
      <PreviewFrame jobId={id}>{children}</PreviewFrame>
    </>
  );
}
