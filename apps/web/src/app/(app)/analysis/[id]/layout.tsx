import AnalysisFrame from "@/components/analysis/AnalysisFrame";
import { THEME_BOOT_SCRIPT } from "@/components/analysis/themeScript";

/**
 * Every tab of one analysis, under one frame (`AnalysisFrame`): the sticky
 * header, the six tabs and the evidence drawer.
 *
 * The inline script puts the reader's theme on <html> before the first paint
 * (see `themeScript.ts`); a client-side visit gets it from `useUiTheme`.
 */
export default async function AnalysisLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return (
    <>
      <script dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
      <AnalysisFrame id={id}>{children}</AnalysisFrame>
    </>
  );
}
