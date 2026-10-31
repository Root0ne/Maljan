import AnalysisFrame from "@/components/analysis/AnalysisFrame";

/**
 * Every tab of one analysis, under one frame (`AnalysisFrame`): the sticky
 * header, the six tabs and the evidence drawer.
 *
 * The reader's theme reaches <html> before the first paint of a full load
 * from the root layout's boot script (see `themeScript.ts`); a client-side
 * visit gets it from `useUiTheme`.
 */
export default async function AnalysisLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <AnalysisFrame id={id}>{children}</AnalysisFrame>;
}
