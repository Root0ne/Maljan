/* Shared table-header cell.
 *
 * audit 2026-07-26 (§5 "yinelenen yardımcılar"): three byte-identical `Th`
 * components lived in the STATIC, DYNAMIC and NETWORK tabs. One definition
 * keeps the table chrome consistent as the styling evolves.
 */
export default function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider">
      {children}
    </th>
  );
}
