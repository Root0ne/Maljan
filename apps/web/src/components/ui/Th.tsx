/* Shared table-header cell.
 *
 * Three byte-identical `Th`
 * components lived in the STATIC, DYNAMIC and NETWORK tabs. One definition
 * keeps the table chrome consistent as the styling evolves. Plain case, as
 * every heading of the console is: capitals are not a second weight.
 */
export default function Th({ children }: { children: React.ReactNode }) {
  return (
    <th
      scope="col"
      className="text-left text-xs text-text-muted font-medium px-4 py-2"
    >
      {children}
    </th>
  );
}
