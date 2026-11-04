import type { Metadata } from 'next';
import Link from 'next/link';
import './home.css';

export const metadata: Metadata = {
  title: 'Page not found',
  robots: { index: false },
};

/* Every address the site does not have. It is drawn like the home page and
 * loads nothing of the docs: this boundary sits under the root layout, so
 * whatever it imports, every page would load. */
export default function NotFound() {
  return (
    <div className="ms-home">
      <main id="main" className="ms-notfound">
        <h1>This page does not exist</h1>
        <p>
          The address may be mistyped, or the page may have been removed. Start from the{' '}
          <Link href="/">home page</Link> or the <Link href="/docs/">documentation</Link>, where
          the search box finds any page.
        </p>
      </main>
    </div>
  );
}
