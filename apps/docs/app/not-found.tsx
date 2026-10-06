import Link from 'next/link';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { baseOptions } from '@/lib/layout.shared';
import { source } from '@/lib/source';

export default function NotFound() {
  return (
    <DocsLayout tree={source.getPageTree()} {...baseOptions()}>
      <main className="flex flex-1 flex-col items-start gap-4 px-8 py-24">
        <p className="mj-eyebrow">404</p>
        <h1 className="text-3xl font-semibold">This page does not exist</h1>
        <p className="text-fd-muted-foreground">
          The address may be mistyped, or the page may have been removed. Search from the left
          column, or start from the{' '}
          <Link href="/" className="text-fd-primary underline">
            introduction
          </Link>
          .
        </p>
      </main>
    </DocsLayout>
  );
}
