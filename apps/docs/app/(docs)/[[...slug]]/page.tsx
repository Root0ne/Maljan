import { sectionOf, source } from '@/lib/source';
import {
  DocsBody,
  DocsDescription,
  DocsPage,
  DocsTitle,
  EditOnGitHub,
} from 'fumadocs-ui/layouts/docs/page';
import { notFound } from 'next/navigation';
import { getMDXComponents } from '@/components/mdx';
import type { Metadata } from 'next';
import { editBranch, repoUrl } from '@/lib/shared';

export default async function Page(props: PageProps<'/[[...slug]]'>) {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  const MDX = page.data.body;
  // The home page opens with its own hero, which carries the name.
  const home = page.slugs.length === 0;
  const section = sectionOf(page.url);

  return (
    <DocsPage toc={page.data.toc} full={page.data.full} breadcrumb={{ enabled: false }}>
      {!home && (
        <header className="mj-page-head">
          {section && <p className="mj-eyebrow">{section}</p>}
          <DocsTitle>{page.data.title}</DocsTitle>
          {page.data.description && <DocsDescription>{page.data.description}</DocsDescription>}
        </header>
      )}
      <DocsBody>
        <MDX components={getMDXComponents()} />
      </DocsBody>
      <EditOnGitHub
        href={`${repoUrl}/edit/${editBranch}/apps/docs/content/docs/${page.path}`}
        className="mj-edit"
      />
    </DocsPage>
  );
}

export function generateStaticParams() {
  return source.generateParams();
}

export async function generateMetadata(props: PageProps<'/[[...slug]]'>): Promise<Metadata> {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();
  const home = page.slugs.length === 0;

  return {
    title: home ? { absolute: page.data.title } : page.data.title,
    description: page.data.description,
    alternates: { canonical: page.url },
  };
}
