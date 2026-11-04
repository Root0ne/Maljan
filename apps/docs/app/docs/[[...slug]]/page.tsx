import { sectionOf, sections, source } from '@/lib/source';
import { SectionStrip } from '@/components/section-strip';
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
import { appName, editBranch, repoUrl } from '@/lib/shared';
import { JsonLd, breadcrumbList, pageMetadata } from '@/lib/seo';
import { slugify } from '@/lib/slug';

export default async function Page(props: PageProps<'/docs/[[...slug]]'>) {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  const MDX = page.data.body;
  // The first page of the docs opens with its own hero, which carries the name.
  const home = page.slugs.length === 0;
  const section = sectionOf(page.url);

  return (
    <DocsPage toc={page.data.toc} full={page.data.full} breadcrumb={{ enabled: false }}>
      <JsonLd data={breadcrumbList(trail(page.slugs))} />
      <SectionStrip sections={sections()} />
      {!home && (
        <header className="mj-page-head">
          {section && <p className="mj-eyebrow">{section}</p>}
          {/* The id MkDocs gave the page title, so old links to it still land. */}
          <DocsTitle id={slugify(page.data.title)}>{page.data.title}</DocsTitle>
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

export async function generateMetadata(props: PageProps<'/docs/[[...slug]]'>): Promise<Metadata> {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  return pageMetadata({
    title: page.data.title,
    description: page.data.description ?? `${page.data.title}, in the ${appName} documentation.`,
    path: `${page.url}/`,
    absoluteTitle: page.slugs.length === 0,
  });
}

/* A page's breadcrumb trail: home, the documentation, every page above this
 * one that exists, then the page itself. */
function trail(slugs: string[]): { name: string; path: string }[] {
  const items = [{ name: 'Home', path: '/' }];
  for (let depth = 0; depth <= slugs.length; depth += 1) {
    const above = source.getPage(slugs.slice(0, depth));
    if (!above) continue;
    items.push({ name: depth === 0 ? 'Documentation' : above.data.title, path: `${above.url}/` });
  }
  return items;
}
