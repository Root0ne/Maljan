import type { Metadata } from 'next';
import { absolute, appName, ogImage, repoUrl, siteDescription, siteUrl } from './shared';

/* One page's metadata: its title and description, the canonical address on
 * malspark.com, and the Open Graph and Twitter cards that repeat them. Next
 * adds no basePath to metadata URLs, and none belongs there: the canonical
 * address is the domain's, whichever host served the page. */
export function pageMetadata({
  title,
  description,
  path,
  absoluteTitle = false,
}: {
  title: string;
  description: string;
  path: string;
  absoluteTitle?: boolean;
}): Metadata {
  const fullTitle = absoluteTitle ? title : `${title} | ${appName}`;
  return {
    title: absoluteTitle ? { absolute: title } : title,
    description,
    alternates: { canonical: absolute(path) },
    openGraph: {
      type: 'website',
      siteName: appName,
      locale: 'en_US',
      url: absolute(path),
      title: fullTitle,
      description,
      images: [ogImage],
    },
    twitter: {
      card: 'summary_large_image',
      title: fullTitle,
      description,
      images: [ogImage.url],
    },
  };
}

/* Structured data, written into the page as JSON-LD. A '<' in any string is
 * escaped so no value can close the script element. */
export function JsonLd({ data }: { data: object }) {
  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data).replace(/</g, '\\u003c') }}
    />
  );
}

const organization = {
  '@type': 'Organization',
  '@id': `${siteUrl}/#organization`,
  name: appName,
  url: `${siteUrl}/`,
  logo: `${siteUrl}/icon-512.png`,
  sameAs: [repoUrl],
};

/* The home page's graph: the project as an organisation, the site, and the
 * software itself. */
export const homeGraph = {
  '@context': 'https://schema.org',
  '@graph': [
    organization,
    {
      '@type': 'WebSite',
      '@id': `${siteUrl}/#website`,
      name: appName,
      url: `${siteUrl}/`,
      description: siteDescription,
      inLanguage: 'en',
      publisher: { '@id': organization['@id'] },
    },
    {
      '@type': 'SoftwareApplication',
      name: appName,
      url: `${siteUrl}/`,
      description: siteDescription,
      applicationCategory: 'SecurityApplication',
      operatingSystem: 'Linux (Docker Compose)',
      license: 'https://opensource.org/licenses/MIT',
      isAccessibleForFree: true,
      offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
      codeRepository: repoUrl,
      softwareHelp: `${siteUrl}/docs/`,
      publisher: { '@id': organization['@id'] },
    },
  ],
};

/* A docs page's trail: home, the documentation, then each page above it. */
export function breadcrumbList(trail: { name: string; path: string }[]) {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: trail.map((item, index) => ({
      '@type': 'ListItem',
      position: index + 1,
      name: item.name,
      item: absolute(item.path),
    })),
  };
}
