import type { MetadataRoute } from 'next';
import { absolute } from '@/lib/shared';

export const dynamic = 'force-static';

/* Every page may be crawled; the search index is data for the docs' own
 * search box, not a page. */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: '*', allow: '/', disallow: '/api/' },
    sitemap: absolute('/sitemap.xml'),
    host: 'malspark.com',
  };
}
