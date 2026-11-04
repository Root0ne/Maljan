import type { MetadataRoute } from 'next';
import { source } from '@/lib/source';
import { absolute } from '@/lib/shared';

export const dynamic = 'force-static';

/* The home page and every docs page, at their malspark.com addresses. */
export default function sitemap(): MetadataRoute.Sitemap {
  return [
    { url: absolute('/'), priority: 1 },
    ...source.getPages().map((page) => ({ url: absolute(`${page.url}/`) })),
  ];
}
