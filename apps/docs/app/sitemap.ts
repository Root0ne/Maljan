import type { MetadataRoute } from 'next';
import { source } from '@/lib/source';
import { basePath } from '@/lib/shared';

export const dynamic = 'force-static';

export default function sitemap(): MetadataRoute.Sitemap {
  return source.getPages().map((page) => ({
    url: `https://root0ne.github.io${basePath}${page.url === '/' ? '/' : `${page.url}/`}`,
  }));
}
