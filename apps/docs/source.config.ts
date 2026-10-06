import { defineConfig, defineDocs, frontmatterSchema, metaSchema } from 'fumadocs-mdx/config';
import { createCssVariablesTheme } from 'shiki';
import { z } from 'zod';
import { mkdocsSlug } from './lib/slug';

export const docs = defineDocs({
  dir: 'content/docs',
  docs: {
    // sidebarTitle: the shorter name a page carries in the navigation.
    schema: frontmatterSchema.extend({ sidebarTitle: z.string().optional() }),
  },
  meta: { schema: metaSchema },
});

/* Code is coloured through CSS variables, so its colours come from the same
 * palette as the rest of the site (app/global.css), per scheme. */
const paletteTheme = createCssVariablesTheme({ name: 'maljan', variablePrefix: '--shiki-' });

export default defineConfig({
  mdxOptions: {
    remarkHeadingOptions: { slug: mkdocsSlug },
    rehypeCodeOptions: { themes: { light: paletteTheme, dark: paletteTheme } },
  },
});
