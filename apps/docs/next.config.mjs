import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

/* A static site served by GitHub Pages under the repository's name. Every
 * page is written as a directory with an index.html, which is the shape the
 * MkDocs site had, so its addresses keep working unchanged. */
/** @type {import('next').NextConfig} */
const config = {
  output: 'export',
  basePath: '/Maljan',
  trailingSlash: true,
  images: { unoptimized: true },
  reactStrictMode: true,
};

export default withMDX(config);
