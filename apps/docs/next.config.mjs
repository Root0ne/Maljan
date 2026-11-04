import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

/* A static site. NEXT_PUBLIC_BASE_PATH sets the path it is served under:
 * unset for malspark.com, '/Maljan' for the GitHub Pages build. Every page is
 * written as a directory with an index.html, which is the shape the MkDocs
 * site had, so its addresses keep working unchanged. */
/** @type {import('next').NextConfig} */
const config = {
  output: 'export',
  basePath: process.env.NEXT_PUBLIC_BASE_PATH ?? '',
  trailingSlash: true,
  images: { unoptimized: true },
  reactStrictMode: true,
};

export default withMDX(config);
