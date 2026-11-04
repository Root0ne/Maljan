import type { Metadata, Viewport } from 'next';
import { JetBrains_Mono } from 'next/font/google';
import { appName, basePath, ogImage, siteDescription, siteUrl } from '@/lib/shared';
import './brand.css';

/* One monospace family for every text on the site, self-hosted by next/font. */
const mono = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '700', '800'],
  variable: '--font-brand-mono',
  display: 'swap',
});

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: { template: `%s | ${appName}`, default: appName },
  description: siteDescription,
  applicationName: appName,
  openGraph: { type: 'website', siteName: appName, locale: 'en_US', images: [ogImage] },
  twitter: { card: 'summary_large_image', images: [ogImage.url] },
  // Next adds no basePath to these; each address carries it here.
  icons: {
    icon: [
      { url: `${basePath}/favicon.ico`, sizes: '32x32' },
      { url: `${basePath}/icon.svg`, type: 'image/svg+xml' },
    ],
    apple: { url: `${basePath}/apple-touch-icon.png`, sizes: '180x180' },
  },
  manifest: `${basePath}/site.webmanifest`,
};

export const viewport: Viewport = {
  themeColor: '#0b1020',
  colorScheme: 'dark light',
};

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html lang="en" className={mono.variable} suppressHydrationWarning>
      <body className="flex flex-col min-h-screen">{children}</body>
    </html>
  );
}
