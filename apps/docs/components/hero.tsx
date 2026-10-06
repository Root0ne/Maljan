import type { ReactNode } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import logo from '@/public/assets/logo.svg';
import { appName, repoUrl } from '@/lib/shared';

/* The home page's opening: the logo, the name, the one-line promise, the
 * paragraph under it and the two ways in. */
export function Hero({ tagline, children }: { tagline: string; children: ReactNode }) {
  return (
    <div className="mj-hero not-prose">
      <Image src={logo} alt={appName} width={88} height={88} priority />
      <h1>{appName}</h1>
      <p className="mj-tagline">{tagline}</p>
      <div className="mj-hero-text">{children}</div>
      <div className="mj-hero-actions">
        <Link href="/getting-started/" className="mj-button mj-button-primary">
          Quick start
        </Link>
        <a href={repoUrl} className="mj-button" rel="noreferrer noopener" target="_blank">
          View on GitHub
        </a>
      </div>
    </div>
  );
}
