'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { Section } from '@/lib/source';

const trim = (path: string) => (path.length > 1 ? path.replace(/\/+$/, '') : path);

/* A thin strip over the content column: the top-level sections, the current
 * one underlined, each linking to its first page. The sidebar keeps every
 * group. */
export function SectionStrip({ sections }: { sections: Section[] }) {
  const path = trim(usePathname());
  const current = sections.find((section) => section.urls.some((url) => trim(url) === path));

  return (
    <nav aria-label="Sections" className="mj-strip">
      <ul>
        {sections.map((section) => (
          <li key={section.name}>
            <Link
              href={section.href}
              aria-current={section === current ? 'true' : undefined}
              className="mj-strip-link"
            >
              {section.name}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}
