'use client';
import SearchDialog from '@/components/search';
import { RootProvider } from 'fumadocs-ui/provider/next';
import { type ReactNode } from 'react';

/* Dark until the reader picks otherwise; the switch offers system, light
 * and dark, and remembers the choice. */
export function Provider({ children }: { children: ReactNode }) {
  return (
    <RootProvider search={{ SearchDialog }} theme={{ defaultTheme: 'dark' }}>
      {children}
    </RootProvider>
  );
}
