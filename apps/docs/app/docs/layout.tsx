import { source } from '@/lib/source';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { baseOptions } from '@/lib/layout.shared';
import { Provider } from '@/components/provider';
import '../global.css';

/* The theme switch and the search dialog belong to the docs; the home page
 * ships without them. */
export default function Layout({ children }: LayoutProps<'/docs'>) {
  return (
    <Provider>
      <DocsLayout tree={source.getPageTree()} {...baseOptions()}>
        {children}
      </DocsLayout>
    </Provider>
  );
}
