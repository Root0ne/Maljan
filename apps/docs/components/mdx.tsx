import defaultMdxComponents from 'fumadocs-ui/mdx';
import { Accordion, Accordions } from 'fumadocs-ui/components/accordion';
import { Step, Steps } from 'fumadocs-ui/components/steps';
import { Tab, Tabs, type TabProps } from 'fumadocs-ui/components/tabs';
import type { MDXComponents } from 'mdx/types';
import { Hero } from './hero';

/* Every tab's content is in the page, hidden until chosen, so the text of
 * all of them is there to read without scripts and to find in the page. */
function MountedTab(props: TabProps) {
  return <Tab forceMount {...props} />;
}

export function getMDXComponents(components?: MDXComponents) {
  return {
    ...defaultMdxComponents,
    Accordion,
    Accordions,
    Hero,
    Step,
    Steps,
    Tab: MountedTab,
    Tabs,
    ...components,
  } satisfies MDXComponents;
}

export const useMDXComponents = getMDXComponents;

declare global {
  type MDXProvidedComponents = ReturnType<typeof getMDXComponents>;
}
