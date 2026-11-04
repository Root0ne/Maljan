import type { Metadata } from 'next';
import Image from 'next/image';
import Link from 'next/link';
import logo from '@/public/assets/logo.svg';
import { appName, repoUrl, siteDescription } from '@/lib/shared';
import { JsonLd, homeGraph, pageMetadata } from '@/lib/seo';
import './home.css';

export const metadata: Metadata = pageMetadata({
  title: `${appName}: multi-agent malware analysis with cited evidence`,
  description: siteDescription,
  path: '/',
  absoluteTitle: true,
});

/* The default team's stages, in the order a run takes them; from
 * usage/teams and the README. */
const stages = [
  {
    id: 'triage_pack',
    kind: 'code',
    text: 'Hashes, file type, signature, rule matches and reputation, established before any agent starts and written to the ledger.',
  },
  {
    id: 'analysis',
    kind: 'agents',
    text: 'Static, dynamic and network analysts call the tools they were given. A stage whose condition does not hold declines and says why.',
  },
  {
    id: 'debate',
    kind: 'agents',
    text: "The analysts' positions are put against each other; the judge mediates.",
  },
  {
    id: 'verdict',
    kind: 'agents',
    text: 'The judge states the verdict, severity, category and family.',
  },
  {
    id: 'report',
    kind: 'agents',
    text: 'Assembled from the ledger and the claims that cite it, mapped to ATT&CK.',
  },
];

const capabilities = [
  {
    tag: 'Evidence',
    title: 'Evidence ledger',
    text: 'Every tool call is written to the ledger with a citable id, ev_NNNN. Each section of the report names the ids it was built from.',
    href: '/docs/architecture/#the-evidence-ledger',
    link: 'The evidence ledger',
  },
  {
    tag: 'Evidence',
    title: 'Validation loops',
    text: 'Nothing rewrites a claim, technique id or confidence behind the producer’s back. A problem goes back as feedback, with one turn to fix it.',
    href: '/docs/architecture/#validation-loops',
    link: 'Validation loops',
  },
  {
    tag: 'Agents',
    title: 'Judge and debate',
    text: 'Analysts revise their claims until they agree or reach the round cap. The judge mediates with its own tool loop: it reads the evidence and can ask named analysts directly.',
    href: '/docs/architecture/',
    link: 'Architecture',
  },
  {
    tag: 'Agents',
    title: 'Teams as configuration',
    text: 'A team is an ordered list of stages with a prompt per agent and a condition per stage, written in the console rather than in code.',
    href: '/docs/usage/teams/',
    link: 'Teams and profiles',
  },
  {
    tag: 'Output',
    title: 'MITRE ATT&CK',
    text: 'A technique id the ATT&CK catalogue does not have goes back to the analyst with suggestions. The report carries an ATT&CK view of what it found.',
    href: '/docs/usage/reports-and-exports/',
    link: 'Reports and exports',
  },
  {
    tag: 'Output',
    title: 'STIX 2.1 and exports',
    text: 'Markdown, HTML, PDF, the full JSON document, a STIX 2.1 bundle, an IOC feed with a publish decision per row, and detection drafts.',
    href: '/docs/usage/reports-and-exports/#renderings',
    link: 'Renderings',
  },
  {
    tag: 'Plug-in',
    title: 'Declared tool servers',
    text: 'Tools are MCP servers, each declared with the tools it exposes and the agents that may call them. Any MCP server works.',
    href: '/docs/integrations/mcp-servers/',
    link: 'MCP servers',
  },
  {
    tag: 'Plug-in',
    title: 'Format-agnostic routing',
    text: 'The sample’s own bytes pick its route: PE, ELF, Mach-O, APK, DEX, documents, scripts, archives. An unknown format gets the neutral path.',
    href: '/docs/architecture/#format-routing',
    link: 'Format routing',
  },
  {
    tag: 'Measure',
    title: 'Replay and scoring',
    text: 'Re-run the deterministic rules over a stored run at no cost, score runs blind against an answer list, and gate changes on known answers.',
    href: '/docs/replay/',
    link: 'Replay',
  },
];

const plugins = [
  {
    title: 'LLM providers',
    href: '/docs/providers/',
    items: ['OpenAI-compatible', 'DeepSeek', 'Anthropic', 'Gemini', 'Ollama', 'llama.cpp'],
    note: 'A model per agent, with fallbacks.',
  },
  {
    title: 'Static tools',
    href: '/docs/tools/',
    items: ['Ghidra', 'radare2', 'capa', 'YARA', 'YARA-X', 'Detect It Easy', 'ILSpy', 'GoReSym', 'JADX', 'unblob', 'oletools', 'webcrack'],
    note: 'As the static provider, as agent tools, or as triage-pack steps.',
  },
  {
    title: 'Sandboxes',
    href: '/docs/tools/sandboxes/',
    items: ['CAPEv2', 'Hatching Triage', 'Uploaded report', 'Generic REST', 'Mock'],
    note: 'The mock, the default, executes nothing.',
  },
  {
    title: 'Tool servers',
    href: '/docs/tools/generic-mcp/',
    items: ['Built-in sidecars', 'VirusTotal MCP', 'Your MCP server'],
    note: 'Over stdio or HTTP, each bound to the agents that may call it.',
  },
];

const teams = [
  {
    name: 'default',
    stages: 'triage_pack, analysis (static, dynamic, network), debate, verdict, report',
    use: 'The general case.',
  },
  {
    name: 'mobile',
    stages: 'triage_pack, triage, android_static, dynamic, debate, verdict, report',
    use: 'An APK or a DEX.',
  },
  {
    name: 'deep_static',
    stages: 'triage_pack, triage, static, reversing, network, debate, verdict, report',
    use: 'Reading the code in the decompiler.',
  },
  {
    name: 'team_lead',
    stages: 'triage_pack, lead, verdict, report',
    use: 'One lead asks the specialists through ask_<agent> tools.',
  },
  {
    name: 'measurement',
    stages: 'The four model stages, with no pack and no tool servers',
    use: 'What the models contribute on their own.',
  },
];

/* From docs/benchmark: the reference sample, 57 core items from a published
 * human analysis. */
const benchmark = [
  { run: 'All-tools team, hosted model, run 4', found: 45, partly: 9, missed: 2, wrong: 1 },
  { run: 'All-tools team, hosted model, run 5', found: 43, partly: 11, missed: 2, wrong: 1 },
  { run: 'All-tools team, local model', found: 15, partly: 21, missed: 21, wrong: 0 },
];

function Framed({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={`ms-frame ${className}`}>
      <span className="ms-frame-corner ms-tl" aria-hidden="true" />
      <span className="ms-frame-corner ms-tr" aria-hidden="true" />
      <span className="ms-frame-corner ms-bl" aria-hidden="true" />
      <span className="ms-frame-corner ms-br" aria-hidden="true" />
      {children}
    </span>
  );
}

export default function Home() {
  return (
    <div className="ms-home">
      <JsonLd data={homeGraph} />
      <a href="#main" className="ms-skip">
        Skip to content
      </a>

      <header className="ms-header">
        <Link href="/" className="ms-brand" aria-label={`${appName} home`}>
          <Framed className="ms-frame-sm">
            <Image src={logo} alt="" width={22} height={23} priority />
          </Framed>
          <span className="ms-wordmark">{appName}</span>
        </Link>
        <nav aria-label="Site" className="ms-nav">
          <Link href="/docs/">Docs</Link>
          <Link href="/docs/benchmark/">Benchmark</Link>
          <a href={repoUrl}>GitHub</a>
        </nav>
      </header>

      <main id="main">
        <section className="ms-hero" aria-labelledby="hero-title">
          <div className="ms-hero-copy">
            <Framed className="ms-frame-lg">
              <Image src={logo} alt={`${appName} logo`} width={84} height={88} priority />
            </Framed>
            <h1 id="hero-title">
              Malware analysis by agent teams, cited to the tool call
            </h1>
            <p className="ms-lede">
              {appName} connects teams of LLM agents to malware-analysis tools: signature
              scanners, rule engines, binary and capture readers, a sandbox, an ATT&amp;CK
              catalogue. Every tool call lands in an evidence ledger, and every claim in the report
              names the calls it came from.
            </p>
            <p className="ms-lede ms-lede-muted">
              Models, tools and sandboxes plug in as configuration. Open source under the MIT
              licence.
            </p>
            <div className="ms-actions">
              <Link href="/docs/getting-started/" className="ms-button ms-button-primary">
                Read the quick start
              </Link>
              <a href={repoUrl} className="ms-button">
                View the source on GitHub
              </a>
            </div>
          </div>

          <figure className="ms-panel ms-run" aria-labelledby="run-caption">
            <div className="ms-panel-head">
              <figcaption id="run-caption">
                Team <code>default</code>
              </figcaption>
              <span className="ms-pill ms-pill-active">
                <span className="ms-dot" aria-hidden="true" />
                Ships as default
              </span>
            </div>
            <ol className="ms-stages">
              {stages.map((stage, index) => (
                <li key={stage.id} className="ms-stage">
                  <span className="ms-stage-index" aria-hidden="true">
                    {String(index + 1).padStart(2, '0')}
                  </span>
                  <div>
                    <div className="ms-stage-head">
                      <code>{stage.id}</code>
                      <span className={`ms-pill ms-pill-${stage.kind}`}>
                        {stage.kind === 'code' ? 'Code, no model' : 'Agents'}
                      </span>
                    </div>
                    <p>{stage.text}</p>
                  </div>
                </li>
              ))}
            </ol>
            <div className="ms-cite" aria-label="How a claim resolves">
              <span className="ms-cite-claim">Report section</span>
              <span className="ms-cite-arrow" aria-hidden="true" />
              <code className="ms-cite-id">ev_NNNN</code>
              <span className="ms-cite-arrow" aria-hidden="true" />
              <span className="ms-cite-claim">Tool call, arguments, output</span>
            </div>
          </figure>
        </section>

        <section className="ms-section" aria-labelledby="rule-title">
          <h2 id="rule-title">The agent decides; the code says what is wrong</h2>
          <div className="ms-split">
            <p>
              Facts about a sample are established by code before any agent starts and cited by id.
              The decisions are the team’s. Nothing rewrites a claim, a technique id, a confidence
              or an attribution behind the producer’s back: a problem goes back to the producer as
              feedback, it gets one turn to fix it, and what it will not fix stays on the record
              where a reader can see it.
            </p>
            <p>
              Nothing is bound to Windows. The route follows the sample’s own format, and a format
              nothing recognises gets the neutral path and a report that says so, rather than a
              rejection.
            </p>
          </div>
        </section>

        <section className="ms-section" aria-labelledby="capabilities-title">
          <h2 id="capabilities-title">What a run gives you</h2>
          <ul className="ms-grid">
            {capabilities.map((item) => (
              <li key={item.title} className="ms-panel ms-card">
                <span className="ms-pill">{item.tag}</span>
                <h3>{item.title}</h3>
                <p>{item.text}</p>
                <Link href={item.href} className="ms-more">
                  {item.link}
                </Link>
              </li>
            ))}
          </ul>
        </section>

        <section className="ms-section" aria-labelledby="plugins-title">
          <h2 id="plugins-title">Plug in what you already run</h2>
          <div className="ms-plugins">
            {plugins.map((group) => (
              <div key={group.title} className="ms-panel ms-plugin">
                <h3>
                  <Link href={group.href}>{group.title}</Link>
                </h3>
                <ul className="ms-badges">
                  {group.items.map((item) => (
                    <li key={item} className="ms-badge">
                      {item}
                    </li>
                  ))}
                </ul>
                <p>{group.note}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="ms-section" aria-labelledby="teams-title">
          <h2 id="teams-title">The teams that ship</h2>
          <div className="ms-panel ms-table-wrap">
            <table className="ms-table">
              <thead>
                <tr>
                  <th scope="col">Team</th>
                  <th scope="col">Stages</th>
                  <th scope="col">For</th>
                </tr>
              </thead>
              <tbody>
                {teams.map((team) => (
                  <tr key={team.name}>
                    <th scope="row">
                      <code>{team.name}</code>
                    </th>
                    <td>{team.stages}</td>
                    <td>{team.use}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="ms-note">
            A team of your own is an ordered list of stages and a prompt per agent.{' '}
            <Link href="/docs/usage/teams/">Writing a team</Link>
          </p>
        </section>

        <section className="ms-section" aria-labelledby="benchmark-title">
          <h2 id="benchmark-title">Measured in the open</h2>
          <div className="ms-split">
            <p>
              Reports are scored item by item against a published human analysis of the same
              sample: 57 core items on the reference sample, from identity and execution flow to
              C2, IOCs and ATT&amp;CK. These are single runs on one reference sample, with no
              variance measured; the method, every score file and the false-positive control are
              in the benchmark.
            </p>
            <div className="ms-panel ms-table-wrap">
              <table className="ms-table ms-table-num">
                <caption>Reference sample, 57 core items</caption>
                <thead>
                  <tr>
                    <th scope="col">Run</th>
                    <th scope="col">Found</th>
                    <th scope="col">Partly</th>
                    <th scope="col">Missed</th>
                    <th scope="col">Wrong</th>
                  </tr>
                </thead>
                <tbody>
                  {benchmark.map((row) => (
                    <tr key={row.run}>
                      <th scope="row">{row.run}</th>
                      <td>{row.found}</td>
                      <td>{row.partly}</td>
                      <td>{row.missed}</td>
                      <td>{row.wrong}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <p className="ms-note">
            <Link href="/docs/benchmark/">Read the benchmark</Link>
          </p>
        </section>

        <section className="ms-section ms-start" aria-labelledby="start-title">
          <h2 id="start-title">Run it on your own machine</h2>
          <div className="ms-split">
            <pre className="ms-panel ms-code">
              <code>
                <span className="ms-prompt">$ </span>git clone https://github.com/Root0ne/Maljan.git
                {'\n'}
                <span className="ms-prompt">$ </span>cd Maljan && make setup
                {'\n'}
                <span className="ms-prompt">$ </span>cp docker/.env.example docker/.env
                {'\n'}
                <span className="ms-prompt">$ </span>make dev-up
              </code>
            </pre>
            <div>
              <p>
                The compose stack is the supported way to run {appName}. It needs Docker with the
                Compose plugin. Open the console on port 3000, register the first account and walk
                Settings, Setup to point the deployment at a model, a sandbox and the rest.
              </p>
              <div className="ms-actions">
                <Link href="/docs/getting-started/" className="ms-button ms-button-primary">
                  Read the quick start
                </Link>
                <Link href="/docs/" className="ms-button">
                  Browse the documentation
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="ms-footer">
        <p className="ms-warn">
          {appName} handles live malware. Run it, and any sandbox it submits to, only on hosts and
          networks you are authorised to use for that purpose.
        </p>
        <nav aria-label="Footer" className="ms-footer-nav">
          <Link href="/docs/">Documentation</Link>
          <Link href="/docs/security/">Security</Link>
          <a href={repoUrl}>GitHub</a>
          <a href={`${repoUrl}/blob/dev/LICENSE`}>MIT licence</a>
        </nav>
      </footer>
    </div>
  );
}
