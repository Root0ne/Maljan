# Frontend Web App (`apps/web/`)

> Refreshed 2026-07-05. Next.js 16 + React 19 + TailwindCSS 4 (App Router). Frontend-specific
> agent docs: `apps/web/AGENTS.md`, `apps/web/CLAUDE.md`. ESLint v9 flat config.

## Structure (`apps/web/src/`)
- `app/` — route groups:
  - `(auth)/login`, `(auth)/register`.
  - `(app)/` (authenticated shell): `dashboard`, `jobs`, `audit`, `settings`.
  - `(app)/analysis/[id]/` — analysis detail. **Nav TABS array = 16 tabs** (June 2026; was ~18):
    SUMMARY(""), IDENTITY, STATIC, DYNAMIC, NETWORK, PERSISTENCE, ATT&CK(`/capabilities`),
    ATTRIBUTION, SIGNATURES, DEFENSE, AGENTS, PIPELINE, RULES, TIMELINE, STIX, LIVE.
    **TTPS tab merged into ATT&CK**: `ttps/page.tsx` is now just a client redirect to
    `/analysis/{id}/capabilities` (kept so old deep links don't 404).
- `components/layout/` — Header, Sidebar, SearchPalette (still the only components dir).
- `lib/` — `api.ts` (JobDTO now has `sample_sha256`/`sample_filename` — BUG-02), `auth.tsx`,
  `useWebSocket.ts`, `report-utils.ts`, `errors.ts`. **`mitre-mobile.ts` DELETED** (OS scope
  narrowed to Windows+Linux); `capabilities/page.tsx` embeds a canonical **Enterprise-only**
  tactic catalogue (`ENTERPRISE_NAME_BY_ID`, `tacticOrder`) derived from the STIX bundle.
- `types/malware-report.ts` — `SamplePlatform` narrowed to `"windows"|"linux"|"unknown"`;
  added `NetworkDomain.dga_score/is_punycode/homograph_target`, `NetworkIOCs.ja3s_fingerprints`,
  `PersistenceKind` +`com_hijacking`/`systemd_timer`/`xdg_autostart`.

## June-2026 UI deltas
- `network/page.tsx`: JA3S Fingerprints panel.
- `persistence/page.tsx`: COM Hijacking / Systemd Timer / XDG Autostart labels+colors.
- `analysis/[id]/layout.tsx`: header title prefers sample filename -> hash prefix -> UUID (BUG-02).

## Data sources (backend, see `mem:api_infrastructure`)
- REST `/api/v1/*`; report tabs consume `/reports/{id}/full`, `/stix`, `/mitre`, `/iocs`
  (kinds now incl. `ja3s`), `/signatures/{kind}`, `/markdown`, `/timeline`.
- Live tab: WebSocket `/ws/analysis/{job_id}` with reconnect.

## Testing
- Playwright E2E in `apps/web/e2e/`: `auth.spec.ts`, `dashboard.spec.ts`, `ws_reconnect.spec.ts`
  + `fixtures.ts` (unchanged). Run `npx playwright test`.

## Docker
- `frontend` service from `docker/Dockerfile.frontend`; build args `NEXT_PUBLIC_API_URL`,
  `NEXT_PUBLIC_WS_URL`. Local dev: `npm run dev`.
