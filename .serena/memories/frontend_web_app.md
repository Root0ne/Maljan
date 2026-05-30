# Frontend Web App (`apps/web/`)

> Written 2026-05-30. Next.js 16 + React 19 + TailwindCSS 4 (App Router). Frontend-specific agent
> docs: `apps/web/AGENTS.md`, `apps/web/CLAUDE.md`. ESLint v9 flat config (W10-LINT-07).

## Structure (`apps/web/src/`)
- `app/` — App Router with route groups:
  - `(auth)/login`, `(auth)/register` (+ `(auth)/layout.tsx`).
  - `(app)/` (authenticated shell `layout.tsx`): `dashboard`, `jobs`, `audit`, `settings`.
  - `(app)/analysis/[id]/` — analysis detail with `layout.tsx` + ~18 tab pages:
    overview (`page.tsx`), `identity`, `static`, `dynamic`, `network`, `persistence`,
    `capabilities`, `ttps`, `attribution`, `signatures`, `rules`, `stix`, `timeline`,
    `defense`, `live`, `pipeline`, `agents`.
- `components/layout/` — `Header.tsx`, `Sidebar.tsx`, `SearchPalette.tsx`.
- `lib/` — `api.ts` (REST client), `auth.tsx` (auth context), `useWebSocket.ts` (live events),
  `report-utils.ts`, `errors.ts` (typed catch-clause narrowing — W10-LINT-DEBT), `mitre-mobile.ts`
  (Mobile ATT&CK tactic resolver — W10-TTP-02).
- `types/` — `index.ts`, `malware-report.ts` (mirrors the backend `MalwareReport` DTO).

## Data sources (backend, see `mem:api_infrastructure`)
- REST `/api/v1/*` (auth, jobs, samples, reports, dashboard, audit, system).
- Report tabs consume `/reports/{id}/full` (MalwareReport), `/stix`, `/mitre`, `/iocs`,
  `/signatures/{kind}`, `/markdown`, `/timeline`.
- Live tab: WebSocket `/ws/analysis/{job_id}` (status_change / pipeline_started / agent_progress /
  phase_change / completed / error / cancelled) with reconnect.
- ATT&CK tab surfaces Wave 9 `platform_filter_summary` (W10-OBS-03); SUMMARY tab shows the
  fp_linter FP-WARNINGS banner (Wave 9 SHIP-07).

## Testing
- **Playwright E2E** in `apps/web/e2e/`: `auth.spec.ts`, `dashboard.spec.ts`, `ws_reconnect.spec.ts`,
  `fixtures.ts`; config `playwright.config.ts`. Run `npx playwright test`.
  (This closes the "no frontend E2E" gap noted in older analysis memories.)

## Docker
- `frontend` service built from `docker/Dockerfile.frontend`; build args `NEXT_PUBLIC_API_URL`,
  `NEXT_PUBLIC_WS_URL`. Local dev: `npm run dev`.
