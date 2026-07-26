# Maljan web UI

Next.js App Router frontend for the Maljan analysis platform.

This file used to be the untouched `create-next-app` boilerplate, which told you
to run `npm run dev` and promised "the page auto-updates as you edit". That is
true of a bare Next.js app and false of this one as it is normally run: the
`frontend` container serves a **baked standalone build** with no source mount,
so an edit here is invisible until the image is rebuilt.

## Running it

Against the Docker stack — the usual case:

```bash
make dev-up        # from the repo root: mounts this directory, runs `next dev`
make fe-rebuild    # or, on the production stack, rebuild + recreate the container
```

Standalone, against an API you are running yourself:

```bash
npm install
npm run dev        # http://localhost:3000
```

`NEXT_PUBLIC_API_URL` and `NEXT_PUBLIC_WS_URL` must point at that API. They are
**build-time** values in the production image (`Dockerfile.frontend`), which is
the other half of why a rebuild is needed after changing them.

## Checks

```bash
npx tsc --noEmit   # types
npm run lint       # baseline: 0 errors, 10 warnings
npm run build      # production build
npm run test:e2e   # Playwright, three browsers
```

The e2e suite is hermetic — it mocks every API call and fails the test if an
unmocked one escapes — so it does not need the backend running. It is also
memory-hungry: three browsers at four workers each will exhaust a machine that
is also running a local LLM. Run one project at a time (`--project=chromium`)
when memory is tight.
