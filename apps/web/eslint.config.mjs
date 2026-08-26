/**
 * Wave 10 W10-LINT-07 (2026-05-30): ESLint v9 flat config migration.
 *
 * The legacy `.eslintrc.json` carried `next/core-web-vitals` +
 * `next/typescript` extends, which ESLint 9.x refuses to load — the
 * flat config is now mandatory. Spec sourced from the in-tree
 * `node_modules/next/dist/docs/01-app/03-api-reference/05-config/03-eslint.md`
 * (Next.js 16 flat-config recipe) rather than the public web docs to
 * match the exact version installed in this repo.
 */
import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

export default defineConfig([
  ...nextVitals,
  ...nextTypescript,
  globalIgnores([
    // Default ignores of eslint-config-next; spell them out under the
    // flat config so the migration preserves the v8 behaviour 1:1.
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
  {
    rules: {
      // Wave 10 W10-LINT-DEBT-02 (2026-05-30): downgrade two React 19
      // / React Compiler advisories from error to warning. Each of the
      // call sites flagged by these rules in the current codebase is a
      // legitimate pattern:
      //
      //   * ``react-hooks/set-state-in-effect`` fires on every async
      //     data-fetch ``useEffect`` (auth.tsx mount-time session
      //     hydration, settings/page.tsx tab switch, ttps/page.tsx
      //     cached-ttp_mappings hydration, SearchPalette.tsx
      //     debounced-query reset + empty-query clear). All of these
      //     reflect actual in-flight request status or cross-effect
      //     coordination; the React docs themselves list data fetching
      //     as an acceptable use case.
      //
      //   * ``react-hooks/preserve-manual-memoization`` fires when a
      //     useCallback can no longer be auto-memoized by the React
      //     Compiler because of the cycle-break ref pattern we use in
      //     auth.tsx + useWebSocket.ts (Wave 10 HOTFIX). The pattern
      //     itself is correct; the compiler advisory is a hint that
      //     the manual memo dropped, not a correctness bug.
      //
      // Keeping them as warnings preserves visibility without failing
      // CI on every commit.
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/preserve-manual-memoization": "warn",
    },
  },
]);
