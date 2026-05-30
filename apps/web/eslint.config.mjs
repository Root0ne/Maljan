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
]);
