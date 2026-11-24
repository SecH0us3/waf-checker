/**
 * Version of the @waf-checker/core package.
 *
 * GENERATED from packages/core/package.json by scripts/sync-version.mjs, which
 * runs on `npm run build` (prebuild) and `npm version`. Do not edit by hand:
 * bump the release with `npm run version:bump -- <version>` from the repo root.
 *
 * Kept as a literal (instead of importing package.json) because the core is
 * compiled with `rootDir: ./src` and consumed from dist/ by both the Worker and
 * the CLI bundle. `test/reports.spec.ts` asserts this matches package.json.
 */
export const CORE_VERSION = '1.8.0';
