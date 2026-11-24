/**
 * Version of the @waf-checker/core package.
 *
 * Kept as a literal (instead of importing package.json) because the core is
 * compiled with `rootDir: ./src` and consumed from dist/ by both the Worker and
 * the CLI bundle. `test/reports.spec.ts` asserts this matches package.json, so a
 * release bump that forgets this file fails CI.
 */
export const CORE_VERSION = '1.8.0';
