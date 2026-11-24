#!/usr/bin/env node
/**
 * Writes packages/core/src/version.ts from packages/core/package.json.
 *
 * The core can't import its own package.json (it compiles with
 * `rootDir: ./src` and is consumed from dist/), so the version lives in a
 * generated TS literal. This keeps it in sync automatically:
 *   - `prebuild` regenerates it on every `npm run build`;
 *   - the `version` lifecycle regenerates it on `npm version` (used by the
 *     root `npm run version:bump -- <version>`).
 *
 * `--check` writes nothing and exits 1 when the committed file is stale (CI).
 *
 * Lives inside packages/core (not the repo-level scripts/) because the
 * Dockerfile copies only packages/core before running the build.
 */
import { readFileSync, writeFileSync } from 'node:fs';

const pkgUrl = new URL('../package.json', import.meta.url);
const outUrl = new URL('../src/version.ts', import.meta.url);

const { version } = JSON.parse(readFileSync(pkgUrl, 'utf8'));
if (typeof version !== 'string' || !/^[0-9A-Za-z.+-]+$/.test(version)) {
	console.error(`sync-version: invalid "version" in packages/core/package.json: ${JSON.stringify(version)}`);
	process.exit(1);
}

const content = `/**
 * Version of the @waf-checker/core package.
 *
 * GENERATED from packages/core/package.json by scripts/sync-version.mjs, which
 * runs on \`npm run build\` (prebuild) and \`npm version\`. Do not edit by hand:
 * bump the release with \`npm run version:bump -- <version>\` from the repo root.
 *
 * Kept as a literal (instead of importing package.json) because the core is
 * compiled with \`rootDir: ./src\` and consumed from dist/ by both the Worker and
 * the CLI bundle. \`test/reports.spec.ts\` asserts this matches package.json.
 */
export const CORE_VERSION = '${version}';
`;

let current = null;
try {
	current = readFileSync(outUrl, 'utf8');
} catch {
	// missing file: (re)create it below, or report stale under --check
}

if (current === content) process.exit(0);

if (process.argv.includes('--check')) {
	console.error(
		`sync-version: packages/core/src/version.ts is out of date with package.json (${version}).\n` +
			'Run `npm run build --workspace=@waf-checker/core` (or `node packages/core/scripts/sync-version.mjs`) and commit the result.',
	);
	process.exit(1);
}

writeFileSync(outUrl, content);
console.log(`sync-version: packages/core/src/version.ts -> ${version}`);
