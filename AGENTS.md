# Agent Instructions for WAF Checker

Welcome to the WAF Checker project. This document provides essential information for AI agents working on this codebase.

## Project Overview
WAF Checker is a modular security testing tool designed as an NPM Workspaces monorepo. It features a shared core audit library, a Cloudflare Worker deployment exposing a Web UI, and a standalone Node.js CLI tool.

## Tech Stack
- **Workspaces**: NPM Workspaces (`packages/core`, `packages/worker`, `packages/cli`)
- **Runtime**: Cloudflare Workers (Worker) & Node.js (CLI)
- **Language**: TypeScript
- **Frontend**: HTML/JS/CSS (Bootstrap 5) served as static assets from `packages/worker/src/static/`
- **Development**: Wrangler CLI (Worker) & esbuild (CLI compiler)
- **Testing**: Vitest with `@cloudflare/vitest-pool-workers`

## Project Structure

NPM Workspaces monorepo (`packages/*`):

### `packages/core` — shared audit library (`@waf-checker/core`)
- `packages/core/src/check.ts` — Main check execution logic.
- `packages/core/src/payloads.ts`, `packages/core/src/payloads-data/` — Base attack payloads and categories (data in `payloads-data/base.ts`).
- `packages/core/src/advanced-payloads.ts` — Advanced evasion techniques (`ADVANCED_PAYLOADS`, `generateWAFSpecificPayloads`) and the `wafBypassCandidates` switch for WAF-specific bypasses.
- `packages/core/src/waf-detection.ts` — WAF fingerprinting logic; `packages/core/src/waf-signatures.ts` — vendor signatures (`WAF_SIGNATURES`).
- `packages/core/src/encoding.ts` — Payload obfuscation/encoding utilities.
- `packages/core/src/http-manipulation.ts` — HTTP protocol tampering (parameter pollution, verb tampering).
- `packages/core/src/utils/security.ts` — SSRF protection (`isValidTargetUrl`); `packages/core/src/utils/payload-utils.ts` — payload helpers.
- `packages/core/src/reports/` — Report formats (SARIF, JUnit, diff).
- `packages/core/src/virtual-patch/` — Virtual-patch rule generators (nginx, ModSecurity, Cloudflare, AWS, etc.).
- `packages/core/src/reverse-engineering/` — WAF rule/limit probing (anomaly score, body limit, rate limit, CRS rules).
- Tests: `packages/core/test/`.

### `packages/worker` — Cloudflare Worker (Web UI + API)
- `packages/worker/src/api.ts` — Entry point and router.
- `packages/worker/src/handlers/` — `check.ts`, `waf-detect.ts`, `http-manip.ts`, `schedule.ts` request handlers.
- `packages/worker/src/services/` — `scan.ts`, `monitor.ts`, `email.ts`, `ownership.ts`, `rate-limiter.ts` (scheduled monitoring, KV, email).
- `packages/worker/src/static/` — Frontend: `index.html`, `main.js`, `style.css` (served via `env.ASSETS`).
- Tests: `packages/worker/test/`.

### `packages/cli` — Node.js CLI
- `packages/cli/src/index.ts` — CLI entry; `packages/cli/src/report.ts`, `packages/cli/src/reports/` — HTML/Markdown reports.

### Config
- `wrangler.toml` (root) and `packages/worker/wrangler.toml` — both point at the worker entry. `npm run dev:worker` / `npm run deploy` (in `packages/worker`) use `packages/worker/wrangler.toml`; running `npx wrangler` from the repo root uses the root one.
- `vitest.workspace.ts`, `scripts/` (e2e, perf, schedule simulation), `docs/`.

## Development & Commands
- **Install & build** (core + CLI): `npm install && npm run build`
- **Run Worker locally**: `npm run dev:worker` (root)
- **Run tests** (builds first via `pretest`): `npm test`
- **Deploy**: `npm run deploy --workspace=packages/worker`
- **Release bump**: `npm run version:bump -- <version>` (root) — sets the core and CLI `package.json` + lockfile and regenerates `packages/core/src/version.ts`; merging to `main` tags and publishes the release. Never edit `version.ts` by hand (`npm run version:check` verifies it).
- **Docker e2e**: `npm run test:e2e`

## Git Workflow & Branching Policy
- **Branching Rule**: Always create a separate branch for implementing any new features, changes, or experiments. Never perform new work directly on the main branch.


## Coding Guidelines

### 🛡️ Security First (SSRF Protection)
Any endpoint or command that accepts a target URL **MUST** validate it using `isValidTargetUrl` from `@waf-checker/core` (defined in `packages/core/src/utils/security.ts`). This is critical to prevent SSRF proxying to internal services.

```typescript
import { isValidTargetUrl } from '@waf-checker/core';

if (url && !isValidTargetUrl(url)) {
    return new Response(JSON.stringify({ error: 'Invalid URL or restricted IP' }), { status: 400 });
}
```

### 💉 Extending Payloads
- **Base Payloads**: Add to `packages/core/src/payloads-data/base.ts` (`payloads.ts` only re-exports them). Use `ParamCheck` for query/body params, `FileCheck` for path-based attacks, and `Header` for header-based attacks.
- **Evasion**: Add advanced payload data to `packages/core/src/payloads-data/advanced.ts`; WAF-specific bypasses go through `wafBypassCandidates` in `packages/core/src/advanced-payloads.ts`.

### 🔍 WAF Detection
When adding support for a new WAF:
1. Add the vendor's signatures to `WAF_SIGNATURES` in `packages/core/src/waf-signatures.ts`.
2. Add a `WAFBypasses` candidate generator in `packages/core/src/encoding.ts` and a case in `wafBypassCandidates` in `packages/core/src/advanced-payloads.ts`.

### 🌐 Frontend
The frontend is a single-page application. Update `packages/worker/src/static/main.js` for UI logic and `packages/worker/src/static/index.html` for layout changes.

## Programmatic Checks
Before submitting any changes to API handlers:
1. **Check SSRF Validation**: Ensure all URL-accepting entry points use `isValidTargetUrl`.
2. **Run SSRF grep**: `rtk grep "isValidTargetUrl" packages/worker/src/handlers/*.ts packages/worker/src/api.ts` (`handlers/check.ts` only re-exports core handlers; validated in `api.ts`).
3. **Verify Tests**: All tests in the workspaces must pass via `npm test`.
