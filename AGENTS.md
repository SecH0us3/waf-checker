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
- `/packages/core/src/check.ts`: Main check execution logic.
- `/packages/core/src/payloads.ts`: Base attack payloads and categories.
- `/packages/core/src/advanced-payloads.ts`: Advanced evasion techniques and WAF-specific payloads.
- `/packages/core/src/waf-detection.ts`: Fingerprinting logic for various WAF vendors.
- `/packages/core/src/encoding.ts`: Utilities for payload obfuscation.
- `/packages/core/src/utils/security.ts`: Security utilities, primarily SSRF protection.
- `/packages/worker/src/api.ts`: Cloudflare Worker API router.
- `/packages/worker/src/static/`: Frontend assets (served via `env.ASSETS`).
- `/packages/cli/src/index.ts`: Standalone CLI executable.

## Development & Commands
- **Run Worker Locally**: From the root directory, run `npm run dev:worker`.
- **Build Core/CLI Packages**: Run `npm run build` from the root directory.
- **Run Tests**: From the root directory, run `npm test`.

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
- **Base Payloads**: Add to `packages/core/src/payloads.ts`. Use `ParamCheck` for query/body params, `FileCheck` for path-based attacks, and `Header` for header-based attacks.
- **Evasion**: Add complex or WAF-specific bypasses to `packages/core/src/advanced-payloads.ts`.

### 🔍 WAF Detection
When adding support for a new WAF:
1. Update `packages/core/src/waf-detection.ts` with relevant header signatures or body patterns.
2. Update the `WAF_BYPASS_PAYLOADS` in `packages/core/src/advanced-payloads.ts` if specific bypasses are known.

### 🌐 Frontend
The frontend is a single-page application. Update `packages/worker/src/static/main.js` for UI logic and `packages/worker/src/static/index.html` for layout changes.

## Programmatic Checks
Before submitting any changes to API handlers:
1. **Check SSRF Validation**: Ensure all URL-accepting entry points use `isValidTargetUrl`.
2. **Verify Tests**: All tests in the workspaces must pass via `npm test`.
