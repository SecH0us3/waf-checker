# Agent Instructions for WAF Checker

Welcome to the WAF Checker project. This document provides essential information for AI agents working on this codebase.

## Project Overview
WAF Checker is a security testing tool designed as a Cloudflare Worker using TypeScript. It allows users to test Web Application Firewalls (WAF) by sending various attack payloads and analyzing the responses.

## Tech Stack
- **Runtime**: Cloudflare Workers
- **Language**: TypeScript
- **Frontend**: HTML/JS/CSS (Bootstrap 5) served as static assets.
- **Development**: Wrangler CLI
- **Testing**: Vitest with `@cloudflare/vitest-pool-workers`

## Project Structure
- `/app/src/api.ts`: Entry point and request router.
- `/app/src/handlers/`: Contains logic for specific API endpoints (check, WAF detect, batch, etc.).
- `/app/src/payloads.ts`: Base attack payloads and categories.
- `/app/src/advanced-payloads.ts`: Advanced evasion techniques and WAF-specific payloads.
- `/app/src/waf-detection.ts`: Fingerprinting logic for various WAF vendors.
- `/app/src/encoding.ts`: Utilities for payload obfuscation.
- `/app/src/utils/security.ts`: Security utilities, primarily SSRF protection.
- `/app/src/static/`: Frontend assets (served via `env.ASSETS`).
- `/app/test/`: Unit and integration tests.

## Development & Commands
- **Run Locally**: From the root directory, run `npx wrangler dev`. This uses the root `wrangler.toml` which binds static assets.
- **Run Tests**: Navigate to the `app` directory and run `npm test`.

## Coding Guidelines

### 🛡️ Security First (SSRF Protection)
Any endpoint that accepts a target URL **MUST** validate it using `isValidTargetUrl` from `app/src/utils/security.ts`. This is critical to prevent the worker from being used as an SSRF proxy to internal services.

```typescript
import { isValidTargetUrl } from './utils/security';

if (url && !isValidTargetUrl(url)) {
    return new Response(JSON.stringify({ error: 'Invalid URL or restricted IP' }), { status: 400 });
}
```

### 💉 Extending Payloads
- **Base Payloads**: Add to `app/src/payloads.ts`. Use `ParamCheck` for query/body params, `FileCheck` for path-based attacks, and `Header` for header-based attacks.
- **Evasion**: Add complex or WAF-specific bypasses to `app/src/advanced-payloads.ts`.

### 🔍 WAF Detection
When adding support for a new WAF:
1. Update `app/src/waf-detection.ts` with relevant header signatures or body patterns.
2. Update the `WAF_BYPASS_PAYLOADS` in `app/src/advanced-payloads.ts` if specific bypasses are known.

### 🌐 Frontend
The frontend is a single-page application. Update `app/src/static/main.js` for UI logic and `app/src/static/index.html` for layout changes.

## Programmatic Checks
Before submitting any changes to API handlers:
1. **Check SSRF Validation**: Ensure `grep "isValidTargetUrl" app/src/handlers/*.ts` shows that all new URL-accepting handlers use the validation utility.
2. **Verify Tests**: All tests in `app/test/` must pass.
