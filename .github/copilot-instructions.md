<!-- Workspace-specific custom instructions for Copilot. -->

WAF Checker is an NPM Workspaces monorepo (TypeScript): `packages/core` (payloads, encoding, WAF detection, `utils/security.ts`, reports, virtual-patch, reverse-engineering), `packages/worker` (Cloudflare Worker: `src/api.ts`, `src/handlers/`, `src/services/`, static Web UI in `src/static/`) and `packages/cli` (Node.js CLI).

The Worker serves the UI at `/` and exposes `/api/*` endpoints that test a user-supplied URL with grouped attack payloads (SQLi, XSS, Path Traversal, Command Injection, SSRF, NoSQLi, LFI) and report status codes (403 = blocked; 2xx/5xx = not blocked). Payloads are grouped by category in `packages/core/src/payloads-data/base.ts` for easy extension.

Rules:
- Any endpoint accepting a target URL MUST validate it with `isValidTargetUrl` from `@waf-checker/core` (`packages/core/src/utils/security.ts`).
- Commands (from repo root): `npm install && npm run build`, `npm run dev:worker`, `npm test`, `npm run deploy --workspace=packages/worker`; release bump: `npm run version:bump -- <version>` (also regenerates `packages/core/src/version.ts`, never edit it by hand).
- Pre-push SSRF check: `grep isValidTargetUrl packages/worker/src/handlers/*.ts packages/worker/src/api.ts`.
- Work on a separate branch; never commit directly to main.
