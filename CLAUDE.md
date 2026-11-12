# AI Agent Instructions (WAF Checker)

This file contains the architecture, file locations, build commands, and coding guidelines for the WAF Checker project.

> [!NOTE]
> The project is an **NPM Workspaces monorepo** under `packages/*`. There is **no `app/` directory** — all source lives in `packages/{core,cli,worker}`.

---

## 📂 Project Structure

### `packages/core/` — `@waf-checker/core` (shared security library)

The portable engine shared by the Worker and the CLI. Runs on both the Workers runtime and Node.js.

- **Payloads**:
  - [packages/core/src/payloads.ts](packages/core/src/payloads.ts) — Public payload API: `PAYLOADS`, `PayloadCategory` (`ParamCheck` / `FileCheck` / `Header`), enhanced/encoded payload builders.
  - [packages/core/src/payloads-data/base.ts](packages/core/src/payloads-data/base.ts) — Base attack payloads and categories (SQLi, XSS, Path Traversal, etc.).
  - [packages/core/src/payloads-data/advanced.ts](packages/core/src/payloads-data/advanced.ts) — Advanced / enhanced evasion payload data.
  - [packages/core/src/advanced-payloads.ts](packages/core/src/advanced-payloads.ts) — Encoding variations and WAF-specific bypass generation (`generateWAFSpecificPayloads`, `firstWAFSpecificVariant`).
- **WAF Detection**:
  - [packages/core/src/waf-detection.ts](packages/core/src/waf-detection.ts) — `WAFDetector`: fingerprinting/scoring logic and suggested bypasses.
  - [packages/core/src/waf-signatures.ts](packages/core/src/waf-signatures.ts) — The `WAF_SIGNATURES` table (headers, cookies, body patterns) per vendor.
- **Checking & Verdicts**:
  - [packages/core/src/check.ts](packages/core/src/check.ts) — Core audit engine, `evaluateWAFVerdict`, `detectBotChallenge`, concurrency, and the Worker-side envelope API.
  - [packages/core/src/baseline.ts](packages/core/src/baseline.ts) — Baseline calibration to reduce false positives.
  - [packages/core/src/encoding.ts](packages/core/src/encoding.ts) — Obfuscation/encoding routines (URL, Hex, Base64, Unicode, NFKC).
  - [packages/core/src/http-manipulation.ts](packages/core/src/http-manipulation.ts) — HTTP protocol tampering (Parameter Pollution, Verb Tampering, etc.).
- **Reverse Engineering & Virtual Patching**:
  - [packages/core/src/reverse-engineering/](packages/core/src/reverse-engineering/) — OWASP CRS mapping, body-limit and anomaly-score detection.
  - [packages/core/src/virtual-patch/](packages/core/src/virtual-patch/) — Remediation-rule generators per platform (Cloudflare, AWS, GCP, Azure, ModSecurity, NGINX, HAProxy, Caddy, Apache, Envoy, K8s).
- **Reports**:
  - [packages/core/src/reports/types.ts](packages/core/src/reports/types.ts) — `AuditResultItem`, `AuditReportStats`, `calculateAuditStats`.
  - [packages/core/src/reports/](packages/core/src/reports/) — SARIF, JUnit, and scan-diff report builders.
- **Utilities**:
  - [packages/core/src/utils/security.ts](packages/core/src/utils/security.ts) — Critical security utilities, specifically SSRF validation (`isValidTargetUrl`).
  - [packages/core/src/utils/payload-utils.ts](packages/core/src/utils/payload-utils.ts) — Helpers for manipulating payload arrays.
  - [packages/core/src/utils/concurrency.ts](packages/core/src/utils/concurrency.ts) — Bounded concurrency pool.

### `packages/worker/` — `@waf-checker/worker` (Cloudflare Worker + Web UI)

- **Entry Point & Router**:
  - [packages/worker/src/api.ts](packages/worker/src/api.ts) — Receives all incoming HTTP requests, handles routing and query params, and is the Cron Trigger entry.
- **API Request Handlers**:
  - [packages/worker/src/handlers/check.ts](packages/worker/src/handlers/check.ts) — Checking payloads against target WAFs.
  - [packages/worker/src/handlers/waf-detect.ts](packages/worker/src/handlers/waf-detect.ts) — Detecting the target WAF type.
  - [packages/worker/src/handlers/http-manip.ts](packages/worker/src/handlers/http-manip.ts) — HTTP protocol manipulation tests.
  - [packages/worker/src/handlers/schedule.ts](packages/worker/src/handlers/schedule.ts) — Scheduled-monitoring subscribe/verify/unsubscribe + the cron scan.
- **Services**:
  - [packages/worker/src/services/](packages/worker/src/services/) — `monitor`, `scan`, `email`, `ownership`, `rate-limiter` (scheduled monitoring with domain-ownership verification and email alerts, backed by `MONITOR_KV`).
- **Client-side (Static Assets)** — served from [packages/worker/src/static/](packages/worker/src/static/):
  - [packages/worker/src/static/index.html](packages/worker/src/static/index.html) — The SPA HTML layout.
  - [packages/worker/src/static/main.js](packages/worker/src/static/main.js) — Frontend logic (scans, rendering, report export).
  - [packages/worker/src/static/style.css](packages/worker/src/static/style.css) — Stylesheets including Light/Dark mode.

### `packages/cli/` — `@waf-checker/cli` (Node.js CLI)

- [packages/cli/src/index.ts](packages/cli/src/index.ts) — Command definitions (`check`, `batch`, `detect`, `patch`, `list-wafs`, `list-categories`, `completion`) and terminal output.
- [packages/cli/src/report.ts](packages/cli/src/report.ts) — CLI result types and file-writing.
- [packages/cli/src/reports/](packages/cli/src/reports/) — HTML and Markdown report generators (SARIF/JUnit come from core).

### Tests & Configuration

- `packages/{core,cli,worker}/test/` — Unit, integration, property-based (fast-check), and network-resilience suites (Vitest).
- [wrangler.toml](wrangler.toml) — Worker configuration (subrequest limit, `MONITOR_KV`, email binding, cron). Run Wrangler from the project root.
- [docs/openapi.yaml](docs/openapi.yaml) — OpenAPI 3.1 spec for the Worker REST API.

---

## 🛠️ Developer Commands

> [!IMPORTANT]
> When running shell commands, always prefix them with **`rtk`** (e.g., `rtk npm test`) to optimize token consumption and filter terminal output.

All commands run from the **project root** (npm workspaces).

- **Install & Build** (core + cli; worker builds via Wrangler):
  ```bash
  rtk npm install
  rtk npm run build
  ```

- **Run the Worker (Web UI) locally**:
  ```bash
  rtk npm run dev:worker
  # Web UI at http://localhost:8787
  ```

- **Run Tests** (whole monorepo; `pretest` builds first):
  ```bash
  rtk npm test
  # or a single workspace:
  rtk npm test --workspace @waf-checker/core
  ```

- **Run the CLI without a global install**:
  ```bash
  node packages/cli/dist/index.js check https://example.com
  ```

- **Deploy the Worker to Cloudflare**:
  ```bash
  rtk npx wrangler deploy --workspace=packages/worker
  ```

- **Live Docker E2E suite**:
  ```bash
  rtk npm run test:e2e
  ```

---

## 🛡️ Coding Guidelines & Rules

### 1. SSRF Protection (Mandatory)
Any endpoint or code path that accepts a target URL **MUST** validate it using `isValidTargetUrl` from [packages/core/src/utils/security.ts](packages/core/src/utils/security.ts). This prevents the Worker (and CLI) from being used as an SSRF proxy to scan internal networks or local services. The `--allow-local` CLI flag is the only sanctioned way to relax this, for local Docker/staging testing.

```typescript
import { isValidTargetUrl } from '@waf-checker/core';

if (url && !isValidTargetUrl(url)) {
    return new Response(JSON.stringify({ error: 'Invalid URL or restricted IP' }), { status: 400 });
}
```

### 2. Payload Management
- **Base Payloads**: Add new ones to [packages/core/src/payloads-data/base.ts](packages/core/src/payloads-data/base.ts) with correct injection types (`ParamCheck`, `FileCheck`, or `Header`).
- **Advanced / Evasion Payloads**: Add bypasses to [packages/core/src/payloads-data/advanced.ts](packages/core/src/payloads-data/advanced.ts); encoding and WAF-specific generation live in [packages/core/src/advanced-payloads.ts](packages/core/src/advanced-payloads.ts).

### 3. WAF Detection Signatures
When adding a new WAF/bot-management vendor:
1. Add its signature (headers, `definitiveHeaders`, cookies, body patterns, status codes) to `WAF_SIGNATURES` in [packages/core/src/waf-signatures.ts](packages/core/src/waf-signatures.ts).
2. Add WAF-specific evasion variants in `wafBypassCandidates` / `generateWAFSpecificPayloads` in [packages/core/src/advanced-payloads.ts](packages/core/src/advanced-payloads.ts).
3. For bot-management/CAPTCHA challenges, also wire `detectBotChallenge` in [packages/core/src/check.ts](packages/core/src/check.ts) so the response is classified under the `challenge` verdict rather than a hard `blocked`.

### 4. Verification Before Push
Before pushing your changes:
1. Verify SSRF validation is present in the handlers that take a URL:
   ```bash
   rtk grep -rn "isValidTargetUrl" packages/worker/src/handlers packages/cli/src
   ```
2. Run the full test suite (it builds first via `pretest`):
   ```bash
   rtk npm test
   ```

### 5. Git Branching Policy
- **Branching Rule**: Always create a separate branch for implementing any new features, changes, or experiments. Never perform new work directly on the main branch.
