# AI Agent Instructions (WAF Checker)

This file contains the architecture, file locations, build commands, and coding guidelines for the WAF Checker project.

---

## 📂 Project Structure

### Server-side (Cloudflare Worker in TypeScript)

All backend source files are located in `app/src/`:

- **Entry Point & Router**:
  - [app/src/api.ts](app/src/api.ts) — Receives all incoming HTTP requests, handles routing, and processes query parameters.
- **API Request Handlers**:
  - [app/src/handlers/check.ts](app/src/handlers/check.ts) — Main handler for checking payloads against target WAFs.
  - [app/src/handlers/batch.ts](app/src/handlers/batch.ts) — Handler for batch URL testing with concurrency and queue management.
  - [app/src/handlers/waf-detect.ts](app/src/handlers/waf-detect.ts) — Handler for detecting the target WAF type.
  - [app/src/handlers/http-manip.ts](app/src/handlers/http-manip.ts) — Handler for testing HTTP protocol manipulations.
- **Core Logic & Business Logic**:
  - [app/src/payloads.ts](app/src/payloads.ts) — Base attack payloads and categories (SQLi, XSS, Path Traversal, etc.).
  - [app/src/advanced-payloads.ts](app/src/advanced-payloads.ts) — Advanced WAF evasion techniques (comment injection, double encoding, etc.).
  - [app/src/waf-detection.ts](app/src/waf-detection.ts) — Fingerprinting logic and signature mapping for different WAF vendors.
  - [app/src/encoding.ts](app/src/encoding.ts) — Obfuscation and encoding routines (URL, Hex, Base64, Unicode).
  - [app/src/http-manipulation.ts](app/src/http-manipulation.ts) — HTTP protocol tampering logic (Parameter Pollution, Verb Tampering).
- **Utilities**:
  - [app/src/utils/security.ts](app/src/utils/security.ts) — Critical security utilities, specifically SSRF validation.
  - [app/src/utils/payload-utils.ts](app/src/utils/payload-utils.ts) — Helper functions for manipulating payload arrays.

### Client-side (Static Assets)

The frontend is served from `app/src/static/`:

- [app/src/static/index.html](app/src/static/index.html) — The Single Page Application (SPA) HTML layout.
- [app/src/static/main.js](app/src/static/main.js) — Frontend logic (initiating scans, rendering charts, exporting reports).
- [app/src/static/style.css](app/src/static/style.css) — Custom stylesheets including Light/Dark mode transitions.

### Tests & Configurations

- [app/test/](app/test/) — Unit and integration tests using Vitest.
- [wrangler.toml](wrangler.toml) — Global Wrangler configuration (run locally from the project root).

---

## 🛠️ Developer Commands

> [!IMPORTANT]
> When running shell commands, always prefix them with **`rtk`** (e.g., `rtk npm test`) to optimize token consumption and filter terminal output.

- **Run Server Locally**:
  ```bash
  npx wrangler dev
  # or using rtk in terminal:
  rtk npx wrangler dev
  ```
  *(Run this from the project root directory)*

- **Run Tests**:
  ```bash
  cd app && npm test
  # or using rtk:
  rtk npm test -- --run
  ```

- **Deploy to Cloudflare**:
  ```bash
  cd app && npm run deploy
  # or using rtk:
  rtk npm run deploy
  ```

---

## 🛡️ Coding Guidelines & Rules

### 1. SSRF Protection (Mandatory)
Any endpoint that accepts a target URL **MUST** validate it using `isValidTargetUrl` from [app/src/utils/security.ts](app/src/utils/security.ts). This prevents the Cloudflare Worker from being used as an SSRF proxy to scan internal networks or local services.

```typescript
import { isValidTargetUrl } from './utils/security';

if (url && !isValidTargetUrl(url)) {
    return new Response(JSON.stringify({ error: 'Invalid URL or restricted IP' }), { status: 400 });
}
```

### 2. Payload Management
- **Base Payloads**: Add new ones to [app/src/payloads.ts](app/src/payloads.ts) with correct injection types (`ParamCheck`, `FileCheck`, or `Header`).
- **Evasion Payloads**: Add bypasses to [app/src/advanced-payloads.ts](app/src/advanced-payloads.ts).

### 3. WAF Detection Signatures
When adding a new WAF:
1. Update [app/src/waf-detection.ts](app/src/waf-detection.ts) with new header signatures.
2. Add specific evasion techniques to `WAF_BYPASS_PAYLOADS` in [app/src/advanced-payloads.ts](app/src/advanced-payloads.ts).

### 4. Verification Before Push
Before pushing your changes:
1. Verify SSRF validation in handlers:
   ```bash
   rtk grep "isValidTargetUrl" app/src/handlers/*.ts
   ```
2. Run the test suite:
   ```bash
   rtk npm test -- --run
   ```
