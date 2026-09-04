# API Improvements Implementation Plan

This plan implements the requested API improvements from `API_IMPROVEMENTS.md` to optimize integration with [swazz](https://github.com/SecH0us3/swazz) and external consumers.

## Invariant Constraints
- **100% Additive Changes**: Do not rename, retype, or remove any existing field. All new fields must be optional or additive alongside existing fields.
- **SSRF Protection**: All endpoints accepting target URLs MUST validate with `isValidTargetUrl`.
- **Git Branching**: Develop on a dedicated git branch `feat/api-improvements-swazz`.
- **Testing**: Add comprehensive unit and integration tests; all 366+ tests must pass with zero regressions.

---

## Proposed Changes & Files Modified

### 1. `packages/core/src/reports/types.ts`
- Extend `AuditResultItem` with:
  - `blocked?: boolean;`
  - `verdict?: 'blocked' | 'passed' | 'exposed';`
  - `error?: string | null;`
- Export new `CheckResultEnvelope` interface:
  ```ts
  export interface CheckResultEnvelope {
    results: AuditResultItem[];
    page: number;
    pageSize: number;
    total: number;
    hasMore: boolean;
  }
  ```

### 2. `packages/core/src/waf-detection.ts`
- Extend `WAFDetectionResult` interface with:
  - `confidencePercent: number;` (clamped 0-100)
  - `confidenceThreshold: number;` (40)
- Update `detectFromResponse` and `activeDetection` to populate these fields.

### 3. `packages/core/src/check.ts`
- Implement `evaluateWAFVerdict(status, bodyText, detection, headers)` helper:
  - `blocked: boolean`: true if WAF stopped the request (characteristic status code or signature/body pattern match like Imperva interstitial).
  - `verdict: 'blocked' | 'passed' | 'exposed'`:
    - `'blocked'` if `blocked === true`
    - `'exposed'` if not blocked and origin returned resource (2xx with non-empty body)
    - `'passed'` if not blocked and origin did not serve resource (404, 5xx, or empty 2xx)
- Update `sendRequest` to:
  - Capture response body snippet (first 64KB for verdict analysis).
  - Categorize errors into explicit strings (`'timeout'`, `'dns'`, `'network_error'`).
  - Return `{ status, is_redirect, responseTime, response, bodyText, error }`.
- Update `results.push` across all 3 check types (`ParamCheck`, `FileCheck`, `Header`) to include `blocked`, `verdict`, and `error`.
- Support configurable `pageSize` / `limit` and export `handleApiCheckWithEnvelope`.

### 4. `packages/worker/src/api.ts`
- **Self-Scan Guard**:
  - Tighten hostname check (parse URL hostname instead of substring match).
  - Check against `['secmy.org']` or ends with `.secmy.org`.
  - Return HTTP 422 `{ error: 'self-scan refused', code: 'SELF_SCAN_REFUSED' }`.
- **Pagination Envelope**:
  - Check for `?envelope=1`, `?envelope=true`, or `Accept: application/vnd.waf-checker.v2+json`.
  - Return `CheckResultEnvelope` if requested; return bare array by default for backward compatibility.
  - Support `pageSize` query parameter.
- **Combined Endpoint (`/api/audit`)**:
  - Implement `GET /api/audit` and `POST /api/audit` executing WAF detection + check + virtual patch generation in a single round-trip.

### 5. `packages/core/src/index.ts`
- Ensure all public interfaces (`CheckResultEnvelope`, `AuditResultItem`, `WAFDetectionResult`, `VirtualPatchReport`) are explicitly exported for external consumers.

### 6. `docs/openapi.yaml` & `README.md`
- Create an OpenAPI 3.1 schema specification documenting the public API endpoints and DTO models.
- Update `README.md` with API documentation and links.

---

## Tasks

### Task 1: Branch Creation & Type Extensions
1. Create and checkout git branch `feat/api-improvements-swazz`.
2. Update `packages/core/src/reports/types.ts` and `packages/core/src/waf-detection.ts` with additive fields.
3. Export new types in `packages/core/src/index.ts`.
4. Run `npm test` to verify zero type regressions.

### Task 2: Core Verdict & Failure Error Handling
1. Write failing unit tests in `packages/core/test/verdict.spec.ts` covering:
   - Cloudflare 403 block page -> blocked: true, verdict: 'blocked'
   - Imperva 200 interstitial -> blocked: true, verdict: 'blocked'
   - Origin 404 Not Found -> blocked: false, verdict: 'passed'
   - Origin 200 with real payload -> blocked: false, verdict: 'exposed'
   - Origin empty 200 -> blocked: false, verdict: 'passed'
   - Network abort / timeout -> status: 'ERR', error: 'timeout'
2. Implement `evaluateWAFVerdict` and update `sendRequest` in `packages/core/src/check.ts`.
3. Update `handleApiCheckFiltered` and add `handleApiCheckWithEnvelope`.
4. Run tests and ensure all pass.

### Task 3: Worker API Enhancements (Envelope, Self-Scan & Combined Audit)
1. Add tests in `packages/worker/test/index.spec.ts`:
   - Self-scan returns 422 `SELF_SCAN_REFUSED` for `secmy.org` (and allows unrelated domains like `secmyapp.io`).
   - `/api/check?envelope=1` returns envelope with `{ results, page, pageSize, total, hasMore }`.
   - `/api/waf-detect` returns `confidencePercent` and `confidenceThreshold`.
   - `/api/audit` returns `{ detection, results, patches }`.
2. Update `packages/worker/src/api.ts` to implement envelope gating, self-scan 422, and `/api/audit`.
3. Run worker tests and verify.

### Task 4: OpenAPI Specification & Documentation
1. Create `docs/openapi.yaml` with OpenAPI 3.1 definitions.
2. Update `README.md` documenting new query flags (`?envelope=1`, `?pageSize=`), response fields (`blocked`, `verdict`), and `/api/audit`.
3. Run full monorepo test suite (`npm test`).
4. Commit, push, and open PR.
