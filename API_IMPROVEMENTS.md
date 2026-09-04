# waf-checker API — improvements requested by the swazz integration

## Who is asking and why

[swazz](https://github.com/SecH0us3/swazz) (an API fuzzer) now ships a "WAF" feature built entirely
on this service. It consumes three endpoints:

| Endpoint | Consumer | Purpose |
|---|---|---|
| `GET /api/waf-detect` | Go engine (`internal/wafcheck`), Cloudflare Worker (`services/wafCheck.ts`) | Pre-scan domain fingerprinting |
| `GET /api/check?categories=Sensitive Files` | Cloudflare Worker | On-demand sensitive-file probing |
| `POST /api/virtual-patch` | Go engine, Cloudflare Worker | Firewall rule generation |

While building it, several workarounds had to be written on the swazz side purely because the API
does not expose information it already has internally. Each item below names the exact file and
line in *this* repo, what swazz is forced to do because of it, and the proposed change.

## Hard constraint: all changes must be additive

swazz already has released Go binaries and a deployed Worker parsing the current response shapes.
**Do not rename, retype, or remove any existing field.** Add new fields alongside the old ones.
A consumer that ignores the new fields must keep working byte-for-byte as it does today.

---

## 1. Add a per-result WAF verdict to `/api/check` — highest impact

**Where:** `packages/core/src/check.ts:341-352` (and the second `results.push` at `:382`)

**Current result item:**

```ts
results.push({
    category,
    payload: currentPayload,
    originalPayload: payload,
    method,
    status: res ? res.status : 'ERR',
    is_redirect: res ? res.is_redirect : false,
    responseTime: res ? res.responseTime : 0,
    wafDetected: wafDetectionResult?.detected || false,
    wafType: detectedWAFType || 'Unknown',
    bypassTechnique: currentPayload !== payload ? 'Advanced' : 'Standard',
});
```

**The problem.** There is no field saying whether the WAF actually blocked the request. Consumers
must infer it from the raw status code. swazz currently ships this guess in its UI:

```ts
function isExposedStatus(status: number): boolean {
    return status === 200;
}
function isBlockedStatus(status: number): boolean {
    return status === 403 || status === 406 || status === 429 || (status >= 300 && status < 400);
}
```

That heuristic is wrong for several vendors this repo already knows how to fingerprint — Imperva
commonly returns `200` with its own interstitial HTML, some AWS WAF configurations return `403`
with an empty body that is indistinguishable from an origin `403`, and a `404` means "the WAF let
the request reach the origin, the file simply is not there" (a coverage gap, not a leak) — a
distinction the consumer cannot make from the status code alone.

The vendor knowledge lives in this repo, not in the consumer. The classification belongs here.

**Requested change.** Add two fields to every result item:

```ts
/** Did the WAF stop this request before it reached the origin? */
blocked: boolean;
/** Coarse outcome, derived from `blocked` + status + response fingerprint. */
verdict: 'blocked' | 'passed' | 'exposed';
```

Semantics to implement:

- `blocked` — the response was produced by the WAF, not the origin. Determine this the same way
  `waf-detection.ts` already does (vendor signature headers, known block-page body markers,
  characteristic status codes per vendor), not by a bare status-code allowlist.
- `verdict`:
  - `'blocked'` — `blocked === true`
  - `'exposed'` — not blocked **and** the origin returned the resource (`2xx` with a non-empty body)
  - `'passed'` — not blocked, but the origin did not serve the resource (`404`, `5xx`, empty `2xx`).
    The WAF failed to filter the probe, yet nothing leaked.

The `'passed'` vs `'exposed'` split matters: it is exactly the distinction between "your WAF has a
coverage gap" and "you are leaking a file", and consumers currently cannot draw it. Both halves
carry real signal and collapsing them in either direction loses something — reporting every
unblocked probe as a leak cries wolf, while dropping the `404`s hides a genuine gap in WAF
coverage. That is why this needs two fields rather than one boolean.

**Verification:** add unit tests covering, at minimum, a Cloudflare `403` block page, an Imperva
`200` interstitial, an origin `404`, and an origin `200` serving real content — asserting the
`verdict` for each.

---

## 2. Wrap `/api/check` results in a pagination envelope

**Where:** `packages/worker/src/api.ts:156` (returns `JSON.stringify(results)` — a bare array),
page size hardcoded at `packages/core/src/check.ts:207` (`const limit = 50;`)

**The problem.** The page size is never sent to the client, and there is no total or
"is there more" signal. swazz has to reverse-engineer the loop termination:

```ts
const MAX_PAGES = 20;
const PAGE_SIZE = 50;      // guessed — must match check.ts's `limit`
for (let page = 0; page < MAX_PAGES; page++) {
  const pageResults = await fetch(`${endpoint}/api/check?...&page=${page}`);
  allResults.push(...pageResults);
  if (pageResults.length < PAGE_SIZE) break;
}
```

If `limit` in `check.ts` ever changes, this loop silently breaks — it will either stop early
(under-scanning, reporting a falsely clean result) or issue an extra pointless request. The
`MAX_PAGES = 20` cap is also a blind guess at how many pages could exist. Worst case that is 20
sequential requests at up to 90s each from inside a Cloudflare Worker, which is uncomfortably
close to platform limits.

**Requested change.** Return an object instead of a bare array:

```ts
{
  results: AuditResultItem[],
  page: number,        // echo of the requested page
  pageSize: number,    // the `limit` actually applied
  total: number,       // total payloads matching the category/method filter
  hasMore: boolean
}
```

**Backwards compatibility:** gate this behind an opt-in so existing clients are untouched — e.g.
respond with the envelope only when the request carries `?envelope=1` (or
`Accept: application/vnd.waf-checker.v2+json`). swazz will adopt the flag immediately; the bare
array stays the default until every consumer has migrated.

Ideally also raise or expose a configurable `pageSize`, so a 72-payload category can be fetched in
one round trip instead of two.

---

## 3. Expose a normalized confidence percentage on `/api/waf-detect`

**Where:** `packages/core/src/waf-detection.ts` — `confidence` accumulates additively
(`+= 30` at `:65` and `:71`, `+= 20` at `:81`, `+= 25` at `:91` and `:102`, `+= 5` at `:110`), with
the detection threshold at `:124` (`const detected = bestMatch.confidence > 40;`).

**The problem.** `confidence` is an unbounded point score, but its name reads like a percentage and
nothing in the response says otherwise. This caused a real, shipped bug in swazz: the value was
multiplied by 100 for display and rendered as **"9500%"**. The fix required scattering clamps
across four separate places in the consumer:

- `packages/container/internal/output/html.go` — `math.Min(100, ...)`
- `packages/container/internal/output/markdown.go` — `math.Min(100, ...)`
- `packages/edge/src/services/wafCheck.ts` — `Math.max(0, Math.min(100, ...))`
- `packages/web/src/components/WafCheck/WafCheckPanel.tsx` — `Math.round(Math.min(100, ...))`

**Requested change.** Keep `confidence` exactly as it is (raw score is genuinely useful for
debugging and tuning) and add, next to it:

```ts
/** `confidence` normalized to 0-100 for display. */
confidencePercent: number;
/** The score above which `detected` flips to true (currently 40). */
confidenceThreshold: number;
```

Exposing the threshold lets consumers render an honest "how close to the line was this" indicator
instead of hardcoding `40`.

---

## 4. `status` can be the string `'ERR'` — make the failure case explicit

**Where:** `packages/core/src/check.ts:346` — `status: res ? res.status : 'ERR'`

**The problem.** The field's real type is `number | 'ERR'`, but nothing documents it. swazz declares
it as `status: number` in TypeScript and as `int` in Go. It does not currently crash (the string
simply fails every numeric comparison and the row falls into a default bucket), but it is a silent
type lie that will bite whoever writes the next consumer.

**Requested change.** Either:

- keep `status` numeric-or-null and move the failure into its own field:
  ```ts
  status: number | null,
  error: string | null,   // e.g. 'timeout', 'dns', 'connection reset'
  ```
- or, at minimum, document the union prominently in the README and give the error a stable,
  machine-readable set of values rather than the single opaque `'ERR'`.

The first option is preferred — a network failure and an HTTP status are different things and
consumers want to report them differently (a timeout is not a WAF block).

---

## 5. Do not silently return an empty array for self-scans

**Where:** `packages/worker/src/api.ts:82-84`

```ts
if (url.includes('secmy')) {
    return new Response(JSON.stringify([]), { headers: { 'content-type': 'application/json; charset=UTF-8' } });
}
```

**The problem.** A refused self-scan is indistinguishable from a completed scan that found nothing.
In swazz's UI this renders as a successful check reporting "0 paths probed", which reads as "your
target is clean" — the opposite of the truth, which is "we did not look at all".

Secondary note: the guard is a naive substring test, so it also refuses any unrelated domain
containing the string (`secmyapp.io`, `mysecmy.dev`, `not-secmy.example.com`).

**Requested change.** Return an explicit refusal the consumer can render:

```
HTTP 422
{ "error": "self-scan refused", "code": "SELF_SCAN_REFUSED" }
```

and tighten the match to the actual hostname (parse the URL, compare `u.hostname` against an exact
domain/suffix list) rather than a substring of the whole URL.

---

## 6. Publish the response types

**The problem.** The DTOs are currently hand-duplicated in four places inside swazz — Go client
(`internal/wafcheck`), Go shared types (`internal/swagger`), the Cloudflare Worker
(`services/wafCheck.ts`), and the React app (`types.ts`). Any change to the wire format here is
discovered by swazz only at runtime, in production.

**Requested change.** Either publish a `@waf-checker/types` package exporting the request/response
interfaces, or commit an OpenAPI description of the four public endpoints. Either lets the
TypeScript consumers generate their types and gives the Go side something to validate against.

---

## 7. Optional: a single combined audit endpoint

**The problem.** swazz's `runWafCheck` is pure orchestration of this API:

1. `GET /api/waf-detect` — fingerprint
2. `GET /api/check?categories=Sensitive Files&page=N` — loop until a short page
3. `POST /api/virtual-patch` — turn the findings into rules

That is up to 22 sequential subrequests from one Cloudflare Worker invocation, with a worst case
well into the tens of minutes, and every consumer that wants this workflow has to reimplement it.

**Requested change (larger, only if you want it).** A single endpoint —
`GET /api/audit?url=...&categories=Sensitive Files` — returning:

```ts
{
  detection: { ... },              // same shape as /api/waf-detect
  results:   AuditResultItem[],    // all pages, already aggregated
  patches:   VirtualPatchReport    // same shape as /api/virtual-patch
}
```

This would delete swazz's entire orchestration layer and remove the Worker-limit risk. Given the
runtime involved, it should probably be a streaming or job-based endpoint rather than one long
request — see the note below before choosing.

**Note on the existing batch API:** `/api/batch/start|status|stop` looks like the natural fit for a
job-based design, but as implemented it will not work for an external consumer. Jobs live in
`const batchJobs = new Map<...>` (`packages/worker/src/handlers/batch.ts:8`, capped at
`MAX_BATCH_JOBS = 50`). In a Cloudflare Worker that Map belongs to a single isolate, so a
`/api/batch/status` poll can easily land on a different isolate that has never seen the job. Making
this reliable requires backing it with a Durable Object or KV first.

---

## Suggested order of work

1. **Item 1** (verdict field) — largest correctness win; removes wrong heuristics from consumers.
2. **Item 2** (pagination envelope) — removes a silent-breakage class of bug.
3. **Item 3** (confidencePercent) — trivial, retires a bug that already shipped once.
4. **Items 4 and 5** — small, self-contained correctness fixes.
5. **Item 6** — prevents future drift.
6. **Item 7** — only if you want to own the whole workflow.

Items 1-5 are individually small and independently shippable. Please keep every change additive,
per the constraint at the top, and add unit tests alongside — swazz will adopt each field as soon
as it appears in production.
