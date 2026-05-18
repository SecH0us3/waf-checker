# Architecture and Implementation Plan for WAF Checker CLI

## 1. Separation of Concerns
To decouple the core WAF auditing logic from Cloudflare Worker constraints:
- **Core Logic Abstraction**: Move `waf-detection.ts`, `payloads.ts`, `advanced-payloads.ts`, `encoding.ts`, `http-manipulation.ts`, and the `utils/` directory to a shared module.
- **Fetch Injection Strategy**: Modify `WAFDetector`, `HTTPManipulator`, and other core functions that perform external network requests to accept an optional `customFetch` function (matching the `fetch` signature). This allows the CLI to pass a custom `fetch` implementation with proxy support, while the Worker defaults to `globalThis.fetch`.
- **Cloudflare Handlers**: The logic inside `app/src/handlers/` and `app/src/api.ts` (handling Cloudflare `Request` and `Response` objects) will remain in the Cloudflare Worker module.

## 2. Directory Structure (Monorepo setup using NPM Workspaces)
Transform the repository into an NPM workspaces monorepo:
```text
/
├── package.json (Workspace root)
└── packages/
    ├── core/ (Shared Business Logic)
    │   ├── package.json
    │   ├── src/
    │   │   ├── waf-detection.ts
    │   │   ├── payloads.ts
    │   │   ├── advanced-payloads.ts
    │   │   ├── encoding.ts
    │   │   ├── http-manipulation.ts
    │   │   └── utils/
    │   └── test/
    ├── worker/ (Cloudflare Worker)
    │   ├── package.json
    │   ├── wrangler.toml
    │   ├── vitest.config.mts
    │   └── src/
    │       ├── api.ts
    │       ├── handlers/
    │       └── static/
    └── cli/ (Node.js CLI)
        ├── package.json
        └── src/
            └── index.ts
```

## 3. CLI Setup
- **Framework**: Use `commander` to build the command-line interface.
- **Commands**: Mirror the functionality of the Worker API (e.g., `waf-checker check <url>`, `waf-checker detect <url>`).
- **Options**: Include `--proxy <url>` for proxy routing, and parameters like `--methods`, `--categories`, etc.
- **Formatting**: Output results clearly in the terminal.
- **Executable**: Configure `"bin"` in `cli/package.json` to map to the compiled index file, enabling global installation via `npm install -g`.

## 4. Proxy Integration
Since Cloudflare Worker's `fetch` does not support standard proxy dispatchers, the Node.js CLI must provide its own HTTP client strategy:
- Add `undici` as a dependency in the CLI package.
- If the `--proxy` flag is provided, instantiate an `undici` `ProxyAgent`.
- Create a custom fetch wrapper that uses `undici.fetch` and injects the `dispatcher: proxyAgent` into the request options.
- Pass this `customFetch` wrapper to the core logic (e.g., `WAFDetector.detectBypassOpportunities(url, { fetch: customFetch })`).

## 5. Build System Modification
- **Root `package.json`**: Add `"workspaces": ["packages/*"]`.
- **`packages/core`**: Add `typescript` and build configuration.
- **`packages/worker`**: Update dependencies to point to `"@waf-checker/core": "*"`. Retain `wrangler` configuration.
- **`packages/cli`**: Build configuration for a standalone Node.js binary.

## Step-by-Step Implementation Sequence

1. **Create Directory Structure**: Run bash commands to create `packages/core/src`, `packages/worker/src`, `packages/cli/src`, `packages/core/test`, and `packages/worker/test` directories.
2. **Configure Root Workspace**: Modify root `package.json` to include `"workspaces": ["packages/*"]` and base scripts.
3. **Move Core Files**: Use bash `mv` to move `waf-detection.ts`, `payloads.ts`, `advanced-payloads.ts`, `encoding.ts`, `http-manipulation.ts`, and `utils/` from `app/src/` to `packages/core/src/`.
4. Move Worker Files: Use bash mv to move api.ts, handlers/, and static/ from app/src/ to packages/worker/src/, and wrangler.toml from ./wrangler.toml to packages/worker/. Move app/vitest.config.mts to packages/worker/vitest.config.mts. Update wrangler.toml paths (main, assets.directory) to be relative to the new root.
5. **Verify File Movements**: Run `ls -R packages/` via bash to confirm the new layout matches the monorepo architecture.
6. **Create Core Package Config**: Create `packages/core/package.json` with appropriate build scripts and TypeScript config.
7. **Create Worker Package Config**: Create `packages/worker/package.json` by copying and modifying the original `app/package.json`, adding a dependency on `@waf-checker/core`.
8. **Create CLI Package Config**: Create `packages/cli/package.json` with `bin` configuration and CLI dependencies.
9. **Verify Package Configs**: Read the contents of all three new `package.json` files to ensure correctness.
10. **Refactor WAFDetector**: Modify `packages/core/src/waf-detection.ts` to accept a custom `fetch` parameter.
11. **Refactor HTTPManipulator**: Modify `packages/core/src/http-manipulation.ts` to accept a custom `fetch` parameter.
12. **Verify Refactoring**: Use `read_file` or `grep` to confirm `customFetch` injection logic was applied correctly in core files.
13. **Update Worker Imports**: Edit `packages/worker/src/api.ts` and files in `packages/worker/src/handlers/` to use `@waf-checker/core` imports.
14. **Verify Imports**: Run a TypeScript compiler check (`npx tsc --noEmit`) to confirm imports resolve correctly.
15. **Install CLI Dependencies**: Run `npm install commander undici --workspace=packages/cli` to add required CLI libraries.
16. **Verify CLI Dependencies**: Read `packages/cli/package.json` to confirm `commander` and `undici` were added.
17. **Implement CLI Entrypoint**: Create and write `packages/cli/src/index.ts` using file editing tools to scaffold the CLI options and handle `--proxy` logic.
18. **Verify CLI Entrypoint**: Run a dry run of the CLI script or use `read_file` to verify `packages/cli/src/index.ts`.
19. Move Test Files: Use bash mv to move pure logic tests (payload-utils.spec.ts, business-logic.spec.ts, security.spec.ts, memory-leak-fix-verification.spec.ts) to packages/core/test/ and integration tests (batch-handler.spec.ts, index.spec.ts, waf-detect-handler.spec.ts) to packages/worker/test/. Move env.d.ts and tsconfig.json to packages/worker/.
20. **Update Vitest Config**: Edit `packages/worker/vitest.config.mts` to reflect the new paths. Create a standard node testing `packages/core/vitest.config.mts` for the core module.
21. **Verify Test Movements**: Confirm the new file paths and config edits using `ls` and `read_file`.
22. **Run Tests**: Execute tests using `npm test -- --run` to verify the shared logic and ensure the Cloudflare worker tests continue to pass without timing out in the bash session.
