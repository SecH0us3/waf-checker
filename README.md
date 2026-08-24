# WAF Checker

[![GitHub Release](https://img.shields.io/github/v/release/SecH0us3/waf-checker?color=blue&label=release)](https://github.com/SecH0us3/waf-checker/releases)
[![GitHub Action](https://img.shields.io/badge/action-v1-blue?logo=githubactions&logoColor=white)](https://github.com/SecH0us3/waf-checker/releases)
[![Coverage: Core](https://img.shields.io/badge/coverage%3A%20core-88.7%25-brightgreen)](packages/core)
[![Coverage: CLI](https://img.shields.io/badge/coverage%3A%20cli-91.0%25-brightgreen)](packages/cli)
[![Tests](https://img.shields.io/badge/tests-249%20passed-brightgreen)]()

This project helps you check how well your Web Application Firewall (WAF) protects your product against common web attacks. It can be run as a Cloudflare Worker (with a built-in interactive Web UI) or as a standalone Node.js CLI tool.

## 🧪 Test Coverage & Status

All packages are thoroughly tested with automated unit and integration suites (100% SSRF safety compliance, protocol evasion techniques, and report formatters):

| Package | Line Coverage | Statements | Functions | Test Suite |
| :--- | :---: | :---: | :---: | :---: |
| [**`@waf-checker/core`**](packages/core) | `88.7%` 🟢 | `88.5%` | `96.1%` | 🟢 178 passing |
| [**`@waf-checker/cli`**](packages/cli) | `91.0%` 🟢 | `90.4%` | `96.7%` | 🟢 45 passing |
| [**`@waf-checker/worker`**](packages/worker) | `Passing` 🟢 | — | — | 🟢 26 passing |
| **Total Monorepo Suite** | **`89.5%`** | **`89.1%`** | **`96.3%`** | **🟢 249 tests passing** |

## Features

### Core Testing
- Enter a target URL, pick HTTP methods (GET, POST, etc.), and attack categories.
- Sends requests with attack payloads (in parameters, headers, or as file paths).
- Color-coded terminal and web results: 🟢 403/BLOCKED = blocked, 🔴 2xx/5xx = potential bypass, 🟠 3xx = redirect.
- Results displayed in a filterable table with details for each payload.

### Attack Categories (25 total)
SQL Injection, XSS, Command Injection, Path Traversal, SSRF, Local File Inclusion, Sensitive Files, Open Redirect, SSTI, XXE, NoSQL Injection, GraphQL Injection, JWT Attack (Header), JWT Attack (Param), Prototype Pollution (JSON Body), Prototype Pollution (URL/Param), LDAP Injection, CRLF Injection, HTTP Parameter Pollution, User-Agent, IP Bypass, HTTP Request Smuggling, Web Cache Poisoning, UTF8/Unicode Bypass, WAF Inspection Limit Bypass (Padding).

### WAF Detection
- Auto-detect WAF type before testing (Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva, F5 BIG-IP, etc.).
- Suggests specific bypass techniques based on detected WAF.
- Can auto-switch to WAF-specific advanced payloads.

### Advanced Payloads & Encoding
- WAF Bypass Payloads — double encoding, unicode, mixed case, comment injection, polyglot payloads.
- Enhanced Payloads — modern evasion techniques.
- Encoding Variations — URL, Unicode, HTML Entity, Hex, Octal, Base64 encoding with automatic combinations.
- WAF-specific bypasses for Cloudflare, AWS WAF, ModSecurity.

### HTTP Protocol Manipulation
- HTTP Verb Tampering — test uncommon HTTP methods.
- Parameter Pollution — duplicate and split parameters across query/body.
- Content-Type Confusion — alternate content types to bypass rules.
- Request Smuggling headers.
- Host Header Injection variations.
- HTTP Method Override via headers (`X-HTTP-Method-Override`, etc.).

### Batch Testing
- Test multiple URLs at once.
- Configurable concurrency and delay between requests.
- Real-time progress tracking.

---

## Project Structure

The project is structured as an NPM Workspaces monorepo:

- [**`packages/core/`**](file:///Users/alex/src/waf-checker/packages/core): The core security testing library, payloads definition, WAF fingerprinting signatures, and obfuscation encoders.
- [**`packages/worker/`**](file:///Users/alex/src/waf-checker/packages/worker): Cloudflare Worker package serving the static HTML/JS Web UI and JSON API endpoints.
- [**`packages/cli/`**](file:///Users/alex/src/waf-checker/packages/cli): Node.js command-line interface tool for executing audits directly from your terminal.

---

## Installation & Building

From the root directory, install dependencies and build all workspaces:

```bash
npm install
npm run build
```

---

## How to Run

### 1. Web Version (Cloudflare Worker)

To run the Worker dev server locally (requires Wrangler):

```bash
npm run dev:worker
```

The Web UI will be accessible at `http://localhost:8787` (or another port if 8787 is occupied).

To deploy the Worker to Cloudflare:
```bash
npx wrangler deploy --workspace=packages/worker
```

### 2. CLI Version (Node.js)

To run security testing audits directly from your command line:

```bash
# Print general CLI help and usage
node packages/cli/dist/index.js --help

# Print check command help (lists all methods, categories, and WAF vendors)
node packages/cli/dist/index.js check --help
```

#### WAF Detection
Detect the WAF vendor behind a target URL:
```bash
node packages/cli/dist/index.js detect <url>
```

#### Vulnerability payload audit
Run an audit against a target URL:
```bash
# Default check (GET method, all payload categories)
node packages/cli/dist/index.js check https://example.com

# Custom check with specific methods, categories, and WAF evasion enabled
node packages/cli/dist/index.js check https://example.com -m GET,POST -c "SQL Injection,XSS" --auto-detect-waf --encoding-variations
```

#### Batch Audits
Run batch audits for a list of URLs defined in a file:
```bash
node packages/cli/dist/index.js batch targets.txt --concurrency 3
```

#### Generating Reports
Save audit results in **SARIF**, **HTML**, **Markdown**, **CSV**, or **JSON** format:
```bash
# Generate SARIF report for GitHub Code Scanning
node packages/cli/dist/index.js check https://example.com -o results.sarif

# Generate interactive HTML report
node packages/cli/dist/index.js check https://example.com -o report.html

# Generate Markdown summary for CI
node packages/cli/dist/index.js check https://example.com -o summary.md
```

#### CI/CD Integration & Protection Thresholds
Fail CI/CD pipelines when protection rate is below required threshold or when bypasses are detected:
```bash
# Fail if WAF protection rate is below 95%
node packages/cli/dist/index.js check https://example.com --threshold 95 -q

# Fail immediately on any detected bypass
node packages/cli/dist/index.js check https://example.com --fail-on-bypass -q
```

---

## 🚀 GitHub Action (CI/CD)

Integrate automated WAF security testing into your GitHub Actions workflow:

```yaml
name: WAF Security Audit

on:
  push:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 1' # Weekly audit

jobs:
  waf-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write # Required for SARIF upload
      contents: read
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run WAF Checker
        uses: SecH0us3/waf-checker@main
        with:
          target-url: 'https://staging.example.com'
          threshold: '95'
          enhanced: 'true'
          advanced: 'true'
          sarif-output: 'waf-results.sarif'
          html-output: 'waf-report.html'

      - name: Upload SARIF to GitHub Security Tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'waf-results.sarif'

      - name: Upload HTML Report Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: waf-audit-report
          path: waf-report.html
```

### 3. Docker Version

You can run the CLI using Docker, either by pulling the pre-built image from GitHub Container Registry or by building it locally.

#### Using Pre-built Image (Recommended)

The pre-built Docker image is available on [GitHub Container Registry](https://github.com/SecH0us3/waf-checker/pkgs/container/waf-checker-cli) at `ghcr.io/sech0us3/waf-checker-cli`.

##### Pull the image
```bash
docker pull ghcr.io/sech0us3/waf-checker-cli:latest
```

##### Print help
```bash
docker run --rm ghcr.io/sech0us3/waf-checker-cli:latest --help
```

##### Run a check
```bash
docker run --rm -it ghcr.io/sech0us3/waf-checker-cli:latest check https://example.com
```

##### Run batch audits (mounting a local directory)
```bash
docker run --rm -it -v "$(pwd):/data" ghcr.io/sech0us3/waf-checker-cli:latest batch /data/targets.txt --concurrency 3
```

#### Building Locally

##### Build the image
```bash
docker build -t waf-checker-cli .
```

##### Print help
```bash
docker run --rm waf-checker-cli --help
```

##### Run a check
```bash
docker run --rm -it waf-checker-cli check https://example.com
```

##### Run batch audits (mounting a local directory)
```bash
docker run --rm -it -v "$(pwd):/data" waf-checker-cli batch /data/targets.txt --concurrency 3
```

---

## Testing

To run the workspace-wide test suite (utilizing Vitest):

```bash
npm test
```

---

Read my blog at [yoursec.substack.com](https://yoursec.substack.com/)
