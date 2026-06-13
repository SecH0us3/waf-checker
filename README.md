# WAF Checker

This project helps you check how well your Web Application Firewall (WAF) protects your product against common web attacks. It can be run as a Cloudflare Worker (with a built-in interactive Web UI) or as a standalone Node.js CLI tool.

## Features

### Core Testing
- Enter a target URL, pick HTTP methods (GET, POST, etc.), and attack categories.
- Sends requests with attack payloads (in parameters, headers, or as file paths).
- Color-coded terminal and web results: 🟢 403/BLOCKED = blocked, 🔴 2xx/5xx = potential bypass, 🟠 3xx = redirect.
- Results displayed in a filterable table with details for each payload.

### Attack Categories (19 total)
SQL Injection, XSS, Path Traversal, Command Injection, SSRF, NoSQL Injection, Local File Inclusion, LDAP Injection, HTTP Request Smuggling, Open Redirect, Sensitive Files, CRLF Injection, UTF8/Unicode Bypass, XXE, SSTI, HTTP Parameter Pollution, Web Cache Poisoning, IP Bypass, User-Agent.

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

### 3. Docker Version

A pre-built Docker image is hosted on GitHub Packages at [ghcr.io/sech0us3/waf-checker-cli](https://github.com/SecH0us3/waf-checker/pkgs/container/waf-checker-cli).

#### Run using the pre-built image
You can run audits immediately without building the image locally:

```bash
# Print help
docker run --rm ghcr.io/sech0us3/waf-checker-cli --help

# Run a check against a target URL
docker run --rm -it ghcr.io/sech0us3/waf-checker-cli check https://example.com

# Run batch audits (mounting a local targets.txt file)
docker run --rm -it -v "$(pwd)/targets.txt:/app/targets.txt" ghcr.io/sech0us3/waf-checker-cli batch targets.txt --concurrency 3
```

#### Build and run locally
Alternatively, if you want to build the image yourself from the source:

```bash
# Build the image locally
docker build -t waf-checker-cli .

# Run a check using the local image
docker run --rm -it waf-checker-cli check https://example.com
```

---

## Testing

To run the workspace-wide test suite (utilizing Vitest):

```bash
npm test
```

---

Read my blog at [yoursec.substack.com](https://yoursec.substack.com/)
