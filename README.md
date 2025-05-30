# WAF Checker (Cloudflare Worker Style)

This project is a web application for testing the security of web applications against various attacks using typical payloads. It is implemented in a Cloudflare Worker style using TypeScript and provides a convenient web interface for WAF (Web Application Firewall) testing.

## Main Features
- Web interface for entering the target URL and selecting HTTP methods (GET, POST, PUT, DELETE).
- Flexible selection of attack categories (SQLi, XSS, Path Traversal, Command Injection, SSRF, NoSQLi, LFI, SSTI, XXE, HTTP Header, and more).
- Each category uses its own set of payloads (in parameters, headers, or as file paths).
- Automatic sending of requests with payloads for the selected categories and methods.
- Color-coded results by status code:
  - 2xx/5xx — red (potential vulnerability)
  - 403 — green (WAF blocks)
  - other 4xx — orange (non-standard response)
- Results are displayed in a table with details for each payload.
- Easily extendable payload list (see `app/src/payloads.ts`).

## How to Use
1. Start the server (for example, via Cloudflare Worker or a dev server).
2. Open your browser and go to `/` (e.g., http://localhost:8000).
3. Enter the URL to test, select HTTP methods and attack categories.
4. Click "Check" — results will appear below.

## Project Structure
- `app/src/static/index.html` — main web interface (Bootstrap, JS).
- `app/src/payloads.ts` — all attack categories and payloads.
- `app/src/index.ts` — server logic: request handling, payload sending, `/api/check` API.

## Extending Payloads
To add or modify payloads, edit the `app/src/payloads.ts` file. You can add new categories, payloads, and check types (in parameters, headers, as file).

---

The project requires Node.js and can be deployed as a Cloudflare Worker or on any server supporting the Fetch API.
