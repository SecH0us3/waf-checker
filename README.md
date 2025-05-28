# WAF Checker Python Cloudflare Worker

This project is a Python-based web service inspired by Cloudflare Workers. It allows users to test a target URL for WAF (Web Application Firewall) protection using a variety of attack payloads across multiple categories.

## Features
- Serves an `index.html` at `/` for user input.
- On submit, triggers a GET to `/api/check`.
- Tests the provided URL with grouped attack payloads (SQLi, XSS, Path Traversal, Command Injection, SSRF, NoSQLi, LFI) using GET/POST/PUT/DELETE.
- Returns an HTML summary with color-coded status codes:
  - 2xx/5xx: Red
  - 403: Green
  - Other 4xx: Orange
- Payloads are grouped by category for easy extension.

## Usage
1. Start the server: `python app.py`
2. Open your browser at `http://localhost:8000`
3. Enter the URL to test and submit.

## Extending Payloads
Edit the `PAYLOADS` dictionary in `app.py` to add or modify payloads by category.

---

This project requires Python 3.8+ and the `requests` and `fastapi` libraries.
