from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import httpx
import asyncio
import os
import html as html_lib
from payloads import PAYLOADS

app = FastAPI()

METHODS = ["GET", "POST", "PUT", "DELETE"]

@app.get("/", response_class=HTMLResponse)
async def index():
    with open(os.path.join(os.path.dirname(__file__), "index.html"), encoding="utf-8") as f:
        return f.read()

@app.get("/api/check", response_class=HTMLResponse)
async def check(request: Request, url: str):
    results = []
    async with httpx.AsyncClient(follow_redirects=False, timeout=10, verify=False) as client:
        for category, payloads in PAYLOADS.items():
            for payload in payloads:
                for method in METHODS:
                    try:
                        if method == "GET":
                            r = await client.get(url, params={"test": payload})
                        elif method == "POST":
                            r = await client.post(url, data={"test": payload})
                        elif method == "PUT":
                            r = await client.put(url, data={"test": payload})
                        elif method == "DELETE":
                            r = await client.delete(url, params={"test": payload})
                        is_redirect = 300 <= r.status_code < 400
                        results.append({
                            "category": category,
                            "payload": payload,
                            "method": method,
                            "status": r.status_code,
                            "is_redirect": is_redirect
                        })
                    except Exception as e:
                        results.append({
                            "category": category,
                            "payload": payload,
                            "method": method,
                            "status": "ERR",
                            "is_redirect": False
                        })
    # Render HTML summary
    html = "<h3>Results</h3><table border='1' cellpadding='5'><tr><th>Category</th><th>Method</th><th>Status</th><th>Payload</th></tr>"
    for r in results:
        color = ""
        if r["is_redirect"]:
            color = "#4CAF50"  # green for redirect
        elif r["status"] == 403:
            color = "#4CAF50"  # green
        elif isinstance(r["status"], int) and (200 <= r["status"] < 300 or 500 <= r["status"] < 600):
            color = "#F44336"  # red
        elif isinstance(r["status"], int) and 400 <= r["status"] < 500:
            color = "#FF9800"  # orange
        else:
            color = "#BDBDBD"  # gray
        html_payload = html_lib.escape(r['payload'])
        html += f"<tr><td>{r['category']}</td><td>{r['method']}</td><td style='background:{color};'>{r['status']}</td><td><code>{html_payload}</code></td></tr>"
    html += "</table>"
    return html
