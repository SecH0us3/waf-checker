from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import httpx
import asyncio
import os
import html as html_lib
from payloads import PAYLOADS
from report import render_report

app = FastAPI()

METHODS = ["GET", "POST", "PUT", "DELETE"]

@app.get("/", response_class=HTMLResponse)
async def index():
    with open(os.path.join(os.path.dirname(__file__), "index.html"), encoding="utf-8") as f:
        return f.read()

@app.get("/api/check", response_class=HTMLResponse)
async def check(request: Request, url: str):
    results = []
    from urllib.parse import urlparse
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else url
    async with httpx.AsyncClient(follow_redirects=False, timeout=10, verify=False) as client:
        for category, info in PAYLOADS.items():
            check_type = info.get("type", "ParamCheck")
            payloads = info.get("payloads", [])
            if check_type == "ParamCheck":
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
            elif check_type == "FileCheck":
                for payload in payloads:
                    file_url = base_url.rstrip("/") + "/" + payload.lstrip("/")
                    try:
                        r = await client.get(file_url)
                        is_redirect = 300 <= r.status_code < 400
                        results.append({
                            "category": category,
                            "payload": payload,
                            "method": "GET",
                            "status": r.status_code,
                            "is_redirect": is_redirect
                        })
                    except Exception as e:
                        results.append({
                            "category": category,
                            "payload": payload,
                            "method": "GET",
                            "status": "ERR",
                            "is_redirect": False
                        })
    return render_report(results)
