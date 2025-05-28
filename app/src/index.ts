import { PAYLOADS, PayloadCategory } from './payloads';

/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

function escapeHtml(str: string): string {
  // Standard HTML escape (no DOM, safe for Workers)
  return str.replace(/[&<>'"`=\\/]/g, (s) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;',
    '`': '&#96;',
    '=': '&#61;',
    '/': '&#47;'
  } as Record<string, string>)[s] || '');
}

async function handleApiCheck(url: string): Promise<any[]> {
  const METHODS = ["GET"];
  const results: any[] = [];
  let baseUrl: string;
  try {
    const u = new URL(url);
    baseUrl = `${u.protocol}//${u.host}`;
  } catch {
    baseUrl = url;
  }
  for (const [category, info] of Object.entries(PAYLOADS)) {
    const checkType = info.type || "ParamCheck";
    const payloads = info.payloads || [];
    if (checkType === "ParamCheck") {
      for (const payload of payloads) {
        for (const method of METHODS) {
          try {
            let resp: Response;
            if (method === "GET") {
              resp = await fetch(url + `?test=${encodeURIComponent(payload)}`, { method });
            } else if (method === "POST" || method === "PUT") {
              resp = await fetch(url, { method, body: new URLSearchParams({ test: payload }) });
            } else if (method === "DELETE") {
              resp = await fetch(url + `?test=${encodeURIComponent(payload)}`, { method });
            } else {
              continue;
            }
            results.push({
              category,
              payload,
              method,
              status: resp.status,
              is_redirect: resp.status >= 300 && resp.status < 400
            });
          } catch (e) {
            console.error(`Error for ${method} ${url} payload:`, payload, e);
            results.push({ category, payload, method, status: 'ERR', is_redirect: false });
          }
        }
      }
    } else if (checkType === "FileCheck") {
      for (const payload of payloads) {
        const fileUrl = baseUrl.replace(/\/$/, '') + '/' + payload.replace(/^\//, '');
        try {
          const resp = await fetch(fileUrl);
          results.push({
            category,
            payload,
            method: 'GET',
            status: resp.status,
            is_redirect: resp.status >= 300 && resp.status < 400
          });
        } catch (e) {
          console.error(`Error for FileCheck ${fileUrl}:`, e);
          results.push({ category, payload, method: 'GET', status: 'ERR', is_redirect: false });
        }
      }
    }
  }
  return results;
}

function renderReport(results: any[]): string {
  const statusCounter: Record<string, number> = {};
  for (const r of results) statusCounter[r.status] = (statusCounter[r.status] || 0) + 1;
  const totalRequests = results.length;
  let summaryHtml = `<div class='mb-3'>`;
  summaryHtml += `<div class='d-flex align-items-center mb-1'><div style='min-width:90px;text-align:left;'><b>Total</b></div><div style='height:24px;width:100%;min-width:2px;line-height:24px;padding-left:8px;text-align:left;display:inline-block;border-radius:4px;background:#d5d6d7;color:#222;font-weight:bold;'>${totalRequests}</div></div>`;
  for (const code of Object.keys(statusCounter).sort()) {
    let status_class = '';
    const codeNum = parseInt(code, 10);
    if (!isNaN(codeNum) && codeNum >= 300 && codeNum < 400) status_class = 'status-redirect';
    else if (codeNum === 403) status_class = 'status-green';
    else if (!isNaN(codeNum) && ((codeNum >= 200 && codeNum < 300) || (codeNum >= 500 && codeNum < 600))) status_class = 'status-red';
    else if (!isNaN(codeNum) && codeNum >= 400 && codeNum < 500) status_class = 'status-orange';
    else status_class = 'status-gray';
    const percent = totalRequests ? (statusCounter[code] / totalRequests * 100) : 0;
    summaryHtml += `<div class='d-flex align-items-center mb-1'><div style='min-width:90px;text-align:left;'><b>Status ${code}</b></div><div class='${status_class}' style='height:24px;width:${percent.toFixed(2)}%;min-width:2px;line-height:24px;padding-left:8px;text-align:left;display:inline-block;border-radius:4px;'>${statusCounter[code]}</div></div>`;
  }
  summaryHtml += `</div>`;
  let html = `<h3>Results</h3>${summaryHtml}<table border='1' cellpadding='5' class='w-100'><tr><th>Category</th><th>Method</th><th>Status</th><th>Payload</th></tr>`;
  for (const r of results) {
    let status_class = '';
    const codeNum = parseInt(r.status, 10);
    if (!isNaN(codeNum) && r.is_redirect) status_class = 'status-redirect';
    else if (codeNum === 403) status_class = 'status-green';
    else if (!isNaN(codeNum) && ((codeNum >= 200 && codeNum < 300) || (codeNum >= 500 && codeNum < 600))) status_class = 'status-red';
    else if (!isNaN(codeNum) && codeNum >= 400 && codeNum < 500) status_class = 'status-orange';
    else status_class = 'status-gray';
    html += `<tr><td>${r.category}</td><td>${r.method}</td><td class='${status_class}'>${r.status}</td><td><code>${escapeHtml(r.payload)}</code></td></tr>`;
  }
  html += `</table>`;
  return html;
}

let INDEX_HTML = "";

export default {
  async fetch(request: Request): Promise<Response> {
    const urlObj = new URL(request.url);
    if (urlObj.pathname === "/") {
      if (INDEX_HTML !== undefined) {
        // Node.js: serve loaded HTML
        return new Response(INDEX_HTML, { headers: { "content-type": "text/html; charset=UTF-8" } });
      } else {
        // Worker: fetch static asset
        const htmlResp = await fetch('index.html');
        return new Response(await htmlResp.text(), { headers: { "content-type": "text/html; charset=UTF-8" } });
      }
    }
    if (urlObj.pathname === "/api/check") {
      const url = urlObj.searchParams.get("url");
      if (!url) return new Response("Missing url param", { status: 400 });
      const results = await handleApiCheck(url);
      return new Response(renderReport(results), { headers: { "content-type": "text/html; charset=UTF-8" } });
    }
    return new Response("Not found", { status: 404 });
  }
};
