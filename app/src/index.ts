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

async function handleApiCheck(url: string, page: number): Promise<any[]> {
  const METHODS = ["GET", "POST", "PUT", "DELETE"];
  const results: any[] = [];
  let baseUrl: string;
  let offset = 0;
  const limit = 50;
  const start = page * limit;
  const end = start + limit;
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
          if (offset >= end) return results;
          if (offset >= start && offset < end) {
            try {
              let resp: Response;
              if (method === "GET") {
                resp = await fetch(url + `?test=${encodeURIComponent(payload)}`, { method, redirect: 'manual' });
              } else if (method === "POST" || method === "PUT") {
                resp = await fetch(url, { method, redirect: 'manual', body: new URLSearchParams({ test: payload }) });
              } else if (method === "DELETE") {
                resp = await fetch(url + `?test=${encodeURIComponent(payload)}`, { method, redirect: 'manual' });
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
          offset++;
        }
      }
    } else if (checkType === "FileCheck") {
      for (const payload of payloads) {
        if (offset >= end) return results;
        if (offset >= start && offset < end) {
          const fileUrl = baseUrl.replace(/\/$/, '') + '/' + payload.replace(/^\//, '');
          console.log(`Checking FileCheck URL: ${fileUrl}`);
          try {
            const resp = await fetch(fileUrl, { redirect: 'manual' });
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
        offset++;
      }
    }
  }
  return results;
}

let INDEX_HTML = "";

export default {
  async fetch(request: Request): Promise<Response> {
    const urlObj = new URL(request.url);
    if (urlObj.pathname === "/") {
      if (INDEX_HTML !== undefined) {
        return new Response(INDEX_HTML, { headers: { "content-type": "text/html; charset=UTF-8" } });
      } else {
        const htmlResp = await fetch('index.html');
        return new Response(await htmlResp.text(), { headers: { "content-type": "text/html; charset=UTF-8" } });
      }
    }
    if (urlObj.pathname === "/api/check") {
      const url = urlObj.searchParams.get("url");
      const page = parseInt(urlObj.searchParams.get("page") || "1", 10);
      if (!url) return new Response("Missing url param", { status: 400 });
      const results = await handleApiCheck(url, page);
      return new Response(JSON.stringify(results), { headers: { "content-type": "application/json; charset=UTF-8" } });
    }
    return new Response("Not found", { status: 404 });
  }
};