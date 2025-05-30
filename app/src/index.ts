import { PAYLOADS, PayloadCategory } from './payloads';

// Вспомогательная функция для отправки запроса с нужным методом и payload
async function sendRequest(url: string, method: string, payload?: string) {
  try {
    let resp: Response;
    switch (method) {
      case "GET":
      case "DELETE":
        resp = await fetch(payload !== undefined ? url + `?test=${encodeURIComponent(payload)}` : url, { method, redirect: 'manual' });
        break;
      case "POST":
      case "PUT":
        resp = await fetch(url, { method, redirect: 'manual', body: new URLSearchParams({ test: payload ?? "" }) });
        break;
      default:
        return null;
    }

    console.log(`Request to ${url} with method ${method} and payload ${payload} returned status ${resp.status}`);
    
    return {
      status: resp.status,
      is_redirect: resp.status >= 300 && resp.status < 400
    };
  } catch (e) {
    return { status: 'ERR', is_redirect: false };
  }
}

async function handleApiCheck(url: string, page: number, methods: string[]): Promise<any[]> {
  const METHODS = methods && methods.length ? methods : ["GET"];
  const results: any[] = [];
  let baseUrl: string;
  const limit = 50;
  const start = page * limit;
  const end = start + limit;
  let offset = 0;
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
          if (offset >= start) {
            const res = await sendRequest(url, method, payload);
            results.push({
              category,
              payload,
              method,
              status: res ? res.status : 'ERR',
              is_redirect: res ? res.is_redirect : false
            });
          }
          offset++;
        }
      }
    } else if (checkType === "FileCheck") {
      for (const payload of payloads) {
        if (offset >= end) return results;
        if (offset >= start) {
          const fileUrl = baseUrl.replace(/\/$/, '') + '/' + payload.replace(/^\//, '');
          const res = await sendRequest(fileUrl, "GET");
          results.push({
            category,
            payload,
            method: 'GET',
            status: res ? res.status : 'ERR',
            is_redirect: res ? res.is_redirect : false
          });
        }
        offset++;
      }
    }
  }
  return results;
}

// Лучше сразу загрузить index.html при старте (если возможно)
let INDEX_HTML = "";

export default {
  async fetch(request: Request): Promise<Response> {
    const urlObj = new URL(request.url);
    if (urlObj.pathname === "/") {
      return new Response(INDEX_HTML, { headers: { "content-type": "text/html; charset=UTF-8" } });
    }
    if (urlObj.pathname === "/api/check") {
      const url = urlObj.searchParams.get("url");
      if (!url) return new Response("Missing url param", { status: 400 });
      if (url.includes('secmy')) {
        // Если параметр url содержит 'secmy', немедленно вернуть пустой массив
        return new Response(JSON.stringify([]), { headers: { "content-type": "application/json; charset=UTF-8" } });
      }
      const page = parseInt(urlObj.searchParams.get("page") || "0", 10);
      const methods = (urlObj.searchParams.get("methods") || "GET")
        .split(',').map(m => m.trim()).filter(Boolean);
      const results = await handleApiCheck(url, page, methods);
      return new Response(JSON.stringify(results), { headers: { "content-type": "application/json; charset=UTF-8" } });
    }
    return new Response("Not found", { status: 404 });
  }
};
