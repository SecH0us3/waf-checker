import { PAYLOADS, PayloadCategory } from './payloads';

// Вспомогательная функция для отправки запроса с нужным методом и payload
async function sendRequest(
  url: string, 
  method: string, 
  payload?: string, 
  headersObj?: Record<string, string>, 
  payloadTemplate?: string, 
  followRedirect: boolean = false
) {
  try {
    let resp: Response;
    const headers = headersObj ? new Headers(headersObj) : undefined;
    const redirectOption = followRedirect ? 'follow' : 'manual';
    switch (method) {
      case "GET":
      case "DELETE":
        resp = await fetch(payload !== undefined ? url + `?test=${encodeURIComponent(payload)}` : url, { method, redirect: redirectOption, headers });
        break;
      case "POST":
      case "PUT":
        if (payloadTemplate) {
          let jsonObj;
          try {
            jsonObj = JSON.parse(payloadTemplate);
            jsonObj = substitutePayload(jsonObj, payload ?? "");
          } catch {
            jsonObj = { test: payload ?? "" };
          }
          resp = await fetch(url, { method, redirect: redirectOption, body: JSON.stringify(jsonObj), headers: new Headers({ ...(headersObj || {}), 'Content-Type': 'application/json' }) });
        } else {
          resp = await fetch(url, { method, redirect: redirectOption, body: new URLSearchParams({ test: payload ?? "" }), headers });
        }
        break;
      default:
        return null;
    }

    console.log(`Request to ${url} with method ${method} and payload ${payload} and headers ${JSON.stringify(headersObj)} returned status ${resp.status}`);
    
    return {
      status: resp.status,
      is_redirect: resp.status >= 300 && resp.status < 400
    };
  } catch (e) {
    return { status: 'ERR', is_redirect: false };
  }
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
        return new Response(JSON.stringify([]), { headers: { "content-type": "application/json; charset=UTF-8" } });
      }
      const page = parseInt(urlObj.searchParams.get("page") || "0", 10);
      const methods = (urlObj.searchParams.get("methods") || "GET")
        .split(',').map(m => m.trim()).filter(Boolean);
      const categoriesParam = urlObj.searchParams.get("categories");
      let categories: string[] | undefined = undefined;
      if (categoriesParam) {
        categories = categoriesParam.split(',').map(c => c.trim()).filter(Boolean);
      }
      let payloadTemplate: string | undefined = undefined;
      let customHeaders: string | undefined = undefined;
      if (request.method === 'POST') {
        try {
          const body: any = await request.json();
          if (body && typeof body.payloadTemplate === 'string') {
            payloadTemplate = body.payloadTemplate;
          }
          if (body && typeof body.customHeaders === 'string') {
            customHeaders = body.customHeaders;
          }
        } catch (e) {
          console.error("Error parsing request body:", e);
        }
      }
      // Новый параметр followRedirect
      const followRedirect = urlObj.searchParams.get('followRedirect') === "1";
      // Новый параметр falsePositiveTest
      const falsePositiveTest = urlObj.searchParams.get('falsePositiveTest') === "1";
      // New parameter caseSensitiveTest
      const caseSensitiveTest = urlObj.searchParams.get('caseSensitiveTest') === "1";
      const results = await handleApiCheckFiltered(url, page, methods, categories, payloadTemplate, followRedirect, customHeaders, falsePositiveTest, caseSensitiveTest);
      return new Response(JSON.stringify(results), { headers: { "content-type": "application/json; charset=UTF-8" } });
    }
    return new Response("Not found", { status: 404 });
  }
};

async function handleApiCheckFiltered(
  url: string, 
  page: number, 
  methods: string[], 
  categories?: string[], 
  payloadTemplate?: string, 
  followRedirect: boolean = false,
  customHeaders?: string,
  falsePositiveTest: boolean = false,
  caseSensitiveTest: boolean = false // New parameter
): Promise<any[]> {
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

  // Case sensitive test: Modify URL hostname if flag is set
  let originalUrl = url; // Keep original for potential error logging or if modification fails
  let originalBaseUrl = baseUrl; // Keep original baseUrl

  if (caseSensitiveTest) {
      try {
          const u = new URL(url);
          const modifiedHostname = randomUppercase(u.hostname);
          // Reconstruct URL for ParamCheck/Header types
          url = `${u.protocol}//${modifiedHostname}${u.port ? `:${u.port}` : ''}${u.pathname}${u.search}${u.hash}`; // Modify the url variable
          baseUrl = `${u.protocol}//${modifiedHostname}${u.port ? `:${u.port}` : ''}`; // Modify the baseUrl variable
          console.log(`Case Sensitive Test: Modified URL hostname from ${originalUrl} to ${url}`);
      } catch (e) {
          console.error(`Case Sensitive Test: Could not parse URL "${originalUrl}" for hostname modification`, e);
          // Fallback: uppercase the whole URL and baseUrl string if parsing fails
          url = randomUppercase(url);
          baseUrl = randomUppercase(baseUrl);
          console.log(`Case Sensitive Test: Fallback - modified URL from ${originalUrl} to ${url}`);
      }
  }


  const payloadEntries = categories && categories.length
    ? Object.entries(PAYLOADS).filter(([cat]) => categories.includes(cat))
    : Object.entries(PAYLOADS);
  for (const [category, info] of payloadEntries) {
    const checkType = info.type || "ParamCheck";
    const payloads = falsePositiveTest ? (info.falsePayloads || []) : (info.payloads || []);
    if (checkType === "ParamCheck") {
      for (let payload of payloads) { // Use let so we can reassign
        if (caseSensitiveTest) {
             payload = randomUppercase(payload); // Modify payload
        }
        for (const method of METHODS) {
          if (offset >= end) return results;
          if (offset >= start) {
            // Process custom headers if provided
            const headersObj = customHeaders ? processCustomHeaders(customHeaders, payload) : undefined;
            const res = await sendRequest(url, method, payload, headersObj, payloadTemplate, followRedirect);
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
      for (let payload of payloads) { // Use let so we can reassign
        if (caseSensitiveTest) {
             payload = randomUppercase(payload); // Modify payload
        }
        if (offset >= end) return results;
        if (offset >= start) {
          // Use potentially modified baseUrl for the base, and modified payload for the file path
          const fileUrl = baseUrl.replace(/\/$/, '') + '/' + payload.replace(/^\//, '');
          // Process custom headers if provided
          const headersObj = customHeaders ? processCustomHeaders(customHeaders, payload) : undefined;
          const res = await sendRequest(fileUrl, "GET", undefined, headersObj, undefined, followRedirect);
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
    } else if (checkType === "Header") {
      for (let payload of payloads) { // Use let so we can reassign
        if (caseSensitiveTest) {
             payload = randomUppercase(payload); // Modify payload
        }
        // Create headers from payload (potentially modified)
        const headersObj: Record<string, string> = {};
        for (const line of payload.split(/\r?\n/)) { // Use the potentially modified payload here
          const idx = line.indexOf(":");
          if (idx > 0) {
            const name = line.slice(0, idx).trim();
            const value = line.slice(idx + 1).trim();
            headersObj[name] = value;
          }
        }
        
        // Add custom headers if provided
        if (customHeaders) {
          const customHeadersObj = processCustomHeaders(customHeaders, payload);
          // Merge headers (custom headers override payload headers if same name)
          Object.assign(headersObj, customHeadersObj);
        }
        
        for (const method of METHODS) {
          if (offset >= end) return results;
          if (offset >= start) {
            const res = await sendRequest(url, method, undefined, headersObj, payloadTemplate, followRedirect);
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
    }
  }
  return results;
}

// Helper function to parse and process custom headers
function processCustomHeaders(customHeadersStr: string, payload?: string): Record<string, string> {
  const headersObj: Record<string, string> = {};
  if (!customHeadersStr || !customHeadersStr.trim()) return headersObj;
  
  for (const line of customHeadersStr.split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      const name = line.slice(0, idx).trim();
      let value = line.slice(idx + 1).trim();
      // Replace payload placeholder in headers if payload provided
      if (payload && value.includes('{{$$}}')) {
        value = value.replace(/\{\{\$\$\}\}/g, payload);
      }
      headersObj[name] = value;
    }
  }
  return headersObj;
}

// Рекурсивная функция для замены всех вхождений "{{$$}}" на payload
function substitutePayload(obj: any, payload: string): any {
  if (typeof obj === 'string') {
    return obj.includes('{{$$}}') ? obj.replace(/\{\{\$\$\}\}/g, payload) : obj;
  } else if (Array.isArray(obj)) {
    return obj.map(item => substitutePayload(item, payload));
  } else if (typeof obj === 'object' && obj !== null) {
    const res: any = {};
    for (const [k, v] of Object.entries(obj)) {
      res[k] = substitutePayload(v, payload);
    }
    return res;
  }
  return obj;
}

// Helper function to randomly uppercase two characters in a string
function randomUppercase(str: string): string {
  if (!str) return str;

  const letters = str.split('');
  const alphabetRegex = /[a-zA-Z]/;
  const letterIndices: number[] = [];

  for (let i = 0; i < letters.length; i++) {
    if (alphabetRegex.test(letters[i])) {
      letterIndices.push(i);
    }
  }

  if (letterIndices.length < 1) {
      // If no letters, return original string
      return str;
  } else if (letterIndices.length === 1) {
      // If only one letter, uppercase that one
      const indexToUppercase = letterIndices[0];
      letters[indexToUppercase] = letters[indexToUppercase].toUpperCase();
  } else {
      // If two or more letters, pick two random distinct indices
      const index1 = letterIndices[Math.floor(Math.random() * letterIndices.length)];
      let index2;
      do {
          index2 = letterIndices[Math.floor(Math.random() * letterIndices.length)];
      } while (index2 === index1); // Ensure distinct indices

      letters[index1] = letters[index1].toUpperCase();
      letters[index2] = letters[index2].toUpperCase();
  }


  return letters.join('');
}
