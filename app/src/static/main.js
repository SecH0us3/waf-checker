function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function getStatusClass(status, is_redirect) {
  const codeNum = parseInt(status, 10);
  if (!isNaN(codeNum) && (is_redirect || codeNum === 405)) return 'status-redirect';
  if (codeNum === 403) return 'status-green';
  if (!isNaN(codeNum) && ((codeNum >= 200 && codeNum < 300) || (codeNum >= 500 && codeNum < 600))) return 'status-red';
  if (!isNaN(codeNum) && codeNum >= 400 && codeNum < 500) return 'status-orange';
  return 'status-gray';
}

function renderSummary(results) {
  if (!results || !results.length) return '';
  const statusCounter = {};
  for (const r of results) statusCounter[r.status] = (statusCounter[r.status] || 0) + 1;
  const totalRequests = results.length;
  let html = `<div class='mb-3'>`;
  html += `<div class='d-flex align-items-center mb-1'><div style='min-width:90px;text-align:left;'><b>Total</b></div><div style='height:24px;width:100%;min-width:2px;line-height:24px;padding-left:8px;text-align:left;display:inline-block;border-radius:4px;background:#d5d6d7;color:#222;font-weight:bold;'>${totalRequests}</div></div>`;
  for (const code of Object.keys(statusCounter).sort()) {
    const percent = totalRequests ? (statusCounter[code] / totalRequests * 100) : 0;
    const status_class = getStatusClass(code, parseInt(code, 10) >= 300 && parseInt(code, 10) < 400);
    html += `<div class='d-flex align-items-center mb-1'><div style='min-width:90px;text-align:left;'><b>Status ${code}</b></div><div class='${status_class}' style='height:24px;width:${percent.toFixed(2)}%;min-width:2px;line-height:24px;padding-left:8px;text-align:left;display:inline-block;border-radius:4px;'>${statusCounter[code]}</div></div>`;
  }
  html += `</div>`;
  return html;
}

function renderReport(results) {
  if (!results || results.length === 0) return '';
  let html = `<h3>Results</h3>`;
  html += renderSummary(results);
  html += `<table border='1' cellpadding='5' class='w-100'><tr><th>Category</th><th>Method</th><th>Status</th><th>Payload</th></tr>`;
  for (const r of results) {
    const status_class = getStatusClass(r.status, r.is_redirect);
    html += `<tr><td>${r.category}</td><td>${r.method}</td><td class='${status_class}'>${r.status}</td><td><code>${escapeHtml(r.payload)}</code></td></tr>`;
  }
  html += `</table>`;
  return html;
}

// --- PAYLOAD CATEGORIES LOGIC ---
const PAYLOAD_CATEGORIES = [
  "SQL Injection",
  "XSS",
  "Path Traversal",
  "Command Injection",
  "SSRF",
  "NoSQL Injection",
  "Local File Inclusion",
  "LDAP Injection",
  "HTTP Request Smuggling",
  "Open Redirect",
  "Sensitive Files",
  "CRLF Injection",
  "UTF8/Unicode Bypass"
];

function renderCategoryCheckboxes() {
  const container = document.getElementById('categoryCheckboxes');
  if (!container) return;
  container.innerHTML = '';
  const defaultChecked = ["SQL Injection", "XSS"];
  PAYLOAD_CATEGORIES.forEach((cat, idx) => {
    const id = 'cat_' + idx;
    const div = document.createElement('div');
    div.className = 'form-check';
    div.innerHTML = `<input class="form-check-input" type="checkbox" value="${cat}" id="${id}"${defaultChecked.includes(cat) ? ' checked' : ''}>
      <label class="form-check-label" for="${id}">${cat}</label>`;
    container.appendChild(div);
  });
}

async function fetchResults() {
  const btn = document.getElementById('checkBtn');
  btn.disabled = true;
  const oldText = btn.textContent;
  btn.textContent = 'Wait...';
  const url = document.getElementById('url').value;
  // Collect selected methods
  const methodCheckboxes = document.querySelectorAll('#methodCheckboxes input[type=checkbox]');
  const selectedMethods = Array.from(methodCheckboxes).filter(cb => cb.checked).map(cb => cb.value);
  // Collect selected categories
  const categoryCheckboxes = document.querySelectorAll('#categoryCheckboxes input[type=checkbox]');
  const selectedCategories = Array.from(categoryCheckboxes).filter(cb => cb.checked).map(cb => cb.value);
  let page = 0;
  let allResults = [];
  try {
    while (true) {
      const resp = await fetch(`/api/check?url=${encodeURIComponent(url)}&methods=${encodeURIComponent(selectedMethods.join(','))}&categories=${encodeURIComponent(selectedCategories.join(','))}&page=${page}`);
      if (!resp.ok) break;
      const results = await resp.json();
      if (!results || !results.length) break;
      allResults = allResults.concat(results);
      page++;
    }
    document.getElementById('results').innerHTML = renderReport(allResults);
    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
  } finally {
    btn.disabled = false;
    btn.textContent = oldText;
  }
}

// Theme logic
function setTheme(theme) {
  document.body.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
  // Use unicode sun/moon for theme toggle
  document.getElementById('themeToggle').textContent = theme === 'dark' ? '\u2600' : '\u263E';
  // Adjust subtitle color for dark/light
  const subtitle = document.getElementById('subtitle');
  if (subtitle) {
    if (theme === 'dark') {
      subtitle.style.color = '#bfc6ce';
    } else {
      subtitle.style.color = '#6c757d';
    }
  }
  // Adjust input placeholder color for dark/light
  const urlInput = document.getElementById('url');
  urlInput.classList.toggle('dark-placeholder', theme === 'dark');
}
function getPreferredTheme() {
  const stored = localStorage.getItem('theme');
  if (stored) return stored;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
document.addEventListener('DOMContentLoaded', function() {
  setTheme(getPreferredTheme());
  document.getElementById('themeToggle').addEventListener('click', function() {
    const current = document.body.getAttribute('data-theme') || getPreferredTheme();
    setTheme(current === 'dark' ? 'light' : 'dark');
  });
  renderCategoryCheckboxes();
  // --- Кнопки select all/deselect all ---
  const selectAllBtn = document.getElementById('selectAllCategoriesBtn');
  const deselectAllBtn = document.getElementById('deselectAllCategoriesBtn');
  if (selectAllBtn) {
    selectAllBtn.addEventListener('click', function() {
      const checkboxes = document.querySelectorAll('#categoryCheckboxes input[type=checkbox]');
      checkboxes.forEach(cb => { cb.checked = true; });
    });
  }
  if (deselectAllBtn) {
    deselectAllBtn.addEventListener('click', function() {
      const checkboxes = document.querySelectorAll('#categoryCheckboxes input[type=checkbox]');
      checkboxes.forEach(cb => { cb.checked = false; });
    });
  }
});
