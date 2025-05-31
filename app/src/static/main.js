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
  html += `<div class='d-flex align-items-left mb-1'><div style='min-width:112px;'><label><input type='checkbox' id='statusSelectAll' checked style='margin-right:4px;vertical-align:middle;'> <b>Total</b></label></div><div style='height:24px;width:100%;min-width:2px;line-height:24px;padding-left:8px;display:inline-block;border-radius:4px;background:#d5d6d7;color:#222;font-weight:bold;'>${totalRequests}</div></div>`;
  for (const code of Object.keys(statusCounter).sort()) {
    const percent = totalRequests ? (statusCounter[code] / totalRequests * 100) : 0;
    const status_class = getStatusClass(code, parseInt(code, 10) >= 300 && parseInt(code, 10) < 400);
    html += `<div class='d-flex align-items-left mb-1'><div style='min-width:112px;'><label><input type='checkbox' class='status-filter-checkbox' data-status='${code}' checked style='margin-right:4px;vertical-align:middle;'> <b>Status ${code}</b></label></div><div class='${status_class}' style='height:24px;width:${percent.toFixed(2)}%;min-width:2px;line-height:24px;padding-left:8px;display:inline-block;border-radius:4px;'>${statusCounter[code]}</div></div>`;
  }
  html += `</div>`;
  return html;
}

function renderReport(results) {
  if (!results || results.length === 0) return '';
  let html = `<h3>Results</h3>`;
  html += renderSummary(results);
  html += `<table border='1' cellpadding='5' class='w-100' id='resultsTable'><tr><th>Category</th><th>Method</th><th>Status</th><th>Payload</th></tr>`;
  for (const r of results) {
    const status_class = getStatusClass(r.status, r.is_redirect);
    html += `<tr data-status='${r.status}'><td>${r.category}</td><td>${r.method}</td><td class='${status_class}'>${r.status}</td><td><code>${escapeHtml(r.payload)}</code></td></tr>`;
  }
  html += `</table>`;
  setTimeout(() => {
    filterResultsTableByStatus();
    const all = document.querySelectorAll('.status-filter-checkbox');
    const checkedCount = Array.from(all).filter(cb => cb.checked).length;
    const selectAll = document.getElementById('statusSelectAll');
    if (selectAll) {
      selectAll.checked = checkedCount === all.length;
    }
  }, 0);
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
  "UTF8/Unicode Bypass",
  "XXE",
  "SSTI",
  "HTTP Parameter Pollution",
  "Web Cache Poisoning",
  "IP Bypass",
  "User-Agent"
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

function highlightCategoryCheckboxesByResults(results) {
  // Собираем категории, где есть хотя бы один статус 200
  const categoriesWith200 = new Set();
  if (Array.isArray(results)) {
    results.forEach(r => {
      if (r.status === 200 || r.status === '200') {
        categoriesWith200.add(r.category);
      }
    });
  }
  // Пробегаем по чекбоксам и выделяем нужные label
  const categoryCheckboxes = document.querySelectorAll('#categoryCheckboxes input[type=checkbox]');
  categoryCheckboxes.forEach(cb => {
    const label = cb.parentElement.querySelector('.form-check-label');
    if (!label) return;
    if (categoriesWith200.has(cb.value)) {
      label.classList.add('category-label-danger');
    } else {
      label.classList.remove('category-label-danger');
    }
  });
}

// --- Toggle payload template panel ---
function updatePayloadTemplatePanel() {
  const methodPOST = document.getElementById('methodPOST');
  const methodPUT = document.getElementById('methodPUT');
  const panel = document.getElementById('payloadTemplatePanel');
  if (!panel) return;
  if ((methodPOST && methodPOST.checked) || (methodPUT && methodPUT.checked)) {
    panel.style.display = '';
  } else {
    panel.style.display = 'none';
  }
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
  // --- Сохраняем в localStorage ---
  localStorage.setItem('wafchecker_url', url);
  localStorage.setItem('wafchecker_methods', JSON.stringify(selectedMethods));
  localStorage.setItem('wafchecker_categories', JSON.stringify(selectedCategories));
  // --- Получаем шаблон ---
  let payloadTemplate = '';
  const templateEl = document.getElementById('payloadTemplate');
  if (templateEl) {
    payloadTemplate = templateEl.value;
    localStorage.setItem('wafchecker_payloadTemplate', payloadTemplate);
  }
  let page = 0;
  let allResults = [];
  try {
    while (true) {
      const resp = await fetch(`/api/check?url=${encodeURIComponent(url)}&methods=${encodeURIComponent(selectedMethods.join(','))}&categories=${encodeURIComponent(selectedCategories.join(','))}&page=${page}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payloadTemplate })
      });
      if (!resp.ok) break;
      const results = await resp.json();
      if (!results || !results.length) break;
      allResults = allResults.concat(results);
      page++;
    }
    document.getElementById('results').innerHTML = renderReport(allResults);
    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
    highlightCategoryCheckboxesByResults(allResults);
  } finally {
    btn.disabled = false;
    btn.textContent = oldText;
  }
}

function restoreStateFromLocalStorage() {
  // URL
  const url = localStorage.getItem('wafchecker_url');
  if (url) {
    const urlInput = document.getElementById('url');
    if (urlInput) urlInput.value = url;
  }
  // Methods
  const methods = localStorage.getItem('wafchecker_methods');
  if (methods) {
    try {
      const arr = JSON.parse(methods);
      const methodCheckboxes = document.querySelectorAll('#methodCheckboxes input[type=checkbox]');
      methodCheckboxes.forEach(cb => {
        cb.checked = arr.includes(cb.value);
      });
    } catch {}
  }
  // Categories
  const categories = localStorage.getItem('wafchecker_categories');
  if (categories) {
    try {
      const arr = JSON.parse(categories);
      const categoryCheckboxes = document.querySelectorAll('#categoryCheckboxes input[type=checkbox]');
      categoryCheckboxes.forEach(cb => {
        cb.checked = arr.includes(cb.value);
      });
    } catch {}
  }
  // Payload template
  const payloadTemplate = localStorage.getItem('wafchecker_payloadTemplate');
  if (payloadTemplate) {
    const templateEl = document.getElementById('payloadTemplate');
    if (templateEl) templateEl.value = payloadTemplate;
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
  // --- Enter в поле URL ---
  const urlInput = document.getElementById('url');
  if (urlInput) {
    urlInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        fetchResults();
      }
    });
  }
  // --- Восстановить состояние ---
  restoreStateFromLocalStorage();
  // --- Toggle payload template panel on method change ---
  const methodCheckboxes = document.querySelectorAll('#methodCheckboxes input[type=checkbox]');
  methodCheckboxes.forEach(cb => {
    cb.addEventListener('change', updatePayloadTemplatePanel);
  });
  updatePayloadTemplatePanel();
  // Делегированный обработчик на #results
  const resultsDiv = document.getElementById('results');
  if (resultsDiv) {
    resultsDiv.addEventListener('change', function(e) {
      const target = e.target;
      // Select all statuses
      if (target && target.id === 'statusSelectAll') {
        const checked = target.checked;
        document.querySelectorAll('.status-filter-checkbox').forEach(cb => {
          cb.checked = checked;
        });
        filterResultsTableByStatus();
      }
      // Обычные чекбоксы статусов
      if (target && target.classList.contains('status-filter-checkbox')) {
        // Если хотя бы один снят — select all снимается, если все включены — включается
        const all = document.querySelectorAll('.status-filter-checkbox');
        const checkedCount = Array.from(all).filter(cb => cb.checked).length;
        const selectAll = document.getElementById('statusSelectAll');
        if (selectAll) {
          selectAll.checked = checkedCount === all.length;
        }
        filterResultsTableByStatus();
      }
    });
  }
});

function filterResultsTableByStatus() {
  const checkedStatuses = Array.from(document.querySelectorAll('.status-filter-checkbox:checked')).map(cb => cb.getAttribute('data-status'));
  const rows = document.querySelectorAll('#resultsTable tr[data-status]');
  rows.forEach(row => {
    if (checkedStatuses.includes(row.getAttribute('data-status'))) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
}
