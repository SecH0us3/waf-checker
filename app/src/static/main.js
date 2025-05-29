function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
function renderReport(results) {
  if (!results || results.length === 0) return '';
  const statusCounter = {};
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
  let html = `<h3>Results</h3>`;
  html += `${summaryHtml}<table border='1' cellpadding='5' class='w-100'><tr><th>Category</th><th>Method</th><th>Status</th><th>Payload</th></tr>`;
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
async function fetchResults() {
    const btn = document.getElementById('checkBtn');
    btn.disabled = true;
    const oldText = btn.textContent;
    btn.textContent = 'Wait...';
    const url = document.getElementById('url').value;
    // Collect selected methods
    const methodCheckboxes = document.querySelectorAll('#methodCheckboxes input[type=checkbox]');
    const selectedMethods = Array.from(methodCheckboxes).filter(cb => cb.checked).map(cb => cb.value);
    let page = 0;
    let allResults = [];
    try {
        while (true) {
            const resp = await fetch(`/api/check?url=${encodeURIComponent(url)}&methods=${encodeURIComponent(selectedMethods.join(','))}&page=${page}`);
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
  if (urlInput) {
    if (theme === 'dark') {
      urlInput.style.setProperty('color', '#f8f9fa');
      urlInput.style.setProperty('background-color', '#181a1b');
      urlInput.style.setProperty('caret-color', '#f8f9fa');
      urlInput.classList.add('dark-placeholder');
    } else {
      urlInput.style.setProperty('color', '#212529');
      urlInput.style.setProperty('background-color', '#f8f9fa');
      urlInput.style.setProperty('caret-color', '#212529');
      urlInput.classList.remove('dark-placeholder');
    }
  }
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
});
