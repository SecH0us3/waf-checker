function escapeHtml(str) {
	const div = document.createElement('div');
	div.textContent = str;
	return div.innerHTML;
}

function getStatusClass(status, is_redirect, falsePositiveMode = false) {
	const codeNum = parseInt(status, 10);
	if (!isNaN(codeNum) && (is_redirect || codeNum === 405)) return 'status-redirect';

	if (falsePositiveMode) {
		// In false positive mode: 200 = good (green), 403 = bad (red)
		if (!isNaN(codeNum) && ((codeNum >= 200 && codeNum < 300) || (codeNum >= 500 && codeNum < 600))) return 'status-green';
		if (codeNum === 403) return 'status-red';
	} else {
		// Normal mode: 403 = good (green), 200 = bad (red)
		if (codeNum === 403) return 'status-green';
		if (!isNaN(codeNum) && ((codeNum >= 200 && codeNum < 300) || (codeNum >= 500 && codeNum < 600))) return 'status-red';
	}

	if (!isNaN(codeNum) && codeNum >= 400 && codeNum < 500) return 'status-orange';
	return 'status-gray';
}

function renderSummary(results, falsePositiveMode = false) {
	if (!results || !results.length) return '';
	const statusCounter = {};
	for (const r of results) statusCounter[r.status] = (statusCounter[r.status] || 0) + 1;
	const totalRequests = results.length;
	let html = `<div class='mb-3'>`;
	html += `<div class='d-flex align-items-left mb-1'><div class='min-width-112'><label><input type='checkbox' id='statusSelectAll' checked class='checkbox-align'> <b>Total</b></label></div><div class='status-bar status-bar-total'>${totalRequests}</div></div>`;
	for (const code of Object.keys(statusCounter).sort()) {
		const percent = totalRequests ? (statusCounter[code] / totalRequests) * 100 : 0;
		const status_class = getStatusClass(code, parseInt(code, 10) >= 300 && parseInt(code, 10) < 400, falsePositiveMode);
		html += `<div class='d-flex align-items-left mb-1'><div class='min-width-112'><label><input type='checkbox' class='status-filter-checkbox checkbox-align' data-status='${code}' checked> <b>Status ${code}</b></label></div><div class='status-bar ${status_class}' style='width:${percent.toFixed(2)}%;'>${statusCounter[code]}</div></div>`;
	}
	html += `</div>`;
	return html;
}

function renderReport(results, falsePositiveMode = false) {
	if (!results || results.length === 0) return '';
	let html = `<h3>Results${falsePositiveMode ? ' (False Positive Test)' : ''}</h3>`;

	// Add visual indicator for test mode
	if (falsePositiveMode) {
		html += `<div class="false-positive-indicator mb-3">
      <strong>🔍 False Positive Test Mode <span class="help-icon" onclick="toggleHelp('fp-help')" title="What is False Positive Test?">ℹ️</span></strong>
      <div id="fp-help" class="help-content" style="display: none;">
        <small><em>False Positive Test checks if your WAF incorrectly blocks legitimate traffic. This helps ensure your security doesn't interfere with normal users.</em></small>
      </div>
      <small>
        <span style="color: #198754">200 = WAF correctly allows legitimate requests</span>
        <span style="color: #dc3545">403 = WAF incorrectly blocks legitimate requests</span>
      </small>
    </div>`;
	} else {
		html += `<div class="normal-test-indicator mb-3">
      <strong>🛡️ Security Test Mode <span class="help-icon" onclick="toggleHelp('security-help')" title="What is Security Test?">ℹ️</span></strong>
      <div id="security-help" class="help-content" style="display: none;">
        <small><em>Security Test checks if your WAF properly blocks malicious attack payloads. This helps verify your application is protected against common web attacks.</em></small>
      </div>
      <small>
        <span style="color: #dc3545">200 = WAF did not protect your application</span>
        <span style="color: #198754">403 = WAF protected your application</span>
      </small>
    </div>`;
	}

	html += renderSummary(results, falsePositiveMode);
	html += `<table border='1' cellpadding='5' class='w-100' id='resultsTable'><tr><th>Category</th><th>Method</th><th>Status</th><th>Payload</th></tr>`;
	for (const r of results) {
		const status_class = getStatusClass(r.status, r.is_redirect, falsePositiveMode);
		let codeClass = '';
		if (falsePositiveMode) {
			codeClass = r.status == 200 || r.status == '200' ? ' payload-green' : '';
		} else {
			codeClass = r.status == 403 || r.status == '403' ? ' payload-green' : '';
		}
		html +=
			`<tr data-status='${r.status}'>` +
			`<td>${r.category}</td>` +
			`<td class='text-center'>${r.method}</td>` +
			`<td class='${status_class} text-center'>${r.status}</td>` +
			`<td><code class='${codeClass}'>${escapeHtml(r.payload)}</code></td>` +
			`</tr>`;
	}
	html += `</table>`;
	setTimeout(() => {
		filterResultsTableByStatus();
		const all = document.querySelectorAll('.status-filter-checkbox');
		const checkedCount = Array.from(all).filter((cb) => cb.checked).length;
		const selectAll = document.getElementById('statusSelectAll');
		if (selectAll) {
			selectAll.checked = checkedCount === all.length;
		}
	}, 0);
	return html;
}

// --- PAYLOAD CATEGORIES LOGIC ---
const PAYLOAD_CATEGORIES = [
	'SQL Injection',
	'XSS',
	'Path Traversal',
	'Command Injection',
	'SSRF',
	'NoSQL Injection',
	'Local File Inclusion',
	'LDAP Injection',
	'HTTP Request Smuggling',
	'Open Redirect',
	'Sensitive Files',
	'CRLF Injection',
	'UTF8/Unicode Bypass',
	'XXE',
	'SSTI',
	'HTTP Parameter Pollution',
	'Web Cache Poisoning',
	'IP Bypass',
	'User-Agent',
];

function renderCategoryCheckboxes() {
	const container = document.getElementById('categoryCheckboxes');
	if (!container) return;
	container.innerHTML = '';
	const defaultChecked = ['SQL Injection', 'XSS'];
	PAYLOAD_CATEGORIES.forEach((cat, idx) => {
		const id = 'cat_' + idx;
		const div = document.createElement('div');
		div.className = 'form-check';
		div.innerHTML = `<input class="form-check-input" type="checkbox" value="${cat}" id="${id}"${defaultChecked.includes(cat) ? ' checked' : ''}>
      <label class="form-check-label" for="${id}">${cat}</label>`;
		container.appendChild(div);
	});
}

function highlightCategoryCheckboxesByResults(results, falsePositiveMode = false) {
	// В режиме false positive: выделяем категории где есть 403 (плохо)
	// В обычном режиме: выделяем категории где есть 200 (плохо)
	const categoriesWithBadStatus = new Set();
	if (Array.isArray(results)) {
		results.forEach((r) => {
			if (falsePositiveMode) {
				if (r.status === 403 || r.status === '403') {
					categoriesWithBadStatus.add(r.category);
				}
			} else {
				if (r.status === 200 || r.status === '200') {
					categoriesWithBadStatus.add(r.category);
				}
			}
		});
	}
	// Пробегаем по чекбоксам и выделяем нужные label
	const categoryCheckboxes = document.querySelectorAll('#categoryCheckboxes input[type=checkbox]');
	categoryCheckboxes.forEach((cb) => {
		const label = cb.parentElement.querySelector('.form-check-label');
		if (!label) return;
		if (categoriesWithBadStatus.has(cb.value)) {
			label.classList.add('category-label-danger');
		} else {
			label.classList.remove('category-label-danger');
		}
	});
}

// --- Toggle payload template section within Additional Settings ---
function updatePayloadTemplateSection() {
	const methodPOST = document.getElementById('methodPOST');
	const methodPUT = document.getElementById('methodPUT');
	const section = document.getElementById('payloadTemplateSection');
	if (!section) return;
	if ((methodPOST && methodPOST.checked) || (methodPUT && methodPUT.checked)) {
		section.style.display = '';
	} else {
		section.style.display = 'none';
	}
}

// --- Toggle More Settings panel ---
function toggleMoreSettings() {
	const panel = document.getElementById('moreSettingsPanel');
	const button = document.getElementById('moreSettingsToggle');
	if (!panel || !button) return;

	const isVisible = panel.style.display !== 'none';
	if (isVisible) {
		// Start closing animation
		panel.style.maxHeight = panel.scrollHeight + 'px';
		panel.offsetHeight; // Force reflow
		panel.style.maxHeight = '0';
		panel.style.opacity = '0';
		panel.style.transform = 'translateY(-10px)';

		setTimeout(() => {
			panel.style.display = 'none';
		}, 300);

		button.innerHTML = '⚙️';
		localStorage.setItem('wafchecker_moreSettingsExpanded', 'false');
	} else {
		// Start opening animation
		panel.style.display = '';
		panel.style.maxHeight = '0';
		panel.style.opacity = '0';
		panel.style.transform = 'translateY(-10px)';

		panel.offsetHeight; // Force reflow
		panel.style.maxHeight = panel.scrollHeight + 'px';
		panel.style.opacity = '1';
		panel.style.transform = 'translateY(0)';

		// Clean up after animation
		setTimeout(() => {
			panel.style.maxHeight = '';
		}, 300);

		button.innerHTML = '⚙️';
		localStorage.setItem('wafchecker_moreSettingsExpanded', 'true');
	}
}

// Update description text based on false positive test mode
function updateDescriptionText() {
	const description = document.querySelector('.description-waf-check');
	if (description) {
		description.innerHTML = `This project helps you check how well your Web Application Firewall (WAF) protects your product against common web attacks.`;
	}
}

async function fetchResults() {
	const btn = document.getElementById('checkBtn');
	btn.disabled = true;
	const oldText = btn.textContent;
	btn.textContent = 'Wait...';
	const url = document.getElementById('url').value;
	// Collect selected methods — ТОЛЬКО из .http-methods!
	const methodCheckboxes = document.querySelectorAll('.http-methods input[type=checkbox]');
	const selectedMethods = Array.from(methodCheckboxes)
		.filter((cb) => cb.checked)
		.map((cb) => cb.value);
	// Follow redirect
	const followRedirect = document.getElementById('followRedirect')?.checked ? true : false;
	// False positive test
	const falsePositiveTest = document.getElementById('falsePositiveTest')?.checked ? true : false;
	// Case sensitive test
	const caseSensitiveTest = document.getElementById('caseSensitiveTest')?.checked ? true : false;
	// Collect selected categories
	const categoryCheckboxes = document.querySelectorAll('#categoryCheckboxes input[type=checkbox]');
	const selectedCategories = Array.from(categoryCheckboxes)
		.filter((cb) => cb.checked)
		.map((cb) => cb.value);
	// --- Сохраняем в localStorage ---
	localStorage.setItem('wafchecker_url', url);
	localStorage.setItem('wafchecker_methods', JSON.stringify(selectedMethods));
	localStorage.setItem('wafchecker_categories', JSON.stringify(selectedCategories));
	localStorage.setItem('wafchecker_followRedirect', followRedirect ? '1' : '0');
	localStorage.setItem('wafchecker_falsePositiveTest', falsePositiveTest ? '1' : '0');
	localStorage.setItem('wafchecker_caseSensitiveTest', caseSensitiveTest ? '1' : '0');
	// --- Получаем шаблон и заголовки ---\n
	let payloadTemplate = '';
	const templateEl = document.getElementById('payloadTemplate');
	if (templateEl) {
		payloadTemplate = templateEl.value;
		localStorage.setItem('wafchecker_payloadTemplate', payloadTemplate);
	}

	let customHeaders = '';
	const headersEl = document.getElementById('customHeaders');
	if (headersEl) {
		customHeaders = headersEl.value;
		localStorage.setItem('wafchecker_customHeaders', customHeaders);
	}
	let page = 0;
	let allResults = [];
	try {
		while (true) {
			const params = new URLSearchParams({
				url,
				methods: selectedMethods.join(','),
				categories: selectedCategories.join(','),
				page: page,
				followRedirect: followRedirect ? '1' : '0',
				falsePositiveTest: falsePositiveTest ? '1' : '0',
				caseSensitiveTest: caseSensitiveTest ? '1' : '0',
			});
			const resp = await fetch(`/api/check?${params.toString()}`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ payloadTemplate, customHeaders }),
			});
			if (!resp.ok) break;
			const results = await resp.json();
			if (!results || !results.length) break;
			allResults = allResults.concat(results);
			page++;
		}
		document.getElementById('results').innerHTML = renderReport(allResults, falsePositiveTest);
		document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
		highlightCategoryCheckboxesByResults(allResults, falsePositiveTest);
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
			const methodCheckboxes = document.querySelectorAll('.http-methods input[type=checkbox]');
			methodCheckboxes.forEach((cb) => {
				cb.checked = arr.includes(cb.value);
			});
		} catch {}
	}
	// Follow redirect
	const followRedirect = localStorage.getItem('wafchecker_followRedirect');
	if (followRedirect !== null) {
		const el = document.getElementById('followRedirect');
		if (el) el.checked = !!parseInt(followRedirect, 10);
	}

	// False positive test
	const falsePositiveTest = localStorage.getItem('wafchecker_falsePositiveTest');
	if (falsePositiveTest !== null) {
		const el = document.getElementById('falsePositiveTest');
		if (el) {
			el.checked = !!parseInt(falsePositiveTest, 10);
		}
	}

	// Categories
	const categories = localStorage.getItem('wafchecker_categories');
	if (categories) {
		try {
			const arr = JSON.parse(categories);
			const categoryCheckboxes = document.querySelectorAll('#categoryCheckboxes input[type=checkbox]');
			categoryCheckboxes.forEach((cb) => {
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

	// Custom headers
	const customHeaders = localStorage.getItem('wafchecker_customHeaders');
	if (customHeaders) {
		const headersEl = document.getElementById('customHeaders');
		if (headersEl) headersEl.value = customHeaders;
	}

	// More Settings panel state
	const moreSettingsExpanded = localStorage.getItem('wafchecker_moreSettingsExpanded');
	if (moreSettingsExpanded === 'true') {
		const panel = document.getElementById('moreSettingsPanel');
		const button = document.getElementById('moreSettingsToggle');
		if (panel && button) {
			panel.style.display = '';
			panel.style.maxHeight = '';
			panel.style.opacity = '1';
			panel.style.transform = 'translateY(0)';
			button.innerHTML = '⚙️';
		}
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
document.addEventListener('DOMContentLoaded', function () {
	setTheme(getPreferredTheme());
	document.getElementById('themeToggle').addEventListener('click', function () {
		const current = document.body.getAttribute('data-theme') || getPreferredTheme();
		setTheme(current === 'dark' ? 'light' : 'dark');
	});
	renderCategoryCheckboxes();
	// --- Кнопки select all/deselect all ---
	const selectAllBtn = document.getElementById('selectAllCategoriesBtn');
	const deselectAllBtn = document.getElementById('deselectAllCategoriesBtn');
	if (selectAllBtn) {
		selectAllBtn.addEventListener('click', function () {
			const checkboxes = document.querySelectorAll('#categoryCheckboxes input[type=checkbox]');
			checkboxes.forEach((cb) => {
				cb.checked = true;
			});
		});
	}
	if (deselectAllBtn) {
		deselectAllBtn.addEventListener('click', function () {
			const checkboxes = document.querySelectorAll('#categoryCheckboxes input[type=checkbox]');
			checkboxes.forEach((cb) => {
				cb.checked = false;
			});
		});
	}
	// --- Enter в поле URL ---
	const urlInput = document.getElementById('url');
	if (urlInput) {
		urlInput.addEventListener('keydown', function (e) {
			if (e.key === 'Enter') {
				e.preventDefault();
				fetchResults();
			}
		});
	}
	// --- Восстановить состояние ---
	restoreStateFromLocalStorage();

	// Update description based on false positive test state
	updateDescriptionText();
	// --- Toggle payload template section on method change ---
	const methodCheckboxes = document.querySelectorAll('#methodCheckboxes input[type=checkbox]');
	methodCheckboxes.forEach((cb) => {
		cb.addEventListener('change', updatePayloadTemplateSection);
	});
	updatePayloadTemplateSection();
	// Делегированный обработчик на #results
	const resultsDiv = document.getElementById('results');
	if (resultsDiv) {
		resultsDiv.addEventListener('change', function (e) {
			const target = e.target;
			// Select all statuses
			if (target && target.id === 'statusSelectAll') {
				const checked = target.checked;
				document.querySelectorAll('.status-filter-checkbox').forEach((cb) => {
					cb.checked = checked;
				});
				filterResultsTableByStatus();
			}
			// Обычные чекбоксы статусов
			if (target && target.classList.contains('status-filter-checkbox')) {
				// Если хотя бы один снят — select all снимается, если все включены — включается
				const all = document.querySelectorAll('.status-filter-checkbox');
				const checkedCount = Array.from(all).filter((cb) => cb.checked).length;
				const selectAll = document.getElementById('statusSelectAll');
				if (selectAll) {
					selectAll.checked = checkedCount === all.length;
				}
				filterResultsTableByStatus();
			}
		});
	}
});

// Function to toggle help content
function toggleHelp(helpId) {
	const helpElement = document.getElementById(helpId);
	if (helpElement) {
		helpElement.style.display = helpElement.style.display === 'none' ? 'block' : 'none';
	}
}

function filterResultsTableByStatus() {
	const checkedStatuses = Array.from(document.querySelectorAll('.status-filter-checkbox:checked')).map((cb) =>
		cb.getAttribute('data-status'),
	);
	const rows = document.querySelectorAll('#resultsTable tr[data-status]');
	rows.forEach((row) => {
		if (checkedStatuses.includes(row.getAttribute('data-status'))) {
			row.style.display = '';
		} else {
			row.style.display = 'none';
		}
	});
}
