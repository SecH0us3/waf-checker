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
	let html = '';

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

	// Add WAF detection info if available
	if (results.length > 0 && results[0].wafDetected) {
		html += `<div class="alert alert-info mb-3">
			<strong>🛡️ WAF Detected:</strong> ${results[0].wafType}
			<small class="text-muted"> (Auto-detection enabled)</small>
		</div>`;
	}

	html += renderSummary(results, falsePositiveMode);
	html += `<table border='1' cellpadding='5' class='w-100' id='resultsTable'><tr><th>Category</th><th>Method</th><th>Status</th><th>Response Time</th><th>Payload</th></tr>`;
	for (const r of results) {
		const status_class = getStatusClass(r.status, r.is_redirect, falsePositiveMode);
		let codeClass = '';
		if (falsePositiveMode) {
			codeClass = r.status == 200 || r.status == '200' ? ' payload-green' : '';
		} else {
			codeClass = r.status == 403 || r.status == '403' ? ' payload-green' : '';
		}
		const responseTime = r.responseTime || 0;
		html +=
			`<tr data-status='${r.status}'>` +
			`<td>${r.category}</td>` +
			`<td class='text-center'>${r.method}</td>` +
			`<td class='${status_class} text-center'>${r.status}</td>` +
			`<td class='text-center'>${responseTime}ms</td>` +
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

	// Create test session
	const sessionId = `session_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
	const startTime = new Date().toISOString();

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
	// Enhanced payloads
	const enhancedPayloads = document.getElementById('enhancedPayloads')?.checked ? true : false;
	// Use advanced WAF bypass payloads
	const useAdvancedPayloads = document.getElementById('useAdvancedPayloadsCheckbox')?.checked ? true : false;
	// Auto detect WAF
	const autoDetectWAF = document.getElementById('autoDetectWAF')?.checked ? true : false;
	// Use encoding variations
	const useEncodingVariations = document.getElementById('useEncodingVariations')?.checked ? true : false;
	// HTTP Manipulation
	const httpManipulation = document.getElementById('httpManipulation')?.checked ? true : false;
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
	localStorage.setItem('wafchecker_enhancedPayloads', enhancedPayloads ? '1' : '0');
	localStorage.setItem('wafchecker_useAdvancedPayloads', useAdvancedPayloads ? '1' : '0');
	localStorage.setItem('wafchecker_autoDetectWAF', autoDetectWAF ? '1' : '0');
	localStorage.setItem('wafchecker_useEncodingVariations', useEncodingVariations ? '1' : '0');
	localStorage.setItem('wafchecker_httpManipulation', httpManipulation ? '1' : '0');
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
	let detectedWAFType = window.detectedWAF || null;
	let wafDetection = null;

	// Auto-detect WAF first if enabled
	if (autoDetectWAF && !detectedWAFType) {
		try {
			const wafResponse = await fetch(`/api/waf-detect?url=${encodeURIComponent(url)}`);
			if (wafResponse.ok) {
				const wafData = await wafResponse.json();
				if (wafData.detection && wafData.detection.detected) {
					detectedWAFType = wafData.detection.wafType;
					window.detectedWAF = detectedWAFType;
					wafDetection = wafData.detection;
					showWAFPanel(wafData);
				}
			}
		} catch (error) {
			console.warn('WAF detection failed, continuing with regular test:', error);
		}
	}

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
				enhancedPayloads: enhancedPayloads ? '1' : '0',
				useAdvancedPayloads: useAdvancedPayloads ? '1' : '0',
				autoDetectWAF: autoDetectWAF ? '1' : '0',
				useEncodingVariations: useEncodingVariations ? '1' : '0',
				httpManipulation: httpManipulation ? '1' : '0',
				detectedWAF: detectedWAFType || '',
			});
			const resp = await fetch(`/api/check?${params.toString()}`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					payloadTemplate,
					customHeaders,
					detectedWAF: detectedWAFType,
				}),
			});
			if (!resp.ok) break;
			const results = await resp.json();
			if (!results || !results.length) break;
			allResults = allResults.concat(results);
			page++;
		}

		const endTime = new Date().toISOString();

		// Create test session object
		currentTestSession = {
			id: sessionId,
			url,
			startTime,
			endTime,
			totalTests: allResults.length,
			results: allResults,
			wafDetection,
			settings: {
				methods: selectedMethods,
				categories: selectedCategories,
				followRedirect,
				falsePositiveTest,
				caseSensitiveTest,
				enhancedPayloads,
				useAdvancedPayloads,
				autoDetectWAF,
				useEncodingVariations,
				httpManipulation,
			},
		};

		document.getElementById('results').innerHTML = renderReport(allResults, falsePositiveTest);
		document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
		highlightCategoryCheckboxesByResults(allResults, falsePositiveTest);

		// Show export controls
		showExportControls();

		// Hide description text
		const descEl = document.querySelector('.description-waf-check');
		if (descEl) descEl.style.display = 'none';
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
		} catch { }
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

	// Case sensitive test
	const caseSensitiveTest = localStorage.getItem('wafchecker_caseSensitiveTest');
	if (caseSensitiveTest !== null) {
		const el = document.getElementById('caseSensitiveTest');
		if (el) {
			el.checked = caseSensitiveTest === '1';
		}
	}

	// Enhanced payloads
	const enhancedPayloads = localStorage.getItem('wafchecker_enhancedPayloads');
	if (enhancedPayloads !== null) {
		const el = document.getElementById('enhancedPayloads');
		if (el) {
			el.checked = enhancedPayloads === '1';
		}
	}

	// Auto detect WAF
	const autoDetectWAF = localStorage.getItem('wafchecker_autoDetectWAF');
	if (autoDetectWAF !== null) {
		const el = document.getElementById('autoDetectWAF');
		if (el) {
			el.checked = autoDetectWAF === '1';
		}
	}

	// HTTP Manipulation
	const httpManipulation = localStorage.getItem('wafchecker_httpManipulation');
	if (httpManipulation !== null) {
		const el = document.getElementById('httpManipulation');
		if (el) {
			el.checked = httpManipulation === '1';
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
		} catch { }
	}
	// Payload template
	const payloadTemplate = localStorage.getItem('wafchecker_payloadTemplate');
	if (payloadTemplate) {
		const templateEl = document.getElementById('payloadTemplate');
		if (templateEl) {
			// Auto-fix legacy placeholder {{$$}} to {PAYLOAD}
			if (payloadTemplate.includes('{{$$}}')) {
				templateEl.value = payloadTemplate.replace(/\{\{\$\$\}\}/g, '{PAYLOAD}');
				localStorage.setItem('wafchecker_payloadTemplate', templateEl.value);
			} else {
				templateEl.value = payloadTemplate;
			}
		}
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

// WAF Detection functionality
async function detectWAF() {
	const btn = document.getElementById('detectWafBtn');
	const url = document.getElementById('url').value;

	if (!url) {
		alert('Please enter a URL first');
		return;
	}

	btn.disabled = true;
	const oldText = btn.textContent;
	btn.textContent = 'Detecting...';

	try {
		const response = await fetch(`/api/waf-detect?url=${encodeURIComponent(url)}`);
		const data = await response.json();

		if (response.ok) {
			displayWAFDetectionResults(data);
			showWAFPanel(data);
		} else {
			alert(`WAF Detection failed: ${data.error || 'Unknown error'}`);
		}
	} catch (error) {
		console.error('WAF Detection error:', error);
		alert('WAF Detection failed. Please check the console for details.');
	} finally {
		btn.disabled = false;
		btn.textContent = oldText;
	}
}

function displayWAFDetectionResults(data) {
	const resultsDiv = document.getElementById('results');
	let html = '<div class="card mb-4"><div class="card-header"><h3>🛡️ WAF Detection Results</h3></div><div class="card-body">';

	// Detection results
	if (data.detection && data.detection.detected) {
		html += `<div class="alert alert-success mb-3">
			<h5><strong>WAF Detected: ${data.detection.wafType}</strong></h5>
			<p><strong>Confidence:</strong> ${data.detection.confidence}%</p>
		</div>`;

		if (data.detection.evidence && data.detection.evidence.length > 0) {
			html += '<h6>Evidence:</h6><ul>';
			data.detection.evidence.forEach((evidence) => {
				html += `<li><code>${escapeHtml(evidence)}</code></li>`;
			});
			html += '</ul>';
		}

		if (data.detection.suggestedBypassTechniques && data.detection.suggestedBypassTechniques.length > 0) {
			html += '<h6>Suggested Bypass Techniques:</h6><ul>';
			data.detection.suggestedBypassTechniques.forEach((technique) => {
				html += `<li>${escapeHtml(technique)}</li>`;
			});
			html += '</ul>';
		}
	} else {
		html += '<div class="alert alert-warning">No WAF detected or low confidence detection.</div>';
	}

	// Bypass opportunities
	if (data.bypassOpportunities) {
		html += '<h6>Detected Bypass Opportunities:</h6>';
		html += '<div class="row">';

		const opportunities = [
			{ key: 'httpMethodsBypass', label: 'HTTP Method Bypass', icon: '🔄' },
			{ key: 'headerBypass', label: 'Header Bypass', icon: '📋' },
			{ key: 'encodingBypass', label: 'Encoding Bypass', icon: '🔤' },
			{ key: 'parameterPollution', label: 'Parameter Pollution', icon: '🔀' },
		];

		opportunities.forEach((opp) => {
			const status = data.bypassOpportunities[opp.key];
			const badgeClass = status ? 'bg-success' : 'bg-secondary';
			const statusText = status ? 'Possible' : 'Not detected';

			html += `<div class="col-6 mb-2">
				<span class="badge ${badgeClass}">${opp.icon} ${opp.label}: ${statusText}</span>
			</div>`;
		});

		html += '</div>';
	}

	html += `<div class="mt-3">
		<button class="btn btn-primary btn-sm" onclick="useAdvancedPayloads()">Use Advanced Payloads</button>
		<button class="btn btn-outline-secondary btn-sm" onclick="clearWAFResults()">Clear</button>
	</div>`;

	html += '</div></div>';
	resultsDiv.innerHTML = html + resultsDiv.innerHTML;
}

function showWAFPanel(data) {
	const panel = document.getElementById('wafDetectionPanel');
	const resultsDiv = document.getElementById('wafDetectionResults');

	if (!panel || !resultsDiv) return;

	let html = '';

	if (data.detection && data.detection.detected) {
		html = `<div class="d-flex align-items-center justify-content-between">
			<div>
				<strong>${data.detection.wafType}</strong> detected
				<span class="badge bg-success ms-2">${data.detection.confidence}% confidence</span>
			</div>
			<small class="text-muted">Auto-detection enabled</small>
		</div>`;

		// Store detected WAF info for later use
		window.detectedWAF = data.detection.wafType;

		// Auto-enable advanced payloads if WAF detected
		const advancedCheckbox = document.getElementById('useAdvancedPayloadsCheckbox');
		if (advancedCheckbox) {
			advancedCheckbox.checked = true;
		}
	} else {
		html = '<div>No WAF detected with high confidence</div>';
		window.detectedWAF = null;
	}

	resultsDiv.innerHTML = html;
	panel.style.display = 'block';
}

function hideWAFPanel() {
	const panel = document.getElementById('wafDetectionPanel');
	if (panel) {
		panel.style.display = 'none';
	}
}

function useAdvancedPayloads() {
	const checkbox = document.getElementById('useAdvancedPayloadsCheckbox');
	const encodingCheckbox = document.getElementById('useEncodingVariations');

	if (checkbox) checkbox.checked = true;
	if (encodingCheckbox) encodingCheckbox.checked = true;

	alert('Advanced payloads enabled! Run the test to see WAF-specific bypass techniques.');
}

function clearWAFResults() {
	const resultsDiv = document.getElementById('results');
	const wafCards = resultsDiv.querySelectorAll('.card:has(.card-header h3:contains("WAF Detection"))');
	wafCards.forEach((card) => card.remove());

	hideWAFPanel();
	window.detectedWAF = null;
}


// HTTP Manipulation Testing functionality
async function testHTTPManipulation() {
	const btn = document.getElementById('httpManipulationBtn');
	const url = document.getElementById('url').value;

	if (!url) {
		alert('Please enter a URL first');
		return;
	}

	btn.disabled = true;
	const oldText = btn.textContent;
	btn.textContent = 'Testing...';

	try {
		const response = await fetch(`/api/http-manipulation?url=${encodeURIComponent(url)}`);
		const data = await response.json();

		if (response.ok) {
			displayHTTPManipulationResults(data);
		} else {
			alert(`HTTP Manipulation test failed: ${data.error || 'Unknown error'}`);
		}
	} catch (error) {
		console.error('HTTP Manipulation test error:', error);
		alert('HTTP Manipulation test failed. Please check the console for details.');
	} finally {
		btn.disabled = false;
		btn.textContent = oldText;
	}
}

function displayHTTPManipulationResults(data) {
	const resultsDiv = document.getElementById('results');
	let html = '<div class="card mb-4"><div class="card-header"><h3>🔄 HTTP Manipulation Test Results</h3></div><div class="card-body">';

	// Summary
	html += `<div class="alert alert-info">
		<p><strong>Total Techniques:</strong> ${data.total_techniques || 'N/A'}</p>
		<p><strong>Tested:</strong> ${data.tested_techniques || 'N/A'}</p>
		<p><strong>Results:</strong> ${data.results ? data.results.length : 0}</p>
	</div>`;

	// Results table
	if (data.results && data.results.length > 0) {
		html += '<div class="table-responsive">';
		html += '<table class="table table-sm"><thead><tr><th>Technique</th><th>Method</th><th>Details</th><th>Status</th><th>Result</th></tr></thead><tbody>';

		data.results.forEach((result) => {
			const statusClass = getStatusClass(result.status, result.is_redirect);

			// Determine result based on status code
			let resultText, resultBadge;
			const st = typeof result.status === 'number' ? result.status : 0;
			if (result.status === 'ERR') {
				resultText = '❌ Connection Error';
				resultBadge = 'badge bg-danger';
			} else if (st >= 200 && st < 300) {
				resultText = '⚠️ Potential Bypass';
				resultBadge = 'badge bg-warning text-dark';
			} else if (st >= 500) {
				resultText = '⚠️ Server Error';
				resultBadge = 'badge bg-warning text-dark';
			} else if (st === 403) {
				resultText = '🛡️ Blocked by WAF';
				resultBadge = 'badge bg-success';
			} else if (st >= 300 && st < 400) {
				resultText = '↩️ Redirect';
				resultBadge = 'badge bg-info';
			} else {
				resultText = '🚫 Rejected';
				resultBadge = 'badge bg-secondary';
			}

			html += `<tr>
				<td>${result.technique || 'Unknown'}</td>
				<td class="text-center">${result.method}</td>
				<td><small class="text-muted">${result.description || ''}</small></td>
				<td class="text-center"><span class="badge ${statusClass}">${result.status}</span></td>
				<td><span class="${resultBadge}">${resultText}</span></td>
			</tr>`;
		});

		html += '</tbody></table></div>';
	} else {
		html += '<div class="alert alert-info">No HTTP manipulation tests performed.</div>';
	}

	html += '</div></div>';
	resultsDiv.innerHTML = html + resultsDiv.innerHTML;
}

// Initialize application
function initApp() {
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
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', initApp);

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

// Global variables for test session and batch testing
let currentTestSession = null;
let currentBatchJob = null;
let batchPollInterval = null;

// Enhanced reporting and analytics functions
function showExportControls() {
	const exportControls = document.getElementById('exportControls');
	if (exportControls && currentTestSession) {
		exportControls.style.display = 'block';
	}
}

function hideExportControls() {
	const exportControls = document.getElementById('exportControls');
	if (exportControls) {
		exportControls.style.display = 'none';
	}
}

function exportResults(format) {
	if (!currentTestSession) {
		alert('No test results to export');
		return;
	}

	const includeAnalysis = document.getElementById('includeAnalysis')?.checked || true;

	try {
		switch (format) {
			case 'json':
				exportAsJSON(currentTestSession, includeAnalysis);
				break;
			case 'csv':
				exportAsCSV(currentTestSession.results);
				break;
			case 'pdf':
				exportAsHTMLReport(currentTestSession);
				break;
			default:
				alert('Unknown export format');
		}
	} catch (error) {
		console.error('Export failed:', error);
		alert('Export failed. Please check the console for details.');
	}
}

function exportAsJSON(session, includeAnalysis) {
	const exportData = {
		...session,
		exportedAt: new Date().toISOString(),
		version: '1.0.0',
	};

	if (includeAnalysis) {
		const vulnerabilityScores = generateVulnerabilityScores(session.results, session.settings.falsePositiveTest);
		const executiveSummary = generateExecutiveSummary(session.results, vulnerabilityScores, session.wafDetection);

		exportData.analysis = {
			vulnerabilityScores,
			executiveSummary,
		};
	}

	const content = JSON.stringify(exportData, null, 2);
	const filename = generateFilename(session.url, 'json');
	downloadFile(content, filename, 'application/json');
}

function exportAsCSV(results) {
	if (results.length === 0) {
		alert('No results to export');
		return;
	}

	const headers = [
		'Category',
		'Method',
		'Status',
		'Response Time (ms)',
		'Payload',
		'Is Redirect',
		'WAF Detected',
		'WAF Type',
		'Timestamp',
		'URL',
	];

	const csvRows = [
		headers.join(','),
		...results.map((result) =>
			[
				`"${result.category}"`,
				`"${result.method}"`,
				result.status,
				result.responseTime || 0,
				`"${result.payload.replace(/"/g, '""')}"`,
				result.is_redirect || false,
				result.wafDetected || false,
				`"${result.wafType || ''}"`,
				`"${result.timestamp || ''}"`,
				`"${result.url || ''}"`,
			].join(','),
		),
	];

	const content = csvRows.join('\n');
	const filename = generateFilename(currentTestSession?.url || 'results', 'csv');
	downloadFile(content, filename, 'text/csv');
}

function exportAsHTMLReport(session) {
	const vulnerabilityScores = generateVulnerabilityScores(session.results, session.settings.falsePositiveTest);
	const executiveSummary = generateExecutiveSummary(session.results, vulnerabilityScores, session.wafDetection);

	const html = generateHTMLReport(session, vulnerabilityScores, executiveSummary);
	const filename = generateFilename(session.url, 'html');
	downloadFile(html, filename, 'text/html');


}

function generateHTMLReport(session, vulnerabilityScores, executiveSummary) {
	const getRiskColor = (risk) => {
		switch (risk) {
			case 'Critical':
				return '#dc3545';
			case 'High':
				return '#fd7e14';
			case 'Medium':
				return '#ffc107';
			case 'Low':
				return '#198754';
			default:
				return '#6c757d';
		}
	};

	return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>WAF Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; color: #333; }
        .header { text-align: center; margin-bottom: 40px; border-bottom: 2px solid #007bff; padding-bottom: 20px; }
        .summary-card { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .risk-badge { padding: 4px 12px; border-radius: 4px; color: white; font-weight: bold; }
        .metric { display: inline-block; margin: 10px 20px; text-align: center; }
        .metric-value { font-size: 2em; font-weight: bold; color: #007bff; }
        .metric-label { font-size: 0.9em; color: #666; }
        .vulnerability-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .vulnerability-table th, .vulnerability-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .vulnerability-table th { background-color: #f8f9fa; font-weight: bold; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #198754; font-weight: bold; }
        .recommendations { background: #e7f3ff; padding: 20px; border-left: 4px solid #007bff; }
        .results-table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
        .results-table th, .results-table td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        .results-table th { background-color: #f8f9fa; }
        .status-200 { background-color: #f8d7da; }
        .status-403 { background-color: #d1e7dd; }
        .status-other { background-color: #fff3cd; }
        .page-break { page-break-before: always; }
        @media print { .page-break { page-break-before: always; } }
    </style>
</head>
<body>
    <div class="header">
        <h1>WAF Security Assessment Report</h1>
        <p><strong>Target URL:</strong> ${session.url}</p>
        <p><strong>Test Date:</strong> ${new Date(session.startTime).toLocaleString()}</p>
        <p><strong>Duration:</strong> ${Math.round((new Date(session.endTime).getTime() - new Date(session.startTime).getTime()) / 1000)}s</p>
    </div>

    <div class="summary-card">
        <h2>Executive Summary</h2>
        <div style="text-align: center; margin: 20px 0;">
            <span class="risk-badge" style="background-color: ${getRiskColor(executiveSummary.riskLevel)}">
                ${executiveSummary.riskLevel} Risk Level
            </span>
        </div>

        <div style="text-align: center;">
            <div class="metric">
                <div class="metric-value">${executiveSummary.overallScore}</div>
                <div class="metric-label">Security Score</div>
            </div>
            <div class="metric">
                <div class="metric-value">${executiveSummary.wafEffectiveness}%</div>
                <div class="metric-label">WAF Effectiveness</div>
            </div>
            <div class="metric">
                <div class="metric-value">${executiveSummary.bypassedTests}</div>
                <div class="metric-label">Bypassed Tests</div>
            </div>
            <div class="metric">
                <div class="metric-value">${executiveSummary.totalTests}</div>
                <div class="metric-label">Total Tests</div>
            </div>
        </div>
    </div>

    ${session.wafDetection?.detected
			? `
    <div class="summary-card">
        <h3>WAF Detection Results</h3>
        <p><strong>Detected WAF:</strong> ${session.wafDetection.wafType}</p>
        <p><strong>Confidence:</strong> ${session.wafDetection.confidence}%</p>
    </div>
    `
			: ''
		}

    <div class="summary-card">
        <h3>Vulnerability Assessment</h3>
        <table class="vulnerability-table">
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Score</th>
                    <th>Bypass Rate</th>
                    <th>Tests (Bypassed/Total)</th>
                </tr>
            </thead>
            <tbody>
                ${vulnerabilityScores
			.map(
				(vuln) => `
                <tr>
                    <td>${vuln.category}</td>
                    <td class="severity-${vuln.severity.toLowerCase()}">${vuln.severity}</td>
                    <td>${vuln.score}/100</td>
                    <td>${vuln.bypassRate}%</td>
                    <td>${vuln.bypassedCount}/${vuln.totalCount}</td>
                </tr>
                `,
			)
			.join('')}
            </tbody>
        </table>
    </div>

    <div class="recommendations">
        <h3>Recommendations</h3>
        <ol>
            ${executiveSummary.recommendations.map((rec) => `<li>${rec}</li>`).join('')}
        </ol>
    </div>

    <p style="margin-top: 40px; text-align: center; color: #666; font-size: 0.9em;">
        Generated by WAF Checker on ${new Date().toLocaleString()}
    </p>
</body>
</html>
    `;
}

function generateVulnerabilityScores(results, falsePositiveMode = false) {
	const categoryStats = new Map();

	results.forEach((result) => {
		const category = result.category;
		const stats = categoryStats.get(category) || { total: 0, bypassed: 0 };
		stats.total++;

		const isBypassed = falsePositiveMode
			? result.status === 403 || result.status === '403'
			: result.status === 200 || result.status === '200';

		if (isBypassed) {
			stats.bypassed++;
		}

		categoryStats.set(category, stats);
	});

	const scores = [];
	categoryStats.forEach((stats, category) => {
		const bypassRate = stats.total > 0 ? (stats.bypassed / stats.total) * 100 : 0;

		let severity, score;
		if (bypassRate >= 75) {
			severity = 'Critical';
			score = 90 + ((bypassRate - 75) / 25) * 10;
		} else if (bypassRate >= 50) {
			severity = 'High';
			score = 70 + ((bypassRate - 50) / 25) * 20;
		} else if (bypassRate >= 25) {
			severity = 'Medium';
			score = 40 + ((bypassRate - 25) / 25) * 30;
		} else {
			severity = 'Low';
			score = (bypassRate / 25) * 40;
		}

		scores.push({
			category,
			severity,
			score: Math.round(score),
			bypassedCount: stats.bypassed,
			totalCount: stats.total,
			bypassRate: Math.round(bypassRate * 100) / 100,
		});
	});

	return scores.sort((a, b) => b.score - a.score);
}

function generateExecutiveSummary(results, vulnerabilityScores, wafDetection) {
	const totalTests = results.length;
	const bypassedTests = results.filter((r) => r.status === 200 || r.status === '200' || r.status === 500 || r.status === '500').length;
	const bypassRate = totalTests > 0 ? (bypassedTests / totalTests) * 100 : 0;
	const wafEffectiveness = Math.max(0, 100 - bypassRate);

	const criticalVulnerabilities = vulnerabilityScores.filter((v) => v.severity === 'Critical').length;
	const highVulnerabilities = vulnerabilityScores.filter((v) => v.severity === 'High').length;
	const mediumVulnerabilities = vulnerabilityScores.filter((v) => v.severity === 'Medium').length;
	const lowVulnerabilities = vulnerabilityScores.filter((v) => v.severity === 'Low').length;

	let riskLevel, overallScore;
	if (criticalVulnerabilities > 0 || bypassRate > 75) {
		riskLevel = 'Critical';
		overallScore = 10;
	} else if (highVulnerabilities > 0 || bypassRate > 50) {
		riskLevel = 'High';
		overallScore = 30;
	} else if (mediumVulnerabilities > 0 || bypassRate > 25) {
		riskLevel = 'Medium';
		overallScore = 60;
	} else {
		riskLevel = 'Low';
		overallScore = 90;
	}

	const recommendations = [];
	if (criticalVulnerabilities > 0) {
		recommendations.push('Immediately review and update WAF rules for critical vulnerabilities');
	}
	if (bypassRate > 50) {
		recommendations.push('WAF configuration needs significant improvement');
	}
	if (!wafDetection?.detected) {
		recommendations.push('Consider implementing a Web Application Firewall');
	}

	vulnerabilityScores.slice(0, 3).forEach((vuln) => {
		if (vuln.severity === 'Critical' || vuln.severity === 'High') {
			recommendations.push(`Strengthen protection against ${vuln.category} attacks`);
		}
	});

	if (recommendations.length === 0) {
		recommendations.push('WAF is performing well, continue monitoring');
	}

	return {
		overallScore,
		riskLevel,
		totalTests,
		bypassedTests,
		bypassRate: Math.round(bypassRate * 100) / 100,
		wafEffectiveness: Math.round(wafEffectiveness * 100) / 100,
		criticalVulnerabilities,
		highVulnerabilities,
		mediumVulnerabilities,
		lowVulnerabilities,
		recommendations: recommendations.slice(0, 5),
	};
}

function showAnalytics() {
	if (!currentTestSession) {
		alert('No test results to analyze');
		return;
	}

	const vulnerabilityScores = generateVulnerabilityScores(currentTestSession.results, currentTestSession.settings.falsePositiveTest);
	const executiveSummary = generateExecutiveSummary(currentTestSession.results, vulnerabilityScores, currentTestSession.wafDetection);

	const dashboard = document.getElementById('analyticsDashboard');
	const content = document.getElementById('analyticsContent');

	if (!dashboard || !content) return;

	content.innerHTML = generateAnalyticsHTML(currentTestSession, vulnerabilityScores, executiveSummary);
	dashboard.style.display = 'block';
}

function hideAnalytics() {
	const dashboard = document.getElementById('analyticsDashboard');
	if (dashboard) {
		dashboard.style.display = 'none';
	}
}

function generateAnalyticsHTML(session, vulnerabilityScores, summary) {
	return `
		<div class="row">
			<div class="col-md-6">
				<div class="card">
					<div class="card-header"><h6>📊 Test Overview</h6></div>
					<div class="card-body">
						<div class="d-flex justify-content-between">
							<span>Total Tests:</span>
							<strong>${summary.totalTests}</strong>
						</div>
						<div class="d-flex justify-content-between">
							<span>Bypassed:</span>
							<strong class="${summary.bypassedTests > 0 ? 'text-danger' : 'text-success'}">${summary.bypassedTests}</strong>
						</div>
						<div class="d-flex justify-content-between">
							<span>WAF Effectiveness:</span>
							<strong class="${summary.wafEffectiveness < 75 ? 'text-warning' : 'text-success'}">${summary.wafEffectiveness}%</strong>
						</div>
						<div class="d-flex justify-content-between">
							<span>Risk Level:</span>
							<span class="badge bg-${summary.riskLevel === 'Critical' ? 'danger' : summary.riskLevel === 'High' ? 'warning' : summary.riskLevel === 'Medium' ? 'info' : 'success'}">${summary.riskLevel}</span>
						</div>
					</div>
				</div>
			</div>
			<div class="col-md-6">
				<div class="card">
					<div class="card-header"><h6>🛡️ Vulnerability Breakdown</h6></div>
					<div class="card-body">
						<div class="d-flex justify-content-between">
							<span>Critical:</span>
							<strong class="text-danger">${summary.criticalVulnerabilities}</strong>
						</div>
						<div class="d-flex justify-content-between">
							<span>High:</span>
							<strong class="text-warning">${summary.highVulnerabilities}</strong>
						</div>
						<div class="d-flex justify-content-between">
							<span>Medium:</span>
							<strong class="text-info">${summary.mediumVulnerabilities}</strong>
						</div>
						<div class="d-flex justify-content-between">
							<span>Low:</span>
							<strong class="text-success">${summary.lowVulnerabilities}</strong>
						</div>
					</div>
				</div>
			</div>
		</div>

		<div class="mt-3">
			<h6>🎯 Category Analysis</h6>
			<div class="table-responsive">
				<table class="table table-sm">
					<thead>
						<tr>
							<th>Category</th>
							<th>Severity</th>
							<th>Score</th>
							<th>Bypass Rate</th>
						</tr>
					</thead>
					<tbody>
						${vulnerabilityScores
			.map(
				(vuln) => `
						<tr>
							<td>${vuln.category}</td>
							<td><span class="badge bg-${vuln.severity === 'Critical' ? 'danger' : vuln.severity === 'High' ? 'warning' : vuln.severity === 'Medium' ? 'info' : 'success'}">${vuln.severity}</span></td>
							<td>${vuln.score}/100</td>
							<td>${vuln.bypassRate}%</td>
						</tr>
						`,
			)
			.join('')}
					</tbody>
				</table>
			</div>
		</div>

		<div class="mt-3">
			<h6>💡 Recommendations</h6>
			<ul>
				${summary.recommendations.map((rec) => `<li>${rec}</li>`).join('')}
			</ul>
		</div>
	`;

	const dashboard = document.getElementById('analyticsDashboard');
	const container = document.getElementById('resultsContainer');

	if (dashboard && container) {
		dashboard.style.display = 'block';
		// Scroll to analytics dashboard with delay to ensure rendering
		setTimeout(() => {
			// Calculate position relative to container
			const headerOffset = 20; // Add some top spacing
			const elementPosition = dashboard.getBoundingClientRect().top;
			const containerPosition = container.getBoundingClientRect().top;
			const offsetPosition = elementPosition - containerPosition + container.scrollTop - headerOffset;

			container.scrollTo({
				top: offsetPosition,
				behavior: 'smooth'
			});
		}, 100);
	}
}

function downloadFile(content, filename, mimeType) {
	const blob = new Blob([content], { type: mimeType });
	const url = URL.createObjectURL(blob);
	const link = document.createElement('a');
	link.href = url;
	link.download = filename;
	document.body.appendChild(link);
	link.click();
	document.body.removeChild(link);
	URL.revokeObjectURL(url);
}

function generateFilename(baseUrl, extension) {
	const timestamp = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
	let hostname;
	try {
		hostname = new URL(baseUrl).hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
	} catch {
		hostname = 'results';
	}
	return `waf-report_${hostname}_${timestamp}.${extension}`;
}

// Batch Testing Functions
function showBatchModal() {
	const modal = new bootstrap.Modal(document.getElementById('batchModal'));
	modal.show();

	// Reset modal state
	document.getElementById('batchProgress').style.display = 'none';
	document.getElementById('batchResults').style.display = 'none';
	document.getElementById('startBatchBtn').style.display = 'inline-block';
	document.getElementById('stopBatchBtn').style.display = 'none';
	document.getElementById('exportBatchBtn').style.display = 'none';

	// Load sample URLs if empty
	const urlsTextarea = document.getElementById('batchUrls');
	if (!urlsTextarea.value.trim()) {
		urlsTextarea.value = 'https://httpbin.org/get\nhttps://jsonplaceholder.typicode.com/posts/1\nhttps://httpbin.org/status/200';
	}

	// Add real-time URL validation feedback
	urlsTextarea.addEventListener('input', function () {
		validateBatchUrls();
	});
}

async function startBatchTest() {
	const urlsText = document.getElementById('batchUrls').value;
	const maxConcurrent = parseInt(document.getElementById('batchMaxConcurrent').value);
	const delay = parseInt(document.getElementById('batchDelay').value);
	const inheritSettings = document.getElementById('batchInheritSettings').checked;

	// Parse and validate URLs
	const allLines = urlsText
		.split('\n')
		.map((line) => line.trim())
		.filter((line) => line.length > 0);

	if (allLines.length === 0) {
		alert('Please enter at least one URL');
		return;
	}

	// Validate URLs client-side
	const validUrls = [];
	const invalidUrls = [];

	allLines.forEach((line) => {
		try {
			if (!line.startsWith('http://') && !line.startsWith('https://')) {
				invalidUrls.push(`${line} (must start with http:// or https://)`);
				return;
			}

			const url = new URL(line);
			if (url.protocol === 'http:' || url.protocol === 'https:') {
				validUrls.push(line);
			} else {
				invalidUrls.push(`${line} (unsupported protocol: ${url.protocol})`);
			}
		} catch (error) {
			invalidUrls.push(`${line} (invalid URL format)`);
		}
	});

	// Show validation results
	if (invalidUrls.length > 0) {
		const message = `Found ${invalidUrls.length} invalid URL(s):\n\n${invalidUrls.slice(0, 5).join('\n')}${invalidUrls.length > 5 ? `\n... and ${invalidUrls.length - 5} more` : ''
			}\n\nContinue with ${validUrls.length} valid URLs?`;

		if (!confirm(message)) {
			return;
		}
	}

	if (validUrls.length === 0) {
		alert('No valid URLs found. Please check your input.');
		return;
	}

	if (validUrls.length > 100) {
		alert('Maximum 100 URLs allowed for batch testing');
		return;
	}

	const urls = validUrls;

	// Prepare batch configuration
	const config = {
		maxConcurrent,
		delayBetweenRequests: delay,
	};

	if (inheritSettings) {
		const methodCheckboxes = document.querySelectorAll('.http-methods input[type=checkbox]');
		const selectedMethods = Array.from(methodCheckboxes)
			.filter((cb) => cb.checked)
			.map((cb) => cb.value);

		const categoryCheckboxes = document.querySelectorAll('#categoryCheckboxes input[type=checkbox]');
		const selectedCategories = Array.from(categoryCheckboxes)
			.filter((cb) => cb.checked)
			.map((cb) => cb.value);

		config.methods = selectedMethods;
		config.categories = selectedCategories;
		config.followRedirect = document.getElementById('followRedirect')?.checked || false;
		config.falsePositiveTest = document.getElementById('falsePositiveTest')?.checked || false;
		config.caseSensitiveTest = document.getElementById('caseSensitiveTest')?.checked || false;
		config.enhancedPayloads = document.getElementById('enhancedPayloads')?.checked || false;
		config.useAdvancedPayloads = document.getElementById('useAdvancedPayloadsCheckbox')?.checked || false;
		config.autoDetectWAF = document.getElementById('autoDetectWAF')?.checked || false;
		config.useEncodingVariations = document.getElementById('useEncodingVariations')?.checked || false;
		config.httpManipulation = document.getElementById('httpManipulation')?.checked || false;
		config.payloadTemplate = document.getElementById('payloadTemplate')?.value || '';
		config.customHeaders = document.getElementById('customHeaders')?.value || '';
	} else {
		config.methods = ['GET'];
		config.categories = ['SQL Injection', 'XSS'];
		config.followRedirect = false;
		config.falsePositiveTest = false;
		config.caseSensitiveTest = false;
		config.enhancedPayloads = false;
		config.useAdvancedPayloads = false;
		config.autoDetectWAF = false;
		config.useEncodingVariations = false;
		config.httpManipulation = false;
	}

	try {
		// Initialize client-side batch processing
		currentBatchJob = {
			urls: urls,
			config: config,
			results: [],
			currentIndex: 0,
			completedCount: 0,
			startTime: new Date().toISOString(),
			status: 'running',
		};

		// Update UI
		document.getElementById('batchProgress').style.display = 'block';
		document.getElementById('startBatchBtn').style.display = 'none';
		document.getElementById('stopBatchBtn').style.display = 'inline-block';
		document.getElementById('batchTotal').textContent = urls.length;

		// Reset progress display
		document.getElementById('batchProgressText').textContent = '0%';
		document.getElementById('batchProgressBar').style.width = '0%';
		document.getElementById('batchProgressBar').classList.add('progress-bar-animated');
		document.getElementById('batchCurrentUrl').textContent = 'Starting...';
		document.getElementById('batchCompleted').textContent = '0';
		document.getElementById('batchETA').textContent = 'Calculating...';

		// Start client-side batch processing
		startClientSideBatchProcessing();

		console.log(`Started client-side batch test with ${urls.length} URLs`);
	} catch (error) {
		console.error('Batch test failed:', error);

		// Show a more user-friendly error message
		const errorLines = error.message.split('\n');
		const mainError = errorLines[0];
		const details = errorLines.slice(1).join('\n');

		let alertMessage = `Failed to start batch test: ${mainError}`;
		if (details.trim()) {
			alertMessage += `\n\nDetails:${details}`;
		}

		alert(alertMessage);

		// Reset UI state
		document.getElementById('batchProgress').style.display = 'none';
		document.getElementById('startBatchBtn').style.display = 'inline-block';
		document.getElementById('stopBatchBtn').style.display = 'none';
	}
}

async function stopBatchTest() {
	if (!currentBatchJob) return;

	try {
		// Stop client-side processing
		if (currentBatchJob) {
			currentBatchJob.status = 'stopped';
		}

		if (batchPollInterval) {
			clearInterval(batchPollInterval);
			batchPollInterval = null;
		}

		document.getElementById('startBatchBtn').style.display = 'inline-block';
		document.getElementById('stopBatchBtn').style.display = 'none';

		console.log('Batch test stopped by user');
	} catch (error) {
		console.error('Failed to stop batch test:', error);
	}
}

async function startClientSideBatchProcessing() {
	if (!currentBatchJob || currentBatchJob.status !== 'running') return;

	const { urls, config } = currentBatchJob;
	const delay = config.delayBetweenRequests || 1000;

	// Process URLs sequentially with delay
	for (let i = 0; i < urls.length && currentBatchJob.status === 'running'; i++) {
		const url = urls[i];
		currentBatchJob.currentIndex = i;

		// Update current URL display
		updateBatchProgress(url, i, urls.length);

		try {
			// Test single URL
			const result = await testSingleUrlClient(url, config);

			if (currentBatchJob.status === 'running') {
				currentBatchJob.results.push({
					url: url,
					success: true,
					results: result,
					timestamp: new Date().toISOString(),
					totalTests: result.length,
					bypassedTests: result.filter((r) => r.status === 200 || r.status === '200').length,
					bypassRate:
						result.length > 0 ? Math.round((result.filter((r) => r.status === 200 || r.status === '200').length / result.length) * 100) : 0,
				});

				currentBatchJob.completedCount++;
			}
		} catch (error) {
			console.error(`Error testing URL ${url}:`, error);

			if (currentBatchJob.status === 'running') {
				currentBatchJob.results.push({
					url: url,
					success: false,
					error: error.message,
					timestamp: new Date().toISOString(),
					totalTests: 0,
					bypassedTests: 0,
					bypassRate: 0,
				});

				currentBatchJob.completedCount++;
			}
		}

		// Apply delay between requests (except for the last one)
		if (i < urls.length - 1 && delay > 0 && currentBatchJob.status === 'running') {
			await new Promise((resolve) => setTimeout(resolve, delay));
		}
	}

	// Mark as completed
	if (currentBatchJob.status === 'running') {
		currentBatchJob.status = 'completed';
		finalizeBatchTest();
	}
}

function updateBatchProgress(currentUrl, completed, total) {
	const progress = Math.round((completed / total) * 100);

	const progressText = document.getElementById('batchProgressText');
	const progressBar = document.getElementById('batchProgressBar');
	const currentUrlElement = document.getElementById('batchCurrentUrl');
	const completedElement = document.getElementById('batchCompleted');
	const eta = document.getElementById('batchETA');

	if (progressText) progressText.textContent = `${progress}%`;
	if (progressBar) {
		progressBar.style.width = `${progress}%`;
		if (progress > 0) {
			progressBar.classList.remove('bg-secondary');
			progressBar.classList.add('bg-primary');
		}
	}
	if (currentUrlElement) {
		const displayUrl = currentUrl.length > 50 ? currentUrl.substring(0, 47) + '...' : currentUrl;
		currentUrlElement.textContent = displayUrl;
		currentUrlElement.title = currentUrl;
	}
	if (completedElement) completedElement.textContent = completed;

	// Calculate ETA
	if (completed > 0 && currentBatchJob) {
		const elapsed = Date.now() - new Date(currentBatchJob.startTime).getTime();
		const avgTimePerUrl = elapsed / completed;
		const remaining = (total - completed) * avgTimePerUrl;
		const delayTime = (total - completed - 1) * (currentBatchJob.config.delayBetweenRequests || 0);
		const totalRemaining = remaining + delayTime;

		if (eta) eta.textContent = formatDuration(totalRemaining);
	}
}

async function testSingleUrlClient(url, config) {
	const methods = config.methods || ['GET'];
	const categories = config.categories || ['SQL Injection', 'XSS'];

	let allResults = [];
	let page = 0;

	while (true) {
		const params = new URLSearchParams({
			url,
			methods: methods.join(','),
			categories: categories.join(','),
			page: page.toString(),
			followRedirect: config.followRedirect ? '1' : '0',
			falsePositiveTest: config.falsePositiveTest ? '1' : '0',
			caseSensitiveTest: config.caseSensitiveTest ? '1' : '0',
			enhancedPayloads: config.enhancedPayloads ? '1' : '0',
			useAdvancedPayloads: config.useAdvancedPayloads ? '1' : '0',
			autoDetectWAF: config.autoDetectWAF ? '1' : '0',
			useEncodingVariations: config.useEncodingVariations ? '1' : '0',
			httpManipulation: config.httpManipulation ? '1' : '0',
		});

		const response = await fetch(`/api/check?${params.toString()}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				payloadTemplate: config.payloadTemplate || '',
				customHeaders: config.customHeaders || '',
			}),
		});

		if (!response.ok) break;

		const results = await response.json();
		if (!results || !results.length) break;

		allResults = allResults.concat(results);
		page++;

		// Limit results to prevent memory issues
		if (allResults.length > 1000) break;
	}

	return allResults;
}

function finalizeBatchTest() {
	if (!currentBatchJob) return;

	// Update UI
	const startBtn = document.getElementById('startBatchBtn');
	const stopBtn = document.getElementById('stopBatchBtn');
	const exportBtn = document.getElementById('exportBatchBtn');

	if (startBtn) startBtn.style.display = 'inline-block';
	if (stopBtn) stopBtn.style.display = 'none';
	if (exportBtn) exportBtn.style.display = 'inline-block';

	// Final progress update
	const progressText = document.getElementById('batchProgressText');
	const progressBar = document.getElementById('batchProgressBar');
	const currentUrl = document.getElementById('batchCurrentUrl');
	const eta = document.getElementById('batchETA');

	if (progressText) progressText.textContent = '100%';
	if (progressBar) {
		progressBar.style.width = '100%';
		progressBar.classList.remove('progress-bar-animated', 'bg-primary');
		progressBar.classList.add(currentBatchJob.status === 'completed' ? 'bg-success' : 'bg-warning');
	}
	if (currentUrl) {
		currentUrl.textContent =
			currentBatchJob.status === 'completed'
				? 'All tests completed'
				: currentBatchJob.status === 'stopped'
					? 'Test stopped by user'
					: 'Test completed with errors';
	}
	if (eta) eta.textContent = 'Done';

	// Show results
	displayBatchResults({
		status: currentBatchJob.status,
		results: currentBatchJob.results,
		totalUrls: currentBatchJob.urls.length,
		completedUrls: currentBatchJob.completedCount,
		progress: 100,
	});

	console.log(`Batch test ${currentBatchJob.status}:`, currentBatchJob.results);
}

function displayBatchResults(job) {
	const resultsDiv = document.getElementById('batchResults');
	const summaryDiv = document.getElementById('batchSummary');

	if (!resultsDiv || !summaryDiv) return;

	const successful = job.results.filter((r) => r.success);
	const failed = job.results.filter((r) => !r.success);

	let html = `
		<div class="row">
			<div class="col-md-3">
				<div class="text-center">
					<div class="h4 text-primary">${job.totalUrls}</div>
					<small>Total URLs</small>
				</div>
			</div>
			<div class="col-md-3">
				<div class="text-center">
					<div class="h4 text-success">${successful.length}</div>
					<small>Successful</small>
				</div>
			</div>
			<div class="col-md-3">
				<div class="text-center">
					<div class="h4 text-danger">${failed.length}</div>
					<small>Failed</small>
				</div>
			</div>
			<div class="col-md-3">
				<div class="text-center">
					<div class="h4 text-info">${job.progress}%</div>
					<small>Progress</small>
				</div>
			</div>
		</div>
	`;

	if (successful.length > 0) {
		const avgBypassRate = successful.reduce((sum, r) => sum + (r.bypassRate || 0), 0) / successful.length;
		html += `<div class="mt-3"><strong>Average Bypass Rate:</strong> ${Math.round(avgBypassRate * 100) / 100}%</div>`;
	}

	summaryDiv.innerHTML = html;
	resultsDiv.style.display = 'block';
}

function exportBatchResults() {
	if (!currentBatchJob || !currentBatchJob.results) {
		alert('No batch results to export');
		return;
	}

	const summary = generateBatchSummary(currentBatchJob.results);
	const exportData = {
		summary,
		results: currentBatchJob.results,
		exportedAt: new Date().toISOString(),
		version: '1.0.0',
	};

	const content = JSON.stringify(exportData, null, 2);
	const filename = `batch-results_${new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19)}.json`;
	downloadFile(content, filename, 'application/json');
}

function generateBatchSummary(results) {
	const successful = results.filter((r) => r.success);
	const failed = results.filter((r) => !r.success);

	const totalTestCases = successful.reduce((sum, r) => sum + (r.results?.length || 0), 0);
	const avgBypassRate = successful.length > 0 ? successful.reduce((sum, r) => sum + (r.bypassRate || 0), 0) / successful.length : 0;

	return {
		totalUrls: results.length,
		successfulTests: successful.length,
		failedTests: failed.length,
		totalTestCases,
		averageBypassRate: Math.round(avgBypassRate * 100) / 100,
	};
}

function formatDuration(milliseconds) {
	const seconds = Math.floor(milliseconds / 1000);
	const minutes = Math.floor(seconds / 60);
	const hours = Math.floor(minutes / 60);

	if (hours > 0) {
		return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
	} else if (minutes > 0) {
		return `${minutes}m ${seconds % 60}s`;
	} else {
		return `${seconds}s`;
	}
}

function validateBatchUrls() {
	const urlsText = document.getElementById('batchUrls').value;
	const lines = urlsText
		.split('\n')
		.map((line) => line.trim())
		.filter((line) => line.length > 0);

	let validCount = 0;
	let invalidCount = 0;

	lines.forEach((line) => {
		try {
			if (line.startsWith('http://') || line.startsWith('https://')) {
				new URL(line);
				validCount++;
			} else {
				invalidCount++;
			}
		} catch (error) {
			invalidCount++;
		}
	});

	// Update UI with validation status
	const startBtn = document.getElementById('startBatchBtn');
	if (startBtn) {
		if (validCount === 0 && lines.length > 0) {
			startBtn.disabled = true;
			startBtn.textContent = '❌ No Valid URLs';
		} else if (validCount > 100) {
			startBtn.disabled = true;
			startBtn.textContent = `❌ Too Many URLs (${validCount}/100)`;
		} else {
			startBtn.disabled = false;
			startBtn.textContent = validCount > 0 ? `▶️ Start Batch Test (${validCount} URLs)` : '▶️ Start Batch Test';
		}
	}

	// Show validation summary
	const urlsTextarea = document.getElementById('batchUrls');
	if (urlsTextarea && lines.length > 0) {
		if (invalidCount > 0) {
			urlsTextarea.style.borderColor = '#ffc107';
			urlsTextarea.title = `${validCount} valid, ${invalidCount} invalid URLs`;
		} else {
			urlsTextarea.style.borderColor = '#198754';
			urlsTextarea.title = `${validCount} valid URLs`;
		}
	} else if (urlsTextarea) {
		urlsTextarea.style.borderColor = '';
		urlsTextarea.title = '';
	}
}
