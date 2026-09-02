import { CheckResult, BatchResult } from '../report';
import { ReverseEngineeringReport, VirtualPatchReport } from '@waf-checker/core';

export function generateMarkdownReport(
	results: CheckResult[],
	targetUrl?: string,
	reverseEngineering?: ReverseEngineeringReport,
	virtualPatches?: VirtualPatchReport
): string {
	let blocked = 0;
	let bypassed = 0;
	let errors = 0;
	let other = 0;
	let detectedWAF = 'Unknown';

	for (const r of results) {
		if (r.wafType && r.wafType !== 'Unknown') {
			detectedWAF = r.wafType;
		}
		if (r.status === 403 || r.status === '403' || r.status === 'BLOCKED') {
			blocked++;
		} else if (r.status === 200 || r.status === '200') {
			bypassed++;
		} else if (r.status === 'ERR' || r.status === 500 || r.status === '500') {
			errors++;
		} else {
			other++;
		}
	}

	const total = results.length;
	const protectionScore = total > 0 ? Math.round((blocked / total) * 100) : 100;

	// Calculate per-category stats
	const categoryMap = new Map<string, { total: number; blocked: number; bypassed: number; errors: number }>();

	for (const r of results) {
		const entry = categoryMap.get(r.category) || { total: 0, blocked: 0, bypassed: 0, errors: 0 };
		entry.total++;
		if (r.status === 403 || r.status === '403' || r.status === 'BLOCKED') {
			entry.blocked++;
		} else if (r.status === 200 || r.status === '200') {
			entry.bypassed++;
		} else {
			entry.errors++;
		}
		categoryMap.set(r.category, entry);
	}

	const bypassedItems = results.filter((r) => r.status === 200 || r.status === '200');

	// Status badge
	const scoreEmoji = protectionScore >= 90 ? '🟢' : protectionScore >= 70 ? '🟡' : '🔴';
	const statusBadge =
		protectionScore === 100
			? '🛡️ **Excellent: 100% Protection**'
			: protectionScore >= 90
				? '🛡️ **Good Protection**'
				: protectionScore >= 70
					? '⚠️ **Moderate Protection**'
					: '🚨 **Poor Protection / High Risk**';

	const safeTargetUrl = (targetUrl || 'Target').replace(/`/g, '&#96;');

	const lines: string[] = [
		`# 🛡️ WAF Checker Audit Report`,
		``,
		`> **Target:** \`${safeTargetUrl}\` | **Date:** ${new Date().toUTCString()} | **Detected WAF:** \`${detectedWAF}\``,
		``,
		`### ${scoreEmoji} Overall Score: ${protectionScore}% (${statusBadge})`,
		``,
		`| Metric | Count | Percentage |`,
		`| :--- | :--- | :--- |`,
		`| 🎯 **Total Tests** | \`${total}\` | \`100%\` |`,
		`| 🛡️ **Blocked (Protected)** | \`${blocked}\` | \`${total > 0 ? Math.round((blocked / total) * 100) : 0}%\` |`,
		`| ⚠️ **Bypassed (Vulnerable)** | \`${bypassed}\` | \`${total > 0 ? Math.round((bypassed / total) * 100) : 0}%\` |`,
		`| ❓ **Errors / Other** | \`${errors + other}\` | \`${total > 0 ? Math.round(((errors + other) / total) * 100) : 0}%\` |`,
		``,
		`### 📊 Attack Category Breakdown`,
		``,
		`| Attack Category | Total | Blocked | Bypassed | Protection Rate |`,
		`| :--- | :--- | :--- | :--- | :--- |`,
	];

	for (const [cat, data] of categoryMap.entries()) {
		const rate = data.total > 0 ? Math.round((data.blocked / data.total) * 100) : 100;
		const catEmoji = rate >= 90 ? '🟢' : rate >= 70 ? '🟡' : '🔴';
		lines.push(`| **${cat}** | \`${data.total}\` | \`${data.blocked}\` | \`${data.bypassed}\` | ${catEmoji} \`${rate}%\` |`);
	}

	lines.push(``);

	if (bypassedItems.length > 0) {
		lines.push(`### ⚠️ Bypassed Payloads (${bypassedItems.length})`);
		lines.push(``);
		lines.push(`<details>`);
		lines.push(`<summary><b>Click to inspect ${bypassedItems.length} bypassed attack vectors</b></summary>`);
		lines.push(``);
		lines.push(`| Category | Method | Status | Time | Bypass Technique | Payload |`);
		lines.push(`| :--- | :--- | :--- | :--- | :--- | :--- |`);

		for (const item of bypassedItems) {
			const safePayload = item.payload
				.replace(/&/g, '&amp;')
				.replace(/</g, '&lt;')
				.replace(/>/g, '&gt;')
				.replace(/"/g, '&quot;')
				.replace(/'/g, '&#39;')
				.replace(/\|/g, '&#124;')
				.replace(/\r?\n/g, ' ');
			lines.push(
				`| \`${item.category}\` | \`${item.method}\` | \`${item.status}\` | \`${item.responseTime}ms\` | \`${item.bypassTechnique || 'Standard'}\` | <code>${safePayload}</code> |`,
			);
		}

		lines.push(``);
		lines.push(`</details>`);
	} else {
		lines.push(`### ✅ No Bypasses Detected`);
		lines.push(`All executed attack payloads were successfully blocked by the WAF.`);
	}

	if (reverseEngineering) {
		lines.push(``);
		lines.push(`### 🕵️ WAF Reverse Engineering & OWASP Core Rule Set (CRS)`);
		lines.push(``);
		lines.push(`| Diagnostic Metric | Detection Result |`);
		lines.push(`| :--- | :--- |`);
		lines.push(`| 🛡️ **OWASP CRS Active Rules** | \`${reverseEngineering.crsSummary.active} / ${reverseEngineering.crsSummary.total} (${reverseEngineering.crsSummary.activePercent}% active)\` |`);
		lines.push(`| 📦 **Inspection Body Limit** | \`${reverseEngineering.bodyLimit.limitFormatted}\` |`);
		lines.push(`| ⚖️ **Scoring Mode** | \`${reverseEngineering.anomalyScore.mode === 'anomaly_scoring' ? `Collaborative Anomaly Scoring (Threshold: ${reverseEngineering.anomalyScore.detectedThreshold ?? 'Unknown'})` : reverseEngineering.anomalyScore.mode === 'traditional_regex' ? 'Traditional Strict Regex Blocking' : 'Unknown'}\` |`);
		lines.push(`| ⏱️ **Rate Limit Protection** | \`${reverseEngineering.rateLimit.detected ? `Triggered at ${reverseEngineering.rateLimit.thresholdRps} req/s` : `Safe up to ${reverseEngineering.rateLimit.safeTestedMaxRps} req/s (No 429)`}\` |`);
		lines.push(``);

		if (reverseEngineering.crsRules.length > 0) {
			lines.push(`<details>`);
			lines.push(`<summary><b>Click to inspect OWASP CRS Rules Matrix (${reverseEngineering.crsRules.length} rules)</b></summary>`);
			lines.push(``);
			lines.push(`| Rule ID | Rule Name | Category | Paranoia Level | Status |`);
			lines.push(`| :--- | :--- | :--- | :---: | :--- |`);
			for (const r of reverseEngineering.crsRules) {
				const statusEmoji = r.status === 'active' ? '🟢 Active' : r.status === 'disabled' ? '🔴 Disabled' : r.status === 'bypassed' ? '⚠️ Bypassed' : '❓ Unknown';
				lines.push(`| \`${r.ruleId}\` | ${r.name} | \`${r.category}\` | \`PL${r.paranoiaLevel}\` | ${statusEmoji} |`);
			}
			lines.push(``);
			lines.push(`</details>`);
		}
	}

	// Virtual Patches (Auto-Mitigation) Section
	if (virtualPatches && virtualPatches.totalBypasses > 0) {
		lines.push(``);
		lines.push(`### 🛡️ Recommended Virtual Patches (Auto-Mitigation)`);
		lines.push(``);
		lines.push(`> Generated **${virtualPatches.patches.length} virtual patch rules** across supported WAF engines to remediate **${virtualPatches.totalBypasses} detected bypasses**.`);
		lines.push(``);
		lines.push(`<details>`);
		lines.push(`<summary><b>Click to inspect ready-to-deploy configuration snippets & Terraform HCL</b></summary>`);
		lines.push(``);

		for (const [vendor, bundle] of Object.entries(virtualPatches.bundles)) {
			if (bundle.ruleCount === 0) continue;
			const vendorTitle = vendor === 'cloudflare' ? 'Cloudflare Ruleset Engine' : vendor === 'aws' ? 'AWS WAF v2' : vendor === 'modsecurity' ? 'ModSecurity (CRS-style)' : 'NGINX';
			lines.push(`#### ${vendorTitle}`);
			lines.push(``);
			lines.push('```' + (vendor === 'aws' ? 'json' : vendor === 'cloudflare' ? 'text' : 'apache'));
			lines.push(bundle.native);
			lines.push('```');
			lines.push(``);

			if (bundle.terraform) {
				lines.push(`*Terraform (HCL):*`);
				lines.push(``);
				lines.push('```hcl');
				lines.push(bundle.terraform);
				lines.push('```');
				lines.push(``);
			}
		}

		lines.push(`</details>`);
	}

	lines.push(``);
	lines.push(`---`);
	lines.push(`*Generated by [WAF-Checker](https://github.com/SecH0us3/waf-checker)*`);

	return lines.join('\n');
}

export function generateBatchMarkdown(batchResults: BatchResult[]): string {
	const totalTargets = batchResults.length;
	const totalBypassed = batchResults.reduce((acc, r) => acc + (r.bypassed || 0), 0);
	const totalBlocked = batchResults.reduce((acc, r) => acc + (r.blocked || 0), 0);
	const totalTests = batchResults.reduce((acc, r) => acc + (r.total || 0), 0);
	const overallRate = totalTests > 0 ? Math.round((totalBlocked / totalTests) * 100) : 100;

	const mdLines = [
		`# 🛡️ WAF Batch Audit Report`,
		``,
		`> **Scanned Targets:** \`${totalTargets}\` | **Total Tests:** \`${totalTests}\` | **Overall Protection:** \`${overallRate}%\``,
		``,
		`| Target URL | Status | Total Tests | Blocked | Bypassed | Bypass Rate |`,
		`| :--- | :--- | :--- | :--- | :--- | :--- |`,
	];

	for (const r of batchResults) {
		const statusBadge = !r.success ? '🔴 Failed' : r.bypassed > 0 ? '⚠️ Bypasses' : '🟢 Secure';
		const safeUrl = (r.url || '').replace(/\|/g, '&#124;').replace(/`/g, '&#96;');
		mdLines.push(
			`| \`${safeUrl}\` | ${statusBadge} | \`${r.total || 0}\` | \`${r.blocked || 0}\` | \`${r.bypassed || 0}\` | \`${r.bypassRate || 0}%\` |`,
		);
	}

	mdLines.push(``);
	mdLines.push(`---`);
	mdLines.push(`*Generated by [WAF-Checker](https://github.com/SecH0us3/waf-checker)*`);
	return mdLines.join('\n');
}
