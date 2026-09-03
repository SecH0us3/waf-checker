#!/usr/bin/env node
import { Command } from 'commander';
import { fetch as undiciFetch, ProxyAgent } from 'undici';
import * as fs from 'fs';
import * as path from 'path';
import {
	WAFDetector,
	handleApiCheckFiltered,
	isValidTargetUrl,
	redactUrl,
	PAYLOADS,
	runReverseEngineeringAudit,
	ReverseEngineeringReport,
	generateVirtualPatches,
	VirtualPatchReport,
	PatchVendor,
	PatchTier,
	PatchAction,
} from '@waf-checker/core';
import { writeReport, deduceFormat, ReportFormat } from './report';

let useColor = true;

const colors = {
	green: (text: string) => useColor ? `\x1b[32m${text}\x1b[0m` : text,
	red: (text: string) => useColor ? `\x1b[31m${text}\x1b[0m` : text,
	yellow: (text: string) => useColor ? `\x1b[33m${text}\x1b[0m` : text,
	cyan: (text: string) => useColor ? `\x1b[36m${text}\x1b[0m` : text,
	bold: (text: string) => useColor ? `\x1b[1m${text}\x1b[0m` : text,
	dim: (text: string) => useColor ? `\x1b[2m${text}\x1b[0m` : text,
};

const supportedMethods = [
	'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS', 'HEAD',
	'PROPFIND', 'REPORT', 'LOCK', 'UNLOCK', 'COPY', 'MOVE'
];
const supportedCategories = Object.keys(PAYLOADS);
const supportedWafs = WAFDetector.getSupportedWafs();

const detailedHelp = `
Supported HTTP Methods (-m, --methods):
${supportedMethods.map((m: string) => `  - ${m}`).join('\n')}

Supported Payload Categories (-c, --categories):
${supportedCategories.map((c: string) => `  - ${c}`).join('\n')}

Supported WAF Vendors (--detected-waf):
${supportedWafs.map((w: string) => `  - ${w}`).join('\n')}
`;

const program = new Command();

program
	.name('waf-checker')
	.description('WAF Security Testing Tool (CLI version)')
	.version('1.1.0')
	.showHelpAfterError()
	.option('--no-color', 'Disable colored output')
	.addHelpText('after', detailedHelp);

program.hook('preAction', () => {
	const opts = program.opts();
	if (opts.color === false || process.env.NO_COLOR || !process.stdout.isTTY) {
		useColor = false;
	}
});

// Helper to get custom fetch with proxy support
function getFetch(proxyUrl?: string): typeof fetch {
	if (proxyUrl) {
		const agent = new ProxyAgent(proxyUrl);
		return ((url: any, init: any) => undiciFetch(url, { ...init, dispatcher: agent })) as any;
	}
	return globalThis.fetch;
}

// Helper to read custom headers from file or string
function parseCustomHeaders(headersOpt?: string): string | undefined {
	if (!headersOpt) return undefined;
	try {
		if (fs.existsSync(headersOpt)) {
			return fs.readFileSync(headersOpt, 'utf8');
		}
	} catch {}
	return headersOpt;
}

// Helper to parse comma-separated lists
function parseCommaList(val?: string): string[] | undefined {
	if (!val) return undefined;
	return val.split(',').map((x) => x.trim()).filter(Boolean);
}

// Helper to format response time
function formatTime(ms: number): string {
	return `${ms}ms`;
}

// Helper to parse and validate threshold
function parseThreshold(val: string): number {
	const minThreshold = parseFloat(val);
	if (isNaN(minThreshold) || minThreshold < 0 || minThreshold > 100) {
		console.error(colors.red(`Error: --threshold must be a valid number between 0 and 100 (received: ${val})`));
		process.exit(1);
	}
	return minThreshold;
}

// Command: detect
program
	.command('detect <url>')
	.description('Detect WAF vendor and status of a target URL')
	.option('-p, --proxy <url>', 'Proxy URL (HTTP/HTTPS)')
	.option('--json', 'Output results in JSON format')
	.action(async (url: string, options: any) => {
		try {
			if (!isValidTargetUrl(url)) {
				console.error(`Error: Invalid target URL "${url}" or restricted IP.`);
				process.exit(1);
			}

			const customFetch = getFetch(options.proxy);
			const detection = await WAFDetector.activeDetection(url, { fetch: customFetch });

			if (options.json) {
				console.log(JSON.stringify(detection, null, 2));
				return;
			}

			console.log(`\n=== WAF Detection Results for ${colors.cyan(url)} ===`);
			console.log(`Status:      ${detection.detected ? colors.green('🛡️ WAF DETECTED') : colors.yellow('❌ WAF NOT DETECTED')}`);
			console.log(`WAF Type:    ${colors.bold(detection.wafType)}`);
			
			let confidenceColor = colors.yellow;
			if (detection.confidence > 70) confidenceColor = colors.green;
			else if (detection.confidence < 40) confidenceColor = colors.red;
			console.log(`Confidence:  ${confidenceColor(`${detection.confidence}%`)}`);

			if (detection.evidence.length > 0) {
				console.log('\nEvidence:');
				detection.evidence.forEach((ev: any) => console.log(`  - ${colors.dim(ev)}`));
			}

			if (detection.suggestedBypassTechniques.length > 0) {
				console.log('\nSuggested Bypass Techniques:');
				detection.suggestedBypassTechniques.forEach((tech: any) => console.log(`  - ${colors.cyan(tech)}`));
			}
			console.log();
		} catch (err: any) {
			console.error(`Error: WAF detection failed: ${err.message}`);
			process.exit(1);
		}
	});

// Command: check
const checkCmd = program.command('check <url>');
checkCmd
	.description('Run vulnerability payload audit against a target URL')
	.option('-p, --proxy <url>', 'Proxy URL (e.g., http://127.0.0.1:8080)')
	.option('-m, --methods <methods>', 'HTTP methods (comma-separated). Supported: GET, POST, PUT, DELETE, PATCH, TRACE, OPTIONS, HEAD, PROPFIND, REPORT, LOCK, UNLOCK, COPY, MOVE', 'GET')
	.option('-c, --categories <categories>', 'Payload categories (comma-separated). Use --help for full list of supported categories')
	.option('--detected-waf <vendor>', 'Force WAF signature and use WAF-specific bypasses. Supported: Cloudflare, AWS WAF, Imperva, F5 BIG-IP, ModSecurity, Akamai, Barracuda, Sucuri, Fastly, KeyCDN, StackPath, DenyAll, FortiWeb, Wallarm, Radware, Azure Front Door, Google Cloud Armor, Citrix NetScaler, Varnish, Palo Alto Networks, Sophos WAF')
	.option('--payload-template <template>', 'JSON or text template (e.g., \'{"input": "{PAYLOAD}"}\')')
	.option('--follow-redirects', 'Follow HTTP redirects', false)
	.option('--custom-headers <headers>', 'Raw headers string (e.g., \'X-Custom: value\\nCookie: name=val\') or file path')
	.option('--false-positives', 'Run false positive test payloads', false)
	.option('--case-sensitive', 'Run case-sensitive variations', false)
	.option('--enhanced', 'Use enhanced payload set', false)
	.option('--advanced', 'Use advanced bypass payloads', false)
	.option('--auto-detect-waf', 'Detect WAF first and try WAF-specific bypasses', false)
	.option('--encoding-variations', 'Use encoding and obfuscation variations', false)
	.option('--http-manipulation', 'Run HTTP manipulation tests (Verb Tampering, Parameter Pollution, etc.)', false)
	.option('--padding <size>', 'Enable WAF inspection buffer padding evasion (e.g. 8kb, 16kb, 64kb, 128kb)')
	.option('--json', 'Output results in JSON format')
	.option('-f, --format <format>', 'Output format for report: json, csv, html, sarif, markdown')
	.option('-o, --output <path>', 'File path to save the report to')
	.option('--sarif-output <path>', 'File path to save SARIF report to')
	.option('--markdown-output <path>', 'File path to save Markdown report to')
	.option('--html-output <path>', 'File path to save HTML report to')
	.option('--threshold <percent>', 'Minimum protection score percentage required to pass (e.g. 95). Exits with code 1 if score is lower')
	.option('--reverse', 'Run deep WAF Reverse Engineering and OWASP Core Rule Set (CRS) audit', false)
	.option('--reverse-engineer', 'Alias for --reverse', false)
	.option('--patch [vendor]', 'Generate ready-to-deploy virtual patches (cloudflare, aws, modsecurity, nginx, gcp, azure, haproxy, caddy, k8s, all)')
	.option('--patch-output <path>', 'File path or directory to save generated virtual patch(es) to')
	.option('--patch-tier <tier>', 'Defense tier: strict (exact token), heuristic (regex pattern), or both', 'both')
	.option('--patch-action <action>', 'Rule action: block or simulate', 'block')
	.option('--patch-scope', 'Scope virtual patches to the target URL path', false)
	.option('--patch-include-misses', 'Include 404 Not Found and 5xx origin responses in virtual patch generation', false)
	.option('-q, --quiet', 'Suppress per-request logging, displaying only final results')
	.option('--silent', 'Alias for --quiet')
	.option('--fail-on-bypass', 'Exit with exit code 1 if any bypasses are detected', false)
	.option('--allow-local', 'Allow testing localhost, 127.0.0.1, and private IP ranges (Docker/LAN)', false)
	.addHelpText('after', detailedHelp)
	.action(async (url: string, options: any) => {
		const isQuiet = options.quiet || options.silent;
		const allowLocal = Boolean(options.allowLocal);
		try {
			if (!isValidTargetUrl(url, { allowLocal })) {
				console.error(colors.red(`Error: Invalid target URL "${url}" or restricted IP.`));
				process.exit(1);
			}

			const customFetch = getFetch(options.proxy);
			const methods = parseCommaList(options.methods) || ['GET'];
			const categories = parseCommaList(options.categories);
			const headers = parseCustomHeaders(options.customHeaders);

			const enableHttp = Boolean(options.httpManipulation);
			const enablePadding = Boolean(options.padding);
			const httpManipulationOpts = (enableHttp || enablePadding) ? {
				enableParameterPollution: enableHttp,
				enableVerbTampering: enableHttp,
				enableContentTypeConfusion: enableHttp,
				enableInspectionLimitPadding: enablePadding,
				paddingSize: options.padding || '16kb',
			} : undefined;

			const results = await handleApiCheckFiltered(
				url,
				0, // Start with page 0 (all payloads by default for CLI)
				methods,
				categories,
				options.payloadTemplate,
				options.followRedirects,
				headers,
				options.falsePositives,
				options.caseSensitive,
				options.enhanced,
				options.advanced,
				options.autoDetectWaf,
				options.encodingVariations,
				options.detectedWaf,
				httpManipulationOpts,
				{ fetch: customFetch, color: useColor, quiet: isQuiet, allowLocal }
			);

			let reverseReport: ReverseEngineeringReport | undefined = undefined;
			if (options.reverse || options.reverseEngineer) {
				if (!isQuiet) console.log(colors.cyan('\n[+] Executing deep WAF Reverse Engineering and OWASP CRS audit...'));
				reverseReport = await runReverseEngineeringAudit(url, { fetch: customFetch, quiet: isQuiet, color: useColor, allowLocal });
			}

			let patchReport: VirtualPatchReport | undefined = undefined;
			if (options.patch || options.patchOutput) {
				const vendorChoice = typeof options.patch === 'string' ? (options.patch as PatchVendor) : 'all';
				patchReport = generateVirtualPatches(results, {
					vendor: vendorChoice,
					tier: options.patchTier as PatchTier,
					action: options.patchAction as PatchAction,
					scopeToPath: Boolean(options.patchScope),
					includeMisses: Boolean(options.patchIncludeMisses),
					targetUrl: url,
				});

				if (options.patchOutput && patchReport.patches.length > 0) {
					const outPath = path.resolve(options.patchOutput);
					if (outPath.endsWith('.tf') || outPath.endsWith('.conf') || outPath.endsWith('.json') || outPath.endsWith('.txt')) {
						const dir = path.dirname(outPath);
						if (dir && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
						const bundledContent = Object.values(patchReport.bundles)
							.map((b) => b.terraform || b.native)
							.filter(Boolean)
							.join('\n\n');
						fs.writeFileSync(outPath, bundledContent, 'utf8');
					} else {
						if (!fs.existsSync(outPath)) fs.mkdirSync(outPath, { recursive: true });
						for (const [v, b] of Object.entries(patchReport.bundles)) {
							if (b.ruleCount === 0) continue;
							fs.writeFileSync(path.join(outPath, `${v}-patches.conf`), b.native, 'utf8');
							if (b.terraform) {
								fs.writeFileSync(path.join(outPath, `${v}-patches.tf`), b.terraform, 'utf8');
							}
						}
					}
					if (!isQuiet) console.log(colors.green(`Virtual patches saved to ${options.patchOutput}`));
				}
			}

			if (options.json) {
				console.log(JSON.stringify({ results, reverseEngineering: reverseReport, virtualPatches: patchReport }, null, 2));
				return;
			}

			console.log(`\n=== WAF Audit Results for ${colors.cyan(url)} ===`);
			console.log(`Total tests executed: ${results.length}`);

			const blocked = results.filter((r: any) => r.status === 403 || r.status === 'BLOCKED');
			const bypassed = results.filter((r: any) => r.status === 200 || r.status === '200');
			const redirect = results.filter((r: any) => r.is_redirect);
			const errors = results.filter((r: any) => r.status === 'ERR');

			const protectionScore = results.length ? Math.round((blocked.length / results.length) * 100) : 100;

			console.log(`  🛡️ Blocked:   ${colors.green(`${blocked.length} (${protectionScore}%)`)}`);
			console.log(`  🔓 Bypassed:  ${bypassed.length > 0 ? colors.red(`${bypassed.length} (${results.length ? Math.round(bypassed.length / results.length * 100) : 0}%)`) : colors.green('0 (0%)')}`);
			if (redirect.length > 0) console.log(`  🔄 Redirects: ${colors.yellow(String(redirect.length))}`);
			if (errors.length > 0) console.log(`  ⚠️ Errors:    ${colors.red(String(errors.length))}`);

			if (bypassed.length > 0) {
				console.log(`\n${colors.red('⚠️ SUCCESSFUL BYPASSES DETECTED:')}`);
				console.log('--------------------------------------------------------------------------------');
				console.log(`| ${'Category'.padEnd(18)} | ${'Method'.padEnd(6)} | ${'Status'.padEnd(6)} | ${'Time'.padEnd(6)} | ${'Payload'.padEnd(40)} |`);
				console.log('--------------------------------------------------------------------------------');
				bypassed.slice(0, 50).forEach((r: any) => {
					const cat = colors.cyan(r.category.substring(0, 18).padEnd(18));
					const meth = r.method.padEnd(6);
					const stat = colors.red(String(r.status).padEnd(6));
					const time = formatTime(r.responseTime).padEnd(6);
					const pay = colors.bold(r.payload.substring(0, 40).padEnd(40));
					console.log(`| ${cat} | ${meth} | ${stat} | ${time} | ${pay} |`);
				});
				if (bypassed.length > 50) {
					console.log(`... and ${colors.yellow(String(bypassed.length - 50))} more bypasses.`);
				}
				console.log('--------------------------------------------------------------------------------');
			} else {
				console.log(`\n${colors.green('🛡️ Perfect Score: All attack vectors were successfully blocked.')}`);
			}

			if (reverseReport) {
				console.log(`\n=== 🕵️ WAF Reverse Engineering & CRS Matrix for ${colors.cyan(url)} ===`);
				console.log(`  🛡️ CRS Active Rules:  ${colors.green(`${reverseReport.crsSummary.active} / ${reverseReport.crsSummary.total} (${reverseReport.crsSummary.activePercent}%)`)}`);
				console.log(`  📦 Body Limit Window: ${colors.cyan(reverseReport.bodyLimit.limitFormatted)}`);
				console.log(`  ⚖️ Scoring Paradigm:  ${colors.yellow(reverseReport.anomalyScore.mode === 'anomaly_scoring' ? `Collaborative Anomaly Scoring (Threshold: ${reverseReport.anomalyScore.detectedThreshold ?? '?'})` : reverseReport.anomalyScore.mode === 'traditional_regex' ? 'Traditional Strict Regex' : 'Unknown')}`);
				console.log(`  ⏱️ Rate Limiting:     ${reverseReport.rateLimit.detected ? colors.red(`Triggered at ${reverseReport.rateLimit.thresholdRps} req/s`) : colors.green(`Safe up to ${reverseReport.rateLimit.safeTestedMaxRps} req/s (No 429)`)}`);
			}

			if (patchReport && patchReport.patches.length > 0) {
				console.log(`\n=== 🛡️ WAF Virtual Patches Generated (${patchReport.patches.length} rules) ===`);
				for (const [v, b] of Object.entries(patchReport.bundles)) {
					if (b.ruleCount === 0) continue;
					console.log(`  • ${colors.bold(v.toUpperCase().padEnd(12))}: ${colors.green(`${b.ruleCount} rule(s) ready`)}`);
				}
				if (options.patchOutput) {
					console.log(`  📁 Saved to: ${colors.cyan(options.patchOutput)}`);
				}
			}
			console.log();

			if (options.output) {
				const format = (options.format || deduceFormat(options.output)) as ReportFormat;
				try {
					writeReport(options.output, format, 'check', url, results, reverseReport, patchReport);
					console.log(colors.green(`Report saved to ${options.output} (${format.toUpperCase()})`));
				} catch (err: any) {
					console.error(colors.red(`Error writing report: ${err.message}`));
				}
			}

			if (options.sarifOutput) {
				try {
					writeReport(options.sarifOutput, 'sarif', 'check', url, results, reverseReport, patchReport);
					console.log(colors.green(`SARIF report saved to ${options.sarifOutput}`));
				} catch (err: any) {
					console.error(colors.red(`Error writing SARIF report: ${err.message}`));
				}
			}

			if (options.markdownOutput) {
				try {
					writeReport(options.markdownOutput, 'markdown', 'check', url, results, reverseReport, patchReport);
					console.log(colors.green(`Markdown report saved to ${options.markdownOutput}`));
				} catch (err: any) {
					console.error(colors.red(`Error writing Markdown report: ${err.message}`));
				}
			}

			if (options.htmlOutput) {
				try {
					writeReport(options.htmlOutput, 'html', 'check', url, results, reverseReport, patchReport);
					console.log(colors.green(`HTML report saved to ${options.htmlOutput}`));
				} catch (err: any) {
					console.error(colors.red(`Error writing HTML report: ${err.message}`));
				}
			}

			if (options.threshold !== undefined) {
				const minThreshold = parseThreshold(options.threshold);
				if (protectionScore < minThreshold) {
					console.error(colors.red(`CI/CD Threshold Failed: Protection score ${protectionScore}% is below required threshold of ${minThreshold}%.`));
					process.exit(1);
				}
			}

			if (options.failOnBypass && bypassed.length > 0) {
				console.error(colors.red(`CI/CD Check Failed: ${bypassed.length} bypasses detected.`));
				process.exit(1);
			}
		} catch (err: any) {
			console.error(`Error: Audit failed: ${err.message}`);
			process.exit(1);
		}
	});

// Command: batch
const batchCmd = program.command('batch <file>');
batchCmd
	.description('Run batch audits for a list of URLs defined in a file')
	.option('-p, --proxy <url>', 'Proxy URL (e.g., http://127.0.0.1:8080)')
	.option('-m, --methods <methods>', 'HTTP methods (comma-separated). Supported: GET, POST, PUT, DELETE, PATCH, TRACE, OPTIONS, HEAD, PROPFIND, REPORT, LOCK, UNLOCK, COPY, MOVE', 'GET')
	.option('-c, --categories <categories>', 'Payload categories (comma-separated). Use --help for full list of supported categories', 'SQL Injection,XSS')
	.option('--detected-waf <vendor>', 'Force WAF signature and use WAF-specific bypasses. Supported: Cloudflare, AWS WAF, Imperva, F5 BIG-IP, ModSecurity, Akamai, Barracuda, Sucuri, Fastly, KeyCDN, StackPath, DenyAll, FortiWeb, Wallarm, Radware, Azure Front Door, Google Cloud Armor, Citrix NetScaler, Varnish, Palo Alto Networks, Sophos WAF')
	.option('--payload-template <template>', 'JSON or text template (e.g., \'{"input": "{PAYLOAD}"}\')')
	.option('--follow-redirects', 'Follow HTTP redirects', false)
	.option('--custom-headers <headers>', 'Raw headers string (e.g., \'X-Custom: value\\nCookie: name=val\') or file path')
	.option('--false-positives', 'Run false positive test payloads', false)
	.option('--case-sensitive', 'Run case-sensitive variations', false)
	.option('--enhanced', 'Use enhanced payload set', false)
	.option('--advanced', 'Use advanced bypass payloads', false)
	.option('--auto-detect-waf', 'Detect WAF first and try WAF-specific bypasses', false)
	.option('--encoding-variations', 'Use encoding and obfuscation variations', false)
	.option('--http-manipulation', 'Run HTTP manipulation tests', false)
	.option('--padding <size>', 'Enable WAF inspection buffer padding evasion (e.g. 8kb, 16kb, 64kb, 128kb)')
	.option('--concurrency <number>', 'Number of concurrent URLs to test', '3')
	.option('--json', 'Output results in JSON format')
	.option('-f, --format <format>', 'Output format for report: json, csv, html, markdown')
	.option('-o, --output <path>', 'File path to save the report to')
	.option('--markdown-output <path>', 'File path to save Markdown report to')
	.option('--html-output <path>', 'File path to save HTML report to')
	.option('--threshold <percent>', 'Minimum average protection score percentage required across all targets')
	.option('-q, --quiet', 'Suppress per-request logging')
	.option('--silent', 'Alias for --quiet')
	.option('--fail-on-bypass', 'Exit with exit code 1 if any bypasses are detected', false)
	.addHelpText('after', detailedHelp)
	.action(async (file: string, options: any) => {
		try {
			if (!fs.existsSync(file)) {
				console.error(`Error: File "${file}" does not exist.`);
				process.exit(1);
			}

			const isQuiet = Boolean(options.quiet || options.silent);
			const content = fs.readFileSync(file, 'utf8');
			const urls = content.split(/\r?\n/).map((u) => u.trim()).filter((u) => u && !u.startsWith('#'));

			const validUrls: string[] = [];
			for (const url of urls) {
				const testUrl = url.replace(/\{PAYLOAD\}/g, 'test-payload');
				if (isValidTargetUrl(testUrl)) {
					validUrls.push(url);
				} else {
					console.warn(`Warning: Skipping invalid or restricted target URL "${url}"`);
				}
			}

			if (validUrls.length === 0) {
				console.error('Error: No valid URLs found in file.');
				process.exit(1);
			}

			const customFetch = getFetch(options.proxy);
			const concurrency = parseInt(options.concurrency, 10) || 3;
			const methods = parseCommaList(options.methods) || ['GET'];
			const categories = parseCommaList(options.categories);
			const headers = parseCustomHeaders(options.customHeaders);

			const enableHttp = Boolean(options.httpManipulation);
			const enablePadding = Boolean(options.padding);
			const httpManipulationOpts = (enableHttp || enablePadding) ? {
				enableParameterPollution: enableHttp,
				enableVerbTampering: enableHttp,
				enableContentTypeConfusion: enableHttp,
				enableInspectionLimitPadding: enablePadding,
				paddingSize: options.padding || '16kb',
			} : undefined;

			if (!isQuiet && !options.json) {
				console.log(`\nStarting batch audit for ${validUrls.length} targets (concurrency = ${concurrency})...\n`);
			}

			const batchResults: any[] = [];
			let completed = 0;
			const totalValidUrls = validUrls.length;

			// Simple concurrent pool processor
			const pool = async () => {
				while (validUrls.length > 0) {
					const url = validUrls.shift();
					if (!url) break;

					try {
						if (!options.json && !isQuiet) {
							console.log(`[${++completed}/${totalValidUrls}] Scanning ${redactUrl(url)}...`);
						}

						const res = await handleApiCheckFiltered(
							url,
							0,
							methods,
							categories,
							options.payloadTemplate,
							options.followRedirects,
							headers,
							options.falsePositives,
							options.caseSensitive,
							options.enhanced,
							options.advanced,
							options.autoDetectWaf,
							options.encodingVariations,
							options.detectedWaf,
							httpManipulationOpts,
							{ fetch: customFetch, color: useColor, quiet: isQuiet }
						);

						const blocked = res.filter((r: any) => r.status === 403 || r.status === 'BLOCKED');
						const bypassed = res.filter((r: any) => r.status === 200 || r.status === '200');

						batchResults.push({
							url,
							success: true,
							total: res.length,
							blocked: blocked.length,
							bypassed: bypassed.length,
							bypassRate: res.length ? Math.round(bypassed.length / res.length * 100) : 0
						});
					} catch (err: any) {
						if (!options.json && !isQuiet) {
							console.error(`Error scanning ${redactUrl(url)}: ${err.message}`);
						}
						batchResults.push({
							url,
							success: false,
							error: err.message
						});
					}
				}
			};

			const workers = Array(concurrency).fill(null).map(() => pool());
			await Promise.all(workers);

			if (options.json) {
				console.log(JSON.stringify(batchResults, null, 2));
				return;
			}

			console.log(`\n=== ${colors.bold('Batch Audit Summary')} ===`);
			console.log('--------------------------------------------------------------------------------');
			console.log(`| ${'Target URL'.padEnd(35)} | ${'Success'.padEnd(8)} | ${'Total'.padEnd(6)} | ${'Blocked'.padEnd(8)} | ${'Bypassed'.padEnd(8)} |`);
			console.log('--------------------------------------------------------------------------------');
			batchResults.forEach((r: any) => {
				const urlStr = colors.cyan(redactUrl(r.url).substring(0, 35).padEnd(35));
				const succ = (r.success ? colors.green('YES'.padEnd(8)) : colors.red('NO'.padEnd(8)));
				const tot = String(r.total || 0).padEnd(6);
				const blk = colors.green(String(r.blocked || 0).padEnd(8));
				const byp = (r.bypassed > 0 ? colors.red : colors.green)(String(r.bypassed || 0).padEnd(8));
				console.log(`| ${urlStr} | ${succ} | ${tot} | ${blk} | ${byp} |`);
			});
			console.log('--------------------------------------------------------------------------------\n');

			if (options.output) {
				const format = (options.format || deduceFormat(options.output)) as ReportFormat;
				try {
					writeReport(options.output, format, 'batch', file, batchResults);
					console.log(colors.green(`Batch report saved to ${options.output} (${format.toUpperCase()})`));
				} catch (err: any) {
					console.error(colors.red(`Error writing batch report: ${err.message}`));
				}
			}

			if (options.markdownOutput) {
				try {
					writeReport(options.markdownOutput, 'markdown', 'batch', file, batchResults);
					console.log(colors.green(`Batch Markdown report saved to ${options.markdownOutput}`));
				} catch (err: any) {
					console.error(colors.red(`Error writing Markdown report: ${err.message}`));
				}
			}

			if (options.htmlOutput) {
				try {
					writeReport(options.htmlOutput, 'html', 'batch', file, batchResults);
					console.log(colors.green(`Batch HTML report saved to ${options.htmlOutput}`));
				} catch (err: any) {
					console.error(colors.red(`Error writing HTML report: ${err.message}`));
				}
			}

			if (options.threshold !== undefined) {
				const minThreshold = parseThreshold(options.threshold);
				const totalBatchTests = batchResults.reduce((acc, r) => acc + (r.total || 0), 0);
				const totalBatchBlocked = batchResults.reduce((acc, r) => acc + (r.blocked || 0), 0);
				const batchScore = totalBatchTests > 0 ? Math.round((totalBatchBlocked / totalBatchTests) * 100) : 0;
				if (batchScore < minThreshold) {
					console.error(colors.red(`CI/CD Threshold Failed: Overall batch protection score ${batchScore}% is below required threshold of ${minThreshold}%.`));
					process.exit(1);
				}
			}

			if (options.failOnBypass && batchResults.some((r: any) => r.bypassed > 0)) {
				const bypassCount = batchResults.reduce((acc, r) => acc + (r.bypassed || 0), 0);
				console.error(colors.red(`CI/CD Check Failed: ${bypassCount} bypasses detected across batch targets.`));
				process.exit(1);
			}
		} catch (err: any) {
			console.error(`Error: Batch audit failed: ${err.message}`);
			process.exit(1);
		}
	});

// Command: patch
program
	.command('patch <file>')
	.description('Generate ready-to-deploy virtual patches from a saved JSON audit report')
	.option('-w, --waf <vendor>', 'Target WAF vendor (cloudflare, aws, modsecurity, nginx, gcp, azure, haproxy, caddy, k8s, all)', 'all')
	.option('-t, --tier <tier>', 'Defense tier: strict, heuristic, or both', 'both')
	.option('-a, --action <action>', 'Rule action: block or simulate', 'block')
	.option('-o, --output <path>', 'Output file or directory to write patches to')
	.option('--scope-to-path', 'Scope rules to target URL path if present in report', false)
	.option('--include-misses', 'Include 404 Not Found and 5xx origin responses in virtual patch generation', false)
	.option('--json', 'Output patch report in JSON format', false)
	.action(async (file: string, options: any) => {
		try {
			const filePath = path.resolve(file);
			if (!fs.existsSync(filePath)) {
				console.error(colors.red(`Error: File "${file}" does not exist.`));
				process.exit(1);
			}

			const content = fs.readFileSync(filePath, 'utf8');
			const parsed = JSON.parse(content);
			const results: any[] = Array.isArray(parsed) ? parsed : parsed.results || [];
			const targetUrl = parsed.targetUrl || parsed.url;

			const patchReport = generateVirtualPatches(results, {
				vendor: options.waf as PatchVendor,
				tier: options.tier as PatchTier,
				action: options.action as PatchAction,
				scopeToPath: Boolean(options.scopeToPath),
				includeMisses: Boolean(options.includeMisses),
				targetUrl,
			});

			if (options.json) {
				console.log(JSON.stringify(patchReport, null, 2));
				return;
			}

			console.log(`\n=== 🛡️ WAF-Checker Virtual Patch Generator ===`);
			console.log(`Loaded ${results.length} audit test results from: ${colors.cyan(file)}`);
			console.log(`Detected Bypasses to Remediate: ${patchReport.totalBypasses > 0 ? colors.red(String(patchReport.totalBypasses)) : colors.green('0')}`);

			if (patchReport.totalBypasses === 0) {
				console.log(colors.green('No bypasses detected in this audit report. No patches required!'));
				return;
			}

			console.log(`\nGenerated Rules Summary:`);
			for (const [v, b] of Object.entries(patchReport.bundles)) {
				if (b.ruleCount === 0) continue;
				console.log(`  • ${colors.bold(v.toUpperCase().padEnd(12))}: ${colors.green(`${b.ruleCount} rule(s)`)}`);
			}

			if (options.output) {
				const outPath = path.resolve(options.output);
				if (outPath.endsWith('.tf') || outPath.endsWith('.conf') || outPath.endsWith('.json') || outPath.endsWith('.yaml') || outPath.endsWith('.cfg') || outPath.endsWith('.txt')) {
					const dir = path.dirname(outPath);
					if (dir && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
					const bundledText = Object.values(patchReport.bundles)
						.map((b) => b.terraform || b.native)
						.filter(Boolean)
						.join('\n\n');
					fs.writeFileSync(outPath, bundledText, 'utf8');
				} else {
					if (!fs.existsSync(outPath)) fs.mkdirSync(outPath, { recursive: true });
					const extMap: Record<string, string> = {
						cloudflare: 'conf',
						aws: 'json',
						modsecurity: 'conf',
						nginx: 'conf',
						gcp: 'cel',
						azure: 'json',
						haproxy: 'cfg',
						caddy: 'caddyfile',
						k8s: 'yaml',
					};
					for (const [v, b] of Object.entries(patchReport.bundles)) {
						if (b.ruleCount === 0) continue;
						const ext = extMap[v] || 'conf';
						fs.writeFileSync(path.join(outPath, `${v}-patches.${ext}`), b.native, 'utf8');
						if (b.gcloud) {
							fs.writeFileSync(path.join(outPath, `${v}-gcloud.sh`), b.gcloud, 'utf8');
						}
						if (b.azureCli) {
							fs.writeFileSync(path.join(outPath, `${v}-azure-cli.sh`), b.azureCli, 'utf8');
						}
						if (b.terraform) {
							fs.writeFileSync(path.join(outPath, `${v}-patches.tf`), b.terraform, 'utf8');
						}
					}
				}
				console.log(colors.green(`\n[✓] Patches successfully written to: ${options.output}`));
			} else {
				console.log(`\nPreview:`);
				for (const [v, b] of Object.entries(patchReport.bundles)) {
					if (b.ruleCount === 0) continue;
					console.log(`\n--- ${v.toUpperCase()} ---`);
					console.log(b.native);
					if (b.gcloud) {
						console.log(`\n--- ${v.toUpperCase()} (gcloud CLI) ---`);
						console.log(b.gcloud);
					}
					if (b.azureCli) {
						console.log(`\n--- ${v.toUpperCase()} (Azure CLI) ---`);
						console.log(b.azureCli);
					}
					if (b.terraform) {
						console.log(`\n--- ${v.toUpperCase()} (Terraform) ---`);
						console.log(b.terraform);
					}
				}
			}
		} catch (err: any) {
			console.error(colors.red(`Error generating patches: ${err.message}`));
			process.exit(1);
		}
	});

export { program };

if (typeof process !== 'undefined' && process.env.NODE_ENV !== 'test' && !process.env.VITEST) {
	if (process.argv.length <= 2) {
		program.outputHelp();
		process.exit(0);
	}
	program.parse(process.argv);
}
