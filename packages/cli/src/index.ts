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
	PAYLOADS
} from '@waf-checker/core';

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
	.version('1.0.0')
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
	.option('-c, --categories <categories>', 'Payload categories (comma-separated). Supported: SQL Injection, XSS, Path Traversal, Command Injection, SSRF, NoSQL Injection, Local File Inclusion, LDAP Injection, HTTP Request Smuggling, Open Redirect, Sensitive Files, CRLF Injection, UTF8/Unicode Bypass, XXE, SSTI, HTTP Parameter Pollution, Web Cache Poisoning, IP Bypass, User-Agent')
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
	.option('--json', 'Output results in JSON format')
	.addHelpText('after', detailedHelp)
	.action(async (url: string, options: any) => {
		try {
			// Substitution check for validation
			const testUrl = url.replace(/\{PAYLOAD\}/g, 'test-payload');
			if (!isValidTargetUrl(testUrl)) {
				console.error(`Error: Invalid target URL "${url}" or restricted IP.`);
				process.exit(1);
			}

			const customFetch = getFetch(options.proxy);
			const methods = parseCommaList(options.methods) || ['GET'];
			const categories = parseCommaList(options.categories);
			const headers = parseCustomHeaders(options.customHeaders);

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
				options.httpManipulation ? {
					enableParameterPollution: true,
					enableVerbTampering: true,
					enableContentTypeConfusion: true,
				} : undefined,
				{ fetch: customFetch, color: useColor }
			);

			if (options.json) {
				console.log(JSON.stringify(results, null, 2));
				return;
			}

			console.log(`\n=== WAF Audit Results for ${colors.cyan(url)} ===`);
			console.log(`Total tests executed: ${results.length}`);

			const blocked = results.filter((r: any) => r.status === 403 || r.status === 'BLOCKED');
			const bypassed = results.filter((r: any) => r.status === 200 || r.status === '200');
			const redirect = results.filter((r: any) => r.is_redirect);
			const errors = results.filter((r: any) => r.status === 'ERR');

			console.log(`  🛡️ Blocked:   ${colors.green(`${blocked.length} (${results.length ? Math.round(blocked.length / results.length * 100) : 0}%)`)}`);
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
			console.log();
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
	.option('-c, --categories <categories>', 'Payload categories (comma-separated). Supported: SQL Injection, XSS, Path Traversal, Command Injection, SSRF, NoSQL Injection, Local File Inclusion, LDAP Injection, HTTP Request Smuggling, Open Redirect, Sensitive Files, CRLF Injection, UTF8/Unicode Bypass, XXE, SSTI, HTTP Parameter Pollution, Web Cache Poisoning, IP Bypass, User-Agent', 'SQL Injection,XSS')
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
	.option('--concurrency <number>', 'Number of concurrent URLs to test', '3')
	.option('--json', 'Output results in JSON format')
	.addHelpText('after', detailedHelp)
	.action(async (file: string, options: any) => {
		try {
			if (!fs.existsSync(file)) {
				console.error(`Error: File "${file}" does not exist.`);
				process.exit(1);
			}

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

			console.log(`\nStarting batch audit for ${validUrls.length} targets (concurrency = ${concurrency})...\n`);

			const batchResults: any[] = [];
			let completed = 0;
			const totalValidUrls = validUrls.length;

			// Simple concurrent pool processor
			const pool = async () => {
				while (validUrls.length > 0) {
					const url = validUrls.shift();
					if (!url) break;

					try {
						if (!options.json) {
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
							options.httpManipulation ? {
								enableParameterPollution: true,
								enableVerbTampering: true,
								enableContentTypeConfusion: true,
							} : undefined,
							{ fetch: customFetch, color: useColor }
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
						if (!options.json) {
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
		} catch (err: any) {
			console.error(`Error: Batch audit failed: ${err.message}`);
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
