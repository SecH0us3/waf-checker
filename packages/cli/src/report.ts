import * as fs from 'fs';
import * as path from 'path';
import { generateSARIFReport, generateMultiTargetSARIFReport, generateJUnitReport } from '@waf-checker/core';
import type { AuditResultItem, SarifTarget } from '@waf-checker/core';
import { generateCheckHtml, generateBatchHtml } from './reports/html';
import { generateMarkdownReport, generateBatchMarkdown } from './reports/markdown';

export type ReportFormat = 'json' | 'csv' | 'html' | 'sarif' | 'markdown' | 'md' | 'junit';

export interface CheckResult {
	status: number | string;
	method: string;
	payload: string;
	responseTime: number;
	category: string;
	is_redirect?: boolean;
	error?: string;
	wafDetected?: boolean;
	wafType?: string;
	bypassTechnique?: string;
	originalPayload?: string;
	blocked?: boolean;
	verdict?: 'blocked' | 'passed' | 'exposed';
	baselineNote?: 'origin_blocked' | 'custom_block_page';
	userAgentBypass?: any;
	ipHeaderBypass?: any;
}

export interface BatchResult {
	url: string;
	success: boolean;
	total: number;
	blocked: number;
	bypassed: number;
	bypassRate: number;
	error?: string;
	/**
	 * Per-payload results of this target. Kept in memory so per-target formats
	 * (SARIF) can be built; stripped from summary formats (JSON, CSV, HTML, Markdown).
	 */
	results?: CheckResult[];
	/** When this target's scan started / finished (ISO 8601 UTC); carried into its SARIF run. */
	startTimeUtc?: string;
	endTimeUtc?: string;
}

/**
 * Drop the per-payload `results` and scan timestamps from batch entries, leaving the summary shape
 * that the JSON batch report and `batch --json` have always emitted.
 */
export function toBatchSummaries(results: BatchResult[]): BatchResult[] {
	return results.map(({ results: _details, startTimeUtc: _start, endTimeUtc: _end, ...summary }) => summary);
}

/**
 * Map batch entries to SARIF targets: one run per successfully scanned target.
 * Failed targets are left out rather than emitted as an empty run, because an
 * empty run would tell GitHub Code Scanning that the target's alerts are fixed.
 */
export function toSarifTargets(results: BatchResult[]): SarifTarget[] {
	return results
		.filter((r) => r.success && Array.isArray(r.results))
		.map((r) => ({
			targetUrl: r.url,
			results: r.results as AuditResultItem[],
			...(r.startTimeUtc ? { startTimeUtc: r.startTimeUtc } : {}),
			...(r.endTimeUtc ? { endTimeUtc: r.endTimeUtc } : {}),
		}));
}

/**
 * Deduce report format from file extension if not explicitly specified.
 */
export function deduceFormat(outputPath: string): ReportFormat {
	const ext = path.extname(outputPath).toLowerCase();
	if (ext === '.sarif') return 'sarif';
	if (ext === '.junit' || ext === '.xml') return 'junit';
	if (ext === '.md' || ext === '.markdown') return 'markdown';
	if (ext === '.json') return 'json';
	if (ext === '.csv') return 'csv';
	if (ext === '.html' || ext === '.htm') return 'html';
	return 'html'; // Default to html
}

/**
 * Generate a CSV report for CheckResults.
 */
function generateCheckCsv(results: CheckResult[]): string {
	const headers = [
		'Category', 'Method', 'Status', 'Response Time (ms)', 'Is Redirect',
		'WAF Type', 'Bypass Technique', 'Verdict', 'Payload', 'Original Payload', 'Error',
	];
	const escape = (val: any) => {
		const str = String(val ?? '');
		if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
			return `"${str.replace(/"/g, '""')}"`;
		}
		return str;
	};

	const lines = [
		headers.join(','),
		...results.map(r => [
			escape(r.category),
			escape(r.method),
			escape(r.status),
			escape(r.responseTime),
			escape(r.is_redirect ? 'Yes' : 'No'),
			escape(r.wafType),
			escape(r.bypassTechnique),
			escape(r.verdict),
			escape(r.payload),
			escape(r.originalPayload),
			escape(r.error)
		].join(','))
	];

	return lines.join('\n');
}

/**
 * Generate a CSV report for BatchResults.
 */
function generateBatchCsv(results: BatchResult[]): string {
	const headers = ['Target URL', 'Success', 'Total Tests', 'Blocked', 'Bypassed', 'Bypass Rate (%)', 'Error'];
	const escape = (val: any) => {
		const str = String(val ?? '');
		if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
			return `"${str.replace(/"/g, '""')}"`;
		}
		return str;
	};

	const lines = [
		headers.join(','),
		...results.map(r => [
			escape(r.url),
			escape(r.success ? 'Yes' : 'No'),
			escape(r.total),
			escape(r.blocked),
			escape(r.bypassed),
			escape(r.bypassRate),
			escape(r.error)
		].join(','))
	];

	return lines.join('\n');
}

import { ReverseEngineeringReport, VirtualPatchReport } from '@waf-checker/core';

/**
 * Write check or batch report to file.
 */
export function writeReport(
	outputPath: string,
	format: ReportFormat,
	type: 'check' | 'batch',
	urlOrFile: string,
	results: any[],
	reverseEngineering?: ReverseEngineeringReport,
	virtualPatches?: VirtualPatchReport
): void {
	let outputContent = '';

	if (format === 'json') {
		if (type === 'check') {
			outputContent = JSON.stringify({ results, reverseEngineering, virtualPatches }, null, 2);
		} else {
			outputContent = JSON.stringify(toBatchSummaries(results as BatchResult[]), null, 2);
		}
	} else if (format === 'sarif') {
		outputContent = type === 'check'
			? generateSARIFReport(results, urlOrFile, reverseEngineering)
			: generateMultiTargetSARIFReport(toSarifTargets(results as BatchResult[]));
	} else if (format === 'junit') {
		if (type === 'batch') {
			throw new Error('JUnit report format is only supported for single target audits (check command), not batch audits.');
		}
		outputContent = generateJUnitReport(results, urlOrFile);
	} else if (format === 'markdown' || format === 'md') {
		if (type === 'check') {
			outputContent = generateMarkdownReport(results as CheckResult[], urlOrFile, reverseEngineering, virtualPatches);
		} else {
			outputContent = generateBatchMarkdown(results as BatchResult[]);
		}
	} else if (format === 'csv') {
		outputContent = type === 'check' 
			? generateCheckCsv(results as CheckResult[])
			: generateBatchCsv(results as BatchResult[]);
	} else {
		outputContent = type === 'check'
			? generateCheckHtml(urlOrFile, results as CheckResult[], reverseEngineering)
			: generateBatchHtml(toBatchSummaries(results as BatchResult[]));
	}

	// Ensure target directory exists
	const dir = path.dirname(outputPath);
	if (dir && !fs.existsSync(dir)) {
		fs.mkdirSync(dir, { recursive: true });
	}

	fs.writeFileSync(outputPath, outputContent, 'utf8');
}
