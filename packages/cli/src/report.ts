import * as fs from 'fs';
import * as path from 'path';
import { generateSARIFReport } from '@waf-checker/core';
import { generateCheckHtml, generateBatchHtml } from './reports/html';
import { generateMarkdownReport, generateBatchMarkdown } from './reports/markdown';

export type ReportFormat = 'json' | 'csv' | 'html' | 'sarif' | 'markdown' | 'md';

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
}

export interface BatchResult {
	url: string;
	success: boolean;
	total: number;
	blocked: number;
	bypassed: number;
	bypassRate: number;
	error?: string;
}

/**
 * Deduce report format from file extension if not explicitly specified.
 */
export function deduceFormat(outputPath: string): ReportFormat {
	const ext = path.extname(outputPath).toLowerCase();
	if (ext === '.sarif') return 'sarif';
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
	const headers = ['Category', 'Method', 'Status', 'Response Time (ms)', 'Is Redirect', 'Payload', 'Error'];
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
			escape(r.payload),
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

import { ReverseEngineeringReport } from '@waf-checker/core';

/**
 * Write check or batch report to file.
 */
export function writeReport(
	outputPath: string,
	format: ReportFormat,
	type: 'check' | 'batch',
	urlOrFile: string,
	results: any[],
	reverseEngineering?: ReverseEngineeringReport
): void {
	let outputContent = '';

	if (format === 'json') {
		if (type === 'check') {
			outputContent = JSON.stringify({ results, reverseEngineering }, null, 2);
		} else {
			outputContent = JSON.stringify(results, null, 2);
		}
	} else if (format === 'sarif') {
		if (type === 'batch') {
			throw new Error('SARIF report format is only supported for single target audits (check command), not batch audits.');
		}
		outputContent = generateSARIFReport(results, urlOrFile, reverseEngineering);
	} else if (format === 'markdown' || format === 'md') {
		if (type === 'check') {
			outputContent = generateMarkdownReport(results as CheckResult[], urlOrFile, reverseEngineering);
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
			: generateBatchHtml(results as BatchResult[]);
	}

	// Ensure target directory exists
	const dir = path.dirname(outputPath);
	if (dir && !fs.existsSync(dir)) {
		fs.mkdirSync(dir, { recursive: true });
	}

	fs.writeFileSync(outputPath, outputContent, 'utf8');
}
