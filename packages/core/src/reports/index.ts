export * from './types';
export * from './sarif';
export * from './markdown';
export * from './html';

import { AuditResultItem, calculateAuditStats } from './types';
import { generateSARIFReport } from './sarif';
import { generateMarkdownReport } from './markdown';
import { generateHTMLReport } from './html';

export function generateJSONReport(results: AuditResultItem[], targetUrl?: string): string {
	const stats = calculateAuditStats(results, targetUrl);
	return JSON.stringify(
		{
			summary: stats,
			results,
		},
		null,
		2,
	);
}

export type ReportFormat = 'sarif' | 'markdown' | 'html' | 'json';

export function generateReport(
	format: ReportFormat,
	results: AuditResultItem[],
	targetUrl?: string,
): string {
	switch (format) {
		case 'sarif':
			return generateSARIFReport(results, targetUrl);
		case 'markdown':
			return generateMarkdownReport(results, targetUrl);
		case 'html':
			return generateHTMLReport(results, targetUrl);
		case 'json':
		default:
			return generateJSONReport(results, targetUrl);
	}
}
