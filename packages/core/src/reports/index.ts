export * from './types';
export * from './sarif';

import { AuditReportStats, AuditResultItem, calculateAuditStats } from './types';
import { generateSARIFReport } from './sarif';

export function generateJSONReport(
	results: AuditResultItem[],
	targetUrl?: string,
	statsOverride?: Partial<AuditReportStats>,
): string {
	const stats = { ...calculateAuditStats(results, targetUrl), ...statsOverride };
	return JSON.stringify(
		{
			summary: stats,
			results,
		},
		null,
		2,
	);
}

export type ReportFormat = 'sarif' | 'json';

export function generateReport(
	format: ReportFormat,
	results: AuditResultItem[],
	targetUrl?: string,
	statsOverride?: Partial<AuditReportStats>,
): string {
	switch (format) {
		case 'sarif':
			return generateSARIFReport(results, targetUrl);
		case 'json':
		default:
			return generateJSONReport(results, targetUrl, statsOverride);
	}
}
