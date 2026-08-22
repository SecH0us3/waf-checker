export interface AuditResultItem {
	category: string;
	payload: string;
	originalPayload?: string;
	method: string;
	status: number | string;
	is_redirect?: boolean;
	responseTime: number;
	wafDetected?: boolean;
	wafType?: string;
	bypassTechnique?: string;
}

export interface AuditReportStats {
	total: number;
	blocked: number;
	bypassed: number;
	errors: number;
	other: number;
	protectionScore: number;
	detectedWAF?: string;
	durationMs?: number;
	targetUrl?: string;
	timestamp?: string;
}

export function calculateAuditStats(results: AuditResultItem[], targetUrl?: string): AuditReportStats {
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

	return {
		total,
		blocked,
		bypassed,
		errors,
		other,
		protectionScore,
		detectedWAF,
		targetUrl,
		timestamp: new Date().toISOString(),
	};
}
