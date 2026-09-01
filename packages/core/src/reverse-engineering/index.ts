import {
	CRSAuditItem,
	ReverseEngineeringOptions,
	ReverseEngineeringReport,
} from './types';
import { OWASP_CRS_RULES } from './crs-rules';
import { detectBodyInspectionLimit } from './body-limit-detector';
import { detectAnomalyScoringMode } from './anomaly-score-detector';
import { probeRateLimit } from './rate-limit-probe';
import { isValidTargetUrl } from '../utils/security';
import { sendRequest } from '../check';

export * from './types';
export * from './crs-rules';
export * from './body-limit-detector';
export * from './anomaly-score-detector';
export * from './rate-limit-probe';

/**
 * Runs a complete WAF Reverse Engineering and OWASP Core Rule Set (CRS) audit on a target URL.
 * Strictly enforces SSRF validation via isValidTargetUrl.
 */
export async function runReverseEngineeringAudit(
	url: string,
	options?: ReverseEngineeringOptions,
): Promise<ReverseEngineeringReport> {
	if (!isValidTargetUrl(url)) {
		throw new Error('Invalid URL or restricted IP');
	}

	// 1. Audit OWASP Core Rule Set (CRS) rules
	const crsItems: CRSAuditItem[] = [];

	// Probe rules with concurrency limit to be respectful
	const chunkSize = 5;
	for (let i = 0; i < OWASP_CRS_RULES.length; i += chunkSize) {
		const chunk = OWASP_CRS_RULES.slice(i, i + chunkSize);
		const chunkPromises = chunk.map(async (rule) => {
			const startTime = Date.now();
			let headersObj: Record<string, string> | undefined = undefined;
			let payload: string | undefined = undefined;
			let method: string = rule.probeMethod || 'GET';

			if (rule.probeLocation === 'header') {
				headersObj = { [rule.headerName || 'X-CRS-Test']: rule.probePayload };
			} else if (rule.probeLocation === 'body') {
				method = 'POST';
				payload = rule.probePayload;
			} else {
				payload = rule.probePayload;
			}

			const res = await sendRequest(
				url,
				method,
				payload,
				headersObj,
				undefined,
				false,
				false,
				undefined,
				undefined,
				{ fetch: options?.fetch, quiet: true },
			);

			const responseTime = Date.now() - startTime;
			const statusCode = res ? res.status : 'ERR';

			let status: 'active' | 'disabled' | 'bypassed' | 'unknown' = 'unknown';
			if (statusCode === 403 || statusCode === 'BLOCKED') {
				status = 'active';
			} else if (typeof statusCode === 'number' && statusCode >= 200 && statusCode < 300) {
				status = 'disabled';
			} else if (statusCode === 'ERR') {
				status = 'unknown';
			} else {
				status = 'unknown';
			}

			const item: CRSAuditItem = {
				ruleId: rule.ruleId,
				name: rule.name,
				category: rule.category,
				paranoiaLevel: rule.paranoiaLevel,
				anomalyScore: rule.anomalyScore,
				status,
				probePayload: rule.probePayload,
				statusCode,
				responseTime,
				evidence: `Status ${statusCode} returned in ${responseTime}ms`,
			};

			return item;
		});

		const chunkResults = await Promise.all(chunkPromises);
		crsItems.push(...chunkResults);
	}

	// 2. Parallel probing for Body Limits, Anomaly Scoring, and Rate Limits
	const [bodyLimit, anomalyScore, rateLimit] = await Promise.all([
		options?.skipBodyLimit
			? Promise.resolve({ detected: false, limitBytes: null, limitFormatted: 'Skipped', confidence: 0 })
			: detectBodyInspectionLimit(url, options),
		options?.skipAnomalyScore
			? Promise.resolve({ mode: 'unknown' as const, detectedThreshold: null, confidence: 0 })
			: detectAnomalyScoringMode(url, options),
		options?.skipRateLimit
			? Promise.resolve({ detected: false, thresholdRps: null, retryAfterSeconds: null, safeTestedMaxRps: 0 })
			: probeRateLimit(url, options),
	]);

	const activeCount = crsItems.filter((r) => r.status === 'active').length;
	const disabledCount = crsItems.filter((r) => r.status === 'disabled').length;
	const bypassedCount = crsItems.filter((r) => r.status === 'bypassed').length;
	const totalRules = crsItems.length;
	const activePercent = totalRules > 0 ? Math.round((activeCount / totalRules) * 100) : 0;

	return {
		targetUrl: url,
		crsRules: crsItems,
		crsSummary: {
			total: totalRules,
			active: activeCount,
			disabled: disabledCount,
			bypassed: bypassedCount,
			activePercent,
		},
		bodyLimit,
		anomalyScore,
		rateLimit,
		timestamp: new Date().toISOString(),
	};
}
