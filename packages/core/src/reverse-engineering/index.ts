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
import { classifyProbe } from './probe-outcome';

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
	if (!isValidTargetUrl(url, { allowLocal: options?.allowLocal })) {
		throw new Error('Invalid URL or restricted IP');
	}

	// 1. Audit OWASP Core Rule Set (CRS) rules
	const crsItems: CRSAuditItem[] = [];

	// Probe rules with rolling concurrency to maximize throughput and be respectful
	const concurrencyLimit = 5;
	let ruleIndex = 0;

	const worker = async () => {
		while (ruleIndex < OWASP_CRS_RULES.length) {
			const currentIndex = ruleIndex++;
			const rule = OWASP_CRS_RULES[currentIndex];
			
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
				{ fetch: options?.fetch, quiet: true, rawPayload: true, allowLocal: options?.allowLocal },
			);

			const responseTime = Date.now() - startTime;
			const statusCode = res ? res.status : 'ERR';

			// 'disabled' claims the rule is off, so it needs a real pass: a 2xx that
			// is not a block page. A 2xx block page counts as active, and anything
			// rate limited, failed or otherwise unclear stays 'unknown'.
			const outcome = classifyProbe(res);
			let status: 'active' | 'disabled' | 'bypassed' | 'unknown' = 'unknown';
			if (outcome === 'blocked') {
				status = 'active';
			} else if (outcome === 'passed' && typeof statusCode === 'number' && statusCode >= 200 && statusCode < 300) {
				status = 'disabled';
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

			crsItems[currentIndex] = item;
		}
	};

	const workers = Array.from({ length: Math.min(concurrencyLimit, OWASP_CRS_RULES.length) }, () => worker());
	await Promise.all(workers);

	// 2. Body limit and anomaly scoring in parallel, then the rate-limit probe on
	// its own. The rate-limit probe pushes the target until it answers 429, and
	// run alongside the others it rate-limited their probes too.
	const [bodyLimit, anomalyScore] = await Promise.all([
		options?.skipBodyLimit
			? Promise.resolve({ detected: false, limitBytes: null, limitFormatted: 'Skipped', confidence: 0 })
			: detectBodyInspectionLimit(url, options),
		options?.skipAnomalyScore
			? Promise.resolve({ mode: 'unknown' as const, detectedThreshold: null, confidence: 0 })
			: detectAnomalyScoringMode(url, options),
	]);
	const rateLimit = options?.skipRateLimit
		? { detected: false, thresholdRps: null, retryAfterSeconds: null, safeTestedMaxRps: 0 }
		: await probeRateLimit(url, options);

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
