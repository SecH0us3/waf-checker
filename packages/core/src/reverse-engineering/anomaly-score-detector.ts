import { AnomalyScoreResult, ReverseEngineeringOptions } from './types';
import { sendRequest } from '../check';
import { classifyProbe } from './probe-outcome';

/**
 * Detects whether the WAF operates in Collaborative Anomaly Scoring Mode (cumulative threshold)
 * or Traditional Regex Blocking Mode (immediate single-rule match blocking).
 */
export async function detectAnomalyScoringMode(
	url: string,
	options?: ReverseEngineeringOptions,
): Promise<AnomalyScoreResult> {
	// Signal 1: Low Anomaly Score (Score = 2, Notice: multiple parameter occurrence / parameter pollution)
	const signal1Payload = 'p1=alpha&p1=beta';
	
	// Signal 2: Medium Anomaly Score (Score = 3, Warning: suspicious character sequence with multiple %20)
	const signal2Payload = 'p2=test%20%20%20%20value';

	// Signal 3: High Anomaly Score (Score = 5, Critical: classic SQLi token)
	const signal3Payload = "' OR '1'='1";

	// 1. Probe individual sub-critical signals
	const [res1, res2] = await Promise.all([
		sendRequest(url, 'GET', signal1Payload, undefined, undefined, false, false, undefined, undefined, {
			fetch: options?.fetch,
			quiet: true,
			rawPayload: true,
			allowLocal: options?.allowLocal,
		}),
		sendRequest(url, 'GET', signal2Payload, undefined, undefined, false, false, undefined, undefined, {
			fetch: options?.fetch,
			quiet: true,
			rawPayload: true,
			allowLocal: options?.allowLocal,
		}),
	]);

	// Each conclusion below rests on the earlier probes having genuinely passed.
	// A rate-limited or failed probe is not a pass, so it ends the analysis
	// instead of being read as one.
	const inconclusive: AnomalyScoreResult = {
		mode: 'unknown',
		detectedThreshold: null,
		confidence: 0,
		details: 'Inconclusive: probe responses were rate limited or failed.',
	};

	const s1 = classifyProbe(res1);
	const s2 = classifyProbe(res2);
	const s1Blocked = s1 === 'blocked';
	const s2Blocked = s2 === 'blocked';

	// If minor individual signals (Score 2 or 3) are individually blocked with 403,
	// the WAF is operating in Traditional Strict Single-Rule Blocking Mode.
	if (s1Blocked || s2Blocked) {
		return {
			mode: 'traditional_regex',
			detectedThreshold: null,
			confidence: 90,
			details: 'WAF blocks isolated low-score notice/warning rules immediately, without score accumulation.',
		};
	}
	if (s1 === 'inconclusive' || s2 === 'inconclusive') {
		return inconclusive;
	}

	// 2. Probe combined composite signal (Signal 1 + Signal 2 -> Cumulative Score = 5)
	const compositeScore5 = `${signal1Payload}&${signal2Payload}`;
	const resScore5 = await sendRequest(
		url,
		'GET',
		compositeScore5,
		undefined,
		undefined,
		false,
		false,
		undefined,
		undefined,
		{ fetch: options?.fetch, quiet: true, rawPayload: true, allowLocal: options?.allowLocal },
	);

	const score5 = classifyProbe(resScore5);
	if (score5 === 'inconclusive') {
		return inconclusive;
	}
	if (score5 === 'blocked') {
		return {
			mode: 'anomaly_scoring',
			detectedThreshold: 5,
			confidence: 95,
			details: 'Collaborative Anomaly Scoring Mode detected: isolated low-severity rules pass, but cumulative score >= 5 triggers a block.',
		};
	}

	// 3. Probe critical individual signal (Score = 5)
	const resCritical = await sendRequest(
		url,
		'GET',
		signal3Payload,
		undefined,
		undefined,
		false,
		false,
		undefined,
		undefined,
		{ fetch: options?.fetch, quiet: true, rawPayload: true, allowLocal: options?.allowLocal },
	);

	const critical = classifyProbe(resCritical);
	if (critical === 'inconclusive') {
		return inconclusive;
	}
	if (critical === 'blocked') {
		// Individual critical rule blocks at score 5
		return {
			mode: 'anomaly_scoring',
			detectedThreshold: 5,
			confidence: 85,
			details: 'Standard Anomaly Scoring threshold 5 (Default OWASP CRS profile).',
		};
	}

	// 4. Probe combined high composite signal (Cumulative Score >= 10)
	const compositeScore10 = `${signal1Payload}&${signal2Payload}&extra=${encodeURIComponent(signal3Payload)}`;
	const resScore10 = await sendRequest(
		url,
		'GET',
		compositeScore10,
		undefined,
		undefined,
		false,
		false,
		undefined,
		undefined,
		{ fetch: options?.fetch, quiet: true, rawPayload: true, allowLocal: options?.allowLocal },
	);

	const score10 = classifyProbe(resScore10);
	if (score10 === 'inconclusive') {
		return inconclusive;
	}
	if (score10 === 'blocked') {
		return {
			mode: 'anomaly_scoring',
			detectedThreshold: 10,
			confidence: 80,
			details: 'Relaxed Anomaly Scoring threshold detected (Score >= 10).',
		};
	}

	return {
		mode: 'unknown',
		detectedThreshold: null,
		confidence: 50,
		details: 'Unable to conclusively differentiate anomaly scoring mode from probe responses.',
	};
}
