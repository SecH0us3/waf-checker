import {
	handleApiCheckWithEnvelope,
	calculateAuditStats,
	WAFDetector,
} from '@waf-checker/core';

export interface MonitorScanResult {
	wafDetected: string;
	summary: {
		blocked: number;
		passed: number;
		total: number;
	};
}

/**
 * Runs a deterministic security scan of targetUrl for scheduled monitoring.
 * Uses fixed parameters (page 0, GET, no advanced/encoding variations, pageSize 15)
 * to ensure day-to-day diff comparability while respecting Cloudflare Worker subrequest limits.
 */
export async function runMonitorScan(targetUrl: string): Promise<MonitorScanResult> {
	let wafDetected = 'None detected';
	try {
		const detection = await WAFDetector.activeDetection(targetUrl.replace(/\{PAYLOAD\}/g, ''), {
			isWorker: true,
		});
		if (detection?.detected && detection.wafType) {
			wafDetected = detection.wafType;
		}
	} catch {
		// Detection error is non-fatal; proceed with envelope check
	}

	const envelope = await handleApiCheckWithEnvelope(
		targetUrl,
		0,
		['GET'],
		undefined, // all categories
		undefined, // payloadTemplate
		true,      // followRedirect
		undefined, // customHeaders
		false,     // falsePositiveTest
		false,     // caseSensitiveTest
		false,     // useEnhancedPayloads
		false,     // useAdvancedPayloads
		false,     // autoDetectWAF (handled above)
		false,     // useEncodingVariations
		wafDetected !== 'None detected' ? wafDetected : undefined,
		undefined, // httpManipulation
		{ isWorker: true, pageSize: 15 }
	);

	const stats = calculateAuditStats(envelope.results, targetUrl);
	if (stats.detectedWAF && stats.detectedWAF !== 'Unknown' && wafDetected === 'None detected') {
		wafDetected = stats.detectedWAF;
	}

	return {
		wafDetected,
		summary: {
			blocked: stats.blocked,
			passed: stats.bypassed, // Number of bypassed attack vectors (status 200)
			total: stats.total,
		},
	};
}
