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
	/** Did the WAF stop this request before it reached the origin? */
	blocked?: boolean;
	/** Coarse outcome: 'blocked' by WAF, 'passed' without leak (404/5xx), or 'exposed' with resource leak */
	verdict?: 'blocked' | 'passed' | 'exposed';
	/** Error category if request failed (e.g. 'timeout', 'network_error') */
	error?: string | null;
	/**
	 * Populated only when the baseline request was blocked (403) AND the
	 * legitimate-User-Agent bypass test was enabled. Describes which trusted
	 * identities (Googlebot, Slackbot, ...) got the otherwise-blocked request
	 * through — i.e. a User-Agent allow-list bypass.
	 */
	userAgentBypass?: UserAgentBypassInfo;
}

/** A single legitimate identity that turned a blocked request into a non-blocked one. */
export interface UserAgentBypassHit {
	/** Friendly name of the trusted identity, e.g. "Googlebot". */
	name: string;
	/** The exact User-Agent header value that was sent. */
	userAgent: string;
	/** Response status observed with the spoofed identity. */
	status: number | string;
	/** Verdict with the spoofed identity ('passed' or 'exposed'). */
	verdict: 'passed' | 'exposed';
}

/** Result of replaying a blocked (403) request under trusted User-Agents. */
export interface UserAgentBypassInfo {
	/** True if at least one legitimate User-Agent bypassed the block. */
	bypassed: boolean;
	/** How many trusted identities were replayed. */
	tested: number;
	/** The identities that got through (empty when nothing bypassed). */
	hits: UserAgentBypassHit[];
}

export interface CheckResultEnvelope {
	results: AuditResultItem[];
	page: number;
	pageSize: number;
	total: number;
	hasMore: boolean;
}

import { ReverseEngineeringReport } from '../reverse-engineering/types';

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
	reverseEngineering?: ReverseEngineeringReport;
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
