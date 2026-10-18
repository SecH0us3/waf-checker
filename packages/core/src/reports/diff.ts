/**
 * Scan-to-scan regression diffing.
 *
 * Each WAF scan is self-contained, but WAF posture drifts over time: a vendor
 * ships a managed-ruleset update, someone disables a CRS rule, an origin change
 * shifts a verdict. This module compares a freshly produced result set against a
 * previously saved JSON report and classifies every test as a regression (a
 * payload that used to be blocked and no longer is), an improvement, an added
 * test, or a removed test — so CI can fail on *worsening* rather than
 * re-triaging the full result list on every run.
 */

import { AuditResultItem, AuditReportStats } from './types';

/**
 * Normalized outcome of a single payload test, derived from the richer
 * {@link AuditResultItem}. `inconclusive` covers network errors and
 * origin-side blocks (not a WAF decision), which must never be read as a
 * regression or improvement.
 */
export type ScanStatus = 'blocked' | 'exposed' | 'passed' | 'inconclusive';

/** Shape of a saved JSON report, as produced by {@link generateJSONReport}. */
export interface StoredScanReport {
	summary?: AuditReportStats;
	results: AuditResultItem[];
}

/** A single test whose outcome changed between the two scans. */
export interface ScanDiffEntry {
	category: string;
	method: string;
	payload: string;
	bypassTechnique?: string;
	/** Previous outcome (undefined for an added test). */
	from?: ScanStatus;
	/** Current outcome (undefined for a removed test). */
	to?: ScanStatus;
}

export interface ScanDiff {
	/** Tests that were blocked before and are no longer blocked (WAF got worse). */
	regressions: ScanDiffEntry[];
	/** Tests that were not blocked before and are blocked now (WAF got better). */
	improvements: ScanDiffEntry[];
	/** Tests present now but absent from the previous report. */
	added: ScanDiffEntry[];
	/** Tests present in the previous report but absent now. */
	removed: ScanDiffEntry[];
	/** Count of tests whose outcome was identical in both scans. */
	unchanged: number;
	/**
	 * Count of changed tests that are neither a regression nor an improvement
	 * (e.g. transitions to/from `inconclusive`, or exposed <-> passed shifts
	 * where the WAF never blocked in the first place).
	 */
	otherChanges: number;
	/** True when at least one regression was found. */
	hasRegressions: boolean;
}

/**
 * Collapse an {@link AuditResultItem} into a {@link ScanStatus}.
 *
 * Priority: hard errors and origin-side blocks are inconclusive; otherwise the
 * baseline-aware `verdict` wins; then the explicit `blocked` flag; then a status
 * heuristic as a last resort for older/partial reports.
 */
export function classifyScanStatus(item: AuditResultItem): ScanStatus {
	if (item.error) return 'inconclusive';
	// Origin returned the block itself — not a WAF verdict, so not comparable.
	if (item.baselineNote === 'origin_blocked') return 'inconclusive';

	if (item.verdict === 'blocked') return 'blocked';
	if (item.verdict === 'exposed') return 'exposed';
	if (item.verdict === 'passed') return 'passed';

	if (item.blocked === true) return 'blocked';

	const s = item.status;
	if (s === 403 || s === '403' || s === 'BLOCKED') return 'blocked';
	if (s === 'ERR' || s === 'timeout' || s === 500 || s === '500') return 'inconclusive';
	if (s === 200 || s === '200') return 'exposed';
	// Not blocked, no leak (404, 3xx, other 4xx/5xx without content).
	return 'passed';
}

const KEY_SEP = '\u0000';

/**
 * Stable identity for a single test across runs: the category, method, the
 * exact payload sent, and the evasion technique (so an encoded variant does not
 * collide with its plain form).
 */
export function scanResultKey(item: AuditResultItem): string {
	return [item.category, item.method, item.bypassTechnique ?? '', item.payload].join(KEY_SEP);
}

function toEntry(item: AuditResultItem, from: ScanStatus | undefined, to: ScanStatus | undefined): ScanDiffEntry {
	const entry: ScanDiffEntry = {
		category: item.category,
		method: item.method,
		payload: item.payload,
	};
	if (item.bypassTechnique) entry.bypassTechnique = item.bypassTechnique;
	if (from !== undefined) entry.from = from;
	if (to !== undefined) entry.to = to;
	return entry;
}

// Hard leaks sort ahead of silent un-blocks when listing regressions.
const REGRESSION_RANK: Record<string, number> = { exposed: 0, passed: 1 };

/**
 * Compare a previous scan's results against the current scan's results.
 *
 * Matching is by {@link scanResultKey}; when a report contains duplicate keys
 * the last occurrence wins, mirroring a map insert.
 */
export function diffScans(previous: AuditResultItem[], current: AuditResultItem[]): ScanDiff {
	const prevMap = new Map<string, AuditResultItem>();
	for (const p of previous) prevMap.set(scanResultKey(p), p);
	const currMap = new Map<string, AuditResultItem>();
	for (const c of current) currMap.set(scanResultKey(c), c);

	const regressions: ScanDiffEntry[] = [];
	const improvements: ScanDiffEntry[] = [];
	const added: ScanDiffEntry[] = [];
	const removed: ScanDiffEntry[] = [];
	let unchanged = 0;
	let otherChanges = 0;

	for (const [key, curr] of currMap) {
		const to = classifyScanStatus(curr);
		const prev = prevMap.get(key);
		if (!prev) {
			added.push(toEntry(curr, undefined, to));
			continue;
		}
		const from = classifyScanStatus(prev);
		if (from === to) {
			unchanged++;
		} else if (from === 'blocked' && (to === 'exposed' || to === 'passed')) {
			regressions.push(toEntry(curr, from, to));
		} else if ((from === 'exposed' || from === 'passed') && to === 'blocked') {
			improvements.push(toEntry(curr, from, to));
		} else {
			otherChanges++;
		}
	}

	for (const [key, prev] of prevMap) {
		if (!currMap.has(key)) {
			removed.push(toEntry(prev, classifyScanStatus(prev), undefined));
		}
	}

	regressions.sort(
		(a, b) => (REGRESSION_RANK[a.to ?? 'passed'] ?? 2) - (REGRESSION_RANK[b.to ?? 'passed'] ?? 2),
	);

	return {
		regressions,
		improvements,
		added,
		removed,
		unchanged,
		otherChanges,
		hasRegressions: regressions.length > 0,
	};
}

/**
 * Parse a saved report, accepting both the full `{ summary, results }` envelope
 * and a bare results array. Throws a descriptive error on malformed input.
 */
export function parseStoredReport(json: string): AuditResultItem[] {
	let parsed: unknown;
	try {
		parsed = JSON.parse(json);
	} catch (err: any) {
		throw new Error(`Comparison report is not valid JSON: ${err.message}`);
	}
	if (Array.isArray(parsed)) return parsed as AuditResultItem[];
	if (parsed && typeof parsed === 'object' && Array.isArray((parsed as StoredScanReport).results)) {
		return (parsed as StoredScanReport).results;
	}
	throw new Error('Comparison report must be a JSON array of results or an object with a "results" array.');
}
