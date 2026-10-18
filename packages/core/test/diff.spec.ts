import { describe, it, expect } from 'vitest';
import {
	classifyScanStatus,
	scanResultKey,
	diffScans,
	parseStoredReport,
	generateJSONReport,
	AuditResultItem,
} from '../src/reports';

function item(partial: Partial<AuditResultItem>): AuditResultItem {
	return {
		category: 'SQL Injection',
		payload: "' OR 1=1--",
		method: 'GET',
		status: 403,
		responseTime: 10,
		...partial,
	};
}

describe('classifyScanStatus', () => {
	it('prefers the baseline-aware verdict over raw status', () => {
		expect(classifyScanStatus(item({ verdict: 'blocked', status: 200 }))).toBe('blocked');
		expect(classifyScanStatus(item({ verdict: 'exposed', status: 403 }))).toBe('exposed');
		expect(classifyScanStatus(item({ verdict: 'passed', status: 200 }))).toBe('passed');
	});

	it('treats network errors and origin-side blocks as inconclusive', () => {
		expect(classifyScanStatus(item({ error: 'timeout', status: 'ERR' }))).toBe('inconclusive');
		expect(classifyScanStatus(item({ blocked: false, baselineNote: 'origin_blocked', status: 403 }))).toBe('inconclusive');
	});

	it('falls back to the blocked flag and status heuristics for older reports', () => {
		expect(classifyScanStatus(item({ blocked: true, status: 200 }))).toBe('blocked');
		expect(classifyScanStatus(item({ status: 'BLOCKED' }))).toBe('blocked');
		expect(classifyScanStatus(item({ status: 200 }))).toBe('exposed');
		expect(classifyScanStatus(item({ status: 404 }))).toBe('passed');
		expect(classifyScanStatus(item({ status: 500 }))).toBe('inconclusive');
	});
});

describe('scanResultKey', () => {
	it('distinguishes encoded variants of the same payload', () => {
		const plain = item({ bypassTechnique: undefined });
		const encoded = item({ bypassTechnique: 'double-url-encode' });
		expect(scanResultKey(plain)).not.toBe(scanResultKey(encoded));
	});

	it('is stable regardless of outcome fields', () => {
		const blocked = item({ verdict: 'blocked', status: 403 });
		const bypassed = item({ verdict: 'exposed', status: 200 });
		expect(scanResultKey(blocked)).toBe(scanResultKey(bypassed));
	});
});

describe('diffScans', () => {
	it('flags a previously blocked payload that now leaks as a regression', () => {
		const prev = [item({ verdict: 'blocked' })];
		const curr = [item({ verdict: 'exposed', status: 200 })];
		const diff = diffScans(prev, curr);
		expect(diff.hasRegressions).toBe(true);
		expect(diff.regressions).toHaveLength(1);
		expect(diff.regressions[0]).toMatchObject({ from: 'blocked', to: 'exposed', category: 'SQL Injection' });
		expect(diff.improvements).toHaveLength(0);
	});

	it('flags a previously bypassed payload that is now blocked as an improvement', () => {
		const prev = [item({ verdict: 'exposed', status: 200 })];
		const curr = [item({ verdict: 'blocked' })];
		const diff = diffScans(prev, curr);
		expect(diff.hasRegressions).toBe(false);
		expect(diff.improvements).toHaveLength(1);
		expect(diff.improvements[0]).toMatchObject({ from: 'exposed', to: 'blocked' });
	});

	it('counts identical outcomes as unchanged', () => {
		const prev = [item({ verdict: 'blocked' })];
		const curr = [item({ verdict: 'blocked' })];
		const diff = diffScans(prev, curr);
		expect(diff.unchanged).toBe(1);
		expect(diff.regressions).toHaveLength(0);
		expect(diff.improvements).toHaveLength(0);
	});

	it('tracks added and removed tests', () => {
		const prev = [item({ category: 'XSS', payload: '<script>' })];
		const curr = [item({ category: 'SQL Injection', payload: "' OR 1=1--" })];
		const diff = diffScans(prev, curr);
		expect(diff.added).toHaveLength(1);
		expect(diff.added[0]).toMatchObject({ category: 'SQL Injection', to: 'blocked' });
		expect(diff.added[0].from).toBeUndefined();
		expect(diff.removed).toHaveLength(1);
		expect(diff.removed[0]).toMatchObject({ category: 'XSS', from: 'blocked' });
		expect(diff.removed[0].to).toBeUndefined();
	});

	it('does not treat transitions to/from inconclusive as regressions or improvements', () => {
		const prev = [item({ verdict: 'blocked' })];
		const curr = [item({ error: 'timeout', status: 'ERR' })];
		const diff = diffScans(prev, curr);
		expect(diff.regressions).toHaveLength(0);
		expect(diff.improvements).toHaveLength(0);
		expect(diff.otherChanges).toBe(1);
	});

	it('sorts hard leaks (exposed) ahead of silent un-blocks (passed)', () => {
		const prev = [
			item({ category: 'XSS', payload: 'a', verdict: 'blocked' }),
			item({ category: 'SQLi', payload: 'b', verdict: 'blocked' }),
		];
		const curr = [
			item({ category: 'XSS', payload: 'a', verdict: 'passed', status: 404 }),
			item({ category: 'SQLi', payload: 'b', verdict: 'exposed', status: 200 }),
		];
		const diff = diffScans(prev, curr);
		expect(diff.regressions.map((r) => r.to)).toEqual(['exposed', 'passed']);
	});

	it('lets the last occurrence win on duplicate keys', () => {
		const prev = [item({ verdict: 'blocked' }), item({ verdict: 'exposed', status: 200 })];
		const curr = [item({ verdict: 'blocked' })];
		const diff = diffScans(prev, curr);
		// prev collapses to 'exposed' (last wins) -> now blocked = improvement, not regression
		expect(diff.improvements).toHaveLength(1);
		expect(diff.regressions).toHaveLength(0);
	});
});

describe('parseStoredReport', () => {
	it('reads the { summary, results } envelope produced by generateJSONReport', () => {
		const json = generateJSONReport([item({ verdict: 'blocked' })], 'https://example.com');
		const parsed = parseStoredReport(json);
		expect(parsed).toHaveLength(1);
		expect(parsed[0].category).toBe('SQL Injection');
	});

	it('reads a bare results array', () => {
		const json = JSON.stringify([item({ verdict: 'blocked' })]);
		expect(parseStoredReport(json)).toHaveLength(1);
	});

	it('throws on invalid JSON', () => {
		expect(() => parseStoredReport('not json')).toThrow(/not valid JSON/);
	});

	it('throws on a shape that has no results', () => {
		expect(() => parseStoredReport(JSON.stringify({ summary: {} }))).toThrow(/must be a JSON array/);
	});
});
