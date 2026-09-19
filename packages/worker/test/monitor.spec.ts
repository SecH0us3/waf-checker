import { describe, it, expect } from 'vitest';
import { computeFingerprint, diffFingerprints } from '../src/services/monitor';
import { BaselineFingerprint } from '../types/monitor';

describe('Monitor & Diff Engine', () => {
	it('computes baseline fingerprint from scan summary', () => {
		const fp = computeFingerprint({
			wafDetected: 'Cloudflare',
			summary: { blocked: 45, passed: 5, total: 50 },
		});
		expect(fp.wafDetected).toBe('Cloudflare');
		expect(fp.blockedCount).toBe(45);
		expect(fp.bypassedCount).toBe(5);
		expect(fp.totalCount).toBe(50);
		expect(fp.scanHash).toBeDefined();
	});

	it('detects degradation as alert when bypasses increase', () => {
		const oldFp: BaselineFingerprint = {
			wafDetected: 'Cloudflare',
			blockedCount: 48,
			bypassedCount: 2,
			totalCount: 50,
			scanHash: 'h1',
			scannedAt: 1000,
		};
		const newFp: BaselineFingerprint = {
			wafDetected: 'Cloudflare',
			blockedCount: 40,
			bypassedCount: 10,
			totalCount: 50,
			scanHash: 'h2',
			scannedAt: 2000,
		};
		const diff = diffFingerprints(oldFp, newFp);
		expect(diff.changed).toBe(true);
		expect(diff.isAlert).toBe(true);
		expect(diff.details.some((d) => d.includes('Увеличилось число пропущенных атак'))).toBe(true);
	});

	it('detects WAF vendor change as alert', () => {
		const oldFp: BaselineFingerprint = {
			wafDetected: 'Cloudflare',
			blockedCount: 50,
			bypassedCount: 0,
			totalCount: 50,
			scanHash: 'h1',
			scannedAt: 1000,
		};
		const newFp: BaselineFingerprint = {
			wafDetected: 'Не обнаружен',
			blockedCount: 50,
			bypassedCount: 0,
			totalCount: 50,
			scanHash: 'h2',
			scannedAt: 2000,
		};
		const diff = diffFingerprints(oldFp, newFp);
		expect(diff.changed).toBe(true);
		expect(diff.isAlert).toBe(true);
	});

	it('reports no alert if scan state is stable', () => {
		const fp: BaselineFingerprint = {
			wafDetected: 'Cloudflare',
			blockedCount: 50,
			bypassedCount: 0,
			totalCount: 50,
			scanHash: 'h1',
			scannedAt: 1000,
		};
		const diff = diffFingerprints(fp, { ...fp, scannedAt: 2000 });
		expect(diff.changed).toBe(false);
		expect(diff.isAlert).toBe(false);
	});
});
