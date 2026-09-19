import { BaselineFingerprint } from '../types/monitor';

export function computeFingerprint(result: {
	wafDetected?: string;
	summary?: { blocked: number; passed: number; total: number };
}): BaselineFingerprint {
	const wafDetected = result.wafDetected || 'Не обнаружен';
	const blockedCount = result.summary?.blocked ?? 0;
	const bypassedCount = result.summary?.passed ?? 0;
	const totalCount = result.summary?.total ?? blockedCount + bypassedCount;

	const scanHash = `${wafDetected}:${blockedCount}:${bypassedCount}:${totalCount}`;

	return {
		wafDetected,
		blockedCount,
		bypassedCount,
		totalCount,
		scanHash,
		scannedAt: Date.now(),
	};
}

export function diffFingerprints(
	oldFp: BaselineFingerprint,
	newFp: BaselineFingerprint
): { changed: boolean; isAlert: boolean; details: string[] } {
	const details: string[] = [];
	let isAlert = false;

	if (oldFp.wafDetected !== newFp.wafDetected) {
		details.push(`Изменился статус WAF: было "${oldFp.wafDetected}", стало "${newFp.wafDetected}".`);
		isAlert = true;
	}

	if (newFp.bypassedCount > oldFp.bypassedCount) {
		const delta = newFp.bypassedCount - oldFp.bypassedCount;
		details.push(`Увеличилось число пропущенных атак (+${delta}): теперь пропускается ${newFp.bypassedCount} из ${newFp.totalCount}.`);
		isAlert = true;
	} else if (newFp.bypassedCount < oldFp.bypassedCount) {
		const delta = oldFp.bypassedCount - newFp.bypassedCount;
		details.push(`Защита улучшилась: заблокировано на ${delta} атак больше.`);
	}

	const changed = details.length > 0 || oldFp.scanHash !== newFp.scanHash;

	return { changed, isAlert, details };
}
