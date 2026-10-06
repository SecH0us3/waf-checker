import { evaluateWAFVerdict, sendRequest } from '../check';

export type ProbeOutcome = 'blocked' | 'passed' | 'inconclusive';

/**
 * Classifies one probe response the way the main scan does, through
 * evaluateWAFVerdict: 403/406, `cf-mitigated`, captcha and block pages all
 * count as blocked, not just 403 (Signal Sciences, for one, blocks with 406
 * only).
 *
 * A 429 is the exception. It is rate limiting, not the probed rule firing, so
 * like a network error or a request that was never sent ('BLOCKED' is the SSRF
 * guard refusing to send it) it says nothing either way. Reading it as "not
 * blocked" turned rate limiting into reported bypasses.
 */
export function classifyProbe(res: Awaited<ReturnType<typeof sendRequest>> | undefined): ProbeOutcome {
	if (!res) return 'inconclusive';
	const { status } = res;
	if (status === 'ERR' || status === 'BLOCKED' || status === 429 || status === '429') {
		return 'inconclusive';
	}
	return evaluateWAFVerdict(status, res.bodyText || '', undefined, res.response?.headers).blocked ? 'blocked' : 'passed';
}
