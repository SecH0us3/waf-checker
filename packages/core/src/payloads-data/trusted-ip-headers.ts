/**
 * Curated Trusted IP / Proxy Headers used by the "IP Header bypass" test.
 *
 * Many WAFs, load balancers, or origin servers behind them allow-list loopback
 * or RFC1918 private addresses based on unverified forwarding headers
 * (X-Forwarded-For, X-Real-IP, True-Client-IP, CF-Connecting-IP, etc.).
 * When an attack payload is blocked normally (403/406) but sails through once
 * one of these headers is attached, that perimeter trust is a real bypass.
 */

export interface TrustedIpHeader {
	/** Short, human-friendly label shown in reports (e.g. "XFF-Loopback"). */
	name: string;
	/** HTTP header name to inject (e.g. "X-Forwarded-For"). */
	headerName: string;
	/** HTTP header value to send (e.g. "127.0.0.1"). */
	headerValue: string;
}

export const TRUSTED_IP_HEADERS: TrustedIpHeader[] = [
	{ name: 'XFF-Loopback', headerName: 'X-Forwarded-For', headerValue: '127.0.0.1' },
	{ name: 'XFF-Private-10', headerName: 'X-Forwarded-For', headerValue: '10.0.0.1' },
	{ name: 'XFF-Private-192', headerName: 'X-Forwarded-For', headerValue: '192.168.1.1' },
	{ name: 'X-Real-IP', headerName: 'X-Real-IP', headerValue: '127.0.0.1' },
	{ name: 'True-Client-IP', headerName: 'True-Client-IP', headerValue: '127.0.0.1' },
	{ name: 'X-Cluster-Client-IP', headerName: 'X-Cluster-Client-IP', headerValue: '127.0.0.1' },
	{ name: 'X-Originating-IP', headerName: 'X-Originating-IP', headerValue: '127.0.0.1' },
	{ name: 'X-Client-IP', headerName: 'X-Client-IP', headerValue: '127.0.0.1' },
	{ name: 'Forwarded-Loopback', headerName: 'Forwarded', headerValue: 'for=127.0.0.1;by=127.0.0.1' },
	{ name: 'X-Forwarded-Host-Local', headerName: 'X-Forwarded-Host', headerValue: 'localhost' },
];

/**
 * Resolve the `spoofIpHeaders` option into a concrete list of headers to test.
 * - `false`/`undefined` -> disabled (empty list).
 * - `true` -> the full curated {@link TRUSTED_IP_HEADERS} list.
 * - an array -> used as-is (custom headers).
 */
export function resolveTrustedIpHeaders(spoof?: boolean | TrustedIpHeader[]): TrustedIpHeader[] {
	if (!spoof) return [];
	if (Array.isArray(spoof)) return spoof;
	return TRUSTED_IP_HEADERS;
}
