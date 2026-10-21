/**
 * The single host normalizer. Every place that validates a host, compares two
 * hosts, or derives a key from one must route through this, so that validation
 * and use can never disagree about what the host is.
 *
 * Canonicalizes: case, and the trailing root dot (`localhost.` and `localhost`
 * resolve identically, so they must compare identically — a mismatch here is a
 * silent bypass of any equality check against a blocked name).
 *
 * The WHATWG URL parser has already canonicalized IPv4 literals in every
 * notation (`0177.0.0.1`, `2130706433`, `127.1` all arrive as `127.0.0.1`) and
 * compressed IPv6, so this deliberately does not re-implement that.
 */
export function normalizeHostname(host: string): string {
	let normalized = host.toLowerCase().trim();
	// IPv6 literals keep their brackets; only DNS names carry a root dot.
	if (!normalized.startsWith('[') && normalized.endsWith('.')) {
		normalized = normalized.slice(0, -1);
	}
	return normalized;
}

export function isValidTargetUrl(urlString: string, options: { allowLocal?: boolean } = {}): boolean {
	try {
		const url = new URL(urlString);

		if (url.protocol !== 'http:' && url.protocol !== 'https:') {
			return false;
		}

		if (options.allowLocal) {
			return true;
		}

		let hostname = normalizeHostname(url.hostname);

		// Block localhost and link-local ranges
		if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '::1') {
			return false;
		}

		// IPv6 normalization: remove brackets for easier parsing if present
		const isIpv6 = hostname.startsWith('[') && hostname.endsWith(']');
		const ipv6Normalized = isIpv6 ? hostname.slice(1, -1) : '';


		// Block the unspecified address (::)
		if (ipv6Normalized === '::') {
			return false;
		}

		// Block IPv6 internal ranges

		// Unique Local Address (fc00::/7)
		if (ipv6Normalized.toLowerCase().startsWith('fc') || ipv6Normalized.toLowerCase().startsWith('fd')) {
			return false;
		}
		// Link-Local Address (fe80::/10)
		if (
			ipv6Normalized.toLowerCase().startsWith('fe8') ||
			ipv6Normalized.toLowerCase().startsWith('fe9') ||
			ipv6Normalized.toLowerCase().startsWith('fea') ||
			ipv6Normalized.toLowerCase().startsWith('feb')
		) {
			return false;
		}
		// Site-Local Address (fec0::/10, deprecated but still routed on some networks)
		if (
			ipv6Normalized.toLowerCase().startsWith('fec') ||
			ipv6Normalized.toLowerCase().startsWith('fed') ||
			ipv6Normalized.toLowerCase().startsWith('fee') ||
			ipv6Normalized.toLowerCase().startsWith('fef')
		) {
			return false;
		}


		// Check for IPv4-compatible IPv6 (::0:0/96)
		if (ipv6Normalized.toLowerCase().startsWith('::') && !ipv6Normalized.toLowerCase().startsWith('::ffff:') && ipv6Normalized !== '::1') {
			const hex = ipv6Normalized.toLowerCase().replace(/^::/, '');

			// e.g. ::7f00:1
			if (hex.startsWith('7f')) return false; // 127.0.0.0/8

			// 10.0.0.0/8 hex is 0a00:0000 to 0aff:ffff. Normalized can be a00:0 to a00:ffff
if (hex.match(/^a[0-9a-f]{2}(:|$)/)) return false;

			if (hex.startsWith('ac')) {
				// 172.16.0.0/12 -> ac10:0000 to ac1f:ffff
const match = hex.match(/^ac1[0-9a-f]/);
				if (match) return false;
			}
			if (hex.startsWith('c0a8')) return false; // 192.168.0.0/16
			if (hex.startsWith('a9fe')) return false; // 169.254.0.0/16

			// Additional ranges
			if (hex.startsWith('6440') || (hex.startsWith('64:') && hex.slice(3).match(/^[4-7]/))) return false; // 100.64.0.0/10

			if (hex.startsWith('c000:')) return false; // 192.0.0.0/24 covers c000:0 to c000:ff
			if (hex === 'c000') return false;

			if (hex.startsWith('c612') || hex.startsWith('c613') || hex.startsWith('c6:12') || hex.startsWith('c6:13')) return false; // 198.18.0.0/15
			if (hex.startsWith('c633:64') || hex.startsWith('c633:100:')) return false; // 198.51.100.0/24
			if (hex.startsWith('cb00:71') || hex.startsWith('cb00:113:')) return false; // 203.0.113.0/24
		}

		// Check for IPv4-mapped IPv6 (::ffff:0:0/96)
		if (ipv6Normalized.toLowerCase().startsWith('::ffff:')) {
			const lastPart = ipv6Normalized.split(':').pop() || '';
			if (lastPart.includes('.')) {
				hostname = lastPart; // Treat it as IPv4 for the next check
			} else {
				const hex = ipv6Normalized.toLowerCase().replace(/^::ffff:/, '');
				// Handle hex-encoded IPv4-mapped IPv6
				if (hex.startsWith('7f')) return false; // 127.0.0.0/8
if (hex.match(/^a[0-9a-f]{2}(:|$)/)) return false; // 10.0.0.0/8
				if (hex.startsWith('ac')) {
					// 172.16.0.0/12
const match = hex.match(/^ac1[0-9a-f]/);
					if (match) return false;
				}
				if (hex.startsWith('c0a8')) return false; // 192.168.0.0/16
				if (hex.startsWith('a9fe')) return false; // 169.254.0.0/16

				// Additional ranges
				if (hex.startsWith('6440') || (hex.startsWith('64:') && hex.slice(3).match(/^[4-7]/))) return false; // 100.64.0.0/10

				if (hex.startsWith('c000:')) return false; // 192.0.0.0/24
				if (hex === 'c000') return false;

				if (hex.startsWith('c612') || hex.startsWith('c613') || hex.startsWith('c6:12') || hex.startsWith('c6:13')) return false; // 198.18.0.0/15
				if (hex.startsWith('c633:64') || hex.startsWith('c633:100:')) return false; // 198.51.100.0/24
				if (hex.startsWith('cb00:71') || hex.startsWith('cb00:113:')) return false; // 203.0.113.0/24
			}
		}

		// Parse IPv4 to check internal subnets
		const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		const match = hostname.match(ipv4Regex);
		if (match) {
			const octets = match.slice(1).map(Number);

			// 10.0.0.0/8
			if (octets[0] === 10) return false;
			// 100.64.0.0/10 (CGNAT)
			if (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) return false;
			// 127.0.0.0/8 (loopback)
			if (octets[0] === 127) return false;
			// 169.254.0.0/16 (link-local)
			if (octets[0] === 169 && octets[1] === 254) return false;
			// 172.16.0.0/12
			if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return false;
			// 192.0.0.0/24 (IETF Protocol Assignments)
			if (octets[0] === 192 && octets[1] === 0 && octets[2] === 0) return false;
			// 192.0.2.0/24 (TEST-NET-1)
			if (octets[0] === 192 && octets[1] === 0 && octets[2] === 2) return false;
			// 192.168.0.0/16
			if (octets[0] === 192 && octets[1] === 168) return false;
			// 192.88.99.0/24 (6to4 relay anycast)
			if (octets[0] === 192 && octets[1] === 88 && octets[2] === 99) return false;
			// 198.18.0.0/15 (Benchmarking)
			if (octets[0] === 198 && octets[1] >= 18 && octets[1] <= 19) return false;
			// 198.51.100.0/24 (TEST-NET-2)
			if (octets[0] === 198 && octets[1] === 51 && octets[2] === 100) return false;
			// 203.0.113.0/24 (TEST-NET-3)
			if (octets[0] === 203 && octets[1] === 0 && octets[2] === 113) return false;
			// 224.0.0.0/4 (Multicast)
			if (octets[0] >= 224 && octets[0] <= 239) return false;
			// 240.0.0.0/4 (Reserved)
			if (octets[0] >= 240) return false;
			// 0.0.0.0/8 ("this" network)
			if (octets[0] === 0) return false;
		}

		return true;
	} catch {
		return false;
	}
}

/**
 * Validates a user-supplied *origin IP* for the "resolve this domain to this IP"
 * bypass test. The whole point of that test is to connect straight to an origin
 * server that normally sits behind a WAF, so the value must be a bare IP literal
 * (v4, or v6 bracketed or not) and nothing else — no scheme, path, port,
 * credentials or hostname. A hostname is refused on purpose: it would skip the
 * literal-IP range checks and reopen an SSRF hole (DNS rebinding, internal name
 * resolution). The IP itself is then run through `isValidTargetUrl`, so every
 * private / loopback / link-local / reserved range it already blocks is blocked
 * here too — a scan must never be steered at 127.0.0.1, 169.254.169.254, etc.
 */
export function isValidOriginIp(ip: string): boolean {
	const trimmed = (ip || '').trim();
	if (!trimmed) return false;
	// A bare host only: reject anything carrying a scheme, path, query, fragment,
	// credentials, whitespace or an explicit port.
	if (/[\s/\\?#@]/.test(trimmed)) return false;

	const isBracketed = trimmed.startsWith('[') && trimmed.endsWith(']');
	const inner = isBracketed ? trimmed.slice(1, -1) : trimmed;
	const looksIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(inner);
	const looksIpv6 = inner.includes(':');
	if (!looksIpv4 && !looksIpv6) return false;
	if (looksIpv4 && inner.split('.').some((o) => Number(o) > 255)) return false;

	const hostForUrl = looksIpv6 ? `[${inner}]` : inner;
	// Reuse the single SSRF validator so the blocked-range list can never drift
	// from the one the rest of the scanner enforces.
	return isValidTargetUrl(`http://${hostForUrl}`);
}

/**
 * Validates and normalizes the inputs for the origin-IP bypass test, where the
 * target hostname is resolved to a known origin IP behind the WAF.
 *
 * The request URL itself is deliberately NOT rewritten to the IP: the Host header
 * and TLS SNI are both derived from the URL (and `Host` is a forbidden request
 * header that fetch silently drops), so pointing the URL at the IP would lose the
 * vhost the test depends on. Instead the caller keeps the URL on the domain and
 * steers only the DNS lookup via Cloudflare's `cf.resolveOverride`, which this
 * returns as `resolveIp`. `hostHeader` is the target's own authority, returned
 * for logging/reporting.
 *
 * Returns `null` when the IP is not a valid public origin (see `isValidOriginIp`)
 * or the target URL is not http(s).
 */
export function applyOriginIpOverride(
	targetUrl: string,
	originIp: string,
): { resolveIp: string; hostHeader: string } | null {
	if (!isValidOriginIp(originIp)) return null;
	let u: URL;
	try {
		u = new URL(targetUrl);
	} catch {
		return null;
	}
	if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;

	const trimmed = originIp.trim();
	// Normalize to the bare IP literal (resolveOverride takes no brackets).
	const resolveIp = trimmed.startsWith('[') && trimmed.endsWith(']') ? trimmed.slice(1, -1) : trimmed;
	return { resolveIp, hostHeader: u.host };
}

/**
 * Decides whether a redirect stays within the scanned target's scope.
 *
 * A scan must not silently follow a redirect off to a CDN, a partner domain or an
 * SSO provider and then report that host's response as the target's. We accept only
 * the same host or a parent/child of it (example.com <-> www.example.com), which
 * covers the http->https and canonical-host redirects that dominate real scans
 * without needing a public-suffix list.
 */
export function isInScopeRedirect(fromUrl: string, toUrl: string): boolean {
	try {
		const from = normalizeHostname(new URL(fromUrl).hostname);
		const to = normalizeHostname(new URL(toUrl).hostname);

		if (!from || !to) return false;
		if (from === to) return true;

		return from.endsWith('.' + to) || to.endsWith('.' + from);
	} catch {
		return false;
	}
}
