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

/**
 * Whether a dotted IPv4 address (as four octets) falls in a blocked private /
 * loopback / reserved range. The single source of truth for both dotted IPv4
 * hosts and IPv4 addresses embedded in IPv6 (see `isPrivateEmbeddedIpv4Hex`).
 */
function isPrivateIpv4Octets(octets: number[]): boolean {
	// 10.0.0.0/8
	if (octets[0] === 10) return true;
	// 100.64.0.0/10 (CGNAT)
	if (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) return true;
	// 127.0.0.0/8 (loopback)
	if (octets[0] === 127) return true;
	// 169.254.0.0/16 (link-local)
	if (octets[0] === 169 && octets[1] === 254) return true;
	// 172.16.0.0/12
	if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
	// 192.0.0.0/24 (IETF Protocol Assignments)
	if (octets[0] === 192 && octets[1] === 0 && octets[2] === 0) return true;
	// 192.0.2.0/24 (TEST-NET-1)
	if (octets[0] === 192 && octets[1] === 0 && octets[2] === 2) return true;
	// 192.168.0.0/16
	if (octets[0] === 192 && octets[1] === 168) return true;
	// 192.88.99.0/24 (6to4 relay anycast)
	if (octets[0] === 192 && octets[1] === 88 && octets[2] === 99) return true;
	// 198.18.0.0/15 (Benchmarking)
	if (octets[0] === 198 && octets[1] >= 18 && octets[1] <= 19) return true;
	// 198.51.100.0/24 (TEST-NET-2)
	if (octets[0] === 198 && octets[1] === 51 && octets[2] === 100) return true;
	// 203.0.113.0/24 (TEST-NET-3)
	if (octets[0] === 203 && octets[1] === 0 && octets[2] === 113) return true;
	// 224.0.0.0/4 (Multicast)
	if (octets[0] >= 224 && octets[0] <= 239) return true;
	// 240.0.0.0/4 (Reserved)
	if (octets[0] >= 240) return true;
	// 0.0.0.0/8 ("this" network)
	if (octets[0] === 0) return true;
	return false;
}

/**
 * Whether the hex tail of an IPv6 address that embeds an IPv4 address
 * (`::<hex>` or `::ffff:<hex>`, e.g. `7f00:1`) decodes to a blocked IPv4 range.
 * Decodes the trailing 16-bit groups into octets and reuses
 * `isPrivateIpv4Octets`, so hex and dotted forms cannot drift. A single group
 * (e.g. `::ffff:0:1` tail `0:1` has two; `::7f` has one) is the low 16 bits.
 * Unparseable tails are not treated as embedded IPv4 (return false).
 */
function isPrivateEmbeddedIpv4Hex(hex: string): boolean {
	const groups = hex.split(':');
	if (groups.length < 1 || groups.length > 2) return false;
	if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return false;
	const [hi, lo] = groups.length === 2 ? groups : ['0', groups[0]];
	const h = parseInt(hi, 16);
	const l = parseInt(lo, 16);
	return isPrivateIpv4Octets([h >> 8, h & 0xff, l >> 8, l & 0xff]);
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
		if (ipv6Normalized.startsWith('fc') || ipv6Normalized.startsWith('fd')) {
			return false;
		}
		// Link-Local Address (fe80::/10)
		if (
			ipv6Normalized.startsWith('fe8') ||
			ipv6Normalized.startsWith('fe9') ||
			ipv6Normalized.startsWith('fea') ||
			ipv6Normalized.startsWith('feb')
		) {
			return false;
		}
		// Site-Local Address (fec0::/10, deprecated but still routed on some networks)
		if (
			ipv6Normalized.startsWith('fec') ||
			ipv6Normalized.startsWith('fed') ||
			ipv6Normalized.startsWith('fee') ||
			ipv6Normalized.startsWith('fef')
		) {
			return false;
		}


		// Check for IPv4-compatible IPv6 (::0:0/96)
		if (ipv6Normalized.startsWith('::') && !ipv6Normalized.startsWith('::ffff:') && ipv6Normalized !== '::1') {
			if (isPrivateEmbeddedIpv4Hex(ipv6Normalized.replace(/^::/, ''))) return false;
		}

		// Check for IPv4-mapped IPv6 (::ffff:0:0/96)
		if (ipv6Normalized.startsWith('::ffff:')) {
			const lastPart = ipv6Normalized.split(':').pop() || '';
			if (lastPart.includes('.')) {
				hostname = lastPart; // Treat it as IPv4 for the next check
			} else if (isPrivateEmbeddedIpv4Hex(ipv6Normalized.replace(/^::ffff:/, ''))) {
				// Hex-encoded IPv4-mapped IPv6
				return false;
			}
		}

		// Parse IPv4 to check internal subnets
		const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		const match = hostname.match(ipv4Regex);
		if (match) {
			if (isPrivateIpv4Octets(match.slice(1).map(Number))) return false;
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
