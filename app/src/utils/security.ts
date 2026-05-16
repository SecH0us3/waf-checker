export function isValidTargetUrl(urlString: string): boolean {
	try {
		const url = new URL(urlString);

		if (url.protocol !== 'http:' && url.protocol !== 'https:') {
			return false;
		}

		let hostname = url.hostname;

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


		// Check for IPv4-compatible IPv6 (::0:0/96)
		if (ipv6Normalized.toLowerCase().startsWith('::') && !ipv6Normalized.toLowerCase().startsWith('::ffff:') && ipv6Normalized !== '::1') {
			// e.g. ::7f00:1
			if (ipv6Normalized.toLowerCase().startsWith('::7f')) return false; // 127.0.0.0/8
			if (ipv6Normalized.toLowerCase().startsWith('::0a') || ipv6Normalized.toLowerCase().startsWith('::a')) return false; // 10.0.0.0/8
			if (ipv6Normalized.toLowerCase().startsWith('::ac')) {
				// 172.16.0.0/12 -> ::ac10:0000 to ::ac1f:ffff
				const match = ipv6Normalized.toLowerCase().match(/^::(ac[12][0-9a-f]|ac3[01])/);
				if (match) return false;
			}
			if (ipv6Normalized.toLowerCase().startsWith('::c0a8')) return false; // 192.168.0.0/16
			if (ipv6Normalized.toLowerCase().startsWith('::a9fe')) return false; // 169.254.0.0/16

			// Additional ranges for IPv4-compatible
			if (ipv6Normalized.toLowerCase().startsWith('::6440')) return false; // 100.64.0.0/10
			if (ipv6Normalized.toLowerCase().startsWith('::c00000')) return false; // 192.0.0.0/24
			if (ipv6Normalized.toLowerCase().startsWith('::c00002')) return false; // 192.0.2.0/24
			if (ipv6Normalized.toLowerCase().startsWith('::c612') || ipv6Normalized.toLowerCase().startsWith('::c613')) return false; // 198.18.0.0/15
			if (ipv6Normalized.toLowerCase().startsWith('::c63364')) return false; // 198.51.100.0/24
			if (ipv6Normalized.toLowerCase().startsWith('::cb0071')) return false; // 203.0.113.0/24
		}

		// Check for IPv4-mapped IPv6 (::ffff:0:0/96)

		if (ipv6Normalized.toLowerCase().startsWith('::ffff:')) {
			const lastPart = ipv6Normalized.split(':').pop() || '';
			if (lastPart.includes('.')) {
				hostname = lastPart; // Treat it as IPv4 for the next check
			} else {
				// Handle hex-encoded IPv4-mapped IPv6
				if (ipv6Normalized.toLowerCase().startsWith('::ffff:7f')) return false; // 127.0.0.0/8
				if (ipv6Normalized.toLowerCase().startsWith('::ffff:0a') || ipv6Normalized.toLowerCase().startsWith('::ffff:a')) return false; // 10.0.0.0/8
				if (ipv6Normalized.toLowerCase().startsWith('::ffff:ac')) {
					// 172.16.0.0/12 -> ::ffff:ac10:0000 to ::ffff:ac1f:ffff
					const match = ipv6Normalized.toLowerCase().match(/^::ffff:(ac[12][0-9a-f]|ac3[01])/);
					if (match) return false;
				}
				if (ipv6Normalized.toLowerCase().startsWith('::ffff:c0a8')) return false; // 192.168.0.0/16
				if (ipv6Normalized.toLowerCase().startsWith('::ffff:a9fe')) return false; // 169.254.0.0/16

				// Additional ranges for IPv4-mapped
				if (ipv6Normalized.toLowerCase().startsWith('::ffff:6440')) return false; // 100.64.0.0/10
				if (ipv6Normalized.toLowerCase().startsWith('::ffff:c00000')) return false; // 192.0.0.0/24
				if (ipv6Normalized.toLowerCase().startsWith('::ffff:c00002')) return false; // 192.0.2.0/24
				if (ipv6Normalized.toLowerCase().startsWith('::ffff:c612') || ipv6Normalized.toLowerCase().startsWith('::ffff:c613')) return false; // 198.18.0.0/15
				if (ipv6Normalized.toLowerCase().startsWith('::ffff:c63364')) return false; // 198.51.100.0/24
				if (ipv6Normalized.toLowerCase().startsWith('::ffff:cb0071')) return false; // 203.0.113.0/24
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
