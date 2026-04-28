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
        const ipv6Normalized = hostname.startsWith('[') && hostname.endsWith(']')
            ? hostname.slice(1, -1)
            : hostname;

        // Block IPv6 internal ranges
        // Unique Local Address (fc00::/7)
        if (ipv6Normalized.toLowerCase().startsWith('fc') || ipv6Normalized.toLowerCase().startsWith('fd')) {
            return false;
        }
        // Link-Local Address (fe80::/10)
        if (ipv6Normalized.toLowerCase().startsWith('fe8') ||
            ipv6Normalized.toLowerCase().startsWith('fe9') ||
            ipv6Normalized.toLowerCase().startsWith('fea') ||
            ipv6Normalized.toLowerCase().startsWith('feb')) {
            return false;
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
            }
        }

        // Parse IPv4 to check internal subnets
        const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        const match = hostname.match(ipv4Regex);
        if (match) {
            const octets = match.slice(1).map(Number);
            
            // 10.0.0.0/8
            if (octets[0] === 10) return false;
            // 172.16.0.0/12
            if (octets[0] === 172 && (octets[1] >= 16 && octets[1] <= 31)) return false;
            // 192.168.0.0/16
            if (octets[0] === 192 && octets[1] === 168) return false;
            // 169.254.0.0/16 (link-local)
            if (octets[0] === 169 && octets[1] === 254) return false;
            // 127.0.0.0/8 (loopback) 
            if (octets[0] === 127) return false;
            // 0.0.0.0/8 ("this" network)
            if (octets[0] === 0) return false;
        }
        
        return true;
    } catch {
        return false;
    }
}
