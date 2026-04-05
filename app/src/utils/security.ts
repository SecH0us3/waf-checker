export function isValidTargetUrl(urlString: string): boolean {
    try {
        const url = new URL(urlString);
        
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
            return false;
        }

        const hostname = url.hostname;
        
        // Bloack localhost and link-local ranges
        if (hostname === 'localhost' || hostname.includes('127.0.0.1') || hostname === '::1') {
            return false;
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
