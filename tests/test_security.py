import os
import unittest
from unittest.mock import patch

from vulnscanner.security import (
    ScopeError, agent_token_is_valid, api_token_is_valid, parse_allowed_targets, target_is_allowed,
    validate_ports, validate_targets,
)

class ScopeTests(unittest.TestCase):
    def test_requires_explicit_scope(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ScopeError):
                parse_allowed_targets()

    def test_ip_and_cidr_scope(self):
        allowed = parse_allowed_targets("10.24.0.0/16,192.0.2.10")
        self.assertTrue(target_is_allowed("10.24.3.4", allowed))
        self.assertTrue(target_is_allowed("10.24.8.0/24", allowed))
        self.assertTrue(target_is_allowed("192.0.2.10", allowed))
        self.assertFalse(target_is_allowed("10.25.3.4", allowed))
        self.assertFalse(target_is_allowed("10.24.0.0/15", allowed))

    def test_exact_and_wildcard_dns_scope(self):
        allowed = parse_allowed_targets("example.org,*.internal.example.org")
        self.assertTrue(target_is_allowed("example.org", allowed))
        self.assertTrue(target_is_allowed("api.internal.example.org", allowed))
        self.assertFalse(target_is_allowed("internal.example.org", allowed))
        self.assertFalse(target_is_allowed("evil-example.org", allowed))

    def test_rejects_universal_scope_and_bad_urls(self):
        with self.assertRaises(ScopeError):
            parse_allowed_targets("*")
        with self.assertRaises(ScopeError):
            parse_allowed_targets("file:///etc/passwd")
        with self.assertRaises(ScopeError):
            validate_targets(["https://user:pass@example.org"], maximum=5)

    def test_batch_scope_deduplicates_and_rejects_outside_target(self):
        with patch.dict(os.environ, {"PEN_ALLOWED_TARGETS": "192.0.2.0/24"}, clear=True):
            self.assertEqual(validate_targets(["192.0.2.10", "192.0.2.10"]), ["192.0.2.10"])
            with self.assertRaises(ScopeError):
                validate_targets(["192.0.2.10", "198.51.100.3"])

    def test_large_cidr_is_rejected_on_single_target_entry_points(self):
        with patch.dict(os.environ, {
            "PEN_ALLOWED_TARGETS": "10.0.0.0/8",
            "PEN_MAX_CIDR_ADDRESSES": "256",
        }, clear=True):
            with self.assertRaises(ScopeError):
                from vulnscanner.security import require_target_in_scope
                require_target_in_scope("10.0.0.0/8")

    def test_ports_are_bounded(self):
        self.assertEqual(validate_ports([80, 443, 80]), [80, 443])
        with self.assertRaises(ScopeError):
            validate_ports([0])
        with self.assertRaises(ScopeError):
            validate_ports([])
        with self.assertRaises(ScopeError):
            validate_ports(list(range(1, 102)))

    def test_token_requires_configured_secret(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(api_token_is_valid("anything"))
        with patch.dict(os.environ, {"PEN_API_TOKEN": "secret"}, clear=True):
            self.assertTrue(api_token_is_valid("secret"))
            self.assertFalse(api_token_is_valid("wrong"))

    def test_agent_token_requires_configured_secret(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(agent_token_is_valid("anything"))
        with patch.dict(os.environ, {"PEN_AGENT_TOKEN": "agent-secret"}, clear=True):
            self.assertTrue(agent_token_is_valid("agent-secret"))
            self.assertFalse(agent_token_is_valid("wrong"))


class NonDestructiveExploitCheckTests(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_rce_and_heartbeat_probes_are_disabled_without_network_io(self):
        from vulnscanner.core.checks.exploits import ExploitScanner
        from vulnscanner.core.exploits import ExploitModule

        with patch.dict(os.environ, {
            "PEN_ALLOWED_TARGETS": "192.0.2.10",
            "PEN_ENABLE_EXPLOIT_CHECKS": "1",
        }, clear=True):
            scanner = ExploitScanner()
            spring = await scanner.check_spring4shell("192.0.2.10", 8080)
            heartbeat = await scanner.check_heartbleed("192.0.2.10", 443)
            log4shell = await scanner.check_log4shell("192.0.2.10", 80)
            self.assertFalse(spring.vulnerable)
            self.assertFalse(heartbeat.vulnerable)
            self.assertFalse(log4shell.vulnerable)
            self.assertEqual(spring.severity, "INFO")
            self.assertIsNone(scanner.session)
            await scanner.close()

            module = ExploitModule()
            spring_result = await module._check_spring4shell("192.0.2.10", 8080)
            heartbeat_result = await module._check_heartbleed("192.0.2.10", 443)
            log4shell_result = await module._check_log4shell("192.0.2.10", 80)
            self.assertFalse(spring_result.success)
            self.assertFalse(heartbeat_result.success)
            self.assertFalse(log4shell_result.success)
            self.assertIn("No Spring4Shell payload was sent", spring_result.evidence["reason"])
            self.assertIn("No crafted heartbeat was sent", heartbeat_result.evidence["reason"])

if __name__ == "__main__":
    unittest.main()
