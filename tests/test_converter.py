"""Unit tests for the AOS 8 -> AOS 10 ACL converter.

Run with: ``python -m pytest`` (or plain ``python tests/test_converter.py``).
Covers parsing, address/service/action translation, any-any expansion, role
injection, IPv6, DPI mapping, fail-closed handling, and bridge-mode flagging.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aos8_acl_converter import convert_text, parse_config  # noqa: E402
from aos8_acl_converter.renderer import policy_to_central_json  # noqa: E402


def _first_policy(text, **kw):
    result = convert_text(text, **kw)
    return result.converted[0].policy, result


class ParserTests(unittest.TestCase):
    def test_parses_acl_and_role(self):
        cfg = (
            "ip access-list session a1\n"
            "  user any svc-dns permit\n"
            "user-role r1\n"
            "  access-list session a1\n"
        )
        parsed = parse_config(cfg)
        self.assertEqual(len(parsed.acl_sessions), 1)
        self.assertEqual(parsed.acl_sessions[0]["accname"], "a1")
        self.assertEqual(len(parsed.role_records), 1)
        self.assertEqual(parsed.role_records[0]["role__acl"][0]["pname"], "a1")

    def test_host_network_alias_parsing(self):
        cfg = (
            "ip access-list session a1\n"
            "  host 10.0.0.1 network 192.168.0.0 255.255.255.0 any permit\n"
            "  internal any any deny\n"
        )
        rule = parse_config(cfg).acl_sessions[0]["acl_sess__v4policy"]
        self.assertEqual(rule[0]["src"], "shost")
        self.assertEqual(rule[0]["sipaddr"], "10.0.0.1")
        self.assertEqual(rule[0]["dst"], "dnetwork")
        self.assertEqual(rule[0]["dnetmask"], "255.255.255.0")
        self.assertEqual(rule[1]["src"], "salias")
        self.assertEqual(rule[1]["srcalias"], "internal")


class TranslationTests(unittest.TestCase):
    def test_role_injection_scopes_any(self):
        cfg = (
            "ip access-list session a1\n"
            "  user any svc-http permit\n"
            "user-role emp\n"
            "  access-list session a1\n"
        )
        policy, _ = _first_policy(cfg)
        src = policy.rules[0]["condition"]["source"]
        self.assertEqual(src["type"], "ADDRESS_ROLE")
        self.assertEqual(src["role-list"], ["emp"])

    def test_any_any_bidirectional_expansion(self):
        cfg = (
            "ip access-list session a1\n"
            "  any any any permit\n"
            "user-role emp\n"
            "  access-list session a1\n"
        )
        policy, _ = _first_policy(cfg)
        self.assertEqual(len(policy.rules), 2)
        s0 = policy.rules[0]["condition"]["source"]["type"]
        d0 = policy.rules[0]["condition"]["destination"]["type"]
        self.assertEqual((s0, d0), ("ADDRESS_ROLE", "ADDRESS_ANY"))
        s1 = policy.rules[1]["condition"]["source"]["type"]
        d1 = policy.rules[1]["condition"]["destination"]["type"]
        self.assertEqual((s1, d1), ("ADDRESS_ANY", "ADDRESS_ROLE"))

    def test_tcp_port_and_range(self):
        cfg = (
            "ip access-list session a1\n"
            "  any any tcp 443 permit\n"
            "  any any udp 16384 32767 permit\n"
        )
        rules = _first_policy(cfg)[0].rules
        eq = rules[0]["condition"]
        self.assertEqual(eq["rule-type"], "RULE_TCP")
        self.assertEqual(eq["transport-fields"]["destination-port"]["operator"], "COMPARISON_EQ")
        self.assertEqual(eq["transport-fields"]["destination-port"]["min"], 443)
        rng = rules[1]["condition"]
        self.assertEqual(rng["rule-type"], "RULE_UDP")
        self.assertEqual(rng["transport-fields"]["destination-port"]["operator"], "COMPARISON_RANGE")
        self.assertEqual(rng["transport-fields"]["destination-port"]["max"], 32767)

    def test_web_category_uses_lookup_table(self):
        cfg = "ip access-list session a1\n  any any webcategory entertainment/arts deny\n"
        rules = _first_policy(cfg)[0].rules
        # 21 categories insert 'AND' -- naive munging would give ENTERTAINMENT-ARTS.
        self.assertEqual(rules[0]["condition"]["services"]["web-category"], "ENTERTAINMENT-AND-ARTS")

    def test_ipv6_family_detected(self):
        cfg = "ipv6 access-list session a6\n  network 2001:db8::/32 any any permit\n"
        rules = _first_policy(cfg)[0].rules
        self.assertEqual(rules[0]["condition"]["address-family"], "IPV6")
        self.assertEqual(
            rules[0]["condition"]["source"]["network-address"]["network-ipv6-address"],
            "2001:db8::/32",
        )

    def test_dst_nat_action(self):
        cfg = "ip access-list session a1\n  user host 10.0.0.1 tcp 80 dst-nat 10.99.0.1 8080\n"
        rules = _first_policy(cfg)[0].rules
        act = rules[0]["action"]
        self.assertEqual(act["type"], "ACTION_DESTINATION_NAT")
        self.assertEqual(act["destination-nat"], {"ip-address": "10.99.0.1", "port": 8080})


class FailClosedTests(unittest.TestCase):
    def test_missing_action_fail_closes_to_deny(self):
        cfg = "ip access-list session a1\n  user any svc-dns\n"
        policy, result = _first_policy(cfg)
        self.assertEqual(policy.rules[0]["action"]["type"], "ACTION_DENY")
        self.assertTrue(policy.is_unresolved)
        self.assertIn("a1", result.report.unresolved_policies)
        body = policy_to_central_json(policy)
        self.assertIn("_unresolved", body)


class BridgeModeTests(unittest.TestCase):
    def test_bridge_flags_redirect_and_dpi(self):
        cfg = (
            "ip access-list session a1\n"
            "  user any svc-https redirect tunnel 5\n"
            "  user any webcategory gambling deny\n"
            "user-role u\n"
            "  access-list session a1\n"
        )
        result = convert_text(cfg, bridge_mode=True)
        issues = " ".join(result.converted[0].stat.bridge_issues)
        self.assertIn("redirect", issues)
        self.assertIn("web-category", issues)


if __name__ == "__main__":
    unittest.main(verbosity=2)
