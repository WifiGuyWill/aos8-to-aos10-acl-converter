"""Statistics, issue flagging, and bridge-mode analysis for a conversion run.

Produces the structured facts the CLI turns into ``--report`` output: per-policy
and aggregate counts, unmapped/unresolved actions, complex-rule callouts, and the
bridge-mode advisories that matter when moving session ACLs from an AOS 8
controller to AOS 10 (Central).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .canonical import CanonicalPolicy
from .parser import ParseResult

# ----------------------------------------------------------------------
# Bridge-mode background
#
# On AOS 8, an AP in *tunnel* mode sends client traffic to the controller,
# where the full session-ACL / firewall (roles, stateful policies, DPI, NAT,
# redirect) is enforced centrally. In *bridge* (and decrypt-tunnel / split-
# tunnel) mode, traffic egresses at the AP, so only the subset of firewall
# features the AP itself can enforce applies. Moving to AOS 10 microbranch /
# bridge deployments inherits the same constraint set. These are the rule
# shapes that commonly do NOT survive a bridge-mode migration unchanged.
# ----------------------------------------------------------------------

# Central action enums that a bridged AP cannot (or should not) enforce locally.
_BRIDGE_UNSUPPORTED_ACTIONS = {
    "ACTION_REDIRECT": "redirect (tunnel/tunnel-group) requires a controller datapath",
    "ACTION_DUAL_NAT": "dual-NAT is a controller datapath feature",
    "ACTION_ROUTE": "policy-based routing (route) is enforced on the controller",
    "ACTION_MIRROR": "packet mirroring is a controller datapath feature",
    "ACTION_CAPTIVE_PORTAL": "captive-portal redirect depends on the controller/portal",
}
# Rule-types whose enforcement is limited or absent on a bridged AP.
_BRIDGE_LIMITED_RULE_TYPES = {
    "RULE_WEB_CATEGORY": "WebCC web-category classification is a DPI feature (AP DPI required)",
    "RULE_WEB_REPUTATION": "WebCC web-reputation classification is a DPI feature (AP DPI required)",
    "RULE_APP_CATEGORY": "AppRF app-category classification needs on-AP DPI",
    "RULE_APPLICATION": "AppRF per-application classification needs on-AP DPI",
}


@dataclass
class PolicyStat:
    """Per-policy roll-up."""

    name: str
    association: str
    role_attribution: List[str] = field(default_factory=list)
    source_rule_count: int = 0
    generated_rule_count: int = 0
    any_any_rules: int = 0
    dropped_rules: int = 0  # source rules that produced no Central rule
    rule_types: Dict[str, int] = field(default_factory=dict)
    actions: Dict[str, int] = field(default_factory=dict)
    unmapped_actions: List[str] = field(default_factory=list)
    ipv6_rules: int = 0
    bridge_issues: List[str] = field(default_factory=list)
    complex_rules: List[str] = field(default_factory=list)

    @property
    def unresolved(self) -> bool:
        return bool(self.unmapped_actions)


def _count(d: Dict[str, int], key: str) -> None:
    d[key] = d.get(key, 0) + 1


def analyze_policy(
    policy: CanonicalPolicy,
    trace: List[Any],
    role_attribution: List[str],
    *,
    bridge_mode: bool = False,
) -> PolicyStat:
    """Compute statistics + issue flags for one translated policy.

    ``trace`` is the ``[(aos8_rule, [central_rules]), ...]`` list from
    :func:`aos8_acl_converter.reader.aos8_read_policy_traced`.
    """
    stat = PolicyStat(name=policy.name, association=policy.association, role_attribution=role_attribution)
    stat.unmapped_actions = list(policy.unmapped_actions)

    for aos8_rule, central_rules in trace:
        stat.source_rule_count += 1
        if not central_rules:
            stat.dropped_rules += 1
            raw = aos8_rule.get("_raw", "<rule>")
            stat.complex_rules.append("dropped (no Central mapping): {0}".format(raw))
            continue
        if aos8_rule.get("src") == "sany" and aos8_rule.get("dst") == "dany":
            stat.any_any_rules += 1
        if len(central_rules) > 1:
            stat.complex_rules.append(
                "any-any expanded to {0} role-scoped rules: {1}".format(
                    len(central_rules), aos8_rule.get("_raw", "")
                )
            )

    for rule in policy.rules:
        stat.generated_rule_count += 1
        cond = rule.get("condition", {})
        rtype = cond.get("rule-type", "RULE_ANY")
        _count(stat.rule_types, rtype)
        if cond.get("address-family") == "IPV6":
            stat.ipv6_rules += 1
        atype = rule.get("action", {}).get("type", "?")
        _count(stat.actions, atype)

        if bridge_mode:
            if atype in _BRIDGE_UNSUPPORTED_ACTIONS:
                stat.bridge_issues.append(
                    "rule {0}: {1}".format(rule.get("position"), _BRIDGE_UNSUPPORTED_ACTIONS[atype])
                )
            if rtype in _BRIDGE_LIMITED_RULE_TYPES:
                stat.bridge_issues.append(
                    "rule {0}: {1}".format(rule.get("position"), _BRIDGE_LIMITED_RULE_TYPES[rtype])
                )

    # De-duplicate bridge advisories while preserving order.
    seen = set()
    deduped = []
    for msg in stat.bridge_issues:
        if msg not in seen:
            seen.add(msg)
            deduped.append(msg)
    stat.bridge_issues = deduped
    return stat


@dataclass
class ConversionReport:
    """Aggregate report across every policy in a conversion run."""

    policies: List[PolicyStat] = field(default_factory=list)
    parse_warnings: List[Any] = field(default_factory=list)
    netdestinations: List[str] = field(default_factory=list)
    roles_seen: List[str] = field(default_factory=list)

    # --- aggregate accessors ---------------------------------------------
    @property
    def total_source_rules(self) -> int:
        return sum(p.source_rule_count for p in self.policies)

    @property
    def total_generated_rules(self) -> int:
        return sum(p.generated_rule_count for p in self.policies)

    @property
    def total_any_any(self) -> int:
        return sum(p.any_any_rules for p in self.policies)

    @property
    def total_dropped(self) -> int:
        return sum(p.dropped_rules for p in self.policies)

    @property
    def unresolved_policies(self) -> List[str]:
        return [p.name for p in self.policies if p.unresolved]

    @property
    def aggregate_actions(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for p in self.policies:
            for k, v in p.actions.items():
                out[k] = out.get(k, 0) + v
        return out

    @property
    def aggregate_rule_types(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for p in self.policies:
            for k, v in p.rule_types.items():
                out[k] = out.get(k, 0) + v
        return out

    def to_dict(self) -> Dict[str, Any]:
        """Serializable summary for ``--output json`` / ``--report`` JSON use."""
        return {
            "summary": {
                "policies": len(self.policies),
                "source_rules": self.total_source_rules,
                "generated_rules": self.total_generated_rules,
                "any_any_rules": self.total_any_any,
                "dropped_rules": self.total_dropped,
                "unresolved_policies": self.unresolved_policies,
                "roles_seen": self.roles_seen,
                "netdestination_aliases": self.netdestinations,
                "action_breakdown": self.aggregate_actions,
                "rule_type_breakdown": self.aggregate_rule_types,
                "parse_warnings": len(self.parse_warnings),
            },
            "policies": [
                {
                    "name": p.name,
                    "association": p.association,
                    "role_attribution": p.role_attribution,
                    "source_rules": p.source_rule_count,
                    "generated_rules": p.generated_rule_count,
                    "any_any_rules": p.any_any_rules,
                    "dropped_rules": p.dropped_rules,
                    "ipv6_rules": p.ipv6_rules,
                    "unresolved": p.unresolved,
                    "unmapped_actions": sorted(set(p.unmapped_actions)),
                    "rule_types": p.rule_types,
                    "actions": p.actions,
                    "bridge_issues": p.bridge_issues,
                    "complex_rules": p.complex_rules,
                }
                for p in self.policies
            ],
        }
