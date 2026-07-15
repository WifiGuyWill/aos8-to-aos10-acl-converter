"""Render a translated policy as AOS 10 / Aruba Central output.

Three surfaces, all driven by the same :class:`~aos8_acl_converter.canonical.CanonicalPolicy`:

* :func:`policy_to_central_json` -- the Central config-API policy body (the shape
  the MCP ``central_write_policy`` writer would push), suitable for
  ``--output json``.
* :func:`render_central_config` -- a readable AOS 10 / Central-style policy
  block for ``--output config``.
* :func:`render_rule_summary` / :func:`format_condition` -- compact one-liners
  used by the side-by-side comparison and the text report.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .canonical import CanonicalPolicy

# ----------------------------------------------------------------------
# Central config-API body (JSON output)
# ----------------------------------------------------------------------


def policy_to_central_json(policy: CanonicalPolicy) -> Dict[str, Any]:
    """Build the Central security-policy create body from a CanonicalPolicy.

    Mirrors the MCP ``central_write_policy`` create payload. When the reader
    flagged unmapped AOS 8 actions (fail-closed to ACTION_DENY), an
    ``_unresolved`` marker is attached so downstream automation blocks the push
    for operator review instead of silently applying a deny.
    """
    body: Dict[str, Any] = {
        "name": policy.name,
        "type": "POLICY_TYPE_SECURITY",
        "association": policy.association,
        "security-policy": {
            "type": "SECURITY_POLICY_TYPE_DEFAULT",
            "policy-rule": policy.rules,
        },
    }
    if policy.unmapped_actions:
        body["_unresolved"] = {
            "kind": "policy_action",
            "name": policy.name,
            "unmapped_actions": sorted(set(policy.unmapped_actions)),
        }
    return body


# ----------------------------------------------------------------------
# Human-readable condition formatting
# ----------------------------------------------------------------------

_ACTION_LABEL = {
    "ACTION_ALLOW": "permit",
    "ACTION_DENY": "deny",
    "ACTION_SOURCE_NAT": "src-nat",
    "ACTION_DESTINATION_NAT": "dst-nat",
    "ACTION_DUAL_NAT": "dual-nat",
    "ACTION_REDIRECT": "redirect",
    "ACTION_ROUTE": "route",
    "ACTION_CAPTIVE_PORTAL": "captive-portal",
    "ACTION_MIRROR": "mirror",
}


def _fmt_address(addr: Dict[str, Any]) -> str:
    """Render a Central source/destination dict as a compact token."""
    if not addr:
        return "-"
    t = addr.get("type")
    if t == "ADDRESS_ANY":
        return "any"
    if t == "ADDRESS_LOCAL":
        return "localip"
    if t == "ADDRESS_USER":
        return "user"
    if t == "ADDRESS_HOST":
        ha = addr.get("host-address", {})
        return "host {0}".format(ha.get("host-ipv4-address") or ha.get("host-ipv6-address") or "?")
    if t == "ADDRESS_NETWORK":
        na = addr.get("network-address", {})
        return "network {0}".format(na.get("network-ipv4-address") or na.get("network-ipv6-address") or "?")
    if t == "ADDRESS_ALIAS":
        return "alias:{0}".format(addr.get("net-group", "?"))
    if t == "ADDRESS_ROLE":
        if addr.get("role"):
            return "role:{0}".format(addr["role"])
        roles = addr.get("role-list") or []
        return "role:{0}".format(",".join(roles) if roles else "?")
    return str(t)


def _fmt_service(condition: Dict[str, Any]) -> str:
    """Render the service/protocol portion of a condition."""
    services = condition.get("services") or {}
    for key, prefix in (
        ("net-service", "svc"),
        ("application", "app"),
        ("app-category", "appcategory"),
        ("web-category", "webcategory"),
        ("web-reputation", "webreputation"),
    ):
        if key in services:
            return "{0} {1}".format(prefix, services[key])

    ip_header = condition.get("ip-header") or {}
    proto = ip_header.get("protocol")
    if proto:
        label = {"IP_TCP": "tcp", "IP_UDP": "udp", "IP_ICMP": "icmp", "IPV6_ICMP": "icmpv6"}.get(proto, proto)
        tf = condition.get("transport-fields") or {}
        dport = tf.get("destination-port") or {}
        if dport:
            op = dport.get("operator")
            if op == "COMPARISON_RANGE":
                return "{0} {1}-{2}".format(label, dport.get("min"), dport.get("max"))
            return "{0} {1}".format(label, dport.get("min"))
        if ip_header.get("icmp"):
            return "{0} type {1}".format(label, ip_header["icmp"].get("icmp-type"))
        return label
    return "any"


def _fmt_action(action: Dict[str, Any]) -> str:
    """Render the action + secondary actions of a rule."""
    label = _ACTION_LABEL.get(action.get("type", ""), action.get("type", "?"))
    extras: List[str] = []
    dnat = action.get("destination-nat")
    if dnat:
        parts = []
        if dnat.get("ip-address"):
            parts.append(dnat["ip-address"])
        if dnat.get("port") is not None:
            parts.append(str(dnat["port"]))
        if parts:
            extras.append(" ".join(parts))
    if action.get("dual-nat"):
        dn = action["dual-nat"]
        if dn.get("nat-pool"):
            extras.append("pool {0}".format(dn["nat-pool"]))
    if action.get("redirect"):
        rd = action["redirect"]
        if rd.get("tunnel") is not None:
            extras.append("tunnel {0}".format(rd["tunnel"]))
        elif rd.get("tunnel-group"):
            extras.append("tunnel-group {0}".format(rd["tunnel-group"]))
    sec = action.get("secondary-actions") or {}
    if sec.get("log"):
        extras.append("log")
    if sec.get("denylist"):
        extras.append("denylist")
    if action.get("send-deny-response"):
        extras.append("send-deny-response")
    return "{0}{1}".format(label, (" " + " ".join(extras)) if extras else "")


def format_condition(rule: Dict[str, Any]) -> str:
    """One-line summary of a single Central rule (source dst service action)."""
    cond = rule.get("condition", {})
    af = cond.get("address-family", "")
    af_tag = "ipv6 " if af == "IPV6" else ""
    src = _fmt_address(cond.get("source", {}))
    dst = _fmt_address(cond.get("destination", {}))
    svc = _fmt_service(cond)
    act = _fmt_action(rule.get("action", {}))
    tr = cond.get("time-range-name")
    tr_tag = " time-range {0}".format(tr) if tr else ""
    return "{0}{1} {2} {3} {4}{5}".format(af_tag, src, dst, svc, act, tr_tag)


def render_rule_summary(rules: List[Dict[str, Any]]) -> List[str]:
    """Numbered one-line summaries for a list of Central rules."""
    return ["{0:>3}. {1}".format(r.get("position", i + 1), format_condition(r)) for i, r in enumerate(rules)]


# ----------------------------------------------------------------------
# Central-style config block (config output)
# ----------------------------------------------------------------------


def render_netdestinations(netdest_objects: list) -> str:
    """Render AOS 8 netdestination blocks as AOS 10 named-destination equivalents.

    AOS 8 ``netdestination`` objects map to Central *named-destination* objects,
    which are referenced in policy rules via ``alias:<name>``. These must be
    created in Central before the policies that reference them are applied.
    """
    if not netdest_objects:
        return ""
    lines: List[str] = [
        "! ==========================================================",
        "! Named destinations (create these in Central before applying",
        "! the policies below that reference them via alias:<name>).",
        "! ==========================================================",
    ]
    for nd in netdest_objects:
        v6_tag = "6" if nd.is_ipv6 else ""
        lines.append("named-destination{0} {1}".format(v6_tag, nd.name))
        for fqdn in nd.fqdns:
            lines.append("  fqdn {0}".format(fqdn))
        for host in nd.hosts:
            lines.append("  host {0}".format(host))
        for net in nd.networks:
            lines.append("  network {0}".format(net))
        lines.append("!")
    return "\n".join(lines)


def render_central_config(policy: CanonicalPolicy) -> str:
    """Render an AOS 10 / Central-style security-policy block.

    AOS 10 security is expressed as a *named policy* whose rules are role- or
    interface-scoped (unlike AOS 8, where a session ACL is a standalone object a
    role later references). This block reflects that model.
    """
    lines: List[str] = []
    assoc = "interface" if policy.association == "ASSOCIATION_INTERFACE" else "role"
    lines.append("security-policy {0}".format(policy.name))
    lines.append("  association {0}".format(assoc))
    if policy.unmapped_actions:
        lines.append("  ! WARNING: unresolved -- unmapped AOS 8 actions fail-closed to deny:")
        lines.append("  !          {0}".format(", ".join(sorted(set(policy.unmapped_actions)))))
    for rule in policy.rules:
        lines.append("  rule {0} {1}".format(rule.get("position"), format_condition(rule)))
    lines.append("!")
    return "\n".join(lines)
