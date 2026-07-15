"""AOS 8 ``acl_sess`` -> canonical security-policy reader.

Standalone port of the HPE Networking MCP reader
(``translations/readers/aos8/policy.py``). The translation logic is preserved
verbatim -- role-attribution reverse-index, v4+v6 rule merge, any-any
bidirectional expansion, role injection (#419), per-rule address / service /
protocol / action builders -- including the intentional fail-closed fix: an
AOS 8 action with no Central mapping becomes ``ACTION_DENY`` and is recorded in
``unmapped_actions`` (never a silent ``ACTION_ALLOW`` fall-through).

Two entry points:

* :func:`aos8_read_policy` -- the faithful port; returns a
  :class:`~aos8_acl_converter.canonical.CanonicalPolicy`.
* :func:`aos8_read_policy_traced` -- same translation, but also returns the
  per-source-rule -> generated-Central-rules mapping the CLI uses to render the
  side-by-side comparison.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from .canonical import ASSOCIATION_INTERFACE, ASSOCIATION_ROLE, CanonicalPolicy
from .enum_tables import (
    AOS8_APP_CATEGORY_TO_CENTRAL,
    AOS8_APP_TO_CENTRAL,
    AOS8_WEB_CATEGORY_TO_CENTRAL,
    AOS8_WEB_REPUTATION_TO_CENTRAL,
)

# AOS 8 ACL names applied to an interface (not a user-role) -> ASSOCIATION_INTERFACE.
_INTERFACE_ACL_NAMES = frozenset({"validuser"})
# AOS 8 service names denoting IPv6-ICMP -- routed to RULE_PROTOCOL (IPV6_ICMP).
_ICMPV6_SERVICE_NAMES = frozenset({"icmpv6", "icmp6"})
_AOS8_TO_CENTRAL_SVC_NAME_ALIASES: Dict[str, str] = {}

# AOS 8 action verb -> Central action enum. An action absent here is *unmapped*
# and fail-closes to ACTION_DENY (see _build_action).
_AOS8_ACTION_TO_CENTRAL: Dict[str, str] = {
    "permit": "ACTION_ALLOW",
    "deny_opt": "ACTION_DENY",
    "deny": "ACTION_DENY",
    "apppermit": "ACTION_ALLOW",
    "appdeny_opt": "ACTION_DENY",
    "appdeny": "ACTION_DENY",
    "src-nat": "ACTION_SOURCE_NAT",
    "dst-nat": "ACTION_DESTINATION_NAT",
    "dual-nat": "ACTION_DUAL_NAT",
    "redir_opt": "ACTION_REDIRECT",
    "redirect": "ACTION_REDIRECT",
    "route": "ACTION_ROUTE",
    "captive": "ACTION_CAPTIVE_PORTAL",
    "mirror": "ACTION_MIRROR",
}


def _compute_role_attribution(acl_name: str, role_records: List[dict]) -> List[str]:
    """Reverse-index role records -> role names that bind this session ACL.

    In AOS 8 a session ACL is not inherently role-scoped; a user-role references
    it via ``access-list session <name>``. Central policies *are* role-scoped, so
    we must discover which roles reference the ACL to inject the role context.
    """
    out: List[str] = []
    for role in role_records or []:
        if not isinstance(role, dict) or (role.get("_flags") or {}).get("default"):
            continue
        for acl_entry in role.get("role__acl") or []:
            if not isinstance(acl_entry, dict):
                continue
            ef = acl_entry.get("_flags") or {}
            if ef.get("system") or ef.get("default") or ef.get("readonly"):
                continue
            if acl_entry.get("acl_type") == "session" and acl_entry.get("pname") == acl_name:
                rname = role.get("rname")
                if rname and rname not in out:
                    out.append(str(rname))
                break
    return out


def _netmask_to_prefix(netmask: str) -> Optional[int]:
    """Dotted IPv4 netmask (255.255.255.0) -> prefix length (24)."""
    try:
        return ipaddress.IPv4Network("0.0.0.0/{0}".format(netmask), strict=False).prefixlen
    except (ValueError, ipaddress.NetmaskValueError):
        return None


def _build_address(
    rule: dict, side: str, address_family: str, role_attribution: List[str]
) -> Optional[Dict[str, Any]]:
    """Build a Central source/destination dict from one AOS 8 rule's fields.

    Maps every AOS 8 address form to its Central equivalent:
      any -> ADDRESS_ANY, localip -> ADDRESS_LOCAL, host -> ADDRESS_HOST,
      network -> ADDRESS_NETWORK, alias (netdestination) -> ADDRESS_ALIAS/net-group,
      user-role -> ADDRESS_ROLE, user -> ADDRESS_ROLE(role-list) or ADDRESS_ANY,
      user-with-address -> ADDRESS_USER.
    """
    discriminator = rule.get(side)
    if discriminator is None:
        return None
    is_ipv6 = address_family == "IPV6"

    if discriminator in ("sany", "dany"):
        return {"type": "ADDRESS_ANY"}
    if discriminator in ("slocalip", "dlocalip"):
        return {"type": "ADDRESS_LOCAL"}
    if discriminator in ("shost", "dhost"):
        ip = rule.get("sipaddr" if side == "src" else "dipaddr")
        if ip is None:
            return None
        host_key = "host-ipv6-address" if is_ipv6 else "host-ipv4-address"
        return {"type": "ADDRESS_HOST", "host-address": {host_key: str(ip)}}
    if discriminator in ("snetwork", "dnetwork"):
        addr = rule.get("snetaddr" if side == "src" else "dnetaddr")
        mask = rule.get("snetmask" if side == "src" else "dnetmask")
        if addr is None or mask is None:
            return None
        if is_ipv6:
            v6_prefix = mask if isinstance(mask, int) else int(str(mask))
            return {
                "type": "ADDRESS_NETWORK",
                "network-address": {"network-ipv6-address": "{0}/{1}".format(addr, v6_prefix)},
            }
        v4_prefix = _netmask_to_prefix(str(mask))
        if v4_prefix is None:
            return None
        return {
            "type": "ADDRESS_NETWORK",
            "network-address": {"network-ipv4-address": "{0}/{1}".format(addr, v4_prefix)},
        }
    if discriminator in ("salias", "dalias"):
        alias = rule.get("srcalias" if side == "src" else "dstalias")
        if alias is None:
            return None
        return {"type": "ADDRESS_ALIAS", "net-group": str(alias)}
    if discriminator in ("suserrole", "duserrole"):
        role_name = rule.get("surname" if side == "src" else "durname")
        if role_name is None:
            return None
        return {"type": "ADDRESS_ROLE", "role": str(role_name)}
    if discriminator in ("suser", "duser"):
        # A bare `user` maps to the role(s) that reference this ACL; if none are
        # known we cannot scope it, so it widens to ANY (documented in report).
        if not role_attribution:
            return {"type": "ADDRESS_ANY"}
        return {"type": "ADDRESS_ROLE", "role-list": list(role_attribution)}
    if discriminator in ("suser_addr", "duser_addr"):
        return {"type": "ADDRESS_USER"}
    return None


def _build_net_service_block(rule: dict) -> Optional[Dict[str, Any]]:
    """Named net-service alias (svc-http, svc-dns, ...) -> services.net-service."""
    if rule.get("svc") != "service-name" or rule.get("service_app") != "service":
        return None
    name = rule.get("service-name") or rule.get("service_name")
    if not name or str(name).lower() in _ICMPV6_SERVICE_NAMES:
        return None
    central_name = _AOS8_TO_CENTRAL_SVC_NAME_ALIASES.get(str(name), str(name))
    return {"services": {"net-service": central_name}}


def _build_services_block(rule: dict) -> Optional[Dict[str, Any]]:
    """DPI app / app-category / web-category / web-reputation -> services.*.

    Uses the vendored enum lookup tables rather than naive case/dash munging --
    21 of the 85 web categories insert a connective 'AND' (entertainment/arts ->
    ENTERTAINMENT-AND-ARTS) that a mechanical transform would get wrong.
    """
    if rule.get("service_app") != "app_opt":
        return None
    awt = rule.get("app_web_type")
    if awt == "app":
        appname = rule.get("appname")
        if not appname:
            return None
        return {"services": {"application": AOS8_APP_TO_CENTRAL.get(str(appname), str(appname))}}
    if awt == "app_cat":
        cat = rule.get("appname")
        if not cat:
            return None
        return {"services": {"app-category": AOS8_APP_CATEGORY_TO_CENTRAL.get(str(cat), str(cat).upper())}}
    if awt in ("web_cc_cat", "web_cat"):
        cat = rule.get("webcccatgname")
        if not cat:
            return None
        central_val = AOS8_WEB_CATEGORY_TO_CENTRAL.get(str(cat), str(cat).replace("/", "-").upper())
        return {"services": {"web-category": central_val}}
    if awt == "web_cc_rep":
        rep = rule.get("web_rep2") or rule.get("web_rep")
        if not rep:
            return None
        rep_norm = re.sub(r"\d+$", "", str(rep)) or str(rep)
        central_val = AOS8_WEB_REPUTATION_TO_CENTRAL.get(rep_norm, rep_norm.replace("-", "_").upper())
        return {"services": {"web-reputation": central_val}}
    return None


def _build_protocol_port_block(rule: dict) -> Optional[Dict[str, Any]]:
    """Protocol + L4 ports -> Central ip-header / transport-fields block."""
    svc_mode = rule.get("svc")
    if rule.get("service_app") != "service":
        return None
    if svc_mode == "service-name":
        name = rule.get("service-name") or rule.get("service_name")
        if name and str(name).lower() in _ICMPV6_SERVICE_NAMES:
            return {"ip-header": {"protocol": "IPV6_ICMP"}}
        return None
    if svc_mode == "icmp":
        ip_header: Dict[str, Any] = {"protocol": "IP_ICMP"}
        icmp_type = rule.get("icmp_type")
        if icmp_type:
            ip_header["icmp"] = {"icmp-type": str(icmp_type)}
        return {"ip-header": ip_header}
    if svc_mode in ("tcp_udp", "tcp", "udp"):
        proto = rule.get("proto")
        proto_enum = {"tcp": "IP_TCP", "udp": "IP_UDP", "6": "IP_TCP", "17": "IP_UDP"}.get(str(proto).lower())
        if proto_enum is None:
            return None
        out: Dict[str, Any] = {"ip-header": {"protocol": proto_enum}}
        port1 = rule.get("port1")
        port2 = rule.get("port2")
        if port1 is not None:
            min_port = int(port1)
            if port2 is not None and int(port2) != min_port:
                out["transport-fields"] = {
                    "destination-port": {"operator": "COMPARISON_RANGE", "min": min_port, "max": int(port2)}
                }
            else:
                out["transport-fields"] = {"destination-port": {"operator": "COMPARISON_EQ", "min": min_port}}
        return out
    return None


def _determine_rule_type(services_block: Optional[dict], proto_port_block: Optional[dict]) -> str:
    """Pick the Central rule-type enum from the built service/protocol blocks."""
    if services_block is not None:
        services = services_block.get("services", {})
        for key, rtype in (
            ("net-service", "RULE_NET_SERVICE"),
            ("application", "RULE_APPLICATION"),
            ("app-category", "RULE_APP_CATEGORY"),
            ("web-category", "RULE_WEB_CATEGORY"),
            ("web-reputation", "RULE_WEB_REPUTATION"),
        ):
            if key in services:
                return rtype
    if proto_port_block is not None:
        protocol = proto_port_block.get("ip-header", {}).get("protocol")
        if protocol == "IP_TCP":
            return "RULE_TCP"
        if protocol == "IP_UDP":
            return "RULE_UDP"
        return "RULE_PROTOCOL"
    return "RULE_ANY"


def _build_action(rule: dict, unmapped: List[str]) -> Dict[str, Any]:
    """Build the Central ``action`` dict.

    Fail-closed fix: an AOS 8 action with no Central mapping becomes
    ``ACTION_DENY`` (never the old silent ``ACTION_ALLOW`` fall-through) and is
    appended to ``unmapped`` so the policy is flagged unresolved.
    """
    aos8_action = rule.get("action") or rule.get("appaction")
    central_type = _AOS8_ACTION_TO_CENTRAL.get(str(aos8_action))
    if central_type is None:
        unmapped.append(str(aos8_action))
        central_type = "ACTION_DENY"
    action: Dict[str, Any] = {"type": central_type}

    if rule.get("log"):
        action.setdefault("secondary-actions", {})["log"] = True
    if rule.get("blacklist"):
        action.setdefault("secondary-actions", {})["denylist"] = True
    if rule.get("app-send-deny-response"):
        action["send-deny-response"] = True

    if central_type == "ACTION_DESTINATION_NAT":
        dst_nat: Dict[str, Any] = {}
        if rule.get("dnatport") is not None:
            dst_nat["port"] = int(rule["dnatport"])
        if rule.get("dnataddr") is not None:
            dst_nat["ip-address"] = str(rule["dnataddr"])
        if dst_nat:
            action["destination-nat"] = dst_nat
    if central_type == "ACTION_DUAL_NAT":
        dual_nat: Dict[str, Any] = {}
        if rule.get("dualnatpool") is not None:
            dual_nat["nat-pool"] = str(rule["dualnatpool"])
        if rule.get("dualnatport") is not None:
            dual_nat["port"] = int(rule["dualnatport"])
        if dual_nat:
            action["dual-nat"] = dual_nat
    if central_type == "ACTION_REDIRECT":
        re_dir = rule.get("re_dir")
        redirect: Dict[str, Any] = {}
        if re_dir == "tunnel" and rule.get("tunid") is not None:
            redirect = {"destination": "REDIRECT_TUNNEL", "tunnel": int(rule["tunid"])}
        elif re_dir == "tunnel-group" and rule.get("tungrpname") is not None:
            redirect = {"destination": "REDIRECT_TUNNEL_GROUP", "tunnel-group": str(rule["tungrpname"])}
        if redirect:
            action["redirect"] = redirect

    return action


def _build_central_rules(
    aos8_rule: dict,
    address_family: str,
    starting_position: int,
    role_attribution: List[str],
    unmapped: List[str],
) -> List[Dict[str, Any]]:
    """Build 0/1/2 Central rules for one AOS 8 v4/v6 rule (any-any expands to 2)."""
    net_service_block = _build_net_service_block(aos8_rule)
    services_block = net_service_block or _build_services_block(aos8_rule)
    proto_port_block = _build_protocol_port_block(aos8_rule)
    rule_type = _determine_rule_type(services_block, proto_port_block)
    action = _build_action(aos8_rule, unmapped)
    time_range = aos8_rule.get("trname")

    def _make_rule(pos: int, source: dict, destination: dict) -> Dict[str, Any]:
        condition: Dict[str, Any] = {
            "rule-type": rule_type,
            "address-family": address_family,
            "source": source,
            "destination": destination,
        }
        if services_block:
            condition.update(services_block)
        if proto_port_block:
            condition.update(proto_port_block)
        if time_range:
            condition["time-range-name"] = str(time_range)
        return {"position": pos, "condition": condition, "action": action}

    # any-any bidirectional expansion: a rule that is `any any` under a
    # role-attributed ACL becomes two role-scoped rules (role->any, any->role)
    # to preserve the AOS 8 semantics where the role bounds both directions.
    is_any_any = aos8_rule.get("src") == "sany" and aos8_rule.get("dst") == "dany"
    if is_any_any and role_attribution:
        role_addr = {"type": "ADDRESS_ROLE", "role-list": list(role_attribution)}
        any_addr = {"type": "ADDRESS_ANY"}
        return [
            _make_rule(starting_position, role_addr, any_addr),
            _make_rule(starting_position + 1, any_addr, role_addr),
        ]

    src = _build_address(aos8_rule, "src", address_family, role_attribution)
    dst = _build_address(aos8_rule, "dst", address_family, role_attribution)
    if src is None or dst is None:
        return []
    # Role injection (#419): scope a bare `any` side to the attributed role(s).
    if role_attribution and src.get("type") != "ADDRESS_ROLE" and dst.get("type") != "ADDRESS_ROLE":
        role_addr = {"type": "ADDRESS_ROLE", "role-list": list(role_attribution)}
        src_any = src.get("type") == "ADDRESS_ANY"
        dst_any = dst.get("type") == "ADDRESS_ANY"
        if src_any and not dst_any:
            src = role_addr
        elif dst_any and not src_any:
            dst = role_addr
    return [_make_rule(starting_position, src, dst)]


def _iter_source_rules(acl_sess: Dict[str, Any]):
    """Yield (aos8_rule, address_family) for each non-system v4 then v6 rule."""
    for variant_field, address_family in (
        ("acl_sess__v4policy", "IPV4"),
        ("acl_sess__v6policy", "IPV6"),
    ):
        for aos8_rule in acl_sess.get(variant_field) or []:
            if not isinstance(aos8_rule, dict) or (aos8_rule.get("_flags") or {}).get("system"):
                continue
            yield aos8_rule, address_family


def aos8_read_policy_traced(
    acl_sess: Dict[str, Any], *, role_records: Optional[List[dict]] = None
) -> Tuple[CanonicalPolicy, List[Tuple[dict, List[Dict[str, Any]]]]]:
    """Translate one ``acl_sess`` and also return the per-source-rule trace.

    Returns ``(policy, trace)`` where ``trace`` is a list of
    ``(aos8_rule, [central_rules])`` pairs in source order -- the CLI renders the
    side-by-side comparison from this without re-deriving anything.
    """
    if role_records is None:
        raise ValueError(
            "aos8_read_policy requires role_records (every AOS 8 role record) "
            "for the role-attribution reverse-index"
        )
    accname = acl_sess.get("accname")
    role_attribution = _compute_role_attribution(accname, role_records) if accname else []

    rules: List[Dict[str, Any]] = []
    trace: List[Tuple[dict, List[Dict[str, Any]]]] = []
    unmapped: List[str] = []
    position = 1
    for aos8_rule, address_family in _iter_source_rules(acl_sess):
        built = _build_central_rules(aos8_rule, address_family, position, role_attribution, unmapped)
        trace.append((aos8_rule, built))
        if not built:
            continue
        rules.extend(built)
        position += len(built)

    association = ASSOCIATION_INTERFACE if str(accname) in _INTERFACE_ACL_NAMES else ASSOCIATION_ROLE
    policy = CanonicalPolicy(
        name=str(accname or ""),
        association=association,
        rules=rules,
        unmapped_actions=unmapped,
    )
    return policy, trace


def aos8_read_policy(
    acl_sess: Dict[str, Any], *, role_records: Optional[List[dict]] = None
) -> CanonicalPolicy:
    """Build a :class:`CanonicalPolicy` from one AOS 8 ``acl_sess`` record.

    Faithful port of the MCP reader. ``role_records`` (every AOS 8 role record)
    is required for the role-attribution reverse-index, matching the original
    runtime contract.
    """
    policy, _ = aos8_read_policy_traced(acl_sess, role_records=role_records)
    return policy
