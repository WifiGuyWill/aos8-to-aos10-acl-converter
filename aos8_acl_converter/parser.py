"""Raw AOS 8 CLI text -> structured ``acl_sess`` records + role records.

The HPE Networking MCP reader consumes the *structured* config objects that
AOS 8's configuration API returns (fields like ``acl_sess__v4policy`` with
per-rule discriminators ``src``/``dst``/``svc``/``service_app``/``action`` ...).
Networking engineers, however, work with ``show running-config`` text. This
module bridges that gap: it parses ``ip access-list session`` /
``ipv6 access-list session`` blocks and ``user-role`` blocks straight from CLI
text and emits exactly the dict shape :mod:`aos8_acl_converter.reader` expects.

Each generated rule carries a ``_raw`` key (the original CLI line) so the CLI can
render an accurate AOS 8 <-> AOS 10 side-by-side. ``_raw`` is ignored by the
reader (it only reads known discriminators).

AOS 8 session-ACL rule grammar handled (order-tolerant options)::

    <source> <destination> <service> <action> [extended-action] [options...]

    source/dest : any | user | host <ip> | network <ip> <mask|/prefix>
                  | localip | <alias-name>
    service     : any | <proto-num> | tcp <port>[ <hi>] | udp <port>[ <hi>]
                  | icmp | icmpv6 | <net-service-name>
                  | app <name> | appcategory <cat>
                  | webcategory <cat> | webreputation <rep>
    action      : permit | deny | src-nat [pool <n>] | dst-nat [<ip>] [<port>]
                  | dual-nat [pool <n>] [<port>] | redirect tunnel <id>
                  | redirect tunnel-group <name> | route ... | captive | mirror
    options     : log | blacklist | time-range <name> | send-deny-response
                  | position <n> | queue ... | tos ... | dot1p-priority ... | ...
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ----------------------------------------------------------------------
# Token classification helpers
# ----------------------------------------------------------------------

_ACTION_TOKENS = {
    "permit",
    "deny",
    "src-nat",
    "dst-nat",
    "dual-nat",
    "redirect",
    "route",
    "captive",
    "mirror",
    "drop",
}
# Options that may trail an action; each maps to how many extra tokens it eats.
_OPTION_ARGC = {
    "log": 0,
    "blacklist": 0,
    "send-deny-response": 0,
    "no-oui": 0,
    "pause": 0,
    "disable-scanning": 0,
    "time-range": 1,
    "position": 1,
    "queue": 1,
    "tos": 1,
    "dot1p-priority": 1,
}
_ADDRESS_KEYWORDS = {"any", "user", "host", "network", "localip"}
_SERVICE_APP_KEYWORDS = {"app", "application", "appcategory", "webcategory", "webreputation", "webcc"}


@dataclass
class ParseWarning:
    """A non-fatal issue encountered while parsing a specific line."""

    acl: str
    line_no: int
    text: str
    message: str


@dataclass
class ParseResult:
    """Everything the reader needs, plus provenance for reporting."""

    acl_sessions: List[Dict[str, Any]] = field(default_factory=list)
    role_records: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[ParseWarning] = field(default_factory=list)
    # Netdestination alias names seen (referenced source/dest that resolve to alias).
    netdestinations: List[str] = field(default_factory=list)

    def acl_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        for a in self.acl_sessions:
            if a.get("accname") == name:
                return a
        return None


def _is_ipv4(token: str) -> bool:
    try:
        ipaddress.IPv4Address(token)
        return True
    except ValueError:
        return False


def _is_ipv6(token: str) -> bool:
    try:
        ipaddress.IPv6Address(token)
        return True
    except ValueError:
        return False


def _is_int(token: str) -> bool:
    return bool(re.fullmatch(r"\d+", token))


# ----------------------------------------------------------------------
# Address-side parsing
# ----------------------------------------------------------------------


def _parse_address(tokens: List[str], idx: int, side: str, af_hint: List[str]) -> Tuple[Dict[str, Any], int]:
    """Parse one source/destination starting at ``tokens[idx]``.

    Returns ``(fields, next_idx)`` where ``fields`` are the reader discriminator
    keys for this side. ``side`` is 's' (source) or 'd' (destination).
    ``af_hint`` is a one-element mutable list used to remember an IPv6 sighting.
    """
    tok = tokens[idx].lower()
    fields: Dict[str, Any] = {}

    disc_key = "src" if side == "s" else "dst"

    if tok == "any":
        fields[disc_key] = "sany" if side == "s" else "dany"
        return fields, idx + 1

    if tok == "localip":
        fields[disc_key] = "slocalip" if side == "s" else "dlocalip"
        return fields, idx + 1

    if tok == "user":
        fields[disc_key] = "suser" if side == "s" else "duser"
        return fields, idx + 1

    if tok == "host":
        ip = tokens[idx + 1]
        if _is_ipv6(ip):
            af_hint[0] = "IPV6"
        fields[disc_key] = "shost" if side == "s" else "dhost"
        fields["sipaddr" if side == "s" else "dipaddr"] = ip
        return fields, idx + 2

    if tok == "network":
        addr = tokens[idx + 1]
        consumed = 2
        mask: Any = None
        if "/" in addr:  # CIDR form network 2001:db8::/64 or 10.0.0.0/24
            net, _, prefix = addr.partition("/")
            addr = net
            mask = prefix
        else:
            mask = tokens[idx + 2]
            consumed = 3
        if _is_ipv6(addr):
            af_hint[0] = "IPV6"
            # For IPv6 the reader expects an int prefix in snetmask.
            fields["snetmask" if side == "s" else "dnetmask"] = int(mask)
        else:
            # For IPv4 the reader expects a dotted netmask (converts to prefix).
            fields["snetmask" if side == "s" else "dnetmask"] = _normalize_v4_mask(str(mask))
        fields[disc_key] = "snetwork" if side == "s" else "dnetwork"
        fields["snetaddr" if side == "s" else "dnetaddr"] = addr
        return fields, idx + consumed

    # Bareword -> netdestination alias (e.g. `internal-networks`, `svc-` names
    # never appear in the source position). Treat as an ADDRESS_ALIAS reference.
    fields[disc_key] = "salias" if side == "s" else "dalias"
    fields["srcalias" if side == "s" else "dstalias"] = tokens[idx]
    return fields, idx + 1


def _normalize_v4_mask(mask: str) -> str:
    """Return a dotted IPv4 netmask.

    AOS 8 session ACLs use a normal subnet mask (255.255.255.0). If a CIDR
    prefix slipped in (``network 10.0.0.0/24`` handled elsewhere) or a wildcard
    mask (0.0.0.255) is present, we still hand a dotted mask to the reader; the
    wildcard case is flagged by the caller.
    """
    if _is_int(mask):  # someone wrote a bare prefix length
        try:
            return str(ipaddress.IPv4Network("0.0.0.0/{0}".format(mask)).netmask)
        except ValueError:
            return mask
    return mask


# ----------------------------------------------------------------------
# Service parsing
# ----------------------------------------------------------------------


def _parse_service(tokens: List[str], idx: int) -> Tuple[Dict[str, Any], int, Optional[str]]:
    """Parse the service portion. Returns ``(fields, next_idx, note)``.

    ``note`` carries a human-readable warning (e.g. an unusual protocol number)
    or ``None``.
    """
    tok = tokens[idx].lower()
    fields: Dict[str, Any] = {}
    note: Optional[str] = None

    if tok == "any":
        # No svc/service_app set -> reader yields RULE_ANY.
        return fields, idx + 1, note

    # --- application / web layer (DPI) ------------------------------------
    if tok in ("app", "application"):
        fields["service_app"] = "app_opt"
        fields["app_web_type"] = "app"
        fields["appname"] = tokens[idx + 1]
        return fields, idx + 2, note
    if tok == "appcategory":
        fields["service_app"] = "app_opt"
        fields["app_web_type"] = "app_cat"
        fields["appname"] = tokens[idx + 1]
        return fields, idx + 2, note
    if tok in ("webcategory", "webcc"):
        fields["service_app"] = "app_opt"
        fields["app_web_type"] = "web_cc_cat"
        fields["webcccatgname"] = tokens[idx + 1]
        return fields, idx + 2, note
    if tok == "webreputation":
        fields["service_app"] = "app_opt"
        fields["app_web_type"] = "web_cc_rep"
        fields["web_rep2"] = tokens[idx + 1]
        return fields, idx + 2, note

    # --- classic L3/L4 service -------------------------------------------
    fields["service_app"] = "service"

    if tok in ("tcp", "udp"):
        fields["svc"] = tok
        fields["proto"] = tok
        consumed = 1
        # Optional port or port-range follows.
        if idx + 1 < len(tokens) and _is_int(tokens[idx + 1]):
            fields["port1"] = int(tokens[idx + 1])
            consumed = 2
            if idx + 2 < len(tokens) and _is_int(tokens[idx + 2]) and not _looks_like_action(tokens, idx + 2):
                fields["port2"] = int(tokens[idx + 2])
                consumed = 3
        return fields, idx + consumed, note

    if tok in ("icmp", "icmpv6", "icmp6"):
        if tok in ("icmpv6", "icmp6"):
            # Reader routes icmpv6 via the net-service-name path (IPV6_ICMP).
            fields["svc"] = "service-name"
            fields["service-name"] = tok
        else:
            fields["svc"] = "icmp"
        return fields, idx + 1, note

    if _is_int(tok):
        # Raw IP protocol number. Map the common ones the reader understands.
        pnum = int(tok)
        if pnum == 6:
            fields["svc"] = "tcp"
            fields["proto"] = "6"
        elif pnum == 17:
            fields["svc"] = "udp"
            fields["proto"] = "17"
        elif pnum == 1:
            fields["svc"] = "icmp"
        elif pnum == 58:
            fields["svc"] = "service-name"
            fields["service-name"] = "icmpv6"
        else:
            # Uncommon protocol -> pass through as a named service; reader will
            # emit RULE_ANY for it, so we flag it for the operator.
            fields["svc"] = "service-name"
            fields["service-name"] = tok
            note = "IP protocol number {0} has no direct Central L4 mapping".format(pnum)
        return fields, idx + 1, note

    # Named net-service alias (svc-http, svc-dns, custom aliases, ...).
    fields["svc"] = "service-name"
    fields["service-name"] = tokens[idx]
    return fields, idx + 1, note


def _looks_like_action(tokens: List[str], idx: int) -> bool:
    return idx < len(tokens) and tokens[idx].lower() in _ACTION_TOKENS


# ----------------------------------------------------------------------
# Action + options parsing
# ----------------------------------------------------------------------


def _parse_action_and_options(
    tokens: List[str], idx: int
) -> Tuple[Dict[str, Any], List[str]]:
    """Parse action + trailing options from ``tokens[idx:]``.

    Returns ``(fields, unknown_options)``.
    """
    fields: Dict[str, Any] = {}
    unknown: List[str] = []
    n = len(tokens)
    i = idx
    action_set = False

    while i < n:
        tok = tokens[i].lower()

        if not action_set and tok in _ACTION_TOKENS:
            action_set = True
            if tok == "drop":
                fields["action"] = "deny"
            elif tok == "src-nat":
                fields["action"] = "src-nat"
                if i + 2 < n and tokens[i + 1].lower() == "pool":
                    fields["srcnatpool"] = tokens[i + 2]
                    i += 2
            elif tok == "dst-nat":
                fields["action"] = "dst-nat"
                # Optional: [ip <ip>] [<port>] or [<ip>] [<port>]
                j = i + 1
                if j < n and tokens[j].lower() == "ip":
                    j += 1
                if j < n and (_is_ipv4(tokens[j]) or _is_ipv6(tokens[j])):
                    fields["dnataddr"] = tokens[j]
                    j += 1
                if j < n and _is_int(tokens[j]):
                    fields["dnatport"] = int(tokens[j])
                    j += 1
                i = j - 1
            elif tok == "dual-nat":
                fields["action"] = "dual-nat"
                j = i + 1
                if j + 1 < n and tokens[j].lower() == "pool":
                    fields["dualnatpool"] = tokens[j + 1]
                    j += 2
                if j < n and _is_int(tokens[j]):
                    fields["dualnatport"] = int(tokens[j])
                    j += 1
                i = j - 1
            elif tok == "redirect":
                fields["action"] = "redirect"
                if i + 2 < n and tokens[i + 1].lower() == "tunnel":
                    fields["re_dir"] = "tunnel"
                    fields["tunid"] = int(tokens[i + 2]) if _is_int(tokens[i + 2]) else tokens[i + 2]
                    i += 2
                elif i + 2 < n and tokens[i + 1].lower() == "tunnel-group":
                    fields["re_dir"] = "tunnel-group"
                    fields["tungrpname"] = tokens[i + 2]
                    i += 2
            elif tok == "route":
                fields["action"] = "route"
                # Consume the rest of the route target (next-hop-list name, etc.)
                if i + 1 < n:
                    i = n - 1
            else:
                fields["action"] = tok  # permit / deny / captive / mirror
            i += 1
            continue

        # Options (may appear before or after action; e.g. `permit log`).
        if tok in _OPTION_ARGC:
            argc = _OPTION_ARGC[tok]
            if tok == "log":
                fields["log"] = True
            elif tok == "blacklist":
                fields["blacklist"] = True
            elif tok == "send-deny-response":
                fields["app-send-deny-response"] = True
            elif tok == "time-range":
                if i + 1 < n:
                    fields["trname"] = tokens[i + 1]
            # position/queue/tos/dot1p-priority are captured but not translated.
            i += 1 + argc
            continue

        if tok == "mirror" and action_set:
            # Trailing mirror modifier on a permit/deny rule.
            fields.setdefault("mirror_flag", True)
            i += 1
            continue

        # Anything else is an unrecognized trailing token.
        unknown.append(tokens[i])
        i += 1

    return fields, unknown


# ----------------------------------------------------------------------
# Rule + block parsing
# ----------------------------------------------------------------------


def _tokenize(line: str) -> List[str]:
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


def _parse_rule_line(line: str, address_family_default: str) -> Tuple[Optional[Dict[str, Any]], List[str], str]:
    """Parse one ACL rule line -> (rule_dict, warnings, address_family).

    ``rule_dict`` is ``None`` when the line is not a rule (blank / comment).
    """
    warnings: List[str] = []
    raw = line.strip()
    tokens = _tokenize(raw)
    if not tokens:
        return None, warnings, address_family_default

    af_hint = [address_family_default]
    rule: Dict[str, Any] = {}

    # A leading `ipv6` keyword forces v6 family for this rule.
    idx = 0
    if tokens[0].lower() == "ipv6":
        af_hint[0] = "IPV6"
        idx = 1

    try:
        src_fields, idx = _parse_address(tokens, idx, "s", af_hint)
        rule.update(src_fields)
        dst_fields, idx = _parse_address(tokens, idx, "d", af_hint)
        rule.update(dst_fields)
        svc_fields, idx, svc_note = _parse_service(tokens, idx)
        rule.update(svc_fields)
        if svc_note:
            warnings.append(svc_note)
        action_fields, unknown = _parse_action_and_options(tokens, idx)
        rule.update(action_fields)
        if unknown:
            warnings.append("unrecognized tokens: {0}".format(" ".join(unknown)))
    except IndexError:
        return None, ["incomplete/unparseable rule -- skipped"], af_hint[0]

    if "action" not in rule and "appaction" not in rule:
        # App rules carry permit/deny in `action` too (set above); a rule with no
        # action verb is malformed.
        warnings.append("no action verb found -- rule fail-closes to deny on translation")

    rule["_raw"] = raw
    return rule, warnings, af_hint[0]


# Header patterns.
_ACL_HDR = re.compile(r"^(ip|ipv6)\s+access-list\s+session\s+(\S+)\s*$", re.IGNORECASE)
_ROLE_HDR = re.compile(r"^user-role\s+(\S+)\s*$", re.IGNORECASE)
_ROLE_ACL = re.compile(r"^access-list\s+session\s+(\S+)", re.IGNORECASE)
_NETDEST_HDR = re.compile(r"^(?:ipv6\s+)?netdestination(?:6)?\s+(\S+)", re.IGNORECASE)


def parse_config(text: str) -> ParseResult:
    """Parse a full AOS 8 running-config (or ACL/role fragment) from text.

    Blocks are delimited by indentation: a header line at column 0 opens a block;
    indented lines belong to it; a non-indented line (or ``!``) closes it. This
    mirrors how ``show running-config`` renders on AOS 8.
    """
    result = ParseResult()
    lines = text.splitlines()

    current_kind: Optional[str] = None  # "acl" | "role"
    current_acl: Optional[Dict[str, Any]] = None
    current_acl_default_af = "IPV4"
    current_role: Optional[Dict[str, Any]] = None
    netdests = set()

    def _close():
        nonlocal current_kind, current_acl, current_role
        current_kind = None
        current_acl = None
        current_role = None

    for line_no, raw_line in enumerate(lines, start=1):
        if not raw_line.strip() or raw_line.strip() == "!":
            _close()
            continue

        indented = raw_line[:1] in (" ", "\t")
        stripped = raw_line.strip()

        # Track netdestination aliases for reporting (not translated here).
        m_nd = _NETDEST_HDR.match(stripped)
        if m_nd and not indented:
            netdests.add(m_nd.group(1))

        if not indented:
            # A new top-level line closes any open block first.
            m_acl = _ACL_HDR.match(stripped)
            if m_acl:
                family = "IPV6" if m_acl.group(1).lower() == "ipv6" else "IPV4"
                name = m_acl.group(2)
                current_acl = {
                    "accname": name,
                    "acl_sess__v4policy": [],
                    "acl_sess__v6policy": [],
                }
                current_acl_default_af = family
                current_kind = "acl"
                result.acl_sessions.append(current_acl)
                continue

            m_role = _ROLE_HDR.match(stripped)
            if m_role:
                current_role = {"rname": m_role.group(1), "role__acl": [], "_flags": {}}
                current_kind = "role"
                result.role_records.append(current_role)
                continue

            # Some other top-level command -> close current block.
            _close()
            continue

        # Indented line -> belongs to the open block.
        if current_kind == "acl" and current_acl is not None:
            rule, warns, af = _parse_rule_line(stripped, current_acl_default_af)
            for w in warns:
                result.warnings.append(ParseWarning(current_acl["accname"], line_no, stripped, w))
            if rule is not None and ("action" in rule or "appaction" in rule or "svc" in rule
                                     or rule.get("src") is not None):
                key = "acl_sess__v6policy" if af == "IPV6" else "acl_sess__v4policy"
                current_acl[key].append(rule)
                # Collect alias references as netdestinations for the report.
                for al in (rule.get("srcalias"), rule.get("dstalias")):
                    if al:
                        netdests.add(al)
        elif current_kind == "role" and current_role is not None:
            m = _ROLE_ACL.match(stripped)
            if m:
                current_role["role__acl"].append({"acl_type": "session", "pname": m.group(1)})

    result.netdestinations = sorted(netdests)
    return result
