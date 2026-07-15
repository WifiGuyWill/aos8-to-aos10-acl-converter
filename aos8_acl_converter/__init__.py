"""AOS 8 -> AOS 10 (Aruba Central) ACL / session-policy converter.

A standalone CLI + library that parses AOS 8 ``show running-config`` session
ACLs and user-roles, translates them to Aruba Central security policies using
the validated HPE Networking MCP translation logic, and reports on anything that
needs operator attention (unmapped actions, complex/expanded rules, and
bridge-mode enforcement differences).

Public API::

    from aos8_acl_converter import convert_text
    result = convert_text(open("running-config.txt").read(), bridge_mode=True)
    for cp in result.converted:
        print(cp.policy.name, len(cp.policy.rules))
"""

from __future__ import annotations

from .canonical import CanonicalPolicy
from .core import ConversionResult, ConvertedPolicy, convert_text
from .parser import ParseResult, parse_config
from .reader import aos8_read_policy, aos8_read_policy_traced
from .renderer import policy_to_central_json, render_central_config
from .report import ConversionReport, PolicyStat

__version__ = "1.0.0"

__all__ = [
    "CanonicalPolicy",
    "ConversionResult",
    "ConvertedPolicy",
    "convert_text",
    "ParseResult",
    "parse_config",
    "aos8_read_policy",
    "aos8_read_policy_traced",
    "policy_to_central_json",
    "render_central_config",
    "ConversionReport",
    "PolicyStat",
    "__version__",
]
