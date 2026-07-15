"""Browser-facing adapter over the AOS 8 -> AOS 10 engine.

Runs inside Pyodide (WASM Python) in the user's browser. It calls the *same*
``aos8_acl_converter`` engine the CLI uses and returns one JSON-serializable
payload the JavaScript frontend renders as HTML. No network, no CLI, no ANSI --
just structured data.
"""

from __future__ import annotations

import json

from aos8_acl_converter.core import convert_text
from aos8_acl_converter.renderer import (
    format_condition,
    policy_to_central_json,
    render_central_config,
    render_netdestinations,
)


def run(text: str, bridge_mode: bool = False) -> str:
    """Translate ``text`` and return a JSON string for the web UI.

    The payload mirrors every CLI surface: per-policy side-by-side trace,
    Central-style config block, Central JSON body, per-policy stats, the
    aggregate report, and parse warnings.
    """
    result = convert_text(text or "", bridge_mode=bool(bridge_mode))

    policies = []
    for cp in result.converted:
        trace = []
        for aos8_rule, central_rules in cp.trace:
            trace.append(
                {
                    "aos8": aos8_rule.get("_raw", ""),
                    "aos10": [format_condition(r) for r in central_rules],
                    "dropped": len(central_rules) == 0,
                    "expanded": len(central_rules) > 1,
                }
            )
        stat = cp.stat
        policies.append(
            {
                "name": cp.policy.name,
                "association": "interface"
                if cp.policy.association == "ASSOCIATION_INTERFACE"
                else "role",
                "role_attribution": stat.role_attribution,
                "unresolved": cp.policy.is_unresolved,
                "unmapped_actions": sorted(set(cp.policy.unmapped_actions)),
                "trace": trace,
                "config": render_central_config(cp.policy),
                "central_json": policy_to_central_json(cp.policy),
                "stat": {
                    "source_rules": stat.source_rule_count,
                    "generated_rules": stat.generated_rule_count,
                    "any_any": stat.any_any_rules,
                    "dropped": stat.dropped_rules,
                    "ipv6": stat.ipv6_rules,
                    "rule_types": stat.rule_types,
                    "actions": stat.actions,
                    "bridge_issues": stat.bridge_issues,
                    "complex_rules": stat.complex_rules,
                },
            }
        )

    warnings = [
        {"acl": w.acl, "line": w.line_no, "text": w.text, "message": w.message}
        for w in result.parsed.warnings
    ]

    # Netdestination objects parsed from the config (name + entries).
    netdests = [
        {
            "name": nd.name,
            "fqdns": nd.fqdns,
            "hosts": nd.hosts,
            "networks": nd.networks,
            "is_ipv6": nd.is_ipv6,
            "mixed_af": nd.mixed_af,
            "entry_count": nd.entry_count,
        }
        for nd in result.parsed.netdest_objects
    ]

    payload = {
        "ok": True,
        "policies": policies,
        "report": result.report.to_dict(),
        "warnings": warnings,
        "netdestinations": netdests,
        "netdest_config": render_netdestinations(result.parsed.netdest_objects),
        "central_json_all": {
            "policies": [policy_to_central_json(cp.policy) for cp in result.converted],
            "named_destinations": [
                {
                    "name": nd.name,
                    "address_family": "ipv6" if nd.is_ipv6 else "ipv4",
                    "mixed_af_warning": nd.mixed_af,
                    "fqdns": nd.fqdns,
                    "hosts": nd.hosts,
                    "networks": nd.networks,
                }
                for nd in result.parsed.netdest_objects
            ],
        },
    }
    return json.dumps(payload)
