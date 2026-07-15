"""End-to-end conversion pipeline: raw AOS 8 text -> translated policies + report.

Ties the pieces together so both the CLI and any programmatic caller share one
code path: :func:`parse_config` -> :func:`aos8_read_policy_traced` (per ACL) ->
:func:`analyze_policy` -> aggregate :class:`ConversionReport`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Tuple

from .canonical import CanonicalPolicy
from .parser import ParseResult, parse_config
from .reader import _compute_role_attribution, aos8_read_policy_traced
from .report import ConversionReport, PolicyStat, analyze_policy


@dataclass
class ConvertedPolicy:
    """One AOS 8 session ACL fully translated, with its trace and stats."""

    policy: CanonicalPolicy
    trace: List[Tuple[dict, list]]
    stat: PolicyStat


@dataclass
class ConversionResult:
    """The full result of converting an AOS 8 config blob."""

    parsed: ParseResult
    converted: List[ConvertedPolicy] = field(default_factory=list)
    report: ConversionReport = field(default_factory=ConversionReport)


def convert_text(text: str, *, bridge_mode: bool = False) -> ConversionResult:
    """Parse, translate, and analyze an AOS 8 config (or ACL/role fragment).

    Args:
        text: raw AOS 8 running-config or a fragment containing
            ``ip access-list session`` / ``user-role`` blocks.
        bridge_mode: when True, flag rules whose enforcement differs on a
            bridged AP (see :mod:`aos8_acl_converter.report`).

    Returns:
        A :class:`ConversionResult` with per-policy translations and an
        aggregate :class:`ConversionReport`.
    """
    parsed = parse_config(text)
    role_records = parsed.role_records

    result = ConversionResult(parsed=parsed)
    report = ConversionReport()
    report.parse_warnings = parsed.warnings
    report.netdestinations = parsed.netdestinations
    report.roles_seen = [r.get("rname") for r in role_records if r.get("rname")]

    for acl_sess in parsed.acl_sessions:
        policy, trace = aos8_read_policy_traced(acl_sess, role_records=role_records)
        role_attr = _compute_role_attribution(acl_sess.get("accname"), role_records)
        stat = analyze_policy(policy, trace, role_attr, bridge_mode=bridge_mode)
        result.converted.append(ConvertedPolicy(policy=policy, trace=trace, stat=stat))
        report.policies.append(stat)

    result.report = report
    return result
