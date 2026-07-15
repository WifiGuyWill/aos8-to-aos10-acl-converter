"""Command-line interface for the AOS 8 -> AOS 10 ACL converter.

Built on Typer when available; falls back to a small argparse shim so the tool
still runs with only the standard library (``python -m aos8_acl_converter``).

Usage::

    aos8-acl-convert convert running-config.txt
    aos8-acl-convert convert running-config.txt --output json
    cat running-config.txt | aos8-acl-convert convert -
    aos8-acl-convert convert acls.txt --bridge-mode --report --verbose
"""

from __future__ import annotations

import json
import sys
from typing import List, Optional

from .core import ConversionResult, convert_text
from .renderer import (
    policy_to_central_json,
    render_central_config,
    render_rule_summary,
)

# ----------------------------------------------------------------------
# ANSI helpers (auto-disabled when not a TTY or NO_COLOR is set)
# ----------------------------------------------------------------------


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return "\033[{0}m{1}\033[0m".format(code, text) if self.enabled else text

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def dim(self, t: str) -> str:
        return self._wrap("2", t)

    def red(self, t: str) -> str:
        return self._wrap("31", t)

    def green(self, t: str) -> str:
        return self._wrap("32", t)

    def yellow(self, t: str) -> str:
        return self._wrap("33", t)

    def cyan(self, t: str) -> str:
        return self._wrap("36", t)


def _make_style() -> _Style:
    import os

    enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    return _Style(enabled)


# ----------------------------------------------------------------------
# Input handling
# ----------------------------------------------------------------------


def _read_input(input_file: str) -> str:
    """Read config from a file path, or from stdin when path is '-'."""
    if input_file == "-" or input_file is None:
        return sys.stdin.read()
    try:
        with open(input_file, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:  # pragma: no cover - user-facing error path
        raise SystemExit("error: cannot read '{0}': {1}".format(input_file, exc))


# ----------------------------------------------------------------------
# Renderers for each --output mode
# ----------------------------------------------------------------------


def _emit_json(result: ConversionResult) -> str:
    payload = {
        "policies": [policy_to_central_json(cp.policy) for cp in result.converted],
        "report": result.report.to_dict(),
    }
    return json.dumps(payload, indent=2)


def _emit_config(result: ConversionResult) -> str:
    blocks = [render_central_config(cp.policy) for cp in result.converted]
    return "\n".join(blocks) if blocks else "! no session ACLs found in input"


def _emit_text(result: ConversionResult, style: _Style, verbose: bool, show_report: bool) -> str:
    out: List[str] = []
    b, c, d = style.bold, style.cyan, style.dim

    if not result.converted:
        out.append(style.yellow("No `ip access-list session` blocks found in the input."))
        if result.parsed.role_records:
            out.append(d("(parsed {0} user-role block(s) but no ACLs to translate)".format(
                len(result.parsed.role_records))))
        return "\n".join(out)

    out.append(b("AOS 8 -> AOS 10 Security Policy Conversion"))
    out.append(d("=" * 60))

    for cp in result.converted:
        policy, stat = cp.policy, cp.stat
        out.append("")
        header = "Policy: {0}".format(policy.name)
        out.append(b(c(header)))
        assoc = "interface" if policy.association == "ASSOCIATION_INTERFACE" else "role"
        attribution = ", ".join(stat.role_attribution) if stat.role_attribution else "(none)"
        out.append("  association: {0}    bound roles: {1}".format(assoc, attribution))
        if policy.unmapped_actions:
            out.append(style.red("  UNRESOLVED: unmapped actions fail-closed to deny -> {0}".format(
                ", ".join(sorted(set(policy.unmapped_actions))))))

        # Side-by-side: each AOS 8 source rule and the AOS 10 rule(s) it became.
        out.append(d("  " + "-" * 56))
        out.append("  {0:<34} {1}".format("AOS 8 (session ACL)", "AOS 10 (Central policy)"))
        out.append(d("  " + "-" * 56))
        for aos8_rule, central_rules in cp.trace:
            raw = aos8_rule.get("_raw", "")
            if not central_rules:
                out.append("  {0:<34} {1}".format(raw[:34], style.red("DROPPED (no mapping)")))
                continue
            first = True
            for cr in central_rules:
                summary = _summarize_central(cr, style)
                left = raw[:34] if first else ""
                out.append("  {0:<34} {1}".format(left, summary))
                first = False

        if verbose:
            out.append(d("  rules (AOS 10):"))
            for line in render_rule_summary(policy.rules):
                out.append("    " + line)

    if show_report:
        out.append("")
        out.append(_render_report_text(result, style))

    return "\n".join(out)


def _summarize_central(rule: dict, style: _Style) -> str:
    from .renderer import format_condition

    text = format_condition(rule)
    action_type = rule.get("action", {}).get("type", "")
    if action_type == "ACTION_DENY":
        return style.yellow(text)
    if action_type == "ACTION_ALLOW":
        return style.green(text)
    return text


def _render_report_text(result: ConversionResult, style: _Style) -> str:
    b, d = style.bold, style.dim
    rep = result.report
    out: List[str] = []
    out.append(b("Conversion Report"))
    out.append(d("=" * 60))
    out.append("  policies converted : {0}".format(len(rep.policies)))
    out.append("  source rules       : {0}".format(rep.total_source_rules))
    out.append("  generated rules    : {0}".format(rep.total_generated_rules))
    out.append("  any-any rules      : {0}".format(rep.total_any_any))
    out.append("  dropped rules      : {0}".format(rep.total_dropped))
    out.append("  roles seen         : {0}".format(", ".join(rep.roles_seen) or "(none)"))
    if rep.netdestinations:
        out.append("  netdestination refs: {0}".format(", ".join(rep.netdestinations)))

    if rep.aggregate_actions:
        out.append("")
        out.append(b("  Action breakdown"))
        for k, v in sorted(rep.aggregate_actions.items()):
            out.append("    {0:<28} {1}".format(k, v))

    if rep.aggregate_rule_types:
        out.append("")
        out.append(b("  Rule-type breakdown"))
        for k, v in sorted(rep.aggregate_rule_types.items()):
            out.append("    {0:<28} {1}".format(k, v))

    if rep.unresolved_policies:
        out.append("")
        out.append(style.red("  UNRESOLVED policies (need operator review): {0}".format(
            ", ".join(rep.unresolved_policies))))

    # Bridge-mode advisories.
    bridge_lines: List[str] = []
    for p in rep.policies:
        for issue in p.bridge_issues:
            bridge_lines.append("    [{0}] {1}".format(p.name, issue))
    if bridge_lines:
        out.append("")
        out.append(style.yellow(b("  Bridge-mode advisories")))
        out.extend(bridge_lines)

    # Complex-rule callouts.
    complex_lines: List[str] = []
    for p in rep.policies:
        for cx in p.complex_rules:
            complex_lines.append("    [{0}] {1}".format(p.name, cx))
    if complex_lines:
        out.append("")
        out.append(b("  Complex / expanded rules"))
        out.extend(complex_lines)

    # Parse warnings.
    if rep.parse_warnings:
        out.append("")
        out.append(style.yellow(b("  Parse warnings")))
        for w in rep.parse_warnings:
            out.append("    [{0}:{1}] {2}".format(w.acl, w.line_no, w.message))
            out.append(d("        > {0}".format(w.text)))

    return "\n".join(out)


# ----------------------------------------------------------------------
# Shared command body (used by both the Typer and argparse front-ends)
# ----------------------------------------------------------------------


def run_convert(
    input_file: str,
    output: str = "text",
    bridge_mode: bool = False,
    verbose: bool = False,
    report: bool = False,
) -> int:
    """Execute a conversion and print the requested output. Returns exit code."""
    if output not in ("text", "json", "config"):
        print("error: --output must be one of: text, json, config", file=sys.stderr)
        return 2

    text = _read_input(input_file)
    result = convert_text(text, bridge_mode=bridge_mode)
    style = _make_style()

    if output == "json":
        print(_emit_json(result))
    elif output == "config":
        print(_emit_config(result))
        if report:
            print("", file=sys.stderr)
            print(_render_report_text(result, _Style(False)), file=sys.stderr)
    else:
        print(_emit_text(result, style, verbose=verbose, show_report=report or bridge_mode))

    # Non-zero exit when any policy is unresolved so CI/automation can gate on it.
    return 1 if result.report.unresolved_policies else 0


# ----------------------------------------------------------------------
# Front-end: Typer if present, else argparse
# ----------------------------------------------------------------------

try:
    import typer

    app = typer.Typer(
        add_completion=False,
        help="Convert & validate AOS 8 session ACLs / user-roles to AOS 10 (Aruba Central) policies.",
    )

    @app.callback()
    def _root() -> None:
        """AOS 8 -> AOS 10 (Aruba Central) ACL / session-policy converter."""
        # A callback keeps `convert` an explicit subcommand (Typer otherwise
        # collapses a single-command app and drops the subcommand name).

    @app.command()
    def convert(
        input_file: str = typer.Argument(
            ..., metavar="INPUT", help="AOS 8 config file path, or '-' to read stdin."
        ),
        output: str = typer.Option("text", "--output", "-o", help="Output format: text | json | config."),
        bridge_mode: bool = typer.Option(
            False, "--bridge-mode", help="Highlight bridge-mode ACL enforcement differences."
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Show every generated AOS 10 rule."),
        report: bool = typer.Option(False, "--report", "-r", help="Include the statistics/issue report."),
    ) -> None:
        """Convert AOS 8 session ACLs to AOS 10 / Central security policies."""
        raise typer.Exit(code=run_convert(input_file, output, bridge_mode, verbose, report))

    def main(argv: Optional[List[str]] = None) -> None:
        app()

except ImportError:  # pragma: no cover - stdlib fallback
    import argparse

    def main(argv: Optional[List[str]] = None) -> None:
        parser = argparse.ArgumentParser(
            prog="aos8-acl-convert",
            description="Convert & validate AOS 8 session ACLs / user-roles to AOS 10 "
            "(Aruba Central) policies.",
        )
        sub = parser.add_subparsers(dest="command", required=True)
        cv = sub.add_parser("convert", help="Convert AOS 8 session ACLs to AOS 10 policies.")
        cv.add_argument("input_file", metavar="INPUT", help="AOS 8 config file path, or '-' for stdin.")
        cv.add_argument("-o", "--output", default="text", choices=["text", "json", "config"])
        cv.add_argument("--bridge-mode", action="store_true", help="Highlight bridge-mode differences.")
        cv.add_argument("-v", "--verbose", action="store_true", help="Show every generated AOS 10 rule.")
        cv.add_argument("-r", "--report", action="store_true", help="Include the statistics/issue report.")
        args = parser.parse_args(argv)
        if args.command == "convert":
            raise SystemExit(
                run_convert(args.input_file, args.output, args.bridge_mode, args.verbose, args.report)
            )


if __name__ == "__main__":  # pragma: no cover
    main()
