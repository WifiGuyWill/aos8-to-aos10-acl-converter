# AOS 8 → AOS 10 ACL / Session-Policy Converter

[![CI](https://github.com/WifiGuyWill/aos8-to-aos10-acl-converter/actions/workflows/ci.yml/badge.svg)](https://github.com/WifiGuyWill/aos8-to-aos10-acl-converter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)

A clean, standalone CLI tool that **converts and validates Aruba AOS 8 session
ACLs and user-roles into AOS 10 (Aruba Central) security policies**.

It parses raw `show running-config` text, translates each `ip access-list
session` block using the validated translation logic ported from the
[hpe-networking-mcp](https://github.com/nowireless4u/hpe-networking-mcp)
project, and produces a clear **side-by-side comparison**, a machine-readable
**Central policy body**, and a **report** flagging anything a network engineer
needs to review — with special attention to **bridge-mode** enforcement
differences.

---

## Why this exists

AOS 8 and AOS 10 model firewall policy differently:

| Concept | AOS 8 | AOS 10 / Central |
|---|---|---|
| Policy object | `ip access-list session <name>` (standalone) | named **security-policy** |
| Role binding | a `user-role` *references* the ACL | the policy is **role-scoped** directly |
| Source `user` | the authenticated client | `ADDRESS_ROLE` (role-list) |
| `any any` under a role | implicitly bounded by the role | must be **expanded** to two role-scoped rules |
| Actions | `permit/deny/src-nat/dst-nat/redirect/...` | `ACTION_ALLOW/ACTION_DENY/ACTION_SOURCE_NAT/...` |
| DPI names | `facebook`, `entertainment/arts`, `high-risk` | `facebook`, `ENTERTAINMENT-AND-ARTS`, `HIGH_RISK` |

This tool automates that translation faithfully, including three subtle-but-critical behaviors carried over from the reference engine:

1. **Role attribution & injection** — a bare `any` side of a rule is scoped to
   the role(s) that reference the ACL, so the migrated policy keeps its original
   intent.
2. **`any any` bidirectional expansion** — an `any any` rule under a role becomes
   two rules (`role → any` and `any → role`).
3. **Fail-closed action handling** — an AOS 8 action with no Central mapping
   becomes `ACTION_DENY` (never a silent `permit`) and the policy is flagged
   **unresolved** for operator review. This avoids the classic
   security-inverting migration bug.

DPI enum translation uses the **vendored Central lookup tables** (≈4,000 apps,
24 app-categories, 85 web-categories, 5 reputation tiers) rather than naive
case/dash munging — 21 web categories insert a connective `AND`
(`entertainment/arts → ENTERTAINMENT-AND-ARTS`) that mechanical transforms get
wrong.

---

## Installation

```bash
# Recommended: use a virtualenv (needs pip >= 21.3 for `pip install -e .`)
python3 -m venv .venv && source .venv/bin/activate

pip install -r requirements.txt        # installs Typer for a polished CLI
# or, for an editable install with the console script:
pip install -e .
```

No install is strictly required — from the repo root you can always run
`python -m aos8_acl_converter convert ...` directly.

The tool is **near-stdlib**. Typer is the only runtime dependency and even that
is optional — if Typer is not installed, an argparse fallback provides the same
CLI. Requires **Python 3.9+**.

---

## Usage

```bash
# From a file
python -m aos8_acl_converter convert running-config.txt

# From stdin (pipe a config or paste and Ctrl-D)
cat running-config.txt | python -m aos8_acl_converter convert -

# If installed via `pip install -e .`, a console script is available:
aos8-acl-convert convert running-config.txt
```

### Options

| Option | Description |
|---|---|
| `-o, --output text\|json\|config` | Output format (default `text`). |
| `--bridge-mode` | Highlight bridge-mode ACL enforcement differences. |
| `-v, --verbose` | Show every generated AOS 10 rule. |
| `-r, --report` | Include the statistics / issue report. |

**Exit code:** `0` on success, `1` when any policy is **unresolved** (unmapped
actions) — so CI/automation can gate a migration on a clean conversion.

---

## Output formats

### `--output text` (default) — side-by-side comparison

```text
AOS 8 -> AOS 10 Security Policy Conversion
============================================================

Policy: corp-acl
  association: role    bound roles: corp
  --------------------------------------------------------
  AOS 8 (session ACL)                AOS 10 (Central policy)
  --------------------------------------------------------
  user any svc-dns permit            role:corp any svc svc-dns permit
  user network 10.0.0.0 255.0.0.0 an role:corp network 10.0.0.0/8 any permit
  user host 10.1.1.50 tcp 3389 deny  role:corp host 10.1.1.50 tcp 3389 deny log
  any any app facebook deny          role:corp any app facebook deny
                                     any role:corp app facebook deny
  any any webcategory gambling deny  role:corp any webcategory GAMBLING deny
                                     any role:corp webcategory GAMBLING deny
  user any any permit                role:corp any any permit
```

Note how `any any app facebook deny` **expands to two role-scoped rules**, and
how bare-`any` sources are **injected with the `corp` role**.

### `--output config` — AOS 10 / Central-style policy block

```text
security-policy corp-acl
  association role
  rule 1 role:corp any svc svc-dns permit
  rule 4 role:corp network 10.0.0.0/8 any permit
  rule 5 role:corp host 10.1.1.50 tcp 3389 deny log
  rule 6 role:corp any app facebook deny
  rule 7 any role:corp app facebook deny
  ...
!
```

### `--output json` — Central config-API policy body

The exact shape the Central configuration API expects (`POLICY_TYPE_SECURITY`
with an ordered `policy-rule[]`). Unresolved policies carry an `_unresolved`
marker so downstream automation blocks the push.

```json
{
  "policies": [
    {
      "name": "corp-acl",
      "type": "POLICY_TYPE_SECURITY",
      "association": "ASSOCIATION_ROLE",
      "security-policy": {
        "type": "SECURITY_POLICY_TYPE_DEFAULT",
        "policy-rule": [
          {
            "position": 1,
            "condition": {
              "rule-type": "RULE_NET_SERVICE",
              "address-family": "IPV4",
              "source": { "type": "ADDRESS_ROLE", "role-list": ["corp"] },
              "destination": { "type": "ADDRESS_ANY" },
              "services": { "net-service": "svc-dns" }
            },
            "action": { "type": "ACTION_ALLOW" }
          }
        ]
      }
    }
  ],
  "report": { "summary": { "...": "..." } }
}
```

---

## Bridge-mode analysis

On AOS 8, a **tunnel-mode** AP forwards traffic to the controller, where the
full stateful firewall (roles, NAT, redirect, DPI) is enforced centrally. In
**bridge mode** traffic egresses at the AP, so only features the AP can enforce
locally apply. `--bridge-mode` flags the rule shapes that commonly do **not**
survive a bridge-mode migration unchanged:

```text
  Bridge-mode advisories
    [branch-acl] rule 2: redirect (tunnel/tunnel-group) requires a controller datapath
    [branch-acl] rule 3: AppRF per-application classification needs on-AP DPI
    [branch-acl] rule 4: WebCC web-category classification is a DPI feature (AP DPI required)
    [branch-acl] rule 5: WebCC web-reputation classification is a DPI feature (AP DPI required)
    [branch-acl] rule 6: dual-NAT is a controller datapath feature
```

Try it:

```bash
python -m aos8_acl_converter convert examples/bridge_mode.cfg --bridge-mode --report
```

---

## Report (`--report`)

Aggregate statistics plus issue callouts:

```text
Conversion Report
============================================================
  policies converted : 3
  source rules       : 17
  generated rules    : 22
  any-any rules      : 5
  dropped rules      : 0
  roles seen         : corp, guest
  netdestination refs: internal-networks

  Action breakdown
    ACTION_ALLOW                 9
    ACTION_DENY                  11
    ACTION_DESTINATION_NAT       1
    ACTION_SOURCE_NAT            1

  Rule-type breakdown
    RULE_NET_SERVICE             6
    RULE_ANY                     5
    RULE_TCP                     1
    ...
```

The report also surfaces **unresolved policies**, **complex/expanded rules**,
**bridge-mode advisories**, and **parse warnings** (with the offending source
line).

---

## What gets translated

| Category | AOS 8 form | AOS 10 / Central |
|---|---|---|
| **Address: any** | `any` | `ADDRESS_ANY` |
| **Address: host** | `host <ip>` | `ADDRESS_HOST` (v4/v6) |
| **Address: network** | `network <ip> <mask>` / `<ip>/<pfx>` | `ADDRESS_NETWORK` (CIDR) |
| **Address: alias** | `<netdestination-name>` | `ADDRESS_ALIAS` (net-group) |
| **Address: user/role** | `user` | `ADDRESS_ROLE` (role-list) |
| **Address: localip** | `localip` | `ADDRESS_LOCAL` |
| **Service: net-service** | `svc-http`, custom aliases | `RULE_NET_SERVICE` |
| **Service: L4** | `tcp <port>`, `udp <lo> <hi>` | `RULE_TCP`/`RULE_UDP` + ports |
| **Service: icmp/icmpv6** | `icmp`, `icmpv6` | `IP_ICMP` / `IPV6_ICMP` |
| **DPI: application** | `app <name>` | `RULE_APPLICATION` |
| **DPI: app-category** | `appcategory <cat>` | `RULE_APP_CATEGORY` |
| **DPI: web-category** | `webcategory <cat>` | `RULE_WEB_CATEGORY` |
| **DPI: web-reputation** | `webreputation <rep>` | `RULE_WEB_REPUTATION` |
| **Actions** | `permit/deny/src-nat/dst-nat/dual-nat/redirect/route/captive/mirror` | `ACTION_*` |
| **Modifiers** | `log`, `blacklist`, `time-range`, `send-deny-response` | secondary-actions |
| **Address family** | v4 and `ipv6 access-list session` | `IPV4` / `IPV6` |

Anything the engine cannot map is **fail-closed to deny** and reported — never
silently permitted.

---

## Programmatic API

```python
from aos8_acl_converter import convert_text

result = convert_text(open("running-config.txt").read(), bridge_mode=True)

for cp in result.converted:
    print(cp.policy.name, "->", len(cp.policy.rules), "rules")
    for issue in cp.stat.bridge_issues:
        print("  bridge:", issue)

print(result.report.to_dict()["summary"])
```

---

## Project layout

```
aos8_acl_converter/
├── __init__.py       # public API
├── __main__.py       # python -m aos8_acl_converter
├── cli.py            # Typer CLI (+ argparse fallback)
├── parser.py         # raw AOS 8 CLI text -> structured acl_sess dicts + roles
├── reader.py         # vendored AOS 8 -> canonical translation logic
├── canonical.py      # CanonicalPolicy model (stdlib dataclass)
├── enum_tables.py    # vendored AOS 8 -> Central DPI enum lookup tables
├── renderer.py       # canonical -> JSON / config / side-by-side
└── report.py         # statistics, issue flagging, bridge-mode analysis
examples/
├── sample_aos8.cfg   # roles, DPI, NAT, IPv6
└── bridge_mode.cfg   # bridge-mode enforcement differences
tests/
└── test_converter.py # unit tests (unittest / pytest compatible)
web/                   # browser frontend (Cloudflare static assets + Pyodide)
├── public/            # served assets (index.html, static/, py/, examples/)
├── build.sh           # syncs the engine into public/py (single source of truth)
├── wrangler.jsonc     # assets-only Worker config
└── package.json       # npm run dev / deploy
```

---

## Web app (browser, no install)

The same engine also runs **entirely in the browser** — no backend, no upload.
The frontend loads [Pyodide](https://pyodide.org) (WASM Python) and calls the
*exact* `aos8_acl_converter` package the CLI uses, so the two can never diverge.
**Your configuration never leaves your device.**

```
web/public/index.html   ──loads──▶  Pyodide (CDN)  ──runs──▶  aos8_acl_converter engine
        static/app.js   mounts the engine files into the in-browser Python FS
        py/web_adapter.py returns one JSON payload the UI renders (side-by-side / config / JSON + report)
```

### Preview locally

```bash
cd web
npm install                # wrangler (+ dev-only pyodide/puppeteer for tests)
npm run dev                # runs build.sh, then `wrangler dev`
# open http://127.0.0.1:8788
```

`npm run build` (invoked by `dev`/`deploy`) copies the engine from
`aos8_acl_converter/` into `web/public/py/` and stages the example configs, so
the browser always runs the current logic.

### Deploy to Cloudflare

Assets-only Worker — no server code to maintain:

```bash
cd web
npx wrangler login         # one-time
npm run deploy             # build.sh + `wrangler deploy`
```

Wrangler prints the deployed URL (e.g. `https://aos8-to-aos10-acl-converter.<subdomain>.workers.dev`).
Add a custom domain in the Cloudflare dashboard if desired. Static assets are
served free/globally; Pyodide fetches its own WASM/stdlib from the jsDelivr CDN.

### Dev checks (optional)

```bash
node verify_pyodide.mjs    # runs the engine under real WASM (no browser)
node e2e_browser.mjs       # headless-Chromium end-to-end (dev server must be up)
```

---

## Testing

```bash
python -m pytest -q          # if pytest is installed
python tests/test_converter.py   # stdlib-only (unittest)
```

---

## Attribution & limitations

- Translation logic (address/service/action builders, role attribution, any-any
  expansion, fail-closed handling) and the DPI enum tables are ported from the
  `hpe-networking-mcp` project's `translations/readers/aos8/policy.py` and
  `translations/policy_enum_tables.py`.
- The reference engine consumes AOS 8's **structured** configuration objects;
  this tool adds a **CLI-text parser** so engineers can feed raw
  `show running-config`. The parser is order-tolerant and covers the common
  session-ACL grammar, but exotic one-off forms may need manual review — such
  lines are reported as **parse warnings**, never dropped silently.
- Always validate generated policies in a lab/Central staging scope before
  production rollout. This tool accelerates and de-risks migration; it does not
  replace change review.
