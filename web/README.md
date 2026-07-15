# Web frontend — AOS 8 → AOS 10 ACL Converter

A zero-backend web UI for the `aos8_acl_converter` engine. It loads
[Pyodide](https://pyodide.org) (WASM Python) in the browser and runs the **exact
same** Python package the CLI uses — so the CLI and the website can never
diverge. **Configs never leave the browser** (no upload, no logging, no server).

Hosting is a Cloudflare **assets-only Worker**: Cloudflare just serves the static
files in `public/`; there is no server-side code.

## How it works

```
public/index.html          the UI (paste box, toggles, output switch)
  static/app.js            loads Pyodide from CDN, mounts the engine into the
                           in-browser Python filesystem, calls web_adapter.run()
  static/style.css         styling
  py/aos8_acl_converter/   copy of the engine package (kept in sync by build.sh)
  py/web_adapter.py        thin adapter: text + bridge flag -> one JSON payload
  examples/*.cfg           sample configs for the "Load sample" buttons
```

`build.sh` copies the engine from the repo's top-level `aos8_acl_converter/`
(the single source of truth) into `public/py/`, excluding the CLI-only modules
(`cli.py`, `__main__.py`, which need Typer and aren't used in the browser).

## Commands

```bash
npm install        # wrangler + dev-only pyodide/puppeteer (for tests)
npm run build      # sync engine + examples into public/
npm run dev        # build, then wrangler dev  -> http://127.0.0.1:8788
npm run deploy     # build, then wrangler deploy
```

## Tests (dev-only, not deployed)

```bash
node verify_pyodide.mjs   # imports + runs the engine under real WASM (no browser)
node e2e_browser.mjs      # headless-Chromium drives the actual UI (dev server up)
```

## Notes

- Requires `compatibility_date >= 2025-04-01` for the SPA `not_found_handling`.
- Pyodide downloads its runtime/stdlib from `cdn.jsdelivr.net` on first load
  (a few MB, cached by the browser afterwards). The engine itself is tiny.
- Translation stays **fail-closed**: any unmapped AOS 8 action becomes `deny`
  and the policy is flagged — never silently permitted.
