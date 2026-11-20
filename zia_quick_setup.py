#!/usr/bin/env python3
"""
zia_quick_setup.py - Stage ZIA policy for the "Securing Amazon Quick" demo.

Creates (idempotently, by name):
  1. Custom URL category  "Amazon Quick (Demo)"  covering Quick web/API domains
  2. URL Filtering rule   "Amazon Quick - Coach (Demo)"   action CAUTION (AUP coaching page)
  3. Web DLP rule         "Amazon Quick - Block PII/PCI (Demo)"  action BLOCK
  4. Activates the changes

DRY RUN BY DEFAULT. Nothing is written until you pass --apply.

Auth: Zscaler OneAPI (ZIdentity OAuth client-credentials).
  export ZS_VANITY=yourcompany          # https://yourcompany.zslogin.net
  export ZS_CLIENT_ID=...
  export ZS_CLIENT_SECRET=...
  python3 zia_quick_setup.py                 # dry run: shows what it would create
  python3 zia_quick_setup.py --apply         # create + activate
  python3 zia_quick_setup.py --teardown --apply   # remove demo objects

Tested shape against the public ZIA API docs / zscaler-sdk-python object models.
Run the dry run first in any new tenant; field names occasionally differ by cloud/version.
"""
import argparse
import json
import os
import sys

import requests

API_BASE = "https://api.zsapi.net/zia/api/v1"
AUDIENCE = "https://api.zscaler.com"

CATEGORY_NAME = "Amazon Quick (Demo)"
URL_RULE_NAME = "Amazon Quick - Coach (Demo)"
DLP_RULE_NAME = "Amazon Quick - Block PII/PCI (Demo)"

# Quick launch regions: us-east-1, us-west-2, ap-southeast-2, eu-west-1.
# Leading "." = match all subdomains. Source: AWS "Domains accessed by Quick".
QUICK_REGIONS = ["us-east-1", "us-west-2", "ap-southeast-2", "eu-west-1"]
QUICK_URLS = (
    [".quicksight.aws.amazon.com"]
    + [f"quicksight.{r}.amazonaws.com" for r in QUICK_REGIONS]
    + [f"{r}.signin.aws" for r in QUICK_REGIONS]
)

# Predefined DLP engine names to look for (substring match, case-insensitive).
DEFAULT_ENGINES = ["PCI", "PII", "GLBA"]


class ZiaError(Exception):
    """Raised for auth/API failures so callers (CLI or GUI) can show the message."""


class ZIA:
    def __init__(self, vanity, client_id, client_secret, verify=True):
        self.s = requests.Session()
        self.s.verify = verify
        tok = self.s.post(
            f"https://{vanity}.zslogin.net/oauth2/v1/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "audience": AUDIENCE,
            },
            timeout=30,
        )
        if tok.status_code != 200:
            raise ZiaError(f"[auth] token request failed {tok.status_code}: {tok.text[:300]}")
        self.s.headers.update(
            {"Authorization": f"Bearer {tok.json()['access_token']}",
             "Content-Type": "application/json"}
        )

    def _req(self, method, path, **kw):
        r = self.s.request(method, API_BASE + path, timeout=60, **kw)
        if r.status_code >= 400:
            raise ZiaError(f"[api] {method} {path} -> {r.status_code}: {r.text[:500]}")
        return r.json() if r.text.strip() else {}

    def get(self, p, **kw):    return self._req("GET", p, **kw)
    def post(self, p, body):   return self._req("POST", p, data=json.dumps(body))
    def delete(self, p):       return self._req("DELETE", p)


def find_by_name(items, name, key="name"):
    return next((i for i in items if i.get(key) == name), None)


def show(title, body, log=print):
    log(f"\n--- {title} ---\n{json.dumps(body, indent=2)}")


def setup(z, apply, engine_names, log=print):
    changed = False

    # 1. Custom URL category
    cats = z.get("/urlCategories", params={"customOnly": "true"})
    cat = find_by_name(cats, CATEGORY_NAME, key="configuredName")
    cat_body = {
        "configuredName": CATEGORY_NAME,
        "superCategory": "USER_DEFINED",
        "customCategory": True,
        "urls": QUICK_URLS,
        "description": "Amazon Quick web app, API and native sign-in domains (demo kit)",
    }
    if cat:
        log(f"[ok] URL category exists: {cat['id']}")
        cat_id = cat["id"]
    else:
        show("CREATE URL category", cat_body, log)
        cat_id = "CUSTOM_xx"
        if apply:
            cat_id = z.post("/urlCategories", cat_body)["id"]
            log(f"[+] created {cat_id}")
            changed = True

    # 2. URL filtering rule (CAUTION = coaching / AUP page on first visit)
    rules = z.get("/urlFilteringRules")
    if find_by_name(rules, URL_RULE_NAME):
        log(f"[ok] URL filtering rule exists: {URL_RULE_NAME}")
    else:
        body = {
            "name": URL_RULE_NAME,
            "order": 1,
            "rank": 7,
            "state": "ENABLED",
            "action": "CAUTION",
            "urlCategories": [cat_id],
            "protocols": ["ANY_RULE"],
            "requestMethods": ["CONNECT", "GET", "HEAD"],
            "description": "Show AUP coaching before Amazon Quick use (demo kit)",
        }
        show("CREATE URL filtering rule", body, log)
        if apply:
            z.post("/urlFilteringRules", body)
            log("[+] created URL filtering rule")
            changed = True

    # 3. Web DLP rule
    engines = z.get("/dlpEngines")
    picked = []
    for want in engine_names:
        m = next((e for e in engines
                  if want.lower() in (e.get("name") or e.get("predefinedEngineName") or "").lower()),
                 None)
        if m:
            picked.append({"id": m["id"], "name": m.get("name")})
    if not picked:
        names = ", ".join(sorted(e.get("name", "?") for e in engines))
        raise ZiaError(f"[dlp] none of {engine_names} found. Available engines: {names}")
    log(f"[ok] DLP engines: {', '.join(p['name'] for p in picked)}")

    dlp_rules = z.get("/webDlpRules")
    if find_by_name(dlp_rules, DLP_RULE_NAME):
        log(f"[ok] DLP rule exists: {DLP_RULE_NAME}")
    else:
        body = {
            "name": DLP_RULE_NAME,
            "order": 1,
            "rank": 7,
            "state": "ENABLED",
            "action": "BLOCK",
            "protocols": ["HTTPS_RULE", "HTTP_RULE"],
            "urlCategories": [{"id": cat_id}],
            "dlpEngines": [{"id": p["id"]} for p in picked],
            "withoutContentInspection": False,
            "matchOnly": False,
            "description": "Block PII/PCI in Amazon Quick prompts and uploads (demo kit)",
        }
        show("CREATE Web DLP rule", body, log)
        if apply:
            z.post("/webDlpRules", body)
            log("[+] created DLP rule")
            changed = True

    return changed


def teardown(z, apply, log=print):
    changed = False
    for path, name, key in [("/webDlpRules", DLP_RULE_NAME, "name"),
                            ("/urlFilteringRules", URL_RULE_NAME, "name")]:
        hit = find_by_name(z.get(path), name, key)
        if hit:
            log(f"[-] delete {path}/{hit['id']} ({name})")
            if apply:
                z.delete(f"{path}/{hit['id']}")
                changed = True
    cat = find_by_name(z.get("/urlCategories", params={"customOnly": "true"}),
                       CATEGORY_NAME, key="configuredName")
    if cat:
        log(f"[-] delete /urlCategories/{cat['id']} ({CATEGORY_NAME})")
        if apply:
            z.delete(f"/urlCategories/{cat['id']}")
            changed = True
    return changed


def run(z, apply=False, do_teardown=False, engine_names=None, log=print):
    """Setup or teardown, then activate if anything changed. Returns True if changes were made."""
    changed = (teardown(z, apply, log) if do_teardown
               else setup(z, apply, engine_names or DEFAULT_ENGINES, log))
    if changed:
        z.post("/status/activate", {})
        log("[✓] Changes activated.")
    elif not apply:
        log("Dry run complete. Nothing was changed.")
    else:
        log("Nothing to change.")
    return changed


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="actually write changes (default: dry run)")
    ap.add_argument("--teardown", action="store_true", help="remove the demo objects")
    ap.add_argument("--engines", nargs="+", default=DEFAULT_ENGINES,
                    help="DLP engine names to match (substring)")
    ap.add_argument("--ca-bundle", help="CA bundle path if you sit behind SSL inspection")
    a = ap.parse_args()

    env = {k: os.environ.get(k) for k in ("ZS_VANITY", "ZS_CLIENT_ID", "ZS_CLIENT_SECRET")}
    missing = [k for k, v in env.items() if not v]
    if missing:
        sys.exit(f"Set env vars: {', '.join(missing)}")

    try:
        z = ZIA(env["ZS_VANITY"], env["ZS_CLIENT_ID"], env["ZS_CLIENT_SECRET"],
                verify=a.ca_bundle or True)
        print(f"Mode: {'APPLY' if a.apply else 'DRY RUN'}  |  {'TEARDOWN' if a.teardown else 'SETUP'}")
        run(z, a.apply, a.teardown, a.engines)
    except ZiaError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
