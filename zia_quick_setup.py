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
# ZIA rule names max out at 31 characters.
URL_RULE_NAME = "Quick - Coach (Demo)"
DLP_RULE_NAME = "Quick - Block PII/PCI (Demo)"
SSL_RULE_NAME = "Quick - Inspect (Demo)"
USER_GROUP_NAME = "Amazon Quick Demo"
TEST_USER_DISPLAY = "Quick Demo User"

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
    def put(self, p, body):    return self._req("PUT", p, data=json.dumps(body))
    def delete(self, p):       return self._req("DELETE", p)


def find_by_name(items, name, key="name"):
    return next((i for i in items if i.get(key) == name), None)


def show(title, body, log=print):
    log(f"\n--- {title} ---\n{json.dumps(body, indent=2)}")


SSL_DECRYPT = {"type": "DECRYPT",
               "decryptSubActions": {"serverCertificates": "ALLOW", "ocspCheck": True,
                                     "blockSslTrafficWithNoSniEnabled": False,
                                     "minClientTLSVersion": "CLIENT_TLS_1_0", "minServerTLSVersion": "SERVER_TLS_1_0",
                                     "blockUndecrypt": False}}


def _scope_ids(rule):
    return sorted(str(u.get("id")) for u in (rule.get("users") or []))


def _ensure_rule(z, path, name, body, users, apply, log, label):
    """Create the rule if missing; if it exists with a different user scope, update its scope. Returns changed."""
    want = [{"id": u} for u in users]
    existing = find_by_name(z.get(path), name)
    if existing:
        if _scope_ids(existing) == sorted(str(u) for u in users):
            log(f"[ok] {label} exists: {name}")
            return False
        log(f"[~] {label} '{name}': scope -> {'user ' + ', '.join(map(str, users)) if users else 'everyone'}")
        if apply:
            upd = dict(existing, users=want)
            z.put(f"{path}/{existing['id']}", upd)
        return apply
    if users:
        body = dict(body, users=want)
    show(f"CREATE {label}", body, log)
    if apply:
        z.post(path, body)
        log(f"[+] created {label}")
    return apply


def setup(z, apply, engine_names, log=print, user_ids=None, ssl=True):
    """URL category, SSL inspection (DECRYPT) for it, Caution URL rule, Block DLP rule.
    user_ids: scope every rule to these ZIA user IDs (recommended: a test user); None/[] = everyone."""
    users = [u for u in (user_ids or []) if u]
    changed = False
    log(f"Scope: {'user ID ' + ', '.join(map(str, users)) if users else 'everyone in the tenant (no test user picked)'}")

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

    # 2. SSL inspection: decrypt Quick traffic so DLP can see prompts and uploads
    if ssl:
        changed |= _ensure_rule(z, "/sslInspectionRules", SSL_RULE_NAME, {
            "name": SSL_RULE_NAME, "order": 1, "rank": 7, "state": "ENABLED",
            "urlCategories": [cat_id], "action": SSL_DECRYPT,
            "description": "Decrypt Amazon Quick so DLP can inspect prompts and uploads (demo kit)",
        }, users, apply, log, "SSL inspection rule")

    # 3. URL filtering rule (CAUTION = coaching / AUP page on first visit)
    changed |= _ensure_rule(z, "/urlFilteringRules", URL_RULE_NAME, {
        "name": URL_RULE_NAME, "order": 1, "rank": 7, "state": "ENABLED", "action": "CAUTION",
        "urlCategories": [cat_id], "protocols": ["ANY_RULE"], "requestMethods": ["CONNECT", "GET", "HEAD"],
        "description": "Show AUP coaching before Amazon Quick use (demo kit)",
    }, users, apply, log, "URL filtering rule")

    # 4. Web DLP rule
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
    changed |= _ensure_rule(z, "/webDlpRules", DLP_RULE_NAME, {
        "name": DLP_RULE_NAME, "order": 1, "rank": 7, "state": "ENABLED", "action": "BLOCK",
        "protocols": ["HTTPS_RULE", "HTTP_RULE"], "urlCategories": [{"id": cat_id}],
        "dlpEngines": [{"id": p["id"]} for p in picked], "withoutContentInspection": False, "matchOnly": False,
        "description": "Block PII/PCI in Amazon Quick prompts and uploads (demo kit)",
    }, users, apply, log, "Web DLP rule")
    return changed


def teardown(z, apply, log=print, created_user=None):
    """Remove the demo rules and category; plus the test user/group/department if the kit created them."""
    changed = False
    for path, name in [("/webDlpRules", DLP_RULE_NAME), ("/urlFilteringRules", URL_RULE_NAME),
                       ("/sslInspectionRules", SSL_RULE_NAME)]:
        hit = find_by_name(z.get(path), name)
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
    cu = created_user or {}
    for path, key in (("/users", "id"), ("/groups", "group_id"), ("/departments", "dept_id")):
        if cu.get(key):
            log(f"[-] delete {path}/{cu[key]} (kit-created test {path.strip('/')[:-1]})")
            if apply:
                try:
                    z.delete(f"{path}/{cu[key]}")
                    changed = True
                except ZiaError as e:
                    log(f"[!] couldn't delete {path}/{cu[key]}: {e}")
    return changed


# ---------------------------------------------------------------- test user
def find_user(z, email):
    email = (email or "").strip().lower()
    users = z.get("/users", params={"pageSize": 10000}) or []
    return next((u for u in users if str(u.get("email", "")).lower() == email), None)


def auth_mode(z):
    """'hosted' (Hosted DB, form sign-in: the kit can create the user and its password), 'saml', 'directory'."""
    try:
        a = z.get("/authSettings") or {}
    except ZiaError:
        return None
    if a.get("samlEnabled"):
        return "saml"
    return "hosted" if str(a.get("orgAuthType", "")).upper() == "SAFECHANNEL_DIR" else "directory"


def gen_password(n=20):
    import secrets as _s
    import string
    special = "!@#$%^&*-_=+"
    pool = string.ascii_letters + string.digits + special
    while True:
        pw = "".join(_s.choice(pool) for _ in range(n))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
                and any(c in special for c in pw)):
            return pw


def _ensure_ref(z, path, name, log):
    hit = find_by_name(z.get(path, params={"search": name}) or [], name)
    if hit:
        return hit
    made = z.post(path, {"name": name, "comments": "Created by the Amazon Quick SE demo kit"})
    log(f"[+] created {path.strip('/')[:-1]} '{name}'")
    return made


def create_test_user(z, email, log=print):
    """Create a ZIA user (Hosted DB tenants only) in its own group and department. Returns (user, password, meta)."""
    mode = auth_mode(z)
    if mode in ("saml", "directory"):
        raise ZiaError(f"This tenant's users come from {'a SAML IdP' if mode == 'saml' else 'a directory'}, so the kit "
                       "can't create one with a password. Create the user in your IdP or ZIdentity, then use "
                       "'Use existing user' with its email.")
    if find_user(z, email):
        raise ZiaError(f"{email} already exists. Use 'Use existing user' instead.")
    grp = _ensure_ref(z, "/groups", USER_GROUP_NAME, log)
    dept = _ensure_ref(z, "/departments", USER_GROUP_NAME, log)
    pw = gen_password()
    try:
        user = z.post("/users", {"name": TEST_USER_DISPLAY, "email": email, "password": pw,
                                 "groups": [{"id": grp["id"]}], "department": {"id": dept["id"]},
                                 "comments": "Test user for the Amazon Quick SE demo kit"})
    except ZiaError as e:
        if "password" in str(e).lower():
            raise ZiaError("ZIA rejected the generated password. Check Password Strength under Internet "
                           "Authentication Settings, or create the user yourself and use 'Use existing user'.")
        raise
    log(f"[+] created test user {email} (group and department '{USER_GROUP_NAME}')")
    return user, pw, {"id": user["id"], "email": email, "group_id": grp["id"], "dept_id": dept["id"]}


def run(z, apply=False, do_teardown=False, engine_names=None, log=print, user_ids=None, ssl=True,
        created_user=None):
    """Setup or teardown, then activate if anything changed. Returns True if changes were made."""
    changed = (teardown(z, apply, log, created_user) if do_teardown
               else setup(z, apply, engine_names or DEFAULT_ENGINES, log, user_ids, ssl))
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
