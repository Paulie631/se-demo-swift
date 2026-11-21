"""AI Guard in front of the demo MCP server.

OneAPI (https://api.zsapi.net/aiguard/v1): create an "Amazon Quick MCP (Demo)" LLM application, a DETECTIONS-mode
key for it, and a policy match rule that sends that app to a policy you choose. The key goes to the AWS stack as a
hidden parameter; the MCP Lambda then calls the detection API (resolve-and-execute-policy) on every tool call.
Shapes follow Zscaler's Python SDK (zscaler/aiguard) and the AI Guard SE kit.
"""
from __future__ import annotations

import json
import time

BASE = "https://api.zsapi.net/aiguard/v1"
APP_NAME = "Amazon Quick MCP (Demo)"
KEY_NAME = "Amazon Quick MCP (Demo) detection key"
RULE_NAME = "Amazon Quick MCP (Demo)"
DAS_PATH = "/v1/detection/resolve-and-execute-policy"
DEFAULT_HOST = "https://api.us1.zseclipse.net"


class AigError(Exception):
    pass


class AIG:
    def __init__(self, session):
        self.s = session

    def req(self, method, path, body=None, ok404=False):
        from zia_quick_setup import ZiaError, send
        try:
            r = send(self.s, method, BASE + path, timeout=60, data=json.dumps(body) if body is not None else None,
                     headers={"Content-Type": "application/json"})
        except ZiaError as e:
            raise AigError(str(e))
        if r.status_code == 404 and ok404:
            return None
        if r.status_code in (401, 403):
            raise AigError(f"AI Guard refused {method} {path} ({r.status_code}). Give the OneAPI client the AI Guard "
                           "scope (Administration > API Clients > Resources), and check AI Guard is licensed.")
        if r.status_code >= 400:
            raise AigError(f"[aiguard] {method} {path} -> {r.status_code}: {r.text[:400]}")
        return r.json() if r.text.strip() else {}

    def list(self, path):
        d = self.req("GET", path) or {}
        return d.get("items", []) if isinstance(d, dict) else d

    def find(self, path, name):
        return next((x for x in self.list(path) if x.get("name") == name), None)

    def policies(self):
        return [{"id": p["id"], "name": p.get("name", str(p["id"]))} for p in self.list("/detections/policies")]


def pick_policy(policies: list[dict], wanted: str | int | None = None) -> dict | None:
    """The chosen policy, else the AI Guard SE kit's policy, else one whose name says Default, else the first."""
    if wanted not in (None, ""):
        return next((p for p in policies if str(p["id"]) == str(wanted) or p["name"] == wanted), None)
    for test in (lambda n: "se kit" in n or "se demo" in n, lambda n: "default" in n):
        hit = next((p for p in policies if test(p["name"].lower())), None)
        if hit:
            return hit
    return policies[0] if policies else None


def setup(aig: AIG, policy: str | int | None, apply: bool, log=print, saved_key: str = "") -> dict:
    """Create/reuse app, detection key and match rule. Returns {"key": str|'' , "policy": {...}, "created": [...]}"""
    pol = pick_policy(aig.policies(), policy)
    if not pol:
        raise AigError("No AI Guard detection policy found. Create one in AI Guard (or run the AI Guard SE kit) first.")
    log(f"[ok] AI Guard policy: {pol['name']} (id {pol['id']})")
    out = {"key": "", "policy": pol, "created": []}
    app = aig.find("/llm-applications", APP_NAME)
    if app:
        log(f"[ok] AI Guard app exists: {app['id']}")
    else:
        body = {"name": APP_NAME, "description": "Amazon Quick SE demo kit: the demo MCP server's tool calls",
                "applicationSettings": {"includeEventContents": True, "encryptEventContents": False}}
        log(f"--- CREATE AI Guard app ---\n{json.dumps(body, indent=2)}")
        if not apply:
            return out
        app = aig.req("POST", "/llm-applications", body)
        out["created"].append("app")
        log(f"[+] created AI Guard app {app.get('id')}")
    key_obj = aig.find("/llm-application-credentials", KEY_NAME)   # list omits DETECTIONS keys on some tenants
    if key_obj and (key_obj.get("key") or saved_key):
        out["key"] = key_obj.get("key") or saved_key
        log("[ok] detection key exists")
    else:
        body = {"name": KEY_NAME if not key_obj else f"{KEY_NAME} {time.strftime('%Y%m%d-%H%M%S')}",
                "applicationId": app["id"], "mode": "DETECTIONS"}
        log(f"--- CREATE detection key ---\n{json.dumps(body, indent=2)}")
        if not apply:
            return out
        key_obj = aig.req("POST", "/llm-application-credentials", body)
        out["key"] = key_obj.get("key", "")
        out["created"].append("key")
        if not out["key"]:
            raise AigError("AI Guard created the detection key but didn't return it. Regenerate it in AI Guard.")
        log("[+] created detection key (shown once; the kit passes it to AWS and keeps it in your keychain)")
    entry = {"applicationId": app["id"], "applicationCredentialsIds": [key_obj["id"]]}
    rule = aig.find("/detections/policy-match-rules", RULE_NAME)
    order = max([r.get("ruleOrder", 0) for r in aig.list("/detections/policy-match-rules")] + [0]) + 1
    body = {"policyId": pol["id"], "name": RULE_NAME, "enabled": True,
            "ruleOrder": rule.get("ruleOrder", order) if rule else order,
            "matchCriteria": {"type": "DAS_APPLICATION", "llmApplications": [entry]}}
    log(f"--- {'UPDATE' if rule else 'CREATE'} policy match rule ---\n{json.dumps(body, indent=2)}")
    if apply:
        if rule:
            aig.req("PUT", f"/detections/policy-match-rules/{rule['id']}", body)
        else:
            aig.req("POST", "/detections/policy-match-rules", body)
            out["created"].append("rule")
        log(f"[+] rule '{RULE_NAME}' sends the app to policy '{pol['name']}'")
    return out


def teardown(aig: AIG, apply: bool, log=print) -> bool:
    changed = False
    for path, name in (("/detections/policy-match-rules", RULE_NAME), ("/llm-application-credentials", None),
                       ("/llm-applications", APP_NAME)):
        items = [x for x in aig.list(path) if (x.get("name") == name if name else
                                               str(x.get("name", "")).startswith(KEY_NAME))]
        for x in items:
            log(f"[-] delete {path}/{x['id']} ({x.get('name')})")
            if apply:
                aig.req("DELETE", f"{path}/{x['id']}", ok404=True)
                changed = True
    return changed


def status(aig: AIG) -> list[dict]:
    rule = aig.find("/detections/policy-match-rules", RULE_NAME)
    return [{"name": APP_NAME, "type": "AI Guard app", "exists": bool(aig.find("/llm-applications", APP_NAME))},
            {"name": RULE_NAME, "type": "Policy match rule", "exists": bool(rule),
             "detail": f"policy {rule.get('policyId')}" if rule else ""}]


def scan(key: str, text: str, direction: str = "IN", host: str = DEFAULT_HOST, session=None) -> dict:
    """One detection call, the same one the MCP Lambda makes. Used by the GUI's 'Test AI Guard' button."""
    import requests
    s = session or requests
    r = s.post(host.rstrip("/") + DAS_PATH, json={"content": text, "direction": direction}, timeout=30,
               headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    if r.status_code >= 400:
        raise AigError(f"Detection API HTTP {r.status_code}: {r.text[:300]}".replace(key, "<key>"))
    return r.json()
