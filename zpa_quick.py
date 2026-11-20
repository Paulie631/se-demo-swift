"""ZPA objects for the optional "Quick only through ZPA" path (playbook Act 2, AWS stack with EnableZpaPath=true).

Creates, idempotently by name:
  Segment group   "Amazon Quick (Demo)"
  Server group    "Amazon Quick (Demo)"   -> your App Connector group (the one the stack's connector enrolls into)
  App segment     "Amazon Quick (Demo)"   -> <region>.quicksight.aws.amazon.com, TCP 443
  Access rule     "Amazon Quick (Demo)"   -> ALLOW that segment, Client Connector only

Uses the same OneAPI token as ZIA (api.zsapi.net/zpa/...). Needs the ZPA customer (tenant) ID.
Field names follow zscaler-sdk-python's ZPA models.
"""
from __future__ import annotations

import json

NAME = "Amazon Quick (Demo)"
BASE = "https://api.zsapi.net/zpa/mgmtconfig"


class ZpaError(Exception):
    pass


class ZPA:
    def __init__(self, session, customer_id: str):
        """session: an authenticated requests.Session (the ZIA OneAPI session works: one token, all products)."""
        if not str(customer_id or "").strip().isdigit():
            raise ZpaError("Enter your ZPA customer (tenant) ID, a long number shown on ZPA's API Keys page.")
        self.s, self.cid = session, str(customer_id).strip()

    def _url(self, path, v=1):
        return f"{BASE}/v{v}/admin/customers/{self.cid}{path}"

    def req(self, method, path, body=None, params=None, v=1):
        r = self.s.request(method, self._url(path, v), params=params, timeout=60,
                           data=json.dumps(body) if body is not None else None,
                           headers={"Content-Type": "application/json"})
        if r.status_code in (401, 403):
            raise ZpaError(f"ZPA refused {method} {path} ({r.status_code}). Give the OneAPI client a ZPA role "
                           "(Administration › API › OneAPI › API Clients › Resources) and check the customer ID.")
        if r.status_code >= 400:
            raise ZpaError(f"[zpa] {method} {path} -> {r.status_code}: {r.text[:400]}")
        return r.json() if r.text.strip() else {}

    def list(self, path, search=None, v=1):
        out, page = [], 1
        while True:
            params = {"page": page, "pagesize": 500}
            if search:
                params["search"] = search
            d = self.req("GET", path, params=params, v=v)
            out += d.get("list") or []
            if page >= int(d.get("totalPages") or 1):
                return out
            page += 1

    def find(self, path, name=NAME):
        return next((x for x in self.list(path, search=name) if x.get("name") == name), None)

    # discovery
    def connector_groups(self):
        return [{"id": g.get("id"), "name": g.get("name"), "enabled": g.get("enabled"),
                 "connectors": len(g.get("connectors") or [])} for g in self.list("/appConnectorGroup")]

    def access_policy_id(self):
        d = self.req("GET", "/policySet/policyType/ACCESS_POLICY")
        if not d.get("id"):
            raise ZpaError("Couldn't find ZPA's access policy set.")
        return d["id"]

    def find_rule(self, policy_id):
        return next((r for r in self.list(f"/policySet/{policy_id}/rule") if r.get("name") == NAME), None)


def plan_bodies(region: str, connector_group_id: str) -> dict:
    domain = f"{region}.quicksight.aws.amazon.com"
    return {
        "segment_group": {"name": NAME, "enabled": True, "description": "Amazon Quick SE demo kit"},
        "server_group": {"name": NAME, "enabled": True, "dynamicDiscovery": True,
                         "appConnectorGroups": [{"id": str(connector_group_id)}],
                         "description": "Amazon Quick SE demo kit: the demo stack's App Connector group"},
        "app_segment": {"name": NAME, "enabled": True, "domainNames": [domain],
                        "tcpPortRanges": ["443", "443"], "bypassType": "NEVER", "healthReporting": "ON_ACCESS",
                        "isCnameEnabled": True, "description": "Quick website through the demo VPC's PrivateLink endpoint"},
        "rule": {"name": NAME, "action": "ALLOW", "description": "Amazon Quick SE demo kit",
                 "conditions": [{"operator": "OR", "operands": [{"objectType": "APP", "values": ["__APP__"]}]},
                                {"operator": "OR", "operands": [{"objectType": "CLIENT_TYPE",
                                                                 "values": ["zpn_client_type_zapp"]}]}]},
    }


def setup(zpa: ZPA, region: str, connector_group_id: str, apply: bool, log=print) -> bool:
    if not connector_group_id:
        raise ZpaError("Pick the App Connector group the demo stack's connector enrolls into.")
    b = plan_bodies(region, connector_group_id)
    changed = False

    def ensure(path, key, label, body):
        nonlocal changed
        hit = zpa.find(path)
        if hit:
            log(f"[ok] {label} exists: {hit.get('id')}")
            return hit.get("id")
        log(f"--- CREATE {label} ---\n{json.dumps(body, indent=2)}")
        if not apply:
            return f"<{key}>"
        made = zpa.req("POST", path, body)
        log(f"[+] created {label} {made.get('id')}")
        changed = True
        return made.get("id")

    sg = ensure("/segmentGroup", "segment_group", "segment group", b["segment_group"])
    srv = ensure("/serverGroup", "server_group", "server group", b["server_group"])
    app = ensure("/application", "app_segment", "application segment",
                 dict(b["app_segment"], segmentGroupId=sg, serverGroups=[{"id": srv}]))
    pid = zpa.access_policy_id()
    if zpa.find_rule(pid):
        log(f"[ok] access policy rule exists: {NAME}")
    else:
        rule = json.loads(json.dumps(b["rule"]).replace("__APP__", str(app)))
        log(f"--- CREATE access policy rule ---\n{json.dumps(rule, indent=2)}")
        if apply:
            zpa.req("POST", f"/policySet/{pid}/rule", rule, v=2)
            log("[+] created access policy rule (added at the bottom of the access policy: move it above any "
                "broad deny rule)")
            changed = True
    if not apply:
        log("Dry run complete. Nothing was changed in ZPA.")
    return changed


def teardown(zpa: ZPA, apply: bool, log=print) -> bool:
    changed = False
    pid = zpa.access_policy_id()
    r = zpa.find_rule(pid)
    if r:
        log(f"[-] delete access policy rule {r['id']}")
        if apply:
            zpa.req("DELETE", f"/policySet/{pid}/rule/{r['id']}")
            changed = True
    for path, label in (("/application", "application segment"), ("/serverGroup", "server group"),
                        ("/segmentGroup", "segment group")):
        hit = zpa.find(path)
        if hit:
            log(f"[-] delete {label} {hit['id']}")
            if apply:
                zpa.req("DELETE", f"{path}/{hit['id']}",
                        params={"forceDelete": "true"} if path == "/application" else None)
                changed = True
    if not changed and apply:
        log("Nothing to remove in ZPA.")
    return changed


def status(zpa: ZPA) -> list[dict]:
    pid = zpa.access_policy_id()
    out = []
    for path, label in (("/segmentGroup", "Segment group"), ("/serverGroup", "Server group"),
                        ("/application", "Application segment")):
        hit = zpa.find(path)
        detail = ""
        if hit and path == "/application":
            detail = ", ".join(hit.get("domainNames") or [])
        if hit and path == "/serverGroup":
            detail = ", ".join(g.get("name", "") for g in hit.get("appConnectorGroups") or [])
        out.append({"name": NAME, "type": label, "exists": bool(hit), "detail": detail})
    r = zpa.find_rule(pid)
    out.append({"name": NAME, "type": "Access policy rule", "exists": bool(r),
                "detail": f"{r.get('action')} · order {r.get('ruleOrder')}" if r else ""})
    return out
