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
GROUP_NAME = "Amazon Quick (Demo) connectors"
KEY_NAME = "Amazon Quick (Demo) key"
# App Connector group location per Quick region (ZPA wants a physical location for the group)
REGION_LOC = {
    "us-east-1": ("Ashburn, VA, USA", "Ashburn, US", "US", "39.0438", "-77.4874"),
    "us-west-2": ("Boardman, OR, USA", "Boardman, US", "US", "45.8399", "-119.7006"),
    "eu-west-1": ("Dublin, Ireland", "Dublin, IE", "IE", "53.3498", "-6.2603"),
    "ap-southeast-2": ("Sydney, Australia", "Sydney, AU", "AU", "-33.8688", "151.2093"),
}
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
        from zia_quick_setup import ZiaError, send
        try:
            r = send(self.s, method, self._url(path, v), params=params, timeout=60,
                     data=json.dumps(body) if body is not None else None,
                     headers={"Content-Type": "application/json"})
        except ZiaError as e:
            raise ZpaError(str(e))
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


def connector_cert_id(zpa: ZPA) -> str:
    """The 'Connector' enrollment certificate every App Connector group and key is tied to (v2 API)."""
    certs = zpa.list("/enrollmentCert", search="Connector", v=2)
    c = next((x for x in certs if x.get("name") == "Connector"), None) or (certs[0] if certs else None)
    if not c:
        raise ZpaError("Couldn't find ZPA's 'Connector' enrollment certificate.")
    return str(c["id"])


def ensure_connector_group(zpa: ZPA, region: str, apply: bool, log=print) -> str:
    """Create (or reuse) the kit's App Connector group. Returns its id ('<new>' on a dry run)."""
    hit = zpa.find("/appConnectorGroup", GROUP_NAME)
    if hit:
        log(f"[ok] App Connector group exists: {hit['id']}")
        return str(hit["id"])
    loc, city, cc, lat, lon = REGION_LOC.get(region, REGION_LOC["us-east-1"])
    body = {"name": GROUP_NAME, "description": "Amazon Quick SE demo kit: the AWS stack's App Connector",
            "enabled": True, "location": loc, "cityCountry": city, "countryCode": cc, "latitude": lat,
            "longitude": lon, "dnsQueryType": "IPV4_IPV6", "upgradeDay": "SUNDAY", "upgradeTimeInSecs": "66600",
            "versionProfileId": "0", "overrideVersionProfile": False}
    log(f"--- CREATE App Connector group ---\n{json.dumps(body, indent=2)}")
    if not apply:
        return "<new connector group>"
    body["enrollmentCertId"] = connector_cert_id(zpa)
    made = zpa.req("POST", "/appConnectorGroup", body)
    log(f"[+] created App Connector group {made.get('id')}")
    return str(made["id"])


def ensure_provisioning_key(zpa: ZPA, group_id: str, apply: bool, log=print) -> str:
    """Create (or reuse) a provisioning key for the group. Returns the key string ('' on a dry run)."""
    path = "/associationType/CONNECTOR_GRP/provisioningKey"
    hit = next((k for k in zpa.list(path, search=KEY_NAME) if k.get("name") == KEY_NAME), None)
    if hit and hit.get("provisioningKey"):
        log("[ok] Provisioning key exists")
        return hit["provisioningKey"]
    body = {"name": KEY_NAME, "maxUsage": "5", "enabled": True, "zcomponentId": str(group_id)}
    log(f"--- CREATE provisioning key ---\n{json.dumps(body, indent=2)}")
    if not apply:
        return ""
    body["enrollmentCertId"] = connector_cert_id(zpa)
    made = zpa.req("POST", path, body)
    key = made.get("provisioningKey") or ""
    if not key:   # some tenants return the key only on a read
        hit = next((k for k in zpa.list(path, search=KEY_NAME) if k.get("name") == KEY_NAME), {})
        key = hit.get("provisioningKey", "")
    if not key:
        raise ZpaError("ZPA created the provisioning key but didn't return its value; copy it from the ZPA console.")
    log("[+] created provisioning key (max 5 uses)")
    return key


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
    """connector_group_id 'auto' (or empty) = create/reuse the kit's own group and provisioning key."""
    if connector_group_id in ("", "auto", None):
        connector_group_id = ensure_connector_group(zpa, region, apply, log)
        ensure_provisioning_key(zpa, connector_group_id, apply, log)
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
    grp = zpa.find("/appConnectorGroup", GROUP_NAME)
    if grp:
        key_path = "/associationType/CONNECTOR_GRP/provisioningKey"
        for k in zpa.list(key_path, search=KEY_NAME):
            if k.get("name") == KEY_NAME:
                log(f"[-] delete provisioning key {k['id']}")
                if apply:
                    zpa.req("DELETE", f"{key_path}/{k['id']}")
                    changed = True
        for c in grp.get("connectors") or []:   # enrolled connectors block deleting the group
            log(f"[-] delete App Connector {c.get('name', c.get('id'))}")
            if apply:
                zpa.req("DELETE", f"/connector/{c['id']}")
                changed = True
        log(f"[-] delete App Connector group {grp['id']}")
        if apply:
            zpa.req("DELETE", f"/appConnectorGroup/{grp['id']}")
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
    g = zpa.find("/appConnectorGroup", GROUP_NAME)
    out.insert(0, {"name": GROUP_NAME, "type": "App Connector group (kit-created)", "exists": bool(g),
                   "detail": f"{len(g.get('connectors') or [])} connector(s)" if g else "only if you let the kit create it"})
    out.append({"name": NAME, "type": "Access policy rule", "exists": bool(r),
                "detail": f"{r.get('action')} · order {r.get('ruleOrder')}" if r else ""})
    return out
