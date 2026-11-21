"""ZIdentity test users for the Amazon Quick demo (OneAPI: /ziam/admin/api/v1).

Tenants on ZIdentity (the Zscaler Admin Console's own IdP) can't take a ZIA "Hosted DB" user with a password, so the
kit creates the test user in ZIdentity instead, sets its password and lets ZIdentity provision it to ZIA.
Request shapes follow Zscaler's Go and Python SDKs (zscaler-sdk-go ziam/services/users).
"""
from __future__ import annotations

import json
import time

BASE = "https://api.zsapi.net/ziam/admin/api/v1"
DISPLAY = "Quick Demo User (Demo)"


class ZidError(Exception):
    pass


class ZID:
    def __init__(self, session):
        """session: the authenticated OneAPI requests.Session (same token as ZIA and ZPA)."""
        self.s = session

    def req(self, method, path, body=None, params=None, ok404=False):
        from zia_quick_setup import ZiaError, send
        try:
            r = send(self.s, method, BASE + path, params=params, timeout=60,
                     data=json.dumps(body) if body is not None else None,
                     headers={"Content-Type": "application/json"})
        except ZiaError as e:
            raise ZidError(str(e))
        if r.status_code == 404 and ok404:
            return None
        if r.status_code in (401, 403):
            raise ZidError(f"ZIdentity refused {method} {path} ({r.status_code}). Give the OneAPI client the "
                           "ZIdentity (Authentication) admin scope: Administration > API Clients > Resources.")
        if r.status_code >= 400:
            raise ZidError(f"[zidentity] {method} {path} -> {r.status_code}: {r.text[:400]}")
        try:
            return r.json() if r.text.strip() else {}
        except ValueError:
            return {"raw": r.text[:200]}   # action endpoints answer with a bare status string

    def find(self, email: str) -> dict | None:
        email = email.strip().lower()
        d = self.req("GET", "/users", params={"login_name": email, "limit": 100}) or {}
        recs = d.get("records") if isinstance(d, dict) else d
        return next((u for u in recs or [] if str(u.get("loginName", "")).lower() == email
                     or str(u.get("primaryEmail", "")).lower() == email), None)

    def create(self, email: str, log=print) -> tuple[dict, str]:
        """Create the user, set a generated password (no reset on first login) and let it skip MFA for 30 days."""
        from zia_quick_setup import gen_password
        if self.find(email):
            raise ZidError(f"{email} already exists in ZIdentity. Use 'Save user' with it instead of creating one.")
        local = email.split("@")[0]
        body = {"loginName": email, "primaryEmail": email, "displayName": DISPLAY, "firstName": "Quick",
                "lastName": "Demo", "status": True}
        log(f"--- CREATE ZIdentity user ---\n{json.dumps(body, indent=2)}")
        u = self.req("POST", "/users", body)
        if not u.get("id"):
            u = self.find(email) or {}
        if not u.get("id"):
            raise ZidError("ZIdentity accepted the user but didn't return it. Check Administration > Users.")
        pw = gen_password()
        pbody = {"password": pw, "resetPwdOnLogin": False}
        if self.req("PUT", f"/users/{u['id']}/updatepassword", pbody, ok404=True) is None:
            self.req("PUT", f"/users/{u['id']}:updatepassword", pbody)   # the docs' spelling
        log(f"[+] created ZIdentity user {email} ({local}) and set its password")
        try:
            sk = {"timestamp": int(time.time()) + 30 * 86400}
            if self.req("POST", f"/users/{u['id']}/setskipmfa", sk, ok404=True) is None:
                self.req("POST", f"/users/{u['id']}:setskipmfa", sk)
            log("[+] MFA enrollment skipped for 30 days (so the CloudShare VM can sign in unattended)")
        except ZidError as e:
            log(f"[!] couldn't set skip-MFA ({e}); the first sign-in may ask to enroll MFA")
        return u, pw

    def delete(self, user_id: str, log=print) -> bool:
        if self.req("DELETE", f"/users/{user_id}", ok404=True) is None:
            log("[ok] ZIdentity user already gone")
            return False
        log(f"[-] deleted ZIdentity user {user_id}")
        return True


def wait_for_zia(z, email: str, find_user, seconds: int = 90, log=print) -> dict | None:
    """ZIdentity provisions users to ZIA asynchronously. Poll ZIA until the user appears (or give up)."""
    end = time.time() + seconds
    while True:
        u = find_user(z, email)
        if u or time.time() > end:
            return u
        log("waiting for ZIdentity to provision the user to ZIA ...")
        time.sleep(10)
