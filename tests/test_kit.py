"""Offline tests: ZIA logic against a fake tenant, the MCP check against the real Lambda handler, templates."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["QUICK_KIT_HOME"] = tempfile.mkdtemp()
import quick_kit as qk  # noqa: E402
import zia_quick_setup as zqs  # noqa: E402


class FakeZIA:
    """Just enough of the ZIA API for setup / status / teardown."""
    def __init__(self):
        self.cats, self.url_rules, self.dlp_rules, self.ssl_rules = [], [], [], []
        self.users, self.groups, self.depts, self.activated, self.n = [], [], [], 0, 0
        self.auth = {"orgAuthType": "SAFECHANNEL_DIR", "samlEnabled": False}
        self.engines = [{"id": 1, "name": "PCI"}, {"id": 2, "name": "PII"}, {"id": 3, "name": "GLBA"}, {"id": 4, "name": "HIPAA"}]

    def _lists(self):
        return {"/urlCategories": self.cats, "/urlFilteringRules": self.url_rules, "/webDlpRules": self.dlp_rules,
                "/sslInspectionRules": self.ssl_rules, "/users": self.users, "/groups": self.groups,
                "/departments": self.depts}

    def get(self, p, **kw):
        if p == "/dlpEngines":
            return self.engines
        if p == "/authSettings":
            return self.auth
        return self._lists()[p]

    def post(self, p, body):
        if p == "/status/activate":
            self.activated += 1
            return {}
        self.n += 1
        body = dict(body, id=f"CUSTOM_{self.n:02d}" if p == "/urlCategories" else self.n)
        self._lists()[p].append(body)
        return body

    def put(self, p, body):
        base, i = p.rsplit("/", 1)
        lst = self._lists()[base]
        lst[:] = [body if str(x["id"]) == i else x for x in lst]
        return body

    def delete(self, p):
        base, i = p.rsplit("/", 1)
        lst = self._lists()[base]
        lst[:] = [x for x in lst if str(x["id"]) != i]
        return {}


class ZiaTests(unittest.TestCase):
    def setUp(self):
        self.z = FakeZIA()
        qk.zia_connect = lambda cfg: self.z

    def test_dry_run_changes_nothing(self):
        r = qk.zia_run({}, apply=False, teardown=False)
        self.assertFalse(r["changed"])
        self.assertIn("CREATE URL category", r["output"])
        self.assertEqual((self.z.cats, self.z.activated), ([], 0))

    def test_apply_status_idempotent_teardown(self):
        self.assertTrue(qk.zia_run({}, True, False)["changed"])
        self.assertEqual(self.z.activated, 1)
        dlp = self.z.dlp_rules[0]
        self.assertEqual(dlp["action"], "BLOCK")
        self.assertEqual([e["id"] for e in dlp["dlpEngines"]], [1, 2, 3])
        self.assertEqual(dlp["urlCategories"], [{"id": "CUSTOM_01"}])
        self.assertEqual(self.z.url_rules[0]["urlCategories"], ["CUSTOM_01"])
        ssl = self.z.ssl_rules[0]
        self.assertEqual(ssl["action"]["type"], "DECRYPT")
        self.assertEqual(ssl["urlCategories"], ["CUSTOM_01"])
        for r in (ssl, self.z.url_rules[0], dlp):
            self.assertLessEqual(len(r["name"]), 31, r["name"])
            self.assertNotIn("users", r)
        self.assertTrue(qk.zia_status({})["ready"])
        self.assertFalse(qk.zia_run({}, True, False)["changed"])      # second run: nothing to do
        self.assertEqual(self.z.activated, 1)
        self.assertTrue(qk.zia_run({}, True, True)["changed"])        # teardown
        self.assertEqual((self.z.cats, self.z.url_rules, self.z.dlp_rules, self.z.ssl_rules), ([], [], [], []))
        self.assertFalse(qk.zia_status({})["ready"])

    def test_missing_engines_is_a_clear_error(self):
        self.z.engines = [{"id": 9, "name": "Something else"}]
        with self.assertRaises(zqs.ZiaError) as e:
            qk.zia_run({}, True, False)
        self.assertIn("Available engines", str(e.exception))

    def test_test_user_scope_and_teardown(self):
        saved = {}
        orig = (qk.set_secret, qk.save_cfg)
        qk.set_secret = lambda v, name="": saved.__setitem__(name, v)
        qk.save_cfg = lambda c: None
        try:
            cfg = {}
            r = qk.zia_user(cfg, "create", "quick-demo@acme.example")
            uid = r["user"]["id"]
            self.assertTrue(saved["zia_test_user_password"])
            self.assertEqual(self.z.users[0]["groups"], [{"id": self.z.groups[0]["id"]}])
            qk.zia_run(cfg, True, False)
            for rule in (self.z.ssl_rules[0], self.z.url_rules[0], self.z.dlp_rules[0]):
                self.assertEqual(rule["users"], [{"id": uid}])
            # rescoping to everyone updates the existing rules in place
            scoped = dict(cfg); scoped.pop("zia_user")
            self.assertTrue(qk.zia_run(scoped, True, False)["changed"])
            self.assertEqual(self.z.url_rules[0]["users"], [])
            qk.zia_run(cfg, True, True)
            self.assertEqual((self.z.users, self.z.groups, self.z.depts), ([], [], []))
            self.assertNotIn("zia_user", cfg)
        finally:
            qk.set_secret, qk.save_cfg = orig

    def test_create_refused_for_idp_tenants(self):
        self.z.auth = {"orgAuthType": "SAFECHANNEL_DIR", "samlEnabled": True}
        with self.assertRaises(zqs.ZiaError) as e:
            qk.zia_user({}, "create", "x@acme.example")
        self.assertIn("SAML", str(e.exception))

    def test_find_existing_user(self):
        self.z.users.append({"id": 77, "email": "SE-Demo@Acme.example", "name": "SE-Demo Traffic"})
        orig = qk.save_cfg
        qk.save_cfg = lambda c: None
        try:
            self.assertEqual(qk.zia_user({}, "find", "se-demo@acme.example")["user"]["id"], 77)
            with self.assertRaises(ValueError):
                qk.zia_user({}, "find", "nobody@acme.example")
        finally:
            qk.save_cfg = orig


class FakeZpaSession:
    """requests.Session stand-in for the ZPA API."""
    def __init__(self):
        self.store = {"segmentGroup": [], "serverGroup": [], "application": [], "rule": []}
        self.groups = [{"id": "500", "name": "AWS Quick demo", "enabled": True, "connectors": [{"id": 1}]}]
        self.n, self.calls = 100, []

    def request(self, method, url, params=None, timeout=None, data=None, headers=None):
        import re
        self.calls.append((method, url, json.loads(data) if data else None))
        path = re.sub(r"^.*/customers/\d+", "", url)
        body = json.loads(data) if data else None

        class R:
            def __init__(s, obj, code=200):
                s.status_code, s._o, s.text = code, obj, json.dumps(obj) if obj is not None else ""
            def json(s):
                return s._o
        if path == "/appConnectorGroup":
            return R({"totalPages": 1, "list": self.groups})
        if path == "/policySet/policyType/ACCESS_POLICY":
            return R({"id": "PS1"})
        key = "rule" if "/rule" in path else path.strip("/").split("/")[0]
        lst = self.store[key]
        if method == "GET":
            return R({"totalPages": 1, "list": lst})
        if method == "POST":
            self.n += 1
            obj = dict(body, id=str(self.n)); lst.append(obj)
            return R(obj)
        if method == "DELETE":
            i = path.rstrip("/").split("/")[-1]
            lst[:] = [x for x in lst if x["id"] != i]
            return R(None, 204)
        return R({}, 404)


class ZpaTests(unittest.TestCase):
    def test_setup_status_teardown(self):
        import zpa_quick
        s = FakeZpaSession()
        z = zpa_quick.ZPA(s, "216196257331281920")
        self.assertEqual(z.connector_groups()[0]["connectors"], 1)
        self.assertFalse(zpa_quick.setup(z, "eu-west-1", "500", apply=False, log=lambda m: None))
        self.assertEqual(s.store["application"], [])
        self.assertTrue(zpa_quick.setup(z, "eu-west-1", "500", apply=True, log=lambda m: None))
        app = s.store["application"][0]
        self.assertEqual(app["domainNames"], ["eu-west-1.quicksight.aws.amazon.com"])
        self.assertEqual(app["segmentGroupId"], s.store["segmentGroup"][0]["id"])
        self.assertEqual(app["serverGroups"], [{"id": s.store["serverGroup"][0]["id"]}])
        self.assertEqual(s.store["serverGroup"][0]["appConnectorGroups"], [{"id": "500"}])
        rule = s.store["rule"][0]
        self.assertEqual(rule["conditions"][0]["operands"][0], {"objectType": "APP", "values": [app["id"]]})
        self.assertTrue(any("/v2/" in c[1] and c[0] == "POST" for c in s.calls))   # access rules use the v2 API
        self.assertFalse(zpa_quick.setup(z, "eu-west-1", "500", apply=True, log=lambda m: None))   # idempotent
        self.assertTrue(all(i["exists"] for i in zpa_quick.status(z)))
        self.assertTrue(zpa_quick.teardown(z, apply=True, log=lambda m: None))
        self.assertEqual(sum(len(v) for v in s.store.values()), 0)

    def test_bad_customer_id(self):
        import zpa_quick
        with self.assertRaises(zpa_quick.ZpaError):
            zpa_quick.ZPA(FakeZpaSession(), "not-a-number")


class McpTests(unittest.TestCase):
    def test_check_against_real_handler(self):
        sys.modules.setdefault("cfnresponse", types.ModuleType("cfnresponse"))
        sys.path.insert(0, str(ROOT / "aws" / "src"))
        import mcp

        class R:
            def __init__(self, resp):
                self.status_code = resp["statusCode"]
                self.text = resp.get("body", "")
                self.headers = resp.get("headers") or {}
            def json(self):
                return json.loads(self.text)

        def fake_post(url, json=None, headers=None, timeout=None):
            import json as j
            ev = {"body": j.dumps(json), "headers": headers, "requestContext": {"http": {"method": "POST"}}}
            resp = mcp.handler(ev, None)
            resp.setdefault("headers", {}).setdefault("Content-Type", "application/json")
            r = R(resp); r.headers = {k.lower(): v for k, v in r.headers.items()}
            return r

        orig = qk.requests.post
        qk.requests.post = fake_post
        try:
            r = qk.mcp_test("https://example.lambda-url.us-east-1.on.aws/")
        finally:
            qk.requests.post = orig
        self.assertTrue(r["ok"])
        self.assertEqual(r["tools"], ["get_ticket", "search_customers", "get_vendor_profile"])
        self.assertIn("ignore prior instructions", r["steps"][-1]["response"]["result"]["content"][0]["text"])


class TemplateTests(unittest.TestCase):
    def test_defaults_set_and_secrets_absent(self):
        t = qk.build_template({"project": "acme-demo", "zpa": True, "ami": "ami-0123456789abcdef0"})
        self.assertIn("Default: 'acme-demo'", t)
        self.assertIn("Default: 'ami-0123456789abcdef0'", t)
        self.assertEqual(t.count("NoEcho: true"), 2)

    def test_untouched_when_zpa_off(self):
        t = qk.build_template({"project": "zs-quick-demo"})
        self.assertIn("Default: 'false'", t)

    def test_rejects_bad_input(self):
        for p in ({"project": "Bad Name"}, {"project": "ok-name", "zpa": True, "ami": "not-an-ami"}):
            with self.assertRaises(ValueError):
                qk.build_template(p)

    def test_inline_lambda_code_under_cfn_limit(self):
        for f in ("seed.py", "mcp.py"):
            self.assertLessEqual(len((ROOT / "aws" / "src" / f).read_text()), 4096)


class CloudShareTests(unittest.TestCase):
    def test_auth_header_matches_sdk_formula(self):
        import cs_runner, hashlib
        url = "https://use.cloudshare.com/api/v3/envs"
        h = cs_runner.auth_header("APIID", "SECRETKEY", url, ts=1424606753, token="5686464440")
        mac = hashlib.sha1(b"SECRETKEY" + url.encode() + b"1424606753" + b"5686464440").hexdigest()
        self.assertEqual(h, f"cs_sha1 userapiid:APIID;timestamp:1424606753;token:5686464440;hmac:{mac}")

    def test_run_command_decodes_to_expected_script(self):
        import base64, cs_runner
        cmd = cs_runner.run_command(["dlp", "upload"], 2, "us-east-1", "Paulie631/se-demo-swift", "main")
        self.assertTrue(cmd.startswith("powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand "))
        self.assertLess(len(cmd), 2000)
        script = base64.b64decode(cmd.split()[-1]).decode("utf-16-le")
        self.assertIn("https://raw.githubusercontent.com/Paulie631/se-demo-swift/main/cloudshare/run.ps1", script)
        self.assertIn("-Scenarios 'dlp,upload' -Loops 2", script)
        self.assertIn("-Region 'us-east-1'", script)
        sched = base64.b64decode(cs_runner.run_command(["dlp"], schedule_every=30).split()[-1]).decode("utf-16-le")
        self.assertIn("-Schedule -Every 30", sched)

    def test_cs_action_end_to_end_with_fake_api(self):
        import cs_runner
        calls = []
        payload = {"ok": True, "results": [{"outcome": "blocked", "label": "PII prompt", "scenario": "dlp"},
                                           {"outcome": "blocked", "label": "PCI prompt", "scenario": "dlp"}]}

        class Resp:
            def __init__(self, obj, code=200):
                self.status_code, self._o, self.text = code, obj, json.dumps(obj)
            def json(self):
                return self._o

        def fake_request(method, url, headers=None, data=None, timeout=None, verify=None):
            calls.append((method, url, headers["Authorization"]))
            if "executePath" in url:
                return Resp({"executionId": "EX1"})
            if "checkExecutionStatus" in url:
                n = sum(1 for c in calls if "checkExecutionStatus" in c[1])
                if n < 2:
                    return Resp({"success": False, "standardOutput": "Installing uv..."})
                return Resp({"success": True, "standardOutput": "noise\nQK_RESULT " + json.dumps(payload)})
            return Resp({}, 404)

        orig_req, orig_sleep, orig_get = cs_runner.requests.request, cs_runner.time.sleep, qk.get_secret
        cs_runner.requests.request, cs_runner.time.sleep = fake_request, lambda s: None
        qk.get_secret = lambda name="": "KEY"
        try:
            cfg = {"cloudshare": {"api_id": "ID", "vm_id": "VM1", "vm_name": "Corp Client PC"}}
            r = qk.cs_action(cfg, "traffic", ["dlp"], 1)
        finally:
            cs_runner.requests.request, cs_runner.time.sleep, qk.get_secret = orig_req, orig_sleep, orig_get
        self.assertEqual(r["summary"], {"blocked": 2})
        self.assertEqual(r["vm"], "Corp Client PC")
        self.assertTrue(all(c[2].startswith("cs_sha1 userapiid:ID;") for c in calls))
        self.assertIn("vmId=VM1", calls[-1][1])

    def test_vm_error_and_missing_result_are_reported(self):
        import cs_runner
        with self.assertRaises(cs_runner.CloudShareError) as e:
            cs_runner.parse_result({"standardOutput": "something broke", "standardError": "boom"})
        self.assertIn("boom", str(e.exception))
        self.assertEqual(cs_runner.parse_result({"standardOutput": 'QK_RESULT {"ok": false, "error": "x"}'})["ok"], False)
        with self.assertRaises(cs_runner.CloudShareError):
            qk.cs_vm({})


class RetryTests(unittest.TestCase):
    def test_retries_dns_hiccup_then_succeeds_and_reports_persistent_failure(self):
        import requests
        calls = []

        class S:
            def __init__(self, fail):
                self.fail = fail
            def request(self, method, url, **kw):
                calls.append(url)
                if len(calls) <= self.fail:
                    raise requests.exceptions.ConnectionError("Failed to resolve 'api.zsapi.net' (nodename nor servname)")
                r = types.SimpleNamespace(status_code=200, headers={}, text="{}")
                return r
        orig = zqs.__dict__.get("time")
        import time as _t
        sleep, _t.sleep = _t.sleep, lambda s: None
        try:
            self.assertEqual(zqs.send(S(2), "GET", "https://api.zsapi.net/zia/api/v1/x").status_code, 200)
            calls.clear()
            with self.assertRaises(zqs.ZiaError) as e:
                zqs.send(S(99), "GET", "https://api.zsapi.net/zia/api/v1/x")
            self.assertIn("DNS lookup failed", str(e.exception))
            self.assertIn("Nothing was changed", str(e.exception))
            self.assertEqual(len(calls), 4)
        finally:
            _t.sleep = sleep


if __name__ == "__main__":
    unittest.main()
