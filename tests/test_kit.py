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
        self.cats, self.url_rules, self.dlp_rules, self.activated, self.n = [], [], [], 0, 0
        self.engines = [{"id": 1, "name": "PCI"}, {"id": 2, "name": "PII"}, {"id": 3, "name": "GLBA"}, {"id": 4, "name": "HIPAA"}]

    def get(self, p, **kw):
        return {"/urlCategories": self.cats, "/urlFilteringRules": self.url_rules,
                "/webDlpRules": self.dlp_rules, "/dlpEngines": self.engines}[p]

    def post(self, p, body):
        if p == "/status/activate":
            self.activated += 1
            return {}
        self.n += 1
        body = dict(body, id=f"CUSTOM_{self.n:02d}" if p == "/urlCategories" else self.n)
        {"/urlCategories": self.cats, "/urlFilteringRules": self.url_rules, "/webDlpRules": self.dlp_rules}[p].append(body)
        return body

    def delete(self, p):
        base, i = p.rsplit("/", 1)
        lst = {"/urlCategories": self.cats, "/urlFilteringRules": self.url_rules, "/webDlpRules": self.dlp_rules}[base]
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
        self.assertTrue(qk.zia_status({})["ready"])
        self.assertFalse(qk.zia_run({}, True, False)["changed"])      # second run: nothing to do
        self.assertEqual(self.z.activated, 1)
        self.assertTrue(qk.zia_run({}, True, True)["changed"])        # teardown
        self.assertEqual((self.z.cats, self.z.url_rules, self.z.dlp_rules), ([], [], []))
        self.assertFalse(qk.zia_status({})["ready"])

    def test_missing_engines_is_a_clear_error(self):
        self.z.engines = [{"id": 9, "name": "Something else"}]
        with self.assertRaises(zqs.ZiaError) as e:
            qk.zia_run({}, True, False)
        self.assertIn("Available engines", str(e.exception))


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


if __name__ == "__main__":
    unittest.main()
