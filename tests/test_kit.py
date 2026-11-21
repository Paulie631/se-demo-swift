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


class UpdaterTests(unittest.TestCase):
    def _zip(self, version):
        import io, zipfile
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr("se-demo-swift-main/quick_kit.py", f'VERSION = "{version}"\nprint("new")\n')
            z.writestr("se-demo-swift-main/gui.html", "<html>new</html>")
            z.writestr("se-demo-swift-main/quick-kit", "#!/bin/bash\n")
        return b.getvalue()

    def _fake_get(self, version, changelog):
        zipped = self._zip(version)

        def get(url, timeout=None, verify=None):
            if url.endswith("/quick_kit.py"):
                body = f'VERSION = "{version}"\n'.encode()
            elif url.endswith("/CHANGELOG.md"):
                body = changelog.encode()
            else:
                body = zipped
            return types.SimpleNamespace(status_code=200, content=body, text=body.decode("latin-1"))
        return get

    def test_check_apply_rollback_copy_mode(self):
        import updater
        here = pathlib.Path(tempfile.mkdtemp()); backup = pathlib.Path(tempfile.mkdtemp()) / "previous"
        (here / "quick_kit.py").write_text('VERSION = "0.2.1"\n'); (here / "gui.html").write_text("old")
        cl = "# Changelog\n\n## 0.3.0\n- Update button\n\n## 0.2.1\n- retries\n"
        orig = updater.requests.get
        updater.requests.get = self._fake_get("0.3.0", cl)
        try:
            info = updater.check("0.2.1", here, backup=backup)
            self.assertTrue(info["available"])
            self.assertEqual(info["mode"], "copy")
            self.assertIn("Update button", info["notes"])
            self.assertNotIn("retries", info["notes"])
            self.assertEqual(updater.apply(here, backup, "0.3.0", log=lambda m: None), "0.3.0")
            self.assertEqual((here / "gui.html").read_text(), "<html>new</html>")
            self.assertTrue(os.access(here / "quick-kit", os.X_OK) or os.name == "nt")
            self.assertEqual(updater.check("0.3.0", here, backup=backup)["rollback"], "0.2.1")
            self.assertEqual(updater.rollback(here, backup, log=lambda m: None), "0.2.1")
            self.assertEqual((here / "gui.html").read_text(), "old")
            with self.assertRaises(updater.UpdateError):          # version mismatch is refused
                updater.apply(here, backup, "9.9.9", log=lambda m: None)
        finally:
            updater.requests.get = orig

    def test_versions_and_git_dirty_refusal(self):
        import subprocess, updater
        self.assertGreater(updater.parse("0.10.0"), updater.parse("0.9.9"))
        self.assertFalse(updater.parse("0.3.0") > updater.parse("0.3.0"))
        repo = pathlib.Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (repo / "quick_kit.py").write_text('VERSION = "0.1.0"\n')
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"], check=True)
        (repo / "quick_kit.py").write_text('VERSION = "0.1.0"\n# local edit\n')
        with self.assertRaises(updater.UpdateError) as e:
            updater.apply(repo, repo / "bk", "0.2.0", log=lambda m: None)
        self.assertIn("local changes", str(e.exception))
        with self.assertRaises(updater.UpdateError):
            updater.rollback(repo, repo / "bk")


class FakeCF:
    """Just enough CloudFormation: create/update/describe/events/delete, completing on the next describe."""
    def __init__(self, fail=False):
        import datetime
        self.dt = datetime
        self.stacks, self.events, self.fail, self.calls = {}, [], fail, []

    def _ev(self, name, lid, status, reason=""):
        self.events.append({"EventId": str(len(self.events)), "LogicalResourceId": lid, "ResourceStatus": status,
                            "ResourceStatusReason": reason, "Timestamp": self.dt.datetime.now(self.dt.timezone.utc)})

    def create_stack(self, **kw):
        self.calls.append(("create", kw))
        self.stacks[kw["StackName"]] = {"StackName": kw["StackName"], "StackStatus": "CREATE_IN_PROGRESS", "StackId": "id"}
        self._ev(kw["StackName"], "McpFunction", "CREATE_IN_PROGRESS")
        return {"StackId": "arn:aws:cloudformation:us-east-1:123456789012:stack/x/1"}

    def update_stack(self, **kw):
        self.calls.append(("update", kw))
        raise Exception("An error occurred (ValidationError): No updates are to be performed.")

    def delete_stack(self, StackName):
        self.calls.append(("delete", StackName))
        self.stacks[StackName]["StackStatus"] = "DELETE_IN_PROGRESS"

    def describe_stacks(self, StackName):
        s = self.stacks.get(StackName)
        if not s:
            raise Exception(f"Stack with id {StackName} does not exist")
        if s["StackStatus"] == "CREATE_IN_PROGRESS":
            if self.fail:   # OnFailure=DELETE: the stack goes away, its events stay readable by stack ID
                self._ev(StackName, "McpFunction", "CREATE_FAILED", "Resource handler returned message: boom")
                del self.stacks[StackName]
                raise Exception(f"Stack with id {StackName} does not exist")
            else:
                self._ev(StackName, "McpFunction", "CREATE_COMPLETE")
                s.update(StackStatus="CREATE_COMPLETE", Outputs=[{"OutputKey": "McpServerUrl", "OutputValue": "https://x.lambda-url.us-east-1.on.aws/"}])
        elif s["StackStatus"] == "DELETE_IN_PROGRESS":
            del self.stacks[StackName]
            raise Exception(f"Stack with id {StackName} does not exist")
        return {"Stacks": [dict(s)]}

    def describe_stack_events(self, StackName):
        if not StackName.startswith("arn:") and StackName not in self.stacks:
            raise Exception(f"Stack [{StackName}] does not exist")
        return {"StackEvents": list(reversed(self.events))}


class FakeSess:
    region_name = "us-east-1"

    def __init__(self, cf):
        self.cf = cf

    def client(self, name):
        if name == "sts":
            return types.SimpleNamespace(get_caller_identity=lambda: {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/paul"})
        return self.cf


class AwsDeployTests(unittest.TestCase):
    def setUp(self):
        import aws_deploy
        self.ad = aws_deploy
        self._sleep = aws_deploy.time.sleep
        aws_deploy.time.sleep = lambda s: None
        self.cf = FakeCF()
        self._sess = qk.aws_sess
        qk.aws_sess = lambda cfg: FakeSess(self.cf)
        self._save = qk.save_cfg
        qk.save_cfg = lambda c: None

    def tearDown(self):
        self.ad.time.sleep = self._sleep
        qk.aws_sess = self._sess
        qk.save_cfg = self._save

    def test_deploy_update_noop_delete(self):
        lines = []
        cfg = {"aws": {"project": "acme-quick", "region": "us-east-1"}}
        st = qk.aws_deploy_stack(cfg, "tok123", "", lines.append)
        self.assertEqual(st["status"], "CREATE_COMPLETE")
        self.assertEqual(st["outputs"]["McpServerUrl"], "https://x.lambda-url.us-east-1.on.aws/")
        kind, kw = self.cf.calls[0]
        self.assertEqual(kind, "create")
        self.assertEqual(kw["Capabilities"], ["CAPABILITY_IAM"])
        self.assertEqual(kw["OnFailure"], "DELETE")
        self.assertIn({"ParameterKey": "McpToken", "ParameterValue": "tok123"}, kw["Parameters"])
        self.assertNotIn("ZpaProvisioningKey", [p["ParameterKey"] for p in kw["Parameters"]])
        self.assertIn("Default: 'acme-quick'", kw["TemplateBody"])
        self.assertLess(len(kw["TemplateBody"]), 51200)        # CloudFormation's inline TemplateBody limit
        self.assertTrue(any("CREATE_COMPLETE" in l for l in lines))
        self.assertEqual(qk.aws_deploy_stack(cfg, "", "", lines.append)["status"], "CREATE_COMPLETE")  # no changes
        self.assertEqual(qk.aws_delete_stack(cfg, lines.append)["status"], "DELETE_COMPLETE")
        self.assertEqual(self.cf.stacks, {})

    def test_failed_create_reports_reason(self):
        self.cf.fail = True
        with self.assertRaises(self.ad.AwsError) as e:
            qk.aws_deploy_stack({"aws": {"project": "acme-quick", "region": "us-east-1"}}, "", "")
        self.assertIn("boom", str(e.exception))

    def test_zpa_needs_key_and_ami(self):
        with self.assertRaises(ValueError):
            qk.aws_deploy_stack({"aws": {"project": "acme-quick", "zpa": True, "ami": "ami-0123456789abcdef0"}}, "", "")

    def test_template_has_no_dlp_bait_literals(self):
        body = qk.build_template({"project": "zs-quick-demo"})
        for s in ("4111111111111111", "4111 1111 1111 1111", "AKIAIOSFODNN7EXAMPLE", "512-44-7381",
                  "BEGIN RSA PRIVATE KEY"):
            self.assertNotIn(s, body)


class SeedReplyTests(unittest.TestCase):
    """The seed function must always answer CloudFormation itself (no cfnresponse), on create and delete."""
    def test_replies_success_on_create_and_delete(self):
        import http.server, importlib, threading
        got = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_PUT(self):
                got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200); self.end_headers()
            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        put = []

        class Bucket:
            def __init__(self, name):
                self.object_versions = types.SimpleNamespace(delete=lambda: (_ for _ in ()).throw(Exception("AccessDenied")))
            def put_object(self, Key, Body):
                put.append(Key)
        fake = types.ModuleType("boto3"); fake.resource = lambda n: types.SimpleNamespace(Bucket=Bucket)
        saved = sys.modules.get("boto3"); sys.modules["boto3"] = fake
        sys.modules.pop("cfnresponse", None)
        sys.path.insert(0, str(ROOT / "aws" / "src"))
        try:
            sys.modules.pop("seed", None)
            seed = importlib.import_module("seed")
            ctx = types.SimpleNamespace(log_stream_name="2026/11/20/[$LATEST]abc")
            base = {"ResponseURL": f"http://127.0.0.1:{srv.server_address[1]}/resp", "StackId": "arn:stack/x",
                    "RequestId": "r1", "LogicalResourceId": "SeedData", "ResourceProperties": {"Bucket": "b"}}
            seed.handler(dict(base, RequestType="Create"), ctx)
            seed.handler(dict(base, RequestType="Delete", PhysicalResourceId="seed-SeedData"), ctx)
        finally:
            srv.shutdown()
            if saved: sys.modules["boto3"] = saved
        self.assertEqual([g["Status"] for g in got], ["SUCCESS", "SUCCESS"])   # delete succeeds even if emptying fails
        self.assertIn("customers/customers_export.csv", put)
        self.assertEqual(got[0]["PhysicalResourceId"], "seed-SeedData")
        self.assertNotIn("cfnresponse", (ROOT / "aws" / "src" / "seed.py").read_text())


class NotFound(Exception):
    pass
NotFound.__name__ = "ResourceNotFoundException"


class FakeQS:
    """Amazon Quick (quicksight) API stand-in: data source -> knowledge base -> space."""
    def __init__(self):
        self.ds, self.kb, self.spaces, self.calls, self.polls = {}, {}, {}, [], 0

    def describe_account_subscription(self, AwsAccountId):
        return {"AccountInfo": {"AccountName": "paulaiuto-quick-demo", "Edition": "ENTERPRISE",
                                "AccountSubscriptionStatus": "ACCOUNT_CREATED", "AuthenticationType": "IAM_AND_QUICKSIGHT"}}

    def list_users(self, **kw):
        return {"UserList": [{"Arn": "arn:aws:quicksight:us-east-1:123456789012:user/default/reader", "UserName": "reader", "Role": "READER"},
                             {"Arn": "arn:aws:quicksight:us-east-1:123456789012:user/default/paul", "UserName": "paul", "Role": "ADMIN"}]}

    def create_data_source(self, **kw):
        self.calls.append(("create_data_source", kw))
        self.ds[kw["DataSourceId"]] = {"Arn": "arn:ds", "Status": "CREATION_IN_PROGRESS"}
        return {"Arn": "arn:ds"}

    def describe_data_source(self, AwsAccountId, DataSourceId):
        d = self.ds.get(DataSourceId)
        if not d:
            raise NotFound("ResourceNotFoundException: no data source")
        out = dict(d); d["Status"] = "CREATION_SUCCESSFUL"
        return {"DataSource": out}

    def create_knowledge_base(self, **kw):
        self.calls.append(("create_knowledge_base", kw))
        self.kb[kw["KnowledgeBaseId"]] = {"KnowledgeBaseArn": "arn:kb", "Status": "CREATING", "PrimaryOwnerUsername": "paul"}
        return {"KnowledgeBaseArn": "arn:kb"}

    def describe_knowledge_base(self, AwsAccountId, KnowledgeBaseId):
        k = self.kb.get(KnowledgeBaseId)
        if not k:
            raise NotFound("ResourceNotFoundException: no kb")
        self.polls += 1
        if self.polls > 2:
            k.update(Status="ACTIVE", DocumentCount=7, LatestIngestionSummary={"Status": "SUCCEEDED"})
        return {"KnowledgeBase": dict(k)}

    def describe_space(self, AwsAccountId, SpaceId):
        s = self.spaces.get(SpaceId)
        if not s:
            raise NotFound("ResourceNotFoundException: no space")
        return {"spaceArn": "arn:space", "Space": {"resources": list(s)}}

    def create_space(self, **kw):
        self.calls.append(("create_space", kw)); self.spaces[kw["SpaceId"]] = []
        return {"spaceArn": "arn:space"}

    def update_space_resources(self, **kw):
        self.calls.append(("update_space_resources", kw))
        self.spaces[kw["SpaceId"]] += [r["ResourceDetails"] for r in kw["AddResources"]]

    def update_space_permissions(self, **kw):
        self.calls.append(("update_space_permissions", kw))
        bad = [a for a in kw["GrantPermissions"][0]["Actions"] if a in ("quicksight:UpdateSpaceResources", "quicksight:ListSpaceResources")]
        if bad:   # what real Quick did: reject one unknown action per call
            raise Exception(f"An error occurred (InvalidParameterValueException) when calling the UpdateSpacePermissions "
                            f"operation: Invalid action: {bad[0]} for principal: {kw['GrantPermissions'][0]['Principal']}")
        self.granted = kw["GrantPermissions"][0]["Actions"]

    def delete_space(self, AwsAccountId, SpaceId):
        self.spaces.pop(SpaceId)

    def delete_knowledge_base(self, AwsAccountId, KnowledgeBaseId):
        self.kb.pop(KnowledgeBaseId)

    def delete_data_source(self, AwsAccountId, DataSourceId):
        self.ds.pop(DataSourceId)


class QuickSetupTests(unittest.TestCase):
    def setUp(self):
        import quick_setup
        self.q = quick_setup
        self._sleep = quick_setup.time.sleep
        quick_setup.time.sleep = lambda s: None
        self.qs = FakeQS()
        self.sess = types.SimpleNamespace(client=lambda n: self.qs)

    def tearDown(self):
        self.q.time.sleep = self._sleep

    def test_full_setup_idempotent_and_teardown(self):
        q, acct = self.q, "123456789012"
        owner = "arn:aws:quicksight:us-east-1:123456789012:user/default/paul"
        self.assertEqual(q.users(self.sess, acct)[0]["name"], "paul")          # admins first
        r = q.setup(self.sess, acct, "zs-quick-demo", "zs-quick-demo-data-123-us-east-1",
                    "arn:aws:iam::123456789012:role/QuickKbRole", owner, True, progress=lambda m: None)
        self.assertEqual((r["knowledge_base"], r["documents"]), ("arn:kb", 7))
        ds = dict(self.qs.calls)["create_data_source"]
        self.assertEqual(ds["Type"], "S3_KNOWLEDGE_BASE")
        self.assertEqual(ds["DataSourceParameters"]["S3KnowledgeBaseParameters"],
                         {"BucketUrl": "s3://zs-quick-demo-data-123-us-east-1/", "RoleArn": "arn:aws:iam::123456789012:role/QuickKbRole"})
        self.assertEqual(ds["Permissions"][0]["Principal"], owner)
        kb = dict(self.qs.calls)["create_knowledge_base"]
        self.assertEqual(kb["PrimaryOwnerArn"], owner)
        self.assertEqual(kb["KnowledgeBaseConfiguration"]["templateConfiguration"]["template"],
                         {"type": "S3V2", "connectionConfiguration": {"bucketName": "zs-quick-demo-data-123-us-east-1",
                                                                      "bucketOwnerAccountId": acct}})
        self.assertEqual(self.qs.spaces["zs-quick-demo-space"], [{"resourceArn": "arn:kb"}])
        self.assertNotIn("quicksight:UpdateSpaceResources", self.qs.granted)     # rejected actions are dropped, then it retries
        self.assertIn("quicksight:DescribeSpace", self.qs.granted)
        n = len(self.qs.calls)
        q.setup(self.sess, acct, "zs-quick-demo", "b", "", owner, True, progress=lambda m: None)   # second run
        self.assertNotIn("create_data_source", [c[0] for c in self.qs.calls[n:]])
        self.assertNotIn("update_space_resources", [c[0] for c in self.qs.calls[n:]])
        st = q.status(self.sess, acct, "zs-quick-demo")
        self.assertEqual(st["knowledge_base"]["status"], "ACTIVE")
        q.teardown(self.sess, acct, "zs-quick-demo", progress=lambda m: None)
        self.assertEqual((self.qs.ds, self.qs.kb, self.qs.spaces), ({}, {}, {}))

    def test_requires_bucket_and_owner(self):
        with self.assertRaises(self.q.QuickError):
            self.q.setup(self.sess, "1", "p", "", "", "arn:owner")
        with self.assertRaises(self.q.QuickError):
            self.q.setup(self.sess, "1", "p", "bucket", "", "")

    def test_template_has_quick_role(self):
        body = qk.build_template({"project": "zs-quick-demo"})
        self.assertIn("QuickKbRole:", body)
        self.assertIn("Service: quicksight.amazonaws.com", body)
        self.assertIn("QuickKbRoleArn:", body)


class JsonSafetyTests(unittest.TestCase):
    def test_console_serializes_aws_datetimes(self):
        """Field bug: Check Quick returned LatestIngestionSummary.StartTime (datetime) and the console threw
        'Object of type datetime is not JSON serializable'."""
        import datetime, http.server, re, threading, requests as rq
        qk.quick_status = lambda cfg: {"quick": {"name": "x"}, "resources": {"knowledge_base": {
            "ingestion": {"IngestionStatus": "COMPLETED", "StartTime": datetime.datetime(2026, 11, 20, 20, 30)}}}}
        th = threading.Thread(target=qk.cmd_gui, kwargs={"port": 8811, "open_browser": False}, daemon=True)
        th.start()
        import time; time.sleep(1)
        html = rq.get("http://127.0.0.1:8811/").text
        tok = re.search(r'const TOKEN="([^"]+)"', html).group(1)
        r = rq.get("http://127.0.0.1:8811/api/quick/status", headers={"X-Kit-Token": tok})
        self.assertEqual(r.status_code, 200)
        self.assertIn("2026-11-20 20:30:00", r.text)


if __name__ == "__main__":
    unittest.main()
