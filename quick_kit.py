# /// script
# requires-python = ">=3.10,<3.15"
# dependencies = ["requests>=2.31", "keyring>=24", "truststore>=0.9", "boto3>=1.43"]
# ///
"""Amazon Quick x Zscaler SE demo kit.

  ./quick-kit gui              open the demo console in your browser (localhost only)  [default]
  ./quick-kit config           save the OneAPI vanity domain, client ID and secret (secret goes to the OS keychain)
  ./quick-kit setup            preview the ZIA demo policy (dry run); --apply to create + activate; --teardown
  ./quick-kit status           check credentials and which demo objects exist in ZIA
  ./quick-kit user find|create|clear EMAIL   scope the demo policy to a test user (create: Hosted DB tenants)
  ./quick-kit zpa              ZPA app segment + access rule for the PrivateLink path (--apply, --teardown)
  ./quick-kit traffic          send Quick-shaped demo traffic through Client Connector (--loops N, --only dlp|...)
                               --via cloudshare: send it from your CloudShare VM instead of this laptop
  ./quick-kit aws deploy|status|delete   deploy the AWS demo stack with boto3 (--profile, --region)
  ./quick-kit template         write the AWS CloudFormation template (--out FILE, --project, --zpa, --ami ...)
  ./quick-kit mcp-test URL     check the demo MCP server from this laptop (--token T)
  ./quick-kit update           update from GitHub (--check, --rollback); the console has an Update button too
  ./quick-kit install          copy the kit to ~/.quick-se-kit/app and add a desktop shortcut (uninstall removes it)

Everything the kit creates in ZIA is named "... (Demo)". `setup --teardown --apply` removes all of it.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import getpass
import json
import os
import pathlib
import re
import secrets
import sys
import threading
import time
import urllib.parse

try:
    import truststore  # trust the OS store, where Client Connector installs the Zscaler root CA
    truststore.inject_into_ssl()
except ImportError:
    pass

import requests

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cs_runner  # noqa: E402
import quick_traffic  # noqa: E402
import zia_quick_setup as zqs  # noqa: E402
import aws_deploy  # noqa: E402
import quick_setup  # noqa: E402
import updater  # noqa: E402
import zpa_quick  # noqa: E402

VERSION = "0.5.4"
HOME = pathlib.Path(os.environ.get("QUICK_KIT_HOME", pathlib.Path.home() / ".quick-se-kit"))
CFG_FILE = HOME / "config.json"
LOG_FILE = HOME / "kit.log"
KEYRING_SERVICE = "quick-se-kit"
BACKUP = HOME / "previous"   # the version before the last update, for rollback
TEMPLATE = HERE / "aws" / "quick-demo-env.yaml"
QUICK_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-2"]
SCENARIOS = ["visibility", "dlp", "upload"]

# ----------------------------------------------------------------------------- config, secrets, logging
LOGS: collections.deque = collections.deque(maxlen=800)
_LOCK = threading.Lock()


def log(msg: str, kind: str = "info") -> None:
    entry = {"t": dt.datetime.now().strftime("%H:%M:%S"), "kind": kind, "msg": str(msg)}
    with _LOCK:
        LOGS.append(entry)
        try:
            HOME.mkdir(parents=True, exist_ok=True)
            with LOG_FILE.open("a", encoding="utf-8") as f:
                f.write(f"{dt.datetime.now().isoformat(timespec='seconds')} [{kind}] {msg}\n")
        except OSError:
            pass


def load_cfg() -> dict:
    try:
        return json.loads(CFG_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_cfg(cfg: dict) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    CFG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def get_secret(name: str = "zia_client_secret") -> str:
    env = {"zia_client_secret": "ZS_CLIENT_SECRET", "cloudshare_api_key": "CLOUDSHARE_API_KEY"}.get(name)
    if env and os.environ.get(env):
        return os.environ[env]
    try:
        import keyring
        return keyring.get_password(KEYRING_SERVICE, name) or ""
    except Exception:  # no keychain backend (headless Linux)
        return ""


def set_secret(value: str, name: str = "zia_client_secret") -> None:
    import keyring
    keyring.set_password(KEYRING_SERVICE, name, value)


def creds(cfg: dict) -> tuple[str, str, str]:
    return (os.environ.get("ZS_VANITY") or cfg.get("vanity", ""),
            os.environ.get("ZS_CLIENT_ID") or cfg.get("client_id", ""),
            get_secret())


def mask(s: str) -> str:
    return (s[:4] + "…" + s[-2:]) if s and len(s) > 8 else ("•••" if s else "")


# ----------------------------------------------------------------------------- ZIA
def zia_connect(cfg: dict) -> zqs.ZIA:
    vanity, cid, sec = creds(cfg)
    missing = [n for n, v in (("vanity domain", vanity), ("client ID", cid), ("client secret", sec)) if not v]
    if missing:
        raise zqs.ZiaError("Missing " + ", ".join(missing) + ". Fill them in on the Setup tab (or ./quick-kit config).")
    log(f"OneAPI login to {vanity}.zslogin.net as client {mask(cid)}")
    try:
        return zqs.ZIA(vanity, cid, sec, verify=cfg.get("ca_bundle") or True)
    except requests.RequestException as e:
        raise zqs.ZiaError(f"Couldn't reach {vanity}.zslogin.net ({e.__class__.__name__}). "
                           "Check the vanity domain, DNS, or SSL inspection (set a CA bundle).")


def zia_run(cfg: dict, apply: bool, teardown: bool) -> dict:
    lines: list[str] = []

    def capture(m):
        lines.append(str(m))
        log(str(m), "zia")

    z = zia_connect(cfg)
    zu = cfg.get("zia_user") or {}
    log(f"ZIA {'teardown' if teardown else 'setup'} ({'APPLY' if apply else 'dry run'})"
        + (f", scoped to {zu.get('email')}" if zu.get("id") and not teardown else ""), "action")
    changed = zqs.run(z, apply, teardown, cfg.get("engines") or zqs.DEFAULT_ENGINES, capture,
                      user_ids=[zu["id"]] if zu.get("id") else None, ssl=cfg.get("ssl", True),
                      created_user=zu.get("created"))
    if teardown and apply and zu.get("created"):
        cfg.pop("zia_user", None)
        save_cfg(cfg)
        try:
            set_secret("", "zia_test_user_password")
        except Exception:
            pass
    return {"changed": changed, "apply": apply, "teardown": teardown, "output": "\n".join(lines)}


def zia_user(cfg: dict, action: str, email: str = "") -> dict:
    """Pick the user the demo policy is scoped to: find an existing one, create one (Hosted DB tenants), or clear."""
    if action == "clear":
        cfg.pop("zia_user", None)
        save_cfg(cfg)
        log("Demo policy scope cleared: it will apply to everyone", "action")
        return {"user": None}
    email = (email or "").strip()
    if "@" not in email:
        raise ValueError("Enter the test user's full email address.")
    z = zia_connect(cfg)
    if action == "find":
        u = zqs.find_user(z, email)
        if not u:
            raise ValueError(f"{email} isn't a ZIA user in this tenant. Check the address, or use Create test user.")
        cfg["zia_user"] = {"id": u["id"], "email": u.get("email"), "name": u.get("name")}
        log(f"Demo policy will be scoped to {email} (ZIA user {u['id']})", "ok")
    elif action == "create":
        u, pw, meta = zqs.create_test_user(z, email, lambda m: log(m, "zia"))
        try:
            set_secret(pw, "zia_test_user_password")
        except Exception as e:
            raise ValueError(f"Created {email}, but couldn't save its password to the keychain ({e}). Reset the "
                             "password in the ZIA console.")
        cfg["zia_user"] = {"id": u["id"], "email": email, "name": u.get("name"), "created": meta}
        z.post("/status/activate", {})
        log(f"Created {email}; password saved in the keychain (Show password on the Setup tab)", "ok")
    else:
        raise ValueError(f"Unknown action {action}")
    save_cfg(cfg)
    return {"user": cfg["zia_user"]}


# ----------------------------------------------------------------------------- ZPA
def zpa_client(cfg: dict) -> zpa_quick.ZPA:
    return zpa_quick.ZPA(zia_connect(cfg).s, (cfg.get("zpa") or {}).get("customer_id", ""))


def zpa_region(cfg: dict) -> str:
    return (cfg.get("aws") or {}).get("region") or "us-east-1"


def zpa_run(cfg: dict, apply: bool, teardown: bool) -> dict:
    lines: list[str] = []

    def capture(m):
        lines.append(str(m))
        log(str(m), "zpa")

    z = zpa_client(cfg)
    log(f"ZPA {'teardown' if teardown else 'setup'} ({'APPLY' if apply else 'dry run'}), region {zpa_region(cfg)}",
        "action")
    changed = (zpa_quick.teardown(z, apply, capture) if teardown else
               zpa_quick.setup(z, zpa_region(cfg), (cfg.get("zpa") or {}).get("connector_group_id", ""), apply,
                               capture))
    return {"changed": changed, "output": "\n".join(lines)}


def zia_status(cfg: dict) -> dict:
    z = zia_connect(cfg)
    cats = z.get("/urlCategories", params={"customOnly": "true"})
    cat = zqs.find_by_name(cats, zqs.CATEGORY_NAME, key="configuredName")
    ssl = zqs.find_by_name(z.get("/sslInspectionRules"), zqs.SSL_RULE_NAME)
    url = zqs.find_by_name(z.get("/urlFilteringRules"), zqs.URL_RULE_NAME)
    dlp = zqs.find_by_name(z.get("/webDlpRules"), zqs.DLP_RULE_NAME)
    items = [
        {"name": zqs.CATEGORY_NAME, "type": "URL category", "exists": bool(cat),
         "detail": f"{cat['id']} · {len(cat.get('urls') or [])} domains" if cat else ""},
        {"name": zqs.SSL_RULE_NAME, "type": "SSL inspection rule", "exists": bool(ssl),
         "detail": f"{(ssl.get('action') or {}).get('type')} · {ssl.get('state')}" if ssl else ""},
        {"name": zqs.URL_RULE_NAME, "type": "URL filtering rule", "exists": bool(url),
         "detail": f"{url.get('action')} · {url.get('state')}" if url else ""},
        {"name": zqs.DLP_RULE_NAME, "type": "Web DLP rule", "exists": bool(dlp),
         "detail": f"{dlp.get('action')} · {', '.join(str(e.get('name') or e.get('id')) for e in dlp.get('dlpEngines') or [])}"
         if dlp else ""},
    ]
    for i, r in ((1, ssl), (2, url), (3, dlp)):
        if r:
            items[i]["detail"] += " · " + (f"{len(r.get('users'))} user(s)" if r.get("users") else "everyone")
    log(f"Status: {sum(i['exists'] for i in items)}/{len(items)} demo objects present", "zia")
    return {"items": items, "ready": all(i["exists"] for i in items)}


# ----------------------------------------------------------------------------- traffic
def traffic(cfg: dict, scenarios: list[str], loops: int = 1, region: str | None = None) -> dict:
    s = quick_traffic.session(cfg.get("ca_bundle") or None)
    results: list[dict] = []
    log(f"Traffic: {', '.join(scenarios)} × {loops} pass(es)", "action")
    for i in range(max(1, min(loops, 10))):
        for sc in scenarios:
            if sc in SCENARIOS:
                results += quick_traffic.run(s, sc, lambda m: log(m, "traffic"), region or None)
        if i < loops - 1:
            time.sleep(5)
    summary = collections.Counter(r["outcome"] for r in results)
    return {"results": results, "summary": dict(summary)}



# ----------------------------------------------------------------------------- CloudShare VM as the traffic source
def cs_cfg(cfg: dict) -> dict:
    c = dict(cfg.get("cloudshare") or {})
    c.setdefault("repo", cs_runner.DEFAULT_REPO)
    c.setdefault("ref", cs_runner.DEFAULT_REF)
    c["api_id"] = os.environ.get("CLOUDSHARE_API_ID") or c.get("api_id", "")
    return c


def cs_client(cfg: dict) -> cs_runner.CloudShare:
    c = cs_cfg(cfg)
    return cs_runner.CloudShare(c["api_id"], get_secret("cloudshare_api_key"), verify=cfg.get("ca_bundle") or True)


def cs_vm(cfg: dict) -> tuple[str, str]:
    c = cs_cfg(cfg)
    if not c.get("vm_id"):
        raise cs_runner.CloudShareError("Pick the CloudShare environment and Windows VM first (Traffic tab › CloudShare).")
    return c["vm_id"], c.get("vm_name") or c["vm_id"]


def cs_action(cfg: dict, action: str, scenarios=None, loops: int = 1, region: str = "", every: int = 60,
              progress=None) -> dict:
    """Run one action on the configured CloudShare VM: check | traffic | schedule | unschedule."""
    c = cs_cfg(cfg)
    vm_id, vm_name = cs_vm(cfg)
    cs = cs_client(cfg)
    scenarios = [s for s in (scenarios or SCENARIOS) if s in SCENARIOS]
    if action == "check":
        cmd = cs_runner.check_command()
    elif action in ("traffic", "schedule", "unschedule"):
        cmd = cs_runner.run_command(scenarios, loops, region, c["repo"], c["ref"],
                                    schedule_every=every if action == "schedule" else 0,
                                    unschedule=action == "unschedule")
    else:
        raise ValueError(f"Unknown CloudShare action {action}")
    log(f"CloudShare: {action} on VM {vm_name}" + (f" ({', '.join(scenarios)} × {loops})" if action == "traffic" else ""),
        "action")
    st = cs.run(vm_id, cmd, timeout=900, progress=progress)
    res = cs_runner.parse_result(st)
    if res.get("ok") is False:
        raise cs_runner.CloudShareError(f"On the VM: {res.get('error')}")
    if action == "traffic":
        summ = collections.Counter(r["outcome"] for r in res.get("results", []))
        log(f"CloudShare traffic done: {dict(summ)}", "ok")
        res.setdefault("summary", dict(summ))
    else:
        log(f"CloudShare {action}: {json.dumps(res)[:300]}", "ok")
    res["vm"] = vm_name
    return res


JOBS: dict = {}


def start_job(fn) -> str:
    """Long CloudShare runs (first one installs Python on the VM) outlive a browser request: run them in a thread."""
    jid = secrets.token_hex(6)
    JOBS[jid] = {"state": "running", "elapsed": 0}

    t0 = time.time()

    def progress(x):
        """int: seconds elapsed (CloudShare); str: a progress line (CloudFormation events)."""
        if isinstance(x, str):
            JOBS[jid].setdefault("log", []).append(x)
            JOBS[jid]["log"] = JOBS[jid]["log"][-200:]
            JOBS[jid]["elapsed"] = int(time.time() - t0)
        else:
            JOBS[jid]["elapsed"] = x

    def work():
        try:
            JOBS[jid].update(state="done", result=fn(progress))
        except (cs_runner.CloudShareError, zqs.ZiaError, aws_deploy.AwsError, quick_setup.QuickError, ValueError) as e:
            log(str(e), "error")
            JOBS[jid].update(state="error", error=str(e))
        except Exception as e:
            log(f"{e.__class__.__name__}: {e}", "error")
            JOBS[jid].update(state="error", error=f"{e.__class__.__name__}: {e}")
    threading.Thread(target=work, daemon=True).start()
    return jid



# ----------------------------------------------------------------------------- AWS deploy (CloudFormation via boto3)
def aws_cfg(cfg: dict) -> dict:
    a = dict(cfg.get("aws") or {})
    a.setdefault("project", "zs-quick-demo")
    a.setdefault("region", "us-east-1")
    return a


def aws_sess(cfg: dict):
    a = aws_cfg(cfg)
    if cfg.get("ca_bundle"):   # boto3 ignores the OS certificate store; this is how it trusts SSL inspection
        os.environ["AWS_CA_BUNDLE"] = cfg["ca_bundle"]
    if a.get("region") not in QUICK_REGIONS:
        raise ValueError(f"Pick a Quick region: {', '.join(QUICK_REGIONS)}.")
    if a.get("auth") == "keys":
        if not a.get("key_id") or not get_secret("aws_secret_access_key"):
            raise aws_deploy.AwsError("Enter the access key ID and secret (AWS environment tab).")
        return aws_deploy.session(a["region"], key_id=a["key_id"], secret=get_secret("aws_secret_access_key"))
    return aws_deploy.session(a["region"], profile=a.get("profile", ""))


def aws_status(cfg: dict) -> dict:
    a = aws_cfg(cfg)
    s = aws_sess(cfg)
    who = aws_deploy.whoami(s)
    st = aws_deploy.stack(s, a["project"])
    return {"identity": who, "stack": st}


def aws_deploy_stack(cfg: dict, mcp_token: str = "", zpa_key: str = "", progress=None) -> dict:
    a = aws_cfg(cfg)
    s = aws_sess(cfg)
    who = aws_deploy.whoami(s)
    if a.get("zpa") and not zpa_key:
        raise ValueError("The ZPA path needs the App Connector provisioning key.")
    if a.get("zpa") and not a.get("ami"):
        raise ValueError("The ZPA path needs the App Connector AMI ID for this region.")
    body = build_template(a)
    log(f"AWS: deploying stack {a['project']} to {who['account']} / {a['region']}"
        + (" with the ZPA path" if a.get("zpa") else ""), "action")
    if progress:
        progress(f"AWS account {who['account']} ({who['arn'].split('/')[-1]}), region {a['region']}")
    st = aws_deploy.deploy(s, a["project"], body, {"ProjectName": a["project"], "McpToken": mcp_token,
                                                   "ZpaProvisioningKey": zpa_key if a.get("zpa") else ""},
                           progress)
    c = load_cfg()
    c.setdefault("aws", {})["outputs"] = st.get("outputs") or {}
    save_cfg(c)
    log(f"AWS: stack {a['project']} {st['status']}", "ok")
    return st


def quick_status(cfg: dict) -> dict:
    a = aws_cfg(cfg)
    s = aws_sess(cfg)
    acct = aws_deploy.whoami(s)["account"]
    info = quick_setup.account(s, acct)
    out = {"account_id": acct, "region": a["region"], "quick": info, "users": [], "resources": None,
           "owner": a.get("quick_owner", ""), "has_stack_outputs": bool((a.get("outputs") or {}).get("DataBucketName"))}
    if info:
        out["users"] = quick_setup.users(s, acct)
        out["resources"] = quick_setup.status(s, acct, a["project"])
    return out


def quick_run(cfg: dict, owner_arn: str, space: bool = True, progress=None) -> dict:
    a = aws_cfg(cfg)
    s = aws_sess(cfg)
    acct = aws_deploy.whoami(s)["account"]
    if not quick_setup.account(s, acct):
        raise quick_setup.QuickError("There's no Amazon Quick account in this AWS account yet. Sign up in the Quick "
                                     "console first (Enterprise, same region as the stack).")
    st = aws_deploy.stack(s, a["project"])
    o = (st or {}).get("outputs") or {}
    if not o.get("DataBucketName"):
        raise quick_setup.QuickError("Deploy the AWS stack first: the knowledge base reads its bucket.")
    if not o.get("QuickKbRoleArn") and progress:
        progress("This stack has no QuickKbRole (deployed before v0.5). Redeploy the stack, or grant Quick the bucket "
                 "under Permissions > AWS resources first.")
    c = load_cfg()
    c.setdefault("aws", {})["quick_owner"] = owner_arn
    save_cfg(c)
    log(f"Quick setup: knowledge base on {o['DataBucketName']} for {owner_arn.split('/')[-1]}", "action")
    r = quick_setup.setup(s, acct, a["project"], o["DataBucketName"], o.get("QuickKbRoleArn", ""), owner_arn,
                          space, progress or (lambda m: None))
    log(f"Quick setup done: {r.get('documents') or 0} documents indexed", "ok")
    return r


def quick_teardown(cfg: dict, progress=None) -> dict:
    a = aws_cfg(cfg)
    s = aws_sess(cfg)
    acct = aws_deploy.whoami(s)["account"]
    if quick_setup.account(s, acct):
        quick_setup.teardown(s, acct, a["project"], progress or (lambda m: None))
    log("Quick setup removed", "ok")
    return {"ok": True}


def aws_delete_stack(cfg: dict, progress=None) -> dict:
    a = aws_cfg(cfg)
    s = aws_sess(cfg)
    try:   # remove the Quick knowledge base first, so nothing in Quick points at the deleted bucket
        acct = aws_deploy.whoami(s)["account"]
        if quick_setup.account(s, acct) and any((quick_setup.status(s, acct, a["project"]) or {}).values()):
            if progress:
                progress("Removing the Quick knowledge base and space first…")
            quick_setup.teardown(s, acct, a["project"], progress or (lambda m: None))
    except Exception as e:
        if progress:
            progress(f"Skipped Quick cleanup ({e}); remove the knowledge base in Quick yourself.")
    log(f"AWS: deleting stack {a['project']} in {a['region']}", "action")
    r = aws_deploy.delete(s, a["project"], progress)
    c = load_cfg()
    c.setdefault("aws", {}).pop("outputs", None)
    save_cfg(c)
    log(f"AWS: stack {a['project']} deleted", "ok")
    return r


# ----------------------------------------------------------------------------- AWS template
def _set_default(text: str, param: str, value: str) -> str:
    """Set Parameters.<param>.Default in the template text (keeps everything else byte-identical)."""
    m = re.search(rf"(?m)^  {re.escape(param)}:\n((?:    .*\n)+)", text)
    if not m:
        return text
    block = m.group(1)
    q = "'" + str(value).replace("'", "''") + "'"
    new = re.sub(r"(?m)^    Default: .*$", f"    Default: {q}", block, count=1)
    return text[:m.start(1)] + new + text[m.end(1):]


def build_template(p: dict) -> str:
    """Template with the SE's non-secret choices as defaults. Secrets (MCP token, ZPA key) stay out of the file:
    they're NoEcho parameters you type into the CloudFormation console."""
    text = TEMPLATE.read_text(encoding="utf-8")
    proj = (p.get("project") or "zs-quick-demo").strip().lower()
    if not re.fullmatch(r"[a-z0-9-]{3,24}", proj):
        raise ValueError("Project name: 3–24 characters, lowercase letters, numbers and dashes.")
    text = _set_default(text, "ProjectName", proj)
    if p.get("zpa"):
        ami = (p.get("ami") or "").strip()
        if ami and not re.fullmatch(r"ami-[0-9a-f]{8,17}", ami):
            raise ValueError("App Connector AMI should look like ami-0123456789abcdef0.")
        text = _set_default(text, "EnableZpaPath", "true")
        if ami:
            text = _set_default(text, "AppConnectorAmiId", ami)
        if p.get("instance_type"):
            text = _set_default(text, "AppConnectorInstanceType", p["instance_type"])
        if p.get("keypair"):
            text = _set_default(text, "KeyPairName", p["keypair"])
    log(f"Template built: project={proj} zpa={'on' if p.get('zpa') else 'off'}", "aws")
    return text


# ----------------------------------------------------------------------------- MCP check
def mcp_test(url: str, token: str = "") -> dict:
    url = (url or "").strip()
    if not url.startswith("https://"):
        raise ValueError("Paste the McpServerUrl output from the stack (it starts with https://).")
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if token:
        h["Authorization"] = "Bearer " + token
    steps = []

    def call(name, body):
        t0 = time.time()
        try:
            r = requests.post(url, json=body, headers=h, timeout=20)
            ms = int((time.time() - t0) * 1000)
            blocked = r.status_code == 403 and "zscaler" in r.text.lower()
            ok = r.status_code in (200, 202)
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else None
            steps.append({"step": name, "ok": ok, "status": r.status_code, "ms": ms,
                          "note": "Blocked by Zscaler on this laptop" if blocked else "", "response": data})
            return data
        except requests.RequestException as e:
            steps.append({"step": name, "ok": False, "status": None, "note": e.__class__.__name__})
            return None

    log(f"MCP check: {url}", "action")
    init = call("initialize", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                          "clientInfo": {"name": "quick-se-kit", "version": VERSION}}})
    tools = []
    if init:
        lst = call("tools/list", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = [t["name"] for t in ((lst or {}).get("result") or {}).get("tools", [])]
        call("tools/call get_vendor_profile", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                                "params": {"name": "get_vendor_profile",
                                                           "arguments": {"vendor": "Acme"}}})
    ok = bool(init) and "get_vendor_profile" in tools
    log(f"MCP check {'passed' if ok else 'failed'}; tools: {', '.join(tools) or 'none'}", "aws")
    return {"ok": ok, "tools": tools, "steps": steps}



# ----------------------------------------------------------------------------- updates
def upd_src(cfg: dict) -> tuple[str, str]:
    return cfg.get("update_repo") or updater.DEFAULT_REPO, cfg.get("update_ref") or updater.DEFAULT_REF


def update_check(cfg: dict) -> dict:
    repo, ref = upd_src(cfg)
    r = updater.check(VERSION, HERE, repo, ref, verify=cfg.get("ca_bundle") or True, backup=BACKUP)
    log(f"Update check: running {VERSION}, latest {r['latest']}" + (" (update available)" if r["available"] else ""),
        "info")
    return r


def update_apply(cfg: dict) -> dict:
    info = update_check(cfg)
    if not info["available"]:
        return {"updated": False, "version": VERSION, "message": f"You're on the latest version ({VERSION})."}
    repo, ref = upd_src(cfg)
    log(f"Updating {VERSION} -> {info['latest']} ({info['mode']})", "action")
    v = updater.apply(HERE, BACKUP, info["latest"], repo, ref, verify=cfg.get("ca_bundle") or True,
                      log=lambda m: log(m, "info"))
    log(f"Updated to {v}", "ok")
    return {"updated": True, "version": v}


def restart_console(srv, port: int) -> None:
    """Start the (updated) console again in the background on the same port, then exit this process."""
    import subprocess
    launcher = HERE / ("quick-kit.cmd" if WINDOWS else "quick-kit")
    args = ["gui", "--port", str(port), "--no-browser"]
    # The launcher runs under uv, so a new version's new dependencies get installed; plain Python is the fallback.
    cmd = ([str(launcher), *args] if launcher.exists()
           else [sys.executable, str(HERE / "quick_kit.py"), *args])
    try:
        srv.socket.close()  # free the port for the new console
    except OSError:
        pass
    HOME.mkdir(parents=True, exist_ok=True)
    with open(HOME / "console-output.log", "ab") as out:
        if WINDOWS:
            subprocess.Popen(["cmd", "/c", *cmd], cwd=str(HERE), stdin=subprocess.DEVNULL, stdout=out,
                             stderr=subprocess.STDOUT,
                             creationflags=0x08000000 | 0x00000200)  # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
        else:
            subprocess.Popen(["nohup", "bash", *cmd] if cmd[0].endswith("quick-kit") else ["nohup", *cmd],
                             cwd=str(HERE), stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                             start_new_session=True)
    os._exit(0)


# ----------------------------------------------------------------------------- GUI
def cmd_gui(port: int = 8770, open_browser: bool = True) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import webbrowser

    token = secrets.token_urlsafe(24)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj=None, ctype="application/json", raw=None, extra=None):
            data = raw if raw is not None else json.dumps(obj, default=str).encode()   # AWS responses carry datetimes
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _guard(self):
            host = (self.headers.get("Host") or "").split(":")[0]
            if host not in ("127.0.0.1", "localhost"):
                self._send(403, {"error": "bad host"})
                return False
            if self.path.startswith("/api/") and self.headers.get("X-Kit-Token") != token:
                self._send(403, {"error": "bad token"})
                return False
            return True

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")

        def _do(self, fn):
            try:
                return self._send(200, fn())
            except (zqs.ZiaError, cs_runner.CloudShareError, zpa_quick.ZpaError, updater.UpdateError,
                    aws_deploy.AwsError, quick_setup.QuickError, ValueError) as e:
                log(str(e), "error")
                return self._send(400, {"error": str(e)})
            except Exception as e:  # unexpected: show it, keep the console alive
                log(f"{e.__class__.__name__}: {e}", "error")
                return self._send(500, {"error": f"{e.__class__.__name__}: {e}"})

        def do_GET(self):
            if not self._guard():
                return
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                html = (HERE / "gui.html").read_text(encoding="utf-8").replace("__KIT_TOKEN__", token)
                return self._send(200, raw=html.encode(), ctype="text/html; charset=utf-8")
            if path == "/api/config":
                c = load_cfg()
                vanity, cid, sec = creds(c)
                return self._send(200, {"vanity": vanity, "client_id": cid, "has_secret": bool(sec),
                                        "ca_bundle": c.get("ca_bundle", ""), "engines": c.get("engines") or zqs.DEFAULT_ENGINES,
                                        "aws": c.get("aws") or {}, "version": VERSION, "regions": QUICK_REGIONS,
                                        "category_urls": zqs.QUICK_URLS,
                                        "cloudshare": {k: v for k, v in cs_cfg(c).items()},
                                        "cs_has_key": bool(get_secret("cloudshare_api_key")),
                                        "traffic_source": c.get("traffic_source", "laptop"),
                                        "zia_user": c.get("zia_user"), "ssl": c.get("ssl", True),
                                        "has_user_pw": bool(get_secret("zia_test_user_password")),
                                        "zpa": c.get("zpa") or {}})
            if path == "/api/logs":
                return self._send(200, {"logs": list(LOGS)})
            if path == "/api/zia/status":
                return self._do(lambda: zia_status(load_cfg()))
            q = dict(urllib.parse.parse_qsl(self.path.split("?", 1)[1])) if "?" in self.path else {}
            if path == "/api/cloudshare/envs":
                return self._do(lambda: {"envs": cs_client(load_cfg()).envs()})
            if path == "/api/cloudshare/vms":
                return self._do(lambda: {"vms": cs_client(load_cfg()).vms(q.get("env", ""))})
            if path == "/api/zia/password":
                pw = get_secret("zia_test_user_password")
                log("Test user password shown in the console", "action")
                return self._send(200 if pw else 404, {"password": pw} if pw else {"error": "No password saved"})
            if path == "/api/zpa/groups":
                return self._do(lambda: {"groups": zpa_client(load_cfg()).connector_groups()})
            if path == "/api/zpa/status":
                return self._do(lambda: {"items": zpa_quick.status(zpa_client(load_cfg()))})
            if path == "/api/aws/profiles":
                return self._send(200, {"profiles": aws_deploy.profiles(),
                                        "has_secret": bool(get_secret("aws_secret_access_key"))})
            if path == "/api/quick/status":
                return self._do(lambda: quick_status(load_cfg()))
            if path == "/api/aws/status":
                return self._do(lambda: aws_status(load_cfg()))
            if path == "/api/update/check":
                return self._do(lambda: update_check(load_cfg()))
            if path == "/api/jobs":
                j = JOBS.get(q.get("id", ""))
                return self._send(200 if j else 404, j or {"error": "no such job"})
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._guard():
                return
            path = self.path.split("?")[0]
            b = self._body()
            if path == "/api/config":
                def save():
                    c = load_cfg()
                    for k in ("vanity", "client_id", "ca_bundle"):
                        if k in b:
                            c[k] = (b[k] or "").strip()
                    if b.get("vanity", "").endswith(".zslogin.net"):
                        c["vanity"] = b["vanity"].split(".")[0]
                    if b.get("engines"):
                        c["engines"] = [e.strip() for e in b["engines"] if e.strip()]
                    if b.get("aws") is not None:
                        keep = dict(c.get("aws") or {})
                        keep.update({k: v for k, v in b["aws"].items()
                                     if k not in ("token", "zpa_key", "secret", "mcp_token", "outputs")})
                        c["aws"] = keep
                    if b.get("aws_secret"):
                        try:
                            set_secret(b["aws_secret"], "aws_secret_access_key")
                        except Exception as e:
                            raise ValueError(f"Couldn't save the AWS secret to the OS keychain: {e}")
                    if b.get("cloudshare") is not None:
                        cs = dict(c.get("cloudshare") or {})
                        cs.update({k: (v or "").strip() for k, v in b["cloudshare"].items()
                                   if k in ("api_id", "env_id", "env_name", "vm_id", "vm_name", "repo", "ref")})
                        c["cloudshare"] = cs
                    if b.get("cs_key"):
                        try:
                            set_secret(b["cs_key"].strip(), "cloudshare_api_key")
                        except Exception as e:
                            raise ValueError(f"Couldn't save the CloudShare key to the OS keychain: {e}")
                    if b.get("zpa") is not None:
                        zp = dict(c.get("zpa") or {})
                        zp.update({k: str(v or "").strip() for k, v in b["zpa"].items()
                                   if k in ("customer_id", "connector_group_id", "connector_group_name")})
                        c["zpa"] = zp
                    if "ssl" in b:
                        c["ssl"] = bool(b["ssl"])
                    if b.get("traffic_source") in ("laptop", "cloudshare"):
                        c["traffic_source"] = b["traffic_source"]
                    if b.get("secret"):
                        try:
                            set_secret(b["secret"])
                        except Exception as e:
                            raise ValueError(f"Couldn't save the secret to the OS keychain: {e}")
                    save_cfg(c)
                    log(f"Saved settings (vanity={c.get('vanity')}, client={mask(c.get('client_id', ''))})", "action")
                    return {"ok": True, "has_secret": bool(get_secret())}
                return self._do(save)
            if path == "/api/zia/test":
                def test():
                    zia_connect(load_cfg()).get("/urlCategories", params={"customOnly": "true"})
                    log("Connection OK: OneAPI token issued and ZIA read access confirmed", "ok")
                    return {"ok": True}
                return self._do(test)
            if path == "/api/zia/run":
                return self._do(lambda: zia_run(load_cfg(), bool(b.get("apply")), bool(b.get("teardown"))))
            if path == "/api/zia/user":
                return self._do(lambda: zia_user(load_cfg(), b.get("action", "find"), b.get("email", "")))
            if path == "/api/zpa/run":
                return self._do(lambda: zpa_run(load_cfg(), bool(b.get("apply")), bool(b.get("teardown"))))
            if path == "/api/traffic":
                return self._do(lambda: traffic(load_cfg(), b.get("scenarios") or SCENARIOS,
                                                int(b.get("loops") or 1), b.get("region")))
            if path == "/api/cloudshare/run":
                c = load_cfg()
                try:
                    cs_vm(c)
                except cs_runner.CloudShareError as e:
                    return self._send(400, {"error": str(e)})
                jid = start_job(lambda prog: cs_action(c, b.get("action", "traffic"), b.get("scenarios"),
                                                       int(b.get("loops") or 1), b.get("region") or "",
                                                       int(b.get("every") or 60), prog))
                return self._send(200, {"job": jid})
            if path in ("/api/quick/setup", "/api/quick/teardown"):
                c = load_cfg()
                if path == "/api/quick/setup":
                    owner, sp = b.get("owner_arn", ""), b.get("space", True)
                    jid = start_job(lambda prog: quick_run(c, owner, sp, prog))
                else:
                    jid = start_job(lambda prog: quick_teardown(c, prog))
                return self._send(200, {"job": jid})
            if path in ("/api/aws/deploy", "/api/aws/delete"):
                c = load_cfg()
                if path == "/api/aws/deploy":
                    tok, zk = b.get("mcp_token", ""), b.get("zpa_key", "")
                    jid = start_job(lambda prog: aws_deploy_stack(c, tok, zk, prog))
                else:
                    jid = start_job(lambda prog: aws_delete_stack(c, prog))
                return self._send(200, {"job": jid})
            if path == "/api/aws/template":
                try:
                    text = build_template(b)
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
                return self._send(200, raw=text.encode(), ctype="application/x-yaml",
                                  extra={"Content-Disposition": 'attachment; filename="quick-demo-env.yaml"'})
            if path == "/api/aws/mcp-test":
                return self._do(lambda: mcp_test(b.get("url", ""), b.get("token", "")))
            if path == "/api/update":
                act = b.get("action", "apply")
                try:
                    r = (update_apply(load_cfg()) if act == "apply"
                         else {"updated": True, "version": updater.rollback(HERE, BACKUP, lambda m: log(m, "info"))})
                except updater.UpdateError as e:
                    log(str(e), "error")
                    return self._send(400, {"error": str(e)})
                if r.get("updated"):
                    r["restarting"] = True
                    self._send(200, r)
                    log("Restarting the console with the new version", "action")
                    threading.Timer(0.5, lambda: restart_console(srv, srv.server_address[1])).start()
                    return
                return self._send(200, r)
            if path == "/api/quit":
                log("Console stopped from the browser", "action")
                self._send(200, {"ok": True})
                threading.Thread(target=srv.shutdown, daemon=True).start()
                return
            if path == "/api/logs/clear":
                LOGS.clear()
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "not found"})

    srv = None
    for p in range(port, port + 10):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), H)
            break
        except OSError:
            continue
    if not srv:
        sys.exit(f"No free port between {port} and {port + 9}.")
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    log(f"Console started at {url} (v{VERSION})", "action")
    print(f"Amazon Quick demo console: {url}\nPress Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")



# ----------------------------------------------------------------------------- install / uninstall
APP_FILES = ["quick_kit.py", "zia_quick_setup.py", "zpa_quick.py", "updater.py", "aws_deploy.py", "quick_setup.py", "CHANGELOG.md", "quick_traffic.py", "cs_runner.py", "cloudshare/run.ps1", "gui.html", "quick-kit", "quick-kit.cmd",
             "README.md", "aws/quick-demo-env.yaml", "aws/README.md"]
WINDOWS = os.name == "nt"
SHORTCUT = "Amazon Quick Demo Console"


def desktop() -> pathlib.Path:
    d = pathlib.Path.home() / "Desktop"
    if WINDOWS:
        od = pathlib.Path(os.environ.get("OneDrive", "")) / "Desktop"
        if os.environ.get("OneDrive") and od.is_dir():
            return od
    return d


def cmd_install() -> None:
    import shutil
    import stat
    app = HOME / "app"
    app.mkdir(parents=True, exist_ok=True)
    for f in APP_FILES:
        src = HERE / f
        if src.exists():
            (app / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, app / f)
    for f in ("quick-kit",):
        p = app / f
        if p.exists():
            p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    d = desktop()
    d.mkdir(parents=True, exist_ok=True)
    if WINDOWS:
        lnk = d / f"{SHORTCUT}.lnk"
        ps = ("$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%s');$s.TargetPath='%s';"
              "$s.Arguments='/c \"\"%s\" gui\"';$s.WorkingDirectory='%s';$s.WindowStyle=7;$s.Save()"
              % (lnk, os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe"),
                 app / "quick-kit.cmd", app))
        import subprocess
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=False)
    elif sys.platform == "darwin":
        sc = d / f"{SHORTCUT}.command"
        sc.write_text(f'#!/bin/bash\nnohup "{app}/quick-kit" gui >>"{HOME}/console-output.log" 2>&1 </dev/null &\n'
                      "disown\nexit 0\n")
        sc.chmod(0o755)
    else:
        sc = d / "amazon-quick-demo-console.desktop"
        sc.write_text(f"[Desktop Entry]\nType=Application\nName={SHORTCUT}\nExec=\"{app}/quick-kit\" gui\nTerminal=false\n")
        sc.chmod(0o755)
    print(f"Installed to {app}. Desktop shortcut: {SHORTCUT}.")


def cmd_uninstall() -> None:
    import shutil
    for p in (desktop() / f"{SHORTCUT}.lnk", desktop() / f"{SHORTCUT}.command",
              desktop() / "amazon-quick-demo-console.desktop"):
        if p.exists():
            p.unlink()
    shutil.rmtree(HOME / "app", ignore_errors=True)
    print(f"Removed the app and shortcut. Settings and logs stay in {HOME}; the secret stays in the keychain "
          f"(service '{KEYRING_SERVICE}'). ZIA objects are untouched: run setup --teardown --apply first if needed.")


# ----------------------------------------------------------------------------- CLI
def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="quick-kit", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    g = sub.add_parser("gui")
    g.add_argument("--port", type=int, default=8770)
    g.add_argument("--no-browser", action="store_true")
    sub.add_parser("config")
    s = sub.add_parser("setup")
    s.add_argument("--apply", action="store_true")
    s.add_argument("--teardown", action="store_true")
    sub.add_parser("status")
    zp = sub.add_parser("zpa", help="ZPA objects for the PrivateLink path (dry run unless --apply)")
    zp.add_argument("--apply", action="store_true")
    zp.add_argument("--teardown", action="store_true")
    us = sub.add_parser("user", help="scope the demo policy to a test user")
    us.add_argument("action", choices=["find", "create", "clear"])
    us.add_argument("email", nargs="?", default="")
    t = sub.add_parser("traffic")
    t.add_argument("--loops", type=int, default=1)
    t.add_argument("--only", choices=SCENARIOS)
    t.add_argument("--scenarios", help="comma list, e.g. dlp,upload (default: all)")
    t.add_argument("--region", choices=QUICK_REGIONS)
    t.add_argument("--via", choices=["laptop", "cloudshare"], default="laptop",
                   help="cloudshare: send from the CloudShare VM picked in the console")
    t.add_argument("--json", action="store_true", help="print one QK_RESULT {json} line (used by cloudshare/run.ps1)")
    tp = sub.add_parser("template")
    tp.add_argument("--out", default="quick-demo-env.yaml")
    tp.add_argument("--project", default="zs-quick-demo")
    tp.add_argument("--zpa", action="store_true")
    tp.add_argument("--ami", default="")
    aw = sub.add_parser("aws", help="deploy / inspect / delete the demo CloudFormation stack (settings from the console)")
    aw.add_argument("action", choices=["deploy", "status", "delete", "quick-setup", "quick-teardown"])
    aw.add_argument("--owner", help="Quick user ARN to own the knowledge base (quick-setup; default: saved or first admin)")
    aw.add_argument("--profile", help="AWS CLI profile (default: the one saved in the console, else default)")
    aw.add_argument("--region", choices=QUICK_REGIONS)
    up = sub.add_parser("update", help="update the kit from GitHub (--check: only check, --rollback: previous version)")
    up.add_argument("--check", action="store_true")
    up.add_argument("--rollback", action="store_true")
    sub.add_parser("install")
    sub.add_parser("uninstall")
    m = sub.add_parser("mcp-test")
    m.add_argument("url")
    m.add_argument("--token", default="")
    a = ap.parse_args(argv)
    cfg = load_cfg()

    try:
        if a.cmd in (None, "gui"):
            cmd_gui(getattr(a, "port", 8770), not getattr(a, "no_browser", False))
        elif a.cmd == "config":
            cfg["vanity"] = input(f"Vanity domain (the 'acme' in acme.zslogin.net) [{cfg.get('vanity', '')}]: ").strip() or cfg.get("vanity", "")
            cfg["client_id"] = input(f"OneAPI client ID [{mask(cfg.get('client_id', ''))}]: ").strip() or cfg.get("client_id", "")
            sec = getpass.getpass("Client secret (Enter to keep the saved one): ")
            if sec:
                set_secret(sec)
            save_cfg(cfg)
            print("Saved. The secret is in your OS keychain, not in", CFG_FILE)
        elif a.cmd == "setup":
            print(zia_run(cfg, a.apply, a.teardown)["output"])
        elif a.cmd == "zpa":
            print(zpa_run(cfg, a.apply, a.teardown)["output"])
        elif a.cmd == "user":
            r = zia_user(cfg, a.action, a.email)
            print("Scope:", (r["user"] or {}).get("email") or "everyone")
        elif a.cmd == "status":
            for i in zia_status(cfg)["items"]:
                print(f"  [{'✓' if i['exists'] else ' '}] {i['type']:<20} {i['name']}  {i['detail']}")
        elif a.cmd == "traffic":
            sc = [a.only] if a.only else ([s.strip() for s in a.scenarios.split(",")] if a.scenarios else SCENARIOS)
            if a.via == "cloudshare":
                r = cs_action(cfg, "traffic", sc, a.loops, a.region or "",
                              progress=lambda s: print(f"  waiting for the VM… {s}s", end="\r"))
            else:
                r = traffic(cfg, sc, a.loops, a.region)
            if a.json:
                print(cs_runner.MARK + json.dumps({"ok": True, **r}))
            else:
                for x in r.get("results", []):
                    print(f"  {x['outcome']:<10} {x['label']}")
                print("Summary:", r.get("summary"))
        elif a.cmd == "template":
            pathlib.Path(a.out).write_text(build_template({"project": a.project, "zpa": a.zpa, "ami": a.ami}), encoding="utf-8")
            print(f"Wrote {a.out}. Upload it in the CloudFormation console (Create stack > Upload a template file).")
        elif a.cmd == "aws":
            if a.profile or a.region:
                cfg.setdefault("aws", {}).update({k: v for k, v in (("profile", a.profile), ("region", a.region),
                                                                     ("auth", "profile" if a.profile else None)) if v})
            if a.action == "status":
                r = aws_status(cfg)
                print(f"Account {r['identity']['account']} · {r['identity']['region']}")
                st = r["stack"]
                print(f"Stack: {st['status'] if st else 'not deployed'}")
                for k, v in ((st or {}).get("outputs") or {}).items():
                    print(f"  {k}: {v}")
            elif a.action == "deploy":
                tok = getpass.getpass("MCP token (Enter for none): ")
                zk = getpass.getpass("ZPA provisioning key: ") if aws_cfg(cfg).get("zpa") else ""
                st = aws_deploy_stack(cfg, tok, zk, progress=lambda m: print("  " + m))
                for k, v in (st.get("outputs") or {}).items():
                    print(f"  {k}: {v}")
            elif a.action == "quick-setup":
                st = quick_status(cfg)
                owner = a.owner or st["owner"] or (st["users"][0]["arn"] if st["users"] else "")
                r = quick_run(cfg, owner, True, progress=lambda m: print("  " + m))
                print(f"Knowledge base ready ({r.get('documents') or 0} documents).")
            elif a.action == "quick-teardown":
                quick_teardown(cfg, progress=lambda m: print("  " + m))
            else:
                if input(f"Delete stack {aws_cfg(cfg)['project']}? Type yes: ").strip().lower() == "yes":
                    aws_delete_stack(cfg, progress=lambda m: print("  " + m))
                    print("Deleted.")
        elif a.cmd == "update":
            if a.rollback:
                print("Rolled back to", updater.rollback(HERE, BACKUP))
            else:
                info = update_check(cfg)
                print(f"Running {VERSION}; latest {info['latest']}.")
                if info["notes"]:
                    print("\n" + info["notes"] + "\n")
                if info["available"] and not a.check:
                    r = update_apply(cfg)
                    print(f"Updated to {r['version']}. Restart the console to use it.")
        elif a.cmd == "install":
            cmd_install()
        elif a.cmd == "uninstall":
            cmd_uninstall()
        elif a.cmd == "mcp-test":
            r = mcp_test(a.url, a.token)
            for st in r["steps"]:
                print(f"  [{'✓' if st['ok'] else '✗'}] {st['step']:<32} {st.get('status')} {st.get('note', '')}")
            print("Tools:", ", ".join(r["tools"]) or "none")
    except (zqs.ZiaError, cs_runner.CloudShareError, zpa_quick.ZpaError, updater.UpdateError, aws_deploy.AwsError,
            quick_setup.QuickError, ValueError) as e:
        if getattr(a, "json", False):
            print(cs_runner.MARK + json.dumps({"ok": False, "error": str(e)}))
        sys.exit(str(e))


if __name__ == "__main__":
    main()
