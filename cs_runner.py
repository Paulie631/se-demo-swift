"""Run the Amazon Quick demo traffic from a CloudShare VM instead of this laptop.

Why: traffic goes to whichever Zscaler tenant the sending machine's Client Connector is enrolled in. A work laptop is
usually enrolled in the corporate tenant, so fake PII sent from it lands in corporate DLP (and never in your demo
tenant). A CloudShare Windows VM with Client Connector enrolled as your demo-tenant user is the right sender.

How: CloudShare REST API v3 (cs_sha1 auth). `executePath` runs a short PowerShell command on the VM that downloads
cloudshare/run.ps1 from this kit's GitHub repo and runs it; run.ps1 installs uv + the kit on the VM (first time
only, under C:\\SE-Demo) and runs `quick_kit.py traffic --json`. `checkExecutionStatus` returns the VM's output,
and the last line starting with QK_RESULT carries the results back.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import string
import time
import urllib.parse

import requests

HOST = "use.cloudshare.com"
DEFAULT_REPO = "Paulie631/se-demo-swift"
DEFAULT_REF = "main"
MARK = "QK_RESULT "


class CloudShareError(Exception):
    pass


def _token() -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))


def auth_header(api_id: str, api_key: str, url: str, ts: int | None = None, token: str | None = None) -> str:
    """cs_sha1 header: hmac = sha1(api_key + full_url + timestamp + token), hex."""
    ts = int(time.time()) if ts is None else ts
    token = token or _token()
    mac = hashlib.sha1(f"{api_key}{url}{ts}{token}".encode()).hexdigest()
    return f"cs_sha1 userapiid:{api_id};timestamp:{ts};token:{token};hmac:{mac}"


class CloudShare:
    def __init__(self, api_id: str, api_key: str, verify=True):
        if not api_id or not api_key:
            raise CloudShareError("Add your CloudShare API ID and API key (CloudShare › My Account › API Credentials).")
        # stray spaces/newlines from copy-paste change the HMAC, so trim them
        self.api_id, self.api_key, self.verify = api_id.strip(), api_key.strip(), verify

    def req(self, method: str, path: str, params: dict | None = None, body: dict | None = None):
        url = f"https://{HOST}/api/v3/{path.strip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        h = {"Accept": "application/json", "Content-Type": "application/json",
             "Authorization": auth_header(self.api_id, self.api_key, url)}
        try:
            r = requests.request(method, url, headers=h, data=json.dumps(body) if body is not None else None,
                                 timeout=30, verify=self.verify)
        except requests.RequestException as e:
            raise CloudShareError(f"Couldn't reach {HOST} ({e.__class__.__name__}).")
        if "HMAC doesn't match" in r.text or "0x50017" in r.text:
            raise CloudShareError("CloudShare says the API key doesn't match the API ID. In CloudShare › My Account › "
                                  "API Credentials, copy the API ID and API key again (both from the same page; if you "
                                  "regenerated credentials, the old key stops working), paste the key into API key and "
                                  "press Save & load environments.")
        if r.status_code in (401, 403):
            raise CloudShareError("CloudShare rejected the API credentials (check the API ID and key).")
        if r.status_code >= 400:
            raise CloudShareError(f"CloudShare {method} {path} -> {r.status_code}: {r.text[:300]}")
        try:
            return r.json()
        except ValueError:
            return {}

    # -- discovery
    def envs(self) -> list[dict]:
        return [{"id": e.get("id"), "name": e.get("name"), "status": e.get("statusText") or e.get("status"),
                 "project": e.get("projectName") or e.get("project")} for e in (self.req("GET", "envs") or [])]

    def vms(self, env_id: str) -> list[dict]:
        ext = self.req("GET", "envs/actions/getextended", {"envId": env_id}) or {}
        return [{"id": v.get("id"), "name": v.get("name"), "os": v.get("os") or "", "status": v.get("statusText"),
                 "windows": "win" in str(v.get("os") or v.get("name") or "").lower()} for v in ext.get("vms") or []]

    # -- execution
    def execute(self, vm_id: str, command: str) -> str:
        r = self.req("POST", "vms/actions/executePath", body={"vmId": vm_id, "path": command})
        if not r.get("executionId"):
            raise CloudShareError(f"CloudShare didn't start the command: {str(r)[:200]}")
        return r["executionId"]

    def status(self, vm_id: str, execution_id: str) -> dict:
        return self.req("GET", "vms/actions/checkExecutionStatus", {"vmId": vm_id, "executionId": execution_id}) or {}

    def run(self, vm_id: str, command: str, timeout: int = 900, every: int = 5, progress=None) -> dict:
        """Start a command and wait for it. Returns the final status dict (standardOutput etc.)."""
        ex = self.execute(vm_id, command)
        t0 = time.time()
        while True:
            time.sleep(every)
            st = self.status(vm_id, ex)
            if st.get("success") or st.get("errorCode") or MARK in (st.get("standardOutput") or ""):
                return st
            if progress:
                progress(int(time.time() - t0))
            if time.time() - t0 > timeout:
                raise CloudShareError(f"The VM didn't finish within {timeout // 60} minutes. "
                                      "Is it running, and does it have internet access through Client Connector?")


def ps_encoded(script: str) -> str:
    """powershell -EncodedCommand line: no quoting problems through CloudShare and cmd."""
    b64 = base64.b64encode(script.encode("utf-16-le")).decode()
    return f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {b64}"


def _ps_str(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def run_command(scenarios: list[str], loops: int = 1, region: str = "", repo: str = DEFAULT_REPO,
                ref: str = DEFAULT_REF, schedule_every: int = 0, unschedule: bool = False) -> str:
    """The command CloudShare runs on the VM: fetch run.ps1 from the kit's repo and run it with these options."""
    url = f"https://raw.githubusercontent.com/{repo}/{ref}/cloudshare/run.ps1"
    args = [f"-Scenarios {_ps_str(','.join(scenarios))}", f"-Loops {int(loops)}",
            f"-Repo {_ps_str(repo)}", f"-Ref {_ps_str(ref)}"]
    if region:
        args.append(f"-Region {_ps_str(region)}")
    if schedule_every:
        args.append(f"-Schedule -Every {int(schedule_every)}")
    if unschedule:
        args.append("-Unschedule")
    script = ("$ProgressPreference='SilentlyContinue';"
              "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
              "New-Item -ItemType Directory -Force -Path C:\\SE-Demo | Out-Null;"
              f"Invoke-WebRequest -UseBasicParsing {_ps_str(url)} -OutFile C:\\SE-Demo\\run.ps1;"
              f"& C:\\SE-Demo\\run.ps1 {' '.join(args)}")
    return ps_encoded(script)


CHECK_SCRIPT = r"""$ProgressPreference='SilentlyContinue'
$o=[ordered]@{}
$o.computer=$env:COMPUTERNAME
$o.user=(whoami)
$s=Get-Service -Name ZSAService -ErrorAction SilentlyContinue
$o.zcc_service=if($s){"$($s.Status)"}else{'not installed'}
try{
  $c=(Invoke-WebRequest -UseBasicParsing https://ip.zscaler.com -TimeoutSec 20).Content
  $t=($c -replace '<[^>]+>',' ' -replace '\s+',' ')
  $o.via_zscaler=[bool]($t -match 'accessing (the Internet|this host) via')
  $m=[regex]::Match($t,'[^.]*Zscaler[^.]*\.')
  $o.ip_zscaler=if($m.Success){$m.Value.Trim()}else{''}
}catch{$o.via_zscaler=$false;$o.ip_zscaler="ip.zscaler.com unreachable: $($_.Exception.Message)"}
$o.kit_installed=Test-Path 'C:\SE-Demo\quick-kit\quick_kit.py'
$o.scheduled=[bool](Get-ScheduledTask -TaskName 'SE-Demo Quick traffic' -ErrorAction SilentlyContinue)
'QK_RESULT '+($o|ConvertTo-Json -Compress)
"""


DEFAULT_ZCC_MSI = "https://d32a6ru7mhaq0c.cloudfront.net/Zscaler-windows-4.4.0.379-installer-x64.msi"

ZCC_SCRIPT = r"""$ProgressPreference='SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$o=[ordered]@{}
$s=Get-Service -Name ZSAService -ErrorAction SilentlyContinue
$o.before=if($s){"$($s.Status)"}else{'not installed'}
if(-not $s -or $Force){
  New-Item -ItemType Directory -Force -Path C:\SE-Demo | Out-Null
  $msi='C:\SE-Demo\zcc.msi'
  try{Invoke-WebRequest -UseBasicParsing $Url -OutFile $msi -TimeoutSec 600}catch{$o.error="download failed: $($_.Exception.Message)"}
  if(-not $o.error){
    $a="/i `"$msi`" /qn /norestart /l*v C:\SE-Demo\zcc-install.log CLOUDNAME=$Cloud"
    if($Domain){$a+=" USERDOMAIN=$Domain"}
    $p=Start-Process msiexec.exe -ArgumentList $a -Wait -PassThru
    $o.msi_exit=$p.ExitCode
    Start-Sleep 20
  }
}
$s=Get-Service -Name ZSAService -ErrorAction SilentlyContinue
$o.after=if($s){"$($s.Status)"}else{'not installed'}
$v=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue|?{$_.DisplayName -like 'Zscaler*'}|select -First 1
$o.version=if($v){$v.DisplayVersion}else{''}
'QK_RESULT '+($o|ConvertTo-Json -Compress)
"""


def zcc_command(cloud: str, domain: str = "", msi_url: str = "", force: bool = False) -> str:
    """Install Zscaler Client Connector silently, preset to this tenant's cloud and sign-in domain. ZCC still needs
    one interactive sign-in on the VM (the test user's email and password)."""
    import re
    cloud = (cloud or "").strip().lower().replace(".net", "")
    if not re.fullmatch(r"[a-z0-9]+", cloud):
        raise CloudShareError("Enter the tenant's cloud name, e.g. zscalertwo.")
    if domain and not re.fullmatch(r"[A-Za-z0-9.-]+", domain):
        raise CloudShareError("The sign-in domain should look like example.com.")
    url = (msi_url or DEFAULT_ZCC_MSI).strip()
    if not url.lower().startswith("https://") or not url.lower().split("?")[0].endswith(".msi"):
        raise CloudShareError("The Client Connector installer link should be an https URL to a .msi file.")
    head = (f"$Url={_ps_str(url)};$Cloud={_ps_str(cloud)};$Domain={_ps_str(domain)};"
            f"$Force=${'true' if force else 'false'}\n")
    return ps_encoded(head + ZCC_SCRIPT)


def check_command() -> str:
    return ps_encoded(CHECK_SCRIPT)


def parse_result(status: dict) -> dict:
    out = status.get("standardOutput") or ""
    for line in reversed(out.splitlines()):
        if line.startswith(MARK):
            try:
                return json.loads(line[len(MARK):])
            except ValueError:
                break
    err = (status.get("standardError") or "").strip()
    tail = "\n".join(out.strip().splitlines()[-15:])
    raise CloudShareError("The VM ran the command but returned no results."
                          + (f"\nError output:\n{err[-1500:]}" if err else "")
                          + (f"\nLast output:\n{tail}" if tail else ""))
