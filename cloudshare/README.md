# Sending demo traffic from CloudShare

**Why:** traffic goes to whichever Zscaler tenant the sending machine's Client Connector is enrolled in. A corporate laptop is enrolled in the corporate tenant. Fake PII sent from it raises real DLP incidents there, under your name, and never reaches your demo tenant. A CloudShare Windows VM whose Client Connector is signed in as your **demo-tenant** user is the right sender. The console stays on your laptop and only talks to the CloudShare API.

## Set up (once)

1. **The VM:** a Windows VM in a CloudShare environment, with Client Connector installed and signed in as your demo-tenant test user (tunnel mode). Internet access goes through Client Connector.
2. **API credentials:** in CloudShare, open My Account → API Credentials and copy the API ID and API key. Click "Generate API Credentials" if the fields are blank.
3. **Console:** Traffic tab → **Send from: CloudShare VM**. Enter the API ID and key (the key goes to your OS keychain), press **Save & load environments**, then pick the environment and the Windows VM.
4. Press **Check VM**. You want **zcc service: Running** and **via zscaler: true**. If via zscaler is false, sign in to Client Connector on the VM.

## Use

- **Send traffic** on the Traffic tab, and the traffic buttons on the Guided demo tab, now run on the VM. The first run installs uv, Python 3.12 and the kit under `C:\SE-Demo` (about 2 minutes). Later runs take seconds, and each run refreshes the kit from GitHub.
- **Keep dashboards fresh** registers a scheduled task on the VM (`SE-Demo Quick traffic`) that sends a batch every 30/60/120 minutes. **Stop schedule** removes it. The task only runs while the environment is running: CloudShare suspends idle environments.
- Command line: `./quick-kit traffic --via cloudshare` uses the VM picked in the console.

## How it works

The console calls CloudShare's `executePath` API with a short PowerShell command. That command downloads [`run.ps1`](run.ps1) from this repo (branch or tag under Advanced) and runs it. `run.ps1` installs what's missing, then runs `quick_kit.py traffic --json` through the VM's Client Connector. The console polls `checkExecutionStatus` and reads the last output line, `QK_RESULT {json}`. The VM keeps a log at `C:\SE-Demo\quick-runner.log`.

You can also run it by hand on the VM:
```powershell
powershell -ExecutionPolicy Bypass -File C:\SE-Demo\run.ps1 -Scenarios dlp,upload
```

## Things to verify on your first run

- **Which user the traffic is logged under.** CloudShare runs commands through its VM agent, and the scheduled task runs as SYSTEM. In tunnel mode, Client Connector forwards the whole device's traffic and ZIA logs it under the enrolled user, but confirm it in Web Insights.
- **Whether the API key can run commands.** Some CloudShare accounts restrict which API actions are allowed. If *Check VM* fails with a permission error, ask your CloudShare admin.
- **The repo must be public.** The VM downloads the kit from GitHub without signing in, and GitHub answers "not found" for private repos.
- **Downloads from GitHub and astral.sh.** If your demo tenant's policy blocks these, the first run fails. Allow them for the test user.
