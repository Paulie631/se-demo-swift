# Amazon Quick × Zscaler — SE Demo Kit

Demo Zscaler securing **Amazon Quick** (AWS's agentic AI workspace) from a browser console. Stage the ZIA policy, fill the dashboards, run a guided six-act customer demo and build a real AWS test environment.

> **Community SE tooling, not an official Zscaler or AWS product.** Use it only in demo or POV tenants and accounts you control. All data is synthetic. `aws/` deploys a **deliberately vulnerable** MCP server for security testing, so don't leave it running unattended.

## Quickstart

**Easiest:** download or clone this repo, then double-click **Install Quick Kit.command** (Mac) or **Install Quick Kit.cmd** (Windows). It installs [uv](https://docs.astral.sh/uv/) if needed, copies the kit to `~/.quick-se-kit/app`, adds an **Amazon Quick Demo Console** desktop shortcut and opens the console.

**Command line:**
```bash
./quick-kit gui          # Mac / Linux   (needs uv: brew install uv)
.\quick-kit.cmd gui      # Windows
```

Then, in the console:
1. **Setup:** enter your OneAPI vanity domain, client ID and secret (the API client needs the ZIA policy-admin role). Press **Save & test**, then **Preview changes**, then **Create & activate**.
2. Do the one-time manual steps listed on the Setup tab. The important one: **SSL inspection** for the `Amazon Quick (Demo)` category.
3. **Traffic:** send a few passes 30–60 minutes before the call so Web Insights and DLP incidents have data. **On a corporate laptop, choose "Send from: CloudShare VM"** (see below).
4. **Guided demo:** present the six acts. Each has a talk track, what to show, copyable prompts and a button for that step's traffic. Tick **Presenting** to hide your notes when you share your screen.

## The console

| Tab | What it's for |
|---|---|
| **Setup** | Connect to ZIA (the secret is stored in the OS keychain). Check, preview, create or remove the demo policy: a custom URL category for Quick's domains, a **Caution** (usage-policy coaching) rule and a **Block** Web DLP rule (PCI / PII / GLBA). |
| **Guided demo** | 1 Discover · 2 Govern access · 3 Protect data in prompts · 4 Agentic Quick (extension, desktop app, MCP) · 5 The data Quick can see (DSPM) · 6 Build-time assurance (AI-SPM, red teaming, prompt hardening). About 35 minutes. ← → to move. |
| **Traffic** | Quick-shaped requests through Client Connector: visibility, PII/PCI/secrets prompts and a fake customer CSV upload, with a result per request (blocked, passed, or a TLS problem with its fix). Works without a Quick account. **Send from** this laptop or a **CloudShare VM**, with a VM check and an optional schedule to keep dashboards fresh. |
| **AWS environment** | Builds the CloudFormation template with your choices filled in. Secrets stay out of the file. Links to the CloudFormation console, lists the steps to wire the stack into Quick, and runs a live check of the deployed MCP server. |
| **Logs** | Everything the kit did (secrets never logged). Full file: `~/.quick-se-kit/kit.log`. |

## Command line

```
./quick-kit config            save vanity domain, client ID, secret (keychain)
./quick-kit setup             preview the ZIA demo policy; --apply to create, --teardown --apply to remove
./quick-kit status            which demo objects exist
./quick-kit traffic           demo traffic (--loops N, --only visibility|dlp|upload, --region, --via cloudshare)
./quick-kit template          write the AWS template (--project, --zpa, --ami, --out)
./quick-kit mcp-test URL      check the deployed MCP server (--token)
./quick-kit install|uninstall desktop shortcut + ~/.quick-se-kit/app
```
`zia_quick_setup.py` and `quick_traffic.py` still run on their own (environment variables `ZS_VANITY`, `ZS_CLIENT_ID`, `ZS_CLIENT_SECRET`).

## Corporate laptop? Send traffic from CloudShare

Traffic goes to whichever tenant the sending machine's Client Connector is enrolled in. From a corporate laptop, the fake PII would land in corporate DLP, not your demo tenant. Run the console on your laptop and send traffic from a CloudShare Windows VM enrolled in your demo tenant: the console drives it through the CloudShare API. Setup and details: [cloudshare/README.md](cloudshare/README.md).

## AWS environment

`aws/quick-demo-env.yaml` builds:
- a private S3 bucket of synthetic sensitive data, including a vendor guide with a hidden prompt injection
- a deliberately vulnerable MCP server on a Lambda Function URL
- optionally, a ZPA App Connector plus a Quick PrivateLink path

See [aws/README.md](aws/README.md).

## Honest boundaries

User and browser-extension traffic to Quick is inline with ZIA. Quick's cloud connectors, Flows browser tasks and Research web retrieval run from AWS to the other services, so they never pass through the user's ZIA connection. Cover those at the tool layer (AI Guard / AI Broker on the customer's own MCP servers and APIs) and the data layer (DSPM, SSPM). Before the call, confirm whether Amazon Quick is in the Cloud App catalog and prompt-extraction list, and the GA status of Endpoint AI Security and AI Broker.

## Development

```bash
python3 -m unittest tests/test_kit.py     # offline: fake ZIA tenant, real MCP handler, template checks
python3 aws/build.py                      # regenerate aws/quick-demo-env.yaml after editing aws/src or template.src.yaml
```
