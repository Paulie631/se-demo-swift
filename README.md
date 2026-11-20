# Amazon Quick × Zscaler — Demo Kit

Stage a "secure Amazon Quick" demo in any ZIA tenant in ~10 minutes.

> **Community SE tooling, not an official Zscaler or AWS product.** Use it only in demo or POV tenants and accounts you control. All data is synthetic. `aws/` deploys a **deliberately vulnerable** MCP server for security testing, so don't leave it running unattended.

| File | What it does |
|---|---|
| `zia_quick_setup.py` | Creates custom URL category **Amazon Quick (Demo)**, a **CAUTION** (AUP coaching) URL rule, and a **BLOCK** Web DLP rule (PCI/PII/GLBA engines), then activates. Dry run by default; `--teardown` removes everything. |
| `quick_traffic.py` | Sends Quick-shaped traffic (benign usage, fake-PII prompts, fake customer CSV upload) through ZCC so dashboards and DLP incidents populate even without a live Quick account. |

## Quick start

```bash
pip install requests truststore

export ZS_VANITY=yourtenant          # https://yourtenant.zslogin.net
export ZS_CLIENT_ID=...              # ZIdentity API client with ZIA policy scope
export ZS_CLIENT_SECRET=...

python3 zia_quick_setup.py           # review the dry run
python3 zia_quick_setup.py --apply   # create + activate

# With ZCC on (tunnel mode, SSL inspection enabled for the new category):
python3 quick_traffic.py --loops 3
```

**Before you use this in a customer tenant:**
- Turn on SSL inspection for the `Amazon Quick (Demo)` category. If you don't, DLP can't see prompt bodies.
- Rule order: the script inserts at order 1. Move the rules if the tenant has stricter rules above them.
- Check in Web Insights which hostnames the customer's Quick actually uses. Add any new ones to the category.
- All test data is synthetic: test card numbers and made-up SSNs.

Cleanup: `python3 zia_quick_setup.py --teardown --apply`

## AWS environment (optional)

`aws/` holds a CloudFormation template for a real test environment:
- synthetic sensitive data in S3, for Quick knowledge bases and DSPM
- a deliberately vulnerable MCP server, for AI Guard, AI-SPM and red teaming
- an optional ZPA App Connector with a Quick PrivateLink path

See `aws/README.md`.
