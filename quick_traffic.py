#!/usr/bin/env python3
"""
quick_traffic.py - Generate Amazon Quick-shaped traffic through Zscaler Client Connector
so ZIA dashboards (Web Insights, DLP incidents, AI app usage) populate on demand.

Use it when:
  * you don't have a live Amazon Quick account for the demo, or
  * you want logs pre-populated before the customer call.

What it sends (ALL DATA IS SYNTHETIC):
  - benign GETs to the Quick web app in each launch region   -> URL / AI-app visibility
  - "prompt" POSTs containing fake PII / card numbers / keys  -> DLP block + incident
  - a fake "file upload" (CSV with synthetic customer rows)   -> DLP on uploads

Requests go to real Quick hostnames, but carry no AWS credentials, so AWS returns 4xx.
That doesn't matter: ZIA inspects and logs (or blocks) the request before it ever reaches AWS.

Prereqs: ZCC in tunnel mode, SSL inspection ON for the "Amazon Quick (Demo)" category,
and Python trusting the Zscaler root CA (pass --ca-bundle, or `pip install truststore`).

  python3 quick_traffic.py                  # one pass, all scenarios
  python3 quick_traffic.py --loops 5 --sleep 20
  python3 quick_traffic.py --only dlp
"""
import argparse
import io
import json
import random
import sys
import time

import requests

try:
    import truststore  # uses the OS trust store (where ZCC installs the Zscaler root CA)
    truststore.inject_into_ssl()
except ImportError:
    pass

REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-2"]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36 zs-quick-demo-kit")

# Synthetic test data only. Card numbers are standard test PANs (Luhn-valid).
RISKY_PROMPTS = [
    ("PII", "Summarize this customer complaint: Jane Rivera, SSN 512-44-7381, DOB 03/14/1986, "
            "lives at 42 Harbor Rd, Huntington NY 11743. She says her claim was denied."),
    ("PCI", "Build a chart of these failed payments: 4111 1111 1111 1111 exp 09/28, "
            "5500 0000 0000 0004 exp 11/27, 3400 000000 00009 exp 01/29."),
    ("Secrets", "Why does this boto3 call fail? aws_access_key_id=AKIAIOSFODNN7EXAMPLE "
                "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("Mixed", "Draft an email to our auditor listing these employees and SSNs: "
              "Mark Chen 623-19-4402, Priya Nair 541-77-2031, Luis Ortega 468-02-9917."),
]
BENIGN_PROMPTS = [
    "Show me Q3 pipeline by region as a bar chart.",
    "Create a flow that summarizes my unread Outlook email every morning.",
    "Research the top three competitors in the managed print market.",
]


def fake_csv(rows=25):
    first = ["Ana", "Ben", "Chloe", "Dev", "Ella", "Femi", "Gus", "Hana", "Ivan", "Jo"]
    last = ["Lopez", "Smith", "Kim", "Patel", "Rossi", "Okafor", "Berg", "Sato", "Novak", "Reyes"]
    out = io.StringIO()
    out.write("name,ssn,card,zip\n")
    for _ in range(rows):
        ssn = f"{random.randint(100, 665)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"
        out.write(f"{random.choice(first)} {random.choice(last)},{ssn},4111111111111111,"
                  f"{random.randint(10001, 11999)}\n")
    return out.getvalue().encode()


def hit(s, method, url, label, **kw):
    try:
        r = s.request(method, url, timeout=20, allow_redirects=False, **kw)
        blocked = r.status_code == 403 and "zscaler" in r.text.lower()
        tag = "BLOCKED by Zscaler" if blocked else f"HTTP {r.status_code}"
        print(f"  [{tag:>18}] {label}")
    except requests.exceptions.SSLError:
        print(f"  [{'TLS ERROR':>18}] {label}  -> trust the Zscaler root CA (--ca-bundle / truststore)")
    except requests.RequestException as e:
        print(f"  [{'ERROR':>18}] {label}  -> {e.__class__.__name__}")


def run(s, only):
    region = random.choice(REGIONS)
    base = f"https://{region}.quicksight.aws.amazon.com"

    if only in (None, "visibility"):
        print(f"\n> Visibility ({region})")
        for path in ["/sn/start", "/sn/start/agents", "/sn/start/flows", "/sn/start/research"]:
            hit(s, "GET", base + path, f"GET {path}")
        for p in BENIGN_PROMPTS:
            hit(s, "POST", base + "/zs-demo/chat", f"benign prompt: {p[:45]}...",
                data=json.dumps({"prompt": p}), headers={"Content-Type": "application/json"})

    if only in (None, "dlp"):
        print(f"\n> DLP on prompts ({region})")
        for kind, p in RISKY_PROMPTS:
            hit(s, "POST", base + "/zs-demo/chat", f"{kind} prompt",
                data=json.dumps({"prompt": p}), headers={"Content-Type": "application/json"})

    if only in (None, "upload"):
        print(f"\n> DLP on uploads ({region})")
        hit(s, "POST", base + "/zs-demo/spaces/upload", "customers_export.csv -> Quick Space",
            files={"file": ("customers_export.csv", fake_csv(), "text/csv")})


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--loops", type=int, default=1)
    ap.add_argument("--sleep", type=int, default=15, help="seconds between loops")
    ap.add_argument("--only", choices=["visibility", "dlp", "upload"])
    ap.add_argument("--ca-bundle", help="path to Zscaler root CA / bundle")
    a = ap.parse_args()

    s = requests.Session()
    s.headers["User-Agent"] = UA
    if a.ca_bundle:
        s.verify = a.ca_bundle

    print("Amazon Quick demo traffic -> make sure Zscaler Client Connector is ON.")
    for i in range(a.loops):
        print(f"\n=== pass {i + 1}/{a.loops} ===")
        run(s, a.only)
        if i < a.loops - 1:
            time.sleep(a.sleep)
    print("\nDone. Logs appear in ZIA Web Insights / DLP incidents within a few minutes.")


if __name__ == "__main__":
    sys.exit(main())
