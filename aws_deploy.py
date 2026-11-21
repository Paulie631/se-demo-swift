"""Deploy, inspect and delete the demo CloudFormation stack straight from the kit (boto3).

Credentials, in order of preference:
  - an AWS CLI profile on this laptop (~/.aws/config or credentials; SSO profiles need `aws sso login` first)
  - access keys typed into the console (the secret goes to the OS keychain)
Secrets for the stack itself (MCP token, ZPA provisioning key) are passed as NoEcho parameters and never stored.
"""
from __future__ import annotations

import time

TERMINAL_OK = {"CREATE_COMPLETE", "UPDATE_COMPLETE", "DELETE_COMPLETE", "IMPORT_COMPLETE"}
TERMINAL_BAD = {"CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "DELETE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
                "UPDATE_ROLLBACK_FAILED", "UPDATE_FAILED", "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED"}


class AwsError(Exception):
    pass


def _boto3():
    try:
        import boto3
        return boto3
    except ImportError:
        raise AwsError("boto3 isn't installed. Start the kit with ./quick-kit (uv installs it), or pip install boto3.")


def profiles() -> list[str]:
    try:
        return sorted(_boto3().session.Session().available_profiles)
    except Exception:
        return []


def session(region: str, profile: str = "", key_id: str = "", secret: str = "", token: str = ""):
    b = _boto3()
    if key_id and secret:
        return b.session.Session(aws_access_key_id=key_id, aws_secret_access_key=secret,
                                 aws_session_token=token or None, region_name=region)
    try:
        return b.session.Session(profile_name=profile or None, region_name=region)
    except Exception as e:
        raise AwsError(f"AWS profile problem: {e}")


def explain(e: Exception) -> str:
    s = str(e)
    if "Token has expired" in s or ("SSO" in s and "expired" in s.lower()) or "UnauthorizedSSOToken" in s:
        return "Your AWS SSO sign-in has expired. Run: aws sso login --profile <profile>, then try again."
    if "Unable to locate credentials" in s or "NoCredentialsError" in type(e).__name__:
        return "No AWS credentials found. Pick a profile, or enter access keys."
    if "InvalidClientTokenId" in s or "SignatureDoesNotMatch" in s:
        return "AWS rejected the access keys (check the key ID and secret)."
    if "OptInRequired" in s:
        return ("AWS Marketplace: subscribe to the Zscaler App Connector product once in this account (Marketplace > "
                "search 'Zscaler App Connector' > Continue to Subscribe), then deploy again.")
    if "AccessDenied" in s:
        return f"AWS denied the request: {s[:300]}. The identity needs CloudFormation, IAM, S3, Lambda and (for ZPA) EC2/Route 53 rights."
    if "SSL" in s or "CERTIFICATE_VERIFY_FAILED" in s:
        return ("TLS check failed talking to AWS, usually because SSL inspection re-signs AWS traffic on this laptop. "
                "Set a CA bundle that includes the Zscaler root certificate under Setup › Advanced, then try again.")
    if "proxy" in s.lower():
        return f"Couldn't reach AWS through this laptop's proxy ({s[:160]})."
    if "Could not connect" in s or "EndpointConnectionError" in type(e).__name__:
        return "Couldn't reach AWS. Check this laptop's network or Client Connector connection."
    return s[:500]


def find_connector_ami(sess) -> list[dict]:
    """Zscaler App Connector AMIs from AWS Marketplace in this region, newest first. You still have to accept the
    Marketplace subscription once, or EC2 refuses to launch it (OptInRequired)."""
    ec2 = sess.client("ec2")
    seen, out = set(), []
    for pat in ("*zpa-connector*", "*ZPA*Connector*", "*Zscaler*App*Connector*"):
        try:
            imgs = ec2.describe_images(Owners=["aws-marketplace"], Filters=[{"Name": "name", "Values": [pat]},
                                                                           {"Name": "state", "Values": ["available"]}])
        except Exception as e:
            raise AwsError(explain(e))
        for i in imgs.get("Images", []):
            if i["ImageId"] not in seen and "arm64" not in i.get("Architecture", ""):
                seen.add(i["ImageId"])
                out.append({"id": i["ImageId"], "name": i.get("Name", ""), "created": i.get("CreationDate", "")})
    return sorted(out, key=lambda x: x["created"], reverse=True)


def whoami(sess) -> dict:
    try:
        i = sess.client("sts").get_caller_identity()
    except Exception as e:
        raise AwsError(explain(e))
    return {"account": i["Account"], "arn": i["Arn"], "region": sess.region_name}


def stack(sess, name: str) -> dict | None:
    cf = sess.client("cloudformation")
    try:
        s = cf.describe_stacks(StackName=name)["Stacks"][0]
    except Exception as e:
        if "does not exist" in str(e):
            return None
        raise AwsError(explain(e))
    return {"name": s["StackName"], "status": s["StackStatus"], "reason": s.get("StackStatusReason", ""),
            "outputs": {o["OutputKey"]: o["OutputValue"] for o in s.get("Outputs") or []},
            "created": str(s.get("CreationTime", "")), "id": s["StackId"]}


def _events(cf, name, since):
    try:
        ev = cf.describe_stack_events(StackName=name)["StackEvents"]
    except Exception:
        return []
    return [e for e in reversed(ev) if e["Timestamp"].timestamp() >= since]


def wait(sess, name: str, since: float, progress=None, timeout: int = 1800, poll: int = 5, deleting=False,
         stack_id: str = "") -> dict:
    """stack_id: read events by ID, which keeps working after a failed create deletes the stack."""
    cf = sess.client("cloudformation")
    seen, failures = set(), []
    t0 = last_new = last_note = time.time()
    pending: dict = {}   # resources currently *_IN_PROGRESS -> when they started
    def drain():
        for e in _events(cf, stack_id or name, since):
            if e["EventId"] in seen:
                continue
            seen.add(e["EventId"])
            last_new = time.time()
            lid, rs = e["LogicalResourceId"], e["ResourceStatus"]
            if rs.endswith("_IN_PROGRESS") and lid != name:
                pending.setdefault(lid, time.time())
            else:
                pending.pop(lid, None)
            line = f"{e['LogicalResourceId']}: {e['ResourceStatus']}"
            if "FAILED" in e["ResourceStatus"] and e.get("ResourceStatusReason"):
                line += f" ({e['ResourceStatusReason'][:200]})"
                failures.append(line)
            if progress:
                progress(line)

    while True:
        drain()
        now = time.time()
        if progress and pending and now - last_new > 120 and now - last_note > 60:
            last_note = now
            waits = ", ".join(f"{k} ({int((now - v) // 60)} min)" for k, v in sorted(pending.items(), key=lambda x: x[1]))
            hint = (" The seed function times out after 5 minutes." if "SeedData" in pending else
                    " NAT gateways, VPC endpoints and EC2 instances often take 3-5 minutes." if
                    pending.keys() & {"NatGw", "QuickWebsiteEndpoint", "AppConnector"} else "")
            progress(f"Still waiting on: {waits}.{hint}")
        st = stack(sess, name)
        if st is None or st["status"] in TERMINAL_OK | TERMINAL_BAD:
            drain()   # the final events (including failure reasons) can land in the same poll as the status
        if st is None:
            if deleting:
                return {"status": "DELETE_COMPLETE"}
            if failures or time.time() - t0 > 20:   # a failed create was rolled back and deleted (OnFailure=DELETE)
                raise AwsError("The stack failed to create and was removed. " + ("; ".join(failures[:3]) or
                               "See the CloudFormation console's deleted stacks for details."))
        if st and st["status"] in TERMINAL_OK:
            return st
        if st and st["status"] in TERMINAL_BAD:
            raise AwsError(f"Stack {st['status']}. " + ("; ".join(failures[:3]) or st.get("reason", "")))
        if time.time() - t0 > timeout:
            raise AwsError(f"Still {st and st['status']} after {timeout // 60} minutes; check the CloudFormation console.")
        time.sleep(poll)


def deploy(sess, name: str, template: str, params: dict, progress=None) -> dict:
    """Create the stack, or update it if it exists. params: {ParameterKey: value}; empty values are skipped."""
    cf = sess.client("cloudformation")
    p = [{"ParameterKey": k, "ParameterValue": str(v)} for k, v in params.items() if v not in (None, "")]
    common = dict(StackName=name, TemplateBody=template, Parameters=p, Capabilities=["CAPABILITY_IAM"],
                  Tags=[{"Key": "Purpose", "Value": "zscaler-quick-demo"}])
    since = time.time() - 5
    sid = ""
    existing = stack(sess, name)
    try:
        if existing and existing["status"] == "ROLLBACK_COMPLETE":
            raise AwsError(f"Stack {name} is in ROLLBACK_COMPLETE from a failed create. Delete it, then deploy again.")
        if existing and existing["status"].endswith("_IN_PROGRESS"):
            raise AwsError(f"Stack {name} is busy ({existing['status']}). Wait for it to finish.")
        if existing:
            if progress:
                progress(f"Updating stack {name}…")
            try:
                cf.update_stack(**common)
            except Exception as e:
                if "No updates are to be performed" in str(e):
                    if progress:
                        progress("No changes: the stack already matches.")
                    return existing
                raise
        else:
            if progress:
                progress(f"Creating stack {name}…")
            sid = cf.create_stack(**common, OnFailure="DELETE").get("StackId", "")   # failed creates clean up
    except AwsError:
        raise
    except Exception as e:
        raise AwsError(explain(e))
    return wait(sess, name, since, progress, stack_id=sid or (existing or {}).get("id", ""))


def delete(sess, name: str, progress=None) -> dict:
    cf = sess.client("cloudformation")
    existing = stack(sess, name)
    if not existing:
        return {"status": "DELETE_COMPLETE", "note": "No such stack."}
    since = time.time() - 5
    try:
        cf.delete_stack(StackName=name)
    except Exception as e:
        raise AwsError(explain(e))
    if progress:
        progress(f"Deleting stack {name} (the bucket is emptied first)…")
    return wait(sess, name, since, progress, deleting=True, stack_id=existing["id"])
