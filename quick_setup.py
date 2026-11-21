"""Set up the Amazon Quick side of the demo through the Quick (QuickSight) API.

  1. Data source  S3_KNOWLEDGE_BASE on the stack's bucket, read through the stack's QuickKbRole (so no console
                  "Permissions > AWS resources" step is needed)
  2. Knowledge base on that data source, owned by the Quick user you pick; waits for the first sync
  3. Space        "Amazon Quick demo" containing the knowledge base (optional)

Not available through the API (as of botocore 1.44): MCP action connectors (CreateActionConnector has no MCP type),
so that one step stays in the Quick console. Creating the Quick account itself is left to the console on purpose:
it starts a paid subscription after the trial.

Shapes follow botocore's quicksight service model: KnowledgeBaseConfiguration.templateConfiguration.template is a
JSON document {"type": "S3V2", "connectionConfiguration": {"bucketName", "bucketOwnerAccountId"}}.
"""
from __future__ import annotations

import time

DS_OWNER_ACTIONS = ["quicksight:DescribeDataSource", "quicksight:DescribeDataSourcePermissions",
                    "quicksight:PassDataSource", "quicksight:UpdateDataSource", "quicksight:DeleteDataSource",
                    "quicksight:UpdateDataSourcePermissions"]
SPACE_OWNER_ACTIONS = ["quicksight:DescribeSpace", "quicksight:DescribeSpacePermissions", "quicksight:UpdateSpace",
                       "quicksight:UpdateSpacePermissions", "quicksight:UpdateSpaceResources",
                       "quicksight:ListSpaceResources", "quicksight:DeleteSpace"]
NEEDED = ("create_knowledge_base", "describe_knowledge_base", "create_space", "update_space_resources")


class QuickError(Exception):
    pass


def ids(project: str) -> dict:
    return {"ds": f"{project}-s3", "kb": f"{project}-kb", "space": f"{project}-space"}


def _qs(sess):
    c = sess.client("quicksight")
    missing = [n for n in NEEDED if not hasattr(c, n)]
    if missing:
        raise QuickError("This boto3 is too old for the Quick knowledge base APIs. Restart the kit with ./quick-kit "
                         "(uv installs a current boto3) or pip install -U boto3.")
    return c


def _nf(e) -> bool:
    return "ResourceNotFound" in type(e).__name__ or "ResourceNotFoundException" in str(e)


def _explain(e) -> str:
    s = str(e)
    if "AccessDenied" in s:
        return f"Quick denied the call: {s[:240]}. The AWS identity needs quicksight:* rights (an admin role is fine)."
    if "UnsupportedUserEdition" in s or ("Enterprise" in s and "edition" in s.lower()):
        return "This needs a Quick Enterprise account."
    if "ResourceExists" in s:
        return "Already exists."
    return s[:400]


def account(sess, acct: str) -> dict | None:
    try:
        i = sess.client("quicksight").describe_account_subscription(AwsAccountId=acct)["AccountInfo"]
    except Exception as e:
        if _nf(e):
            return None
        raise QuickError(_explain(e))
    return {"name": i.get("AccountName"), "edition": i.get("Edition"), "status": i.get("AccountSubscriptionStatus"),
            "auth": i.get("AuthenticationType")}


def users(sess, acct: str) -> list[dict]:
    c = sess.client("quicksight")
    out, tok = [], None
    try:
        while True:
            kw = {"AwsAccountId": acct, "Namespace": "default", "MaxResults": 100}
            if tok:
                kw["NextToken"] = tok
            r = c.list_users(**kw)
            out += [{"arn": u["Arn"], "name": u["UserName"], "email": u.get("Email", ""), "role": u.get("Role", "")}
                    for u in r.get("UserList", []) if u.get("Active", True)]
            tok = r.get("NextToken")
            if not tok:
                break
    except Exception as e:
        raise QuickError(_explain(e))
    order = {"ADMIN": 0, "ADMIN_PRO": 0, "AUTHOR": 1, "AUTHOR_PRO": 1}
    return sorted(out, key=lambda u: (order.get(u["role"], 2), u["name"].lower()))


def status(sess, acct: str, project: str) -> dict:
    c = _qs(sess)
    i = ids(project)
    st = {"data_source": None, "knowledge_base": None, "space": None}
    try:
        d = c.describe_data_source(AwsAccountId=acct, DataSourceId=i["ds"])["DataSource"]
        st["data_source"] = {"status": d.get("Status"), "arn": d.get("Arn"),
                             "error": (d.get("ErrorInfo") or {}).get("Message", "")}
    except Exception as e:
        if not _nf(e):
            raise QuickError(_explain(e))
    try:
        k = c.describe_knowledge_base(AwsAccountId=acct, KnowledgeBaseId=i["kb"])["KnowledgeBase"]
        last = k.get("LatestIngestionSummary") or {}
        st["knowledge_base"] = {"status": k.get("Status"), "arn": k.get("KnowledgeBaseArn"), "docs": k.get("DocumentCount"),
                                "owner": k.get("PrimaryOwnerUsername"), "ingestion": last}
    except Exception as e:
        if not _nf(e):
            raise QuickError(_explain(e))
    try:
        s = c.describe_space(AwsAccountId=acct, SpaceId=i["space"])
        st["space"] = {"arn": s.get("spaceArn"), "resources": len((s.get("Space") or {}).get("resources") or [])}
    except Exception as e:
        if not _nf(e):
            raise QuickError(_explain(e))
    return st


def setup(sess, acct: str, project: str, bucket: str, role_arn: str, owner_arn: str, space: bool = True,
          progress=print, timeout: int = 1200) -> dict:
    if not bucket:
        raise QuickError("Deploy the AWS stack first (the knowledge base reads its bucket).")
    if not owner_arn:
        raise QuickError("Pick the Quick user who will own the knowledge base (the one you demo as).")
    c = _qs(sess)
    i = ids(project)

    # 1. data source
    try:
        ds = c.describe_data_source(AwsAccountId=acct, DataSourceId=i["ds"])["DataSource"]
        progress(f"Data source {i['ds']} exists ({ds.get('Status')})")
    except Exception as e:
        if not _nf(e):
            raise QuickError(_explain(e))
        params = {"BucketUrl": f"s3://{bucket}/"}
        if role_arn:
            params["RoleArn"] = role_arn
        try:
            c.create_data_source(AwsAccountId=acct, DataSourceId=i["ds"], Name="Demo company files (S3)",
                                 Type="S3_KNOWLEDGE_BASE", DataSourceParameters={"S3KnowledgeBaseParameters": params},
                                 Permissions=[{"Principal": owner_arn, "Actions": DS_OWNER_ACTIONS}],
                                 Tags=[{"Key": "Purpose", "Value": "zscaler-quick-demo"}])
        except Exception as e2:
            raise QuickError("Creating the S3 data source failed: " + _explain(e2))
        progress(f"Creating data source {i['ds']} on s3://{bucket}/" + (" (via the stack's QuickKbRole)" if role_arn else ""))
    t0 = time.time()
    while True:
        ds = c.describe_data_source(AwsAccountId=acct, DataSourceId=i["ds"])["DataSource"]
        if ds["Status"] in ("CREATION_SUCCESSFUL", "UPDATE_SUCCESSFUL"):
            break
        if ds["Status"] in ("CREATION_FAILED", "UPDATE_FAILED"):
            raise QuickError(f"Data source failed: {(ds.get('ErrorInfo') or {}).get('Message', ds['Status'])}. If it's "
                             "an access error, check the stack has QuickKbRole (redeploy with v0.5+) or grant Quick the "
                             "bucket under Permissions > AWS resources.")
        if time.time() - t0 > 300:
            raise QuickError("The data source is still creating after 5 minutes; check it in the Quick console.")
        time.sleep(5)
    ds_arn = ds["Arn"]

    # 2. knowledge base
    try:
        kb = c.describe_knowledge_base(AwsAccountId=acct, KnowledgeBaseId=i["kb"])["KnowledgeBase"]
        progress(f"Knowledge base {i['kb']} exists ({kb.get('Status')})")
    except Exception as e:
        if not _nf(e):
            raise QuickError(_explain(e))
        try:
            c.create_knowledge_base(
                AwsAccountId=acct, KnowledgeBaseId=i["kb"], Name="Demo company files",
                Description="Synthetic sensitive data for the Zscaler x Amazon Quick demo",
                DataSourceArn=ds_arn, PrimaryOwnerArn=owner_arn,
                KnowledgeBaseConfiguration={"templateConfiguration": {"template": {
                    "type": "S3V2", "connectionConfiguration": {"bucketName": bucket, "bucketOwnerAccountId": acct}}}},
                Tags=[{"Key": "Purpose", "Value": "zscaler-quick-demo"}])
        except Exception as e2:
            raise QuickError("Creating the knowledge base failed: " + _explain(e2))
        progress("Creating knowledge base 'Demo company files'; the first sync starts automatically")
    t0, last = time.time(), ""
    while True:
        kb = c.describe_knowledge_base(AwsAccountId=acct, KnowledgeBaseId=i["kb"])["KnowledgeBase"]
        ing = kb.get("LatestIngestionSummary") or {}
        line = f"Knowledge base: {kb.get('Status')}" + (f", {kb['DocumentCount']} documents" if kb.get("DocumentCount") else "") \
            + (f", sync {ing.get('Status') or ing.get('status')}" if ing else "")
        if line != last:
            progress(line)
            last = line
        if kb.get("Status") == "FAILED":
            raise QuickError("The knowledge base failed. Open it in the Quick console for the ingestion error.")
        if kb.get("Status") == "ACTIVE" and kb.get("DocumentCount"):
            break
        if kb.get("Status") == "ACTIVE" and time.time() - t0 > 120:
            progress("Knowledge base is active; the sync may still be running (check the document count in Quick).")
            break
        if time.time() - t0 > timeout:
            raise QuickError(f"Still {kb.get('Status')} after {timeout // 60} minutes; check it in the Quick console.")
        time.sleep(10)
    kb_arn = kb["KnowledgeBaseArn"]

    # 3. space
    sp = None
    if space:
        try:
            sp = c.describe_space(AwsAccountId=acct, SpaceId=i["space"])
            progress(f"Space {i['space']} exists")
            arn = sp.get("spaceArn")
        except Exception as e:
            if not _nf(e):
                raise QuickError(_explain(e))
            arn = c.create_space(AwsAccountId=acct, SpaceId=i["space"], Name="Amazon Quick demo",
                                 Description="Zscaler demo: synthetic company files")["spaceArn"]
            progress("Created space 'Amazon Quick demo'")
        have = {r.get("resourceArn") or (r.get("ResourceDetails") or {}).get("resourceArn")
                for r in ((sp or {}).get("Space") or {}).get("resources") or [] if isinstance(r, dict)}
        if kb_arn not in have:
            try:
                c.update_space_resources(AwsAccountId=acct, SpaceId=i["space"], AddResources=[
                    {"ResourceType": "KNOWLEDGE_BASE", "ResourceDetails": {"resourceArn": kb_arn}}])
                progress("Added the knowledge base to the space")
            except Exception as e:
                progress(f"Couldn't add the knowledge base to the space ({_explain(e)}); add it in the Quick console.")
        try:
            c.update_space_permissions(AwsAccountId=acct, SpaceId=i["space"],
                                       GrantPermissions=[{"Principal": owner_arn, "Actions": SPACE_OWNER_ACTIONS}])
            progress("Shared the space with your Quick user")
        except Exception as e:
            progress(f"Couldn't share the space with your user ({_explain(e)}); share it in the Quick console if "
                     "you don't see it.")
        sp = {"arn": arn}
    return {"data_source": ds_arn, "knowledge_base": kb_arn, "space": sp, "documents": kb.get("DocumentCount")}


def teardown(sess, acct: str, project: str, progress=print) -> None:
    c = _qs(sess)
    i = ids(project)
    for what, fn, kw in (("space", "delete_space", {"SpaceId": i["space"]}),
                         ("knowledge base", "delete_knowledge_base", {"KnowledgeBaseId": i["kb"]}),
                         ("data source", "delete_data_source", {"DataSourceId": i["ds"]})):
        try:
            getattr(c, fn)(AwsAccountId=acct, **kw)
            progress(f"Deleted the {what}")
        except Exception as e:
            if _nf(e):
                progress(f"No {what} to delete")
            else:
                progress(f"Couldn't delete the {what}: {_explain(e)}")
        if what == "knowledge base":
            for _ in range(30):   # the data source can't go while its knowledge base is still deleting
                try:
                    c.describe_knowledge_base(AwsAccountId=acct, KnowledgeBaseId=i["kb"])
                    time.sleep(5)
                except Exception:
                    break
