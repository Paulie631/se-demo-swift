# Changelog

## 0.4.4
- **Wire it to Amazon Quick** checklist on the AWS tab: step-by-step console instructions (bucket access, S3 knowledge base, MCP connector, optional ZPA, smoke-test prompts, cleanup) with your stack's bucket, S3 URL and MCP URL filled in and copy buttons. Ticks are saved in the browser.

## 0.4.3
- Corrected the Quick wiring steps: Quick's MCP integration supports OAuth or No authentication, not custom headers, so deploy without an MCP token when Quick connects.

## 0.4.2
- **Fix: the AWS stack hung on SeedData and then couldn't be deleted.** The seed function relied on CloudFormation's `cfnresponse` helper, which CloudFormation only adds when it spots a plain `import cfnresponse` line, and ours was a combined import, so the function crashed before it could answer. It now answers CloudFormation itself, and a delete always succeeds even if emptying the bucket fails.

## 0.4.1
- If the seed function never answers CloudFormation, the stack now fails after 5 minutes instead of hanging for an hour.
- While a deploy is waiting, the progress pane names the resource it's stuck on and for how long.

## 0.4.0
- **Deploy the AWS stack from the console:** Deploy stack / Delete stack with an AWS CLI profile or access keys, live progress, outputs filled in (the MCP check picks up the URL). A failed create cleans itself up and shows the reason.
- `./quick-kit aws deploy|status|delete` on the command line.
- The template no longer contains test card numbers, example keys or SSNs verbatim (they're assembled at runtime), so sending it through an inspecting proxy doesn't trip DLP.

## 0.3.0
- **Update button** in the console header: checks GitHub for a newer version, shows what's new, updates and restarts the console. A git clone updates with `git pull`; other copies are backed up first and can be rolled back.
- `./quick-kit update` (`--check`, `--rollback`) on the command line.

## 0.2.1
- API calls retry brief network trouble (DNS lookups failing while Client Connector or Wi-Fi reconnects, resets, timeouts, rate limits). If it keeps failing, you get a plain message that nothing was changed.

## 0.2.0
- **SSL inspection rule** for the Quick category (decrypt), so DLP can see prompts without a manual step.
- **Test user:** use an existing ZIA user or create one (Hosted DB tenants); every demo rule is scoped to it.
- **ZPA panel:** segment group, server group, application segment and a Client Connector access rule for the AWS stack's PrivateLink path.
- Rule names fit ZIA's 31-character limit.

## 0.1.x
- Browser console: Setup, Guided demo (six acts), Traffic, AWS environment, Logs.
- Send traffic from a **CloudShare VM** instead of a corporate laptop.
- AWS CloudFormation environment: synthetic data bucket, deliberately vulnerable MCP server, optional ZPA path.
