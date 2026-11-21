# Changelog

## 0.6.0
- **ZPA, fully automatic (phase 1):** the ZPA panel's connector group now defaults to **Create one for me**. The kit creates the "Amazon Quick (Demo) connectors" App Connector group (located near your Quick region, tied to the Connector enrollment certificate) and a provisioning key (max 5 uses), then the segment group, server group, application and access rule as before.
- **AWS deploy with the ZPA path needs no copy and paste:** leave the provisioning key and AMI blank. The kit creates or reuses the key in ZPA and passes it to CloudFormation as a hidden parameter (never saved), and finds the newest Zscaler App Connector AMI in the region. If AWS says OptInRequired, subscribe to Zscaler App Connector in AWS Marketplace once.
- ZPA teardown also removes the kit's provisioning key, any connectors enrolled in its group, and the group itself. Groups you made yourself are never touched.

## 0.5.5
- **Simpler ZIA policy panel:** choose "Everyone in this tenant" or "One test user" (one email box and **Save user**, which uses the user if it exists or offers to create it), then one **Set up ZIA policy** button. Status shows automatically as ticks; SSL option, Preview and raw output moved under Advanced.

## 0.5.4
- CloudShare: pasted API IDs and keys are trimmed (a stray space or line break breaks the signature), and "HMAC doesn't match" now says plainly that the key doesn't match the API ID and how to fix it. (Signing verified identical to CloudShare's official SDK.)

## 0.5.3
- The update check sees a new version immediately. Git checkouts check with `git fetch`; other copies use GitHub's API before the file server, which caches files for about 5 minutes and could report "up to date" right after a release.

## 0.5.2
- Fix: **Check Quick** failed with "Object of type datetime is not JSON serializable" once a knowledge base had synced (AWS returns timestamps). All console responses now handle them.

## 0.5.1
- Sharing the demo Space with your Quick user now drops any permission Quick rejects (it rejected `UpdateSpaceResources`) and retries, instead of giving up.
- The knowledge base progress shows the real sync status (queued, running, completed) and waits for the first sync to finish.

## 0.5.0
- **Automatic Amazon Quick setup** (AWS tab › Wire it to Amazon Quick › Check Quick / Set up knowledge base): through the Quick API the kit creates the S3 data source, the knowledge base (owned by the Quick user you pick, waits for the first sync) and a demo Space containing it. **Remove** deletes them; **Delete stack** removes them first.
- The stack now includes **QuickKbRole**, which Quick assumes to read the bucket, so the console's Permissions › AWS resources step isn't needed. Redeploy (Deploy stack updates in place) to add it.
- Still manual: the MCP connector (the Quick API has no MCP connector type yet) and creating the Quick account itself (it's a paid subscription after the trial).
- `./quick-kit aws quick-setup | quick-teardown` on the command line.

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
