# Changelog

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
