# Maintenance service: checks and recovery

This reference is for ongoing maintenance of the shared GitHub App and Cloudflare
service. Repository maintainers install the shared App; they do not host it.

The receiver verifies signed webhook deliveries and reads canonical repository
metadata with a Contents-read token restricted to one repository. Check actions,
dispatch, storage and dependency repairs belong to later slices.

## Check the receiver locally

Use Node 24 and run these commands from `repair-app/`:

```sh
npm ci --ignore-scripts --no-fund
npm test
npm run test:runtime
npm run check
```

The unit suite reports coverage for the receiver. The runtime test executes it
in local Cloudflare Workers with synthetic credentials and intercepted GitHub
requests. The final command bundles the preview with `--dry-run`; it does not
deploy. The CI job runs the same checks without App or Cloudflare credentials.

## Stop deliveries or recover

Disable the App webhook or uninstall the affected installation to stop new
deliveries. Restore a previous approved Worker version when one exists. This
receiver slice has no request database, dispatched runs or repository writes.

Webhook processing shares an eight-second budget across input and GitHub reads.
Timed-out requests fail without an automatic retry. After recovery, redeliver
failed deliveries through the GitHub App's webhook delivery controls.

Keep App credentials in operator storage and Worker secrets. Keep verification
receipts outside the repository, without credentials or webhook payloads. A
local test or dry-run bundle does not replace live delivery evidence.
