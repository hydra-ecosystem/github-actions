# Maintenance service: checks and recovery

This reference is for ongoing maintenance of the shared GitHub App and Cloudflare
service. Repository maintainers install the shared App; they do not host it.

The receiver verifies signed webhook deliveries and reads canonical repository
metadata with a token restricted to one repository. For managed PRs it also
reads the canonical PR and displays the selected package versions in the App's
**Dependency repair** Check. Check actions, dispatch, storage and dependency
repairs belong to later slices.

## Check the selected batch

The PR must be open, bot-authored, from `maintenance/node-security` in the same
repository, and target its current default branch. Its description contains one
selection block:

```markdown
<!-- node-repair:selection:v1 -->
- [x] Allow `launch-editor` `2.14.1 → 2.14.2` by updating its explicit pin.
<!-- /node-repair:selection -->
```

Select at most 20 distinct packages. Each change must increase the patch version
within the same major and minor. Unchecked rows must also be valid and unique.
Malformed or missing selections produce a Check that asks for attention.

Editing selections or changing the PR head refreshes the Check from canonical
GitHub data. The Check displays the exact selected versions, bound to the PR
number, head and base. It has no Run button in this slice. Checkbox edits do not
start a run. The token grants only Contents read, Pull requests read and Checks
write; the service never updates another App's Check.

## Check the receiver locally

Use Node 24 and run these commands from `repair-app/`:

```sh
npm ci --ignore-scripts --no-fund
npm test
npm run test:runtime
npm run check
```

The unit suite reports coverage for the receiver, selection parser and Check
updates. `selection-fixtures.json` holds the shared C1 cases and expected
fingerprints. The runtime test executes the receiver
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
