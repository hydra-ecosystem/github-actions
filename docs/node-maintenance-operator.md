# Maintenance service: checks and recovery

This reference is for ongoing maintenance of the shared GitHub App and Cloudflare
service. Repository maintainers install the shared App; they do not host it.

The receiver verifies signed webhook deliveries and reads canonical repository
metadata with a token restricted to one repository. For managed PRs it also
reads the canonical PR and displays the selected package versions in the App's
**Dependency repair** Check. A maintainer can request one harmless pilot run
through its native action. D1 retains the active request and returned Actions run
identity. Dependency repairs and completion handling belong to later slices.

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
number, head and base. With D1 configured, a nonempty valid batch shows
**Run selected fixes**. Checkbox edits do not start a run. PR-event tokens grant
only Contents read, Pull requests read and Checks write. Action-event tokens
also grant Actions write, restricted to the same repository. The service never
updates another App's Check.

## Request the selected batch

Review the exact versions in the Check summary, then click **Run selected fixes**.
The service reads current write, maintain or admin permission and verifies the
canonical PR and Check again. A stale selection or head refreshes the Check and
requires another click; it starts no run.

The request UUID is the signed GitHub delivery ID. A single D1 insert reserves
one active request per installation, repository and PR before dispatch. Replayed
deliveries and competing clicks cannot admit another active request. The Check
loses its action and retains the request identity across PR edits. A new head can
have its own selection Check, but the existing PR lock still blocks dispatch.

Only `.github/workflows/dependency-repair.yml` on the current default branch is
dispatched, with the five C2 inputs. The API must return HTTP 200 with the exact
run ID and matching repository URLs. The known run link is saved in D1 and shown
in the Check. The fixture in `repair-app/pilot/` validates those inputs without
checking out code or changing dependency files. A successful pilot does not mean
a dependency repair was published.

## Check the receiver locally

Use Node 24 and run these commands from `repair-app/`:

```sh
npm ci --ignore-scripts --no-fund
npm test
npm run test:runtime
npm run check
```

The unit suite reports coverage for the receiver, selection parser and Check
updates, action authorization, fixed dispatch and request-state failures.
`selection-fixtures.json` holds the shared C1 cases and expected
fingerprints. The runtime test executes the receiver
in local Cloudflare Workers with synthetic credentials and intercepted GitHub
requests and an actual local D1 binding for concurrency and replay checks.
The final command bundles the preview with `--dry-run`; it does not
deploy. The CI job runs the same checks without App or Cloudflare credentials.

## Stop deliveries or recover

Disable the App webhook or uninstall the affected installation to stop new
deliveries. Restore a previous approved Worker version when one exists. This
service does not cancel an already dispatched Actions run; cancel it separately.
Restoring Worker code does not roll back the D1 database.

Webhook processing shares an eight-second budget across input and GitHub reads.
Timed-out requests fail without an automatic dispatch retry. Before a reservation
exists, a failed delivery can be redelivered after recovery. After reservation,
inspect the request record and Actions first:

- `reserved`: a crash or Check update failure may have interrupted the attempt.
- `unknown`: the dispatch response was lost, invalid or unexpected. A run may exist.
- `dispatched`: the exact returned run ID and URLs are retained.

Active locks never expire automatically. Replaying the same delivery never
repeats its dispatch POST. Do not delete an ambiguous row or start another attempt
until an operator proves no run remains active and reconciles any observed run
with the exact request inputs, repository, workflow and actor.

Completion updates and releasing finished requests arrive in slice 4. Until then,
even a finished harmless pilot keeps its active lock. Do not describe its
in-progress Check as proof that Actions is still running.

Keep App credentials in operator storage and Worker secrets. Keep verification
receipts outside the repository, without credentials or webhook payloads. A
local test or dry-run bundle does not replace live delivery evidence.
