# Maintenance service: checks and recovery

This reference is for ongoing maintenance of the shared GitHub App and Cloudflare
service. Repository maintainers install the shared App; they do not host it.

The receiver verifies signed webhook deliveries and reads canonical repository
metadata with a token restricted to one repository. For managed PRs it also
reads the canonical PR and displays the selected package versions in the App's
**Dependency repair** Check. A maintainer can select fixes in the PR description
and post `/repair selected` in the Conversation tab. The App replies there with
the request status and exact Actions link. The native Check action remains an
optional secondary entry point. D1 retains the active request and returned Actions run
identity. Completed runs update that same reply and release their own request
lock. The current workflow remains a harmless fixture; dependency repairs belong
to later slices.

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

## Request the selected batch from the PR conversation

The report includes the head and base revisions in one hidden line outside the
selection block (replace these illustrative hashes with the exact PR revisions):

```markdown
<!-- node-repair:revision:v1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb -->
```

Tick the allowed fixes in the PR description, then post a new comment containing
only `/repair selected`. Use GitHub's normal **Comment** button to submit it.
Neither ticking a checkbox nor editing an existing comment starts an attempt.
There is no need to visit Checks. Request status appears in an App-owned reply;
supporting Check details remain available separately.

The receiver accepts only a newly created human comment on a managed PR. It
re-fetches the comment and verifies its author, exact body, PR association and
unchanged creation/update timestamps. It checks current maintainer permission,
the selections captured in the signed comment event, the report's head/base
binding, and the current canonical PR/Check fingerprint. A stale report or
selection starts no run and produces a reply asking for a fresh command.
Unrelated comments and edits are ignored. Missing or edited/deleted commands
and unmanaged PRs do not authorize an attempt.

For this unreleased integration, reports/pilot descriptions must include the
revision line. Existing reports without it cannot authorize comment dispatch.
The production report renderer is still a later slice; it is not deployed.

### Existing Check action

Review the exact versions in the Check summary, then click **Run selected fixes**.
The service reads current write, maintain or admin permission and verifies the
canonical PR and Check again. A stale selection or head refreshes the Check and
requires another click; it starts no run.

### Shared admission and recovery

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

Comment requests additionally retain the source comment ID, reply ID and exact
selections. A unique source-comment index prevents the same comment from
authorizing a second attempt, even under a different delivery UUID. Only the
winning reservation creates a status reply. Its ID is saved before dispatch;
a lost reply POST or failed save retains the lock and starts no run. Replays,
losing admissions and PR refreshes do not repaint request output or retry an
ambiguous reply POST. Exposed idle Checks are reused without PATCHing them,
or a fresh idle Check is created. Admission still validates current selections
and revisions; an older idle control cannot authorize a stale batch.

The control Check stays completed/neutral while its text changes. Real GitHub
did not reopen the previously completed Check when asked for `in_progress`.
The pending text stays **Request accepted**, with a workflow-page link, until
verified completion. No request-status writes occur after dispatch except
completion updates using the immutable verified outcome. An uncertain pending
write prevents dispatch and retains the reservation for operator recovery. The reply
says **Workflow succeeded**, **Workflow failed** or **Workflow cancelled** and
retains the exact run link and selected versions. The dependency report is not
rewritten: harmless success does not turn “needs review” into “upgraded”.

## Enable comment delivery after review

This change is local and unreleased. Before testing the reviewed revision live:

1. Add **Issues: read** and change **Pull requests** to **read/write** on the App.
   Subscribe to **Issue comment** events. Existing installations must accept the
   new permissions. Keep Contents read, Checks write and Actions write.
2. For an existing slice-3 database, apply
   `repair-app/migrations/0001_comment_requests.sql` exactly once. It preserves
   all existing request rows and active locks. New databases use `schema.sql`
   instead; do not apply both initial schema and migration to one database.
3. Deploy the reviewed Worker. Put the correct revision marker and selections
   in the pilot description, then verify a real command, exact inputs, reply
   link, replay and stale-command rejection against the harmless fixture.

No live permission, database, deployment or repository change is performed by
these instructions. The local/native tests cannot replace that acceptance.

## Candidate preparation boundary

The reusable `.github/workflows/node-repair.yml` enables `guard`, `prepare`
and `validate`. It accepts the existing five request inputs and returns
`candidate-artifact-id` for the immutable artifact created in that run.
It does not install a caller or enable repairs in an existing repository.

The read-only guard fetches the canonical repository and managed PR again.
It checks bot authorship, the same repository, maintenance branch, default
branch, exact head/base, revision marker and selected versions. It does not
require the old idle Check identity after the App has admitted the request.

Preparation checks out only the expected head without persisted credentials.
It uses the configured toolchain, existing audit engine, release cooldown and
parent/direct constraint evidence. Lifecycle and local/global pnpmfile hooks
are disabled during metadata reads, audit and lockfile-only resolution.
Unselected versions, unrelated lockfile metadata and changed peer suffixes
fail preparation. No project validation script runs in this job.

The preparation artifact contains exactly three regular files:

- `candidate.patch`: only the selected project's `pnpm-workspace.yaml` and
  `pnpm-lock.yaml` changes, exported with external diff and text conversion off.
- `audit.json`: a version-1 envelope containing the exact request, normalized
  project directory, structured before audit and candidate audit.
- `result.md`: the shared package report. It states that project validation and
  dependency publication have not run.

The envelope rejects missing/extra fields, mismatched request or project,
unsupported versions, symlinked project parents, unconfirmed selected fixes and
new findings. Later consumers must download by the returned artifact ID from
the same run. A preparation success is not proof of a validated or published
repair.

Validation checks out the same expected head on a separate read-only runner,
without persisted Git credentials or App credentials. It downloads only the
preparation artifact ID from the current run. It rejects extra members and
unapproved patch paths or file modes before applying the candidate. Frozen
installation and the configured `validationScript` run against that candidate;
include any project-specific local-patch tests in this script. Changes to
dependency files or configuration fail validation. A fresh audit must confirm
all selected advisories are removed and no new finding is present.

The separate `node-repair-validation-<request-id>` artifact contains human
evidence only: install/check logs, the fresh audit and a validation result.
It never replaces the preparation artifact. Project code runs with the
repository write maintainer as its trust principal; validation cannot attest
intentionally dishonest tests. A later publisher must use the original
preparation artifact and actual validation job success, never validation-local
patches, reports or logs. Publication and normal-audit retention remain later
slices, followed by the isolated live repair gate and general rollout.

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

For a known run, redeliver its `workflow_run.completed` event after correcting
an output-update failure. The service fetches the canonical run and checks the
saved installation, repository, run ID, workflow path, dispatch event, original
dispatched branch and App actor. It never searches by run title. An early event
that arrives before the run ID is saved can be redelivered afterward.

The service saves the verified conclusion and completion time before updating
the recorded App-owned reply and request Check. These fields can be populated
while the state is still active. A transient GitHub failure retains that lock;
redelivery retries safe output updates without dispatching or posting another
reply. Conflicting conclusions require inspection. A missing or replaced old
reply/Check is not overwritten or recreated; the verified run can still finish
its own record. A new PR head's Check is left alone.

After safe output updates, state becomes `success`, `failure` or `cancelled`.
Other unsuccessful GitHub conclusions map to `failure` and retain the exact
conclusion. The request Check stays neutral and request-bound. A separate idle
Check exposes the current selection action when the same PR head is eligible.
A later deliberate command can start a fresh attempt without manual SQL recovery.
Duplicate completion does not dispatch or create another conversation reply.

The daily Cron Trigger runs at 03:17 UTC and deletes terminal records older
than 90 days. It never expires active or unknown requests, including those with
a saved outcome awaiting output recovery. Retention bounds replay history;
it does not promise permanent deduplication after a record is deleted.

Keep App credentials in operator storage and Worker secrets. Keep verification
receipts outside the repository, without credentials or webhook payloads. A
local test or dry-run bundle does not replace live delivery evidence.
