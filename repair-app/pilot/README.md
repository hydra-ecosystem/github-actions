# Harmless infrastructure fixture

For the approved pilot, copy `dependency-repair.yml` to
`.github/workflows/dependency-repair.yml` on the repository's default branch.
Review that concrete change before merging it. This fixture is the service's
fixed dispatch target; there is no alternate dispatch endpoint or pilot mode.

The five C2 inputs are validated and retained in the Actions job summary.
The workflow checks out no code, uses read-only permissions and changes no
repository files. A successful run proves input delivery, not dependency repair.

For controlled completion probes, select the synthetic package `pilot-failure`
to fail after writing the receipt. Select `pilot-cancellation` to wait for two
minutes so an operator can cancel the run. Use any increasing stable same-minor
patch pair. These probes belong only to this installation fixture.

Slice 3 proves admission, replay rejection and one returned run ID. Completion
handling updates the existing App reply and request Check from that canonical
run. Success, failure and cancellation release only their own request lock after
safe output updates. The reply explicitly states that this fixture performs no
dependency repair. The package report remains unchanged.

To verify completion, retain one real signed `workflow_run.completed` delivery
for each outcome, its known run ID, request state and existing reply URL. Redeliver
one completion to prove idempotence. Start a fresh deliberate command after
completion to prove admission without manual SQL recovery. A transient output
failure must retain the active lock and saved conclusion until redelivery.
Restore the original PR description after temporary probe selections, checking
that no concurrent edit would be overwritten. Record actual source/deployment
identities and distinguish local intercepted API tests from real GitHub events.

## Isolated candidate preparation, validation and publication acceptance

After reviewing the preparation, validation and publisher slices and completing
their required checks, use an explicitly authorized isolated repository. Replace its existing harmless caller's job with a call to the
reviewed reusable workflow. Keep the default-branch workflow path
`.github/workflows/dependency-repair.yml` and its five dispatch inputs unchanged.
Do not replace Hydra's harmless caller or roll this out to other installations
as part of this gate.

Use the actual reviewed reference in place of `REVIEWED_REF`. For repeated
experimentation, use a dedicated experimentation tag whose updates are reviewed.

```yaml
jobs:
  candidate:
    permissions:
      contents: write
      pull-requests: write
      actions: read
      checks: read
    uses: hydra-ecosystem/github-actions/.github/workflows/node-repair.yml@REVIEWED_REF
    with:
      request-id: ${{ inputs.request-id }}
      pull-request: ${{ inputs.pull-request }}
      expected-head: ${{ inputs.expected-head }}
      expected-base: ${{ inputs.expected-base }}
      selections: ${{ inputs.selections }}
```

Retain the exact caller and reusable-workflow revisions, the bot-authored managed
PR's head/base, selected batch, Actions run and immutable candidate artifact ID.
Inspect the downloaded artifact for exactly `candidate.patch`, `audit.json` and
`result.md`. Verify request/project binding, allowed patch paths, unchanged
unselected dependencies and a truthful preparation-only report. Record that producer upload precedes validation and publication and that no
project scripts run on the producer or publisher.
Stale consent and unavailable evidence must fail without a candidate artifact.

Validation runs on a separate read-only runner after preparation. Record a
successful frozen install and configured project/local-patch checks, followed
by a fresh audit with all selected advisories removed and no new finding.
Use a deliberately failing check or dependency-file mutation to prove rejection
without changes to the PR. Keep those test changes in the isolated repository.

Also exercise project code that changes the validation runner's downloaded
`candidate.patch` or `result.md`. Download the original preparation artifact by
its retained ID again and prove its bytes did not change. The validation
artifact is human evidence only; its files cannot become publication inputs.
Keep both artifact IDs and their separate contents in the acceptance record.

These preparation/validation checks alone do not pass G-REPAIR. The current
workflow also has a separate publisher. Grant the caller write permissions only
for an explicitly authorized isolated publication test; the prepare and validate
jobs still receive read-only permissions. Normal-audit retention remains its own
acceptance gate before general rollout.

## Initial normal-audit evidence acceptance

Use the isolated demo repository for the reviewed producer slice. Keep the
five repair dispatch inputs and the three-member C4 artifact unchanged. The
normal-audit probe is a separate workflow; it is not a new repair dispatch route.

Run the reviewed `node-audit.yml` workflow with a fixed artifact prefix and
retain its exact source ref, audited head, report artifact ID, API/archive and
content SHA256 hashes, producer job ID and server-derived Check URL. Verify that
the producer uploaded the report before its seal notice and before the separate
project-validation job. Poison lifecycle, local/global pnpmfile and project-check
sentinels must not run on the producer. Validation must consume the exact prepared
dependency hashes, and must not replace the original report artifact.

Use a later read-only run with Actions and Checks read permission to verify the
exact original artifact and producer Check annotation. In the original run,
include a sibling job that uploads a forged report and emits the same notice
title. A forged locator for that sibling, even with the same run and referenced
workflow, must reject. Retain both actual outcomes and the immutable artifact
metadata. The normal publisher also needs those read grants to retain native
commit locators; it grants no extra permissions to either untrusted runner.

Do not start the cumulative repair consumer from focused/local fixture tests.
The required local full review, regular PR approval/CI and this hosted mapping
and forgery gate must all pass first. This gate does not claim cumulative repair
reporting, dependency publication or full repair acceptance is complete.

For cumulative preparation acceptance, use the private demo repository. Retain
an initial normal-audit receipt and exercise two subsequent repair attempts.
Verify the original advisory row survives a later audit that omits it, then use
the second attempt's sealed `result.md` as the third attempt's seed. Keep current
unresolved findings distinct from historical outcomes. Record all three native
source/dependency bindings and exact run/job/Check/artifact IDs and digests.

After the reviewed source passes CI, verify a real preparation upload precedes
separate validation. A distinct read-only run must accept the genuine producer
and reject an identical sibling-job copy. Grant only Actions/Checks read access
to the consumer. Preserve the existing demo PR and restore the complete fixture
file tree after the bounded test. No Hydra mutation, dependency publication or
source merge is included in this preparation slice.

## Isolated cumulative publication acceptance

After the publisher source passes full local validation, independent review,
regular PR approval and required CI, run one bounded private-demo publication
test using its reviewed reference. Keep the five dispatch inputs unchanged.
Select fixes in the existing managed PR and post a new `/repair selected`
comment. Retain the original preparation run/job/Check/artifact IDs and digests,
old/new branch heads and report URL. Verify the publisher changes only the
approved dependency files after actual separate validation success, uses the
original sealed cumulative report, and preserves the platform section exactly.

The publisher records the original preparation locator and trusted workflow SHA
in its validated-repair commit trailers. The next attempt must consume that
original artifact through native history. It does not fetch validation artifacts
or execute project hooks, package-manager commands or a fresh audit. Native Git
stale-consent, lease-race and push-success/body-edit-failure tests are required;
ambiguous pushes require branch inspection rather than an automatic retry.

Preserve original CVEs and cumulative historical/current rows in the PR
conversation. Restore the isolated fixture tree and original PR head/body with
expected-head guards after the bounded test. No source merge, stable-tag update,
Hydra change or App/Worker/D1 deployment is included. The deployed App's historical
harmless-pilot wording must be corrected before general actual-repair use; this
is an isolated publisher test, not general consumer rollout.

## Isolated normal-audit preservation acceptance

Use this slice's reviewed reusable workflow reference and keep the repair
caller's five inputs unchanged. After a genuine validated repair is published,
run normal security publication against that open PR and verify that its head,
body, open state and draft status remain unchanged. Repeat with a later
maintainer commit and with the preserved partial-publication fixture whose body
is stale. Retain the original native repair receipts and actual run URLs.

The normal publisher reads unmerged native commit trailers, not the PR body.
Real Git controls must reject a forged body marker and a lookalike trailer,
permit later publication after the repair is merged, and stop on unavailable
history. A failed new audit must remain visible in Actions without drafting or
rewriting the existing repaired PR. Restore the exact isolated fixture after
verification. The complete G-REPAIR gate also requires a clean review of
preparation, separate validation, publication and preservation together. No merge
or consumer rollout follows from that gate alone.
