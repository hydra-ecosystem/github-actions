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

## Isolated candidate preparation and validation acceptance

After reviewing the preparation slice, use a separately authorized isolated
repository. Replace its existing harmless caller's job with a call to the
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
      contents: read
      pull-requests: read
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
unselected dependencies and a truthful preparation-only report. Also record
that no project scripts ran and no repository dependency files were published.
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

Publication is not enabled yet. These gates do not pass G-REPAIR or upgrade the
PR. Publication and retention are tested in their owning slices before the
final Hydra rollout.

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
