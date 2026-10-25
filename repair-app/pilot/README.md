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

## Isolated candidate-preparation acceptance

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

Only guard and preparation are enabled now. This gate does not pass G-REPAIR,
upgrade the PR or prove the later validation/publisher jobs. Those are added and
tested in their owning slices before the final Hydra rollout.
