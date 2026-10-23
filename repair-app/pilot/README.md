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

Slice 3 proves action admission, replay rejection and one returned run ID.
Completion and releasing active requests belong to slice 4. Until that slice is
deployed, a finished pilot still retains its active request lock. Inspect its
known Actions run and D1 record; do not remove the lock or dispatch again merely
because the Check still says the workflow started.
