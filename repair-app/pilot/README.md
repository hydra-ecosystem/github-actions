# Isolated repair acceptance

For a repository installation, use the [main setup guide](../../docs/node-maintenance.md#install-interactive-repairs)
and [supported caller](../../node/repair-caller.yml). Copy it to the fixed
`.github/workflows/dependency-repair.yml` path on the default branch. There is
one dispatch route and five inputs; there is no service-side pilot mode.

The original harmless input-only fixture is retired from current setup. Its
[historical source](https://github.com/hydra-ecosystem/github-actions/blob/2297871617c11e5a4404e73f569faf46967f159b/repair-app/pilot/dependency-repair.yml)
remains available for interpreting the original infrastructure receipts.
Do not use that fixture as evidence of a dependency repair.

## Completed implementation acceptance

The private `hydra-ecosystem/demo-repository` acceptance used the real reviewed
workflow, original producer artifacts and native history. The source at
`f22661948429e391906b887842932a7b9fa7906a` passed:

- Preparation, separate validation and bounded two-file publication in
  [run 41334589821](https://github.com/hydra-ecosystem/demo-repository/actions/runs/41334589821).
- Actual normal-audit retention below a maintainer commit in
  [run 41335290085](https://github.com/hydra-ecosystem/demo-repository/actions/runs/41335290085).
- Actual normal-audit retention of genuine partial publication and its stale
  description in [run 41335868118](https://github.com/hydra-ecosystem/demo-repository/actions/runs/41335868118).

Original advisory/platform evidence, native producer/Check/artifact locators,
digests and cumulative attempts were retained. A real stale Git lease was
rejected without overwriting the branch. Earlier failure-validation,
validator-tamper and stale-revision cases were reused with exact unchanged
runtime-function and workflow-job proofs. No new failing normal audit was
claimed. The exact original demo tree, PR head and description were restored.

These historical implementation results do not attest a later source change,
Worker deployment or fresh consumer installation.

## Installation acceptance still required

Follow the [operator release gate](../../docs/node-maintenance-operator.md#installation-release-gate).
After source review and CI, the operator deploys the exact reviewed status-message
update. Then install the App and callers in a fresh isolated repository using
only the user guide. Repository users host no service and store no App key.

Retain the actual source/deployment, installation/repository, caller hashes,
request, run, Check, producer artifact/digests, published PR/diff and cleanup.
Create `consumer-receipt.json` only after observing the result. Current source
changes and planned values are not a passed receipt. Keep selection and
`/repair selected` in the main PR conversation and preserve original CVEs.

A fresh-consumer result does not authorize a Hydra pilot, stable-tag update,
source merge, new service permissions, database mutation or broad rollout.
