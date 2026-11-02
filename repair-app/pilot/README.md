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

## Completed fresh-consumer installation acceptance

The [consumer receipt](consumer-receipt.json) records the 2026-11-02 run using
workflow source `42fe6d163e7f3152b8ef55ed3b0a842a999564a9` and the deployed
reviewed Worker. A new private repository reused the existing organization-wide
App installation and copied both supported callers. It hosted no service and
stored no App key. This verifies the consumer flow under that installation;
it does not exercise a new App permission grant.

The real PR contained generated choices and a head/base revision binding.
One `minimist` selection and a new `/repair selected` comment triggered
[run 41394558474](https://github.com/hydra-ecosystem/node-maintenance-installation-acceptance-20261102/actions/runs/41394558474).
Preparation, separate validation and bounded publication passed. The native
repair changed only its selected override and lockfile. The unselected
`launch-editor` pin, all four original advisory identities and the platform
section remained. The same App reply reported the actual final run result.

An earlier fixture used incompatible exact direct manifest constraints; the
repair correctly rejected it before publication. The corrected fixture used
compatible direct ranges with identical vulnerable overrides and lockfile bytes.
Both attempts and their native evidence are retained. After acceptance, the
two fixture workflows were disabled; its private PR and history were preserved.

For later revisions, follow the
[operator release gate](../../docs/node-maintenance-operator.md#installation-release-gate)
and record fresh evidence before claiming acceptance.

A fresh-consumer result does not authorize a Hydra pilot, stable-tag update,
source merge, new service permissions, database mutation or broad rollout.
