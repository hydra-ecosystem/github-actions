# Workflow releases

Use `@v1` on the reusable workflow calls to receive compatible updates without
an installation PR for every fix. This applies to maintenance and fleet setup
checks. Keep the audit and publisher calls on the same reference.

`v1` is a moving release tag maintained in this repository. Advancing it changes
the code that installations trust on their next run. Compatible fixes are
reviewed, tested, and merged before the tag advances. The tag does not track
every push to `main`. Changes that require an incompatible caller or
configuration use a new major tag, such as `v2`, and require a local adoption PR.
Defaults files and local schedules are separate; a workflow release does not
rewrite them.

For immutable code, replace both `@v1` references with the same reviewed full
40-character commit SHA. This gives you control over each code update and
requires an installation PR to adopt each fix. Read `node/contract.json` and
the caller template at that commit. Both reference styles are supported by the
fleet checker; arbitrary branches and version strings are not.

The fleet checker resolves a major tag once per scan, then inspects files from
that commit's immutable tree. Its static verdict describes that observed
release, not every future value of the tag. The audit's internal actions load
from the called workflow's revision. Avoid moving the tag while a release is
being validated across installations.

## Publish a compatible release

Maintainers first obtain approval and passing checks for the exact proposed
change, squash-merge it, and verify the resulting commit has the reviewed file
tree. Then create or advance `refs/tags/v1` through GitHub's Git references API
to that full merged commit SHA. Verify the tag's resolved commit afterward.
Do this once centrally, without editing each installation. Never move `v1` to
an unreviewed commit or publish an incompatible interface through it. Retain
the previous release SHA so a faulty compatible release can be rolled back.

For the initial release, `v1` exposes the Node integration version 6 interface.
The major release number is independent of the integration contract's version.
