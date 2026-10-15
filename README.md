# Shared GitHub Actions

Reusable workflows, actions, and supporting scripts for organization-owned and
personally owned repositories. Each component has its own interface and policy.

The first component maintains Docusaurus dependencies. Consumers retain their
documentation, dependency declarations, overrides, build scripts, deployment,
project configuration, and schedule. Shared calls are pinned to full commit SHAs.

## Docusaurus

Use the two reusable workflows in `.github/workflows/docusaurus-audit.yml` and
`.github/workflows/docusaurus-publish.yml` at the same reviewed commit. The
auditor has read-only permissions. Only the publisher receives repository write
permissions and optional GitHub App credentials. Both execute in the consumer's
context; publication targets the consumer's repository and default branch.

`docusaurus/caller.yml` describes the caller layout. Replace its source repository
and revision placeholders and render the schedule from `.github/docusaurus.json`.
That configuration retains its existing `directory` and optional `schedule` keys.
The documentation project owns its normal build and all prerequisites.
The [maintenance policy](docusaurus/maintenance.md) describes dependency repair,
reporting, and publication behavior.

The publisher supports the built-in workflow token. Optionally set the consumer
repository variable `DOCUSAURUS_APP_CLIENT_ID` and secret
`DOCUSAURUS_APP_PRIVATE_KEY`. The App must be installed on that consumer; personal
repositories need no organization-level secrets or membership. The token is
limited to that repository's Contents and Pull requests write permissions.
Configured App authentication failures stop publication. App setup is independent
of using the shared workflows.

The audit performs security repair before other stable upgrades, preserves
package policy, and checks frozen installation and the production build. Only
dependency files enter the proposal. Failed candidates are drafts; nothing
merges automatically. Remaining advisories and unavailable evidence stay visible.

## Integration compatibility

`docusaurus/contract.json` declares the public integration interface version.
A changed runtime commit does not necessarily change this interface. Increment
the integration version when callers need changes to inputs, configuration,
permissions, secret bindings, or workflow structure. Consumers can compare the
contract at their installed SHA with a proposed SHA and verify their caller
against that revision's template. Detecting an available update does not apply it.

Reusable workflows reference sibling actions with `$/`, binding the actions and
their supporting files to the running central commit. This requires GitHub.com;
GitHub Enterprise Server is not supported by this initial implementation.

The transferred Docusaurus implementation retains its BSD 3-Clause license.
