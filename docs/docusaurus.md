# Docusaurus dependency maintenance

Audit dependencies, propose upgrades, and build the website before reviewing
one maintenance PR. Your repository keeps its project pins, build script,
schedule, and deployment. Works with organization-owned and personal repositories.

## Why use this workflow?

Review **one maintenance PR per website** that combines security fixes and
routine dependency upgrades. Reruns update that PR, with a frozen-install check,
production build, and a report of resolved advisories, pin decisions, and
blocked fixes. Your chosen schedule controls when routine maintenance arrives.

[Dependabot can also group updates](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/customizing-dependabot-security-prs).
This workflow packages the updates, Docusaurus build evidence, and security
decisions into one maintenance review. It targets the selected documentation
project; use other dependency tooling for the rest of your repository.

## Set it up

The examples below use `website` as the documentation directory. Replace that
value if your site lives elsewhere.

### 1. Prepare the website

You need a Docusaurus project with its own pnpm lockfile and a package script
that runs all required checks and build steps. Choose a [supported toolchain](#toolchain-selection) already used by your project.
The script defaults to `build`; select another existing script with
[`buildScript`](#build-and-maintenance-options).
Node 22 or 24 and pnpm 11.20.0 or 11.21.0 are the initial tested combinations.
Node 22 must be at least 22.13.0.

Keep an exact supported pnpm version in `website/package.json`, for example:

```json
{
  "packageManager": "pnpm@11.21.0"
}
```

Merge the following settings into `website/pnpm-workspace.yaml`. Preserve your
existing overrides and exact-version release-age exceptions. This component
expects a standalone website pnpm project with one `.` package, rather than a
multi-package pnpm workspace.

```yaml
packages:
  - "."

minimumReleaseAge: 14400
blockExoticSubdeps: true
strictDepBuilds: true
allowBuilds:
  core-js: false
  core-js-pure: false
  fsevents: false
```

These settings apply a ten-day release delay and require explicit decisions
about dependency install scripts. Review any additional script approvals your
site needs; keep its existing approved settings.

From the website directory, update the lockfile and verify your normal build:

```sh
cd website
corepack pnpm install
corepack pnpm run build
```

Commit the working manifest, `pnpm-lock.yaml`, and workspace settings. If you
use npm or Yarn today, migrate and verify the website before adding this workflow.

### 2. Add the project configuration

Create `.github/docusaurus.json` in your repository:

```json
{
  "directory": "website",
  "toolchain": {},
  "schedule": ["0 2 30 1 *"]
}
```

This example uses the default cadence: January 30 at 02:00 UTC. You can also run
the audit manually at any time. To use another cadence, change the cron expression
here **and** in the workflow below. Editing this JSON file alone does not change
GitHub's schedule.

### 3. Add the caller workflow

Create `.github/workflows/dependency-audit.yml`:

```yaml
name: Docusaurus dependency audit

'on':
  schedule:
  - cron: 0 2 30 1 *
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: dependency-audit
  cancel-in-progress: false

jobs:
  audit:
    permissions:
      contents: read
    uses: hydra-ecosystem/github-actions/.github/workflows/docusaurus-audit.yml@REVIEWED_FULL_COMMIT_SHA

  pull-request:
    needs: audit
    permissions:
      contents: write
      pull-requests: write
    uses: hydra-ecosystem/github-actions/.github/workflows/docusaurus-publish.yml@REVIEWED_FULL_COMMIT_SHA
    with:
      validation-passed: ${{ needs.audit.outputs.validation_passed }}
      app-client-id: ${{ vars.DOCUSAURUS_APP_CLIENT_ID }}
    secrets:
      app-private-key: ${{ secrets.DOCUSAURUS_APP_PRIVATE_KEY }}
```

Replace both `REVIEWED_FULL_COMMIT_SHA` placeholders with the same reviewed
40-character commit SHA that contains integration contract version 3.
Both calls use the same full commit SHA, so the implementation stays fixed until
you choose to update it. The audit job has read access. Only the publisher has
permission to push the dependency branch and open a PR.

The App variable and secret can remain unset for the initial setup. The workflow
then publishes with the repository's built-in `GITHUB_TOKEN`.

### 4. Allow PR creation

For the built-in token, open **Settings → Actions → General → Workflow permissions**
and enable **Allow GitHub Actions to create and approve pull requests**. You can
keep the default token permissions read-only; the caller grants the publisher
the two write permissions it needs. This workflow does not approve or merge PRs.

If your repository restricts allowed actions, permit the shared workflows in
`hydra-ecosystem/github-actions` and the GitHub-owned `actions/*` dependencies
they use. Organization policy can restrict these repository settings. See
[GitHub's Actions settings guide](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository).

### 5. Run the first audit

Merge the setup files into your default branch. Open **Actions → Docusaurus
dependency audit → Run workflow** and select that branch.

The run resolves dependencies, performs a frozen install, builds your site, and
publishes the report. Expect one of these results:

| Result | What to inspect |
| --- | --- |
| Changes pass validation | An open maintenance PR with the proposed dependency changes. |
| Install or build fails | A draft PR and a failed run, with the failure recorded. |
| No dependency changes | The new report in the run summary and artifacts; an existing PR stays unchanged. |

The PR is called **Docusaurus maintenance: security audit and dependency
upgrades**. Reruns reuse the same maintenance branch and open PR. A successful
rerun leaves an existing draft for human review. Remaining advisories do not
mean the build failed; the report explains what remains blocked. A passing build
does not establish that every dependency vulnerability is resolved.

## Toolchain selection

New installations include `"toolchain": {}` in `.github/docusaurus.json`.
Both omitted settings default to **follow project**:

```json
{
  "directory": "website",
  "toolchain": {"node": "project", "pnpm": "project"}
}
```

| Setting | Project declaration | Supported values |
| --- | --- | --- |
| Node | Nearest `.nvmrc` or `.node-version`, starting in the website directory and stopping at the repository root | Major 22 or 24, or an exact stable version in those majors; minimum 22.13.0 |
| pnpm | Website `package.json` → `packageManager` | Exact 11.20.0 or 11.21.0, including an optional Corepack integrity suffix |

Both pnpm versions are tested with both Node majors. The audit requires pnpm
lockfile version 9.0. It checks the actual installed versions and website
`engines.node` before changing dependencies.

A website declaration takes precedence over declarations in its parent directories.
If `.nvmrc` and `.node-version` are both present in the selected directory, they
must agree. A major and an exact version within that major agree; the exact pin
wins. Different majors or different exact versions stop the run.

Use numeric majors or exact stable versions in these files. Symbolic aliases
such as `lts/*` and broad engine ranges do not select a runtime. Missing runtime
declarations stop with instructions; the workflow does not guess or fall back
to a different version. Engine checks accept stable numeric comparisons,
major/minor families, `^`, `~`, wildcards and `||`; unsupported range syntax
stops with a diagnostic.

To require explicit values, set either setting independently:

```json
{
  "directory": "website",
  "toolchain": {"node": "24", "pnpm": "11.21.0"}
}
```

An explicit value is a requirement. It must agree with the project's declarations
and the installed tools. Node `24` requires that major; an exact Node value
requires that exact release. pnpm requires an exact version. Conflicts fail
before dependency resolution; the action does not rewrite declarations to match.

Before enabling or changing these settings:

1. Align the website's Node declaration and `engines.node`, if present.
2. Align `packageManager` with the selected supported pnpm version.
3. Make website build/deployment CI use the same declaration. For example, use
   `node-version-file: website/.nvmrc` with `actions/setup-node`, then run the
   project's pinned pnpm through Corepack. Keep one source for the Node pin.
4. Run a frozen install and the normal production build with those tools.

Changing a setting does not perform a migration. npm/Yarn, pnpm major changes,
incompatible lockfiles and other tool versions require a separately verified
migration before adoption.

Existing configurations **without a `toolchain` object** keep the legacy Node 24
and pnpm 11.21.0 selection. Updating the shared SHA alone does not opt them into
project-derived versions. To opt in, first review and align the declarations and
website CI, pin a contract-version-2 revision, then add `"toolchain": {}`.

## Build and maintenance options

Set these options in `.github/docusaurus.json`. They are available starting with
integration contract version 3. Each omitted option uses the default below:

```json
{
  "directory": "website",
  "buildScript": "build",
  "maintenance": {
    "mode": "security-and-maintenance",
    "upgradeScope": "major"
  }
}
```

| Setting | Values and behavior |
| --- | --- |
| `buildScript` | An existing, nonempty script in the selected website's `package.json`. For example, `"docs:build"` runs `pnpm run docs:build` in that website. |
| `maintenance.mode` | `"security-and-maintenance"` attempts security fixes followed by routine upgrades. `"security-only"` attempts security fixes and skips routine version lookups and upgrade resolution. |
| `maintenance.upgradeScope` | The maximum routine **direct dependency** change: `"patch"` stays within the current major and minor; `"minor"` includes patches within the current major; `"major"` permits all stable levels. |

Put prerequisites and checks in the selected package script. The configuration
does not accept shell commands or arbitrary hooks. Script names must start with
an ASCII letter or digit and contain only letters, digits, `:`, `_`, `.`, or `-`.
Invalid options or a missing selected script stop the run before dependency changes.

Routine scope uses the resolved direct dependency versions after the initial
security fix attempt. It restricts candidate selection and checks the actual
resolved proposal. If resolution crosses the limit, the workflow restores the
accepted security proposal and reports the rejected routine upgrade. Changes to
transitive dependencies can accompany an allowed direct upgrade. An unverifiable
direct version is retained for manual review when scope is restricted.

Security fixes use the existing compatibility rules independently of routine
scope. For example, `"patch"` does not block a compatible security fix that needs
a minor update. Security resolution can change related dependencies. Unresolved
or unconfirmed findings remain in the report. Both modes retain the frozen install,
selected build script, release-age policy, project pins and publication checks.

Existing configurations without these options keep the `build` script and
security fixes plus routine upgrades at all stable levels. Selecting these options
does not require new workflow inputs or a separate maintenance PR.

## Optional: publish with a GitHub App

GitHub may require approval before running checks on PRs created with
`GITHUB_TOKEN`. To let those checks start without that workflow-token prompt,
configure an App for publication:

1. Create an App with repository **Contents: read/write** and **Pull requests:
   read/write** permissions. Metadata read access is implicit. Webhooks and user
   authorization are not required.
2. Install it on each repository it will maintain, including personal repositories.
3. Set the repository Actions variable `DOCUSAURUS_APP_CLIENT_ID` to its Client ID.
4. Set the repository Actions secret `DOCUSAURUS_APP_PRIVATE_KEY` to its PEM key.

The caller above already supplies these values. The publisher creates a token
limited to the calling repository and revokes it when the job finishes. The
dependency installation and build job never receive the key or publisher token.
An App authentication failure stops publication; it does not fall back to the
built-in token. Other repository approval policies still apply.

## Update an existing installation

Review the proposed shared revision, compare its
[`docusaurus/contract.json`](../docusaurus/contract.json) and
[`caller.yml`](../docusaurus/caller.yml) with your installed revision, then update
**both** caller SHA references together. Check whether the toolchain requirements
changed. If the integration version changed, apply the corresponding caller and
configuration changes too.

An update does not need a new integration version when the caller interface is
unchanged. After merging an update, run a manual audit and inspect the result.
Shared code changes do not update your repository's pinned references automatically.

## Reference

- [Maintenance policy](../docusaurus/maintenance.md): repair rules, reports, and publication behavior.
- [Caller template](../docusaurus/caller.yml): the reusable workflow interface.
- [Toolchain](../docusaurus/runtime/toolchain.json): current Node, pnpm, and release-delay values.
- [Workspace settings](../docusaurus/runtime/templates/pnpm-workspace.yaml): the baseline to merge with project policy.

The workflows use GitHub.com's `$/` references to keep supporting actions and
scripts bound to the selected shared commit. GitHub Enterprise Server is not
supported by this implementation.

The Docusaurus implementation retains its BSD 3-Clause license.
