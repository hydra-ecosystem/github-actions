# Docusaurus dependency maintenance

Add dependency maintenance to an existing Docusaurus website. Each run attempts
security fixes, optionally proposes routine upgrades, and validates the result
with a frozen install and your website's build script. Reruns update one
maintenance PR for the website.

Your repository keeps its dependency pins, build checks, schedule, and deployment
workflow. The shared workflows support organization-owned and personal
repositories on GitHub.com.

The setup below uses integration version 5: weekly security checks, manual
upgrade runs, and one maintained dependency PR. To schedule routine upgrades,
see the [scheduling guide](audit-schedules.md).

Managing several websites? [Shared defaults](shared-defaults.md) let them inherit
one policy with per-site overrides. The recommended file selects weekly security
and quarterly upgrades. Configuration failures update one reusable issue.

## Why use this workflow?

Review security fixes, routine upgrades, build evidence, and blocked fixes in one
PR. Choose security-only maintenance or limit routine direct upgrades to patch,
minor, or major versions. [Dependabot also supports grouped updates](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/customizing-dependabot-security-prs);
this workflow adds the selected website's build and security-fix report to that
review. Use other dependency tooling for the rest of your repository.

## Before you start

Check the website project, not just the repository root:

| Requirement | What to check |
| --- | --- |
| Docusaurus | The website's `package.json` declares `@docusaurus/core`. |
| Standalone pnpm project | The website owns `package.json`, `pnpm-lock.yaml` version 9.0, and `pnpm-workspace.yaml` with one `.` package. A multi-package workspace is not supported. |
| Node | A supported version is declared in `.nvmrc` or `.node-version`: Node 22, at least 22.13.0, or Node 24. |
| pnpm | The website's `packageManager` pins exactly 11.20.0 or 11.21.0. Corepack is available locally. |
| Build | An existing package script runs all required checks and the production build. The default script name is `build`. |

If the website needs an npm/Yarn, pnpm-major, or Node migration, complete and
verify that change before installing this workflow. The configuration selects
and checks tools; it does not migrate the website.

## Set it up

The steps below use `website` as the project directory. Change that value if your
site lives elsewhere. Preserve existing supported versions and project settings
when merging the examples.

### 1. Verify the website locally

The default configuration follows the website's Node and pnpm declarations.
For a project using Node 24, `website/.nvmrc` can contain:

```text
24
```

Keep an existing supported `.nvmrc` or `.node-version` instead of adding a
conflicting declaration. A declaration in a parent directory also works; see
[toolchain selection](#toolchain-selection).

Merge an exact pnpm pin into `website/package.json`, keeping its existing scripts
and dependencies. For example:

```json
{
  "packageManager": "pnpm@11.21.0"
}
```

Merge the baseline below into `website/pnpm-workspace.yaml`. Keep your existing
overrides, exact-version release-age exceptions, and dependency-script approvals:

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

This applies a ten-day release delay and requires explicit decisions about
additional dependency install scripts. Review the approvals your own site needs.

Activate the declared Node version with your normal version manager. From the
website directory, confirm the tools, refresh the lockfile after any
settings changes, then verify a frozen install and build:

```sh
cd website
node --version
corepack pnpm --version
corepack pnpm install
corepack pnpm install --frozen-lockfile
corepack pnpm run build
```

If your script is named `docs:build`, run `corepack pnpm run docs:build` instead
and select that name in the next step. Put prerequisites and checks in that
package script. Commit the working declarations, manifest, lockfile, and workspace
settings along with the setup files below.

### 2. Add the project configuration

Create `.github/docusaurus.json` at the repository root:

```json
{
  "directory": "website",
  "toolchain": {},
  "buildScript": "build",
  "maintenance": {
    "mode": "security-only",
    "upgradeScope": "major"
  },
  "schedule": {
    "security": ["0 2 * * 1"],
    "upgrades": []
  }
}
```

`"toolchain": {}` follows the project declarations verified in step 1. The build
and maintenance values shown are the defaults; change them using the
[options reference](#build-and-maintenance-options).

The example checks security every Monday at 02:00 UTC and leaves routine
upgrades manual. To use another cadence, update both the resolved JSON schedule
and the caller workflow's cron entries. GitHub reads scheduled triggers from
the workflow file; changing JSON alone does not reschedule the audit.

To inherit the [recommended shared defaults](shared-defaults.md), use that guide's
source configuration and omit local maintenance and schedule fields that you
want to inherit. Mirror both weekly and quarterly entries in the caller.

### 3. Add the caller workflow

Choose one reviewed full commit SHA from `hydra-ecosystem/github-actions`.
Inspect its `docusaurus/contract.json` and confirm `integration_version` is at
least `5`. Use `docusaurus/caller.yml` from that same revision.

Create `.github/workflows/dependency-audit.yml` at the repository root using the
example below. Replace **both** `REVIEWED_FULL_COMMIT_SHA` placeholders with that
chosen SHA before committing. The placeholder avoids a stale hard-coded release
hash in this guide; installed workflows still pin one immutable revision.

```yaml
name: Docusaurus dependency audit

'on':
  schedule:
  - cron: '0 2 * * 1'
  workflow_dispatch:
    inputs:
      audit-kind:
        description: Security fixes only, or security plus routine upgrades for this run.
        type: choice
        default: security
        options:
        - security
        - upgrades

permissions:
  contents: read

concurrency:
  group: dependency-audit
  cancel-in-progress: false

jobs:
  audit:
    permissions:
      contents: read
      issues: write
    uses: hydra-ecosystem/github-actions/.github/workflows/docusaurus-audit.yml@REVIEWED_FULL_COMMIT_SHA
    with:
      audit-kind: ${{ inputs.audit-kind || 'auto' }}

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

Both calls must pin the same reviewed revision. The implementation stays fixed
until you update both references. The audit's dependency-execution job has read
access; a separate reporter uses `issues: write` for configuration failures.
Only the publisher can push the maintenance branch
and open its PR. For the initial setup, leave the App variable and secret unset;
the publisher uses the repository's built-in `GITHUB_TOKEN`.

### 4. Allow the workflow to open PRs

In the consumer repository, open **Settings → Actions → General → Workflow
permissions**. Enable **Allow GitHub Actions to create and approve pull requests**.
You can keep the default token permissions read-only; the caller grants the
publisher its required write permissions. The workflow does not approve or merge
maintenance PRs.

If the repository restricts allowed actions, permit the shared workflows in
`hydra-ecosystem/github-actions` and the GitHub-owned `actions/*` dependencies
they use. An organization policy can override repository settings. See
[GitHub's Actions settings guide](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository).

### 5. Run and inspect the first audit

Merge the website preparation and setup files into your default branch. Open
**Actions → Docusaurus dependency audit → Run workflow** and select that branch.
Manual dispatch from another branch is rejected.
Choose **security** for security fixes only, or **upgrades** for security plus
routine upgrades for this run. A manual upgrade run keeps your automatic policy
unchanged and still obeys scope, cooldown and build checks. Enable repository
issues so the configuration reporter can open or update its single issue.

| Result | What to do |
| --- | --- |
| Dependency changes pass validation | Review the maintenance PR and its report before merging. |
| Frozen install or build fails | Inspect the report and logs. The workflow fails and publishes a draft proposal when it can retain a candidate. |
| No dependency changes | Read the new report in the run summary or artifacts. An existing PR and its report stay unchanged. |
| Configuration or toolchain is rejected | Fix the diagnostic before rerunning; dependency changes have not started. |

The PR is titled **Docusaurus maintenance: security audit and dependency
upgrades**. Reruns reuse the same branch and open PR. A successful rerun leaves
an existing draft for human review. Remaining advisories do not by themselves
mean the build failed; inspect the reported blockers. A passing build does not
establish that all vulnerabilities are resolved.

With the built-in token, PR workflows triggered by opening or updating the PR
require approval. A user with write access can select **Approve workflows to
run** in the PR. See [GitHub's token behavior](https://docs.github.com/en/actions/concepts/security/github_token).
To avoid that token-specific prompt, use the optional App below.

## Toolchain selection

With a `toolchain` object, omitted Node and pnpm settings default to **follow
project**. These explicit values have the same effect as `"toolchain": {}`:

```json
{
  "directory": "website",
  "toolchain": {"node": "project", "pnpm": "project"}
}
```

| Setting | Declaration used | Supported values |
| --- | --- | --- |
| Node | Nearest `.nvmrc` or `.node-version`, from the website directory up to the repository root | Major 22 or 24, or an exact stable release in those majors; minimum 22.13.0 |
| pnpm | Website `package.json` → `packageManager` | Exact 11.20.0 or 11.21.0, with an optional Corepack integrity suffix |

Both pnpm versions are tested with both Node majors. The workflow verifies the
installed tools, website `engines.node`, and pnpm lockfile version 9.0 before
changing dependencies.

A website Node declaration takes precedence over one in a parent directory.
If `.nvmrc` and `.node-version` are both present in the selected directory, they
must agree. A major and an exact release within it agree; the exact pin wins.
Different majors or exact releases stop the run. Use numeric declarations;
symbolic aliases such as `lts/*` do not select a runtime. Missing declarations
stop with a diagnostic.

To require specific supported versions, set either option independently:

```json
{
  "directory": "website",
  "toolchain": {"node": "24", "pnpm": "11.21.0"}
}
```

Explicit values must agree with the project declarations and installed tools.
The workflow does not rewrite declarations to resolve a conflict. Keep website
build/deployment CI on the same declaration, for example with
`node-version-file: website/.nvmrc` in `actions/setup-node` and the project's
pinned pnpm through Corepack.

Existing configurations **without a `toolchain` object** retain the legacy
Node 24 and pnpm 11.21.0 selection. To opt in to project selection, align the
project declarations and website CI, verify a frozen install and build, pin
version 2 or later of the integration contract, then add `"toolchain": {}`.
The version-5 revision selected in step 3 also supports these toolchain, build
and maintenance options.

With integration version 4, toolchain constraints can also come from a
[shared defaults source](shared-defaults.md). Explicit local fields override
inherited fields. Resolved values are checked against project declarations;
conflicts fail rather than rewriting those declarations.

## Build and maintenance options

Version 5 adds [separate security and upgrade schedules](audit-schedules.md),
manual audit selection, and a security-fix requirement for security-only PRs.
The standalone setup above uses security-only. The recommended shared defaults
select weekly security and quarterly upgrades. Explicit local settings win.

These options live in `.github/docusaurus.json` and require integration contract
version 3 or later; separate schedules and manual selection require version 5.

| Setting | Values and behavior |
| --- | --- |
| `buildScript` | Default `"build"`. Names an existing, nonempty script in the selected website's `package.json`. For example, `"docs:build"` runs `pnpm run docs:build` in that website. |
| `maintenance.mode` | With a schedule object, default `"security-only"`: skip routine version lookups and resolution. `"security-and-maintenance"` allows routine work on the upgrades cadence. Legacy list/omitted schedules default to combined maintenance. Manual `audit-kind=upgrades` requests combined work for one run. |
| `maintenance.upgradeScope` | Default `"major"`. Maximum routine **direct dependency** change: `"patch"` stays within the current major and minor; `"minor"` includes patches within the current major; `"major"` permits all stable levels. |

The script name starts with an ASCII letter or digit and contains only letters,
digits, `:`, `_`, `.`, or `-`. Put commands in the package script, not this setting.
There are no arbitrary shell hooks. Invalid options or a missing selected script
stop the run before dependency changes.

Routine scope uses the resolved direct versions after the initial security fix
attempt. It limits candidate selection and checks the actual resolved proposal.
If resolution crosses the limit or changes an unverifiable direct reference, the
workflow restores the accepted security proposal and reports the rejection.
Transitive changes can accompany an allowed direct upgrade.

Security fixes use the existing compatibility rules independently of routine
scope. For example, `"patch"` does not block a compatible security fix that needs
a minor update. Security resolution can change related dependencies. Unresolved
or unconfirmed findings stay visible. Both modes retain the release-age policy,
project pins, frozen installation, selected build script, and publication checks.

Existing configurations without these options retain the `build` script and
security fixes plus routine upgrades at all stable levels. No additional caller
inputs or separate PR are needed for these options.

## Optional: publish with a GitHub App

Use an App if generated PR workflows should start without the built-in token's
approval prompt:

1. Create a GitHub App with repository **Contents: read/write** and **Pull requests:
   read/write** permissions. Metadata read access is implicit. Webhooks and user
   authorization are not required.
2. Install it on each consumer repository you want it to maintain.
3. Set the repository Actions variable `DOCUSAURUS_APP_CLIENT_ID` to its Client ID.
4. Set the repository Actions secret `DOCUSAURUS_APP_PRIVATE_KEY` to its PEM key.

The caller in step 3 already supplies these values. The publisher creates a token
limited to that repository and revokes it when the job finishes. The audit and
build job never receive the App key or publisher token. App authentication failure
stops publication rather than falling back to the built-in token. Other repository
approval policies still apply.

## Update an existing installation

Review the proposed shared revision. Compare its
[`docusaurus/contract.json`](../docusaurus/contract.json) and
[`caller.yml`](../docusaurus/caller.yml) with the installed revision, then update
**both caller SHA references together**. Apply any required configuration changes
before running the new revision. A shared-repository update never moves consumer
pins automatically.

After merging the update into the consumer's default branch, run a manual audit
and inspect its report and PR. Changing a toolchain setting is not a migration;
verify any tool or lockfile migration separately first.

## Troubleshooting

| Symptom | Next step |
| --- | --- |
| Missing Node declaration or conflicting versions | Check `.nvmrc` / `.node-version`, website `packageManager` and `engines.node`, the `toolchain` options, and website CI. Use supported versions that agree. |
| Missing build script | Set `buildScript` to an existing nonempty website script, then run that script locally. |
| pnpm rejects workspace policy or lockfile | Merge the standalone workspace settings, retain project policy, and refresh and verify the lockfile locally. |
| Dependency installation scripts need approval | Review the named packages and record the required decisions in website `allowBuilds`; keep existing approvals. |
| PR creation is denied | Check the repository setting in step 4 and any overriding organization policy. |
| Generated PR checks are waiting for approval | Select **Approve workflows to run**, or configure the optional GitHub App. |
| Default branch changed during the audit | Rerun from the current default branch; the publisher refuses a stale proposal. |
| Shared defaults cannot be read or do not match the project | Use integration version 4, inspect the configuration issue, and align the declaration or add an explicit local override. See [shared defaults](shared-defaults.md). |
| Cooldown is rejected by integration version 4 | Set workspace `minimumReleaseAge` to at least the resolved `minimumReleaseAgeDays * 1440`, or explicitly choose a different local minimum. |
| Configuration issue cannot be maintained | Enable repository issues and grant `issues: write` on the caller's audit job using the version-4 caller template. Do not create another marked configuration issue. |

## Reference

- [Maintenance policy](../docusaurus/maintenance.md): repair rules, reports, and publication behavior.
- [Caller template](../docusaurus/caller.yml): the reusable workflow interface.
- [Integration contract](../docusaurus/contract.json): configuration version and defaults.
- [Toolchain](../docusaurus/runtime/toolchain.json): supported Node and pnpm combinations.
- [Shared defaults for multiple installations](shared-defaults.md): live sources, local overrides, validation and issue lifecycle.
- [Workspace settings](../docusaurus/runtime/templates/pnpm-workspace.yaml): baseline to merge with project policy.

The implementation uses GitHub.com's `$/` references to bind supporting actions
and scripts to the selected shared commit. GitHub Enterprise Server is not
supported. The Docusaurus implementation retains its BSD 3-Clause license.
