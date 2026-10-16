# Shared GitHub Actions

Reusable workflows for your repositories, with the maintenance scripts kept in
one place. They work with organization-owned and personal repositories on
GitHub.com.

## Docusaurus dependency maintenance

Use this workflow to audit your documentation dependencies, propose upgrades,
and build your website before you review the changes. It opens or updates one
maintenance PR in your repository. You decide what to merge.

- Attempts security fixes before other stable dependency upgrades.
- Shows remaining advisories and the constraints or project pins blocking fixes.
- Keeps detailed dependency changes and validation evidence in expandable sections.

Your repository keeps its website, dependency declarations, overrides, build
script, schedule, and deployment. The shared workflow maintains dependencies;
your existing deployment workflow continues to publish the site.

## Set it up

The examples below use `website` as the documentation directory. Replace that
value if your site lives elsewhere.

### 1. Prepare the website

You need a Docusaurus project with its own pnpm lockfile and a `build` script
that runs all required checks and build steps. The current shared toolchain is
Node.js 24 and pnpm 11.21.0.

In `website/package.json`, set this field alongside your existing fields:

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
    uses: hydra-ecosystem/github-actions/.github/workflows/docusaurus-audit.yml@85e313c617eaf8afee0bbdb18ec79a4c51341323

  pull-request:
    needs: audit
    permissions:
      contents: write
      pull-requests: write
    uses: hydra-ecosystem/github-actions/.github/workflows/docusaurus-publish.yml@85e313c617eaf8afee0bbdb18ec79a4c51341323
    with:
      validation-passed: ${{ needs.audit.outputs.validation_passed }}
      app-client-id: ${{ vars.DOCUSAURUS_APP_CLIENT_ID }}
    secrets:
      app-private-key: ${{ secrets.DOCUSAURUS_APP_PRIVATE_KEY }}
```

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
[`docusaurus/contract.json`](docusaurus/contract.json) and
[`caller.yml`](docusaurus/caller.yml) with your installed revision, then update
**both** caller SHA references together. Check whether the toolchain requirements
changed. If the integration version changed, apply the corresponding caller and
configuration changes too.

An update does not need a new integration version when the caller interface is
unchanged. After merging an update, run a manual audit and inspect the result.
Shared code changes do not update your repository's pinned references automatically.

## Reference

- [Maintenance policy](docusaurus/maintenance.md): repair rules, reports, and publication behavior.
- [Caller template](docusaurus/caller.yml): the reusable workflow interface.
- [Toolchain](docusaurus/runtime/toolchain.json): current Node, pnpm, and release-delay values.
- [Workspace settings](docusaurus/runtime/templates/pnpm-workspace.yaml): the baseline to merge with project policy.

The workflows use GitHub.com's `$/` references to keep supporting actions and
scripts bound to the selected shared commit. GitHub Enterprise Server is not
supported by this implementation.

The Docusaurus implementation retains its BSD 3-Clause license.
