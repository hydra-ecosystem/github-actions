# Node dependency maintenance

Maintain dependencies for a standalone Node application, library, or website.
Each audit attempts compatible security fixes, optionally proposes routine
upgrades, and runs a frozen installation and your selected package script.
Reruns update one maintenance PR instead of opening a PR for each dependency.

## Supported projects

- One project directory, at the repository root (`"directory": "."`) or in a
  subdirectory. It owns one `package.json` and one lockfile.
- Node 22 (at least 22.13.0) or Node 24, declared in `.nvmrc`, `.node-version`,
  or explicitly in the audit configuration.
- **npm 11.9.0**, pinned as `"packageManager": "npm@11.9.0"`, with a version-3
  `package-lock.json`.
- **pnpm 11.20.0 or 11.21.0**, pinned in `packageManager`, with lockfile version
  9.0 and a standalone `pnpm-workspace.yaml` containing `packages: ["."]`.
- An existing, nonempty package script for validation. The default name is
  `build`. It can run tests, lint, a build, or several checks.

Yarn, multi-package workspaces, and multiple independent projects per installation
are outside this version's scope. The workflow does not migrate package managers
or change deployment. Both package-manager branches use the same audit engine.
The toolchain versions listed above are the supported test matrix, not a promise
that every npm or pnpm version works.

## Set it up

### 1. Verify the project locally

The examples use `app` as the project directory. Use `.` for a root project.
Declare Node in `app/.nvmrc`, for example:

```text
24
```

Keep an existing supported declaration instead of adding a conflicting one.
The nearest declaration up to the repository root wins. When `.nvmrc` and
`.node-version` are present in that directory, they must agree.

For **npm**, merge these fields into the existing `app/package.json`:

```json
{
  "packageManager": "npm@11.9.0",
  "scripts": {"check": "node --test"}
}
```

The script is an example. Use the checks your project actually needs. Activate
Node with your version manager, then verify from the project directory:

```sh
cd app
npm install --global npm@11.9.0
node --version
npm --version
npm ci
npm run check
```

For **pnpm**, retain your supported exact `packageManager` pin, for example
`pnpm@11.21.0`. Merge the [standalone workspace policy](../node/runtime/templates/pnpm-workspace.yaml)
into `app/pnpm-workspace.yaml`. Preserve existing overrides, release-age
exceptions and dependency script approvals. Then verify:

```sh
cd app
corepack enable
corepack pnpm --version
corepack pnpm install --frozen-lockfile
corepack pnpm run check
```

Commit the working declarations, manifest, lockfile, and pnpm policy, if used.

### 2. Add the project configuration

Create `.github/node-maintenance.json` at the repository root:

```json
{
  "directory": "app",
  "toolchain": {},
  "validationScript": "check",
  "minimumReleaseAgeDays": 10,
  "maintenance": {"mode": "security-only", "upgradeScope": "major"},
  "schedule": {"security": ["0 2 * * 1"], "upgrades": []}
}
```

This checks security every Monday at 02:00 UTC and leaves routine upgrades
manual. `toolchain: {}` follows the declared Node and package manager. Explicit
constraints, for example `{"node": "24", "npm": "11.9.0"}`, must agree with those
declarations. `toolchain.pnpm` applies to pnpm projects; `toolchain.npm` applies
to npm projects. Omitting `toolchain` also follows the project.

`validationScript` names a package script, not a shell command. Its name starts
with a letter or digit and uses only letters, digits, `:`, `_`, `.`, or `-`.
For a Docusaurus website, use `"validationScript": "build"` and retain its
existing build script. No Docusaurus dependency is required.

### 3. Add the caller workflow

Choose a reviewed full commit SHA from `hydra-ecosystem/github-actions` whose
[`node/contract.json`](../node/contract.json) has integration version **6**.
Create `.github/workflows/dependency-audit.yml` using the following caller.
Replace **both** `REVIEWED_FULL_COMMIT_SHA` placeholders with that same SHA.
The guide intentionally uses a placeholder; installed workflows pin an immutable
reviewed revision.

```yaml
name: Node dependency audit

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
    uses: hydra-ecosystem/github-actions/.github/workflows/node-audit.yml@REVIEWED_FULL_COMMIT_SHA
    with:
      audit-kind: ${{ inputs.audit-kind || 'auto' }}

  pull-request:
    needs: audit
    permissions:
      contents: write
      pull-requests: write
    uses: hydra-ecosystem/github-actions/.github/workflows/node-publish.yml@REVIEWED_FULL_COMMIT_SHA
    with:
      validation-passed: ${{ needs.audit.outputs.validation_passed }}
      app-client-id: ${{ vars.NODE_AUDIT_APP_CLIENT_ID }}
    secrets:
      app-private-key: ${{ secrets.NODE_AUDIT_APP_PRIVATE_KEY }}
```

The dependency job has read access. A separate configuration reporter can update
one reusable issue. Only the publisher can write the maintenance branch and PR.
Leave the optional App variable and secret unset to use `GITHUB_TOKEN`.

### 4. Enable publication and run the first audit

In **Settings → Actions → General → Workflow permissions**, enable **Allow
GitHub Actions to create and approve pull requests**, or configure the optional
GitHub App below. Default token permissions can stay read-only. Enable repository
issues for configuration diagnostics. Organization restrictions still apply.

Merge the setup into the consumer's default branch. Open **Actions → Node
dependency audit → Run workflow**, select the default branch, and choose
**security** or **upgrades**. Other dispatch branches are rejected.

- A passing proposal opens or updates one maintenance PR.
- Failed installation or project checks fail the workflow and retain a draft
  proposal when there are dependency changes to publish.
- No dependency changes leave the existing PR untouched. Read the current report
  in the run summary or artifacts.
- Configuration failures stop before dependency changes and update one reusable
  configuration issue. A successful preflight closes it.

The PR title describes its actual changes, for example **Node: 3 routine
dependency updates, no security fixes**. The report leads with versions and
validation. Unchanged blocked findings appear as neutral background; new findings
remain visible. Passing project checks does not prove all vulnerabilities are fixed.
Nothing merges automatically.

## Toolchain selection

Project declarations remain authoritative. Explicit settings constrain them and
fail on disagreement; the workflow does not rewrite them. Exact npm/pnpm versions
are required. A pnpm Corepack integrity suffix is retained. Node may be a major
or exact stable release. Symbolic aliases such as `lts/*` are rejected. Installed
tools, `engines.node`, lockfile format and standalone scope are checked before
changes. See the [tested versions](../node/runtime/toolchain.json).

## Validation and maintenance options

| Setting | Behavior |
| --- | --- |
| `validationScript` | Default `"build"`. Runs that script after a frozen install. Use `"test"`, `"check"`, or another existing script. Put prerequisites in the script. |
| `maintenance.mode` | With a schedule object, defaults to `"security-only"`. `"security-and-maintenance"` permits automatic routine upgrades on the upgrades cadence. |
| `maintenance.upgradeScope` | Default `"major"`. Routine direct upgrades may be limited to `"patch"` or `"minor"`. Transitive changes can accompany an allowed direct upgrade. |
| `minimumReleaseAgeDays` | Default ten. Controls the release cooldown; see package-manager details below. |

Security-only runs retain changes only when a security fix is confirmed and
unrelated direct changes are excluded. Manual **upgrades** requests routine
work for one run without changing automatic policy. Routine scope is checked
against resolved versions; violations restore the accepted security proposal.
Security compatibility is independent of the routine scope. No forced upgrades
or automatic override removal are used.

For **pnpm**, preflight requires workspace `minimumReleaseAge` to be at least
`minimumReleaseAgeDays * 1440`. Stricter project policy is preserved. The engine
can retain exact security-related release-age exceptions and reports them.

For **npm**, the audit supplies a publication cutoff to security and routine
resolution using `--before`. Routine direct candidates also use release-time
metadata. There is no npm release-age exception mechanism in this version;
recent fixes can remain blocked until the cutoff permits them. Existing locked
versions are not downgraded just because they are younger than the cutoff.

## Schedules and shared defaults

[Shared defaults](shared-defaults.md) let many installations follow one public
GitHub JSON file. Local fields override inherited policy. Directory, validation
script, deployment and credentials stay local.

The [recommended defaults](../defaults/node-maintenance.json) select Node 24,
pnpm 11.21.0 or npm 11.9.0, ten days, weekly security, and quarterly upgrades.
If you inherit them, mirror both schedules in your caller. JSON does not change
GitHub's workflow triggers. See [scheduling](audit-schedules.md) for cadence
examples and manual runs.

## Optional: publish with a GitHub App

An App can publish without enabling the repository-wide built-in-token PR setting.
Create an App with repository **Contents: read/write** and **Pull requests:
read/write**, then install it on each repository you maintain. Set:

- Actions variable `NODE_AUDIT_APP_CLIENT_ID` to its Client ID.
- Actions secret `NODE_AUDIT_APP_PRIVATE_KEY` to its PEM private key.

The caller supplies these values only to the publisher, which mints and revokes
a repository-scoped token. The dependency job never receives the App key or
publisher token. Authentication failure stops publication without falling back
to `GITHUB_TOKEN`. Generated CI follows GitHub's token and repository policies.
Neither mode waits for consumer CI or merges the PR.

## Update or migrate an installation

This is a breaking replacement of the Docusaurus interface. Follow the
[migration checklist](node-migration.md) for an existing installation. There are
no aliases for the old configuration, script setting, action paths or workflows.

For later updates, compare the proposed contract and caller template, update
both shared SHA references together, then run a manual audit from the default
branch. Toolchain changes still require separate local verification.

## Troubleshooting

| Symptom | Next step |
| --- | --- |
| Toolchain conflict | Align `.nvmrc`/`.node-version`, `packageManager`, `engines.node`, shared defaults and local constraints. |
| Missing validation script | Set `validationScript` to an existing script and run it locally. |
| Workspace or lockfile rejected | Select a standalone project and verify one supported lockfile. |
| pnpm scripts need approval | Review and preserve the project's `allowBuilds` decisions. |
| Cooldown rejected | Align pnpm workspace policy with the resolved minimum, or explicitly override that minimum. |
| Caller schedule mismatch | Mirror the resolved security and upgrades lists in the caller workflow. |
| PR publication denied | Check Actions permissions, App installation, and organization policy. |
| Default branch changed during audit | Rerun from the current default branch. Stale proposals are refused. |

See the [maintenance policy](../node/maintenance.md), [caller template](../node/caller.yml),
and [integration contract](../node/contract.json). The public repository contains
all required source, tests and CI; private AWD tools are optional. GitHub.com is
supported; GitHub Enterprise Server is outside the current scope.
