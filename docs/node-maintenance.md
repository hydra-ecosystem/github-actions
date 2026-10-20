# Set up Node dependency maintenance

Use these workflows for a standalone Node application, library, or website.
They attempt compatible security fixes, optionally propose routine upgrades,
and validate the result before opening or updating one maintenance PR.

This guide installs maintenance in one repository. To monitor setup across several
installations, use the separate [fleet setup checker](node-fleet-setup.md).

Already using the earlier Docusaurus workflows? Follow the
[migration checklist](node-migration.md) instead.

For separate security and routine-upgrade proposals with dependency-file-triggered
validation and refresh, use the [coordinated caller](node-coordination.md).
The released two-job caller below retains one combined maintenance PR.

## Supported projects

- One project directory, at the repository root (`"directory": "."`) or in a
  subdirectory, with one `package.json` and one lockfile.
- Node 22 (at least 22.13.0) or Node 24.
- **npm 11.9.0**, pinned in `packageManager`, with a version-3 `package-lock.json`.
- **pnpm 11.20.0 or 11.21.0**, pinned in `packageManager`, with lockfile version
  9.0 and a standalone `pnpm-workspace.yaml` containing `packages: ["."]`.
- A package script that runs the checks needed to validate dependency changes.
  It can run tests, lint, a build, or several checks.

Yarn, `npm-shrinkwrap.json`, multi-package workspaces (including a selected
package inside an ancestor workspace), and multiple projects per installation
are not supported. Use an existing supported package manager; these workflows
do not migrate it or change deployment. GitHub.com is supported; GitHub
Enterprise Server is outside the current scope.

## Set it up

The steps below install **weekly security checks with manual-only routine
upgrades**. For weekly security and quarterly upgrades across several projects,
use the [shared-defaults setup](shared-defaults.md) when completing step 2.
Both choices use the same workflows and ten-day release cooldown.

### 1. Verify the project locally

The examples use `app` as the project directory. Use `.` for a root project.
Run only the instructions for your existing package manager.

Declare Node in `app/.nvmrc`, for example:

```text
24
```

Keep an existing supported declaration instead of adding a conflicting one.
The nearest `.nvmrc` or `.node-version` up to the repository root wins. If both
exist in that directory, they must agree. Activate that Node version with your
version manager before continuing.

Choose a validation script in `app/package.json`. Both package-manager examples
below use `check`. For example, a project using Node's test runner could use:

```json
{
  "scripts": {"check": "node --test"}
}
```

Merge this field into the existing manifest; do not replace other scripts.
Use the checks your project actually needs. To use an existing `build` or `test`
script instead, substitute that name in the local commands and in
`validationScript` in step 2. Put required setup and checks in that script.
A Docusaurus website can keep its existing `build` script; Docusaurus is not
required for other projects.

#### npm

Keep or add this exact supported pin in `app/package.json`:

```json
{"packageManager": "npm@11.9.0"}
```

From the project directory, verify the pinned tools and validation script:

```sh
cd app
npm install --global npm@11.9.0
node --version
npm --version
npm ci
npm run check
```

If your manifest edits require a lockfile update, run
`npm install --package-lock-only --ignore-scripts` with the pinned npm version,
review the diff, then repeat `npm ci` and the validation script. The resulting
`package-lock.json` must use `lockfileVersion: 3`.

#### pnpm

Keep your existing supported exact pin, including any Corepack integrity suffix.
For a project using pnpm 11.21.0, the field is:

```json
{"packageManager": "pnpm@11.21.0"}
```

Merge the [standalone workspace policy](../node/runtime/templates/pnpm-workspace.yaml)
into `app/pnpm-workspace.yaml`:

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

`14400` minutes is ten days. Preserve stricter cooldowns, existing overrides,
exact-version release-age exceptions, and dependency-script approval decisions.
Review any new script approval required by your project.

From the project directory, verify the pinned tools and validation script:

```sh
cd app
corepack enable
node --version
corepack pnpm --version
corepack pnpm install --frozen-lockfile
corepack pnpm run check
```

If your manifest or workspace edits require a lockfile update, run
`corepack pnpm install --lockfile-only --ignore-scripts`, review the diff, then
repeat the frozen install and validation script. The resulting `pnpm-lock.yaml`
must use `lockfileVersion: '9.0'`.

Commit the working Node declaration, manifest, lockfile, and pnpm policy if used.
Return to the repository root for the remaining steps.

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

This basic setup follows the project's supported toolchain, checks security
every Monday at 02:00 UTC, and leaves routine upgrades manual. Change `directory`
and `validationScript` to match step 1. `validationScript` names a package script,
not a shell command; it defaults to `build` when omitted.

To inherit policy for several installations, use the configuration in the
[shared-defaults guide](shared-defaults.md#2-point-each-installation-at-the-source)
instead. Do not keep explicit local fields for policy you want to inherit.
The recommended shared file selects weekly security **and quarterly upgrades**,
so its caller needs both cron entries in step 3.

### 3. Add the caller workflow

Create `.github/workflows/dependency-audit.yml` using the following caller.
Both workflow calls use `@v1`, a moving release tag. Compatible fixes reach your
installation without a local workflow edit. Breaking changes use a new major
release and require an explicit update.

To review every workflow update yourself, replace **both** `v1` references with
the same reviewed full 40-character commit SHA. That revision must declare Node
integration version **6** in `node/contract.json`; use its caller template.
See [workflow releases and immutable pins](workflow-releases.md) for the release
policy and tradeoff.

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
    uses: hydra-ecosystem/github-actions/.github/workflows/node-audit.yml@v1
    with:
      audit-kind: ${{ inputs.audit-kind || 'auto' }}

  pull-request:
    needs: audit
    permissions:
      contents: write
      pull-requests: write
    uses: hydra-ecosystem/github-actions/.github/workflows/node-publish.yml@v1
    with:
      validation-passed: ${{ needs.audit.outputs.validation_passed }}
      app-client-id: ${{ vars.NODE_AUDIT_APP_CLIENT_ID }}
    secrets:
      app-private-key: ${{ secrets.NODE_AUDIT_APP_PRIVATE_KEY }}
```

This caller matches the basic configuration in step 2. If you chose the
recommended shared defaults, add `- cron: '0 2 1 */3 *'` under `on.schedule`.
For other policies, use the unique cron entries from the resolved security and
upgrades lists. Omit `on.schedule` when both lists are empty. See
[schedules and manual runs](audit-schedules.md) for complete examples.

The dependency job is read-only. A separate reporter can update one configuration
issue; the publisher can write the maintenance branch and PR. Leave the optional
App variable and secret unset to use `GITHUB_TOKEN`.

### 4. Enable publication and run the first audit

In **Settings → Actions → General → Workflow permissions**, enable **Allow
GitHub Actions to create and approve pull requests**, or configure the optional
GitHub App below. Default token permissions can stay read-only. Enable repository
issues for configuration diagnostics. Organization restrictions still apply.

Merge the setup into your repository's default branch. Open **Actions → Node
dependency audit → Run workflow**, select the default branch, and choose
**security**. Manual dispatch from other branches is rejected.

Check the preflight logs or `node-audit-configuration` artifact for resolved
tool requirements and defaults sources. Read the run summary for frozen
installation, validation, and the audit result:

| Result | What happens |
| --- | --- |
| Validated dependency changes | Opens or updates the single maintenance PR. |
| Dependency changes with failed installation or checks | Retains a draft proposal when possible and fails the workflow. |
| Incomplete or unavailable security audit | Fails the run and skips publication, even if project checks pass; retains the diagnostic summary and report artifact. |
| No dependency changes | Creates no PR and leaves any existing proposal untouched; read the current run summary or report artifact. |
| Invalid configuration | Stops before dependency changes and updates one reusable configuration issue. Successful preflight adds a verification comment and closes it, preserving the last failure description. |

Choose **upgrades** for a separate manual run when you want routine updates.
It also checks security and still obeys the cooldown and upgrade scope. It does
not enable automatic upgrades. Nothing merges automatically. See
[reports and PR behavior](../node/maintenance.md#reports-and-prs) for details.

## Toolchain selection

The basic setup follows project declarations. Explicit or inherited constraints
must agree with them; the workflow fails on disagreement and does not rewrite
files. Use `toolchain.node`, `toolchain.npm`, or `toolchain.pnpm` to constrain the
relevant tool, or `"project"` to follow its declaration. An empty object does not
erase inherited constraints. The unused package-manager constraint is ignored.

Node may be a major or exact stable release; aliases such as `lts/*` are rejected.
An explicit `toolchain.node` can also supply Node when no declaration file exists.
Exact npm/pnpm versions are required in `packageManager`. A pnpm Corepack integrity
suffix is retained; npm integrity suffixes are unsupported. Installed tools,
`engines.node`, lockfile format, and standalone scope are checked before changes.
See the [tested versions](../node/runtime/toolchain.json).

## Validation and maintenance options

| Setting | Behavior |
| --- | --- |
| `validationScript` | Existing nonempty package script; default `"build"`. Names start with a letter or digit and contain only letters, digits, `:`, `_`, `.`, or `-`. |
| `localPatches` | Project-local declarations identifying advisories mitigated by local patches. These are maintainer assertions, never inherited or counted as independently confirmed security fixes. See [local patches](#local-security-patches). |
| `minimumReleaseAgeDays` | Minimum release cooldown in days; nonnegative integer, default `10`. pnpm workspace policy must be at least this strict. |
| `maintenance.mode` | `"security-only"` or `"security-and-maintenance"`. A schedule object defaults to security-only unless a mode is supplied locally or inherited. |
| `maintenance.upgradeScope` | Maximum routine direct upgrade level: `"patch"`, `"minor"` including patches, or `"major"` including both (default). Security fixes are handled separately. |
| `schedule` | Separate `security` and `upgrades` cron lists. Must match the caller's cron triggers. See the [scheduling guide](audit-schedules.md). |
| `defaults` | Public GitHub JSON source with `repository`, `path`, and `ref`. See [shared defaults](shared-defaults.md). |

The [maintenance policy](../node/maintenance.md) explains security-fix evidence,
package-manager cooldown behavior, proposal rollback, and permissions.

## Optional: publish with a GitHub App

An App can publish without enabling the repository-wide built-in-token PR setting.
Create an App with repository **Contents: read/write** and **Pull requests:
read/write**, then install it on each repository you maintain. Set these in each
repository's Actions configuration:

- Variable `NODE_AUDIT_APP_CLIENT_ID`: the App's Client ID.
- Secret `NODE_AUDIT_APP_PRIVATE_KEY`: the App's PEM private key.

The caller already forwards these values to the publisher. The dependency job
never receives the App key or publisher token. A configured App that cannot
authenticate fails publication without falling back to `GITHUB_TOKEN`.

With the built-in token, workflows triggered by opening or updating the dependency
PR require approval by a user with write access. An App token avoids that prompt,
subject to the repository's other policies. The maintenance run already performs
the frozen install and selected project checks; neither authentication mode waits
for additional PR CI. See [GitHub's token behavior](https://docs.github.com/en/actions/concepts/security/github_token).

## Local security patches

Record a maintainer assertion in `.github/node-maintenance.json` using an advisory
ID alone, or `[advisory, comment]` when you want to add context:

```json
{
  "localPatches": [
    "GHSA-5p2g-fcmc-qvqq",
    ["GHSA-w3rx-r6r6-pgpr", "Covered by regression tests."]
  ]
}
```

Merge this field into the existing configuration. The optional comment is a
single-line string of at most 2048 characters. Up to 32 distinct advisories are
supported. Assertions stay local to this repository; they are not inherited.
Package names and affected versions come from audit and lockfile evidence.

This records your assertion; the Action does not inspect, apply, or certify
arbitrary patches. Raw advisory findings stay visible and assertions never count
as confirmed security fixes. pnpm ignore rules stay unchanged while audits collect
the complete findings. An assertion whose advisory is absent from a complete
audit remains recorded as **not reported**, rather than being certified fixed.

When a newer stable official fix is verified, one **Node local patches: official
fixes available** issue is created, updated, or reopened for the repository.
Availability does not prove compatibility or release-cooldown eligibility. Review
the upstream fix and everything your patch changes before upgrading, removing the
patch and obsolete assertion, and rerunning. **Patches are never removed automatically.**
A complete check with no remaining notifications adds a resolution comment with
the verification run and closes the issue, preserving its last findings and any
maintainer notes. Later healthy runs do not add more comments. Unavailable
evidence does not close it. The reporter uses the existing `issues: write`
permission without checking out or executing project code.

Use a workflow revision whose `node/contract.json` includes `local_patches`
support. Use `@v1` or update both immutable pins together; older version-6 revisions do not
accept `localPatches`.

## Update or migrate an installation

For an earlier Docusaurus installation, use the [migration checklist](node-migration.md).
There are no aliases for its old configuration, script option, or workflow paths.

With `@v1`, compatible workflow updates need no installation PR. When adopting a
new major release, compare its contract and caller template, update both workflow
references together, and run a manual security audit from the default branch.
For immutable pins, follow those steps for each chosen commit. Shared-defaults
refs are independent of workflow references; review their changes separately.
Verify toolchain changes locally first.

## Troubleshooting

| Symptom | Next step |
| --- | --- |
| Toolchain conflict | Align Node declarations, `packageManager`, `engines.node`, and resolved toolchain constraints. |
| Missing validation script | Set `validationScript` to an existing script and run it locally. |
| Workspace or lockfile rejected | Select a standalone project with one supported lockfile; remove unsupported shrinkwrap or mixed lockfiles. |
| pnpm scripts need approval | Review the project's `allowBuilds` decisions. |
| Cooldown rejected | Align pnpm workspace policy with the resolved minimum, or explicitly override that minimum. |
| Caller schedule mismatch | Mirror the resolved security and upgrades lists in the caller; manual dispatch also checks this. |
| PR publication denied | Check Actions permissions, App installation, and organization policy. |
| Default branch changed during audit | Rerun from the current default branch. Stale proposals are refused. |

All required source, tests, and workflows are checked into this public repository.
No external workflow generator is required.
