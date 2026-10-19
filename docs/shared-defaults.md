# Shared defaults for multiple Node installations

Use one JSON file as the authoritative policy for several repositories. Each
installation inherits toolchain constraints, release cooldown, maintenance
options, and schedules, while keeping its own project settings and credentials.

To monitor the installations following that policy, keep an optional repository
inventory beside the defaults and run the separate [fleet setup checker](node-fleet-setup.md).
It reports broken setup centrally without running dependency maintenance.

A source can be a regular file in **any public GitHub.com repository**. It needs
no service, App, or registration here. The consuming repository may be private.
Use integration version **6** and the [setup guide](node-maintenance.md#set-it-up)
for local project verification, the caller workflow, and publication permissions.

## 1. Choose an authoritative defaults file

You can follow the [recommended defaults in this repository](../defaults/node-maintenance.json)
or publish an equivalent file in your own public configuration repository:

```json
{
  "toolchain": {
    "node": "24",
    "npm": "11.9.0",
    "pnpm": "11.21.0"
  },
  "minimumReleaseAgeDays": 10,
  "maintenance": {
    "mode": "security-and-maintenance",
    "upgradeScope": "major"
  },
  "schedule": {
    "security": ["0 2 * * 1"],
    "upgrades": ["0 2 1 */3 *"]
  }
}
```

This policy checks security weekly and proposes routine upgrades quarterly.
It requires Node 24 and the listed version of the project's existing package
manager; it does not choose or migrate the package manager. A shared file cannot
add support for toolchain versions outside the [supported matrix](node-maintenance.md#supported-projects).

## 2. Point each installation at the source

Use this as the configuration in step 2 of the setup guide, replacing `website`
and `build` with your project directory and validation script:

```json
{
  "directory": "website",
  "defaults": {
    "repository": "hydra-ecosystem/github-actions",
    "path": "defaults/node-maintenance.json",
    "ref": "main"
  },
  "validationScript": "build"
}
```

All three source fields are required. Change `repository` and `path` to use your
own file. `ref` can be a branch, tag, or full commit SHA. Sources are fetched
without credentials; private defaults repositories are not supported.

**Replace the basic setup's explicit policy fields rather than appending this
source to them.** Local fields keep overriding the source. In particular, the
basic `security-only` mode conflicts with inherited nonempty upgrade schedules.
Keep explicit local values only when you intend to override shared policy.

## 3. Match the caller and run an audit

Continue with [step 3 of the setup guide](node-maintenance.md#3-add-the-caller-workflow).
For the recommended defaults, the caller must contain both cron entries:

```yaml
schedule:
- cron: '0 2 * * 1'
- cron: '0 2 1 */3 *'
```

Place this under `on` in the caller. Keep both reusable workflow calls pinned
to the same reviewed version-6 SHA. Enable repository issues and publication as
shown in [step 4](node-maintenance.md#4-enable-publication-and-run-the-first-audit),
then run a manual security audit. Preflight checks the resolved tools, cooldown,
and schedules before dependency changes.

A defaults edit does not rewrite local workflow triggers. When shared schedules
change, update affected callers too. A mismatch fails preflight, including manual
runs, and updates the single configuration issue. See the
[scheduling guide](audit-schedules.md) for disabling or changing a cadence.

## Local overrides

Local fields override inherited values independently. For example:

```json
{
  "directory": "website",
  "defaults": {
    "repository": "hydra-ecosystem/github-actions",
    "path": "defaults/node-maintenance.json",
    "ref": "main"
  },
  "toolchain": {"node": "22"},
  "minimumReleaseAgeDays": 14,
  "maintenance": {"upgradeScope": "patch"}
}
```

This project requires Node 22 and a fourteen-day minimum cooldown. It inherits
the package-manager constraint, maintenance mode, and both schedules, while
limiting routine direct upgrades to patches. Its local declarations and pnpm
policy, if used, must satisfy those settings.

| Setting | Override behavior |
| --- | --- |
| `toolchain.node`, `toolchain.npm`, `toolchain.pnpm` | Each local value replaces that inherited constraint. Use `"project"` to follow the consuming project's declaration. An empty object erases nothing. |
| `minimumReleaseAgeDays` | A local integer replaces the inherited minimum; stricter pnpm workspace policy remains valid. |
| `maintenance.mode`, `maintenance.upgradeScope` | Each local value replaces that inherited field. |
| `schedule.security`, `schedule.upgrades` | Each local list replaces that cadence. Omitted lists inherit; `[]` disables a cadence. An empty object inherits both lists. |

Directory, validation script, dependency declarations, security exceptions,
deployment, and credentials remain local. They are not inherited. Shared
constraints are checked against declarations; they never rewrite them.
`localPatches` declarations are also project-local and never inherited; see
[local security patches](node-maintenance.md#local-security-patches).

## Use another project as the authoritative source

Point `repository` at that project's public repository and `path` at its
`.github/node-maintenance.json`. Only its shared fields are inherited; its
directory and validation script are ignored.

The source can itself inherit defaults. Its inherited values apply first, then
its explicit shared values, then the consuming project's explicit values.
This is live inheritance, not a one-time copy. Versions are not inferred from
another project's `.nvmrc` or `package.json`. `"project"` always refers to the
consuming project.

Cycles, chains longer than eight sources, unknown settings, invalid JSON,
unreadable sources, and oversized files fail validation. Source files are limited
to 64 KiB; each source reference field is limited to 2048 characters. Sources are
treated only as JSON data.

## Manage shared updates

- Follow a **branch** to apply shared changes on each installation's next audit.
- Use a **full commit SHA** when each policy update needs a local adoption PR.
- A tag can move; use a full SHA for an immutable source.

The defaults ref is independent of the workflow pin. A pinned workflow that
follows defaults at `main` still receives future defaults changes. Each audit
resolves references to full commits and freezes its configuration for that run;
source changes apply to later runs. Configuration reports retain source identities.

Before changing shared policy, verify a representative project's declarations
and validation script against the proposed values. Align affected declarations,
pnpm cooldowns, and caller triggers as needed. A shared change can cause the next
preflight to fail; no automatic migration or repair PR is generated.

Failures reuse one **Node audit configuration** issue per repository. Fix the
named declaration or override, then rerun. Successful preflight closes the issue;
recurrence reopens it. See [configuration issue behavior](../node/maintenance.md#configuration-issues)
for reporting permissions and failure cases.
