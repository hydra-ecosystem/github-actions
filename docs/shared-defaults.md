# Shared defaults for multiple Docusaurus installations

Define shared defaults once, reuse them across many Docusaurus installations,
and override settings in individual repositories when needed. A source is a
regular JSON file in any **public GitHub.com repository**. It needs no service,
App, or registration with this repository.

This feature requires **integration version 4**. Inspect
[`docusaurus/contract.json`](../docusaurus/contract.json) at your chosen reviewed
workflow revision and confirm `integration_version` is at least `4`. Use the
[caller template](../docusaurus/caller.yml) from that same revision and pin both
reusable workflow calls to its full commit SHA. The pinned integration-v3 starter
in the [general setup guide](docusaurus.md#set-it-up) does not resolve shared
defaults or maintain configuration issues.

## 1. Choose an authoritative defaults file

For example, publish this as `defaults/docusaurus.json` in your own public
configuration repository:

```json
{
  "toolchain": {
    "node": "24",
    "pnpm": "11.21.0"
  },
  "minimumReleaseAgeDays": 10,
  "maintenance": {
    "mode": "security-and-maintenance",
    "upgradeScope": "major"
  }
}
```

You can also use the [recommended defaults in this repository](../defaults/docusaurus.json).
They live outside the `docusaurus/` action implementation tree. Other maintainers
can keep equivalent files in their own repositories and review changes through
their normal pull-request process. Supported Node/pnpm combinations still apply;
a shared file does not add support for an untested toolchain.

## 2. Point each installation at the source

In each website repository, add the source to `.github/docusaurus.json`:

```json
{
  "directory": "website",
  "defaults": {
    "repository": "hydra-ecosystem/github-actions",
    "path": "defaults/docusaurus.json",
    "ref": "main"
  },
  "buildScript": "build",
  "schedule": ["0 2 30 1 *"]
}
```

Change `repository` and `path` to use your own file. All three source fields are
required. `ref` can be a branch, tag, or full commit SHA. Sources are read without
credentials, so private source repositories are not supported; the website
repository itself may be private.

Each installation keeps its own directory, build script, schedule, dependency
declarations, security exceptions, deployment, and credentials. These values are
not inherited. Keep the local schedule mirrored in the caller workflow. Remove
explicit local toolchain or maintenance values when you want to inherit them.
A local `maintenance.upgradeScope` keeps overriding the source after updates.

## 3. Allow the configuration issue reporter

The version-4 caller grants these permissions on its **`jobs.audit`**:

```yaml
permissions:
  contents: read
  issues: write
```

Use the complete [caller template](../docusaurus/caller.yml) from your selected
version-4 revision. Keep both workflow references pinned to that same full SHA.
The workflow's internal audit job has only `contents: read`; a separate reporting
job has only `issues: write`. The reporting job reads a bounded JSON status
artifact and does not check out or execute website code. It receives no App key.

Enable repository issues. No App is required for reporting. The existing
[PR-creation setup](docusaurus.md#4-allow-the-workflow-to-open-prs) still applies
to publishing dependency proposals.

## Local overrides

Local settings win independently for each toolchain and maintenance field:

```json
{
  "directory": "website",
  "defaults": {
    "repository": "hydra-ecosystem/github-actions",
    "path": "defaults/docusaurus.json",
    "ref": "main"
  },
  "toolchain": {
    "node": "22"
  },
  "minimumReleaseAgeDays": 14,
  "maintenance": {
    "upgradeScope": "patch"
  }
}
```

This site requires Node 22 and a fourteen-day minimum cooldown. It inherits pnpm
and maintenance mode, and restricts routine upgrades to patches. Its project
declarations must agree with those resolved settings.

An empty `toolchain` object does not erase inherited constraints. Set either
`toolchain.node` or `toolchain.pnpm` to `"project"` to explicitly follow that
project's declaration instead of the inherited version requirement.

`minimumReleaseAgeDays` is a nonnegative integer and defaults to `10` when no
source or local setting supplies it. The website's `pnpm-workspace.yaml` must
have an integer `minimumReleaseAge` of at least `days * 1440` minutes. A stricter
workspace value is accepted. Exact-version security exceptions remain intact;
the workflow does not lower the global cooldown or rewrite declarations.

## Use another website as the authoritative source

Point `repository` at that website's repository and `path` at its
`.github/docusaurus.json`. Its shared settings become live defaults for dependent
websites. Source directory, build script, and schedule fields are ignored.

The source can itself inherit defaults. Its inherited values are applied first,
then its explicit shared values, then the dependent website's explicit values.
This is live inheritance, not a one-time copy. Sources must declare shared
values explicitly or inherit them; the resolver does not infer versions from
another website's `.nvmrc` or `package.json`. `"project"` always refers to the
consuming website.

Cycles, chains longer than eight sources, unknown settings, invalid JSON,
unreadable sources, and oversized files fail validation. Source files are limited
to 64 KiB and are treated only as JSON data. Each source reference field is
limited to 2048 characters.

## Manage shared updates

- **Follow a branch** for fleet-wide changes on each installation's next audit.
- **Use a full commit SHA** for fixed defaults and adopt updates through local PRs.
- A tag can move; use a full SHA when you need an immutable source.

The source revision is independent of the workflow revision. Each audit resolves
branch/tag references to full commits and freezes the effective configuration
for that run. Failure reports record the source path, requested reference, and
resolved commit. Changing a source during a run does not change that run's
requirements. Future runs resolve the source again.

Before changing fleet defaults, verify one site's declarations and build against
the proposed values. Align affected sites' declarations when adopting a change.
A shared change can cause sites that have drifted to fail their next preflight;
it does not migrate them automatically.

## Failures and the single configuration issue

Preflight runs before any website dependency command. Conflicting Node or pnpm
declarations, an insufficient cooldown, or a bad source produce a GitHub Actions
error annotation, a failed audit, and a configuration issue with the diagnostic,
source information, and workflow-run link. Failed configuration checks do not
publish a dependency proposal.

There is **one bot-owned `Docusaurus configuration` issue per repository**:

1. The first configuration failure opens it.
2. Repeated failures update its body without adding per-run comments.
3. Successful configuration and runtime validation closes it, even if a later
   dependency install or build fails for a different reason.
4. A later configuration failure reopens the same issue, including when the
   defaults source has changed.

Fix the named declaration, or explicitly override the inherited setting, then
rerun the audit. The workflow never edits files to resolve a mismatch. Interrupted
preflight does not close an existing issue. Ordinary build or dependency failures
retain the existing audit-report/draft-PR behavior.

Reporting is serialized per repository. Ambiguous duplicate marked issues,
disabled repository issues, or insufficient issue permission produce a reporting
error rather than creating another issue. Inspect that error before retrying.

Automatic migration or repair PRs are not part of this feature. Repeated manual
repair effort can inform whether an opt-in migration feature is worthwhile.
