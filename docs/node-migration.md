# Migrate from Docusaurus maintenance

Integration version 6 replaces the Docusaurus interface with standalone Node
maintenance. This checklist applies to Hydra and OmegaConf and to any other
installation pinned to the earlier workflows. Updating this shared repository
does not update their pinned callers.

## Rollout order

A workflow SHA pin does not freeze a defaults source whose `ref` is `main`.
This replacement removes `defaults/docusaurus.json`. An old installation that
reads that path from `main` will fail preflight as soon as the removal reaches
`main`, even if its workflow pin has not changed.

Before merging the shared replacement, choose one of these rollout orders:

- Pin the old defaults source to an immutable commit that contains the old file.
  Then merge the shared replacement and migrate each consumer using the checklist.
- Publish and review the new commit, then migrate consumers to that exact commit
  and the new defaults path/ref before moving the shared default branch.

Preserve each consumer's existing policy while changing its source reference.
Do not leave the old path following `main` through the removal. Existing
installations without a shared defaults source are not affected by that removal.
These are operator steps; this repository does not migrate consumers automatically.

## Consumer checklist

1. Choose a reviewed version-6 commit. Read `node/contract.json` and use
   `node/caller.yml` from that same revision.
2. Rename `.github/docusaurus.json` to `.github/node-maintenance.json`.
3. Rename `buildScript` to `validationScript`. Keep `"build"` for the existing
   Docusaurus production build. Preserve the directory and maintenance policy.
4. Change shared defaults paths, if used, from `defaults/docusaurus.json` to
   `defaults/node-maintenance.json`. Use a ref containing the new file. Check
   inherited values and explicit overrides before removing any local field.
5. Change **both** caller workflow references to `node-audit.yml` and
   `node-publish.yml` at the same reviewed SHA. Keep the caller filename
   `.github/workflows/dependency-audit.yml` and mirror its resolved cron entries.
6. If an App is configured, supply its variable and secret as
   `NODE_AUDIT_APP_CLIENT_ID` and `NODE_AUDIT_APP_PRIVATE_KEY`. Store them under
   those names before changing the caller. Unset values use `GITHUB_TOKEN`.
7. Verify the Node declaration, exact supported `packageManager`, standalone
   pnpm policy and lockfile locally. Toolchain selection now always follows
   declarations unless explicit constraints are supplied; omitted `toolchain`
   no longer selects the old fixed toolchain. Preserve deployment checks.
8. Remove the old caller if it had another filename. Run only the new caller;
   leaving both enabled schedules duplicate work.
9. Inspect and close any old bot-owned **Docusaurus configuration** issue after
   resolving it. The new reporter uses a new marker and will not adopt that issue.
10. Merge the consumer update, dispatch **security** from the default branch,
    and inspect the resolved tools, configuration status, validation, and report.
    Dispatch **upgrades** separately when routine work is wanted.

The branch remains `maintenance/dependency-audit`, so a new proposal updates the
existing open maintenance PR instead of creating another one. Its title changes
to `Node: …`. A run without dependency changes retains the existing PR and report.
A successful run leaves an existing draft for human review.

Hydra and OmegaConf can keep pnpm, their Docusaurus build scripts, Node 24 and
pnpm 11.21.0. Their integration revisions differ: inspect each current caller
and policy instead of copying one installation's configuration over the other.
No package-manager migration is required for this interface change.
