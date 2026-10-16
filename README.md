# Shared GitHub Actions

Reusable GitHub workflows for organization-owned and personal repositories.
Shared scripts stay here; each repository keeps its configuration and pins
the workflow to a reviewed commit.

## Available workflows

| Workflow | What it does | Get started |
| --- | --- | --- |
| Docusaurus maintenance | Fix security advisories, propose dependency upgrades, build the website, and open one PR for review. | [Setup guide](docs/docusaurus.md) |

The report highlights fixes, decisions that need your attention, and blocked
packages. Detailed audit evidence stays folded. You decide what to merge.

The Docusaurus workflow requires Node.js 24, pnpm 11.21.0, and a standalone
website project. Existing project pins and deployment remain under your control.
The built-in GitHub token works; a GitHub App is optional.

## Reference

- [Setup, first run, and updates](docs/docusaurus.md)
- [Maintenance policy](docusaurus/maintenance.md)
- [Caller template](docusaurus/caller.yml)
- [Integration contract](docusaurus/contract.json)

Currently supports GitHub.com. The Docusaurus implementation retains its
BSD 3-Clause license.
