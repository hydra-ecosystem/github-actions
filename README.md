# Shared GitHub Actions

Reusable GitHub workflows for organization-owned and personal repositories.
Shared scripts stay here; each repository keeps its configuration and pins
the workflow to a reviewed commit.

## Available workflows

| Workflow | What it does | Get started |
| --- | --- | --- |
| Docusaurus maintenance | Fix security advisories, propose dependency upgrades, build the website, and open one PR for review. | [Setup guide](docs/docusaurus.md) |

## One maintenance PR per website

**Security fixes and routine upgrades, together in one PR.** Reruns update that
same PR, so each audit does not add another PR to review.

- **Less PR noise:** one combined review instead of individual Dependabot PRs. [Comparison](docs/docusaurus.md#why-use-this-workflow).
- **Build evidence:** a frozen install and production website build before review.
- **Clear decisions:** see what was fixed, which pins need review, and what is blocked.

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
