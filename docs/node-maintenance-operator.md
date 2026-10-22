# Operate the shared maintenance App

This guide is for the maintainer who hosts the shared GitHub App and Cloudflare
service. Repository users follow [the maintenance setup guide](node-maintenance.md); they
do not need to deploy this service or manage its credentials.

## Deploy the service

One public GitHub App and one Cloudflare Worker serve every installation. Only
the operator needs a Cloudflare account and App credentials. The Worker performs
authentication, consent checks, check updates, and workflow dispatch. It does
not install dependencies or run repository scripts.

1. Register a public GitHub App. Set its webhook URL to your Worker's
   `https://<worker-host>/webhook`. Generate a strong webhook secret and App
   private key. Request repository permissions: **Contents: read**, **Pull
   requests: read**, **Checks: write**, and **Actions: write**. Metadata read
   is implicit. Subscribe to **Pull request**, **Check run**, and **Workflow run**
   events. No user authorization callback or external selection page is needed.
2. Run `npm ci --ignore-scripts` in `repair-app`. Use a supported Node 24 runtime.
   Authenticate Wrangler with your Cloudflare account.
3. Create one D1 database with `npx wrangler d1 create node-dependency-repair`.
   Put its returned ID in [wrangler.jsonc](../repair-app/wrangler.jsonc), along
   with the GitHub App's numeric ID and slug. Do not put secrets in that file.
4. Apply the schema with `npx wrangler d1 execute node-dependency-repair
   --remote --file schema.sql` from `repair-app`.
5. Convert GitHub's downloaded RSA key to unencrypted PKCS#8 for Web Crypto:
   `openssl pkcs8 -topk8 -nocrypt -in github-app.pem -out worker-app.pem`.
   Store it with `npx wrangler secret put APP_PRIVATE_KEY < worker-app.pem`.
   Store the matching webhook secret with `npx wrangler secret put WEBHOOK_SECRET`.
   Delete temporary key files according to your credential handling policy.
6. Run `npm test`, `npm run test:runtime`, and `npm run check`. The latter
   bundles without deploying.
   Deploy deliberately with `npx wrangler deploy`, then test GitHub's webhook
   ping and one selected repository before inviting other installations.

## Prepare the user installation instructions

Keep the App's installation URL in your installation instructions. It depends
on the registered App's slug; this source repository does not yet name or host
a deployed shared service. Use a custom domain for a maintained production
service if appropriate. `workers.dev` is sufficient to try the integration.

Before publishing the user guide as generally available, supply the App
installation URL and a released workflow reference that includes the repair
workflow and report renderer. For a pilot, supply the reviewed reference
explicitly. Update the maintenance setup guide's availability notice when these are ready.

## Permissions and request handling

The Worker verifies each webhook's HMAC signature, fetches the current PR from
GitHub, checks write access for the person clicking, and binds consent to the
PR head, base, and exact selected versions. The runner independently checks the
same state. Validation runs without write credentials. A separate publisher
checks the candidate paths and scope without executing project scripts.

GitHub grants **Actions: write** per selected repository, not per workflow.
The service restricts itself to `dependency-repair.yml`, but that restriction is
in this code. The App has no contents-write permission and cannot push repair
commits itself; the repository's publisher job owns that permission.

## Stored data and operations

D1 stores request IDs, repository names, PR numbers, revisions, check IDs, and
run status for 90 days. It prevents duplicate webhook delivery from starting
the same request twice. A daily cleanup removes old records. Treat these records
as private installation data. Do not enable request-body or token logging.

Monitor delivery failures, failed Actions runs, Worker errors, D1 storage and
request limits, and App credential expiry or rotation. A failure after recording
a request but before confirmed dispatch needs inspection; the service favors
avoiding duplicate execution over automatically retrying an ambiguous POST.

Use the App's webhook delivery logs to investigate failures. Redelivering a
recorded request does not dispatch it again. Inspect the repository's Actions
runs before arranging a new attempt when dispatch could not be confirmed.

## Cost and capacity

Workers Free and Paid both support D1. Account quotas are shared by installations;
repair jobs consume the repository's normal Actions allocation. Workers Paid
starts at US$5 per account per month; D1 and other usage can add charges beyond
included allowances. Measure actual Worker CPU and database use during the pilot
before choosing the plan. Creating additional Workers does not multiply a free
account's quota.

References: [GitHub App installation](https://docs.github.com/en/apps/using-github-apps/installing-a-github-app-from-a-third-party),
[Checks API](https://docs.github.com/en/rest/checks/runs),
[workflow dispatch](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event),
[webhook validation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries),
[Cloudflare pricing](https://developers.cloudflare.com/workers/platform/pricing/),
[D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/),
and [Worker secrets](https://developers.cloudflare.com/workers/configuration/secrets/).
