# Node maintenance service: operator preview

This guide is for the operator of the shared GitHub App and Cloudflare service.
Repository maintainers will install the shared App; they do not host this service.

The first delivery slice implements a signed webhook receiver and a repository
metadata read. It accepts GitHub ping deliveries and authenticates the subscribed
PR events. Check actions, dispatch, storage and dependency repairs belong to
later slices. Local tests and a dry-run bundle do not prove a live installation.

## Check the receiver locally

Use Node 24 and run these commands from `repair-app/`:

```sh
npm ci --ignore-scripts --no-fund
npm test
npm run test:runtime
npm run check
```

The unit suite reports coverage for the receiver. The runtime test executes it
in local Cloudflare Workers with synthetic credentials and intercepted GitHub
requests. The final command bundles the preview with `--dry-run`; it does not
deploy. The CI job runs the same checks without App or Cloudflare credentials.

## Choose the pilot targets: G-SETUP

Before registration, installation, resource creation or deployment, obtain
explicit operator permission for these named targets and retain a sanitized
receipt outside the repository:

Record the chosen names and permitted actions first. Add assigned App and
installation IDs, the deployed URL and the deployment identity after their
approved creation steps; those IDs do not exist before creation.

| Target | Required value |
| --- | --- |
| GitHub App | Owner, slug and public App ID; use one public shared App |
| Installation | Account and installation ID; selected repositories |
| Pilot repository | Full name and numeric repository ID |
| Negative scope probe | A different private repository accessible to that installation, with its full name and ID |
| Cloudflare | Account and approved preview Worker name, environment and URL |
| Later storage | Planned D1 name and `DB` binding; no database is created in this slice |
| Reviewed code | Exact source revision and dry-run Worker bundle SHA-256 |

The negative probe must name an existing private repository. First verify it
with a separate token scoped to that repository. A nonexistent repository or
a public repository does not establish the intended narrowing test.

## Configure the approved preview

Use the named Cloudflare account and the approved reviewed source. The checked-in
Worker names are placeholders. Always supply the approved name to the commands
below. Run these live commands only after G-SETUP permission is recorded:

```sh
./node_modules/.bin/wrangler deploy --env preview --name "$PREVIEW_WORKER"
```

Record the returned deployment/version identity and `workers.dev` URL. The
receiver returns 503 until its required bindings are configured.

Register the named public GitHub App with webhook URL
`https://<approved-preview-host>/webhook`. Its complete permission model is
Contents read, Pull requests read, Checks write and Actions write; Metadata read
is implicit. Do not grant Contents write. Subscribe to `pull_request`,
`check_run` and `workflow_run`. GitHub also sends ping deliveries. Install the
App only on the approved pilot/probe repositories. This slice ignores the
Check and workflow events and requests only a Contents-read installation token
for one repository ID at a time.

Keep the App private key and a high-entropy webhook secret in operator secret
storage. GitHub's downloaded RSA key must be converted to PKCS#8 for Web Crypto:

```sh
umask 077
openssl pkcs8 -topk8 -nocrypt -in "$APP_KEY_FILE" -out "$APP_PKCS8_FILE"
./node_modules/.bin/wrangler secret put APP_ID --env preview --name "$PREVIEW_WORKER"
./node_modules/.bin/wrangler secret put APP_PRIVATE_KEY --env preview --name "$PREVIEW_WORKER" < "$APP_PKCS8_FILE"
./node_modules/.bin/wrangler secret put WEBHOOK_SECRET --env preview --name "$PREVIEW_WORKER"
```

`APP_ID` is the public numeric App ID. Keeping all three bindings in the Worker
secret store avoids putting operator-specific values in the reusable template.
Enter the same webhook secret in the App settings. These commands update the
live preview. Never put credential values in a commit, issue, PR, command-line
argument or acceptance receipt. Local `.dev.vars*` and `.env*` files are ignored.

See [GitHub webhook verification](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries),
[App JWT authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app),
[installation-token scope](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)
and [Workers secret storage](https://developers.cloudflare.com/workers/configuration/secrets/).

## Prove the first live handshake

1. Redeliver a real ping from the App's recent deliveries. Retain its delivery
   URL, delivery ID and actual HTTP result; require 200.
2. Send an invalid-signature request to the same URL. Require 401. A 503 means
   configuration is incomplete and does not satisfy signature rejection.
3. Open or edit a harmless PR in the pilot repository. Require its real signed
   `pull_request` delivery to return 200. The receiver must complete its scoped
   token creation and canonical repository read before it returns success.
4. Run the scope probe below with the same reviewed authentication code and
   operator credentials. Require both positive reads and the negative read to
   produce their stated results.

For the probe, load `APP_ID`, the PKCS#8 string `APP_PRIVATE_KEY`,
`INSTALLATION_ID`, `PILOT_REPOSITORY`, `PILOT_REPOSITORY_ID`,
`OUTSIDE_REPOSITORY` and `OUTSIDE_REPOSITORY_ID` from operator storage into the
local process environment. Both repositories must be in the chosen App
installation. Run from `repair-app/`; this prints only sanitized results:

```sh
node --input-type=module <<'JS'
import assert from 'node:assert/strict';
import {api, installationToken} from './worker.mjs';
const env = process.env;
const installation = Number(env.INSTALLATION_ID);
const pilot = Number(env.PILOT_REPOSITORY_ID);
const outside = Number(env.OUTSIDE_REPOSITORY_ID);
for (const name of ['PILOT_REPOSITORY', 'OUTSIDE_REPOSITORY']) {
  assert.match(env[name] || '', /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/);
}
assert.notEqual(pilot, outside);
const token = await installationToken(env, installation, pilot);
assert.equal((await api(token, `/repos/${env.PILOT_REPOSITORY}`)).id, pilot);
const visible = await api(token, '/installation/repositories');
assert.equal(visible.total_count, 1);
assert.deepEqual(visible.repositories.map(repo => repo.id), [pilot]);
const outsideToken = await installationToken(env, installation, outside);
const outsideRepository = await api(outsideToken, `/repos/${env.OUTSIDE_REPOSITORY}`);
assert.equal(outsideRepository.id, outside);
assert.equal(outsideRepository.private, true);
let denied = false;
try {
  await api(token, `/repos/${env.OUTSIDE_REPOSITORY}`);
} catch (error) {
  if (![403, 404].includes(error.status)) throw new Error('Scope probe failed');
  denied = true;
}
assert.equal(denied, true);
console.log(JSON.stringify({pilot_read: true, single_repository_scope: true,
  outside_repository_verified: true, outside_read_denied: true}));
JS
```

Record actual results, the two repository IDs, the reviewed revision, bundle
hash, App/installation identity, Cloudflare account, Worker name/environment,
deployment identity and real delivery URLs. Keep all credentials out of that
receipt. This completes only the first part of G-INFRA. Do not accept slice 1
or start slice 2 until this live evidence is complete. Full G-INFRA still needs
the later Check, dispatch and completion/cancellation proofs.

For rollback, disable the App webhook or uninstall the pilot installation to
stop new deliveries, then restore the previous approved Worker version if one
exists. This slice has no request database, dispatched runs or repository writes.
