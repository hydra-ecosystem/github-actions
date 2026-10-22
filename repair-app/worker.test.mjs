import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import {test} from 'node:test';
import worker, {digest, handle, selections, verifySignature} from './worker.mjs';

const selection = [{name: 'launch-editor', from: '2.14.1', to: '2.14.2'}];
const body = '<!-- node-repair:selection:v1 -->\n- [x] Allow `launch-editor` `2.14.1 → 2.14.2` by updating its explicit pin.\n<!-- /node-repair:selection -->';
const keys = await crypto.subtle.generateKey({name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256'}, true, ['sign', 'verify']);
const pem = '-----BEGIN PRIVATE KEY-----\n' + Buffer.from(await crypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64') + '\n-----END PRIVATE KEY-----';
const delivery = 'e330b54a-89e6-4d55-b766-0e46dd037055';

async function fixture() {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'));
  const env = {APP_ID: '42', APP_SLUG: 'repair-app', APP_PRIVATE_KEY: pem, WEBHOOK_SECRET: 'test-secret', DB: {
    prepare(sql) { return {bind(...values) { return {
      async first() {return db.prepare(sql).get(...values);},
      async run() {return {meta: db.prepare(sql).run(...values)};},
    }; }}; },
  }};
  const pr = {number: 3572, state: 'open', body, user: {type: 'Bot'}, head: {ref: 'maintenance/node-security', sha: 'a'.repeat(40), repo: {full_name: 'example/repo'}}, base: {ref: 'main', sha: 'b'.repeat(40), repo: {full_name: 'example/repo'}}};
  const check = {id: 123, name: 'Dependency repair', app: {id: 42}, head_sha: pr.head.sha, external_id: `node-repair:3572:${await digest(pr, selection)}`, status: 'completed'};
  const payload = {installation: {id: 5}, repository: {id: 6, full_name: 'example/repo', default_branch: 'main'}, sender: {login: 'maintainer'}, action: 'requested_action', requested_action: {identifier: 'repair-selected'}, check_run: {...check, pull_requests: [{number: 3572}]}};
  const calls = [];
  let permission = 'write', failDispatch = false;
  const call = async (_token, path, method = 'GET', data) => {
    calls.push({path, method, data});
    if (path.endsWith('/access_tokens')) return {token: 'installation-token'};
    if (path.endsWith('/pulls/3572')) return pr;
    if (path.endsWith('/permission')) return {permission};
    if (path.endsWith('/check-runs/123')) {
      if (method === 'PATCH') Object.assign(check, data);
      return check;
    }
    if (path.includes('/check-runs?')) return {check_runs: [check]};
    if (path.endsWith('/dispatches')) {if (failDispatch) throw new Error('timeout'); return null;}
    if (path.endsWith('/dependency-repair.yml')) return {state: 'active'};
    if (path.endsWith('/actions/runs/456')) return payload.workflow_run;
    throw new Error(`Unexpected request ${path}`);
  };
  return {env, pr, check, payload, call, calls, db, setPermission: value => permission = value, failDispatch: () => failDispatch = true};
}

test('selection syntax matches the generated consent list and rejects broad upgrades', () => {
  assert.deepEqual(selections(body), selection);
  assert.deepEqual(selections(body.replace('[x]', '[ ]')), []);
  for (const text of [body + body, body.replace('2.14.2', '3.0.0'), body.replace('2.14.2', '2.14.0'), body.replace('Allow', 'Install')]) assert.throws(() => selections(text));
});

test('webhook signatures authenticate the exact bytes', async () => {
  const bytes = new TextEncoder().encode('{"a":1}');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode('secret'), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  const signature = 'sha256=' + Buffer.from(await crypto.subtle.sign('HMAC', key, bytes)).toString('hex');
  assert.equal(await verifySignature('secret', bytes, signature), true);
  assert.equal(await verifySignature('wrong', bytes, signature), false);
  assert.equal(await verifySignature('secret', new TextEncoder().encode('{}'), signature), false);
  assert.equal(await verifySignature('secret', bytes, 'garbage'), false);
});

test('a permitted click captures exact versions and revisions and dispatches once', async () => {
  const f = await fixture();
  await handle('check_run', f.payload, delivery, f.env, f.call);
  await handle('check_run', f.payload, delivery, f.env, f.call);
  const sent = f.calls.filter(c => c.path.endsWith('/dispatches'));
  assert.equal(sent.length, 1);
  assert.deepEqual(sent[0].data, {ref: 'main', inputs: {'request-id': delivery, 'pull-request': '3572', 'expected-head': f.pr.head.sha, 'expected-base': f.pr.base.sha, selections: JSON.stringify(selection)}});
  assert.equal(f.check.status, 'in_progress');
});

for (const reason of ['read-only actor', 'changed selection', 'changed head', 'fork', 'closed', 'wrong branch', 'wrong app']) {
  test(`rejects ${reason}`, async () => {
    const f = await fixture();
    if (reason === 'read-only actor') f.setPermission('read');
    if (reason === 'changed selection') f.pr.body = body.replace('2.14.2', '2.14.3');
    if (reason === 'changed head') f.pr.head.sha = 'c'.repeat(40);
    if (reason === 'fork') f.pr.head.repo.full_name = 'attacker/repo';
    if (reason === 'closed') f.pr.state = 'closed';
    if (reason === 'wrong branch') f.pr.head.ref = 'feature';
    if (reason === 'wrong app') f.payload.check_run.app = {id: 999};
    await handle('check_run', f.payload, delivery, f.env, f.call);
    assert.equal(f.calls.some(c => c.path.endsWith('/dispatches')), false);
    if (reason === 'changed selection') assert.match(f.check.output.summary, /No repair was dispatched by this click/);
  });
}

test('PR edits update a read-only summary and do not dispatch a run', async () => {
  const f = await fixture();
  await handle('pull_request', {...f.payload, action: 'edited', number: 3572, pull_request: f.pr}, delivery, f.env, f.call);
  assert.match(f.check.output.summary, /launch-editor.*2.14.1 → 2.14.2/);
  assert.equal(f.check.actions[0].label, 'Run selected fixes');
  assert.equal(f.calls.some(c => c.path.endsWith('/dispatches')), false);
});

test('an uncertain dispatch is never replayed automatically', async () => {
  const f = await fixture(); f.failDispatch();
  await assert.rejects(handle('check_run', f.payload, delivery, f.env, f.call));
  await handle('check_run', f.payload, delivery, f.env, f.call);
  assert.equal(f.calls.filter(c => c.path.endsWith('/dispatches')).length, 1);
  assert.match(f.check.output.summary, /may have reached GitHub/);
});

test('workflow failure links evidence and requires an explicit next attempt', async () => {
  const f = await fixture();
  await handle('check_run', f.payload, delivery, f.env, f.call);
  f.payload.action = 'completed';
  f.payload.workflow_run = {id: 456, display_title: `Node repair #3572 · ${delivery}`, path: '.github/workflows/dependency-repair.yml', event: 'workflow_dispatch', actor: {login: 'repair-app[bot]'}, status: 'completed', conclusion: 'failure', html_url: 'https://github.com/example/repo/actions/runs/456'};
  await handle('workflow_run', f.payload, 'other-delivery', f.env, f.call);
  assert.equal(f.check.conclusion, 'failure');
  assert.equal(f.check.actions[0].identifier, 'repair-selected');
  assert.match(f.check.output.summary, /Failed validation leaves the PR files unchanged/);
  assert.equal(f.calls.filter(c => c.path.endsWith('/dispatches')).length, 1);
});

test('unsigned HTTP requests cannot reach GitHub', async () => {
  const f = await fixture();
  const result = await worker.fetch(new Request('https://test/webhook', {method: 'POST', body: '{}'}), f.env);
  assert.equal(result.status, 401);
});
