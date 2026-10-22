// Exercise the bundled service and real local D1 binding in Cloudflare's runtime.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
import {digest} from './worker.mjs';

const items = [{name: 'launch-editor', from: '2.14.1', to: '2.14.2'}];
const bodyText = '<!-- node-repair:selection:v1 -->\n- [x] Allow `launch-editor` `2.14.1 → 2.14.2` by updating its explicit pin.\n<!-- /node-repair:selection -->';
const pr = {number: 1, state: 'open', body: bodyText, user: {type: 'Bot'}, head: {ref: 'maintenance/node-security', sha: 'a'.repeat(40), repo: {full_name: 'test/repo'}}, base: {ref: 'main', sha: 'b'.repeat(40), repo: {full_name: 'test/repo'}}};
const check = {id: 2, app: {id: 42}, head_sha: pr.head.sha, external_id: `node-repair:1:${await digest(pr, items)}`, status: 'completed'};
const keys = await crypto.subtle.generateKey({name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256'}, true, ['sign', 'verify']);
const privateKey = '-----BEGIN PRIVATE KEY-----\n' + Buffer.from(await crypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64') + '\n-----END PRIVATE KEY-----';
const dispatched = [];

const service = new Miniflare(convertV4MiniflareOptions({
  modules: true,
  scriptPath: new URL('./worker.mjs', import.meta.url).pathname,
  compatibilityDate: '2026-10-22',
  bindings: {APP_ID: '42', APP_SLUG: 'test-repair', APP_PRIVATE_KEY: privateKey, WEBHOOK_SECRET: 'test-secret'},
  d1Databases: {DB: 'local-repair-test'},
  outboundService: async request => {
    const path = new URL(request.url).pathname;
    let response;
    if (path.endsWith('/access_tokens')) response = {token: 'test-token'};
    else if (path.endsWith('/pulls/1')) response = pr;
    else if (path.endsWith('/permission')) response = {permission: 'write'};
    else if (path.endsWith('/check-runs/2')) {
      if (request.method === 'PATCH') Object.assign(check, await request.json());
      response = check;
    } else if (path.endsWith('/dispatches')) {
      dispatched.push(await request.json());
      return new Response(null, {status: 204});
    } else throw new Error(`Unexpected external request: ${path}`);
    return new Response(JSON.stringify(response), {headers: {'Content-Type': 'application/json'}});
  },
}));
try {
  const database = await service.getD1Database('DB');
  await database.exec(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8').replaceAll('\n', ' '));
  const statement = 'INSERT OR IGNORE INTO requests (id, repository, pr, head, check_id, fingerprint, installation, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
  const values = ['request', 'test/repo', 1, 'head', 2, 'fingerprint', 3, 'dispatched', Date.now()];
  assert.equal((await database.prepare(statement).bind(...values).run()).meta.changes, 1);
  assert.equal((await database.prepare(statement).bind(...values).run()).meta.changes, 0);
  const body = JSON.stringify({zen: 'local runtime test'});
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode('test-secret'), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  const signature = 'sha256=' + Buffer.from(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body))).toString('hex');
  const result = await service.dispatchFetch('https://worker.test/webhook', {method: 'POST', body, headers: {'x-github-event': 'ping', 'x-hub-signature-256': signature}});
  assert.equal(result.status, 200);
  const unsigned = await service.dispatchFetch('https://worker.test/webhook', {method: 'POST', body});
  assert.equal(unsigned.status, 401);
  const payload = {action: 'requested_action', installation: {id: 3}, repository: {id: 4, full_name: 'test/repo', default_branch: 'main'}, sender: {login: 'maintainer'}, requested_action: {identifier: 'repair-selected'}, check_run: {...check, pull_requests: [{number: 1}]}};
  const click = JSON.stringify(payload);
  const clickSignature = 'sha256=' + Buffer.from(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(click))).toString('hex');
  const options = {method: 'POST', body: click, headers: {'x-github-event': 'check_run', 'x-hub-signature-256': clickSignature, 'x-github-delivery': 'e330b54a-89e6-4d55-b766-0e46dd037055'}};
  assert.equal((await service.dispatchFetch('https://worker.test/webhook', options)).status, 200);
  assert.equal((await service.dispatchFetch('https://worker.test/webhook', options)).status, 200);
  assert.equal(dispatched.length, 1);
  assert.deepEqual(JSON.parse(dispatched[0].inputs.selections), items);
  console.log('Cloudflare runtime: signed ping, unsigned rejection, native crypto, D1 deduplication, and one selected dispatch passed.');
} finally {
  await service.dispose();
}
