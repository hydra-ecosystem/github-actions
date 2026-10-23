// Exercise the receiver in Cloudflare's local runtime. All GitHub calls are intercepted.
import assert from 'node:assert/strict';
import {createHmac, generateKeyPairSync, verify} from 'node:crypto';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';

const keys = generateKeyPairSync('rsa', {modulusLength: 2048,
  privateKeyEncoding: {type: 'pkcs8', format: 'pem'}});
const secret = 'native-runtime-fixture-secret';
const calls = [];
let slowGithub = false;
const service = new Miniflare(convertV4MiniflareOptions({
  modules: true,
  scriptPath: new URL('./worker.mjs', import.meta.url).pathname,
  compatibilityDate: '2026-10-19',
  bindings: {APP_ID: '42', APP_PRIVATE_KEY: keys.privateKey, WEBHOOK_SECRET: secret},
  outboundService: async request => {
    const url = new URL(request.url);
    assert.equal(url.origin, 'https://api.github.com');
    calls.push([request.method, url.pathname]);
    if (slowGithub) await new Promise(resolve => setTimeout(resolve, 5_000));
    if (url.pathname === '/app/installations/3/access_tokens') {
      assert.equal(request.method, 'POST');
      assert.deepEqual(await request.json(), {repository_ids: [7], permissions: {contents: 'read'}});
      const [header, claims, sig] = request.headers.get('authorization').slice('Bearer '.length).split('.');
      assert.equal(JSON.parse(Buffer.from(header, 'base64url')).alg, 'RS256');
      assert.equal(JSON.parse(Buffer.from(claims, 'base64url')).iss, '42');
      assert.equal(verify('RSA-SHA256', Buffer.from(`${header}.${claims}`), keys.publicKey, Buffer.from(sig, 'base64url')), true);
      return Response.json({token: 'ghs_42.native-fixture-token'});
    }
    assert.equal(url.pathname, '/repos/fixture/repo');
    assert.equal(request.method, 'GET');
    assert.equal(request.headers.get('authorization'), 'Bearer ghs_42.native-fixture-token');
    return Response.json({id: 7, full_name: 'fixture/repo'});
  },
}));

function signed(value, event = 'ping') {
  const body = JSON.stringify(value);
  return {method: 'POST', body, headers: {
    'x-github-event': event,
    'x-github-delivery': '94e535a5-2a7d-491d-858a-3df51ce211df',
    'x-hub-signature-256': 'sha256=' + createHmac('sha256', secret).update(body).digest('hex'),
  }};
}

try {
  assert.equal((await service.dispatchFetch('https://worker.test/webhook', signed({zen: 'native 🌍'}))).status, 200);
  const invalid = signed({zen: 'tampered'});
  invalid.headers['x-hub-signature-256'] = 'sha256=' + '0'.repeat(64);
  assert.equal((await service.dispatchFetch('https://worker.test/webhook', invalid)).status, 401);
  const body = new ReadableStream({start(controller) {
    for (let i = 0; i < 3; i++) controller.enqueue(new Uint8Array(800_000));
    controller.close();
  }});
  assert.equal((await service.dispatchFetch('https://worker.test/webhook', {
    method: 'POST', body, duplex: 'half', headers: {'x-hub-signature-256': 'sha256=' + '0'.repeat(64)},
  })).status, 413);
  assert.equal(calls.length, 0);
  const pr = {action: 'opened', installation: {id: 3}, repository: {id: 7, full_name: 'fixture/repo'}};
  assert.equal((await service.dispatchFetch('https://worker.test/webhook', signed(pr, 'pull_request'))).status, 200);
  assert.deepEqual(calls, [['POST', '/app/installations/3/access_tokens'], ['GET', '/repos/fixture/repo']]);
  assert.equal((await service.dispatchFetch('https://worker.test/webhook', signed({}, 'check_run'))).status, 200);
  assert.equal(calls.length, 2);
  slowGithub = true;
  const started = performance.now();
  const timedOut = await service.dispatchFetch('https://worker.test/webhook', signed(pr, 'pull_request'));
  const elapsed = performance.now() - started;
  assert.equal(timedOut.status, 500);
  assert.equal(await timedOut.text(), 'Webhook processing failed');
  assert.ok(elapsed >= 7_500 && elapsed < 9_500, `Shared deadline took ${elapsed} ms`);
  assert.deepEqual(calls.slice(2), [['POST', '/app/installations/3/access_tokens'], ['GET', '/repos/fixture/repo']]);
  console.log('Native Workers runtime passed: signed ping, invalid signature, streamed limit, RSA JWT, scoped read, shared 8-second deadline and no Check/dispatch writes.');
} finally {
  await service.dispose();
}

// A separate native Worker instance uses an actual local D1 binding. These
// constraints and concurrent admissions are not simulated with an object map.
const {readFileSync} = await import('node:fs');
const {createHash, randomUUID} = await import('node:crypto');
let nativeItems = [{name: 'launch-editor', from: '2.14.1', to: '2.14.2'}];
const nativePR = {number: 12, state: 'open', user: {type: 'Bot'},
  body: '<!-- node-repair:selection:v1 -->\n- [x] Allow `launch-editor` `2.14.1 → 2.14.2` by updating its explicit pin.\n<!-- /node-repair:selection -->',
  head: {sha: 'a'.repeat(40), ref: 'maintenance/node-security', repo: {id: 7}},
  base: {sha: 'b'.repeat(40), ref: 'main', repo: {id: 7}}};
let nativeFingerprint = createHash('sha256').update(JSON.stringify([12, nativePR.head.sha, nativePR.base.sha, nativeItems])).digest('hex');
const nativeCheck = {id: 77, app: {id: 42}, name: 'Dependency repair', head_sha: nativePR.head.sha,
  external_id: `node-repair:12:${nativeFingerprint}`, status: 'completed', conclusion: 'neutral'};
const documentedCheck = value => { const response = {...value}; delete response.actions; return response; };
const nativeCalls = [];
const admissionService = new Miniflare(convertV4MiniflareOptions({
  modules: true, scriptPath: new URL('./worker.mjs', import.meta.url).pathname,
  compatibilityDate: '2026-10-19', d1Databases: ['DB'],
  bindings: {APP_ID: '42', APP_PRIVATE_KEY: keys.privateKey, WEBHOOK_SECRET: secret},
  outboundService: async request => {
    const url = new URL(request.url), path = url.pathname;
    const body = request.method === 'POST' || request.method === 'PATCH' ? await request.json() : null;
    assert.equal(url.origin, 'https://api.github.com');
    assert.equal(request.headers.get('X-GitHub-Api-Version'), '2026-03-10');
    nativeCalls.push({method: request.method, path, body});
    if (path === '/app/installations/3/access_tokens') {
      assert.deepEqual(body.repository_ids, [7]);
      assert.equal(body.permissions.contents, 'read');
      assert.equal(body.permissions.checks, 'write');
      return Response.json({token: 'ghs_42.native-action-token'});
    }
    assert.equal(request.headers.get('authorization'), 'Bearer ghs_42.native-action-token');
    if (path === '/repos/fixture/repo') return Response.json({id: 7, full_name: 'fixture/repo', default_branch: 'main'});
    if (path === '/repos/fixture/repo/pulls/12') return Response.json(nativePR);
    if (path === '/repos/fixture/repo/collaborators/maintainer/permission') return Response.json({permission: 'maintain', user: {login: 'maintainer'}});
    if (path === '/repos/fixture/repo/check-runs/77') {
      if (request.method === 'PATCH') Object.assign(nativeCheck, body);
      return Response.json(request.method === 'GET' ? documentedCheck(nativeCheck) : nativeCheck);
    }
    if (path.includes('/commits/') && path.endsWith('/check-runs')) return Response.json({total_count: 1, check_runs: [documentedCheck(nativeCheck)]});
    assert.equal(path, '/repos/fixture/repo/actions/workflows/dependency-repair.yml/dispatches');
    assert.equal(request.method, 'POST');
    assert.equal(body.ref, 'main');
    assert.deepEqual(Object.keys(body.inputs), ['request-id', 'pull-request', 'expected-head', 'expected-base', 'selections']);
    assert.equal(body.inputs['pull-request'], '12');assert.equal(body.inputs['expected-head'], nativePR.head.sha);
    assert.equal(body.inputs['expected-base'], nativePR.base.sha);assert.equal(body.inputs.selections, JSON.stringify(nativeItems));
    return Response.json({workflow_run_id: 900, run_url: 'https://api.github.com/repos/fixture/repo/actions/runs/900',
      html_url: 'https://github.com/fixture/repo/actions/runs/900'});
  },
}));
try {
  const db = await admissionService.getD1Database('DB');
  await db.exec(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8').replaceAll('\n', ' '));
  const insert = (id, installation = 3, repository = 7) => db.prepare(`INSERT OR IGNORE INTO requests
    (id, installation_id, repository_id, repository, pr, head, base, dispatched_ref, fingerprint, check_id, actor_login, created_at, state)
    VALUES (?, ?, ?, 'fixture/repo', 12, ?, ?, 'main', ?, 77, 'maintainer', 1, 'reserved')`)
    .bind(id, installation, repository, nativePR.head.sha, nativePR.base.sha, nativeFingerprint).run();
  const admitted = await Promise.all(Array.from({length: 12}, () => insert(randomUUID())));
  assert.equal(admitted.reduce((sum, r) => sum + r.meta.changes, 0), 1);
  const winner = await db.prepare('SELECT id FROM requests').first();
  assert.equal((await insert(winner.id)).meta.changes, 0);
  assert.equal((await insert(randomUUID(), 4)).meta.changes, 1);
  assert.equal((await insert(randomUUID(), 3, 8)).meta.changes, 1);
  await db.prepare("UPDATE requests SET state = 'unknown' WHERE id = ?").bind(winner.id).run();
  assert.equal((await insert(randomUUID())).meta.changes, 0);
  await db.exec('DELETE FROM requests');
  const click = (id, checkRun = nativeCheck) => {
    const input = signed({action: 'requested_action', requested_action: {identifier: 'repair-selected'},
      installation: {id: 3}, repository: {id: 7, full_name: 'fixture/repo'},
      check_run: {...checkRun, app: {...checkRun.app}}, sender: {type: 'User', login: 'maintainer'}}, 'check_run');
    input.headers['x-github-delivery'] = id;
    return admissionService.dispatchFetch('https://worker.test/webhook', input);
  };
  const first = randomUUID();
  assert.deepEqual((await Promise.all([click(first), click(randomUUID())])).map(r => r.status), [200, 200]);
  assert.equal((await click(first)).status, 200);
  const rows = await db.prepare('SELECT * FROM requests').all();
  assert.equal(rows.results.length, 1);assert.equal(rows.results[0].state, 'dispatched');assert.equal(rows.results[0].run_id, 900);
  assert.equal(nativeCalls.filter(c => c.path.endsWith('/dispatches')).length, 1);
  assert.equal(nativeCheck.external_id, `node-repair-request:${rows.results[0].id}`);
  assert.equal(nativeCheck.status, 'in_progress');assert.deepEqual(nativeCheck.actions, []);

  // A queued A click must not admit the refreshed B selection or a changed base.
  await db.exec('DELETE FROM requests');
  nativePR.body = nativePR.body.replace('2.14.2', '2.14.3');
  nativeItems = [{name: 'launch-editor', from: '2.14.1', to: '2.14.3'}];
  nativeFingerprint = createHash('sha256').update(JSON.stringify([12, nativePR.head.sha, nativePR.base.sha, nativeItems])).digest('hex');
  Object.assign(nativeCheck, {external_id: `node-repair:12:${nativeFingerprint}`, status: 'completed', conclusion: 'neutral', actions: []});
  const queuedA = {id: nativeCheck.id, app: {...nativeCheck.app}, name: nativeCheck.name,
    head_sha: nativeCheck.head_sha, external_id: `node-repair:12:${createHash('sha256').update(JSON.stringify([12, nativePR.head.sha, 'b'.repeat(40), [{name: 'launch-editor', from: '2.14.1', to: '2.14.2'}]])).digest('hex')}`,
    status: 'completed', conclusion: 'neutral'};
  const staleSelection = await click(randomUUID(), queuedA);
  assert.equal(staleSelection.status, 200);
  assert.equal((await db.prepare('SELECT * FROM requests').all()).results.length, 0);
  assert.equal(nativeCalls.filter(c => c.path.endsWith('/dispatches')).length, 1);

  const queuedB = {...nativeCheck, app: {...nativeCheck.app}};
  nativePR.base.sha = 'c'.repeat(40);
  nativeFingerprint = createHash('sha256').update(JSON.stringify([12, nativePR.head.sha, nativePR.base.sha, nativeItems])).digest('hex');
  Object.assign(nativeCheck, {external_id: `node-repair:12:${nativeFingerprint}`, status: 'completed', conclusion: 'neutral', actions: []});
  const staleBase = await click(randomUUID(), queuedB);
  assert.equal(staleBase.status, 200);
  assert.equal((await db.prepare('SELECT * FROM requests').all()).results.length, 0);
  assert.equal(nativeCalls.filter(c => c.path.endsWith('/dispatches')).length, 1);

  const missingIdentity = {...queuedB};
  delete missingIdentity.head_sha; delete missingIdentity.external_id;
  assert.equal((await click(randomUUID(), missingIdentity)).status, 200);
  assert.equal((await db.prepare('SELECT * FROM requests').all()).results.length, 0);

  const fresh = await click(randomUUID(), {...nativeCheck, app: {...nativeCheck.app}});
  assert.equal(fresh.status, 200);
  const freshRows = await db.prepare('SELECT * FROM requests').all();
  assert.equal(freshRows.results.length, 1);
  assert.equal(nativeCalls.filter(c => c.path.endsWith('/dispatches')).length, 2);
  assert.equal(JSON.parse(nativeCalls.findLast(c => c.path.endsWith('/dispatches')).body.inputs.selections)[0].to, '2.14.3');
  console.log('Native D1 passed: concurrent atomic admission, UUID replay, scoped active locks, ambiguous-lock retention, complete clicked Check identity binding across stale selection/base changes, missing identity rejection, and one fresh exact dispatch.');
} finally {
  await admissionService.dispose();
}
