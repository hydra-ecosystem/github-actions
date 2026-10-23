import assert from 'node:assert/strict';
import {createHmac, createPrivateKey, generateKeyPairSync, verify} from 'node:crypto';
import {beforeEach, test} from 'node:test';
import {readFileSync} from 'node:fs';
import worker, {api, installationToken, selections, selectionFingerprint, verifySignature, workflowInputs} from './worker.mjs';

const keys = generateKeyPairSync('rsa', {modulusLength: 2048,
  privateKeyEncoding: {type: 'pkcs8', format: 'pem'}});
const env = {APP_ID: '42', APP_PRIVATE_KEY: keys.privateKey, WEBHOOK_SECRET: 'unit-fixture-secret'};
const delivery = '94e535a5-2a7d-491d-858a-3df51ce211df';
const payload = {action: 'opened', installation: {id: 3}, repository: {id: 7, full_name: 'fixture/repo'}};
const token = 'ghs_42.opaque.installation-token';
const json = value => new Response(JSON.stringify(value), {headers: {'Content-Type': 'application/json'}});
const signature = bytes => 'sha256=' + createHmac('sha256', env.WEBHOOK_SECRET).update(bytes).digest('hex');

function signed(value, event = 'ping', headers = {}) {
  const body = typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value);
  return new Request('https://worker.test/webhook', {method: 'POST', body, headers: {
    'x-github-event': event, 'x-github-delivery': delivery, 'x-hub-signature-256': signature(body), ...headers,
  }});
}

beforeEach(t => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('Unexpected network request'); });
});

function githubMock(repository = {id: 7, full_name: 'fixture/repo'}, tokenReply = {token}) {
  const calls = [];
  globalThis.fetch.mock.mockImplementation(async (url, options) => {
    const path = new URL(url).pathname;
    assert.equal(new URL(url).origin, 'https://api.github.com');
    assert.equal(options.redirect, 'manual');
    assert.ok(options.signal instanceof AbortSignal);
    assert.equal(options.headers['X-GitHub-Api-Version'], '2026-03-10');
    calls.push({path, options});
    if (path === '/app/installations/3/access_tokens') return json(tokenReply);
    if (path === '/repos/fixture/repo') return json(repository);
    throw new Error('Unexpected API path');
  });
  return calls;
}

test('GitHub documented HMAC vector and malformed signatures', async () => {
  // https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
  const body = new TextEncoder().encode('Hello, World!');
  assert.equal(await verifySignature("It's a Secret to Everybody", body,
    'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17'), true);
  for (const header of [null, '', 'sha1=123', 'sha256=00', 'sha256=' + 'g'.repeat(64)]) {
    assert.equal(await verifySignature(env.WEBHOOK_SECRET, body, header), false);
  }
});

test('signed Unicode ping uses original bytes; tampering and missing signatures reject', async () => {
  const body = '{ "zen": "hello 🌍" }\r\n';
  assert.equal((await worker.fetch(signed(body), env)).status, 200);
  const tampered = signed('{"zen":"hello 🌍"}', 'ping', {'x-hub-signature-256': signature(body)});
  assert.equal((await worker.fetch(tampered, env)).status, 401);
  assert.equal((await worker.fetch(signed({}, 'ping', {'x-hub-signature-256': ''}), env)).status, 401);
  assert.equal(fetch.mock.callCount(), 0);
});

test('only the configured POST webhook route is served', async () => {
  for (const [method, path] of [['GET', '/webhook'], ['POST', '/other']]) {
    assert.equal((await worker.fetch(new Request(`https://worker.test${path}`, {method}), {})).status, 404);
  }
  for (const override of [{WEBHOOK_SECRET: ''}, {APP_PRIVATE_KEY: 1}, {APP_ID: '0'}, {APP_ID: ''}]) {
    assert.equal((await worker.fetch(signed({}), {...env, ...override})).status, 503);
  }
  assert.equal(fetch.mock.callCount(), 0);
});

test('signed ignored events and unhandled PR actions perform no API calls', async () => {
  for (const event of ['ping', 'issues', 'check_run', 'workflow_run']) {
    assert.equal((await worker.fetch(signed({}, event), env)).status, 200);
  }
  assert.equal((await worker.fetch(signed({...payload, action: 'closed'}, 'pull_request'), env)).status, 200);
  assert.equal(fetch.mock.callCount(), 0);
});

test('invalid delivery IDs, JSON and UTF-8 fail without exposing payload data', async () => {
  const requests = [signed({}, 'ping', {'x-github-delivery': ''}), signed({}, 'ping', {'x-github-delivery': 'invalid'}),
    signed('private-payload'), signed('null'), signed('[]'), signed('42'), signed(Buffer.from([0xff]))];
  requests.push(new Request('https://worker.test/webhook', {method: 'POST', headers: {
    'x-github-event': 'ping', 'x-github-delivery': delivery, 'x-hub-signature-256': signature(''),
  }}));
  for (const request of requests) {
    const response = await worker.fetch(request, env);
    assert.equal(response.status, 500);
    assert.equal(await response.text(), 'Webhook processing failed');
  }
  assert.equal(fetch.mock.callCount(), 0);
});

test('body limit accepts exactly two million bytes and rejects an advertised excess before reading', async () => {
  const body = JSON.stringify({zen: 'x'.repeat(2_000_000 - 10)});
  assert.equal(Buffer.byteLength(body), 2_000_000);
  assert.equal((await worker.fetch(signed(body), env)).status, 200);
  const excessive = signed({}, 'ping', {'content-length': '2000001'});
  assert.equal((await worker.fetch(excessive, env)).status, 413);
  assert.equal(excessive.bodyUsed, false);
  assert.equal(fetch.mock.callCount(), 0);
});

test('oversized streams reject even when cancellation fails or never settles', {timeout: 2_000}, async () => {
  for (const cancellation of ['ok', 'reject', 'pending']) {
    let pulled = 0, cancelled = false;
    const body = new ReadableStream({
      pull(controller) {
        pulled++;
        controller.enqueue(new Uint8Array(700_000));
        if (pulled === 20) controller.close();
      },
      cancel() {
        cancelled = true;
        if (cancellation === 'reject') throw new Error('fixture cancellation failure');
        if (cancellation === 'pending') return new Promise(() => {});
      },
    });
    const request = new Request('https://worker.test/webhook', {method: 'POST', body, duplex: 'half',
      headers: {'content-length': '1', 'x-hub-signature-256': 'sha256=' + '0'.repeat(64)}});
    assert.equal((await worker.fetch(request, env)).status, 413);
    assert.equal(cancelled, true);
    assert.ok(pulled < 20);
  }
  assert.equal(fetch.mock.callCount(), 0);
});

test('a failing input stream returns a sanitized processing failure', async () => {
  const body = new ReadableStream({start(controller) { controller.error(new Error('private-stream-data')); }});
  const response = await worker.fetch(new Request('https://worker.test/webhook', {method: 'POST', body, duplex: 'half'}), env);
  assert.equal(response.status, 500);
  assert.equal(await response.text(), 'Webhook processing failed');
});

function shortenWebhookDeadline(t) {
  const original = globalThis.setTimeout;
  const budgets = [];
  t.mock.method(globalThis, 'setTimeout', (callback, delay, ...args) => {
    if (delay === 8_000) budgets.push(delay);
    return original(callback, delay === 8_000 ? 160 : delay, ...args);
  });
  return budgets;
}

test('the webhook deadline cancels stalled input without waiting for cancellation', {timeout: 2_000}, async t => {
  const budgets = shortenWebhookDeadline(t);
  let cancelled = false;
  const body = new ReadableStream({cancel() { cancelled = true; return new Promise(() => {}); }});
  const response = await worker.fetch(new Request('https://worker.test/webhook', {
    method: 'POST', body, duplex: 'half',
  }), env);
  assert.equal(response.status, 500);
  assert.equal(await response.text(), 'Webhook processing failed');
  assert.equal(cancelled, true);
  assert.deepEqual(budgets, [8_000]);
  assert.equal(fetch.mock.callCount(), 0);
});

for (const scenario of ['stalled token', 'slow sequential reads']) {
  test(`one webhook deadline bounds ${scenario}`, {timeout: 2_000}, async t => {
    const budgets = shortenWebhookDeadline(t);
    const signals = [];
    fetch.mock.mockImplementation(async (url, options) => {
      signals.push(options.signal);
      await new Promise((resolve, reject) => {
        const timer = scenario === 'stalled token' ? null : setTimeout(resolve, 90);
        const abort = () => { clearTimeout(timer); reject(new Error('private upstream timeout')); };
        if (options.signal.aborted) abort();
        else options.signal.addEventListener('abort', abort, {once: true});
      });
      return json(new URL(url).pathname.endsWith('/access_tokens') ? {token} : {id: 7, full_name: 'fixture/repo'});
    });
    const response = await worker.fetch(signed(payload, 'pull_request'), env);
    assert.equal(response.status, 500);
    assert.equal(await response.text(), 'Webhook processing failed');
    assert.equal(signals.length, scenario === 'stalled token' ? 1 : 2);
    assert.ok(signals.every(signal => signal === signals[0] && signal.aborted));
    assert.deepEqual(budgets, [8_000]);
  });
}

for (const type of ['pkcs8', 'pkcs1']) test(`PR deliveries sign with ${type} and use one repository-scoped read-only token`, async () => {
  const calls = githubMock({id: 7, full_name: 'Fixture/Repo'});
  const pem = createPrivateKey(keys.privateKey).export({type, format: 'pem'}).replaceAll('\n', '\r\n');
  assert.equal((await worker.fetch(signed(payload, 'pull_request'), {...env, APP_PRIVATE_KEY: pem})).status, 200);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].options.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].options.body), {repository_ids: [7], permissions: {contents: 'read'}});
  const jwt = calls[0].options.headers.Authorization.slice('Bearer '.length);
  const [header, claims, sig] = jwt.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url')), {alg: 'RS256', typ: 'JWT'});
  const decoded = JSON.parse(Buffer.from(claims, 'base64url'));
  assert.equal(decoded.iss, '42');
  assert.equal(decoded.exp - decoded.iat, 600);
  const now = Math.floor(Date.now() / 1000);
  assert.ok(decoded.iat <= now && decoded.iat >= now - 120);
  assert.ok(decoded.exp > now && decoded.exp <= now + 600);
  assert.equal(verify('RSA-SHA256', Buffer.from(`${header}.${claims}`), keys.publicKey, Buffer.from(sig, 'base64url')), true);
  assert.equal(calls[1].path, '/repos/fixture/repo');
  assert.equal(calls[1].options.method, 'GET');
  assert.equal(calls[1].options.headers.Authorization, `Bearer ${token}`);
  assert.equal(calls[1].options.body, undefined);
});

test('each subscribed PR action is a read-only handshake', async () => {
  for (const action of ['edited', 'synchronize', 'reopened']) {
    const calls = githubMock();
    assert.equal((await worker.fetch(signed({...payload, action}, 'pull_request'), env)).status, 200);
    assert.deepEqual(calls.map(call => [call.options.method, call.path]), [
      ['POST', '/app/installations/3/access_tokens'], ['GET', '/repos/fixture/repo'],
    ]);
  }
});

test('invalid installation/repository IDs and names cannot reach the API', async () => {
  for (const id of [0, -1, '3', null, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(installationToken(env, id, 7), /Invalid installation/);
    await assert.rejects(installationToken(env, 3, id), /Invalid installation/);
  }
  const invalid = [{...payload, installation: {}}, {...payload, repository: {id: 7}},
    {...payload, repository: {id: 7, full_name: 'fixture/repo/../other'}}, {...payload, repository: null}];
  for (const value of invalid) assert.equal((await worker.fetch(signed(value, 'pull_request'), env)).status, 500);
  assert.equal(fetch.mock.callCount(), 0);
});

test('missing, empty or invalid token responses never cause a repository request', async () => {
  for (const result of [null, {}, {token: 42}, {token: ''}, {token: '  '}]) {
    const calls = githubMock(undefined, result);
    assert.equal((await worker.fetch(signed(payload, 'pull_request'), env)).status, 500);
    assert.equal(calls.length, 1);
  }
});

test('canonical repository mismatch and invalid private keys fail closed', async () => {
  for (const repository of [null, {id: 8, full_name: 'fixture/repo'}, {id: 7, full_name: 'fixture/other'}]) {
    const calls = githubMock(repository);
    assert.equal((await worker.fetch(signed(payload, 'pull_request'), env)).status, 500);
    assert.equal(calls.length, 2);
  }
  const calls = githubMock();
  assert.equal((await worker.fetch(signed(payload, 'pull_request'), {...env, APP_PRIVATE_KEY: 'invalid'})).status, 500);
  assert.equal(calls.length, 0);
});

test('API redirects and error responses are not followed or disclosed', async () => {
  for (const status of [302, 403, 500]) {
    fetch.mock.mockImplementation(async (_url, options) => {
      assert.equal(options.redirect, 'manual');
      return new Response('private-upstream-data', {status, headers: {Location: 'https://other.test'}});
    });
    await assert.rejects(api(token, '/repos/fixture/repo'), error => error.status === status && !error.message.includes('private-upstream-data'));
  }
});

test('network and invalid upstream JSON errors stay sanitized in the client and receiver', async () => {
  fetch.mock.mockImplementation(async () => { throw new Error('private-network-data'); });
  await assert.rejects(api(token, '/repos/fixture/repo'), /^Error: GitHub request failed$/);
  const response = await worker.fetch(signed(payload, 'pull_request'), env);
  assert.equal(response.status, 500);
  assert.equal(await response.text(), 'Webhook processing failed');
  fetch.mock.mockImplementation(async () => new Response('private-invalid-json'));
  await assert.rejects(api(token, '/repos/fixture/repo'), /^Error: Invalid GitHub response$/);
});

const fixtures = JSON.parse(readFileSync(new URL('./selection-fixtures.json', import.meta.url), 'utf8'));
const selectionPR = {number: fixtures.pr.number, head: {sha: fixtures.pr.head_sha}, base: {sha: fixtures.pr.base_sha}};
for (const fixture of fixtures.cases) {
  test(`C1 fixture: ${fixture.name}`, async () => {
    if (fixture.invalid) assert.throws(() => selections(fixture.body));
    else {
      const items = selections(fixture.body);
      assert.deepEqual(items, fixture.items);
      assert.equal(await selectionFingerprint(selectionPR, items), fixture.fingerprint);
    }
  });
}

test('C1 fingerprint binds the PR, head, base and sorted selected versions', async () => {
  const items = selections(fixtures.cases[0].body);
  const original = await selectionFingerprint(selectionPR, items);
  for (const changed of [{...selectionPR, number: 13}, {...selectionPR, head: {sha: 'c'.repeat(40)}},
    {...selectionPR, base: {sha: 'c'.repeat(40)}}]) {
    assert.notEqual(await selectionFingerprint(changed, items), original);
  }
  assert.notEqual(await selectionFingerprint(selectionPR, [{...items[0], to: '2.14.3'}]), original);
});

function checkMock({changePR, list = {total_count: 0, check_runs: []}, failPath} = {}) {
  const repository = {id: 7, full_name: 'fixture/repo', default_branch: 'main'};
  const pr = {number: 12, state: 'open', user: {type: 'Bot'}, body: fixtures.cases[0].body,
    head: {sha: 'a'.repeat(40), ref: 'maintenance/node-security', repo: {id: 7}},
    base: {sha: 'b'.repeat(40), ref: 'main', repo: {id: 7}}};
  changePR?.(pr, repository);
  const calls = [];
  fetch.mock.mockImplementation(async (url, options) => {
    const path = new URL(url).pathname;
    const body = options.body === undefined ? undefined : JSON.parse(options.body);
    calls.push({path, url, method: options.method, body, signal: options.signal});
    assert.equal(options.redirect, 'manual');
    if (path === failPath) return new Response('private upstream failure', {status: 403});
    if (path === '/app/installations/3/access_tokens') return json({token});
    assert.equal(options.headers.Authorization, `Bearer ${token}`);
    if (path === '/repos/fixture/repo') return json(repository);
    if (path === '/repos/fixture/repo/pulls/12') return json(pr);
    if (path === `/repos/fixture/repo/commits/${pr.head.sha}/check-runs`) {
      const query = new URL(url).searchParams;
      assert.equal(query.get('app_id'), env.APP_ID);
      assert.equal(query.get('filter'), 'all');
      assert.equal(query.get('check_name'), 'Dependency repair');
      assert.equal(query.get('per_page'), '100');
      return json({...list, check_runs: list.check_runs.map(check => {
        const response = {...check}; delete response.actions; return response;
      })});
    }
    if (path === '/repos/fixture/repo/check-runs' || path === '/repos/fixture/repo/check-runs/77' ||
        path === '/repos/fixture/repo/check-runs/78') return json({id: 77});
    throw new Error(`Unexpected API path: ${path}`);
  });
  return {calls, pr, repository};
}
const ownCheck = (overrides = {}) => ({id: 77, app: {id: 42}, name: 'Dependency repair',
  head_sha: 'a'.repeat(40), external_id: 'node-repair:12:33b17f82caff79dd2065972e92b5e5b83aa761be9c5799dcbbced028f0f60849', status: 'completed', ...overrides});
const listOf = (...checks) => ({total_count: checks.length, check_runs: checks});
const checkWrites = calls => calls.filter(call => call.path.includes('/check-runs') && call.method !== 'GET');
const managedPR = (body, headSha = 'a'.repeat(40), state = 'open') => ({number: 12, state, user: {type: 'Bot'}, body,
  head: {sha: headSha, ref: 'maintenance/node-security', repo: {id: 7}},
  base: {sha: 'b'.repeat(40), ref: 'main', repo: {id: 7}}});

test('canonical bot PR creates an App Check with exact selections and no action or dispatch', async () => {
  const {calls, pr} = checkMock();
  // Event-local PR identity and body are not used as approval evidence.
  const event = {...payload, number: 12, pull_request: {user: {type: 'User'}, head: {ref: 'other'}, body: 'forged'}};
  assert.equal((await worker.fetch(signed(event, 'pull_request'), env)).status, 200);
  assert.deepEqual(calls[0].body, {repository_ids: [7], permissions: {contents: 'read', pull_requests: 'read', checks: 'write'}});
  assert.ok(calls.every(call => call.signal === calls[0].signal));
  const writes = checkWrites(calls); assert.equal(writes.length, 1);
  assert.equal(writes[0].method, 'POST');
  assert.deepEqual(writes[0].body, {name: 'Dependency repair', head_sha: pr.head.sha,
    external_id: `node-repair:12:${await selectionFingerprint(pr, selections(pr.body))}`,
    status: 'completed', conclusion: 'neutral', output: {title: '1 selected fix',
      summary: '- `launch-editor` `2.14.1 → 2.14.2`\n\nSelections are displayed for review. Running fixes is not enabled yet.'}, actions: []});
  assert.equal(calls.length, 6);
});

for (const action of ['opened', 'edited', 'synchronize', 'reopened']) {
  test(`managed PR ${action} refreshes its own idle Check`, async () => {
    const {calls} = checkMock({list: listOf(ownCheck())});
    assert.equal((await worker.fetch(signed({...payload, action, number: 12}, 'pull_request'), env)).status, 200);
    const writes = checkWrites(calls); assert.equal(writes.length, 1);
    assert.equal(writes[0].path, '/repos/fixture/repo/check-runs/77');
    assert.equal(writes[0].method, 'PATCH');
    assert.deepEqual(writes[0].body.actions, []);
    assert.equal(writes[0].body.head_sha, undefined);
  });
}

test('selection edits and clearing the block replace the idle fingerprint and summary', async () => {
  const versions = [], identities = [];
  for (const body of [fixtures.cases[0].body, fixtures.cases[0].body.replace('2.14.2', '2.14.3'),
    fixtures.cases[1].body, 'malformed selection']) {
    const {calls} = checkMock({changePR: pr => { pr.body = body; }, list: listOf(ownCheck())});
    assert.equal((await worker.fetch(signed({...payload, number: 12}, 'pull_request'), env)).status, 200);
    const output = checkWrites(calls)[0].body;
    identities.push(output.external_id);versions.push(output.output.summary);
    assert.deepEqual(output.actions, []);
  }
  assert.notEqual(identities[0], identities[1]);assert.notEqual(identities[1], identities[2]);
  assert.match(versions[1], /2\.14\.3/);assert.doesNotMatch(versions[2], /launch-editor/);
  assert.match(versions[3], /valid selection block/);
});

for (const [name, body] of [['changed', fixtures.cases[0].body.replace('2.14.2', '2.14.3')],
  ['cleared', fixtures.cases[1].body]]) {
  test(`a ${name} selection creates a new Check when the list response omits actions`, async () => {
    const {calls, pr} = checkMock({changePR: current => { current.body = body; }, list: listOf(ownCheck())});
    assert.equal((await worker.fetch(signed({...payload, number: 12, action: 'edited'}, 'pull_request'), env)).status, 200);
    const writes = checkWrites(calls);
    assert.equal(writes.length, 1);
    assert.equal(writes[0].method, 'POST');
    assert.equal(writes[0].path, '/repos/fixture/repo/check-runs');
    assert.equal(writes[0].body.external_id, `node-repair:12:${await selectionFingerprint(pr, selections(pr.body))}`);
  });
}

test('head synchronization creates a Check on the canonical new head', async () => {
  const {calls, pr} = checkMock({changePR: pr => { pr.head.sha = 'c'.repeat(40); }});
  assert.equal((await worker.fetch(signed({...payload, number: 12, action: 'synchronize',
    pull_request: {head: {sha: 'a'.repeat(40)}}}, 'pull_request'), env)).status, 200);
  const output = checkWrites(calls)[0].body;
  assert.equal(output.head_sha, 'c'.repeat(40));
  assert.equal(output.external_id, `node-repair:12:${await selectionFingerprint(pr, selections(pr.body))}`);
});

for (const [name, changePR] of [
  ['closed', pr => { pr.state = 'closed'; }], ['human author', pr => { pr.user.type = 'User'; }],
  ['missing author', pr => { pr.user = null; }], ['fork', pr => { pr.head.repo.id = 99; }],
  ['wrong base repository', pr => { pr.base.repo.id = 99; }], ['deleted head repository', pr => { pr.head.repo = null; }],
  ['wrong branch', pr => { pr.head.ref = 'feature'; }], ['stale default branch', pr => { pr.base.ref = 'master'; }],
  ['wrong PR number', pr => { pr.number = 13; }], ['bad head SHA', pr => { pr.head.sha = 'bad'; }],
  ['bad base SHA', pr => { pr.base.sha = 'bad'; }],
  ['missing default branch', (pr, repo) => { delete repo.default_branch; delete pr.base.ref; }],
]) {
  test(`canonical ${name} PR cannot write a Check`, async () => {
    const {calls} = checkMock({changePR});
    assert.equal((await worker.fetch(signed({...payload, number: 12}, 'pull_request'), env)).status, 200);
    assert.equal(checkWrites(calls).length, 0);assert.equal(calls.length, 3);
  });
}

test('canonical current default branch is used after a repository rename', async () => {
  const {calls} = checkMock({changePR: (pr, repo) => { repo.default_branch = 'trunk'; pr.base.ref = 'trunk'; }});
  assert.equal((await worker.fetch(signed({...payload, number: 12}, 'pull_request'), env)).status, 200);
  assert.equal(checkWrites(calls).length, 1);
});

for (const foreign of [ownCheck({app: {id: 999}}), ownCheck({name: 'Other Check'}),
  ownCheck({head_sha: 'c'.repeat(40)}), ownCheck({external_id: 'node-repair:13:' + '0'.repeat(64)}),
  ownCheck({external_id: 'unrelated'})]) {
  test(`unrelated Check is never reused: ${JSON.stringify(foreign)}`, async () => {
    const {calls} = checkMock({list: listOf(foreign)});
    assert.equal((await worker.fetch(signed({...payload, number: 12}, 'pull_request'), env)).status, 200);
    assert.equal(checkWrites(calls)[0].method, 'POST');
    assert.equal(checkWrites(calls)[0].path, '/repos/fixture/repo/check-runs');
  });
}

for (const list of [{}, {total_count: 101, check_runs: []}, {total_count: -1, check_runs: []},
  {total_count: 1, check_runs: []}, listOf(ownCheck({id: 0})), listOf(ownCheck({id: '77'})),
  listOf(ownCheck({status: 'in_progress'}))]) {
  test(`incomplete or non-idle Check state fails without a write: ${JSON.stringify(list)}`, async () => {
    const {calls} = checkMock({list});
    assert.equal((await worker.fetch(signed({...payload, number: 12}, 'pull_request'), env)).status, 500);
    assert.equal(checkWrites(calls).length, 0);
  });
}

test('duplicate owned idle Checks refresh the newest Check', async () => {
  const {calls} = checkMock({list: listOf(ownCheck({id: 78}), ownCheck({id: 77}))});
  assert.equal((await worker.fetch(signed({...payload, number: 12}, 'pull_request'), env)).status, 200);
  const writes = checkWrites(calls);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].path, '/repos/fixture/repo/check-runs/78');
  assert.equal(writes[0].method, 'PATCH');
  assert.deepEqual(writes[0].body.actions, []);
});

test('overlapping initial deliveries recover from duplicate idle Checks on a later edit', async () => {
  const repository = {id: 7, full_name: 'fixture/repo', default_branch: 'main'};
  const pr = {number: 12, state: 'open', user: {type: 'Bot'}, body: fixtures.cases[0].body,
    head: {sha: 'a'.repeat(40), ref: 'maintenance/node-security', repo: {id: 7}},
    base: {sha: 'b'.repeat(40), ref: 'main', repo: {id: 7}}};
  const calls = [], created = [];
  let phase = 'initial', listCalls = 0, resolveLists;
  const listsReady = new Promise(resolve => { resolveLists = resolve; });
  fetch.mock.mockImplementation(async (url, options) => {
    const path = new URL(url).pathname;
    const body = options.body === undefined ? undefined : JSON.parse(options.body);
    calls.push({path, method: options.method, body});
    assert.equal(options.redirect, 'manual');
    if (path === '/app/installations/3/access_tokens') return json({token});
    assert.equal(options.headers.Authorization, `Bearer ${token}`);
    if (path === '/repos/fixture/repo') return json(repository);
    if (path === '/repos/fixture/repo/pulls/12') return json(pr);
    if (path === `/repos/fixture/repo/commits/${pr.head.sha}/check-runs`) {
      if (phase === 'initial') {
        listCalls++;
        if (listCalls === 2) resolveLists();
        await listsReady;
        return json({total_count: 0, check_runs: []});
      }
      return json(listOf(ownCheck({id: 77}), ownCheck({id: 78})));
    }
    if (path === '/repos/fixture/repo/check-runs') {
      created.push(body);
      return json({id: created.length === 1 ? 77 : 78});
    }
    if (path === '/repos/fixture/repo/check-runs/78') return json({id: 78});
    throw new Error(`Unexpected API path: ${path}`);
  });

  const first = worker.fetch(signed({...payload, number: 12, action: 'opened'}, 'pull_request'), env);
  const second = worker.fetch(signed({...payload, number: 12, action: 'opened'}, 'pull_request'), env);
  const initialResponses = await Promise.all([first, second]);
  assert.deepEqual(initialResponses.map(response => response.status), [200, 200]);
  assert.equal(listCalls, 2);
  assert.equal(created.length, 2);

  phase = 'edit';
  pr.body = fixtures.cases[0].body.replace('2.14.2', '2.14.3');
  const edit = await worker.fetch(signed({...payload, number: 12, action: 'edited'}, 'pull_request'), env);
  assert.equal(edit.status, 200);
  const writes = checkWrites(calls);
  assert.deepEqual(writes.slice(0, 2).map(write => write.method), ['POST', 'POST']);
  assert.equal(writes.length, 3);
  assert.equal(writes[2].path, '/repos/fixture/repo/check-runs');
  assert.equal(writes[2].method, 'POST');
  assert.match(writes[2].body.output.summary, /2\.14\.3/);
  assert.deepEqual(writes[2].body.actions, []);
});

test('overlapping edits reconcile an existing Check to the current canonical selection', async () => {
  const repository = {id: 7, full_name: 'fixture/repo', default_branch: 'main'};
  let body = fixtures.cases[0].body;
  const calls = [], writes = [];
  let listCalls = 0, releaseFirstList, markFirstList;
  const firstListReached = new Promise(resolve => { markFirstList = resolve; });
  const firstListHold = new Promise(resolve => { releaseFirstList = resolve; });
  fetch.mock.mockImplementation(async (url, options) => {
    const path = new URL(url).pathname;
    const requestBody = options.body === undefined ? undefined : JSON.parse(options.body);
    calls.push({path, method: options.method, body: requestBody});
    assert.equal(options.redirect, 'manual');
    if (path === '/app/installations/3/access_tokens') return json({token});
    assert.equal(options.headers.Authorization, `Bearer ${token}`);
    if (path === '/repos/fixture/repo') return json(repository);
    if (path === '/repos/fixture/repo/pulls/12') return json(managedPR(body));
    if (path === `/repos/fixture/repo/commits/${'a'.repeat(40)}/check-runs`) {
      if (++listCalls === 1) { markFirstList(); await firstListHold; }
      return json(listOf(ownCheck()));
    }
    if (path === '/repos/fixture/repo/check-runs/77' && options.method === 'PATCH') {
      writes.push(requestBody);
      return json({id: 77});
    }
    if (path === '/repos/fixture/repo/check-runs' && options.method === 'POST') {
      writes.push(requestBody);
      return json({id: 78});
    }
    throw new Error(`Unexpected API path: ${options.method} ${path}`);
  });

  const older = worker.fetch(signed({...payload, number: 12, action: 'edited'}, 'pull_request'), env);
  await firstListReached;
  body = fixtures.cases[0].body.replace('2.14.2', '2.14.3');
  const newer = worker.fetch(signed({...payload, number: 12, action: 'edited'}, 'pull_request',
    {'x-github-delivery': '94e535a5-2a7d-491d-858a-3df51ce211de'}), env);
  const newerResponse = await newer;
  releaseFirstList();
  const olderResponse = await older;
  assert.equal(newerResponse.status, 200);
  assert.equal(olderResponse.status, 200);
  assert.equal(writes.length, 3);
  assert.match(writes[0].output.summary, /2\.14\.3/);
  assert.match(writes[1].output.summary, /2\.14\.2/);
  assert.match(writes[2].output.summary, /2\.14\.3/);
  assert.equal(writes[0].external_id, writes[2].external_id);
  assert.notEqual(writes[1].external_id, writes[2].external_id);
  assert.ok(writes.every(write => write.actions.length === 0));
});

test('repeated canonical changes exhaust bounded Check reconciliation', async () => {
  const repository = {id: 7, full_name: 'fixture/repo', default_branch: 'main'};
  const writes = [];
  let prReads = 0, currentExternal;
  fetch.mock.mockImplementation(async (url, options) => {
    const path = new URL(url).pathname;
    const requestBody = options.body === undefined ? undefined : JSON.parse(options.body);
    assert.equal(options.redirect, 'manual');
    if (path === '/app/installations/3/access_tokens') return json({token});
    assert.equal(options.headers.Authorization, `Bearer ${token}`);
    if (path === '/repos/fixture/repo') return json(repository);
    if (path === '/repos/fixture/repo/pulls/12') {
      prReads++;
      const current = managedPR(fixtures.cases[0].body.replace('2.14.2', `2.14.${prReads + 1}`));
      currentExternal = `node-repair:12:${await selectionFingerprint(current, selections(current.body))}`;
      return json(current);
    }
    if (path === `/repos/fixture/repo/commits/${'a'.repeat(40)}/check-runs`)
      return json(listOf(ownCheck({external_id: currentExternal})));
    if (path === '/repos/fixture/repo/check-runs/77' && options.method === 'PATCH') {
      writes.push(requestBody);
      return json({id: 77});
    }
    throw new Error(`Unexpected API path: ${options.method} ${path}`);
  });
  const response = await worker.fetch(signed({...payload, number: 12, action: 'edited'}, 'pull_request'), env);
  assert.equal(response.status, 500);
  assert.equal(prReads, 6);
  assert.equal(writes.length, 3);
  assert.deepEqual(writes.map(write => write.actions), [[], [], []]);
});

test('eligibility loss after a Check write stops reconciliation safely', async () => {
  const repository = {id: 7, full_name: 'fixture/repo', default_branch: 'main'};
  let prReads = 0;
  const writes = [];
  fetch.mock.mockImplementation(async (url, options) => {
    const path = new URL(url).pathname;
    const requestBody = options.body === undefined ? undefined : JSON.parse(options.body);
    assert.equal(options.redirect, 'manual');
    if (path === '/app/installations/3/access_tokens') return json({token});
    assert.equal(options.headers.Authorization, `Bearer ${token}`);
    if (path === '/repos/fixture/repo') return json(repository);
    if (path === '/repos/fixture/repo/pulls/12') {
      prReads++;
      return json(managedPR(fixtures.cases[0].body, 'a'.repeat(40), prReads === 2 ? 'closed' : 'open'));
    }
    if (path === `/repos/fixture/repo/commits/${'a'.repeat(40)}/check-runs`) return json(listOf(ownCheck()));
    if (path === '/repos/fixture/repo/check-runs/77' && options.method === 'PATCH') {
      writes.push(requestBody);
      return json({id: 77});
    }
    throw new Error(`Unexpected API path: ${options.method} ${path}`);
  });
  const response = await worker.fetch(signed({...payload, number: 12, action: 'edited'}, 'pull_request'), env);
  assert.equal(response.status, 200);
  assert.equal(prReads, 2);
  assert.equal(writes.length, 1);
  assert.deepEqual(writes[0].actions, []);
});

test('head changes during reconciliation refresh the new canonical head', async () => {
  const repository = {id: 7, full_name: 'fixture/repo', default_branch: 'main'};
  const oldHead = 'a'.repeat(40), newHead = 'c'.repeat(40);
  let prReads = 0;
  const calls = [];
  fetch.mock.mockImplementation(async (url, options) => {
    const path = new URL(url).pathname;
    const requestBody = options.body === undefined ? undefined : JSON.parse(options.body);
    calls.push({path, method: options.method, body: requestBody});
    assert.equal(options.redirect, 'manual');
    if (path === '/app/installations/3/access_tokens') return json({token});
    assert.equal(options.headers.Authorization, `Bearer ${token}`);
    if (path === '/repos/fixture/repo') return json(repository);
    if (path === '/repos/fixture/repo/pulls/12') {
      prReads++;
      return json(managedPR(fixtures.cases[0].body, prReads === 1 ? oldHead : newHead));
    }
    if (path === `/repos/fixture/repo/commits/${oldHead}/check-runs`) return json(listOf(ownCheck()));
    if (path === `/repos/fixture/repo/commits/${newHead}/check-runs`) return json(listOf());
    if (path === '/repos/fixture/repo/check-runs/77' && options.method === 'PATCH') return json({id: 77});
    if (path === '/repos/fixture/repo/check-runs' && options.method === 'POST') return json({id: 88});
    throw new Error(`Unexpected API path: ${options.method} ${path}`);
  });
  const response = await worker.fetch(signed({...payload, number: 12, action: 'edited'}, 'pull_request'), env);
  assert.equal(response.status, 200);
  const writes = checkWrites(calls);
  assert.equal(writes.length, 2);
  assert.equal(writes[0].method, 'PATCH');
  assert.equal(writes[1].method, 'POST');
  assert.equal(writes[1].body.head_sha, newHead);
  assert.deepEqual(writes.map(write => write.body.actions), [[], []]);
});

test('canonical PR or Check-list API failures are sanitized and cannot cause writes', async () => {
  for (const failPath of ['/repos/fixture/repo/pulls/12', `/repos/fixture/repo/commits/${'a'.repeat(40)}/check-runs`]) {
    const {calls} = checkMock({failPath});
    const response = await worker.fetch(signed({...payload, number: 12}, 'pull_request'), env);
    assert.equal(response.status, 500);assert.equal(await response.text(), 'Webhook processing failed');
    assert.equal(checkWrites(calls).length, 0);
  }
});

// Execute the service's SQL against SQLite constraints; the native suite also
// exercises these same queries through Cloudflare's real local D1 binding.
const {DatabaseSync} = await import('node:sqlite');
function requestDatabase() {
  const sql = new DatabaseSync(':memory:');
  sql.exec(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'));
  return {sql, prepare(query) {
    return {bind(...values) {
      return {async first() { return sql.prepare(query).get(...values) ?? null; },
        async run() { return {meta: {changes: Number(sql.prepare(query).run(...values).changes)}}; }};
    }};
  }};
}

async function actionMock(t, {permission = 'write', alterPR, alterCheck, dispatch = 'ok', onCall} = {}) {
  const db = requestDatabase();t.after(() => db.sql.close());
  const pr = managedPR(fixtures.cases[0].body);
  const repository = {id: 7, full_name: 'fixture/repo', default_branch: 'main'};
  const check = ownCheck({conclusion: 'neutral', external_id: `node-repair:12:${await selectionFingerprint(pr, selections(pr.body))}`});
  const clickedCheck = {...check, app: {...check.app}};
  alterPR?.(pr, repository);alterCheck?.(check);
  const documentedCheck = value => { const response = {...value}; delete response.actions; return response; };
  const calls = [], environment = {...env, DB: db};
  fetch.mock.mockImplementation(async (url, options) => {
    const path = new URL(url).pathname, body = options.body && JSON.parse(options.body);
    const call = {path, method: options.method, body, signal: options.signal};calls.push(call);
    const intercepted = await onCall?.(call, {db, pr, check, repository});
    if (intercepted) return intercepted;
    assert.equal(options.headers['X-GitHub-Api-Version'], '2026-03-10');
    if (path === '/app/installations/3/access_tokens') return json({token});
    assert.equal(options.headers.Authorization, `Bearer ${token}`);
    if (path === '/repos/fixture/repo') return json(repository);
    if (path === '/repos/fixture/repo/collaborators/maintainer/permission') return json({permission, user: {login: 'maintainer'}});
    if (path === '/repos/fixture/repo/pulls/12') return json(pr);
    if (path.includes('/commits/') && path.endsWith('/check-runs')) return json(listOf(documentedCheck(check)));
    if (path === '/repos/fixture/repo/check-runs/77' || path === '/repos/fixture/repo/check-runs/78') {
      if (options.method === 'PATCH') Object.assign(check, body);
      return json(options.method === 'GET' ? documentedCheck(check) : check);
    }
    if (path === '/repos/fixture/repo/check-runs' && options.method === 'POST') return json({...check, ...body, id: 78});
    if (path === '/repos/fixture/repo/actions/workflows/dependency-repair.yml/dispatches') {
      if (dispatch === 'timeout') throw Error('private lost response');
      if (dispatch === '204') return new Response(null, {status: 204});
      if (dispatch === '201') return new Response(JSON.stringify({workflow_run_id: 900,
        run_url: 'https://api.github.com/repos/fixture/repo/actions/runs/900',
        html_url: 'https://github.com/fixture/repo/actions/runs/900'}), {status: 201});
      return json({workflow_run_id: 900, run_url: 'https://api.github.com/repos/fixture/repo/actions/runs/900',
        html_url: `https://github.com/${dispatch === 'foreign' ? 'other/repo' : 'fixture/repo'}/actions/runs/900`});
    }
    throw Error(`Unexpected request path ${path}`);
  });
  const event = {...payload, action: 'requested_action', requested_action: {identifier: 'repair-selected'},
    check_run: clickedCheck, sender: {login: 'maintainer', type: 'User'}};
  const click = (id = delivery, changes = {}) => worker.fetch(signed({...event, ...changes}, 'check_run', {'x-github-delivery': id}), environment);
  const rows = () => db.sql.prepare('SELECT * FROM requests').all();
  const dispatches = () => calls.filter(call => call.path.endsWith('/dispatches'));
  return {calls, db, pr, repository, check, clickedCheck, environment, event, click, rows, dispatches};
}

test('an authorized current action reserves once and retains the documented run and exact C2 inputs', async t => {
  const f = await actionMock(t);
  assert.equal((await f.click()).status, 200);
  assert.equal(f.dispatches().length, 1);
  assert.deepEqual(f.dispatches()[0].body, {ref: 'main', inputs: {'request-id': delivery, 'pull-request': '12',
    'expected-head': 'a'.repeat(40), 'expected-base': 'b'.repeat(40),
    selections: JSON.stringify([{name: 'launch-editor', from: '2.14.1', to: '2.14.2'}])}});
  assert.deepEqual(f.calls[0].body, {repository_ids: [7], permissions: {contents: 'read', pull_requests: 'read', checks: 'write', actions: 'write'}});
  const row = f.rows()[0];
  assert.equal(row.state, 'dispatched');assert.equal(row.run_id, 900);assert.equal(row.check_id, 77);
  assert.equal(row.installation_id, 3);assert.equal(row.repository_id, 7);assert.equal(row.dispatched_ref, 'main');
  assert.equal(row.completed_at, null);assert.equal(row.conclusion, null);
  assert.equal(f.check.external_id, `node-repair-request:${delivery}`);assert.equal(f.check.status, 'in_progress');
  assert.deepEqual(f.check.actions, []);assert.match(f.check.output.summary, /actions\/runs\/900/);
  const before = f.calls.length;
  assert.equal((await f.click()).status, 200);
  assert.equal(f.dispatches().length, 1);assert.equal(f.rows().length, 1);
  assert.equal(f.calls.length - before, 4); // Token, repository and owned Check reconciliation; no new attempt.
});

test('a queued click for selection A cannot dispatch after the canonical Check refreshes to selection B', async t => {
  const f = await actionMock(t);
  f.pr.body = fixtures.cases[0].body.replace('2.14.2', '2.14.3');
  const refreshedExternal = `node-repair:12:${await selectionFingerprint(f.pr, selections(f.pr.body))}`;
  f.check.external_id = refreshedExternal;
  assert.equal((await f.click()).status, 200);
  assert.equal(f.rows().length, 0);
  assert.equal(f.dispatches().length, 0);
  assert.equal(f.check.external_id, refreshedExternal);
});

test('a queued click for the old base cannot dispatch after the canonical Check refreshes', async t => {
  const f = await actionMock(t);
  f.pr.base.sha = 'c'.repeat(40);
  f.check.external_id = `node-repair:12:${await selectionFingerprint(f.pr, selections(f.pr.body))}`;
  assert.equal((await f.click()).status, 200);
  assert.equal(f.rows().length, 0);
  assert.equal(f.dispatches().length, 0);
});

for (const [name, mutate] of [
  ['missing head and selection identity', clicked => {
    delete clicked.head_sha; delete clicked.external_id;
  }],
  ['mismatched Check ID', clicked => { clicked.id = 78; }],
  ['mismatched head identity', clicked => { clicked.head_sha = 'c'.repeat(40); }],
  ['mismatched selection identity', clicked => { clicked.external_id = 'node-repair:12:' + '0'.repeat(64); }],
]) {
  test(`a ${name} requires a fresh click and cannot reserve`, async t => {
    const f = await actionMock(t);
    const clicked = {...f.event.check_run, app: {...f.event.check_run.app}};
    mutate(clicked);
    assert.equal((await f.click(delivery, {check_run: clicked})).status, 200);
    assert.equal(f.rows().length, 0);
    assert.equal(f.dispatches().length, 0);
  });
}

test('a fresh click for the current refreshed Check dispatches only the current batch', async t => {
  const f = await actionMock(t);
  f.pr.body = fixtures.cases[0].body.replace('2.14.2', '2.14.3');
  f.check.external_id = `node-repair:12:${await selectionFingerprint(f.pr, selections(f.pr.body))}`;
  const clicked = {...f.check, app: {...f.check.app}};
  const freshDelivery = 'a4e535a5-2a7d-491d-858a-3df51ce211df';
  assert.equal((await f.click(freshDelivery, {check_run: clicked})).status, 200);
  assert.equal(f.rows().length, 1);
  assert.equal(f.dispatches().length, 1);
  assert.equal(JSON.parse(f.dispatches()[0].body.inputs.selections)[0].to, '2.14.3');
  assert.equal(f.rows()[0].fingerprint, await selectionFingerprint(f.pr, selections(f.pr.body)));
});

for (const permission of ['read', 'triage', 'none']) {
  test(`${permission} permission cannot reserve or dispatch`, async t => {
    const f = await actionMock(t, {permission});assert.equal((await f.click()).status, 200);
    assert.equal(f.rows().length, 0);assert.equal(f.dispatches().length, 0);
  });
}
for (const permission of ['maintain', 'admin']) {
  test(`${permission} permission may request the fixed workflow`, async t => {
    const f = await actionMock(t, {permission});assert.equal((await f.click()).status, 200);assert.equal(f.dispatches().length, 1);
  });
}
for (const [name, alterPR] of [['head', pr => {pr.head.sha = 'c'.repeat(40);}],
  ['base', pr => {pr.base.sha = 'c'.repeat(40);}], ['selections', pr => {pr.body = fixtures.cases[0].body.replaceAll('2.14.2', '2.14.3');}],
  ['empty selections', pr => {pr.body = fixtures.cases[1].body;}], ['malformed selections', pr => {pr.body = 'invalid';}],
  ['fork', pr => {pr.head.repo.id = 99;}], ['human author', pr => {pr.user.type = 'User';}],
  ['wrong branch', pr => {pr.head.ref = 'other';}], ['closed', pr => {pr.state = 'closed';}]]) {
  test(`a stale or unmanaged ${name} cannot dispatch`, async t => {
    const f = await actionMock(t, {alterPR});assert.equal((await f.click()).status, 200);
    assert.equal(f.dispatches().length, 0);assert.equal(f.rows().length, 0);
  });
}
for (const [name, alterCheck] of [['foreign App', c => {c.app.id = 99;}], ['wrong name', c => {c.name = 'other';}],
  ['request identity', c => {c.external_id = `node-repair-request:${delivery}`;}], ['in progress', c => {c.status = 'in_progress';}],
  ['wrong conclusion', c => {c.conclusion = 'success';}]]) {
  test(`a ${name} Check cannot dispatch`, async t => {
    const f = await actionMock(t, {alterCheck});await f.click();assert.equal(f.dispatches().length, 0);assert.equal(f.rows().length, 0);
  });
}

test('the canonical Check is rechecked after permission and PR reads', async t => {
  let reads = 0;
  const f = await actionMock(t, {onCall(call, {check}) {
    if (call.path.endsWith('/check-runs/77') && call.method === 'GET' && ++reads === 2) check.app.id = 999;
  }});
  await f.click();assert.equal(f.dispatches().length, 0);assert.equal(f.rows().length, 0);
});

test('action routing rejects wrong identifiers and foreign event Apps without network calls', async t => {
  const f = await actionMock(t);
  for (const changed of [{requested_action: {identifier: 'other'}}, {check_run: {id: 77, app: {id: 99}}}]) {
    assert.equal((await f.click(delivery, changed)).status, 200);
  }
  assert.equal(f.calls.length, 0);
  assert.equal((await f.click(delivery, {sender: {login: '../escape', type: 'User'}})).status, 200);
  assert.equal(f.rows().length, 0);
});

for (const dispatch of ['timeout', '204', '201', 'foreign']) {
  test(`ambiguous ${dispatch} dispatch retains its active lock and does not retry`, async t => {
    const f = await actionMock(t, {dispatch});assert.equal((await f.click()).status, 500);
    assert.equal(f.rows()[0].state, 'unknown');assert.equal(f.rows()[0].run_id, null);
    assert.equal((await f.click()).status, 200);assert.equal(f.dispatches().length, 1);
    const next = '94e535a5-2a7d-491d-858a-3df51ce211de';
    // A new delivery UUID cannot release the active request either.
    assert.equal((await f.click(next)).status, 200);assert.equal(f.rows().length, 1);assert.equal(f.dispatches().length, 1);
  });
}

test('a failed in-progress Check update retains reserved state without dispatch', async t => {
  let failed = false;
  const f = await actionMock(t, {onCall(call) {
    if (!failed && call.path.endsWith('/check-runs/77') && call.method === 'PATCH') {
      failed = true;
      return new Response('private', {status: 502});
    }
  }});
  assert.equal((await f.click()).status, 500);assert.equal(f.rows()[0].state, 'reserved');assert.equal(f.dispatches().length, 0);
  assert.equal((await f.click()).status, 200);assert.equal(f.dispatches().length, 0);
  assert.equal(f.check.external_id, `node-repair-request:${delivery}`);
  assert.equal(f.check.status, 'in_progress');assert.deepEqual(f.check.actions, []);
  assert.equal(f.check.output.title, 'Request reserved');
});

test('a fresh click restores a same-Check reservation after the first Check write failed', async t => {
  let failed = false;
  const f = await actionMock(t, {onCall(call) {
    if (!failed && call.path.endsWith('/check-runs/77') && call.method === 'PATCH') {
      failed = true;
      return new Response('private', {status: 502});
    }
  }});
  assert.equal((await f.click()).status, 500);
  assert.equal((await f.click('94e535a5-2a7d-491d-858a-3df51ce211de')).status, 200);
  assert.equal(f.rows().length, 1);assert.equal(f.rows()[0].state, 'reserved');assert.equal(f.dispatches().length, 0);
  assert.equal(f.check.external_id, `node-repair-request:${delivery}`);assert.deepEqual(f.check.actions, []);
});

test('replay cannot overwrite a foreign Check or regress a completed request', async t => {
  const f = await actionMock(t);assert.equal((await f.click()).status, 200);
  f.check.app.id = 999;
  const writes = checkWrites(f.calls).length;
  assert.equal((await f.click()).status, 500);assert.equal(checkWrites(f.calls).length, writes);
  f.db.sql.prepare("UPDATE requests SET state = 'success' WHERE id = ?").run(delivery);
  assert.equal((await f.click()).status, 200);assert.equal(checkWrites(f.calls).length, writes);
  assert.equal(f.dispatches().length, 1);
});

test('the exact five-input payload accepts 65535 characters and rejects one more', () => {
  const pr = managedPR(fixtures.cases[0].body);
  const items = [{name: 'launch-editor', from: '1.0.1', to: '1.0.2'}];
  const remaining = 65_535 - JSON.stringify(workflowInputs(pr, items, delivery)).length;
  items[0].to += '2'.repeat(remaining);
  assert.equal(JSON.stringify(workflowInputs(pr, items, delivery)).length, 65_535);
  items[0].to += '2';
  assert.throws(() => workflowInputs(pr, items, delivery), /payload limit/);
});

test('oversized selected versions expose no action and reserve no request', async t => {
  const f = await actionMock(t);
  f.pr.body = '<!-- node-repair:selection:v1 -->\n- [x] Allow `launch-editor` `1.0.1 → 1.0.' + '2'.repeat(65_535) + '` by updating its explicit pin.\n<!-- /node-repair:selection -->';
  f.check.external_id = `node-repair:12:${await selectionFingerprint(f.pr, selections(f.pr.body))}`;
  f.clickedCheck.external_id = f.check.external_id;
  assert.equal((await f.click()).status, 200);assert.equal(f.rows().length, 0);assert.equal(f.dispatches().length, 0);
  const writes = checkWrites(f.calls);
  assert.equal(writes.at(-1).body.output.title, 'Repair selections need attention');
  assert.deepEqual(writes.at(-1).body.actions, []);
});

test('failure after retaining the known run cannot erase its identity or dispatch again', async t => {
  let writes = 0;
  const f = await actionMock(t, {onCall(call) {
    if (call.path.endsWith('/check-runs/77') && call.method === 'PATCH' && ++writes === 2) return new Response('private', {status: 502});
  }});
  assert.equal((await f.click()).status, 500);assert.equal(f.rows()[0].state, 'dispatched');assert.equal(f.rows()[0].run_id, 900);
  assert.equal((await f.click()).status, 200);assert.equal(f.dispatches().length, 1);
});

test('concurrent current clicks admit one request through the actual SQLite unique index', async t => {
  let arrivals = 0, release;
  const ready = new Promise(resolve => {release = resolve;});
  const f = await actionMock(t, {async onCall(call) {
    if (call.path.endsWith('/check-runs/77') && call.method === 'GET') {
      if (++arrivals === 4) release();
      if (arrivals > 2) await ready;
    }
  }});
  const result = await Promise.all([f.click(), f.click('94e535a5-2a7d-491d-858a-3df51ce211de')]);
  assert.deepEqual(result.map(r => r.status), [200, 200]);assert.equal(f.rows().length, 1);assert.equal(f.dispatches().length, 1);
});

test('D1-enabled PR edits show an action only for an eligible selected batch', async t => {
  const f = await actionMock(t);
  const refresh = () => worker.fetch(signed({...payload, number: 12, action: 'edited'}, 'pull_request'), f.environment);
  assert.equal((await refresh()).status, 200);assert.equal(f.check.actions[0].identifier, 'repair-selected');
  f.pr.body = fixtures.cases[1].body;assert.equal((await refresh()).status, 200);
  const writes = checkWrites(f.calls);
  assert.equal(writes.at(-1).method, 'POST');assert.deepEqual(writes.at(-1).body.actions, []);
  assert.equal(f.dispatches().length, 0);
});

test('PR edits preserve a reserved/dispatched Check request identity and do not dispatch', async t => {
  const f = await actionMock(t);assert.equal((await f.click()).status, 200);
  f.pr.body = fixtures.cases[1].body;
  assert.equal((await worker.fetch(signed({...payload, number: 12, action: 'edited'}, 'pull_request'), f.environment)).status, 200);
  assert.equal(f.check.external_id, `node-repair-request:${delivery}`);assert.equal(f.check.status, 'in_progress');
  assert.deepEqual(f.check.actions, []);assert.equal(f.dispatches().length, 1);
});

test('deadline after reservation prevents dispatch and preserves the ambiguous reservation', async t => {
  shortenWebhookDeadline(t);
  const f = await actionMock(t, {async onCall(call) {
    if (call.path.endsWith('/check-runs/77') && call.method === 'PATCH') await new Promise(resolve => setTimeout(resolve, 200));
  }});
  assert.equal((await f.click()).status, 500);assert.equal(f.dispatches().length, 0);assert.equal(f.rows()[0].state, 'reserved');
});

test('an idle refresh that races admission restores the reserved Check identity', async t => {
  let raced = false;
  const f = await actionMock(t, {onCall(call, {db}) {
    if (!raced && call.path.endsWith('/check-runs/77') && call.method === 'PATCH' && call.body.external_id.startsWith('node-repair:')) {
      raced = true;
      db.sql.prepare(`INSERT INTO requests (id, installation_id, repository_id, repository, pr, head, base,
        dispatched_ref, fingerprint, check_id, actor_login, created_at, state)
        VALUES (?, 3, 7, 'fixture/repo', 12, ?, ?, 'main', ?, 77, 'maintainer', 1, 'reserved')`)
        .run(delivery, 'a'.repeat(40), 'b'.repeat(40), '0'.repeat(64));
    }
  }});
  assert.equal((await worker.fetch(signed({...payload, number: 12}, 'pull_request'), f.environment)).status, 200);
  assert.equal(raced, true);assert.equal(f.check.external_id, `node-repair-request:${delivery}`);
  assert.equal(f.check.status, 'in_progress');assert.deepEqual(f.check.actions, []);assert.equal(f.dispatches().length, 0);
});

test('a different active Check blocks a fresh idle click and links the active request', async t => {
  const f = await actionMock(t);
  f.db.sql.prepare(`INSERT INTO requests (id, installation_id, repository_id, repository, pr, head, base,
    dispatched_ref, fingerprint, check_id, actor_login, created_at, state)
    VALUES (?, 3, 7, 'fixture/repo', 12, ?, ?, 'main', ?, 88, 'maintainer', 1, 'unknown')`)
    .run('94e535a5-2a7d-491d-858a-3df51ce211de', 'a'.repeat(40), 'b'.repeat(40), '0'.repeat(64));
  assert.equal((await f.click()).status, 200);assert.equal(f.rows().length, 1);assert.equal(f.dispatches().length, 0);
  assert.equal(f.check.output.title, 'Another request is active');assert.match(f.check.output.summary, /runs\/88/);
  assert.deepEqual(f.check.actions, []);
});

test('an active request cannot authorize overwriting a replaced or foreign Check', async t => {
  const f = await actionMock(t);assert.equal((await f.click()).status, 200);
  f.check.app.id = 999;
  const writes = checkWrites(f.calls).length;
  assert.equal((await worker.fetch(signed({...payload, number: 12}, 'pull_request'), f.environment)).status, 500);
  assert.equal(checkWrites(f.calls).length, writes);assert.equal(f.rows()[0].state, 'dispatched');
});

for (const route of ['PR edit', 'delivery replay']) {
  for (const pause of ['GET', 'PATCH']) {
    test(`a ${route} paused on Check ${pause} cannot erase a newly retained run link`, async t => {
      const dispatchReached = Promise.withResolvers(), finishDispatch = Promise.withResolvers();
      const restoreReached = Promise.withResolvers(), finishRestore = Promise.withResolvers();
      let dispatchPending = false, held = false;
      const f = await actionMock(t, {async onCall(call) {
        if (call.path.endsWith('/dispatches')) {
          dispatchPending = true; dispatchReached.resolve(); await finishDispatch.promise;
        } else if (dispatchPending && !held && call.path.endsWith('/check-runs/77') && call.method === pause) {
          held = true; restoreReached.resolve(); await finishRestore.promise;
        }
      }});
      const click = f.click();
      await dispatchReached.promise;
      const restore = route === 'PR edit' ?
        worker.fetch(signed({...payload, number: 12, action: 'edited'}, 'pull_request'), f.environment) : f.click();
      await restoreReached.promise;
      finishDispatch.resolve();
      assert.equal((await click).status, 200);
      assert.equal(f.rows()[0].state, 'dispatched');
      assert.match(f.check.output.summary, /actions\/runs\/900/);
      finishRestore.resolve();
      assert.equal((await restore).status, 200);
      assert.equal(f.rows()[0].run_id, 900);
      assert.equal(f.check.output.title, 'Workflow started');
      assert.match(f.check.output.summary, /actions\/runs\/900/);
      assert.equal(f.check.external_id, `node-repair-request:${delivery}`);
      assert.deepEqual(f.check.actions, []);
      assert.equal(f.dispatches().length, 1);
    });
  }
}
