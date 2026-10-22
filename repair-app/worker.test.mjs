import assert from 'node:assert/strict';
import {createHmac, generateKeyPairSync, verify} from 'node:crypto';
import {beforeEach, test} from 'node:test';
import worker, {api, installationToken, verifySignature} from './worker.mjs';

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

test('oversized streams are cancelled before reading the complete body, even with a false small length', async () => {
  for (const cancelFails of [false, true]) {
    let pulled = 0, cancelled = false;
    const body = new ReadableStream({
      pull(controller) {
        pulled++;
        controller.enqueue(new Uint8Array(700_000));
        if (pulled === 20) controller.close();
      },
      cancel() { cancelled = true; if (cancelFails) throw new Error('fixture cancellation failure'); },
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

test('PR deliveries use a valid App JWT and exactly one repository-scoped read-only token', async () => {
  const calls = githubMock({id: 7, full_name: 'Fixture/Repo'});
  assert.equal((await worker.fetch(signed(payload, 'pull_request'), env)).status, 200);
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
