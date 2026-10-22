// Exercise the receiver in Cloudflare's local runtime. All GitHub calls are intercepted.
import assert from 'node:assert/strict';
import {createHmac, generateKeyPairSync, verify} from 'node:crypto';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';

const keys = generateKeyPairSync('rsa', {modulusLength: 2048,
  privateKeyEncoding: {type: 'pkcs8', format: 'pem'}});
const secret = 'native-runtime-fixture-secret';
const calls = [];
const service = new Miniflare(convertV4MiniflareOptions({
  modules: true,
  scriptPath: new URL('./worker.mjs', import.meta.url).pathname,
  compatibilityDate: '2026-10-19',
  bindings: {APP_ID: '42', APP_PRIVATE_KEY: keys.privateKey, WEBHOOK_SECRET: secret},
  outboundService: async request => {
    const url = new URL(request.url);
    assert.equal(url.origin, 'https://api.github.com');
    calls.push([request.method, url.pathname]);
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
  console.log('Native Workers runtime passed: signed ping, invalid signature, streamed limit, RSA JWT, scoped read and no Check/dispatch writes.');
} finally {
  await service.dispose();
}
