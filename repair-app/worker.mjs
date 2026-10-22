const encoder = new TextEncoder();
const MAX_BODY_BYTES = 2_000_000;
const DELIVERY_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const PR_ACTIONS = ['opened', 'edited', 'synchronize', 'reopened'];

async function readBody(request) {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BODY_BYTES) {
        try { await reader.cancel(); } catch { /* Still reject an oversized body. */ }
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

export async function verifySignature(secret, body, signature) {
  if (!/^sha256=[a-f0-9]{64}$/.test(signature || '')) return false;
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret),
    {name: 'HMAC', hash: 'SHA-256'}, false, ['verify']);
  const bytes = Uint8Array.from(signature.slice(7).match(/../g), part => parseInt(part, 16));
  return crypto.subtle.verify('HMAC', key, bytes, body);
}

function base64url(value) {
  const bytes = typeof value === 'string' ? encoder.encode(value) : new Uint8Array(value);
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

async function appJWT(env) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({alg: 'RS256', typ: 'JWT'}));
  const claims = base64url(JSON.stringify({iat: now - 60, exp: now + 540, iss: String(env.APP_ID)}));
  const pem = env.APP_PRIVATE_KEY.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, '');
  const key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(pem), c => c.charCodeAt(0)),
    {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['sign']);
  const input = `${header}.${claims}`;
  return `${input}.${base64url(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(input)))}`;
}

export async function api(token, path, method = 'GET', body) {
  let response;
  try {
    response = await fetch(`https://api.github.com${path}`, {
      method, redirect: 'manual', signal: AbortSignal.timeout(15_000),
      headers: {Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json',
        'User-Agent': 'node-maintenance', 'X-GitHub-Api-Version': '2026-03-10',
        'Content-Type': 'application/json'},
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new Error('GitHub request failed');
  }
  if (!response.ok) {
    const error = new Error(`GitHub request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  try { return await response.json(); } catch { throw new Error('Invalid GitHub response'); }
}

export async function installationToken(env, installationID, repositoryID) {
  if (![installationID, repositoryID].every(id => Number.isSafeInteger(id) && id > 0)) {
    throw new Error('Invalid installation or repository ID');
  }
  const result = await api(await appJWT(env), `/app/installations/${installationID}/access_tokens`, 'POST', {
    repository_ids: [repositoryID], permissions: {contents: 'read'},
  });
  if (typeof result?.token !== 'string' || !result.token.trim()) throw new Error('Invalid installation token response');
  return result.token;
}

async function readRepository(payload, env) {
  const repository = payload.repository;
  if (typeof repository?.full_name !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository.full_name)) {
    throw new Error('Invalid repository name');
  }
  const token = await installationToken(env, payload.installation?.id, repository.id);
  const current = await api(token, `/repos/${repository.full_name}`);
  if (current?.id !== repository.id || current.full_name?.toLowerCase() !== repository.full_name.toLowerCase()) {
    throw new Error('Repository identity changed');
  }
}

export default {
  async fetch(request, env) {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/webhook') return new Response('Not found', {status: 404});
    if (!['WEBHOOK_SECRET', 'APP_PRIVATE_KEY'].every(name => typeof env[name] === 'string' && env[name]) ||
        !/^[1-9][0-9]*$/.test(env.APP_ID || '')) return new Response('Not configured', {status: 503});
    if (Number(request.headers.get('content-length')) > MAX_BODY_BYTES) return new Response('Too large', {status: 413});
    try {
      const body = await readBody(request);
      if (body === null) return new Response('Too large', {status: 413});
      if (!await verifySignature(env.WEBHOOK_SECRET, body, request.headers.get('x-hub-signature-256'))) return new Response('Invalid signature', {status: 401});
      if (!DELIVERY_ID.test(request.headers.get('x-github-delivery') || '')) throw new Error('Invalid delivery ID');
      const payload = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(body));
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Invalid payload');
      // Slice 1 authenticates and reads metadata only. Later slices own Checks and dispatch.
      if (request.headers.get('x-github-event') === 'pull_request' && PR_ACTIONS.includes(payload.action)) {
        await readRepository(payload, env);
      }
      return new Response('Accepted', {status: 200});
    } catch {
      // Keep payloads, credentials and upstream response bodies out of responses and logs.
      return new Response('Webhook processing failed', {status: 500});
    }
  },
};
