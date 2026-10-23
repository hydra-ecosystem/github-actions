const encoder = new TextEncoder();
const MAX_BODY_BYTES = 2_000_000;
const DELIVERY_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const PR_ACTIONS = ['opened', 'edited', 'synchronize', 'reopened'];
const START = '<!-- node-repair:selection:v1 -->';
const END = '<!-- /node-repair:selection -->';
const VERSION = '(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)';
const PACKAGE = '(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*';
const LINE = new RegExp('^- \\[([ xX])\\] Allow `(' + PACKAGE + ')` `(' + VERSION + ') → (' + VERSION + ')` by updating its explicit pin\\.$');
const CHECK = 'Dependency repair';
const MAX_RECONCILIATIONS = 3;

export function selections(body) {
  if (typeof body !== 'string' || body.split(START).length !== 2 || body.split(END).length !== 2) {
    throw new Error('Expected one selection block');
  }
  const lines = body.split(/\r?\n/), start = lines.indexOf(START), end = lines.indexOf(END);
  if (start < 0 || end <= start) throw new Error('Invalid selection markers');
  const items = [], names = new Set();
  for (const line of lines.slice(start + 1, end)) {
    const match = LINE.exec(line);
    if (!match || match[2].length > 214 || ['node_modules', 'favicon.ico'].includes(match[2]) ||
        names.has(match[2])) throw new Error('Invalid selection line');
    names.add(match[2]);
    const from = match[3].split('.'), to = match[4].split('.');
    if (from[0] !== to[0] || from[1] !== to[1] || BigInt(from[2]) >= BigInt(to[2])) {
      throw new Error('Only increasing same-minor patches are allowed');
    }
    if (match[1].toLowerCase() === 'x') items.push({name: match[2], from: match[3], to: match[4]});
  }
  if (items.length > 20) throw new Error('Too many selected fixes');
  return items.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
}

export async function selectionFingerprint(pr, items) {
  const bytes = encoder.encode(JSON.stringify([pr.number, pr.head.sha, pr.base.sha, items]));
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
    .map(value => value.toString(16).padStart(2, '0')).join('');
}

async function readBody(request, signal) {
  signal.throwIfAborted();
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, {once: true});
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BODY_BYTES) {
        cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    signal.removeEventListener('abort', cancel);
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

function der(tag, bytes) {
  let size = bytes.length;
  const length = [];
  do { length.unshift(size & 255); size = Math.floor(size / 256); } while (size);
  const header = bytes.length < 128 ? [tag, bytes.length] : [tag, 128 | length.length, ...length];
  const result = new Uint8Array(header.length + bytes.length);
  result.set(header);
  result.set(bytes, header.length);
  return result;
}

function appKey(pem) {
  const match = pem.trim().match(/^-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY)-----\s+([A-Za-z0-9+/=\s]+)-----END \1-----$/);
  if (!match) throw new Error('Invalid App key');
  let bytes = Uint8Array.from(atob(match[2].replace(/\s/g, '')), c => c.charCodeAt(0));
  if (match[1] === 'RSA PRIVATE KEY') {
    // PKCS#8 PrivateKeyInfo: version 0, rsaEncryption + NULL, PKCS#1 octet string.
    const prefix = [2, 1, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0];
    const octets = der(4, bytes);
    const contents = new Uint8Array(prefix.length + octets.length);
    contents.set(prefix);
    contents.set(octets, prefix.length);
    bytes = der(48, contents);
  }
  return bytes;
}

async function appJWT(env) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({alg: 'RS256', typ: 'JWT'}));
  const claims = base64url(JSON.stringify({iat: now - 60, exp: now + 540, iss: String(env.APP_ID)}));
  const key = await crypto.subtle.importKey('pkcs8', appKey(env.APP_PRIVATE_KEY),
    {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['sign']);
  const input = `${header}.${claims}`;
  return `${input}.${base64url(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(input)))}`;
}

export async function api(token, path, method = 'GET', body, signal = AbortSignal.timeout(15_000)) {
  let response;
  try {
    signal.throwIfAborted();
    response = await fetch(`https://api.github.com${path}`, {
      method, redirect: 'manual', signal,
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

export async function installationToken(env, installationID, repositoryID, signal, permissions = {contents: 'read'}) {
  if (![installationID, repositoryID].every(id => Number.isSafeInteger(id) && id > 0)) {
    throw new Error('Invalid installation or repository ID');
  }
  const result = await api(await appJWT(env), `/app/installations/${installationID}/access_tokens`, 'POST', {
    repository_ids: [repositoryID], permissions,
  }, signal);
  if (typeof result?.token !== 'string' || !result.token.trim()) throw new Error('Invalid installation token response');
  return result.token;
}

async function readRepository(payload, env, signal) {
  const repository = payload.repository;
  if (typeof repository?.full_name !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository.full_name)) {
    throw new Error('Invalid repository name');
  }
  const number = payload.number;
  const hasPR = Number.isSafeInteger(number) && number > 0;
  const permissions = hasPR ? {contents: 'read', pull_requests: 'read', checks: 'write'} : {contents: 'read'};
  const token = await installationToken(env, payload.installation?.id, repository.id, signal, permissions);
  const current = await api(token, `/repos/${repository.full_name}`, 'GET', undefined, signal);
  if (current?.id !== repository.id || current.full_name?.toLowerCase() !== repository.full_name.toLowerCase()) {
    throw new Error('Repository identity changed');
  }
  if (hasPR) await refreshSelectionCheck(token, current, number, env.APP_ID, signal);
}

async function refreshSelectionCheck(token, repository, number, appID, signal) {
  const prefix = `/repos/${repository.full_name}`;
  for (let attempt = 0; attempt < MAX_RECONCILIATIONS; attempt++) {
    const pr = await api(token, `${prefix}/pulls/${number}`, 'GET', undefined, signal);
    if (typeof repository.default_branch !== 'string' || !repository.default_branch ||
        pr?.number !== number || pr.state !== 'open' || pr.user?.type !== 'Bot' ||
        pr.head?.repo?.id !== repository.id || pr.base?.repo?.id !== repository.id ||
        pr.head.ref !== 'maintenance/node-security' || pr.base.ref !== repository.default_branch ||
        !/^[a-f0-9]{40}$/.test(pr.head.sha || '') || !/^[a-f0-9]{40}$/.test(pr.base.sha || '')) return;
    let items = [], valid = true;
    try { items = selections(pr.body); } catch { valid = false; }
    const external = `node-repair:${number}:${await selectionFingerprint(pr, items)}`;
    const state = `${valid ? 'valid' : 'invalid'}:${external}`;
    const list = await api(token, `${prefix}/commits/${pr.head.sha}/check-runs?check_name=Dependency%20repair&app_id=${appID}&filter=all&per_page=100`, 'GET', undefined, signal);
    if (!Array.isArray(list?.check_runs) || !Number.isSafeInteger(list.total_count) ||
        list.total_count < 0 || list.total_count > 100 || list.total_count !== list.check_runs.length) {
      throw new Error('Incomplete Check list');
    }
    const owned = list.check_runs.filter(check => String(check.app?.id) === String(appID) &&
      check.name === CHECK && check.head_sha === pr.head.sha &&
      new RegExp(`^node-repair:${number}:[a-f0-9]{64}$`).test(check.external_id || ''));
    if (owned.some(check => !Number.isSafeInteger(check.id) || check.id <= 0 || check.status !== 'completed')) {
      throw new Error('Repair Check is not idle');
    }
    const check = owned.reduce((newest, candidate) => !newest || candidate.id > newest.id ? candidate : newest, undefined);
    const output = {
      title: !valid ? 'Repair selections need attention' : items.length ? `${items.length} selected fix${items.length === 1 ? '' : 'es'}` : 'No fixes selected',
      summary: !valid ? 'Use one valid selection block in the PR description. No run was started.' : items.length ?
        items.map(item => `- \`${item.name}\` \`${item.from} → ${item.to}\``).join('\n') +
          '\n\nSelections are displayed for review. Running fixes is not enabled yet.' :
        'Select the allowed fixes in the PR description. Editing checkboxes does not start a run.',
    };
    await api(token, `${prefix}/check-runs${check ? `/${check.id}` : ''}`, check ? 'PATCH' : 'POST', {
      ...(check ? {} : {name: CHECK, head_sha: pr.head.sha}), external_id: external,
      status: 'completed', conclusion: 'neutral', output, actions: [],
    }, signal);
    const current = await api(token, `${prefix}/pulls/${number}`, 'GET', undefined, signal);
    if (typeof repository.default_branch !== 'string' || !repository.default_branch ||
        current?.number !== number || current.state !== 'open' || current.user?.type !== 'Bot' ||
        current.head?.repo?.id !== repository.id || current.base?.repo?.id !== repository.id ||
        current.head.ref !== 'maintenance/node-security' || current.base.ref !== repository.default_branch ||
        !/^[a-f0-9]{40}$/.test(current.head.sha || '') || !/^[a-f0-9]{40}$/.test(current.base.sha || '')) return;
    let currentItems = [], currentValid = true;
    try { currentItems = selections(current.body); } catch { currentValid = false; }
    const currentExternal = `node-repair:${number}:${await selectionFingerprint(current, currentItems)}`;
    if (`${currentValid ? 'valid' : 'invalid'}:${currentExternal}` === state) return;
  }
  throw new Error('Repair Check freshness did not settle');
}

export default {
  async fetch(request, env) {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/webhook') return new Response('Not found', {status: 404});
    if (!['WEBHOOK_SECRET', 'APP_PRIVATE_KEY'].every(name => typeof env[name] === 'string' && env[name]) ||
        !/^[1-9][0-9]*$/.test(env.APP_ID || '')) return new Response('Not configured', {status: 503});
    if (Number(request.headers.get('content-length')) > MAX_BODY_BYTES) return new Response('Too large', {status: 413});
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8_000);
    try {
      const body = await readBody(request, controller.signal);
      controller.signal.throwIfAborted();
      if (body === null) return new Response('Too large', {status: 413});
      if (!await verifySignature(env.WEBHOOK_SECRET, body, request.headers.get('x-hub-signature-256'))) return new Response('Invalid signature', {status: 401});
      if (!DELIVERY_ID.test(request.headers.get('x-github-delivery') || '')) throw new Error('Invalid delivery ID');
      const payload = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(body));
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Invalid payload');
      // PR edits refresh the selected batch only. Later slices own actions and dispatch.
      if (request.headers.get('x-github-event') === 'pull_request' && PR_ACTIONS.includes(payload.action)) {
        await readRepository(payload, env, controller.signal);
      }
      controller.signal.throwIfAborted();
      return new Response('Accepted', {status: 200});
    } catch {
      // Keep payloads, credentials and upstream response bodies out of responses and logs.
      return new Response('Webhook processing failed', {status: 500});
    } finally {
      clearTimeout(timer);
    }
  },
};
