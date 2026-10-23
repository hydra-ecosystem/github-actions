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
const ACTION = {label: 'Run selected fixes', description: 'Run the selected batch in Actions', identifier: 'repair-selected'};
const WORKFLOW = 'dependency-repair.yml';
const ACTIVE = "state IN ('reserved', 'dispatched', 'unknown')";
const positiveID = value => Number.isSafeInteger(value) && value > 0;

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
  if (!response.ok || (method === 'POST' && path.endsWith(`/workflows/${WORKFLOW}/dispatches`) && response.status !== 200)) {
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

async function readRepository(payload, env, signal, delivery) {
  const repository = payload.repository;
  if (typeof repository?.full_name !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository.full_name)) {
    throw new Error('Invalid repository name');
  }
  const number = payload.number;
  const hasPR = Number.isSafeInteger(number) && number > 0;
  const isAction = delivery !== undefined;
  const permissions = hasPR || isAction ? {contents: 'read', pull_requests: 'read', checks: 'write',
    ...(isAction ? {actions: 'write'} : {})} : {contents: 'read'};
  const token = await installationToken(env, payload.installation?.id, repository.id, signal, permissions);
  const current = await api(token, `/repos/${repository.full_name}`, 'GET', undefined, signal);
  if (current?.id !== repository.id || current.full_name?.toLowerCase() !== repository.full_name.toLowerCase()) {
    throw new Error('Repository identity changed');
  }
  if (isAction) await requestRepair(token, current, payload, env, delivery, signal);
  else if (hasPR) await refreshSelectionCheck(token, current, number, env.APP_ID, signal, env, payload.installation.id);
}

function managedPR(pr, repository, number) {
  return typeof repository.default_branch === 'string' && repository.default_branch &&
    pr?.number === number && pr.state === 'open' && pr.user?.type === 'Bot' &&
    pr.head?.repo?.id === repository.id && pr.base?.repo?.id === repository.id &&
    pr.head.ref === 'maintenance/node-security' && pr.base.ref === repository.default_branch &&
    /^[a-f0-9]{40}$/.test(pr.head.sha || '') && /^[a-f0-9]{40}$/.test(pr.base.sha || '');
}

async function activeRequest(env, installation, repository, number) {
  return env.DB ? env.DB.prepare(`SELECT * FROM requests WHERE installation_id = ? AND repository_id = ? AND pr = ? AND ${ACTIVE}`)
    .bind(installation, repository, number).first() : null;
}

function ownedCheck(check, appID, head) {
  return positiveID(check?.id) && String(check.app?.id) === String(appID) && check.name === CHECK && check.head_sha === head;
}

function selectionCheck(check, appID) {
  const match = /^node-repair:([1-9][0-9]*):([a-f0-9]{64})$/.exec(check?.external_id || '');
  if (!positiveID(check?.id) || String(check.app?.id) !== String(appID) || check.name !== CHECK ||
      !/^[a-f0-9]{40}$/.test(check.head_sha || '') || !match ||
      check.status !== 'completed' || check.conclusion !== 'neutral') return null;
  return match;
}

function sameCheckIdentity(left, right) {
  return positiveID(left?.id) && positiveID(right?.id) && left.id === right.id &&
    String(left.app?.id) === String(right.app?.id) && left.name === right.name &&
    left.head_sha === right.head_sha && left.external_id === right.external_id;
}

async function showRequest(token, repository, row, signal) {
  await api(token, `/repos/${repository.full_name}/check-runs/${row.check_id}`, 'PATCH', {
    external_id: `node-repair-request:${row.id}`, status: 'in_progress', actions: [],
    output: {title: row.state === 'unknown' ? 'Request requires inspection' : row.run_id ? 'Workflow started' : 'Request reserved',
      summary: row.run_id ? `[View workflow run](${row.html_url}). This pilot performs no dependency repair.` :
        'A request is reserved. Inspect Actions and the request record before recovery; do not retry dispatch automatically.'},
  }, signal);
}

async function preserveActiveCheck(token, repository, pr, env, installation, signal) {
  const row = await activeRequest(env, installation, repository.id, pr.number);
  if (!row || row.head !== pr.head.sha) return row;
  const check = await api(token, `/repos/${repository.full_name}/check-runs/${row.check_id}`, 'GET', undefined, signal);
  if (!ownedCheck(check, env.APP_ID, row.head) ||
      !(check.external_id === `node-repair-request:${row.id}` || new RegExp(`^node-repair:${pr.number}:[a-f0-9]{64}$`).test(check.external_id || ''))) {
    throw new Error('Active Check identity changed');
  }
  await showRequest(token, repository, row, signal);
  return row;
}

async function requestRepair(token, repository, payload, env, delivery, signal) {
  const clicked = payload.check_run;
  const clickedMatch = selectionCheck(clicked, env.APP_ID);
  if (!env.DB || !clickedMatch) return;
  const installation = payload.installation.id;
  // A retained delivery is never another dispatch attempt, even after a crash.
  const replay = await env.DB.prepare('SELECT id FROM requests WHERE id = ? AND installation_id = ? AND repository_id = ?')
    .bind(delivery, installation, repository.id).first();
  if (replay) return;
  const prefix = `/repos/${repository.full_name}`;
  const check = await api(token, `${prefix}/check-runs/${clicked.id}`, 'GET', undefined, signal);
  if (!sameCheckIdentity(check, clicked)) {
    await refreshSelectionCheck(token, repository, Number(clickedMatch[1]), env.APP_ID, signal, env, installation);
    return;
  }
  const match = clickedMatch;
  const number = Number(match[1]), actor = payload.sender?.login;
  if (payload.sender?.type !== 'User' || typeof actor !== 'string' || !/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/i.test(actor)) return;
  const permission = await api(token, `${prefix}/collaborators/${actor}/permission`, 'GET', undefined, signal);
  if (!['write', 'maintain', 'admin'].includes(permission?.permission) || permission.user?.login?.toLowerCase() !== actor.toLowerCase()) return;
  const pr = await api(token, `${prefix}/pulls/${number}`, 'GET', undefined, signal);
  if (!managedPR(pr, repository, number)) return;
  let items;
  try { items = selections(pr.body); } catch { items = []; }
  const fingerprint = await selectionFingerprint(pr, items);
  const current = await api(token, `${prefix}/check-runs/${check.id}`, 'GET', undefined, signal);
  if (!items.length || !sameCheckIdentity(current, clicked) || !ownedCheck(current, env.APP_ID, pr.head.sha) ||
      current.status !== 'completed' || current.conclusion !== 'neutral' ||
      current.external_id !== `node-repair:${number}:${fingerprint}`) {
    await refreshSelectionCheck(token, repository, number, env.APP_ID, signal, env, installation);
    return;
  }
  signal.throwIfAborted();
  const row = {id: delivery, installation_id: installation, repository_id: repository.id, repository: repository.full_name,
    pr: number, head: pr.head.sha, base: pr.base.sha, dispatched_ref: repository.default_branch, fingerprint,
    check_id: current.id, actor_login: actor, created_at: Date.now(), state: 'reserved'};
  const inserted = await env.DB.prepare(`INSERT OR IGNORE INTO requests
    (id, installation_id, repository_id, repository, pr, head, base, dispatched_ref, fingerprint, check_id, actor_login, created_at, state)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(...Object.values(row)).run();
  if (inserted.meta?.changes !== 1) {
    if (inserted.meta?.changes !== 0) throw new Error('Invalid admission result');
    const active = await activeRequest(env, installation, repository.id, number);
    if (active && active.check_id !== current.id) await api(token, `${prefix}/check-runs/${current.id}`, 'PATCH', {
      actions: [], output: {title: 'Another request is active', summary:
        `[Inspect the active Check](https://github.com/${repository.full_name}/runs/${active.check_id}). No new run was started.`},
    }, signal);
    return;
  }
  // Failure here retains reserved state, so redelivery cannot repeat the POST.
  await showRequest(token, repository, row, signal);
  signal.throwIfAborted();
  try {
    const run = await api(token, `${prefix}/actions/workflows/${WORKFLOW}/dispatches`, 'POST', {
      ref: row.dispatched_ref, inputs: {'request-id': delivery, 'pull-request': String(number),
        'expected-head': row.head, 'expected-base': row.base, selections: JSON.stringify(items)},
    }, signal);
    if (!positiveID(run?.workflow_run_id) || run.run_url !== `https://api.github.com${prefix}/actions/runs/${run.workflow_run_id}` ||
        run.html_url !== `https://github.com/${repository.full_name}/actions/runs/${run.workflow_run_id}`) {
      throw new Error('Invalid dispatch identity');
    }
    const saved = await env.DB.prepare("UPDATE requests SET state = 'dispatched', run_id = ?, run_url = ?, html_url = ? WHERE id = ? AND installation_id = ? AND repository_id = ? AND state = 'reserved'")
      .bind(run.workflow_run_id, run.run_url, run.html_url, delivery, installation, repository.id).run();
    if (saved.meta?.changes !== 1) throw new Error('Dispatch identity was not retained');
    await showRequest(token, repository, {...row, state: 'dispatched', run_id: run.workflow_run_id, html_url: run.html_url}, signal);
  } catch {
    // The POST may have reached GitHub. Never release this lock or repeat it.
    await env.DB.prepare("UPDATE requests SET state = 'unknown' WHERE id = ? AND installation_id = ? AND repository_id = ? AND state = 'reserved' AND run_id IS NULL")
      .bind(delivery, installation, repository.id).run();
    throw new Error('Dispatch requires inspection');
  }
}

async function refreshSelectionCheck(token, repository, number, appID, signal, env = {}, installation) {
  const prefix = `/repos/${repository.full_name}`;
  for (let attempt = 0; attempt < MAX_RECONCILIATIONS; attempt++) {
    const pr = await api(token, `${prefix}/pulls/${number}`, 'GET', undefined, signal);
    if (!managedPR(pr, repository, number)) return;
    const active = await preserveActiveCheck(token, repository, pr, env, installation, signal);
    if (active?.head === pr.head.sha) return;
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
      new RegExp(`^node-repair:${number}:[a-f0-9]{64}$`).test(check.external_id || '') &&
      check.external_id === external);
    if (owned.some(check => !Number.isSafeInteger(check.id) || check.id <= 0 || check.status !== 'completed')) {
      throw new Error('Repair Check is not idle');
    }
    const check = owned.reduce((newest, candidate) => !newest || candidate.id > newest.id ? candidate : newest, undefined);
    const output = {
      title: !valid ? 'Repair selections need attention' : items.length ? `${items.length} selected fix${items.length === 1 ? '' : 'es'}` : 'No fixes selected',
      summary: !valid ? 'Use one valid selection block in the PR description. No run was started.' : items.length ?
        items.map(item => `- \`${item.name}\` \`${item.from} → ${item.to}\``).join('\n') +
          (active ? '\n\nAnother request is active. Inspect it before requesting a new attempt.' : env.DB ?
            '\n\nReview these exact versions, then click Run selected fixes. The pilot only validates inputs.' :
            '\n\nSelections are displayed for review. Running fixes is not enabled yet.') :
        'Select the allowed fixes in the PR description. Editing checkboxes does not start a run.',
    };
    await api(token, `${prefix}/check-runs${check ? `/${check.id}` : ''}`, check ? 'PATCH' : 'POST', {
      ...(check ? {} : {name: CHECK, head_sha: pr.head.sha}), external_id: external,
      status: 'completed', conclusion: 'neutral', output, actions: valid && items.length && env.DB && !active ? [ACTION] : [],
    }, signal);
    // Repair a concurrent idle write that raced an action's reservation/Check update.
    const reserved = await preserveActiveCheck(token, repository, pr, env, installation, signal);
    if (reserved?.head === pr.head.sha) return;
    const current = await api(token, `${prefix}/pulls/${number}`, 'GET', undefined, signal);
    if (!managedPR(current, repository, number)) return;
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
      const event = request.headers.get('x-github-event');
      if (event === 'pull_request' && PR_ACTIONS.includes(payload.action)) {
        await readRepository(payload, env, controller.signal);
      } else if (event === 'check_run' && payload.action === 'requested_action' &&
          payload.requested_action?.identifier === ACTION.identifier && String(payload.check_run?.app?.id) === String(env.APP_ID)) {
        await readRepository(payload, env, controller.signal, request.headers.get('x-github-delivery'));
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
