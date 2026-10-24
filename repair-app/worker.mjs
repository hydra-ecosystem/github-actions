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
const ACTION = {label: 'Run selected fixes', description: 'Run the selected batch in Actions', identifier: 'repair-selected'};
const WORKFLOW = 'dependency-repair.yml';
const ACTIVE = "state IN ('reserved', 'dispatched', 'unknown')";
const TERMINAL = "state IN ('success', 'failure', 'cancelled')";
const CONCLUSIONS = new Set(['success', 'failure', 'cancelled', 'timed_out', 'action_required', 'neutral', 'skipped', 'stale', 'startup_failure']);
const MAX_INPUT_CHARS = 65_535;
const COMMAND = '/repair selected';
const positiveID = value => Number.isSafeInteger(value) && value > 0;

function repairComment(payload) {
  return payload.action === 'created' && positiveID(payload.issue?.number) &&
    positiveID(payload.comment?.id) && typeof payload.issue.pull_request?.url === 'string' &&
    typeof payload.comment.body === 'string' && payload.comment.body.trim() === COMMAND &&
    payload.sender?.type === 'User' && payload.comment.user?.type === 'User' &&
    positiveID(payload.sender.id) && payload.sender.id === payload.comment.user.id;
}

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

export function workflowInputs(pr, items, requestID = '00000000-0000-0000-0000-000000000000') {
  const inputs = {'request-id': requestID, 'pull-request': String(pr.number),
    'expected-head': pr.head.sha, 'expected-base': pr.base.sha, selections: JSON.stringify(items)};
  if (JSON.stringify(inputs).length > MAX_INPUT_CHARS) throw new Error('Workflow inputs exceed the payload limit');
  return inputs;
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
  const isComment = isAction && repairComment(payload);
  const permissions = hasPR || isAction ? {contents: 'read', pull_requests: 'read', checks: 'write',
    ...(isAction ? {actions: 'write'} : {}), ...(isComment ? {pull_requests: 'write', issues: 'read'} : {})} : {contents: 'read'};
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

export function requestStatus(row, items = []) {
  if (row.selections_json) items = JSON.parse(row.selections_json);
  const outcome = row.conclusion && (row.conclusion === 'success' ? 'succeeded' : row.conclusion === 'cancelled' ? 'cancelled' : 'failed');
  const title = outcome ? `Workflow ${outcome}` : 'Request accepted';
  const summary = outcome ? `[View workflow run](${row.html_url}). This pilot performs no dependency repair.` :
    `[View repair workflows](https://github.com/${row.repository}/actions/workflows/${WORKFLOW}).\n\nWaiting for a verified completion result. This pilot performs no dependency repair.`;
  const result = outcome ? `${summary}\n\nGitHub conclusion: \`${row.conclusion}\`.` : summary;
  return {title, summary: result, body: `<!-- node-repair:request:${row.id} -->\n### Dependency repair: ${title}\n\n` +
    (items.length ? items.map(item => `- \`${item.name}\` \`${item.from} → ${item.to}\``).join('\n') + '\n\n' : '') +
    `${result}\n\nSelections remain in the PR description. No merge is authorized by this request.`};
}

async function requestReply(token, repository, row, env, signal) {
  if (!row.comment_id || !row.status_comment_id) return null;
  const prefix = `/repos/${repository.full_name}/issues`;
  const comment = await api(token, `${prefix}/comments/${row.status_comment_id}`, 'GET', undefined, signal)
    .catch(error => { if (row.conclusion && error.status === 404) return null; throw error; });
  if (comment?.id === row.status_comment_id && String(comment.performed_via_github_app?.id) === String(env.APP_ID) &&
      comment.issue_url === `https://api.github.com${prefix}/${row.pr}` &&
      comment.body?.startsWith(`<!-- node-repair:request:${row.id} -->\n`)) return comment;
  if (!row.conclusion) throw new Error('Status comment identity changed');
  return null;
}

async function showRequest(token, repository, row, signal, env, items = [], createComment = false, writeCheck = true, reply) {
  const {title, summary, body} = requestStatus(row, items);
  const checkWrite = writeCheck ? api(token, `/repos/${repository.full_name}/check-runs/${row.check_id}`, 'PATCH', {
    external_id: `node-repair-request:${row.id}`, status: 'completed', conclusion: 'neutral', actions: [],
    output: {title, summary},
  }, signal).catch(error => { if (!row.conclusion || error.status !== 404) throw error; }) : Promise.resolve();
  if (!row.comment_id || !env) { await checkWrite; return; }
  const prefix = `/repos/${repository.full_name}/issues`;
  if (row.status_comment_id) {
    const writes = await Promise.allSettled([checkWrite, (async () => {
      const comment = reply === undefined ? await requestReply(token, repository, row, env, signal) : reply;
      if (comment) await api(token, `${prefix}/comments/${row.status_comment_id}`, 'PATCH', {body}, signal)
        .catch(error => { if (!row.conclusion || error.status !== 404) throw error; });
    })()]);
    const failed = writes.find(result => result.status === 'rejected');
    if (failed) throw failed.reason;
  } else {
    await checkWrite;
    if (!createComment) return;
    // Only the winning admission creates a reply. An ambiguous POST is never retried.
    const comment = await api(token, `${prefix}/${row.pr}/comments`, 'POST', {body}, signal);
    if (!positiveID(comment?.id) || String(comment.performed_via_github_app?.id) !== String(env.APP_ID) ||
        comment.issue_url !== `https://api.github.com${prefix}/${row.pr}`) throw new Error('Invalid status comment identity');
    const saved = await env.DB.prepare('UPDATE requests SET status_comment_id = ? WHERE id = ? AND installation_id = ? AND repository_id = ? AND status_comment_id IS NULL')
      .bind(comment.id, row.id, row.installation_id, repository.id).run();
    if (saved.meta?.changes !== 1) throw new Error('Status comment identity was not retained');
    row.status_comment_id = comment.id;
  }
}

async function retainedCheck(env, installation, repository, check) {
  return env.DB ? env.DB.prepare('SELECT * FROM requests WHERE installation_id = ? AND repository_id = ? AND check_id = ? ORDER BY created_at DESC LIMIT 1')
    .bind(installation, repository, check).first() : null;
}

async function readRequest(env, row) {
  return env.DB.prepare('SELECT * FROM requests WHERE id = ? AND installation_id = ? AND repository_id = ?')
    .bind(row.id, row.installation_id, row.repository_id).first();
}

async function publishCompletion(token, repository, row, env, signal) {
  if (!row.conclusion) throw new Error('Completion outcome is not retained');
  const [check, reply] = await Promise.all([
    api(token, `/repos/${repository.full_name}/check-runs/${row.check_id}`, 'GET', undefined, signal)
      .catch(error => { if (error.status === 404) return null; throw error; }),
    requestReply(token, repository, row, env, signal),
  ]);
  const writable = check?.id === row.check_id && ownedCheck(check, env.APP_ID, row.head) &&
    check.external_id === `node-repair-request:${row.id}`;
  await showRequest(token, repository, row, signal, env, [], false, writable, reply);
}

async function requestRepair(token, repository, payload, env, delivery, signal) {
  const isComment = repairComment(payload);
  let clicked = payload.check_run, clickedMatch = selectionCheck(clicked, env.APP_ID);
  if (!env.DB || (!isComment && !clickedMatch)) return;
  const installation = payload.installation.id;
  // A retained delivery is never another dispatch attempt, even after a crash.
  const replay = await env.DB.prepare('SELECT * FROM requests WHERE installation_id = ? AND repository_id = ? AND (id = ? OR comment_id = ?)')
    .bind(installation, repository.id, delivery, isComment ? payload.comment.id : null).first();
  if (replay) return;
  const prefix = `/repos/${repository.full_name}`;
  const actor = payload.sender?.login;
  if (payload.sender?.type !== 'User' || typeof actor !== 'string' || !/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/i.test(actor)) return;
  // These reads are independent. Both must finish before any reply or admission.
  const [permission, candidate] = await Promise.all([
    api(token, `${prefix}/collaborators/${actor}/permission`, 'GET', undefined, signal),
    isComment ? commentSelection(token, repository, payload, env, signal) : undefined,
  ]);
  if (!['write', 'maintain', 'admin'].includes(permission?.permission) || permission.user?.login?.toLowerCase() !== actor.toLowerCase()) return;
  const submitted = candidate;
  if (isComment) {
    if (!submitted) return;
    if (submitted.active) return;
    if (submitted.rejection) {
      await api(token, `${prefix}/issues/${payload.issue.number}/comments`, 'POST', {body: submitted.rejection}, signal);
      return;
    }
    clicked = submitted.check;
    clickedMatch = selectionCheck(clicked, env.APP_ID);
    if (!clickedMatch) return;
  }
  const number = Number(clickedMatch[1]);
  const [check, pr] = await Promise.all([
    api(token, `${prefix}/check-runs/${clicked.id}`, 'GET', undefined, signal),
    api(token, `${prefix}/pulls/${number}`, 'GET', undefined, signal),
  ]);
  if (!sameCheckIdentity(check, clicked)) {
    await refreshSelectionCheck(token, repository, number, env.APP_ID, signal, env, installation);
    return;
  }
  if (!managedPR(pr, repository, number)) return;
  let items, inputs;
  try { items = selections(pr.body); inputs = workflowInputs(pr, items, delivery); } catch { items = []; }
  const fingerprint = await selectionFingerprint(pr, items);
  const current = await api(token, `${prefix}/check-runs/${check.id}`, 'GET', undefined, signal);
  if (!items.length || (submitted && fingerprint !== submitted.fingerprint) ||
      !sameCheckIdentity(current, clicked) || !ownedCheck(current, env.APP_ID, pr.head.sha) ||
      current.status !== 'completed' || current.conclusion !== 'neutral' ||
      current.external_id !== `node-repair:${number}:${fingerprint}`) {
    await refreshSelectionCheck(token, repository, number, env.APP_ID, signal, env, installation);
    if (isComment) await api(token, `${prefix}/issues/${number}/comments`, 'POST', {
      body: 'No run started: the report or PR revision changed. Review the refreshed selections and post `/repair selected` again.',
    }, signal);
    return;
  }
  signal.throwIfAborted();
  const row = {id: delivery, installation_id: installation, repository_id: repository.id, repository: repository.full_name,
    pr: number, head: pr.head.sha, base: pr.base.sha, dispatched_ref: repository.default_branch, fingerprint,
    check_id: current.id, actor_login: actor, created_at: Date.now(), state: 'reserved',
    comment_id: isComment ? payload.comment.id : null, selections_json: JSON.stringify(items)};
  const inserted = await env.DB.prepare(`INSERT OR IGNORE INTO requests
    (id, installation_id, repository_id, repository, pr, head, base, dispatched_ref, fingerprint, check_id, actor_login, created_at, state, comment_id, selections_json)
    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    WHERE NOT EXISTS (SELECT 1 FROM requests WHERE installation_id = ? AND repository_id = ? AND check_id = ?)`)
    .bind(...Object.values(row), installation, repository.id, current.id).run();
  if (inserted.meta?.changes !== 1) {
    if (inserted.meta?.changes !== 0) throw new Error('Invalid admission result');
    return;
  }
  // Failure here retains reserved state, so redelivery cannot repeat the POST.
  await showRequest(token, repository, row, signal, env, items, isComment);
  signal.throwIfAborted();
  try {
    const run = await api(token, `${prefix}/actions/workflows/${WORKFLOW}/dispatches`, 'POST', {
      ref: row.dispatched_ref, inputs,
    }, signal);
    if (!positiveID(run?.workflow_run_id) || run.run_url !== `https://api.github.com${prefix}/actions/runs/${run.workflow_run_id}` ||
        run.html_url !== `https://github.com/${repository.full_name}/actions/runs/${run.workflow_run_id}`) {
      throw new Error('Invalid dispatch identity');
    }
    const saved = await env.DB.prepare("UPDATE requests SET state = 'dispatched', run_id = ?, run_url = ?, html_url = ? WHERE id = ? AND installation_id = ? AND repository_id = ? AND state = 'reserved'")
      .bind(run.workflow_run_id, run.run_url, run.html_url, delivery, installation, repository.id).run();
    if (saved.meta?.changes !== 1) throw new Error('Dispatch identity was not retained');
  } catch {
    // The POST may have reached GitHub. Never release this lock or repeat it.
    await env.DB.prepare("UPDATE requests SET state = 'unknown' WHERE id = ? AND installation_id = ? AND repository_id = ? AND state = 'reserved' AND run_id IS NULL")
      .bind(delivery, installation, repository.id).run();
    throw new Error('Dispatch requires inspection');
  }
}

async function commentSelection(token, repository, payload, env, signal) {
  const prefix = `/repos/${repository.full_name}`, number = payload.issue.number;
  if (payload.issue.pull_request.url !== `https://api.github.com${prefix}/pulls/${number}`) return;
  const [comment, pr] = await Promise.all([
    api(token, `${prefix}/issues/comments/${payload.comment.id}`, 'GET', undefined, signal)
      .catch(error => { if (error.status === 404) return null; throw error; }),
    api(token, `${prefix}/pulls/${number}`, 'GET', undefined, signal),
  ]);
  if (!comment || comment.id !== payload.comment.id || comment.issue_url !== `https://api.github.com${prefix}/issues/${number}` ||
      comment.user?.id !== payload.sender.id || comment.user?.type !== 'User' ||
      comment.user.login !== payload.sender.login || comment.body !== payload.comment.body ||
      comment.created_at !== payload.comment.created_at || comment.updated_at !== comment.created_at ||
      !Number.isFinite(Date.parse(comment.created_at))) return;
  if (!managedPR(pr, repository, number)) return;
  const rejection = {rejection: 'No run started: the report or selections changed, or no valid fixes are selected. Wait for a current report, review its checkboxes, and post `/repair selected` again.'};
  const active = await activeRequest(env, payload.installation.id, repository.id, number);
  if (active) return active.comment_id ? {active} : {
    rejection: `No new run started: another repair request is active. ${requestStatus(active).summary}`,
  };
  let items;
  try {
    items = selections(pr.body);
    if (!items.length || JSON.stringify(items) !== JSON.stringify(selections(payload.issue.body))) return rejection;
    // issue_comment includes the description snapshot, but has no PR head/base.
    // The report binds those revisions explicitly so a queued command cannot
    // authorize a later head, even when its checked package versions are equal.
    const lines = payload.issue.body.split(/\r?\n/).filter(line => line.includes('<!-- node-repair:revision:'));
    if (lines.length !== 1 || lines[0] !== `<!-- node-repair:revision:v1 ${pr.head.sha} ${pr.base.sha} -->`) return rejection;
    workflowInputs(pr, items);
  } catch { return rejection; }
  const fingerprint = await selectionFingerprint(pr, items);
  const check = await findSelectionCheck(token, repository, pr, env.APP_ID, `node-repair:${number}:${fingerprint}`, signal, env, payload.installation.id);
  if (!check) return rejection;
  return {check, fingerprint};
}

async function findSelectionCheck(token, repository, pr, appID, external, signal, env = {}, installation) {
  let check, total, read = 0;
  for (let page = 1; ; page++) {
    const list = await api(token, `/repos/${repository.full_name}/commits/${pr.head.sha}/check-runs?check_name=Dependency%20repair&app_id=${appID}&filter=all&per_page=100&page=${page}`, 'GET', undefined, signal);
    if (!Array.isArray(list?.check_runs) || !Number.isSafeInteger(list.total_count) || list.total_count < 0 ||
        (total !== undefined && list.total_count !== total) || list.check_runs.length !== Math.min(100, list.total_count - read)) {
      throw new Error('Incomplete Check list');
    }
    total = list.total_count;
    for (const candidate of list.check_runs) {
      if (String(candidate.app?.id) !== String(appID) || candidate.name !== CHECK ||
          candidate.head_sha !== pr.head.sha || candidate.external_id !== external) continue;
      if (!positiveID(candidate.id) || candidate.status !== 'completed') throw new Error('Repair Check is not idle');
      if (await retainedCheck(env, installation, repository.id, candidate.id)) continue;
      if (!check || candidate.id > check.id) check = candidate;
    }
    read += list.check_runs.length;
    if (read === total) return check;
  }
}

async function refreshSelectionCheck(token, repository, number, appID, signal, env = {}, installation, expectedHead) {
  const prefix = `/repos/${repository.full_name}`;
  const pr = await api(token, `${prefix}/pulls/${number}`, 'GET', undefined, signal);
  if (!managedPR(pr, repository, number) || (expectedHead && pr.head.sha !== expectedHead)) return;
  const active = await activeRequest(env, installation, repository.id, number);
  if (active?.head === pr.head.sha) return;
  let items = [], valid = true;
  try { items = selections(pr.body); workflowInputs(pr, items); } catch { valid = false; items = []; }
  const external = `node-repair:${number}:${await selectionFingerprint(pr, items)}`;
  // An exposed control may already be admitted when this read returns. Never PATCH it.
  if (await findSelectionCheck(token, repository, pr, appID, external, signal, env, installation)) return;
  const output = {
    title: !valid ? 'Repair selections need attention' : items.length ? `${items.length} selected fix${items.length === 1 ? '' : 'es'}` : 'No fixes selected',
    summary: !valid ? 'Use one valid selection block in the PR description. No run was started.' : items.length ?
      items.map(item => `- \`${item.name}\` \`${item.from} → ${item.to}\``).join('\n') +
        (env.DB ? '\n\nPost `/repair selected` in the PR conversation to request these fixes. Only one request can be active per PR. The native Run selected fixes action is also available here. The pilot only validates inputs.' :
          '\n\nSelections are displayed for review. Running fixes is not enabled yet.') :
      'Select the allowed fixes in the PR description. Editing checkboxes does not start a run.',
  };
  await api(token, `${prefix}/check-runs`, 'POST', {
    name: CHECK, head_sha: pr.head.sha, external_id: external,
    status: 'completed', conclusion: 'neutral', output,
    actions: valid && items.length && env.DB ? [ACTION] : [],
  }, signal);
}

async function completeRequest(payload, env, signal) {
  const installation = payload.installation?.id, repository = payload.repository, runID = payload.workflow_run?.id;
  if (!env.DB || ![installation, repository?.id, runID].every(positiveID)) return;
  const found = await env.DB.prepare('SELECT * FROM requests WHERE installation_id = ? AND repository_id = ? AND run_id = ? LIMIT 2')
    .bind(installation, repository.id, runID).all();
  if (!Array.isArray(found.results) || found.results.length > 1) throw new Error('Ambiguous run identity');
  let row = found.results[0];
  if (!row || repository.full_name?.toLowerCase() !== row.repository.toLowerCase()) return;
  const prefix = `/repos/${row.repository}`;
  const [token, app] = await Promise.all([
    installationToken(env, installation, repository.id, signal, {contents: 'read',
      pull_requests: row.comment_id ? 'write' : 'read', checks: 'write', actions: 'read',
      ...(row.comment_id ? {issues: 'read'} : {})}),
    appJWT(env).then(jwt => api(jwt, '/app', 'GET', undefined, signal)),
  ]);
  const [run, currentRepository] = await Promise.all([
    api(token, `${prefix}/actions/runs/${runID}`, 'GET', undefined, signal),
    api(token, prefix, 'GET', undefined, signal),
  ]);
  if (String(app?.id) !== String(env.APP_ID) || typeof app.slug !== 'string' ||
      run?.id !== runID || run.repository?.id !== row.repository_id ||
      run.repository.full_name?.toLowerCase() !== row.repository.toLowerCase() ||
      currentRepository?.id !== row.repository_id || currentRepository.full_name?.toLowerCase() !== row.repository.toLowerCase() ||
      run.path !== `.github/workflows/${WORKFLOW}` || run.event !== 'workflow_dispatch' ||
      run.head_branch !== row.dispatched_ref || run.actor?.type !== 'Bot' || run.actor.login !== `${app.slug}[bot]` ||
      run.html_url !== row.html_url || run.status !== 'completed') return;
  const completed = Date.parse(run.updated_at);
  if (!CONCLUSIONS.has(run.conclusion) || typeof run.updated_at !== 'string' || !Number.isFinite(completed) || completed <= 0) throw new Error('Invalid completed run');
  if (row.conclusion && row.conclusion !== run.conclusion) throw new Error('Conflicting retained outcome');
  if (!row.conclusion) {
    // Keep the active unique-index lock until known outputs are safely updated.
    await env.DB.prepare(`UPDATE requests SET conclusion = ?, completed_at = ?
      WHERE id = ? AND installation_id = ? AND repository_id = ? AND run_id = ? AND conclusion IS NULL AND ${ACTIVE}`)
      .bind(run.conclusion, completed, row.id, installation, repository.id, runID).run();
  }
  row = await readRequest(env, row);
  if (row?.conclusion !== run.conclusion || !Number.isFinite(row.completed_at) || row.completed_at <= 0) throw new Error('Outcome was not retained');
  await publishCompletion(token, currentRepository, row, env, signal);
  const state = ['success', 'cancelled'].includes(run.conclusion) ? run.conclusion : 'failure';
  await env.DB.prepare(`UPDATE requests SET state = ? WHERE id = ? AND installation_id = ? AND repository_id = ?
    AND run_id = ? AND conclusion = ? AND ${ACTIVE}`)
    .bind(state, row.id, installation, repository.id, runID, run.conclusion).run();
  const terminal = await readRequest(env, row);
  if (terminal?.state !== state || terminal.conclusion !== run.conclusion) throw new Error('Terminal state was not retained');
  // A terminal request keeps its own Check. A fresh idle control is separate.
  await refreshSelectionCheck(token, currentRepository, row.pr, env.APP_ID, signal, env, installation, row.head);
}

export default {
  async scheduled(event, env) {
    if (!env.DB || !Number.isFinite(event.scheduledTime)) throw new Error('Retention is not configured');
    await env.DB.prepare(`DELETE FROM requests WHERE ${TERMINAL} AND completed_at < ?`)
      .bind(event.scheduledTime - 90 * 86_400_000).run();
  },
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
      } else if (event === 'issue_comment' && repairComment(payload)) {
        await readRepository(payload, env, controller.signal, request.headers.get('x-github-delivery'));
      } else if (event === 'workflow_run' && payload.action === 'completed') {
        await completeRequest(payload, env, controller.signal);
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
