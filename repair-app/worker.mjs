// No repository code runs here. GitHub Actions owns candidate preparation.
const encoder = new TextEncoder();
const START = '<!-- node-repair:selection:v1 -->';
const END = '<!-- /node-repair:selection -->';
const VERSION = '(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)';
const LINE = new RegExp('^- \\[([ xX])\\] Allow `((?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*)` `(' + VERSION + ') → (' + VERSION + ')` by updating its explicit pin\\.$');
const WORKFLOW = 'dependency-repair.yml';
const CHECK = 'Dependency repair';
const ACTION = {label: 'Run selected fixes', description: 'Prepare and validate the selected pins', identifier: 'repair-selected'};

export function selections(body) {
  if (typeof body !== 'string' || body.split(START).length !== 2 || body.split(END).length !== 2) throw new Error('Missing repair selections');
  const block = body.split(START)[1].split(END)[0].trim();
  const result = [], names = new Set();
  for (const line of block.split('\n')) {
    const m = LINE.exec(line.trimEnd());
    if (!m) throw new Error('Invalid repair selection block');
    if (m[1].toLowerCase() !== 'x') continue;
    const old = m[3].split('.').map(Number), next = m[4].split('.').map(Number);
    if (names.has(m[2]) || old[0] !== next[0] || old[1] !== next[1] || old[2] >= next[2]) throw new Error('Only distinct patch upgrades are allowed');
    names.add(m[2]);
    result.push({name: m[2], from: m[3], to: m[4]});
  }
  if (result.length > 20) throw new Error('Too many selections');
  return result.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
}

export async function verifySignature(secret, body, signature) {
  if (!/^sha256=[a-f0-9]{64}$/.test(signature || '')) return false;
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), {name: 'HMAC', hash: 'SHA-256'}, false, ['verify']);
  const bytes = Uint8Array.from(signature.slice(7).match(/../g), x => parseInt(x, 16));
  return crypto.subtle.verify('HMAC', key, bytes, body);
}

function base64url(value) {
  const bytes = typeof value === 'string' ? encoder.encode(value) : new Uint8Array(value);
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

async function jwt(env) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({alg: 'RS256', typ: 'JWT'}));
  const claim = base64url(JSON.stringify({iat: now - 60, exp: now + 540, iss: env.APP_ID}));
  const pem = env.APP_PRIVATE_KEY.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  const key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(pem), c => c.charCodeAt(0)), {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['sign']);
  return `${header}.${claim}.${base64url(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(`${header}.${claim}`)))}`;
}

export async function api(token, path, method = 'GET', body) {
  const response = await fetch(`https://api.github.com${path}`, {
    method, redirect: 'manual',
    headers: {Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'node-dependency-repair', 'X-GitHub-Api-Version': '2026-03-10', 'Content-Type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) throw new Error(`GitHub ${method} ${path.split('?')[0]}: ${response.status}`);
  return response.status === 204 ? null : response.json();
}

function validPR(pr, repo, defaultBranch) {
  return pr.state === 'open' && pr.head?.repo?.full_name === repo && pr.base?.repo?.full_name === repo &&
    pr.head.ref === 'maintenance/node-security' && pr.base.ref === defaultBranch && pr.user?.type === 'Bot' &&
    /^[a-f0-9]{40}$/.test(pr.head.sha) && /^[a-f0-9]{40}$/.test(pr.base.sha);
}

export async function digest(pr, items) {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(JSON.stringify([pr.number, pr.head.sha, pr.base.sha, items]))))].map(x => x.toString(16).padStart(2, '0')).join('');
}

export async function handle(event, payload, delivery, env, call = api) {
  if (event === 'ping') return;
  if (!((event === 'pull_request' && ['opened', 'edited', 'synchronize', 'reopened'].includes(payload.action)) ||
      (event === 'check_run' && payload.action === 'requested_action') ||
      (event === 'workflow_run' && payload.action === 'completed'))) return;
  if (event === 'pull_request' && payload.pull_request?.head?.ref !== 'maintenance/node-security') return;
  if (event === 'workflow_run' && payload.workflow_run?.path !== `.github/workflows/${WORKFLOW}`) return;
  if (event === 'check_run' && (payload.requested_action?.identifier !== ACTION.identifier || String(payload.check_run?.app?.id) !== String(env.APP_ID))) return;
  if (!Number.isSafeInteger(payload.installation?.id) || !Number.isSafeInteger(payload.repository?.id) || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(payload.repository?.full_name || '')) return;
  const repo = payload.repository.full_name, prefix = `/repos/${repo}`;
  const installation = payload.installation.id;
  const token = (await call(await jwt(env), `/app/installations/${installation}/access_tokens`, 'POST', {
    repository_ids: [payload.repository.id],
    permissions: {contents: 'read', pull_requests: 'read', checks: 'write', actions: 'write'},
  })).token;

  if (event === 'workflow_run' && payload.action === 'completed') {
    const run = payload.workflow_run;
    const match = /^Node repair #[1-9][0-9]* · ([a-f0-9-]{36})$/.exec(run?.display_title || '');
    if (!match || run.path !== `.github/workflows/${WORKFLOW}` || run.event !== 'workflow_dispatch') return;
    const row = await env.DB.prepare('SELECT * FROM requests WHERE id = ?').bind(match[1]).first();
    if (!row || row.repository !== repo || row.installation !== installation || (row.run_id && row.run_id !== run.id)) return;
    // Fetch the canonical run instead of trusting a mutable event snapshot.
    const current = await call(token, `${prefix}/actions/runs/${run.id}`);
    if (current.display_title !== run.display_title || current.status !== 'completed' || current.path !== run.path || current.event !== 'workflow_dispatch' || current.actor?.login !== `${env.APP_SLUG}[bot]`) return;
    const check = await call(token, `${prefix}/check-runs/${row.check_id}`);
    if (check.external_id !== `node-repair-request:${row.id}`) return;
    const success = current.conclusion === 'success';
    await call(token, `${prefix}/check-runs/${row.check_id}`, 'PATCH', {
      status: 'completed', conclusion: success ? 'success' : 'failure', details_url: current.html_url, external_id: row.fingerprint,
      output: {title: success ? 'Repair validation and publication completed' : 'Repair did not complete', summary: success ? 'The selected batch passed validation and was published. Review the changes before merging.' : 'See the run for the failed step. Failed validation leaves the PR files unchanged. A publication or report failure may need inspection of the PR before another attempt.'},
      actions: success ? [] : [ACTION],
    });
    await env.DB.prepare('UPDATE requests SET status = ?, run_id = ? WHERE id = ?').bind(current.conclusion, run.id, row.id).run();
    return;
  }

  let number;
  if (event === 'pull_request' && ['opened', 'edited', 'synchronize', 'reopened'].includes(payload.action)) number = payload.number;
  else if (event === 'check_run' && payload.action === 'requested_action' && payload.requested_action?.identifier === ACTION.identifier && String(payload.check_run?.app?.id) === String(env.APP_ID)) {
    const matches = payload.check_run.pull_requests || [];
    if (matches.length !== 1) return;
    number = matches[0].number;
  } else return;
  if (!Number.isSafeInteger(number) || number < 1) return;
  const pr = await call(token, `${prefix}/pulls/${number}`);
  if (!validPR(pr, repo, payload.repository.default_branch)) return;
  let items;
  try { items = selections(pr.body); } catch { items = []; }
  const fingerprint = await digest(pr, items);
  const external = `node-repair:${number}:${fingerprint}`;

  if (event === 'pull_request') {
    // A missing caller is a setup gap, not a repair button that cannot work.
    try { await call(token, `${prefix}/actions/workflows/${WORKFLOW}`); } catch { return; }
    const checks = await call(token, `${prefix}/commits/${pr.head.sha}/check-runs?check_name=Dependency%20repair&per_page=100`);
    const check = checks.check_runs.find(c => String(c.app?.id) === String(env.APP_ID) && c.name === CHECK);
    if (check?.status === 'in_progress') return;
    const output = {title: items.length ? `${items.length} selected fixes` : 'Select fixes in the PR description', summary: items.length ? items.map(i => `- \`${i.name}\` \`${i.from} → ${i.to}\``).join('\n') + '\n\nRun selected fixes prepares and validates this batch. Merging is a separate decision.' : 'Select the allowed pin changes in the PR description, then return here. Checkboxes alone do not start a run.'};
    await call(token, `${prefix}/check-runs${check ? `/${check.id}` : ''}`, check ? 'PATCH' : 'POST', {
      ...(check ? {} : {name: CHECK, head_sha: pr.head.sha}), external_id: external,
      status: 'completed', conclusion: 'neutral', output, actions: items.length ? [ACTION] : [],
    });
    return;
  }

  if (!items.length || !/^[a-f0-9-]{36}$/.test(delivery)) return;
  if (await env.DB.prepare('SELECT id FROM requests WHERE id = ?').bind(delivery).first()) return;
  const check = await call(token, `${prefix}/check-runs/${payload.check_run.id}`);
  if (String(check.app?.id) !== String(env.APP_ID) || check.head_sha !== pr.head.sha || check.status === 'in_progress') return;
  if (check.external_id !== external) {
    await call(token, `${prefix}/check-runs/${check.id}`, 'PATCH', {
      status: 'completed', conclusion: 'neutral', external_id: external,
      output: {title: 'Selections changed; confirm the refreshed batch', summary: items.map(i => `- \`${i.name}\` \`${i.from} → ${i.to}\``).join('\n') + '\n\nReview these versions, then click Run selected fixes again. No repair was dispatched by this click.'},
      actions: [ACTION],
    });
    return;
  }
  const login = payload.sender?.login;
  if (!/^[A-Za-z0-9-]+$/.test(login || '')) return;
  const permission = await call(token, `${prefix}/collaborators/${login}/permission`);
  if (!['write', 'maintain', 'admin'].includes(permission.permission)) return;
  const inserted = await env.DB.prepare('INSERT OR IGNORE INTO requests (id, repository, pr, head, check_id, fingerprint, installation, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(delivery, repo, number, pr.head.sha, check.id, external, installation, 'dispatching', Date.now()).run();
  if (inserted.meta.changes !== 1) return;
  await call(token, `${prefix}/check-runs/${check.id}`, 'PATCH', {status: 'in_progress', external_id: `node-repair-request:${delivery}`, details_url: `https://github.com/${repo}/actions/workflows/${WORKFLOW}`, output: {title: 'Repair requested', summary: `Requested by @${login}.\n\n` + items.map(i => `- \`${i.name}\` \`${i.from} → ${i.to}\``).join('\n') + `\n\n[Open the repair workflow](https://github.com/${repo}/actions/workflows/${WORKFLOW}).`}, actions: []});
  try {
    await call(token, `${prefix}/actions/workflows/${WORKFLOW}/dispatches`, 'POST', {
      ref: payload.repository.default_branch,
      inputs: {'request-id': delivery, 'pull-request': String(number), 'expected-head': pr.head.sha, 'expected-base': pr.base.sha, selections: JSON.stringify(items)},
    });
    await env.DB.prepare('UPDATE requests SET status = ? WHERE id = ?').bind('dispatched', delivery).run();
  } catch (error) {
    // A timed-out POST may have reached GitHub. Never automatically dispatch twice.
    await call(token, `${prefix}/check-runs/${check.id}`, 'PATCH', {status: 'completed', conclusion: 'action_required', output: {title: 'Dispatch could not be confirmed', summary: 'Inspect Actions before requesting another attempt. The request may have reached GitHub; this service will not retry it automatically.'}, actions: []});
    throw error;
  }
}

export default {
  async fetch(request, env) {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/webhook') return new Response('Not found', {status: 404});
    if (!env.WEBHOOK_SECRET || !env.APP_PRIVATE_KEY || !env.APP_SLUG || !/^[1-9][0-9]*$/.test(env.APP_ID || '')) return new Response('Not configured', {status: 503});
    if (Number(request.headers.get('content-length') || 0) > 2_000_000) return new Response('Too large', {status: 413});
    const body = await request.arrayBuffer();
    if (body.byteLength > 2_000_000) return new Response('Too large', {status: 413});
    if (!await verifySignature(env.WEBHOOK_SECRET, body, request.headers.get('x-hub-signature-256'))) return new Response('Invalid signature', {status: 401});
    try {
      await handle(request.headers.get('x-github-event'), JSON.parse(new TextDecoder().decode(body)), request.headers.get('x-github-delivery'), env);
      return new Response('Accepted', {status: 200});
    } catch {
      // Do not log bodies, tokens, private repo names, or upstream response bodies.
      return new Response('Webhook processing failed; inspect the check and redeliver if no request was dispatched', {status: 500});
    }
  },
  async scheduled(_event, env) {
    await env.DB.prepare('DELETE FROM requests WHERE created_at < ?').bind(Date.now() - 90 * 86400000).run();
  },
};
