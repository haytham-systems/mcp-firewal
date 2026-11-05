const $ = (selector) => document.querySelector(selector);
const scenarios = {
  'prod-drop': { agent: 'ops', tool: 'db.drop_table', args: { database: 'prod', table: 'users' } },
  'staging-drop': { agent: 'ops', tool: 'db.drop_table', args: { database: 'staging', table: 'sessions' } },
  'org-settings': { agent: 'ops', tool: 'github.update_org_settings', args: { org: 'acme', setting: 'visibility', value: 'public' } },
  'read-file': { agent: 'research', tool: 'github.get_file', args: { owner: 'acme', repo: 'website', path: 'README.md' } },
  'write-issue': { agent: 'ops', tool: 'github.create_issue', args: { owner: 'acme', repo: 'website', title: 'Review firewall demo' } },
  payment: { agent: 'ops', tool: 'payments.send_money', args: { to: 'vendor-42', amount_cents: 50000, currency: 'USD' } },
};

let approvals = [];
let currentApproval = null;
let signingKey = null;
let challengeMatches = false;

async function request(path, options = {}) {
  const response = await fetch(path, { cache: 'no-store', ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error ?? body.message ?? `Request failed (${response.status})`);
  return body;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

function b64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

async function checkChallenge(approval) {
  try {
    const encoded = approval.challenge.split('.')[1];
    if (!encoded) return false;
    const payload = JSON.parse(atob(encoded.replaceAll('-', '+').replaceAll('_', '/'))) ;
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalJson(approval.arguments))));
    return payload.args_sha256 === b64url(digest) && payload.sub === approval.id;
  } catch {
    return false;
  }
}

function riskClass(risk) {
  return risk === 'read' ? 'risk-read' : risk === 'write' ? 'risk-write' : 'risk-destructive';
}

function renderApprovals() {
  const list = $('#approvalList');
  const pendingCount = approvals.filter((item) => item.status === 'pending').length;
  $('#pendingCount').textContent = pendingCount;
  if (!approvals.length) {
    list.innerHTML = '<div class="empty-state"><span class="empty-icon">⌛</span><strong>No requests in this view</strong><p>Run a production or payment scenario to create an approval.</p></div>';
    return;
  }
  list.innerHTML = approvals.map((item) => {
    const date = new Date(item.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const votes = item.approvals?.length ?? 0;
    return `<button class="approval-item" type="button" data-id="${escapeHtml(item.id)}">
      <span class="item-icon ${item.status === 'pending' ? 'item-pending' : 'item-closed'}">${item.status === 'pending' ? '⌛' : '✓'}</span>
      <span class="item-main"><span class="item-title"><strong>${escapeHtml(item.tool)}</strong><span class="status-mini status-${escapeHtml(item.status)}">${escapeHtml(item.status)}</span></span>
        <span class="item-resource">${escapeHtml(item.resource)}</span><span class="item-meta">${escapeHtml(item.agentId)} · ${votes}/${item.requiredApprovals} votes · ${date}</span></span>
      <span class="item-chevron">›</span>
    </button>`;
  }).join('');
  list.querySelectorAll('.approval-item').forEach((button) => button.addEventListener('click', () => void openApproval(button.dataset.id)));
}

async function refreshApprovals() {
  try {
    const status = $('#statusFilter').value;
    const result = await request(`/api/approvals?status=${encodeURIComponent(status)}`);
    approvals = result.approvals ?? [];
    renderApprovals();
    $('#lastUpdated').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (error) {
    $('#approvalList').innerHTML = `<div class="error-state">${escapeHtml(error.message)}</div>`;
  }
}

async function refreshStatus() {
  try {
    const status = await request('/api/status');
    const ready = status.firewall && status.approvals;
    $('#connectionLed').classList.toggle('online', ready);
    $('#connectionLed').classList.toggle('offline', !ready);
    $('#connectionText').textContent = ready ? 'Firewall and approval API connected' : 'Waiting for local services';
    $('#connectionHint').textContent = `Firewall :7800 ${status.firewall ? 'online' : 'offline'} · Approval API :7801 ${status.approvals ? 'online' : 'offline'}`;
  } catch {
    $('#connectionLed').classList.add('offline');
    $('#connectionText').textContent = 'Local services unavailable';
    $('#connectionHint').textContent = 'Start the MCP firewall and approval API, then refresh.';
  }
}

function setScenario() {
  const scenario = scenarios[$('#scenarioSelect').value];
  $('#agentSelect').value = scenario.agent;
  $('#agentBadge').textContent = `agent-${scenario.agent}`;
  $('#argsInput').value = JSON.stringify(scenario.args, null, 2);
}

function renderApprovalDetails(approval) {
  $('#dialogTitle').textContent = approval.tool;
  $('#dialogStatus').textContent = approval.status.toUpperCase();
  $('#dialogStatus').className = `status-badge status-${approval.status}`;
  $('#dialogRisk').textContent = approval.risk.toUpperCase();
  $('#dialogRisk').className = `risk-badge ${riskClass(approval.risk)}`;
  $('#dialogAgent').textContent = approval.agentId;
  $('#dialogResource').textContent = approval.resource;
  $('#dialogServer').textContent = approval.serverId;
  $('#dialogGroup').textContent = approval.approverGroup ?? 'Any registered approver';
  $('#dialogVotes').textContent = `${approval.requiredApprovals} signature${approval.requiredApprovals === 1 ? '' : 's'}`;
  $('#dialogArgs').textContent = JSON.stringify(approval.arguments, null, 2);
  $('#voteList').innerHTML = approval.approvals?.length
    ? `<div class="detail-label">SIGNED VOTES</div>${approval.approvals.map((vote) => `<div class="vote-row"><span>${escapeHtml(vote.approverId)}</span><span class="vote-${vote.decision}">${escapeHtml(vote.decision)}</span></div>`).join('')}`
    : '';
  $('#verificationBox').classList.toggle('verified', challengeMatches);
  $('#verificationBox').classList.toggle('verify-failed', !challengeMatches);
  $('.verify-icon').textContent = challengeMatches ? '✓' : '!';
  $('#verificationBox strong').textContent = challengeMatches ? 'Arguments match the signed challenge' : 'Challenge verification failed';
  $('#verificationBox small').textContent = challengeMatches
    ? 'The displayed arguments are bound to this approval. This does not verify the firewall HMAC.'
    : 'Do not sign: the arguments or approval identifier do not match the challenge.';
  const canVote = approval.status === 'pending' && challengeMatches && Boolean(signingKey);
  $('#approveButton').disabled = !canVote;
  $('#denyButton').disabled = !canVote;
}

function recordCallResult(result) {
  const card = $('#callResult');
  card.classList.remove('hidden', 'result-allowed', 'result-blocked');
  const denied = result.isError;
  card.classList.add(denied ? 'result-blocked' : 'result-allowed');
  $('#resultIndicator').textContent = denied ? '!' : '✓';
  $('#resultTitle').textContent = denied ? 'Firewall blocked this call' : 'Call passed through firewall';
  const code = result.firewall?.code;
  $('#resultCode').textContent = code ?? (denied ? 'BLOCKED' : 'FORWARDED');
  const content = result.content?.map((part) => part.text ?? '').filter(Boolean).join('\n') ?? '';
  $('#resultText').textContent = [content, result.firewall ? JSON.stringify(result.firewall, null, 2) : ''].filter(Boolean).join('\n\n');
}

$('#callForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#sendButton');
  button.disabled = true;
  button.innerHTML = '<span>Request in flight…</span><span class="spinner"></span>';
  $('#callResult').classList.add('hidden');
  try {
    const args = JSON.parse($('#argsInput').value);
    const scenario = scenarios[$('#scenarioSelect').value];
    const result = await request('/api/demo/call', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ agent: $('#agentSelect').value, tool: scenario.tool, args }),
    });
    recordCallResult(result);
    await refreshApprovals();
  } catch (error) {
    $('#callResult').classList.remove('hidden', 'result-allowed');
    $('#callResult').classList.add('result-blocked');
    $('#resultIndicator').textContent = '!';
    $('#resultTitle').textContent = 'Call did not complete';
    $('#resultCode').textContent = 'ERROR';
    $('#resultText').textContent = error.message;
  } finally {
    button.disabled = false;
    button.innerHTML = '<span>Run through firewall</span><span aria-hidden="true">↗</span>';
  }
});

async function openApproval(id) {
  try {
    const approval = await request(`/api/approvals/${encodeURIComponent(id)}`);
    currentApproval = approval;
    signingKey = null;
    challengeMatches = await checkChallenge(approval);
    $('#keyFile').value = '';
    $('#keyStatus').textContent = 'No key loaded';
    $('#dialogMessage').textContent = '';
    renderApprovalDetails(approval);
    $('#approvalDialog').showModal();
  } catch (error) {
    window.alert(`Could not load approval: ${error.message}`);
  }
}

async function loadSigningKey(file) {
  signingKey = null;
  $('#approveButton').disabled = true;
  $('#denyButton').disabled = true;
  if (!file) {
    $('#keyStatus').textContent = 'No key loaded';
    return;
  }
  try {
    const pem = await file.text();
    const encoded = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, '');
    const der = Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));
    const key = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign']);
    const jwk = await crypto.subtle.exportKey('jwk', key);
    if (!jwk.x) throw new Error('Not an Ed25519 private key');
    const thumbprintInput = new TextEncoder().encode(`{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`);
    const kid = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', thumbprintInput)));
    signingKey = { key, kid };
    $('#keyStatus').textContent = `${file.name} · ${kid.slice(0, 12)}…`;
    $('#approveButton').disabled = !challengeMatches || currentApproval?.status !== 'pending';
    $('#denyButton').disabled = !challengeMatches || currentApproval?.status !== 'pending';
  } catch (error) {
    $('#keyStatus').textContent = `Could not load key: ${error.message}`;
  }
}

async function submitVote(decision) {
  if (!currentApproval || !signingKey || !challengeMatches) return;
  const button = decision === 'approve' ? $('#approveButton') : $('#denyButton');
  button.disabled = true;
  $('#dialogMessage').textContent = 'Signing this approval in your browser…';
  try {
    const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'EdDSA', kid: signingKey.kid, typ: 'mcp-fw-decision+jwt' })));
    const payload = b64url(new TextEncoder().encode(JSON.stringify({
      aid: currentApproval.id,
      chal: b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(currentApproval.challenge)))),
      decision,
      jti: b64url(crypto.getRandomValues(new Uint8Array(18))),
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 120,
    })));
    const signingInput = `${header}.${payload}`;
    const signature = b64url(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, signingKey.key, new TextEncoder().encode(signingInput))));
    const result = await request(`/api/approvals/${currentApproval.id}/decisions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ signature: `${signingInput}.${signature}` }),
    });
    currentApproval = await request(`/api/approvals/${currentApproval.id}`);
    challengeMatches = await checkChallenge(currentApproval);
    signingKey = null;
    $('#keyFile').value = '';
    $('#keyStatus').textContent = 'Vote recorded · choose next approver key';
    renderApprovalDetails(currentApproval);
    $('#dialogMessage').textContent = `Vote signed. Approval status: ${result.status}.`;
    await refreshApprovals();
  } catch (error) {
    $('#dialogMessage').textContent = error.message;
    button.disabled = !signingKey || currentApproval.status !== 'pending';
  }
}

$('#scenarioSelect').addEventListener('change', setScenario);
$('#agentSelect').addEventListener('change', () => { $('#agentBadge').textContent = `agent-${$('#agentSelect').value}`; });
$('#statusFilter').addEventListener('change', () => void refreshApprovals());
$('#refreshButton').addEventListener('click', () => { void refreshStatus(); void refreshApprovals(); });
$('#closeDialog').addEventListener('click', () => $('#approvalDialog').close());
$('#keyFile').addEventListener('change', (event) => void loadSigningKey(event.target.files[0]));
$('#approveButton').addEventListener('click', () => void submitVote('approve'));
$('#denyButton').addEventListener('click', () => void submitVote('deny'));
$('#approvalDialog').addEventListener('close', () => {
  currentApproval = null;
  signingKey = null;
});

setScenario();
void refreshStatus();
void refreshApprovals();
setInterval(() => { void refreshStatus(); void refreshApprovals(); }, 3000);
