'use strict';
// 웹 터미널. app.js의 api/withReauth/show·패스키 도우미와 xterm.js(Terminal, FitAddon)를 쓴다.
// /terminal?node=<id>[&user=<계정>]  실시간 터미널
// /terminal?replay=<녹화 파일>        녹화 재생

const q = new URLSearchParams(location.search);
let term = null;
let fit = null;
let ws = null;

const enc = new TextEncoder();
const toB64 = (s) => {
  let bin = '';
  for (const b of enc.encode(s)) bin += String.fromCharCode(b);
  return btoa(bin);
};
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function status(text) { $('term-status').textContent = text; }

function makeTerminal() {
  term = new Terminal({
    cursorBlink: true,
    fontFamily: 'ui-monospace, "SFMono-Regular", Menlo, Consolas, "Noto Sans Mono CJK KR", monospace',
    fontSize: 14,
    scrollback: 5000,
    theme: matchMedia('(prefers-color-scheme: dark)').matches
      ? { background: '#0f1115', foreground: '#e8eaee' }
      : { background: '#ffffff', foreground: '#16181d', cursor: '#16181d', selectionBackground: '#c9d6ff' },
  });
  fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($('term'));
  fit.fit();
  window.addEventListener('resize', () => {
    fit.fit();
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: 'resize', c: term.cols, r: term.rows }));
  });
  term.onData((d) => {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: 'in', d: toB64(d) }));
  });
}

async function connect(nodeId, user) {
  $('term-connect').hidden = true;
  status('패스키 확인 중…');
  let ticket;
  try {
    // 서버(Agent)가 이 서명을 직접 확인한다: 이 서버, 이 계정, 지금
    const opts = await api('/api/terminal/options', { node_id: nodeId, user, cols: term.cols, rows: term.rows });
    const cred = await navigator.credentials.get({ publicKey: toRequestOptions(opts.publicKey) });
    ({ ticket } = await api('/api/terminal/ticket', { pending: opts.pending, credential: assertionJson(cred) }));
  } catch (e) {
    status('');
    if (e.message === 'passkey_required') show('터미널을 열려면 패스키가 필요합니다. 계정 화면에서 이 기기에 패스키를 등록하세요 (서버가 터미널을 열 때마다 그 서명을 직접 확인합니다).');
    else if (e.message === 'term_trust_missing') show('이 서버가 믿는 패스키가 이 계정에 없습니다. 새로 등록한 패스키라면 관리자가 서버 화면에서 터미널 신뢰 목록 변경을 승인해야 합니다.');
    else show(e.name ? friendlyWebAuthnError(e) : e.message);
    $('term-connect').hidden = false;
    return;
  }
  show('', 'ok');
  status('연결 중…');
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/api/terminal/ws?ticket=${encodeURIComponent(ticket)}`);
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.t === 'out') term.write(fromB64(m.d));
    else if (m.t === 'opened') {
      status(`${user} · 연결됨 (화면 출력은 녹화됩니다)`);
      $('term-close').hidden = false;
      term.focus();
    } else if (m.t === 'exit') {
      term.write(`\r\n\x1b[2m[${window.t(m.error ? `연결 종료: ${m.error}` : '연결 종료')}]\x1b[0m\r\n`);
    }
  };
  ws.onclose = () => {
    status(`${user} · 연결 끊김`);
    $('term-close').hidden = true;
    $('term-connect').textContent = '다시 연결';
    $('term-connect').hidden = false;
    ws = null;
  };
}

// ---------- 파일 올리기·내려받기 ----------
// 파일마다 패스키로 "이 서버·계정·경로(·크기·SHA-256)"에 서명하고, 서버(Agent)가 그 서명과 내용을 직접 확인한다.

const FILE_WINDOW = 2 << 20; // 서버가 받았다고 알리기 전에 보낼 수 있는 양
const FILE_CHUNK = 192 << 10;

function bytesToB64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 8192) s += String.fromCharCode.apply(null, u8.subarray(i, i + 8192));
  return btoa(s);
}

async function sha256Hex(buf) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  return Array.from(h, (b) => b.toString(16).padStart(2, '0')).join('');
}

// "~/a" → "a" (Agent는 홈 기준 상대 경로로 받는다)
function normPath(p) {
  p = p.trim();
  return p.startsWith('~/') ? p.slice(2) : p;
}

function fileStatus(text) { $('files-status').textContent = text; }

async function fileSocket(body) {
  const opts = await api('/api/files/options', body);
  const cred = await navigator.credentials.get({ publicKey: toRequestOptions(opts.publicKey) });
  const { ticket } = await api('/api/files/ticket', { pending: opts.pending, credential: assertionJson(cred) });
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  return new WebSocket(`${proto}://${location.host}/api/files/ws?ticket=${encodeURIComponent(ticket)}`);
}

async function uploadFile(nodeId, user, file, path) {
  if (file.size > 100 << 20) throw new Error('파일은 100MB까지입니다');
  fileStatus('파일 확인 중…');
  const buf = new Uint8Array(await file.arrayBuffer());
  const sha = await sha256Hex(buf);
  fileStatus('패스키로 승인하세요…');
  const ws = await fileSocket({ node_id: nodeId, user, op: 'put', path, size: buf.length, sha256: sha });
  return new Promise((resolve, reject) => {
    let sent = 0, acked = 0, ended = false;
    const pump = () => {
      while (sent < buf.length && sent - acked < FILE_WINDOW) {
        const end = Math.min(sent + FILE_CHUNK, buf.length);
        ws.send(JSON.stringify({ t: 'chunk', d: bytesToB64(buf.subarray(sent, end)) }));
        sent = end;
      }
      if (sent === buf.length && !ended) { ended = true; ws.send(JSON.stringify({ t: 'end' })); }
      fileStatus(`올리는 중… ${Math.round((acked / Math.max(buf.length, 1)) * 100)}%`);
    };
    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.t === 'ready') pump();
      else if (m.t === 'ack') { acked = m.n; pump(); }
      else if (m.t === 'done') resolve(m);
      else if (m.t === 'error') reject(new Error(m.error));
    };
    ws.onclose = () => reject(new Error('연결이 끊겼습니다'));
  });
}

async function downloadFile(nodeId, user, path) {
  fileStatus('패스키로 승인하세요…');
  const ws = await fileSocket({ node_id: nodeId, user, op: 'get', path });
  const parts = [];
  let got = 0;
  const done = await new Promise((resolve, reject) => {
    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.t === 'data') { const b = fromB64(m.d); parts.push(b); got += b.length; fileStatus(`받는 중… ${(got / 1048576).toFixed(1)}MB`); }
      else if (m.t === 'done') resolve(m);
      else if (m.t === 'error') reject(new Error(m.error));
    };
    ws.onclose = () => reject(new Error('연결이 끊겼습니다'));
  });
  const all = new Uint8Array(got);
  let off = 0;
  for (const p of parts) { all.set(p, off); off += p.length; }
  if (all.length !== done.size || (await sha256Hex(all)) !== done.sha256) throw new Error('받은 내용이 서버의 파일과 다릅니다');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([all]));
  a.download = path.split('/').pop() || 'download';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  return done;
}

function initFiles(nodeId, userOf) {
  const dlg = $('files-dialog');
  $('term-files').hidden = false;
  $('term-files').addEventListener('click', () => { $('files-user').textContent = userOf(); fileStatus(''); dlg.showModal(); });
  $('files-close').addEventListener('click', () => dlg.close());
  $('up-file').addEventListener('change', () => { const f = $('up-file').files[0]; if (f && !$('up-path').value) $('up-path').value = f.name; });
  const busy = (on) => { $('up-go').disabled = on; $('down-go').disabled = on; };
  const why = (e) => (e.message === 'term_trust_missing' ? '이 서버가 믿는 패스키가 이 계정에 없습니다. 관리자가 서버 화면에서 신뢰 목록 변경을 승인해야 합니다.'
    : e.message === 'passkey_required' ? '패스키가 필요합니다. 계정 화면에서 등록하세요.' : e.name ? friendlyWebAuthnError(e) : e.message);
  $('up-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    busy(true);
    try {
      const r = await uploadFile(nodeId, userOf(), $('up-file').files[0], normPath($('up-path').value));
      fileStatus(`올렸습니다 (${r.size}바이트)`);
    } catch (e) { fileStatus(why(e)); }
    busy(false);
  });
  $('down-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    busy(true);
    try {
      const r = await downloadFile(nodeId, userOf(), normPath($('down-path').value));
      fileStatus(`내려받았습니다 (${r.size}바이트)`);
    } catch (e) { fileStatus(why(e)); }
    busy(false);
  });
}

async function initLive() {
  const nodeId = Number(q.get('node'));
  const node = await api(`/api/nodes/${nodeId}`);
  document.title = `Douve 터미널 · ${node.name}`;
  $('term-title').textContent = node.name;
  const users = (node.inventory && node.inventory.terminal_users) || [];
  if (!node.connected) { show('이 서버가 지금 Douve에 접속해 있지 않습니다.'); return; }
  if (!users.length) { show('이 서버에서 터미널을 열 수 있는 계정이 없습니다 (sudo/wheel 그룹의 일반 계정 필요).'); return; }
  const sel = $('term-user');
  sel.replaceChildren(...users.map((u) => Object.assign(document.createElement('option'), { value: u, textContent: u })));
  if (q.get('user') && users.includes(q.get('user'))) sel.value = q.get('user');
  sel.hidden = users.length < 2;
  makeTerminal();
  initFiles(nodeId, () => sel.value);
  $('term-connect').addEventListener('click', () => connect(nodeId, sel.value));
  $('term-close').addEventListener('click', () => ws && ws.close());
  window.addEventListener('beforeunload', (e) => { if (ws) { e.preventDefault(); } });
  connect(nodeId, sel.value);
}

// 녹화 재생: asciicast v2. 2초 넘는 공백은 줄여서 재생한다.
async function initReplay() {
  const name = q.get('replay');
  $('term-title').textContent = `녹화 · ${name}`;
  let text;
  try {
    text = await withReauth(async () => {
      const r = await fetch(`/api/terminal/recordings/${encodeURIComponent(name)}`, { credentials: 'same-origin' });
      if (!r.ok) {
        let msg = `요청 실패 (${r.status})`;
        try { msg = (await r.json()).error || msg; } catch (_) { /* */ }
        const err = new Error(msg);
        err.status = r.status;
        throw err;
      }
      return r.text();
    });
  } catch (e) { show(e.message); return; }
  const lines = text.split('\n').filter(Boolean);
  const header = JSON.parse(lines.shift());
  makeTerminal();
  term.resize(header.width || 80, header.height || 24);
  status(`${header.title || ''} · ${new Date(header.timestamp * 1000).toLocaleString(window.douveLocale)}`);
  const events = lines.map((l) => JSON.parse(l));
  let clock = 0;
  let last = 0;
  for (const [t, kind, data] of events) {
    clock += Math.min(t - last, 2);
    last = t;
    setTimeout(() => {
      if (kind === 'o') term.write(data);
      else if (kind === 'r') { const [c, r] = data.split('x').map(Number); term.resize(c, r); }
    }, clock * 1000);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const run = q.get('replay') ? initReplay : initLive;
  run().catch((e) => {
    if (e.status === 401) location.href = `/login?rd=${encodeURIComponent(location.pathname + location.search)}`;
    else show(e.message);
  });
});
