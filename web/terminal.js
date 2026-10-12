'use strict';
// 웹 터미널. app.js의 api/withReauth/show와 xterm.js(Terminal, FitAddon)를 쓴다.
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
    ({ ticket } = await withReauth(() => api('/api/terminal/ticket', { node_id: nodeId, user, cols: term.cols, rows: term.rows })));
  } catch (e) {
    status('');
    show(e.message);
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
