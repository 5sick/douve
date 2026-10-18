'use strict';
// 대시보드·서버 상세 화면. app.js의 공용 함수($, api, show, withReauth, text, li, fmtTime)를 쓴다.

const POLL_MS = 5000;

function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}
const fmtRate = (n) => `${fmtBytes(n)}/s`;
const pct = (used, total) => (total > 0 ? (100 * used) / total : 0);

function fmtAgo(sec) {
  if (sec < 60) return `${Math.max(0, Math.round(sec))}초 전`;
  if (sec < 3600) return `${Math.round(sec / 60)}분 전`;
  if (sec < 86400) return `${Math.round(sec / 3600)}시간 전`;
  return `${Math.round(sec / 86400)}일 전`;
}

function fmtUptime(sec) {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  return d > 0 ? `${d}일 ${h}시간` : `${h}시간 ${Math.floor((sec % 3600) / 60)}분`;
}

function el(tag, attrs = {}, children = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else e.setAttribute(k, v);
  }
  e.append(...children);
  return e;
}

function bar(label, value, detail) {
  const level = value >= 90 ? ' crit' : value >= 75 ? ' warn' : '';
  const fill = el('div', { class: `fill${level}` });
  fill.style.width = `${Math.min(100, value).toFixed(1)}%`; // CSP상 style 속성 대신 CSSOM
  return el('div', { class: 'bar' }, [
    el('div', { class: 'lbl' }, [el('span', { text: label }), el('span', { text: detail })]),
    el('div', { class: 'track' }, [fill]),
  ]);
}

function statusText(n, now) {
  if (n.connected) return '접속 중';
  if (!n.last_seen_at) return '아직 접속한 적 없음';
  return `응답 없음 · ${fmtAgo(now - n.last_seen_at)}`;
}

function renderAlerts(nodes) {
  const box = $('alerts');
  const items = [];
  for (const n of nodes) for (const a of n.alerts) items.push({ n, a });
  box.replaceChildren(...items.map(({ n, a }) =>
    el('div', { class: 'alert-line' }, [icon('triangle-alert', 16), ` ${n.name} — ${a.message} (${fmtTime(a.started_at)}부터)`])));
  box.hidden = items.length === 0;
}

// ---------- 대시보드 ----------

function nodeCard(n, now) {
  const s = n.latest;
  const children = [
    el('h3', {}, [el('span', { class: `dot ${n.connected ? 'on' : 'off'}` }), el('span', { text: n.name })]),
    el('div', { class: 'meta', text: `${n.hostname || ''} · ${statusText(n, now)}` }),
  ];
  if (s && n.connected) {
    const root = s.disks[0];
    children.push(
      bar('CPU', s.cpu, `${s.cpu.toFixed(0)}%`),
      bar('메모리', pct(s.mem.used, s.mem.total), `${fmtBytes(s.mem.used)} / ${fmtBytes(s.mem.total)}`),
    );
    if (root) children.push(bar(`디스크 ${root.mount}`, pct(root.used, root.total), `${fmtBytes(root.used)} / ${fmtBytes(root.total)}`));
    children.push(el('div', { class: 'stats' }, [
      el('span', { text: `↓ ${fmtRate(s.net.rx)}` }),
      el('span', { text: `↑ ${fmtRate(s.net.tx)}` }),
      el('span', { text: `load ${s.load[0].toFixed(2)}` }),
      el('span', { text: `가동 ${fmtUptime(s.uptime)}` }),
    ]));
  }
  for (const a of n.alerts) children.push(el('span', { class: 'badge', text: a.message }));
  return el('a', { class: `card node${n.connected ? '' : ' offline'}`, href: `/node?id=${n.id}` }, children);
}

async function loadNodes() {
  const { nodes, now, security_open: secOpen } = await api('/api/nodes');
  $('nodes').replaceChildren(...nodes.map((n) => nodeCard(n, now)));
  $('empty').hidden = nodes.length > 0;
  const online = nodes.filter((n) => n.connected).length;
  const alerts = nodes.reduce((k, n) => k + n.alerts.length, 0);
  $('summary').textContent = nodes.length
    ? `서버 ${nodes.length}대 · 접속 ${online}대${alerts ? ` · 알림 ${alerts}건` : ''}`
    : '등록된 서버 없음';
  renderAlerts(nodes);
  if (secOpen) {
    const box = $('alerts');
    const a = el('a', { href: '/security', class: 'alert-line' }, [icon('shield-check', 16), ` 확인이 필요한 보안 이슈 ${secOpen}건 →`]);
    box.append(el('div', {}, [a]));
    box.hidden = false;
  }
  return nodes;
}

// 터미널 신뢰 목록: 패스키 추가·삭제, 역할·서버 권한 변경은 관리자가 패스키로 승인해야 서버(Agent)에 반영된다.
// 서버는 승인 없는 변경을 받지 않는다 (Hub가 장악돼도 공격자 패스키를 넣을 수 없게).
function trustKeyLine(kind, k, names) {
  const scope = k.admin ? '관리자' : `허락된 서버: ${k.nodes.join(', ')}`;
  return el('li', {}, [el('span', { text: kind }), ': ',
    el('span', { 'data-no-i18n': '', text: `${k.user} · ${names[k.id] || '-'}` }), ' (', el('span', { text: scope }), ')']);
}

let trustAdmin = null; // 관리자만 신뢰 목록을 본다 (처음 한 번 역할 확인)

async function loadTrust(nodes) {
  const box = $('trust-banner');
  if (trustAdmin === null) trustAdmin = await api('/api/summary').then((x) => x.role === 'admin', () => false);
  if (!trustAdmin) return;
  let st;
  try {
    st = await api('/api/terminal/trust');
  } catch (_) { box.hidden = true; return; }
  const items = [];
  if (st.pending) {
    const cur = new Map(st.keys.map((k) => [k.id, k]));
    const want = new Map(st.desired.map((k) => [k.id, k]));
    const lines = [];
    for (const [id, k] of want) {
      if (!cur.has(id)) lines.push(trustKeyLine('추가됨', k, st.key_names));
      else if (JSON.stringify(cur.get(id)) !== JSON.stringify(k)) lines.push(trustKeyLine('바뀜', k, st.key_names));
    }
    for (const [id, k] of cur) if (!want.has(id)) lines.push(trustKeyLine('제거됨', k, st.key_names));
    const btn = el('button', { class: 'primary small', text: '패스키로 승인' });
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      try {
        const opts = await api('/api/terminal/trust/options', {});
        const cred = await navigator.credentials.get({ publicKey: toRequestOptions(opts.publicKey) });
        await api('/api/terminal/trust/sign', { pending: opts.pending, credential: assertionJson(cred) });
        show('승인했습니다. 서버들에 반영합니다.', 'ok');
        setTimeout(() => loadTrust(nodes), 1500);
      } catch (e) {
        show(e.name ? friendlyWebAuthnError(e) : e.message);
      }
      btn.disabled = false;
    });
    items.push(el('strong', { text: '터미널 신뢰 목록에 승인되지 않은 변경이 있습니다.' }),
      el('p', { class: 'meta', text: '서버는 관리자 패스키로 승인한 목록의 패스키로만 터미널을 엽니다. 승인 전까지 아래 변경은 서버에 반영되지 않습니다.' }),
      el('ul', {}, lines),
      el('div', {}, [btn]));
  }
  const behind = st.nodes.filter((n) => n.connected && (n.error || (n.version || 0) < st.version));
  if (behind.length) {
    items.push(el('strong', { text: '터미널 신뢰 목록이 아직 반영되지 않은 서버' }),
      el('ul', {}, behind.map((n) => el('li', {}, [el('span', { 'data-no-i18n': '', text: n.name }), ': ',
        el('span', { text: n.error || `버전 ${n.version || 0} / ${st.version}` })]))));
  }
  box.replaceChildren(...items);
  box.hidden = items.length === 0;
}

function initJoinDialog() {
  const dlg = $('join-dialog');
  let waitTimer = null;
  let expireTimer = null;
  const reset = () => {
    clearInterval(waitTimer);
    clearInterval(expireTimer);
    $('join-form').hidden = false;
    $('join-result').hidden = true;
    $('join-name').value = '';
  };
  $('add-node').addEventListener('click', () => { reset(); dlg.showModal(); });
  $('join-close').addEventListener('click', () => dlg.close());
  dlg.addEventListener('close', reset);

  $('join-create').addEventListener('click', async (ev) => {
    ev.preventDefault();
    try {
      const before = new Set((await api('/api/nodes')).nodes.map((n) => n.id));
      const r = await withReauth(() => api('/api/nodes/join-token', { name: $('join-name').value.trim() }));
      show('', 'ok');
      $('join-cmd').textContent = r.command;
      $('join-form').hidden = true;
      $('join-result').hidden = false;
      $('join-wait').textContent = '서버가 접속하기를 기다리는 중…';
      const tick = () => {
        const left = r.expires_at - Math.floor(Date.now() / 1000);
        $('join-expire').textContent = left > 0 ? `${Math.floor(left / 60)}분 ${left % 60}초 뒤 만료` : '만료됨 — 다시 만드세요';
      };
      tick();
      expireTimer = setInterval(tick, 1000);
      waitTimer = setInterval(async () => {
        const nodes = await loadNodes().catch(() => []);
        const fresh = nodes.find((n) => !before.has(n.id));
        if (fresh) {
          $('join-wait').textContent = fresh.connected ? `${fresh.name} 접속 완료 ✓` : `${fresh.name} 등록됨, 접속 대기 중…`;
          if (fresh.connected) clearInterval(waitTimer);
        }
      }, 2000);
    } catch (e) {
      dlg.close();
      show(e.message);
    }
  });

  $('join-copy').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('join-cmd').textContent);
      $('join-copy').textContent = '복사됨';
      setTimeout(() => { $('join-copy').textContent = '복사'; }, 1500);
    } catch (_) {
      getSelection().selectAllChildren($('join-cmd'));
    }
  });
}

async function initDashboard() {
  initJoinDialog();
  const refresh = () => loadNodes().then(loadTrust).catch((e) => {
    if (e.status === 401) location.href = `/login?rd=${encodeURIComponent(location.pathname)}`;
    else show(e.message);
  });
  await refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, POLL_MS);
}

// ---------- 서버 상세 ----------

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

// 기간별 가로축: 보여줄 길이, 눈금 간격, 이보다 긴 빈틈은 선을 끊는다 (초)
const RANGES = {
  live: { span: 1800, step: 300, gap: 45 },
  '6h': { span: 6 * 3600, step: 3600, gap: 600 },
  '24h': { span: 86400, step: 4 * 3600, gap: 1200 },
  '7d': { span: 7 * 86400, step: 86400, gap: 7200 },
  '30d': { span: 30 * 86400, step: 5 * 86400, gap: 6 * 3600 },
};

// 눈금 위치: 지역 시간 기준으로 step 경계에 맞춘다 (5분·1시간·4시간·자정)
function timeTicks(t0, t1, step) {
  const d = new Date(t0 * 1000);
  d.setSeconds(0, 0);
  if (step < 3600) {
    const m = step / 60;
    d.setMinutes(Math.ceil(d.getMinutes() / m) * m);
  } else if (step < 86400) {
    const hh = step / 3600;
    d.setMinutes(0);
    d.setHours(Math.ceil(d.getHours() / hh) * hh);
  } else {
    d.setHours(24, 0, 0, 0); // 다음 자정
  }
  const out = [];
  for (let t = d.getTime() / 1000; t <= t1; t += step) out.push(t);
  return out;
}

// 의존성 없는 선 그래프. series = [{ values: [[ts, v], ...], color }]
function drawChart(canvas, series, { max = null, format = (v) => v.toFixed(0), range = 'live', now = Date.now() / 1000 } = {}) {
  const R = RANGES[range] || RANGES.live;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth;
  const h = canvas.clientHeight;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  const g = canvas.getContext('2d');
  g.scale(dpr, dpr);
  g.clearRect(0, 0, w, h);
  const t1 = now;
  const t0 = now - R.span;
  const padB = 16;
  const all = series.flatMap((s) => s.values).filter((p) => p[0] >= t0);
  const top = max ?? Math.max(1, ...all.map((p) => p[1])) * 1.15;
  const x = (t) => ((t - t0) / (t1 - t0)) * (w - 2) + 1;
  const padT = 16; // 맨 위 눈금 라벨 자리
  const y = (v) => h - padB - (Math.min(v, top) / top) * (h - padB - padT);
  g.font = '11px system-ui, sans-serif';
  // 가로 격자 + 세로축 값
  g.lineWidth = 1;
  for (const f of [0, 0.5, 1]) {
    g.strokeStyle = css('--line');
    g.beginPath();
    g.moveTo(0, Math.round(y(top * f)) + 0.5);
    g.lineTo(w, Math.round(y(top * f)) + 0.5);
    g.stroke();
    if (f > 0) {
      g.fillStyle = css('--muted');
      g.fillText(format(top * f), 2, y(top * f) - 3);
    }
  }
  // 시간 눈금
  const two = (n) => String(n).padStart(2, '0');
  const fmtT = (t) => {
    const d = new Date(t * 1000);
    return R.step >= 86400 ? `${d.getMonth() + 1}/${d.getDate()}` : `${two(d.getHours())}:${two(d.getMinutes())}`;
  };
  g.fillStyle = css('--muted');
  for (const t of timeTicks(t0, t1, R.step)) {
    const px = x(t);
    g.strokeStyle = css('--line');
    g.beginPath();
    g.moveTo(Math.round(px) + 0.5, h - padB);
    g.lineTo(Math.round(px) + 0.5, h - padB + 3);
    g.stroke();
    const label = fmtT(t);
    const lw = g.measureText(label).width;
    if (px - lw / 2 > 0 && px + lw / 2 < w) g.fillText(label, px - lw / 2, h - 3);
  }
  if (all.length < 2) {
    g.fillStyle = css('--muted');
    g.fillText(window.t(range === 'live' ? '데이터 수집 중…' : '이 기간의 기록이 없습니다'), w / 2 - 50, h / 2);
    return;
  }
  // 선 (빈틈이 길면 끊음)
  for (const s of series) {
    g.strokeStyle = s.color;
    g.lineWidth = 1.6;
    g.lineJoin = 'round';
    g.beginPath();
    let prev = null;
    for (const [t, v] of s.values) {
      if (t < t0) continue;
      if (prev === null || t - prev > R.gap) g.moveTo(x(t), y(v));
      else g.lineTo(x(t), y(v));
      prev = t;
    }
    g.stroke();
  }
}

const state = { id: null, range: 'live', node: null };

function seriesFromRecent(recent) {
  return {
    cpu: recent.map((s) => [s.ts, s.cpu]),
    mem: recent.map((s) => [s.ts, pct(s.mem.used, s.mem.total)]),
    rx: recent.map((s) => [s.ts, s.net.rx]),
    tx: recent.map((s) => [s.ts, s.net.tx]),
    disk: recent.filter((s) => s.disks[0]).map((s) => [s.ts, pct(s.disks[0].used, s.disks[0].total)]),
  };
}

function seriesFromRows(rows) {
  // columns: ts, cpu, mem_used, mem_total, disk_used, disk_total, net_rx, net_tx, load1
  return {
    cpu: rows.map((r) => [r[0], r[1]]),
    mem: rows.map((r) => [r[0], pct(r[2], r[3])]),
    rx: rows.map((r) => [r[0], r[6]]),
    tx: rows.map((r) => [r[0], r[7]]),
    disk: rows.map((r) => [r[0], pct(r[4], r[5])]),
  };
}

function drawAll(sr) {
  const accent = css('--accent');
  const ok = css('--ok');
  const now = state.node?.now ?? Date.now() / 1000; // 서버 시각 기준 (브라우저 시계 오차 무시)
  const p = { max: 100, format: (v) => `${v.toFixed(0)}%`, range: state.range, now };
  drawChart($('c-cpu'), [{ values: sr.cpu, color: accent }], p);
  drawChart($('c-mem'), [{ values: sr.mem, color: accent }], p);
  drawChart($('c-disk'), [{ values: sr.disk, color: accent }], p);
  drawChart($('c-net'), [{ values: sr.rx, color: accent }, { values: sr.tx, color: ok }], { format: fmtRate, range: state.range, now });
}

function listOrNone(id, items, render, none) {
  const ul = $(id);
  ul.replaceChildren(...(items.length ? items.map(render) : [el('li', { class: 'none', text: none })]));
}

// 클라우드 방화벽 안내 (공유기가 아니라 클라우드 쪽에서 막는다)
const CLOUD_GUIDE = {
  oci: ['Oracle Cloud', 'OCI 콘솔 → 네트워킹 → 가상 클라우드 네트워크 → 서브넷의 보안 목록 → 수신 규칙 추가: 소스 0.0.0.0/0, TCP 80과 443.'],
  aws: ['AWS', 'EC2 콘솔 → 인스턴스 → 보안 → 보안 그룹 → 인바운드 규칙 편집: HTTP(80)·HTTPS(443), 소스 0.0.0.0/0.'],
  gcp: ['Google Cloud', 'VPC 네트워크 → 방화벽 → 방화벽 규칙 만들기: 수신, 이 VM, tcp:80,443, 소스 0.0.0.0/0 (또는 VM 수정에서 HTTP·HTTPS 트래픽 허용).'],
  azure: ['Azure', '가상 머신 → 네트워킹 → 인바운드 포트 규칙 추가: 80, 443.'],
  hetzner: ['Hetzner', 'Cloud 콘솔 → 방화벽(쓰는 경우) → 인바운드 규칙: TCP 80, 443.'],
  digitalocean: ['DigitalOcean', 'Networking → Firewalls(쓰는 경우) → Inbound Rules: HTTP, HTTPS.'],
  vultr: ['Vultr', 'Network → Firewall(쓰는 경우) → TCP 80, 443 허용.'],
  linode: ['Linode/Akamai', 'Cloud Firewalls(쓰는 경우) → Inbound: TCP 80, 443 허용.'],
  scaleway: ['Scaleway', 'Security Groups → Inbound: TCP 80, 443 허용.'],
};

function isPublicIp(ip) {
  const m = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(ip || '');
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return !(a === 10 || a === 127 || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b < 128) || (a === 169 && b === 254));
}

function renderReach(n) {
  $('reach-box').hidden = !n.edge;
  if (!n.edge) return;
  const box = $('reach');
  const cloud = (n.inventory?.system || {}).cloud;
  const items = [];
  if (cloud && CLOUD_GUIDE[cloud]) {
    const [name, how] = CLOUD_GUIDE[cloud];
    items.push(el('div', {}, [el('strong', { text: `클라우드 서버 (${name})` })]),
      el('div', { class: 'meta', text: `공유기 대신 클라우드 방화벽이 막습니다. ${how} 서버 안의 방화벽(ufw·firewalld)도 확인하세요.` }));
    box.replaceChildren(...items);
    return;
  }
  const toggle = el('input', { type: 'checkbox', id: 'pf-on' });
  toggle.checked = !!n.port_forward;
  toggle.addEventListener('change', async () => {
    try {
      await withReauth(() => api('/api/nodes/portforward', { id: n.id, on: toggle.checked }));
      show(toggle.checked ? '공유기에 80·443을 요청했습니다. 잠시 후 결과가 보입니다.' : '공유기 포트 자동 열기를 껐습니다 (연 포트를 닫습니다).', 'ok');
      setTimeout(() => refresh().catch(() => {}), 4000);
    } catch (e) { toggle.checked = !toggle.checked; show(e.message); }
  });
  items.push(el('label', { class: 'check' }, [toggle, ' 공유기에서 80·443 자동 열기 (UPnP/NAT-PMP)']),
    el('div', { class: 'meta', text: '집 공유기 뒤에 있는 서버라면 공유기에 포트포워딩을 요청합니다. 공유기 설정에서 UPnP가 켜져 있어야 합니다.' }));
  const pm = n.portmap;
  if (n.port_forward && pm) {
    if (!pm.gateway) {
      items.push(el('div', { class: 'banner' }, [el('strong', { text: '공유기가 자동 열기를 지원하지 않습니다.' }),
        el('div', { class: 'meta', text: '공유기 관리 화면(보통 192.168.0.1 또는 192.168.1.1)의 포트포워딩 메뉴에서 TCP 80·443을 이 서버로 직접 연결하세요. ipTIME: 고급 설정 → NAT/라우터 관리 → 포트포워드 설정.' })]));
    } else {
      items.push(el('div', { class: 'meta', text: `공유기 ${pm.gateway === 'upnp' ? 'UPnP' : 'NAT-PMP'} · 외부 주소 ${pm.external_ip || '알 수 없음'} · ${fmtTime(pm.checked_at)} 확인` }));
      for (const m of pm.mappings || []) {
        items.push(el('div', {}, [el('span', { class: `dot ${m.ok ? 'on' : 'off'}` }), ` ${m.proto.toUpperCase()} ${m.port} `,
          el('span', { class: 'meta', text: m.ok ? '열림' : (m.error || '실패') })]));
      }
      const doubleNat = pm.external_ip && isPublicIp(n.last_ip) && n.last_ip !== pm.external_ip;
      if (pm.cgnat || doubleNat) {
        items.push(el('div', { class: 'banner' }, [el('strong', { text: '통신사 NAT(CGNAT) 또는 이중 공유기 뒤에 있습니다.' }),
          el('div', { class: 'meta', text: '공유기에 포트를 열어도 인터넷에서 닿지 않습니다. 앞쪽 공유기도 함께 설정하거나, Tailscale 모드 또는 공인 IP가 있는 서버(클라우드 VM)를 입구로 쓰세요.' })]));
      }
    }
  }
  box.replaceChildren(...items);
}

function renderNode(n) {
  state.node = n;
  document.title = `Douve · ${n.name}`;
  $('name').textContent = n.name;
  $('status-dot').className = `dot ${n.connected ? 'on' : 'off'}`;
  $('subtitle').textContent = `${n.hostname} · ${statusText(n, n.now)}`;
  $('edge').textContent = n.edge ? '입구 해제' : '입구로 지정';
  const termUsers = (n.inventory && n.inventory.terminal_users) || [];
  $('open-term').href = `/terminal?node=${n.id}`;
  $('open-term').hidden = !n.connected || termUsers.length === 0 || state.features?.terminal === false;
  renderAlerts([n]);
  renderReach(n);

  const s = n.latest;
  $('v-cpu').textContent = s ? `${s.cpu.toFixed(0)}%` : '';
  $('v-mem').textContent = s ? `${fmtBytes(s.mem.used)} / ${fmtBytes(s.mem.total)}` : '';
  $('v-net').textContent = s ? `↓ ${fmtRate(s.net.rx)} ↑ ${fmtRate(s.net.tx)}` : '';
  $('v-disk').textContent = s && s.disks[0] ? `${fmtBytes(s.disks[0].used)} / ${fmtBytes(s.disks[0].total)}` : '';
  if (state.range === 'live') drawAll(seriesFromRecent(n.recent));
  else if (Date.now() - lastRangeFetch > 60000) loadRange().catch(() => {});

  const inv = n.inventory || {};
  const sys = inv.system || {};
  const kv = [
    ['OS', sys.os], ['커널', sys.kernel], ['CPU', sys.cpus ? `${sys.cpus}코어 (${sys.arch})` : ''],
    ['가동 시간', s ? fmtUptime(s.uptime) : ''], ['load', s ? s.load.map((v) => v.toFixed(2)).join(' / ') : ''],
    ['스왑', s && s.swap.total ? `${fmtBytes(s.swap.used)} / ${fmtBytes(s.swap.total)}` : '없음'],
    ['메시 주소', n.mesh_address], ['역할', n.edge ? '입구(edge) — 공개 HTTPS 처리' : ''],
    ['Agent', n.agent_version], ['접속 IP', n.last_ip], ['등록일', fmtTime(n.created_at)],
  ];
  $('system').replaceChildren(...kv.filter(([, v]) => v).flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { text: v })]));

  listOrNone('disks', s ? s.disks : [], (d) => el('li', {}, [bar(d.mount, pct(d.used, d.total), `${fmtBytes(d.used)} / ${fmtBytes(d.total)}`)]), '정보 없음');
  listOrNone('units', inv.failed_units || [], (u) => el('li', { text: u }), '없음 ✓');
  listOrNone('containers', inv.containers || [], (c) => el('li', {}, [
    el('div', { class: 'li-row' }, [el('strong', { text: c.name }), el('span', { class: 'tag', text: c.health || c.state })]),
    el('div', { class: 'meta', text: `${c.image} · ${c.status}${c.ports && c.ports.length ? ` · 포트 ${c.ports.join(', ')}` : ''}` }),
  ]), sys.docker ? '컨테이너 없음' : 'Docker 없음');
  listOrNone('wg', inv.wireguard || [], (p) => el('li', {}, [
    el('div', { class: 'li-row' }, [el('strong', { text: p.allowed_ips }), el('span', { class: 'meta', text: p.last_handshake ? `핸드셰이크 ${fmtAgo(n.now - p.last_handshake)}` : '핸드셰이크 없음' })]),
    el('div', { class: 'meta', text: `${p.interface} · ${p.endpoint || '엔드포인트 없음'} · ↓${fmtBytes(p.rx)} ↑${fmtBytes(p.tx)}` }),
  ]), 'WireGuard 없음');
  listOrNone('ports', inv.ports || [], (p) => el('li', { class: 'li-row' }, [
    el('span', { text: `${p.address.includes(':') ? `[${p.address}]` : p.address}:${p.port}` }), el('span', { class: 'meta', text: p.process || '' }),
  ]), '정보 없음');
}

async function loadRecordings() {
  const { recordings } = await api('/api/terminal/recordings');
  const mine = recordings.filter((r) => r.node === state.node?.name);
  const fmt = (r) => `${r.date.slice(0, 4)}-${r.date.slice(4, 6)}-${r.date.slice(6)} ${r.time.slice(0, 2)}:${r.time.slice(2, 4)} UTC`;
  const del = async (names, what) => {
    if (!confirm(`${what}을(를) 지울까요? 되돌릴 수 없습니다.`)) return;
    try {
      const r = await withReauth(() => api('/api/terminal/recordings/delete', { names }));
      show(`녹화 ${r.removed}개를 지웠습니다.`, 'ok');
      await loadRecordings();
    } catch (e) { show(e.message); }
  };
  listOrNone('recordings', mine.slice(0, 50), (r) => {
    const b = el('button', { class: 'small danger', text: '삭제' });
    b.addEventListener('click', () => del([r.name], '이 녹화'));
    return el('li', { class: 'li-row' }, [
      el('a', { href: `/terminal?replay=${encodeURIComponent(r.name)}`, target: '_blank', rel: 'noopener', text: `${fmt(r)} · ${r.user}` }),
      el('span', { class: 'row' }, [el('span', { class: 'meta', text: fmtBytes(r.size) }), b]),
    ]);
  }, '기록 없음');
  const all = $('recordings-clear');
  if (all) {
    all.hidden = mine.length === 0;
    all.onclick = () => del(mine.map((r) => r.name), `이 서버의 녹화 ${mine.length}개 모두`);
  }
}

let lastRangeFetch = 0;
async function loadRange() {
  lastRangeFetch = Date.now();
  if (state.range === 'live') {
    if (state.node) drawAll(seriesFromRecent(state.node.recent));
    return;
  }
  const { rows } = await api(`/api/nodes/${state.id}/metrics?range=${state.range}`);
  drawAll(seriesFromRows(rows));
}

// ---------- 연결 진단 ----------
// Agent가 모은 사실(STUN·공유기)과 외부 접속 검증 결과를 사람이 읽는 말로.

function ipv4(s) { const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s || ''); return m ? m.slice(1).map(Number) : null; }
function isCGNATip(s) { const p = ipv4(s); return !!p && p[0] === 100 && p[1] >= 64 && p[1] < 128; }
function isPrivateIp(s) {
  const p = ipv4(s);
  return !!p && (p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] < 32) || (p[0] === 192 && p[1] === 168));
}

function diagnose(d) {
  const rep = d.report;
  const out = { lines: [], level: 'ok' };
  const bump = (lv) => { const order = { ok: 0, info: 1, warn: 2, fail: 3 }; if (order[lv] > order[out.level]) out.level = lv; };
  if (!rep) {
    out.where = '아직 진단 결과가 없습니다 (서버가 접속하고 1분쯤 뒤에 나옵니다).';
  } else {
    const st = rep.stun || {}, rt = rep.router || {};
    const pub = st.public_ip, ext = rt.external_ip;
    const gw = rt.kind === 'upnp' ? 'UPnP' : rt.kind === 'natpmp' ? 'NAT-PMP' : '';
    if (d.cloud) out.where = `클라우드 서버라 공인 IP(${pub || d.last_ip || '?'})가 있습니다. 밖에서 들어오는 걸 막는 건 클라우드 방화벽(보안 목록)입니다.`;
    else if (st.nat === 'none') out.where = `서버에 공인 IP(${pub})가 바로 있습니다.`;
    else if (ext && isCGNATip(ext)) { out.where = '통신사 NAT(CGNAT) 뒤에 있습니다. 통신사가 공인 IP를 여러 집과 나눠 써서, 공유기 설정으로는 밖에서 직접 들어올 수 없습니다.'; bump('info'); }
    else if (ext && isPrivateIp(ext)) { out.where = `공유기가 두 단계입니다 (공유기의 바깥 주소 ${ext}도 사설 주소). 앞쪽 장비(모뎀·다른 공유기)에도 포트를 열어야 밖에서 직접 들어옵니다.`; bump('info'); }
    else if (ext && pub && ext !== pub) { out.where = `공유기 바깥에 NAT가 하나 더 있습니다 (공유기 외부 주소 ${ext}, 실제 공인 주소 ${pub}).`; bump('info'); }
    else if (ext) out.where = `공유기 하나 뒤에 있습니다 (공인 IP ${pub || ext}). 공유기가 자동 포트 열기(${gw})를 지원합니다.`;
    else if (!st.ok) { out.where = '인터넷 쪽 주소를 알아내지 못했습니다 (서버에서 UDP가 막혀 있을 수 있습니다).'; bump('info'); }
    else out.where = `공유기(또는 사설망) 뒤에 있습니다 (공인 IP ${pub}). 공유기가 자동 포트 열기를 지원하지 않거나 꺼져 있습니다.`;
    if (st.nat === 'symmetric') out.lines.push(['info', '대칭 NAT: 목적지마다 바깥 포트가 달라 기기끼리 직접(P2P) 연결이 어렵습니다. 터널은 문제없습니다.']);
  }
  out.path = {
    edge: '이 서버가 입구입니다 — 인터넷에서 80·443으로 들어옵니다.',
    tunnel: 'Douve는 이 서버의 앱에 터널로 연결합니다 — 공유기 설정 없이 동작합니다.',
    direct: 'Douve 입구가 이 서버에 직접(사설망·공인 IP) 연결합니다.',
    none: '입구 서버가 없습니다. 앱을 밖에 공개하려면 공인 IP가 있는 서버를 입구로 정하세요.',
  }[d.path];
  const v = d.verify;
  if (!v || !v.at) out.test = '밖에서 접속 시험: 아직 안 함';
  else if (!v.tested) {
    out.test = { no_public_ip: '밖에서 접속 시험: 이 서버의 공인 주소를 몰라 시험하지 못했습니다.',
      no_tester: '밖에서 접속 시험: 시험해 줄 다른 공인 서버가 없습니다 (다른 서버를 하나 더 연결하면 됩니다).',
    }[v.reason] || '밖에서 접속 시험: 시험한 서버가 답하지 않았습니다.';
  } else {
    out.test = `밖에서 접속 시험: ${v.tester}에서 ${v.host}로 (${fmtTime(v.at)})`;
    for (const p of v.ports || []) {
      const shut = p.error === 'timeout' ? '막힘 (응답 없음)' : '닫힘';
      if (p.port === 22) {
        if (p.open) { out.lines.push(['warn', 'SSH(22): 인터넷에 열려 있습니다 — Douve 터미널을 쓰면 닫아도 됩니다 (방화벽·보안 목록에서).']); bump('warn'); }
        else out.lines.push(['ok', `SSH(22): ${shut}`]);
      } else if (p.open) {
        out.lines.push(['ok', `${p.port === 443 ? 'HTTPS(443)' : 'HTTP(80)'}: 밖에서 들어옵니다`]);
      } else if (d.edge) {
        out.lines.push(['fail', `${p.port === 443 ? 'HTTPS(443)' : 'HTTP(80)'}: ${shut} — 입구인데 밖에서 닿지 않습니다. 클라우드 방화벽이나 공유기 포트포워딩을 확인하세요.`]);
        bump('fail');
      } else {
        out.lines.push(['info', `${p.port === 443 ? 'HTTPS(443)' : 'HTTP(80)'}: ${shut}${d.path === 'tunnel' ? ' (터널을 쓰므로 필요 없습니다)' : ''}`]);
      }
    }
  }
  return out;
}

const DIAG_TAG = { ok: ['정상', ''], info: ['참고', 'sev-info'], warn: ['주의', 'sev-warn'], fail: ['위험', 'sev-crit'] };

async function loadDiag() {
  const { nodes } = await api('/api/reach');
  const d = nodes.find((n) => n.id === state.id);
  if (!d) { $('diag').replaceChildren(el('div', { class: 'meta', text: '진단할 수 없습니다.' })); return; }
  const r = diagnose(d);
  const [label, cls] = DIAG_TAG[r.level];
  const lines = r.lines.map(([lv, text]) => el('div', {}, [el('span', { class: `dot ${lv === 'ok' ? 'on' : lv === 'info' ? '' : 'off'}` }), ' ', el('span', { text })]));
  $('diag').replaceChildren(
    el('div', {}, [el('span', { class: `tag ${cls}`, text: label }), ' ', el('span', { text: r.where })]),
    el('div', { class: 'meta', text: r.path || '' }),
    el('div', { class: 'meta', text: r.test }),
    ...lines,
    d.report_at ? el('div', { class: 'meta', text: `진단 ${fmtTime(d.report_at)}` }) : '',
  );
}

async function initNode() {
  state.id = Number(new URLSearchParams(location.search).get('id'));
  loadDiag().catch(() => {});
  setInterval(() => { if (!document.hidden) loadDiag().catch(() => {}); }, 60000);
  $('diag-run').addEventListener('click', async () => {
    $('diag-run').disabled = true;
    show('진단하는 중… (밖에서 접속 시험 포함, 최대 15초)', 'ok');
    try {
      await api('/api/reach/run', { node_id: state.id });
      await new Promise((res) => setTimeout(res, 2500)); // 서버 쪽 진단(STUN) 보고를 조금 기다린다
      await loadDiag();
      show('진단했습니다.', 'ok');
    } catch (e) { show(e.message); }
    $('diag-run').disabled = false;
  });
  try {
    state.features = (await api('/api/summary')).features;
    if (state.features && !state.features.monitoring) {
      for (const id of ['range', 'c-cpu']) $(id)?.closest('.charts, .row')?.setAttribute('hidden', '');
      document.querySelector('.charts')?.setAttribute('hidden', '');
    }
  } catch (_) { /* 기본값 */ }
  const refresh = () => api(`/api/nodes/${state.id}`).then(renderNode).catch((e) => {
    if (e.status === 401) location.href = `/login?rd=${encodeURIComponent(location.pathname + location.search)}`;
    else show(e.message);
  });
  await refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, POLL_MS);
  loadRecordings().catch(() => {});

  for (const b of $('range').querySelectorAll('button')) {
    b.addEventListener('click', () => {
      state.range = b.dataset.range;
      for (const o of $('range').querySelectorAll('button')) o.classList.toggle('on', o === b);
      loadRange().catch((e) => show(e.message));
    });
  }
  window.addEventListener('resize', () => loadRange().catch(() => {}));

  $('rename').addEventListener('click', async () => {
    const name = prompt('새 이름 (영문 소문자·숫자·하이픈)', state.node?.name || '');
    if (!name) return;
    try {
      await api('/api/nodes/rename', { id: state.id, name });
      await refresh();
      show('이름을 바꿨습니다.', 'ok');
    } catch (e) { show(e.message); }
  });
  $('edge').addEventListener('click', async () => {
    const on = !state.node?.edge;
    const q = on
      ? `'${state.node?.name}'을(를) 입구(edge)로 지정할까요?\n이 서버의 80·443 포트에서 등록된 서비스를 HTTPS로 공개합니다. 공인 IP가 있고 80·443이 열려 있어야 합니다.`
      : `'${state.node?.name}'의 입구 역할을 해제할까요?\n이 서버로 들어오던 서비스 접속이 끊깁니다.`;
    if (!confirm(q)) return;
    try {
      await withReauth(() => api('/api/nodes/edge', { id: state.id, edge: on }));
      await refresh();
      show(on ? '입구로 지정했습니다.' : '입구 역할을 해제했습니다.', 'ok');
    } catch (e) { show(e.message); }
  });
  $('delete').addEventListener('click', async () => {
    if (!confirm(`'${state.node?.name}' 서버를 Douve에서 삭제할까요?\n수집한 기록도 지워지고, 서버의 Agent는 더 이상 접속할 수 없습니다.`)) return;
    try {
      await withReauth(() => api('/api/nodes/delete', { id: state.id }));
      location.href = '/dashboard';
    } catch (e) { show(e.message); }
  });
}

// ---------- 서비스 ----------

const svcState = { data: null, editing: null, nodes: [] };

function healthView(h) {
  if (!h) return el('span', { class: 'meta', text: '확인 전' });
  return el('span', { class: 'health' }, [
    el('span', { class: `dot ${h.ok ? 'on' : 'off'}` }),
    el('span', { text: h.ok ? ` 정상 · ${Math.round(h.latency_ms)}ms` : ` 응답 없음 · ${h.error}` }),
  ]);
}

function serviceRow(s) {
  const auth = s.auth === 'public' ? '공개' : 'Douve 로그인';
  const edit = el('button', { class: 'small', text: '수정' });
  const del = el('button', { class: 'small danger', text: '삭제' });
  edit.addEventListener('click', () => openServiceDialog(s));
  del.addEventListener('click', async () => {
    if (!confirm(`'${s.name}' (${s.host})를 삭제할까요?\n입구에서 이 도메인으로 들어오는 접속이 끊깁니다.`)) return;
    try {
      await withReauth(() => api('/api/services/delete', { id: s.id }));
      await loadServices();
      show('삭제했습니다.', 'ok');
    } catch (e) { show(e.message); }
  });
  return el('li', { class: 'svc' }, [
    el('div', { class: 'li-row' }, [
      el('div', { class: 'svc-head' }, [tileIcon({ name: s.name, icon_url: s.icon_url }), el('div', {}, [
        el('strong', { text: s.name }), el('div', {}, [el('a', { href: `https://${s.host}${s.path_prefix !== '/' ? s.path_prefix : ''}`, target: '_blank', rel: 'noopener', text: `${s.host}${s.path_prefix !== '/' ? s.path_prefix : ''}` })]),
      ])]),
      el('div', { class: 'row' }, [edit, del]),
    ]),
    el('div', { class: 'meta' }, [
      s.kind === 'redirect' ? `리다이렉트 → ${s.redirect_to} · `
        : `${s.node_name || '외부'} · ${['', 'https://', 'https(검증 안 함)://'][s.upstream_tls] || ''}${s.upstream}${s.path_prefix !== '/' ? ` · 경로 ${s.path_prefix}${s.strip_prefix ? ' (접두사 제거)' : ''}` : ''} · `,
      ...(s.internal ? [el('span', { class: 'tag', text: '내부 길' }), ' '] : []),
      ...(s.external ? [el('span', { class: 'tag', text: s.kind === 'redirect' ? '외부 · 리다이렉트' : `외부 · ${auth}` })] : []),
      s.public_paths.length ? ` 예외: ${s.public_paths.join(', ')}` : '',
    ]),
    el('div', { class: 'meta' }, [healthView(s.health)]),
  ]);
}

function renderServices() {
  const d = svcState.data;
  const f = svcState.filter || 'all';
  const list = d.services.filter((s) => f === 'all' || s[f]);
  $('services').replaceChildren(...(list.length ? list.map(serviceRow)
    : [el('li', { class: 'none', text: d.services.length ? '이 길로 연 서비스가 없습니다.' : '아직 서비스가 없습니다. "서비스 추가"로 서버의 포트를 도메인에 연결하세요.' })]));
}

async function loadServices() {
  const d = await api('/api/services');
  svcState.data = d;
  renderServices();
  const down = d.services.filter((s) => s.health && !s.health.ok).length;
  $('summary').textContent = `서비스 ${d.services.length}개${down ? ` · 응답 없음 ${down}개` : ''}`;
  const banner = $('edge-banner');
  if (!d.edges.length) {
    banner.replaceChildren(el('strong', { text: '입구(edge) 서버가 없습니다.' }),
      el('div', { class: 'meta', text: '공인 IP가 있는 서버의 상세 화면에서 "입구로 지정"을 누르면, 그 서버가 여기 등록한 서비스를 HTTPS(자동 인증서)로 공개합니다.' }));
    banner.hidden = false;
  } else {
    const off = d.edges.filter((e) => !e.connected);
    banner.hidden = off.length === 0;
    if (off.length) banner.replaceChildren(el('strong', { text: `입구 서버 응답 없음: ${off.map((e) => e.name).join(', ')}` }));
  }
}

// ---------- 실행 중인 앱 (공개 제안) ----------
const HIDDEN_APPS_KEY = 'douve.hiddenApps';
function hiddenApps() {
  try { return new Set(JSON.parse(localStorage.getItem(HIDDEN_APPS_KEY) || '[]')); } catch (_) { return new Set(); }
}
function setHiddenApps(set) {
  try { localStorage.setItem(HIDDEN_APPS_KEY, JSON.stringify([...set])); } catch (_) { /* 저장 안 돼도 동작 */ }
}
const appKey = (a) => `${a.node_id}:${a.kind}:${a.name}:${a.port}`;

function appRow(a, hidden) {
  const iconItem = { name: a.suggest_name || a.name, icon_url: a.icon ? `/api/icons/name/0?n=${encodeURIComponent(a.icon)}` : '' };
  const buttons = [];
  if (!a.no_port) {
    const pub = el('button', { class: 'small primary', text: '공개' });
    pub.addEventListener('click', () => openServiceDialog(null, a).catch((e) => show(e.message)));
    buttons.push(pub);
    const hide = el('button', { class: 'small', text: hidden ? '다시 보기' : '숨기기' });
    hide.addEventListener('click', () => {
      const set = hiddenApps();
      if (hidden) set.delete(appKey(a)); else set.add(appKey(a));
      setHiddenApps(set);
      renderApps();
    });
    buttons.push(hide);
  }
  const meta = [`${a.node_name}`];
  if (a.port) meta.push(`포트 ${a.port}`);
  if (a.image) meta.push(a.image);
  else if (a.kind === 'process') meta.push('프로그램');
  return el('li', { class: 'svc' }, [
    el('div', { class: 'li-row' }, [
      el('div', { class: 'svc-head' }, [tileIcon(iconItem), el('div', {}, [
        el('strong', { text: a.name }),
        el('div', { class: 'meta' }, [meta.join(' · '),
          a.loopback ? el('span', { class: 'tag tag-gap', text: '이 서버 안에서만 열림', title: '127.0.0.1에만 열려 있습니다. 다른 서버의 입구에서는 Douve 터널로 연결합니다.' }) : '']),
      ])]),
      el('div', { class: 'row' }, buttons),
    ]),
  ]);
}

function renderApps() {
  const d = svcState.apps;
  if (!d) return;
  const hidden = hiddenApps();
  const open = d.apps.filter((a) => !a.published && !a.no_port);
  const shown = open.filter((a) => !hidden.has(appKey(a)));
  const hid = open.filter((a) => hidden.has(appKey(a)));
  const noPort = d.apps.filter((a) => a.no_port && !a.published);
  $('apps-section').hidden = open.length === 0 && noPort.length === 0;
  $('apps').replaceChildren(...(shown.length ? shown.map((a) => appRow(a, false))
    : [el('li', { class: 'none', text: '새로 공개할 앱이 없습니다.' })]));
  $('apps-hidden-box').hidden = hid.length === 0;
  $('apps-hidden-title').textContent = `숨긴 앱 ${hid.length}개`;
  $('apps-hidden').replaceChildren(...hid.map((a) => appRow(a, true)));
  $('apps-noport-box').hidden = noPort.length === 0;
  $('apps-noport-title').textContent = `포트가 없는 컨테이너 ${noPort.length}개`;
  $('apps-noport').replaceChildren(...noPort.map((a) => appRow(a, false)));
}

async function loadApps() {
  svcState.apps = await api('/api/apps');
  renderApps();
}

async function loadCandidates() {
  const box = $('svc-candidates');
  box.replaceChildren();
  const nodeId = $('svc-node').value;
  if (!nodeId) { $('svc-candidates-box').hidden = true; return; }
  try {
    const { candidates } = await api(`/api/services/suggest?node_id=${nodeId}`);
    $('svc-candidates-box').hidden = candidates.length === 0;
    for (const c of candidates) {
      const b = el('button', { type: 'button', class: `chip${c.registered ? ' used' : ''}`, text: `${c.port}${c.label ? ` · ${c.label}` : ''}` });
      b.addEventListener('click', () => {
        $('svc-upstream').value = c.upstream;
        if (!$('svc-name').value && c.label) {
          $('svc-name').value = c.label.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32);
          $('svc-name').dispatchEvent(new Event('input'));
        }
      });
      box.append(b);
    }
  } catch (_) { $('svc-candidates-box').hidden = true; }
}

function syncAuth() {
  const redirect = $('svc-kind').value === 'redirect';
  const pub = document.querySelector('input[name="svc-auth"]:checked').value === 'public';
  const external = $('svc-external').checked;
  $('svc-paths-box').hidden = pub || redirect || !external;
  for (const id of ['svc-node-box', 'svc-candidates-box', 'svc-upstream-box', 'svc-auth-box', 'svc-proxy-opts']) $(id).hidden = redirect;
  if (!external) $('svc-auth-box').hidden = true; // 내부 길은 기기 신원으로 확인
  if (redirect) $('svc-candidates-box').hidden = true;
  $('svc-redirect-box').hidden = !redirect;
  $('svc-upstream').required = !redirect;
  $('svc-redirect').required = redirect;
  const prefix = $('svc-prefix').value.trim();
  $('svc-strip-box').hidden = redirect || !prefix || prefix === '/';
}

// prefill: 실행 중인 앱 목록에서 "공개"를 눌렀을 때 채울 값 (/api/apps 항목)
async function openServiceDialog(s = null, prefill = null) {
  svcState.editing = s;
  const { nodes } = await api('/api/nodes');
  svcState.nodes = nodes;
  $('svc-title').textContent = s ? `서비스 수정 · ${s.name}` : '서비스 추가';
  $('svc-node').replaceChildren(el('option', { value: '', text: '(외부 · 직접 입력)' }),
    ...nodes.map((n) => el('option', { value: String(n.id), text: `${n.name}${n.mesh_address ? ` (${n.mesh_address})` : ''}` })));
  $('svc-node').value = s ? String(s.node_id ?? '') : String(nodes[0]?.id ?? '');
  $('svc-upstream').value = s?.upstream ?? '';
  $('svc-name').value = s?.name ?? '';
  $('svc-host').value = s?.host ?? '';
  $('svc-host').dataset.touched = s ? '1' : '';
  for (const r of document.querySelectorAll('input[name="svc-auth"]')) r.checked = r.value === (s?.auth ?? 'douve');
  // 새 서비스: 내부 길이 켜져 있으면 내부에서 먼저 시험하고 원할 때 외부로 공개
  const devnet = !!svcState.data?.devnet;
  $('svc-internal').checked = s ? s.internal : devnet;
  $('svc-external').checked = s ? s.external : !devnet;
  $('svc-internal').disabled = !devnet && !(s && s.internal);
  $('svc-ways-help').textContent = devnet ? '' : '내부 길이 꺼져 있습니다 (설정 → 내부 길).';
  $('svc-paths').value = (s?.public_paths ?? []).join('\n');
  $('svc-group').value = s?.group ?? '';
  $('svc-desc').value = s?.description ?? '';
  $('svc-icon').value = s?.icon ?? '';
  $('svc-onhome').checked = s ? s.on_home : true;
  $('svc-kind').value = s?.kind ?? 'proxy';
  $('svc-redirect').value = s?.redirect_to ?? '';
  $('svc-prefix').value = s && s.path_prefix !== '/' ? s.path_prefix : '';
  $('svc-strip').checked = !!s?.strip_prefix;
  $('svc-tls').value = String(s?.upstream_tls ?? 0);
  $('svc-hosthdr').value = s?.host_header ?? '';
  $('svc-timeout').value = s?.timeout ?? 0;
  $('svc-adv').open = !!s && (s.kind === 'redirect' || s.path_prefix !== '/' || s.upstream_tls > 0 || !!s.host_header || s.timeout > 0);
  if (prefill) {
    $('svc-node').value = String(prefill.node_id);
    $('svc-upstream').value = prefill.upstream;
    $('svc-name').value = prefill.suggest_name;
    $('svc-icon').value = prefill.icon || '';
    $('svc-tls').value = String(prefill.upstream_tls || 0);
    $('svc-adv').open = prefill.upstream_tls > 0;
    $('svc-name').dispatchEvent(new Event('input')); // 도메인 = 이름.기본도메인
  }
  syncAuth();
  if ($('svc-kind').value !== 'redirect') await loadCandidates();
  $('svc-dialog').showModal();
}

function initServiceFilter() {
  for (const b of document.querySelectorAll('#svc-filter .chip')) {
    b.addEventListener('click', () => {
      svcState.filter = b.dataset.f;
      for (const x of document.querySelectorAll('#svc-filter .chip')) x.classList.toggle('on', x === b);
      if (svcState.data) renderServices();
    });
  }
}

function initServiceDialog() {
  initServiceFilter();
  $('add-service').addEventListener('click', () => openServiceDialog().catch((e) => show(e.message)));
  $('svc-node').addEventListener('change', loadCandidates);
  for (const r of document.querySelectorAll('input[name="svc-auth"]')) r.addEventListener('change', syncAuth);
  $('svc-kind').addEventListener('change', syncAuth);
  $('svc-external').addEventListener('change', syncAuth);
  $('svc-prefix').addEventListener('input', syncAuth);
  $('svc-host').addEventListener('input', () => { $('svc-host').dataset.touched = '1'; });
  $('svc-name').addEventListener('input', () => {
    const base = svcState.data?.base_domain;
    if (base && !$('svc-host').dataset.touched && $('svc-name').value) $('svc-host').value = `${$('svc-name').value}.${base}`;
  });
  $('svc-save').addEventListener('click', async (ev) => {
    ev.preventDefault();
    if (!$('svc-form').reportValidity()) return;
    const s = svcState.editing;
    const body = {
      name: $('svc-name').value.trim(),
      host: $('svc-host').value.trim(),
      upstream: $('svc-upstream').value.trim(),
      node_id: Number($('svc-node').value || 0),
      auth: document.querySelector('input[name="svc-auth"]:checked').value,
      public_paths: $('svc-paths').value.split('\n').map((x) => x.trim()).filter(Boolean),
      group: $('svc-group').value.trim(),
      description: $('svc-desc').value.trim(),
      icon: $('svc-icon').value.trim(),
      on_home: $('svc-onhome').checked,
      kind: $('svc-kind').value,
      redirect_to: $('svc-redirect').value.trim(),
      path_prefix: $('svc-prefix').value.trim() || '/',
      strip_prefix: $('svc-strip').checked,
      upstream_tls: Number($('svc-tls').value),
      host_header: $('svc-hosthdr').value.trim(),
      timeout: Number($('svc-timeout').value || 0),
      internal: $('svc-internal').checked,
      external: $('svc-external').checked,
    };
    if (!body.internal && !body.external) { show('내부 길이나 외부 공개 중 하나는 켜야 합니다.'); return; }
    if (s) body.id = s.id;
    try {
      await withReauth(() => api(s ? '/api/services/update' : '/api/services/create', body));
      $('svc-dialog').close();
      await loadServices();
      loadApps().catch(() => {});
      show(s ? '저장했습니다. 입구에 바로 반영됩니다.'
        : body.external ? `추가했습니다. https://${body.host} 로 접속할 수 있습니다 (첫 접속 때 인증서 발급에 몇 초 걸릴 수 있음).`
          : `추가했습니다. 내부 길에 연결된 기기에서 https://${body.host} 로 열립니다.`, 'ok');
    } catch (e) { show(e.message); }
  });
}

async function initServices() {
  initServiceDialog();
  const refresh = () => Promise.all([loadServices(), loadApps()]).catch((e) => {
    if (e.status === 401) location.href = `/login?rd=${encodeURIComponent(location.pathname)}`;
    else show(e.message);
  });
  await refresh();
  // 홈 화면의 편집 버튼: /services#edit=<id>
  const m = location.hash.match(/^#edit=(\d+)$/);
  if (m) {
    const target = svcState.data?.services.find((x) => x.id === Number(m[1]));
    history.replaceState(null, '', '/services');
    if (target) openServiceDialog(target).catch((e) => show(e.message));
  }
  setInterval(() => { if (!document.hidden && !$('svc-dialog').open) refresh(); }, 15000);
}

// ---------- 설정 ----------

async function loadSettings() {
  const s = await api('/api/settings');
  $('about').textContent = `${s.public_url} · 버전 ${s.version}`;
  $('tg-token-hint').textContent = s.telegram.token_hint ? `(저장됨 ${s.telegram.token_hint})` : '(없음)';
  $('tg-chat').value = s.telegram.chat_id;
  $('gg-redirect').value = s.google.redirect_uri;
  $('gg-id').value = s.google.client_id;
  $('gg-secret-hint').textContent = s.google.secret_hint ? `(저장됨 ${s.google.secret_hint})` : '(없음)';
  $('tg-token').value = '';
  $('gg-secret').value = '';
  $('expose-on').checked = s.agent_expose;
  $('notify-lang').value = s.language || 'ko';
  settingsFeatures = s.features;
  for (const box of document.querySelectorAll('#features input[data-f]')) {
    const [a, b] = box.dataset.f.split('.');
    box.checked = b ? s.features[a][b] : s.features[a];
  }
}

let settingsFeatures = null;

async function saveSettings(body, okMsg) {
  try {
    await withReauth(() => api('/api/settings/save', body));
    await loadSettings();
    show(okMsg, 'ok');
  } catch (e) { show(e.message); }
}

// ---------- 알림 채널 ----------
const CH_HELP = {
  ntfy: '휴대폰에 ntfy 앱을 설치하고 이 토픽을 구독하세요. 공개 서버(ntfy.sh)에서는 토픽 이름이 곧 비밀번호이니 추측하기 어렵게 두세요.',
  discord: 'Discord 채널 설정 → 연동 → 웹후크 → 새 웹후크 → 웹후크 URL 복사.',
  slack: 'Slack 앱 디렉터리 → Incoming Webhooks → 채널 선택 → Webhook URL 복사.',
  webhook: 'Douve가 {"source":"douve","type":"alert","text":…,"time":…}를 POST합니다. 서명 비밀값을 넣으면 X-Douve-Signature: sha256=HMAC(비밀값, "시각.본문")와 X-Douve-Timestamp 헤더를 붙입니다. 감사 기록을 함께 받으면 {"type":"audit","prev_hash":…,"records":[…]} 묶음이 순서대로 옵니다 (각 기록의 hash로 이어 계산해 확인).',
};
const CH_KIND = { ntfy: 'ntfy', discord: 'Discord', slack: 'Slack', webhook: '웹훅' };

function randomTopic() {
  const a = new Uint8Array(12);
  crypto.getRandomValues(a);
  return `douve-${[...a].map((x) => 'abcdefghijkmnpqrstuvwxyz23456789'[x % 32]).join('')}`;
}

function syncChannelForm() {
  const k = $('ch-kind').value;
  $('ch-ntfy-box').hidden = k !== 'ntfy';
  $('ch-url-box').hidden = k === 'ntfy';
  $('ch-secret-box').hidden = k !== 'webhook';
  $('ch-audit-box').hidden = k !== 'webhook';
  $('ch-help').textContent = CH_HELP[k];
  if (k === 'ntfy' && !$('ch-topic').value) $('ch-topic').value = randomTopic();
}

function channelRow(c) {
  const on = el('input', { type: 'checkbox' });
  on.checked = c.enabled;
  on.addEventListener('change', async () => {
    try { await withReauth(() => api('/api/channels/toggle', { id: c.id, enabled: on.checked })); } catch (e) { on.checked = !on.checked; show(e.message); }
  });
  const test = el('button', { class: 'small', type: 'button', text: '테스트 발송' });
  test.addEventListener('click', async () => {
    try { await api('/api/channels/test', { id: c.id }); show('테스트 알림을 보냈습니다.', 'ok'); } catch (e) { show(e.message); }
  });
  const del = el('button', { class: 'small danger', type: 'button', text: '삭제' });
  del.addEventListener('click', async () => {
    if (!confirm(`'${c.name}' 알림 채널을 삭제할까요?`)) return;
    try { await withReauth(() => api('/api/channels/delete', { id: c.id })); await loadChannels(); show('삭제했습니다.', 'ok'); } catch (e) { show(e.message); }
  });
  return el('li', {}, [el('div', { class: 'li-row' }, [
    el('div', {}, [el('strong', { text: c.name }), ' ', el('span', { class: 'tag', text: CH_KIND[c.kind] || c.kind }),
      ...(c.audit ? [' ', el('span', { class: 'tag', text: '감사 기록' })] : []),
      el('div', { class: 'meta', text: c.target })]),
    el('div', { class: 'row' }, [el('label', { class: 'check' }, [on, '켬']), test, del]),
  ])]);
}

async function loadChannels() {
  const { channels } = await api('/api/channels');
  $('channels').replaceChildren(...(channels.length ? channels.map(channelRow)
    : [el('li', { class: 'none', text: '추가한 채널이 없습니다.' })]));
}

function initChannels() {
  $('ch-kind').addEventListener('change', syncChannelForm);
  $('ch-add').addEventListener('toggle', syncChannelForm);
  $('ch-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const kind = $('ch-kind').value;
    const config = kind === 'ntfy'
      ? { server: $('ch-server').value.trim(), topic: $('ch-topic').value.trim(), token: $('ch-token').value.trim() }
      : { url: $('ch-url').value.trim(), secret: $('ch-secret').value.trim(), audit: kind === 'webhook' && $('ch-audit').checked };
    try {
      await withReauth(() => api('/api/channels/create', { kind, name: $('ch-name').value.trim(), config }));
      for (const id of ['ch-name', 'ch-server', 'ch-topic', 'ch-token', 'ch-url', 'ch-secret']) $(id).value = '';
      $('ch-audit').checked = false;
      $('ch-add').open = false;
      await loadChannels();
      show('알림 채널을 추가했습니다. "테스트 발송"으로 확인하세요.', 'ok');
    } catch (e) { show(e.message); }
  });
  loadChannels().catch(() => {});
}

async function loadDevnet() {
  const d = await api('/api/devnet');
  $('devnet-on').checked = d.enabled;
  $('devnet-port').value = d.port;
  $('devnet-endpoint').value = d.endpoint;
  $('devnet-endpoint').placeholder = d.endpoint_default;
  $('devnet-help').textContent = `클라우드 방화벽(보안 목록)에서 입구 서버의 UDP ${d.port}번을 열어야 합니다. 포트나 주소를 바꾸면 이미 등록한 기기는 다시 등록해야 합니다.`;
  let state;
  if (!d.gateway) state = '입구(edge) 서버가 없습니다. 서버 화면에서 입구를 정하세요.';
  else if (!d.enabled) state = `꺼짐 · 맡을 입구: ${d.gateway}`;
  else if (d.ready && d.running) state = `동작 중 · 입구 ${d.gateway} · 내부 주소 ${d.address} · 등록 기기 ${d.devices}대`;
  else state = `준비 중 · 입구 ${d.gateway}${d.gateway_connected ? '' : ' (접속 안 됨)'}`;
  $('devnet-state').textContent = state;
}

function initDevnet() {
  $('devnet-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await withReauth(() => api('/api/devnet/update', { enabled: $('devnet-on').checked, port: Number($('devnet-port').value), endpoint: $('devnet-endpoint').value.trim() }));
      show('저장했습니다.', 'ok');
      setTimeout(() => loadDevnet().catch(() => {}), 1500);
      await loadDevnet();
    } catch (e) { show(e.message); }
  });
  loadDevnet().catch(() => {});
}

async function initSettings() {
  initChannels();
  initDevnet();
  await loadSettings().catch((e) => {
    if (e.status === 401) location.href = `/login?rd=${encodeURIComponent(location.pathname)}`;
    else show(e.message);
  });
  for (const box of document.querySelectorAll('#features input[data-f]')) {
    box.addEventListener('change', () => {
      const f = structuredClone(settingsFeatures);
      const [a, b] = box.dataset.f.split('.');
      if (b) f[a][b] = box.checked; else f[a] = box.checked;
      saveSettings({ features: f }, '기능 설정을 저장했습니다. 모든 서버에 적용됩니다.');
    });
  }
  $('expose-on').addEventListener('change', () => saveSettings({ agent_expose: $('expose-on').checked },
    $('expose-on').checked ? '노드에서 서비스 공개를 허용했습니다.' : '노드에서 서비스 공개를 껐습니다.'));
  $('notify-lang').addEventListener('change', () => saveSettings({ language: $('notify-lang').value }, '알림 언어를 바꿨습니다.'));
  $('tg-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    saveSettings({ telegram: { bot_token: $('tg-token').value, chat_id: $('tg-chat').value } }, '텔레그램 설정을 저장했습니다. "테스트 발송"으로 확인하세요.');
  });
  $('tg-clear').addEventListener('click', () => {
    if (confirm('텔레그램 알림을 끌까요?')) saveSettings({ telegram: { clear: true } }, '텔레그램 알림을 껐습니다.');
  });
  $('tg-test').addEventListener('click', async () => {
    try {
      await api('/api/settings/telegram-test', {});
      show('테스트 알림을 보냈습니다. 텔레그램을 확인하세요.', 'ok');
    } catch (e) { show(e.message); }
  });
  $('gg-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    saveSettings({ google: { client_id: $('gg-id').value, client_secret: $('gg-secret').value } }, 'Google 로그인 설정을 저장했습니다.');
  });
  $('gg-clear').addEventListener('click', () => {
    if (confirm('Google 로그인을 끌까요? (패스키 로그인은 그대로)')) saveSettings({ google: { clear: true } }, 'Google 로그인을 껐습니다.');
  });
  let invitePick = null;
  const syncInvite = async () => {
    const t = await accessTargets();
    invitePick = accessPicker($('invite-role').value, [], [], t);
    $('invite-access').replaceChildren(invitePick.el);
  };
  $('invite-role').addEventListener('change', () => syncInvite().catch(() => {}));
  syncInvite().catch(() => {});
  loadUsers().catch(() => {});
  $('invite-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const r = await withReauth(() => api('/api/invites/create', {
        email: $('invite-email').value.trim(), role: $('invite-role').value, ...(invitePick ? invitePick.value() : {}),
      }));
      $('invite-link').textContent = r.link;
      $('invite-result').hidden = false;
      show(`${r.email} 초대 링크를 만들었습니다. 안전한 경로(직접 메시지 등)로 전달하세요.`, 'ok');
    } catch (e) { show(e.message); }
  });
  $('invite-copy').addEventListener('click', () => navigator.clipboard.writeText($('invite-link').textContent).then(() => show('복사했습니다.', 'ok')));
}

// ---------- 사용자·역할 ----------

const ROLE_LABEL = { admin: '관리자', operator: '운영자', app: '앱만' };
let targetsCache = null;
async function accessTargets() {
  if (!targetsCache) {
    const [{ nodes }, { services }] = await Promise.all([api('/api/nodes'), api('/api/services')]);
    targetsCache = { nodes: nodes.map((n) => ({ id: n.id, name: n.name })), services: services.map((v) => ({ id: v.id, name: v.name, host: v.host })) };
  }
  return targetsCache;
}

// 역할에 맞는 권한 고르기: 운영자는 서버(그 서버의 앱 포함) + 앱, 앱만은 앱
function accessPicker(role, nodeIds, serviceIds, t) {
  const boxes = { nodes: [], services: [] };
  const group = (title, kind, list, chosen, label) => {
    if (!list.length) return el('p', { class: 'meta', text: `${title}: 없음` });
    const wrap = el('div', { class: 'checks' });
    for (const x of list) {
      const c = el('input', { type: 'checkbox' });
      c.checked = chosen.includes(x.id);
      c.dataset.id = x.id;
      boxes[kind].push(c);
      wrap.append(el('label', { class: 'check' }, [c, ' ', label(x)]));
    }
    return el('div', { class: 'stack' }, [el('div', { class: 'meta', text: title }), wrap]);
  };
  const parts = [];
  if (role === 'operator') parts.push(group('허락할 서버', 'nodes', t.nodes, nodeIds, (n) => n.name));
  if (role !== 'admin') parts.push(group(role === 'operator' ? '따로 허락할 앱 (다른 서버의 앱)' : '허락할 앱', 'services', t.services, serviceIds, (v) => `${v.name} (${v.host})`));
  const ids = (kind) => boxes[kind].filter((c) => c.checked).map((c) => Number(c.dataset.id));
  return { el: el('div', { class: 'stack' }, parts), value: () => ({ nodes: ids('nodes'), services: ids('services') }) };
}

function accessSummary(u, t) {
  if (u.role === 'admin') return '모든 서버·앱';
  const name = (list, id) => (list.find((x) => x.id === id) || { name: `#${id}` }).name;
  const parts = [];
  if (u.role === 'operator') parts.push(`서버: ${u.nodes.map((id) => name(t.nodes, id)).join(', ') || '없음'}`);
  parts.push(`앱: ${u.services.map((id) => name(t.services, id)).join(', ') || (u.role === 'operator' ? '서버의 앱' : '없음')}`);
  return parts.join(' · ');
}

function userRow(u, t) {
  const editor = el('div', { class: 'stack' });
  editor.hidden = true;
  const role = el('select', {}, Object.entries(ROLE_LABEL).map(([k, v]) => {
    const o = el('option', { value: k, text: v });
    o.selected = k === u.role;
    return o;
  }));
  let pick = accessPicker(u.role, u.nodes, u.services, t);
  const pickBox = el('div', {}, [pick.el]);
  role.addEventListener('change', () => { pick = accessPicker(role.value, u.nodes, u.services, t); pickBox.replaceChildren(pick.el); });
  const save = el('button', { class: 'small primary', type: 'button', text: '저장' });
  save.addEventListener('click', async () => {
    try {
      await withReauth(() => api('/api/users/update', { id: u.id, role: role.value, ...pick.value() }));
      show('권한을 바꿨습니다.', 'ok');
      await loadUsers();
    } catch (e) { show(e.message); }
  });
  editor.append(el('label', { class: 'field' }, ['역할 ', role]), pickBox, el('div', { class: 'row end' }, [save]));
  const edit = el('button', { class: 'small', type: 'button', text: '권한' });
  edit.addEventListener('click', () => { editor.hidden = !editor.hidden; });
  const buttons = [edit];
  if (!u.me) {
    const del = el('button', { class: 'small danger', type: 'button', text: '삭제' });
    del.addEventListener('click', async () => {
      if (!confirm(`${u.email} 사용자를 삭제할까요? 패스키와 로그인 세션도 함께 지워집니다.`)) return;
      try { await withReauth(() => api('/api/users/delete', { id: u.id })); show('삭제했습니다.', 'ok'); await loadUsers(); } catch (e) { show(e.message); }
    });
    buttons.push(del);
  }
  const seen = u.last_login_at ? `마지막 로그인 ${new Date(u.last_login_at * 1000).toLocaleString()}` : '로그인한 적 없음';
  return el('li', {}, [
    el('div', { class: 'li-row' }, [
      el('div', {}, [el('strong', { text: u.email }), ' ', el('span', { class: 'tag', text: ROLE_LABEL[u.role] || u.role }),
        ...(u.me ? [' ', el('span', { class: 'tag', text: '나' })] : []),
        el('div', { class: 'meta', text: accessSummary(u, t) }),
        el('div', { class: 'meta', text: `${seen} · 패스키 ${u.passkeys}개` })]),
      el('div', { class: 'row' }, buttons),
    ]),
    editor,
  ]);
}

async function loadUsers() {
  const [{ users }, t] = await Promise.all([api('/api/users'), accessTargets()]);
  $('users').replaceChildren(...users.map((u) => userRow(u, t)));
}

// ---------- 보안 ----------

const SEV = { crit: '심각', warn: '주의', info: '기록' };
const STATUS = { acked: '확인함 (24시간 조용)', ignored: '문제 없음 (무시 중)', open: '열림' };

async function securityAction(fps, mode) {
  try {
    await withReauth(() => api('/api/security/resolve', { fingerprints: fps, mode }));
    show(mode === 'ignore' ? '앞으로 같은 일은 알리지 않습니다.' : '확인했습니다. 다시 생기면 알립니다.', 'ok');
    await loadSecurity();
  } catch (e) { show(e.message); }
}

function issueRow(i) {
  const head = el('div', { class: 'li-row' }, [
    el('div', {}, [el('span', { class: `tag sev-${i.severity}`, text: SEV[i.severity] || i.severity }), el('strong', { text: ` ${i.summary}` })]),
    el('span', { class: 'meta', text: i.node }),
  ]);
  const meta = el('div', { class: 'meta', text: `${i.count}회 · 처음 ${fmtTime(i.first_seen)} · 마지막 ${fmtTime(i.last_seen)}${i.status !== 'open' ? ` · ${STATUS[i.status]}${i.acked_by ? ` (${i.acked_by})` : ''}` : ''}` });
  const actions = el('div', { class: 'row end' });
  if (i.status === 'open') {
    const ok = el('button', { class: 'small', text: '확인함 · 24시간 조용히' });
    ok.title = '확인했습니다. 24시간 동안 같은 일로 알리지 않고, 그 뒤 또 생기면 알립니다';
    ok.addEventListener('click', () => securityAction([i.fingerprint], 'ack'));
    const ign = el('button', { class: 'small primary', text: '문제 없음 · 앞으로 무시' });
    ign.addEventListener('click', () => securityAction([i.fingerprint], 'ignore'));
    actions.append(ok, ign);
  } else if (i.status === 'ignored') {
    const re = el('button', { class: 'small', text: '다시 알리기' });
    re.addEventListener('click', async () => {
      try { await api('/api/security/reopen', { fingerprint: i.fingerprint }); await loadSecurity(); } catch (e) { show(e.message); }
    });
    actions.append(re);
  }
  const hint = i.status !== 'ignored' && i.count >= 5
    ? el('div', { class: 'meta hint', text: '자주 반복되는 일입니다. 정상 작업(예: 정기 점검)이라면 "문제 없음 · 앞으로 무시"를 누르세요.' })
    : '';
  return el('li', {}, [head, meta, hint, actions]);
}

async function loadSecurity() {
  const d = await api(`/api/security?kind=${encodeURIComponent($('kind').value)}`);
  const open = d.issues.filter((i) => i.status === 'open');
  const closed = d.issues.filter((i) => i.status !== 'open');
  $('summary').textContent = open.length ? `확인이 필요한 이슈 ${open.length}건` : '확인이 필요한 이슈 없음 ✓';
  listOrNone('open', open, issueRow, '없음 ✓');
  listOrNone('closed', closed.slice(0, 50), issueRow, '없음');
  $('ack-all').hidden = open.length < 2;
  $('ack-all').onclick = () => securityAction(open.map((i) => i.fingerprint), 'ack');
  listOrNone('events', d.events, (e) => el('li', {}, [
    el('div', { class: 'li-row' }, [
      el('span', {}, [el('span', { class: `tag sev-${e.severity}`, text: SEV[e.severity] || e.severity }), el('span', { text: ` ${e.summary}` })]),
      el('span', { class: 'meta', text: `${e.node} · ${fmtTime(e.ts)}` }),
    ]),
    e.via ? el('div', { class: 'meta', text: `Douve 터미널 — ${e.via} (알리지 않음)` })
      : e.status === 'ignored' ? el('div', { class: 'meta', text: '무시 중인 이슈' }) : '',
  ]), '기록 없음');
}

// ---------- 보안 점검표 ----------
// 항목 문구는 화면에서 만든다 (Agent는 id·상태·사실만 보낸다)
const CHECK_TEXT = {
  ssh_password: { title: 'SSH 비밀번호 로그인', ok: '꺼짐 (키로만 로그인)', fail: '켜져 있음 — 약한 비밀번호 하나로 서버가 뚫릴 수 있습니다',
    fix: '비밀번호·키보드 입력 SSH 로그인을 끕니다 (/etc/ssh/sshd_config.d/00-douve.conf, sshd -t로 검사한 뒤 적용, 실패하면 되돌림). 키가 없는 계정은 SSH로 들어올 수 없게 됩니다. Douve 터미널은 그대로입니다.' },
  ssh_root: { title: 'SSH root 로그인', ok: '막힘', warn: '키로는 root 로그인 가능', fail: '비밀번호로도 root 로그인 가능',
    fix: 'SSH로 root 로그인을 막습니다 (PermitRootLogin no). 관리 계정으로 들어와 sudo를 쓰세요.' },
  ssh_match: { title: '계정별 SSH 예외', ok: '비밀번호를 다시 허용하는 예외 없음', warn: '일부 계정은 비밀번호 로그인이 다시 허용됩니다' },
  auto_updates: { title: '자동 보안 업데이트', ok: '켜짐', fail: '꺼짐 — 알려진 취약점이 그대로 남습니다',
    fix: '자동 보안 업데이트를 설치하고 켭니다 (Ubuntu: unattended-upgrades / Rocky·RHEL: dnf-automatic, 보안 업데이트만). 몇 분 걸릴 수 있습니다.' },
  time_sync: { title: '시간 동기화', ok: '맞음', warn: '켜져 있지만 아직 맞추지 못했습니다', fail: '꺼짐 — 터미널을 열 때 서명 시각 확인이 실패할 수 있습니다',
    fix: '시간 동기화(NTP)를 켭니다 (timedatectl set-ntp true).' },
  reboot: { title: '재부팅', ok: '필요 없음', warn: '업데이트를 적용하려면 재부팅이 필요합니다 (터미널에서 직접)' },
  public_ports: { title: '인터넷 쪽에서 열린 포트', ok: '없음', info: '필요 없는 포트는 닫거나 127.0.0.1에만 여세요' },
};
const CHECK_STATUS = { ok: ['정상', ''], warn: ['주의', 'sev-warn'], fail: ['위험', 'sev-crit'], info: ['참고', 'sev-info'], unknown: ['확인 불가', 'sev-info'], na: ['해당 없음', ''] };

async function signedFix(nodeId, check) {
  const opts = await api('/api/checkup/fix/options', { node_id: nodeId, check });
  const cred = await navigator.credentials.get({ publicKey: toRequestOptions(opts.publicKey) });
  const { rid } = await api('/api/checkup/fix', { pending: opts.pending, credential: assertionJson(cred) });
  for (let i = 0; i < 600; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    const st = await api(`/api/checkup/fix/status?rid=${encodeURIComponent(rid)}`);
    if (st.done) return st;
  }
  throw new Error('서버에서 답이 없습니다. 잠시 후 점검표를 다시 확인하세요.');
}

function checkRow(node, r) {
  const t = CHECK_TEXT[r.id] || { title: r.id };
  const [label, cls] = CHECK_STATUS[r.status] || [r.status, ''];
  const f = r.facts || {};
  let text = t[r.status] || (r.status === 'unknown' ? '확인할 수 없음' : r.status === 'na' ? '해당 없음' : '');
  const extra = [];
  if (r.id === 'ssh_match' && f.where) extra.push(f.where);
  if (r.id === 'auto_updates' && f.tool) extra.push(f.tool);
  if (r.id === 'reboot' && f.packages) extra.push(f.packages);
  if (r.id === 'public_ports' && f.ports) extra.push(f.ports);
  if (f.no_include) extra.push('sshd_config가 sshd_config.d/*.conf를 먼저 읽지 않아 자동으로 고칠 수 없습니다');
  if (r.error) extra.push(r.error);
  const info = el('div', {}, [el('div', {}, [el('span', { class: `tag ${cls}`, text: label }), ' ', el('strong', { text: t.title })]),
    el('div', { class: 'meta', text }),
    ...extra.map((x) => el('div', { class: 'meta', 'data-no-i18n': '', text: x }))]);
  const row = el('div', { class: 'li-row' }, [info]);
  if (r.fixable && r.status !== 'ok') {
    const btn = el('button', { class: 'small primary', text: '고치기' });
    btn.addEventListener('click', async () => {
      if (!confirm(`${node.name}: ${window.t(t.fix || t.title)}\n\n${window.t('패스키로 승인하면 서버가 서명을 확인한 뒤 실행합니다.')}`)) return;
      btn.disabled = true;
      show('서버에서 고치는 중…', 'ok');
      try {
        const st = await signedFix(node.id, r.id);
        if (st.ok) show(`고쳤습니다: ${st.message}`, 'ok'); else show(`고치지 못했습니다: ${st.error}`);
      } catch (e) {
        show(e.message === 'term_trust_missing' ? '이 서버가 믿는 패스키가 이 계정에 없습니다. 관리자가 서버 화면에서 신뢰 목록 변경을 승인해야 합니다.'
          : e.message === 'passkey_required' ? '패스키가 필요합니다. 계정 화면에서 등록하세요.' : e.name ? friendlyWebAuthnError(e) : e.message);
      }
      btn.disabled = false;
      setTimeout(() => loadCheckup().catch(() => {}), 1500);
    });
    row.append(el('div', { class: 'row' }, [btn]));
  }
  return el('li', {}, [row]);
}

async function loadCheckup() {
  const { nodes } = await api('/api/checkup');
  const order = { fail: 0, warn: 1, unknown: 2, info: 3, ok: 4, na: 5 };
  $('checkup').replaceChildren(...nodes.map((n) => {
    const again = el('button', { class: 'small', text: '다시 점검' });
    again.disabled = !n.connected;
    again.addEventListener('click', async () => {
      try { await api('/api/checkup/run', { node_id: n.id }); show('점검을 요청했습니다.', 'ok'); setTimeout(() => loadCheckup().catch(() => {}), 3000); } catch (e) { show(e.message); }
    });
    const results = (n.results || []).filter((r) => r.status !== 'na').sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9));
    const bad = results.filter((r) => r.status === 'fail').length;
    const head = el('div', { class: 'row' }, [el('div', {}, [el('strong', { 'data-no-i18n': '', text: n.name }),
      el('div', { class: 'meta', text: n.checked_at ? `${bad ? `위험 ${bad}개 · ` : ''}점검 ${fmtTime(n.checked_at)}` : '아직 점검 결과가 없습니다' })]), again]);
    return el('div', { class: 'card stack' }, [head, el('ul', { class: 'list' }, results.map((r) => checkRow(n, r)))]);
  }));
}

async function initSecurity() {
  loadCheckup().catch((e) => show(e.message));
  $('kind').addEventListener('change', () => loadSecurity().catch((e) => show(e.message)));
  const refresh = () => loadSecurity().catch((e) => {
    if (e.status === 401) location.href = `/login?rd=${encodeURIComponent(location.pathname)}`;
    else show(e.message);
  });
  await refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, 30000);
}

// ---------- 홈 ----------

const homeState = { data: null, editing: false, link: null };

function letterAvatar(name) {
  let h = 0;
  for (const c of name) h = (h * 31 + c.codePointAt(0)) % 360;
  const d = el('span', { class: 'letter', text: (name.trim()[0] || '?').toUpperCase() });
  d.style.background = `hsl(${h} 55% 52%)`;
  return d;
}

function tileIcon(item) {
  const box = el('span', { class: 'ico' });
  const img = el('img', { alt: '', loading: 'lazy', src: item.icon_url });
  img.addEventListener('error', () => box.replaceChildren(letterAvatar(item.name)));
  box.append(img);
  return box;
}

function homeTile(item) {
  const isLink = item.type === 'link';
  const a = el('a', { class: 'tile', href: item.url });
  if (isLink) { a.target = '_blank'; a.rel = 'noopener noreferrer'; }
  a.append(tileIcon(item), el('span', { class: 'txt' }, [
    el('div', { class: 'name', text: item.name }),
    el('div', { class: 'desc', text: item.description || item.url.replace(/^https?:\/\//, '') }),
  ]));
  if (!isLink) {
    const dot = el('span', { class: `dot ${item.health === 'up' ? 'on' : item.health === 'down' ? 'off' : ''}` });
    dot.title = item.health === 'up' ? '정상' : item.health === 'down' ? '응답 없음' : '확인 전';
    a.append(el('span', { class: 'state' }, [dot]));
  }
  const edit = el('button', { class: 'icon-btn edit', type: 'button', 'aria-label': `${item.name} 편집` });
  edit.append(icon('pencil', 16));
  edit.addEventListener('click', (ev) => {
    ev.preventDefault();
    if (isLink) openLinkDialog(item);
    else location.href = `/services#edit=${item.id}`;
  });
  a.append(edit);
  return a;
}

function renderHome() {
  const d = homeState.data;
  const pills = $('pills');
  const s = d.summary;
  const pill = (href, ic, text, bad) => {
    const a = el('a', { class: `pill${bad ? ' bad' : ''}`, href });
    a.append(icon(ic, 15), text);
    return a;
  };
  pills.replaceChildren(
    pill('/dashboard', 'server', `서버 ${s.online}/${s.servers}`, s.online < s.servers),
    pill('/dashboard', 'bell', s.alerts ? `알림 ${s.alerts}` : '알림 없음', s.alerts > 0),
    pill('/security', 'shield-check', s.security_open ? `보안 이슈 ${s.security_open}` : '보안 이슈 없음', s.security_open > 0),
  );
  // 그룹: 서비스 순서 → 링크 순서, 그룹 없는 항목은 "서비스"/"링크"
  const groups = new Map();
  for (const it of d.items) {
    const g = it.group || (it.type === 'link' ? '링크' : '서비스');
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(it);
  }
  for (const list of groups.values()) list.sort((a, b) => (a.type === b.type ? a.position - b.position || a.name.localeCompare(b.name) : a.type === 'service' ? -1 : 1));
  const box = $('groups');
  box.classList.toggle('editing', homeState.editing);
  const nodes = [];
  for (const [g, list] of groups) {
    const tiles = el('div', { class: 'tiles' }, list.map(homeTile));
    if (homeState.editing) {
      const add = el('button', { class: 'tile add', type: 'button' });
      add.append(icon('plus', 16), ' 링크 추가');
      add.addEventListener('click', () => openLinkDialog({ group: g === '링크' ? '' : g }));
      tiles.append(add);
    }
    nodes.push(el('div', { class: 'group-title' }, [el('h2', { text: g })]), tiles);
  }
  if (!groups.size) {
    nodes.push(el('div', { class: 'card empty' }, [
      el('h2', { text: '아직 바로가기가 없습니다' }),
      el('p', { class: 'meta', text: '서비스를 등록하면 여기에 나타납니다. "편집"을 눌러 외부 링크도 추가할 수 있습니다.' }),
    ]));
  }
  if (homeState.editing) {
    const add = el('button', { class: 'small', type: 'button' });
    add.append(icon('plus', 15), '새 그룹에 링크 추가');
    add.addEventListener('click', () => openLinkDialog({}));
    nodes.push(el('div', { class: 'group-title' }, [add]));
  }
  box.replaceChildren(...nodes);
  $('group-list').replaceChildren(...[...groups.keys()].map((g) => el('option', { value: g })));
}

function openLinkDialog(l) {
  homeState.link = l.id ? l : null;
  $('link-title').textContent = l.id ? '링크 수정' : '링크 추가';
  $('link-name').value = l.name || '';
  $('link-url').value = l.url || '';
  $('link-group').value = l.group || '';
  $('link-desc').value = l.description || '';
  $('link-icon').value = l.icon || '';
  $('link-delete').hidden = !l.id;
  $('link-dialog').showModal();
}

async function loadHome() {
  homeState.data = await api('/api/home');
  renderHome();
}

async function initHome() {
  const h = new Date().getHours();
  const part = h < 5 ? '늦은 밤이에요' : h < 11 ? '좋은 아침이에요' : h < 14 ? '좋은 점심이에요' : h < 18 ? '좋은 오후예요' : '좋은 저녁이에요';
  $('greet').textContent = part;
  $('today').textContent = new Date().toLocaleDateString(window.douveLocale, { year: 'numeric', month: 'long', day: 'numeric', weekday: 'long' });
  $('search-icon').replaceWith(icon('search', 18));
  $('search').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const q = $('q').value.trim();
    if (q) window.open(`https://duckduckgo.com/?q=${encodeURIComponent(q)}`, '_blank', 'noopener');
  });
  $('edit-home').addEventListener('click', () => {
    homeState.editing = !homeState.editing;
    $('edit-home').textContent = homeState.editing ? '완료' : '편집';
    renderHome();
  });
  $('link-save').addEventListener('click', async (ev) => {
    ev.preventDefault();
    if (!$('link-form').reportValidity()) return;
    const body = { name: $('link-name').value, url: $('link-url').value, group: $('link-group').value,
      description: $('link-desc').value, icon: $('link-icon').value.trim() };
    try {
      if (homeState.link) await api('/api/links/update', { id: homeState.link.id, ...body });
      else await api('/api/links/create', body);
      $('link-dialog').close();
      await loadHome();
    } catch (e) { show(e.message); }
  });
  $('link-delete').addEventListener('click', async () => {
    if (!homeState.link || !confirm(`'${homeState.link.name}' 링크를 지울까요?`)) return;
    try {
      await api('/api/links/delete', { id: homeState.link.id });
      $('link-dialog').close();
      await loadHome();
    } catch (e) { show(e.message); }
  });
  await loadHome().catch((e) => {
    if (e.status === 401) location.href = '/login?rd=/';
    else show(e.message);
  });
  setInterval(() => { if (!document.hidden && !$('link-dialog').open) loadHome().catch(() => {}); }, 60000);
}

document.addEventListener('DOMContentLoaded', () => {
  const page = document.body.dataset.page;
  if (page === 'dashboard') initDashboard();
  if (page === 'node') initNode();
  if (page === 'services') initServices();
  if (page === 'settings') initSettings();
  if (page === 'security') initSecurity();
  if (page === 'home') initHome();
});
