'use strict';
// Douve 웹 UI. 외부 라이브러리 없이 WebAuthn을 호출한다.

const $ = (id) => document.getElementById(id);

function b64uToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
}

function bufToB64u(buf) {
  let bin = '';
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function api(path, body) {
  const opts = body === undefined
    ? { credentials: 'same-origin' }
    : { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (_) { /* 본문 없음 */ }
  if (!res.ok) {
    const err = new Error(data.error || `요청 실패 (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function show(msg, kind = 'error') {
  const el = $('msg');
  el.textContent = msg;
  el.className = `msg ${kind}`;
}

function fmtTime(ts) {
  if (!ts) return '없음';
  return new Date(ts * 1000).toLocaleString(window.douveLocale, { dateStyle: 'medium', timeStyle: 'short' });
}

const passkeySupported = () => !!(window.PublicKeyCredential && navigator.credentials);

// 서버가 준 옵션(base64url 문자열)을 브라우저 API 형식(ArrayBuffer)으로 변환
function toRequestOptions(pk) {
  return {
    ...pk,
    challenge: b64uToBuf(pk.challenge),
    allowCredentials: (pk.allowCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  };
}

function toCreationOptions(pk) {
  return {
    ...pk,
    challenge: b64uToBuf(pk.challenge),
    user: { ...pk.user, id: b64uToBuf(pk.user.id) },
    excludeCredentials: (pk.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  };
}

function assertionJson(cred) {
  return {
    id: cred.id,
    type: cred.type,
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      authenticatorData: bufToB64u(cred.response.authenticatorData),
      signature: bufToB64u(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null,
    },
  };
}

function friendlyWebAuthnError(e) {
  if (e.name === 'NotAllowedError') return '취소되었거나 시간이 초과되었습니다.';
  if (e.name === 'InvalidStateError') return '이 기기에는 이미 패스키가 등록되어 있습니다.';
  if (e.name === 'SecurityError') return '이 주소에서는 패스키를 사용할 수 없습니다.';
  return e.message || String(e);
}

// ---------- 로그인 화면 ----------

const LOGIN_ERRORS = {
  google_disabled: 'Google 로그인이 설정되지 않았습니다.',
  google_cancelled: 'Google 로그인을 취소했습니다.',
  state: '로그인 요청이 만료되었습니다. 다시 시도하세요.',
  google: 'Google 로그인 확인에 실패했습니다.',
  not_allowed: '로그인이 허용되지 않은 계정입니다.',
};

async function initLogin() {
  const params = new URLSearchParams(location.search);
  const rd = params.get('rd') || '/account';
  $('google-login').href = `/auth/google/start?rd=${encodeURIComponent(rd)}`;
  // Google 로그인이 설정되지 않았으면 버튼을 숨긴다 (패스키만으로 쓰는 설치)
  let google = true;
  const syncOr = () => { $('or').hidden = !(google && !$('passkey-login').hidden); };
  api('/auth/methods').then((m) => { google = !!m.google; $('google-login').hidden = !google; syncOr(); }).catch(() => {});
  if (params.get('error')) show(LOGIN_ERRORS[params.get('error')] || '로그인에 실패했습니다.');

  // 이미 로그인되어 있으면 바로 이동
  try {
    await api('/api/me');
    if (!params.get('error')) return location.replace(rd.startsWith('/') ? rd : '/account');
  } catch (_) { /* 로그인 필요 */ }

  $('recovery-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    show('');
    try {
      await api('/auth/recovery', { code: $('recovery-code').value });
      location.assign('/account?recovered=1');
    } catch (e) {
      show(e.message);
    }
  });

  if (!passkeySupported()) return;
  $('passkey-login').hidden = false;
  syncOr();
  $('passkey-login').addEventListener('click', async () => {
    const btn = $('passkey-login');
    btn.disabled = true;
    show('');
    try {
      const opts = await api('/auth/passkey/login/options', { rd });
      const cred = await navigator.credentials.get({ publicKey: toRequestOptions(opts.publicKey) });
      const res = await api('/auth/passkey/login/verify', { pending: opts.pending, credential: assertionJson(cred) });
      location.assign(res.redirect || '/account');
    } catch (e) {
      show(e.name ? friendlyWebAuthnError(e) : e.message);
      btn.disabled = false;
    }
  });
}

// ---------- 계정 화면 ----------

async function reauth() {
  const opts = await api('/auth/passkey/reauth/options', {});
  const cred = await navigator.credentials.get({ publicKey: toRequestOptions(opts.publicKey) });
  await api('/auth/passkey/reauth/verify', { pending: opts.pending, credential: assertionJson(cred) });
}

// 재인증이 필요하다고 하면 패스키 확인 후 한 번 더 시도
async function withReauth(fn) {
  try {
    return await fn();
  } catch (e) {
    if (e.status === 403 && e.message === 'reauth_required') {
      show('본인 확인을 위해 패스키를 사용하세요.', 'ok');
      await reauth();
      return fn();
    }
    throw e;
  }
}

async function addPasskey() {
  const name = prompt('이 패스키의 이름 (예: 맥북, 아이폰)', '') ?? null;
  if (name === null) return;
  try {
    await withReauth(async () => {
      const opts = await api('/auth/passkey/register/options', {});
      const cred = await navigator.credentials.create({ publicKey: toCreationOptions(opts.publicKey) });
      await api('/auth/passkey/register/verify', {
        pending: opts.pending,
        name,
        credential: {
          id: cred.id,
          type: cred.type,
          response: {
            clientDataJSON: bufToB64u(cred.response.clientDataJSON),
            attestationObject: bufToB64u(cred.response.attestationObject),
            transports: cred.response.getTransports ? cred.response.getTransports() : [],
          },
        },
      });
    });
    show('패스키를 등록했습니다.', 'ok');
    $('setup-banner').hidden = true;
    history.replaceState(null, '', '/account');
    await loadPasskeys();
  } catch (e) {
    show(e.name ? friendlyWebAuthnError(e) : e.message);
  }
}

function li(children) {
  const el = document.createElement('li');
  el.append(...children);
  return el;
}

function text(tag, value, cls) {
  const el = document.createElement(tag);
  el.textContent = value;
  if (cls) el.className = cls;
  return el;
}

async function loadPasskeys() {
  const { passkeys } = await api('/api/passkeys');
  const ul = $('passkeys');
  ul.replaceChildren();
  if (passkeys.length === 0) ul.append(li([text('span', '등록된 패스키가 없습니다.', 'meta')]));
  for (const k of passkeys) {
    const del = text('button', '삭제', 'small danger');
    del.addEventListener('click', async () => {
      if (!confirm(`'${k.name}' 패스키를 삭제할까요?`)) return;
      try {
        await withReauth(() => api('/api/passkeys/delete', { id: k.id }));
        show('삭제했습니다.', 'ok');
        await loadPasskeys();
      } catch (e) { show(e.name ? friendlyWebAuthnError(e) : e.message); }
    });
    const info = document.createElement('div');
    info.append(text('div', k.name), text('div', `등록 ${fmtTime(k.created_at)} · 마지막 사용 ${fmtTime(k.last_used_at)}`, 'meta'));
    const row = document.createElement('div');
    row.className = 'row';
    row.append(info, del);
    ul.append(li([row]));
  }
}

async function loadSessions() {
  const { sessions } = await api('/api/sessions');
  const ul = $('sessions');
  ul.replaceChildren();
  for (const s of sessions) {
    const info = document.createElement('div');
    const title = text('div', s.user_agent ? s.user_agent.slice(0, 80) : '알 수 없는 기기');
    if (s.current) title.append(' ', text('span', '현재 기기', 'tag'));
    info.append(title, text('div', `${s.ip || '-'} · ${({ passkey: '패스키 로그인', google: 'Google 로그인', recovery: '복구 코드 로그인', tailscale: 'Tailscale 로그인' })[s.auth_method] || s.auth_method} · 마지막 사용 ${fmtTime(s.last_seen_at)}`, 'meta'));
    const row = document.createElement('div');
    row.className = 'row';
    row.append(info);
    if (!s.current) {
      const btn = text('button', '로그아웃', 'small');
      btn.addEventListener('click', async () => {
        await api('/api/sessions/revoke', { hint: s.hint });
        await loadSessions();
      });
      row.append(btn);
    }
    ul.append(li([row]));
  }
}

async function loadRecovery() {
  const r = await api('/api/account/recovery');
  $('recovery-status').textContent = r.created_at
    ? `남은 코드 ${r.remaining}/${r.total}개 · ${fmtTime(r.created_at)}에 만듦${r.remaining <= 3 ? ' — 얼마 남지 않았습니다. 새로 만드세요.' : ''}`
    : '아직 없습니다. 패스키를 쓰는 기기를 모두 잃었을 때를 대비해 만들어 두세요.';
}

function initRecoveryCodes() {
  $('new-codes').addEventListener('click', async () => {
    if (!confirm('복구 코드를 새로 만들까요? 이전 코드는 모두 쓸 수 없게 됩니다.')) return;
    try {
      const { codes } = await withReauth(() => api('/api/account/recovery/generate', {}));
      $('codes').textContent = codes.join('\n');
      $('codes-box').hidden = false;
      show('');
      await loadRecovery();
    } catch (e) { show(e.message); }
  });
  $('copy-codes').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText($('codes').textContent); show('복사했습니다.', 'ok'); } catch (_) { show('복사하지 못했습니다. 직접 선택해 복사하세요.'); }
  });
  $('save-codes').addEventListener('click', () => {
    const text = `${window.t(`Douve 복구 코드 (${location.host})`)}\n${window.t('한 번씩만 쓸 수 있습니다. 로그인 화면 → "복구 코드로 로그인"')}\n\n${$('codes').textContent}\n`;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    a.download = `douve-recovery-codes-${location.host}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  loadRecovery().catch(() => {});
}

async function initAccount() {
  let me;
  try {
    me = await api('/api/me');
  } catch (_) {
    return location.replace('/login?rd=/account');
  }
  $('email').textContent = me.email;
  if (new URLSearchParams(location.search).get('setup') === 'passkey') $('setup-banner').hidden = false;
  if (new URLSearchParams(location.search).get('recovered') === '1') $('recovered-banner').hidden = false;
  initRecoveryCodes();
  if (!passkeySupported()) $('add-passkey').disabled = true;
  $('add-passkey').addEventListener('click', addPasskey);
  $('logout').addEventListener('click', async () => {
    await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' });
    location.assign('/login');
  });
  $('revoke-others').addEventListener('click', async () => {
    if (!confirm('이 기기를 제외한 모든 기기에서 로그아웃할까요?')) return;
    const { sessions } = await api('/api/sessions');
    for (const s of sessions.filter((x) => !x.current)) await api('/api/sessions/revoke', { hint: s.hint });
    await loadSessions();
    show('다른 기기를 모두 로그아웃했습니다.', 'ok');
  });
  await Promise.all([loadPasskeys(), loadSessions()]);
}

// ---------- 초대 수락 ----------
// 링크: /invite#<토큰> (토큰은 # 뒤라 서버 로그에 남지 않는다)
async function initInvite() {
  const token = location.hash.slice(1);
  history.replaceState(null, '', '/invite'); // 주소창·방문 기록에서 토큰 제거
  if (!token) { $('invite-sub').textContent = '초대 링크가 올바르지 않습니다.'; return; }
  if (!passkeySupported()) { $('invite-sub').textContent = '이 브라우저는 패스키를 지원하지 않습니다. 최신 브라우저로 여세요.'; return; }
  $('invite-sub').textContent = 'Douve에 초대되었습니다. 이 기기에 패스키를 만들면 바로 시작합니다.';
  $('invite-name-box').hidden = false;
  $('invite-accept').hidden = false;
  $('invite-help').hidden = false;
  $('invite-accept').addEventListener('click', async () => {
    const btn = $('invite-accept');
    btn.disabled = true;
    show('');
    try {
      const opts = await api('/auth/invite/options', { token });
      const cred = await navigator.credentials.create({ publicKey: toCreationOptions(opts.publicKey) });
      await api('/auth/invite/verify', {
        token,
        pending: opts.pending,
        name: $('invite-name').value.trim(),
        credential: {
          id: cred.id,
          type: cred.type,
          response: {
            clientDataJSON: bufToB64u(cred.response.clientDataJSON),
            attestationObject: bufToB64u(cred.response.attestationObject),
            transports: cred.response.getTransports ? cred.response.getTransports() : [],
          },
        },
      });
      location.replace('/dashboard');
    } catch (e) {
      show(e.name ? friendlyWebAuthnError(e) : e.message);
      btn.disabled = false;
    }
  });
}

// ---------- 공통 레이아웃 (사이드바 / 모바일 하단 탭) ----------
const NAV = [
  { key: 'home', href: '/', label: '홈', icon: 'house' },
  { key: 'servers', href: '/dashboard', label: '서버', icon: 'server' },
  { key: 'services', href: '/services', label: '서비스', icon: 'app-window' },
  { key: 'security', href: '/security', label: '보안', icon: 'shield-check' },
  { key: 'settings', href: '/settings', label: '설정', icon: 'settings' },
  { key: 'account', href: '/account', label: '계정', icon: 'user', wide: true },
];

// 언어 바꾸기 (다른 언어 이름을 보여 준다). 번역하지 않도록 data-no-i18n.
function langSwitch() {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'lang-switch';
  b.dataset.noI18n = '';
  const other = window.douveLang === 'en' ? 'ko' : 'en';
  b.textContent = other === 'en' ? 'English' : '한국어';
  b.addEventListener('click', () => window.setDouveLang(other));
  return b;
}

function mountShell(active) {
  const side = document.createElement('nav');
  side.className = 'side';
  side.setAttribute('aria-label', '메뉴');
  const brand = document.createElement('a');
  brand.className = 'brand';
  brand.href = '/';
  const logo = document.createElement('img');
  logo.className = 'logo';
  logo.src = '/favicon.svg';
  logo.alt = '';
  brand.append(logo, 'Douve');
  side.append(brand);
  const counts = {};
  for (const n of NAV) {
    const a = document.createElement('a');
    a.className = `nav-item${n.key === active ? ' on' : ''}${n.wide ? ' wide-only' : ''}`;
    a.href = n.href;
    if (n.key === active) a.setAttribute('aria-current', 'page');
    const label = document.createElement('span');
    label.textContent = n.label;
    const c = document.createElement('span');
    c.className = 'count';
    c.hidden = true;
    counts[n.key] = c;
    a.append(icon(n.icon, 18), label, c);
    if (n.key === 'account') side.append(Object.assign(document.createElement('div'), { className: 'spacer' }));
    side.append(a);
  }
  const who = document.createElement('div');
  who.className = 'who';
  side.append(who, langSwitch());

  const shell = document.createElement('div');
  shell.className = 'shell';
  const content = document.createElement('div');
  content.className = 'content';
  while (document.body.firstChild) content.append(document.body.firstChild);
  shell.append(side, content);
  document.body.append(shell);

  const refresh = () => api('/api/summary').then((s) => {
    who.textContent = s.email;
    const set = (k, n) => { counts[k].textContent = n; counts[k].hidden = !n; };
    set('servers', s.alerts + (s.servers - s.online));
    set('security', s.security_open);
  }).catch(() => {});
  refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, 60000);
}

document.addEventListener('DOMContentLoaded', () => {
  const page = document.body.dataset.page;
  if (document.body.dataset.shell) mountShell(document.body.dataset.shell);
  if ($('logo')) $('logo').append(Object.assign(document.createElement('img'), { src: '/favicon.svg', alt: '' }));
  // 로그인·초대처럼 메뉴가 없는 화면은 카드 아래에 언어 바꾸기
  if (!document.body.dataset.shell && document.querySelector('.card')) document.querySelector('.card').append(langSwitch());
  if (page === 'login') initLogin();
  if (page === 'invite') initInvite();
  if (page === 'account') initAccount();
  if (page === 'privacy') {
    api('/api/privacy').then(({ contact }) => {
      if (!contact) return;
      for (const a of document.querySelectorAll('a.contact')) {
        a.textContent = contact;
        if (contact.includes('@')) a.href = `mailto:${contact}`;
      }
      for (const e of document.querySelectorAll('.contact-box')) e.hidden = false;
      for (const e of document.querySelectorAll('.no-contact')) e.hidden = true;
    }).catch(() => {});
  }
});
