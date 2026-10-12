// 화면 번역: 한국어 원문을 사전(/static/i18n-en.js → window.DOUVE_I18N_EN)으로 영어로 바꾼다.
// <head>에서 동기로 실행되어 문서가 파싱되는 동안 추가되는 노드까지 MutationObserver로 번역한다
// (화면에 한국어가 잠깐 보이는 일 없음). 각 화면 코드는 한국어 그대로 두고 여기서만 처리한다.
//   언어: localStorage 'douve.lang'(ko|en) → 없으면 브라우저 언어(ko면 한국어, 아니면 영어)
//   사전 키의 {이름}은 패턴 ({n}·{m}은 숫자만, 값의 {n|단수|복수}는 영어 단·복수). 통째로 없으면 " · ", 줄바꿈 단위로 나눠 번역.
(function () {
  'use strict';
  const KO = /[가-힣]/;

  function detect() {
    try {
      const v = localStorage.getItem('douve.lang');
      if (v === 'ko' || v === 'en') return v;
    } catch (_) { /* 저장소를 못 써도 브라우저 언어로 */ }
    return /^ko\b/i.test(navigator.language || '') ? 'ko' : 'en';
  }
  const lang = detect();

  const exact = new Map();
  const patterns = [];
  const dict = window.DOUVE_I18N_EN || {};
  for (const [k, v] of Object.entries(dict)) {
    if (k.startsWith('_')) continue;
    if (!/\{[a-z0-9_]+\}/i.test(k)) { exact.set(k, v); continue; }
    const names = [];
    const src = k.split(/(\{[a-z0-9_]+\})/i).map((part) => {
      const m = part.match(/^\{([a-z0-9_]+)\}$/i);
      if (!m) return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      names.push(m[1]);
      return m[1] === 'n' || m[1] === 'm' ? '(\\d+(?:[.,]\\d+)?)' : '(.+?)';
    }).join('');
    patterns.push({ re: new RegExp(`^${src}$`, 's'), names, out: v, len: k.length });
  }
  patterns.sort((a, b) => b.len - a.len); // 구체적인(긴) 패턴 먼저

  function tr(s, depth = 0) {
    if (lang !== 'en' || typeof s !== 'string' || depth > 5 || !KO.test(s)) return s;
    const lead = s.match(/^[\s·]*/)[0];
    const tail = s.slice(lead.length).match(/[\s·]*$/)[0];
    const core = s.slice(lead.length, s.length - tail.length);
    if (!core) return s;
    let r = exact.get(core);
    // HTML 안에서 줄을 바꿔 쓴 문장: 공백을 하나로 모아 다시 (안 되면 줄 단위로)
    if (r === undefined && /\s\s|\n/.test(core)) {
      const flat = core.replace(/\s+/g, ' ');
      const f = tr(flat, depth + 1);
      if (f !== flat) r = f;
    }
    if (r === undefined && core.includes('\n')) r = core.split('\n').map((x) => tr(x, depth + 1)).join('\n');
    if (r === undefined) {
      for (const p of patterns) {
        const m = core.match(p.re);
        if (!m) continue;
        // {n|issue|issues}: 숫자 자리 n이 1이면 앞, 아니면 뒤 (영어 단·복수)
        r = p.out.replace(/\{([a-z0-9_]+)(?:\|([^|}]*)\|([^}]*))?\}/gi, (all, n, one, many) => {
          const i = p.names.indexOf(n);
          if (i < 0) return all;
          if (one !== undefined) return m[i + 1] === '1' ? one : many;
          return tr(m[i + 1], depth + 1);
        });
        break;
      }
    }
    if (r === undefined && core.includes(' · ')) r = core.split(' · ').map((x) => tr(x, depth + 1)).join(' · ');
    return r === undefined ? s : lead + r + tail;
  }

  window.douveLang = lang;
  window.douveLocale = lang === 'ko' ? 'ko-KR' : (/^ko/i.test(navigator.language || '') ? 'en-US' : undefined);
  window.t = tr;
  window.setDouveLang = (l) => {
    try { localStorage.setItem('douve.lang', l); } catch (_) { /* 이번 화면만 */ }
    location.reload();
  };
  document.documentElement.lang = lang;
  if (lang !== 'en') return;

  // ---- 문서 번역 ----
  const ATTRS = ['placeholder', 'title', 'aria-label', 'alt'];
  // 사용자 데이터·터미널 출력·코드는 건드리지 않는다
  const SKIP = 'script,style,textarea,pre,code,.xterm,[data-no-i18n]';
  function skipped(el) { return !!(el && el.closest && el.closest(SKIP)); }
  function walk(node) {
    if (node.nodeType === 3) {
      if (KO.test(node.nodeValue) && !skipped(node.parentElement)) {
        const v = tr(node.nodeValue);
        if (v !== node.nodeValue) node.nodeValue = v;
      }
      return;
    }
    if (node.nodeType !== 1 || skipped(node)) return;
    for (const a of ATTRS) {
      const v = node.getAttribute(a);
      if (v && KO.test(v)) {
        const n = tr(v);
        if (n !== v) node.setAttribute(a, n);
      }
    }
    for (let c = node.firstChild; c; c = c.nextSibling) walk(c);
  }
  new MutationObserver((records) => {
    for (const r of records) {
      if (r.type === 'childList') r.addedNodes.forEach(walk);
      else if (r.type === 'characterData') walk(r.target);
      else walk(r.target); // attributes
    }
  }).observe(document.documentElement, {
    childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS,
  });
  walk(document.documentElement);

  // 대화상자 문구
  for (const name of ['alert', 'confirm', 'prompt']) {
    const orig = window[name];
    window[name] = function (msg, ...rest) { return orig.call(window, tr(String(msg ?? '')), ...rest); };
  }
})();
