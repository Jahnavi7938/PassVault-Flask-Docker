/* PassVault - shared helpers. Loaded on every page.
   Nothing secret is ever written to storage: only theme and timeout preferences. */
const PV = (() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // ---- preferences (non-sensitive) ----
  const DEFAULTS = { pv_reveal_secs: 15, pv_clip_secs: 30, pv_lock_mins: 15 };
  function pref(key) {
    try { const v = localStorage.getItem(key); if (v !== null) return Number(v); } catch (e) {}
    return DEFAULTS[key];
  }
  function setPref(key, val) { try { localStorage.setItem(key, String(val)); } catch (e) {} }

  // ---- fetch wrapper: adds the CSRF header, normalises errors ----
  async function api(method, url, body) {
    const opts = {
      method, credentials: 'same-origin',
      headers: { 'X-CSRFToken': $('meta[name="csrf-token"]').content, 'Accept': 'application/json' },
    };
    if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    let res;
    try { res = await fetch(url, opts); }
    catch (e) { throw new Error('Could not reach the server. Check your connection.'); }
    let data = {};
    try { data = await res.json(); } catch (e) {}
    if (!res.ok) {
      if (data.code === 'vault_locked') { location.href = '/unlock?next=' + encodeURIComponent(location.pathname); }
      else if (data.code === 'unauthenticated') { location.href = '/login'; }
      const err = new Error(data.error || 'Something went wrong (' + res.status + ').');
      err.status = res.status; err.fields = data.fields || {};
      throw err;
    }
    return data;
  }

  // ---- toasts ----
  function toast(msg, type) {
    const box = $('#toasts'); if (!box) return;
    const el = document.createElement('div');
    el.className = 'toast ' + (type || 'info');
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 300); }, 3500);
  }

  // ---- tiny DOM builder (textContent only, so user data can't inject markup) ----
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v == null) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('data-') || k === 'href' || k === 'type' || k === 'rel' || k === 'target' || k === 'aria-label') el.setAttribute(k, v);
      else el[k] = v;
    }
    kids.flat().forEach(kid => { if (kid != null) el.append(kid); });
    return el;
  }

  // ---- modal ----
  function modal(title, body, buttons) {
    const backdrop = h('div', { class: 'modal-backdrop' });
    const box = h('div', { class: 'modal', role: 'dialog', 'aria-label': title }, h('h2', { text: title }), body);
    const close = () => { backdrop.remove(); document.removeEventListener('keydown', onKey); };
    const onKey = e => { if (e.key === 'Escape') close(); };
    if (buttons && buttons.length) {
      box.append(h('div', { class: 'modal-actions' }, buttons.map(b =>
        h('button', { class: 'btn ' + (b.cls || ''), type: 'button', text: b.label, onclick: () => b.onClick(close) }))));
    }
    backdrop.addEventListener('mousedown', e => { if (e.target === backdrop) close(); });
    document.addEventListener('keydown', onKey);
    backdrop.append(box);
    document.body.append(backdrop);
    const first = $('input, select, textarea, button', box); if (first) first.focus();
    return close;
  }
  function confirmBox(title, message, okLabel) {
    return new Promise(resolve => {
      modal(title, h('p', { class: 'muted', text: message }), [
        { label: 'Cancel', cls: 'btn-ghost', onClick: close => { close(); resolve(false); } },
        { label: okLabel || 'Confirm', cls: 'btn-danger', onClick: close => { close(); resolve(true); } },
      ]);
    });
  }

  // ---- strength estimate (mirrors the server; the server's score is the one that's stored) ----
  const COMMON = ['password', 'passw0rd', 'qwerty', 'letmein', 'welcome', 'admin', 'login', 'iloveyou', 'monkey', 'dragon', 'football', 'baseball', 'master', 'sunshine', 'princess', 'abc123', 'trustno1', 'shadow', 'superman', 'michael', 'hello', 'freedom', 'whatever'];
  const SEQS = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiopasdfghjklzxcvbnm'];
  function hasSequence(pw) {
    const low = pw.toLowerCase();
    return SEQS.some(s => [s, [...s].reverse().join('')].some(t => { for (let i = 0; i <= t.length - 4; i++) if (low.includes(t.slice(i, i + 4))) return true; return false; }));
  }
  function label(bits) { return bits < 40 ? 'weak' : bits < 60 ? 'medium' : 'strong'; }
  function strength(pw) {
    if (!pw) return { score: 0, label: 'weak', entropy: 0 };
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26; if (/[A-Z]/.test(pw)) pool += 26;
    if (/\d/.test(pw)) pool += 10; if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
    let e = pool ? pw.length * Math.log2(pool) : 0;
    e *= 0.4 + 0.6 * (new Set(pw).size / pw.length);
    if (/(.)\1{2,}/.test(pw)) e -= 8;
    if (hasSequence(pw)) e -= 10;
    const core = pw.toLowerCase().replace(/[0134$@5!]/g, c => ({ '0': 'o', '1': 'l', '3': 'e', '4': 'a', '$': 's', '@': 'a', '5': 's', '!': 'i' }[c])).replace(/[^a-z]/g, '');
    if (COMMON.includes(core) || COMMON.some(w => w.length >= 6 && core.includes(w))) e = Math.min(e, 28);
    e = Math.max(e, 0);
    return { score: Math.min(100, Math.round(e / 80 * 100)), label: label(e), entropy: Math.round(e * 10) / 10 };
  }
  function paintMeter(meter, labelEl, s, extra) {
    if (!meter) return;
    meter.dataset.level = s.label;
    meter.firstElementChild.style.width = Math.max(s.score, s.score ? 6 : 0) + '%';
    if (labelEl) {
      labelEl.textContent = '';
      labelEl.append(h('b', { 'data-level': s.label, text: s.label.charAt(0).toUpperCase() + s.label.slice(1) }),
        ' · about ' + Math.round(s.entropy) + ' bits' + (extra || ''));
    }
  }
  function bindMeter(input, meter, labelEl) {
    input.addEventListener('input', () => {
      if (!input.value) { paintMeter(meter, null, { score: 0, label: 'weak' }); if (labelEl) labelEl.textContent = 'Type a password or generate one.'; return; }
      paintMeter(meter, labelEl, strength(input.value));
    });
  }

  // ---- clipboard (best effort clear) ----
  let clipTimer = null;
  async function copyText(text, btn) {
    try { await navigator.clipboard.writeText(text); }
    catch (e) { toast('Your browser blocked clipboard access.', 'error'); return false; }
    const secs = pref('pv_clip_secs');
    toast('Copied. Clipboard clears in ' + secs + 's.', 'success');
    if (btn) { const old = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = old; }, 1600); }
    clearTimeout(clipTimer);
    clipTimer = setTimeout(() => { navigator.clipboard.writeText('').catch(() => {}); }, secs * 1000);
    return true;
  }

  // ---- reveal / copy for any element carrying data-reveal / data-copy ----
  const hideTimers = new WeakMap();
  function hide(out, btn) {
    out.textContent = '••••••••••••'; out.classList.remove('revealed');
    if (btn) btn.textContent = 'Reveal';
    clearTimeout(hideTimers.get(out)); hideTimers.delete(out);
  }
  async function toggleReveal(btn) {
    const row = btn.closest('[data-item]');
    const out = row && $('[data-mask]', row);
    if (!out) return;
    if (out.classList.contains('revealed')) return hide(out, btn);
    btn.disabled = true;
    try {
      const { password } = await api('POST', '/api/vault/' + btn.dataset.reveal + '/reveal');
      out.textContent = password; out.classList.add('revealed'); btn.textContent = 'Hide';
      hideTimers.set(out, setTimeout(() => hide(out, btn), pref('pv_reveal_secs') * 1000));
    } catch (e) { toast(e.message, 'error'); }
    btn.disabled = false;
  }
  async function copyFromVault(btn) {
    btn.disabled = true;
    try {
      const { password } = await api('POST', '/api/vault/' + btn.dataset.copy + '/copy');
      await copyText(password, btn);
    } catch (e) { toast(e.message, 'error'); }
    btn.disabled = false;
  }
  document.addEventListener('click', e => {
    const r = e.target.closest('[data-reveal]'); if (r) return toggleReveal(r);
    const c = e.target.closest('[data-copy]'); if (c) return copyFromVault(c);
    const t = e.target.closest('[data-toggle-pw]');
    if (t) {
      const input = t.parentElement.querySelector('input');
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password'; t.textContent = show ? 'Hide' : 'Show';
    }
    if (e.target.closest('[data-action="lock-now"]')) lockNow();
  });

  // ---- lock ----
  async function lockNow() {
    try { await api('POST', '/api/lock'); } catch (e) { /* not fatal; still go to the unlock page */ }
    location.href = '/unlock?next=' + encodeURIComponent(location.pathname);
  }
  function idleLock() {
    if (document.body.dataset.auth !== '1' || location.pathname === '/unlock') return;
    let timer = null;
    const arm = () => {
      clearTimeout(timer);
      const mins = pref('pv_lock_mins');
      if (mins > 0) timer = setTimeout(lockNow, mins * 60 * 1000);
    };
    ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'].forEach(ev => document.addEventListener(ev, arm, { passive: true }));
    arm();
  }

  // ---- page chrome ----
  function paintAvatars(root) {
    $$('.avatar[data-name]', root).forEach(a => {
      let n = 0; for (const ch of a.dataset.name) n = (n * 31 + ch.charCodeAt(0)) % 360;
      a.style.setProperty('--h', n);
    });
  }
  function init() {
    $$('#flash-data li').forEach(li => toast(li.textContent, li.dataset.cat === 'message' ? 'info' : li.dataset.cat));
    paintAvatars(document);
    const nt = $('#nav-toggle'), links = $('#nav-links');
    if (nt) nt.addEventListener('click', () => { const o = links.classList.toggle('open'); nt.setAttribute('aria-expanded', o); });
    if (links) links.addEventListener('click', e => { if (e.target.closest('a')) links.classList.remove('open'); });
    const dt = $('#drawer-toggle'), sb = $('#sidebar');
    if (dt && sb) {
      const scrim = h('div', { class: 'scrim', hidden: true });
      document.body.append(scrim);
      const set = open => { sb.classList.toggle('open', open); scrim.hidden = !open; };
      dt.addEventListener('click', () => set(!sb.classList.contains('open')));
      scrim.addEventListener('click', () => set(false));
    }
    // settings page
    const th = $('#set-theme');
    if (th) {
      th.value = document.documentElement.getAttribute('data-theme');
      th.addEventListener('change', () => { document.documentElement.setAttribute('data-theme', th.value); try { localStorage.setItem('pv_theme', th.value); } catch (e) {} });
      [['#set-lock', 'pv_lock_mins'], ['#set-reveal', 'pv_reveal_secs'], ['#set-clip', 'pv_clip_secs']].forEach(([sel, key]) => {
        const s = $(sel); s.value = String(pref(key));
        s.addEventListener('change', () => { setPref(key, s.value); toast('Saved.', 'success'); });
      });
    }
    idleLock();
  }
  document.addEventListener('DOMContentLoaded', init);

  return { $, $$, h, api, toast, modal, confirmBox, strength, paintMeter, bindMeter, copyText, paintAvatars, pref };
})();
