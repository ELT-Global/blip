// Shared helpers: DOM building, the API client, formatting and the two
// visualisations (uptime blocks and the latency chart).

// h builds an element. Attributes starting with "on" become listeners;
// children may be strings, nodes, arrays or falsy (skipped). Text is never
// parsed as HTML, so user data is always safe to pass.
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k in el && k !== 'list') el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  return fill(el, ...kids), el;
}

// fill replaces el's children, skipping falsy entries like h does.
export function fill(el, ...kids) {
  el.replaceChildren(...kids.flat(9).filter(k => k != null && k !== false && k !== ''));
}

export const $ = (sel, root = document) => root.querySelector(sel);

export class APIError extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}

// api calls the JSON API. Pass {body} to send JSON and {signal} to make the
// request cancellable when the view that issued it goes away.
export async function api(path, { method = 'GET', body, signal } = {}) {
  const opts = { method, signal, headers: {}, credentials: 'same-origin' };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  let res;
  try { res = await fetch('/api' + path, opts); } catch (err) {
    if (err.name === 'AbortError') throw err;
    throw Object.assign(new APIError(0, 'You appear to be offline'), { offline: true });
  }
  // Parse only JSON; an abort mid-body rejects here and propagates as AbortError.
  const data = res.headers.get('Content-Type')?.startsWith('application/json') ? await res.json() : null;
  if (res.status === 401) dispatchEvent(new Event('blip:signedout'));
  if (!res.ok) throw new APIError(res.status, data?.error || 'HTTP ' + res.status);
  return data;
}

export const tz = () => -new Date().getTimezoneOffset() * 60;

// The live region exists before the first message so screen readers announce it.
const toastEl = document.body.appendChild(h('div', { id: 'toast', role: 'status', 'aria-live': 'polite' }));
let toastTimer;
export function toast(msg, bad = false) {
  const el = toastEl;
  el.textContent = msg;
  el.className = 'show' + (bad ? ' bad' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.className = '', 2600);
}

// --- formatting ---

const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const df = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });
const tf = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });
const tsf = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });

export const fmt = {
  dateTime: t => dtf.format(t * 1000),
  date: t => df.format(t * 1000),
  time: t => tf.format(t * 1000),
  timeSec: t => tsf.format(t * 1000),
  ms: ms => ms >= 1000 ? (ms / 1000).toFixed(2) + ' s' : Math.round(ms) + ' ms',
  pct: (up, n) => n ? (Math.floor(up / n * 10000) / 100).toFixed(2) + '%' : '—',
  ago(t) {
    const s = Math.max(0, Date.now() / 1000 - t);
    if (s < 60) return Math.round(s) + 's ago';
    if (s < 3600) return Math.round(s / 60) + 'm ago';
    if (s < 86400) return Math.round(s / 3600) + 'h ago';
    return Math.round(s / 86400) + 'd ago';
  },
  duration(s) {
    s = Math.max(0, Math.round(s));
    if (s < 60) return s + 's';
    const d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return [d && d + 'd', hh && hh + 'h', m && m + 'm'].filter(Boolean).join(' ') || '0m';
  },
  interval(s) {
    if (s % 3600 === 0) return s / 3600 + 'h';
    if (s % 60 === 0) return s / 60 + 'm';
    return s + 's';
  },
  bytes(n) {
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + ' ' + u[i];
  },
};

// codeText explains a stored check code: an HTTP status, or a negative
// value for transport failures (see store.Code*).
export function codeText(code) {
  return { 0: 'Connection error', '-1': 'Timeout', '-2': 'DNS failure', '-3': 'Connection refused', '-4': 'TLS error' }[code]
    ?? 'HTTP ' + code;
}
export const isUp = code => code >= 200 && code < 400;

// --- time slots ---

// localDays returns the start (unix s) of each of the last n local days, oldest first.
export function localDays(n) {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  const out = [];
  for (let i = n - 1; i >= 0; i--) {
    const x = new Date(d);
    x.setDate(d.getDate() - i);
    out.push(x.getTime() / 1000);
  }
  return out;
}

// dayHours returns the starts of the hourly rollups covering the local day
// beginning at day. Rollups are aligned to UTC hours, so in zones with a
// fractional offset (e.g. +05:30) slots start at :30 local time.
export function dayHours(day) {
  const end = new Date(day * 1000);
  end.setDate(end.getDate() + 1);
  const out = [];
  // ceil: the server files an hour under the day its start falls in.
  for (let t = Math.ceil(day / 3600) * 3600; t < end.getTime() / 1000; t += 3600) out.push(t);
  return out;
}

// dayKey aligns a timestamp to a day index under the current offset; rounding
// absorbs the one-hour skew of buckets on the other side of a DST change.
export const dayKey = t => Math.round((t + tz()) / 86400);

// --- uptime blocks ---

const tipEl = document.body.appendChild(h('div', { class: 'tip hidden', 'aria-hidden': 'true' }));

function showTip(x, y, text) {
  tipEl.textContent = text;
  tipEl.classList.remove('hidden');
  const r = tipEl.getBoundingClientRect();
  tipEl.style.left = Math.min(innerWidth - r.width - 8, Math.max(8, x - r.width / 2)) + 'px';
  tipEl.style.top = Math.max(8, y - r.height - 14) + 'px';
}
// hideTip must also run before re-renders: removed nodes never fire pointerleave.
export const hideTip = () => tipEl.classList.add('hidden');

// bars renders one block per slot. Each slot is {n, up, label, detail}
// where n=0 means no data. With onPick, blocks that have data are buttons
// that zoom in, so they work from the keyboard too.
export function bars(slots, { cls = '', label = 'Uptime', onPick } = {}) {
  const el = h('div', { class: 'bars ' + cls, role: 'group', 'aria-label': label });
  for (const s of slots) {
    const state = !s.n ? 'none' : s.up === s.n ? 'up' : s.up === 0 ? 'down' : 'part';
    const text = s.label + (s.n ? ' · ' + s.detail : ' · no data');
    const pick = onPick && s.n;
    const b = pick
      ? h('button', { type: 'button', class: state, 'aria-label': text, onclick: () => { hideTip(); onPick(s); } })
      : h('i', { class: state, role: 'img', 'aria-label': text });
    b.addEventListener('pointermove', e => showTip(e.clientX, e.clientY, text));
    b.addEventListener('pointerleave', hideTip);
    b.addEventListener('focus', () => { const r = b.getBoundingClientRect(); showTip(r.left + r.width / 2, r.top, text); });
    b.addEventListener('blur', hideTip);
    el.append(b);
  }
  return el;
}

// --- latency chart ---

const SVG = 'http://www.w3.org/2000/svg';
const W = 1000, H = 180;
const s = (tag, attrs) => {
  const el = document.createElementNS(SVG, tag);
  for (const k in attrs) el.setAttribute(k, attrs[k]);
  return el;
};

// niceMax rounds a latency up to a readable axis bound.
function niceMax(v) {
  if (v <= 0) return 100;
  const p = 10 ** Math.floor(Math.log10(v));
  return [1, 2, 2.5, 5, 10].map(m => m * p).find(m => m >= v * 1.1) ?? 10 * p;
}

// latencyChart plots points [{t, ms, up}] across [from, to). Missing data
// (a gap well beyond both the usual spacing and minGap seconds) breaks the
// line; failed checks are marked along the baseline.
export function latencyChart(points, from, to, minGap) {
  if (!points.length) return h('div', { class: 'empty' }, 'No checks in this range yet.');
  const ok = points.filter(p => p.up);
  const steps = ok.slice(1).map((p, i) => p.t - ok[i].t).sort((a, b) => a - b);
  const gap = Math.max(minGap, 3 * (steps[steps.length >> 1] || 0));
  const sorted = ok.map(p => p.ms).sort((a, b) => a - b);
  // Scale to the 99th percentile so one slow outlier doesn't flatten the line.
  const top = niceMax(sorted[Math.floor((sorted.length - 1) * 0.99)] || 0);
  const x = t => (t - from) / (to - from) * W;
  const y = ms => H - Math.min(ms, top) / top * (H - 8);

  const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none' });
  const defs = s('defs', {});
  const grad = s('linearGradient', { id: 'fade', x1: 0, y1: 0, x2: 0, y2: 1 });
  grad.append(s('stop', { offset: 0, 'stop-color': '#2b8cff', 'stop-opacity': .28 }),
    s('stop', { offset: 1, 'stop-color': '#2b8cff', 'stop-opacity': 0 }));
  defs.append(grad);
  svg.append(defs);
  const g = s('g', { class: 'grid' });
  for (const f of [0.25, 0.5, 0.75]) g.append(s('line', { x1: 0, x2: W, y1: y(top * f), y2: y(top * f) }));
  svg.append(g);

  let line = '', area = '', seg = null, prev = null;
  const close = () => { if (seg) area += `L${seg.x1},${H}L${seg.x0},${H}Z`; };
  for (const p of ok) {
    const px = x(p.t).toFixed(1), py = y(p.ms).toFixed(1);
    if (!prev || p.t - prev.t > gap) {
      close();
      line += `M${px},${py}`;
      area += `M${px},${H}L${px},${py}`;
      seg = { x0: px };
    } else {
      line += `L${px},${py}`;
      area += `L${px},${py}`;
    }
    seg.x1 = px;
    prev = p;
  }
  close();
  svg.append(s('path', { class: 'area', d: area }), s('path', { class: 'line', d: line }));
  for (const p of points) if (!p.up) svg.append(s('rect', { class: 'fail', x: x(p.t) - 1.5, y: H - 10, width: 3, height: 10 }));
  const cross = s('line', { class: 'cross hidden', y1: 0, y2: H });
  svg.append(cross);

  const wrap = h('div', {
    class: 'chart', role: 'img',
    'aria-label': `Response time: ${points.length} checks, ${points.length - ok.length} failed` +
      (ok.length ? `, ${fmt.ms(sorted[0])} to ${fmt.ms(sorted.at(-1))}` : ''),
  });
  wrap.append(svg, h('div', { class: 'yaxis' }, fmt.ms(top)));
  // Nearest point by binary search on time.
  wrap.addEventListener('pointermove', e => {
    const r = wrap.getBoundingClientRect();
    const t = from + (e.clientX - r.left) / r.width * (to - from);
    let lo = 0, hi = points.length - 1;
    while (lo < hi) { const mid = (lo + hi) >> 1; points[mid].t < t ? lo = mid + 1 : hi = mid; }
    if (lo > 0 && t - points[lo - 1].t < points[lo].t - t) lo--;
    const p = points[lo];
    cross.setAttribute('x1', x(p.t)); cross.setAttribute('x2', x(p.t));
    cross.classList.remove('hidden');
    showTip(e.clientX, e.clientY, `${p.label} · ${p.up ? fmt.ms(p.ms) : p.text}`);
  });
  wrap.addEventListener('pointerleave', () => { cross.classList.add('hidden'); hideTip(); });
  return wrap;
}

// poll runs fn every ms while the page is visible, and at once when it becomes
// visible again. It returns a stop function.
export function poll(fn, ms) {
  let timer;
  const tick = () => { clearTimeout(timer); if (!document.hidden) fn(); timer = setTimeout(tick, ms); };
  const vis = () => { if (!document.hidden) tick(); };
  document.addEventListener('visibilitychange', vis);
  timer = setTimeout(tick, ms);
  return () => { clearTimeout(timer); document.removeEventListener('visibilitychange', vis); };
}

export function registerSW() {
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {});
}
