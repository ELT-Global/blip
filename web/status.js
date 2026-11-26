// Public status page: the monitor list at / and monitor detail at /m/{id}.
import { h, $, fill, api, tz, fmt, codeText, isUp, bars, hideTip, latencyChart, localDays, dayHours, dayKey, poll, toast, registerSW } from './lib.js';

const app = $('#app');
let me = null;
let view = null; // {abort, stop} for the active route

registerSW();

document.addEventListener('click', e => {
  const a = e.target.closest('a[data-link]');
  if (!a || e.metaKey || e.ctrlKey || e.shiftKey || e.button) return;
  e.preventDefault();
  if (a.getAttribute('href') !== location.pathname) history.pushState(null, '', a.href);
  route();
  scrollTo(0, 0); // only on push: back/forward keeps the browser's scroll restoration
});
addEventListener('popstate', route);

api('/me').then(u => {
  me = u;
  if (u) $('#account').textContent = 'Panel';
}).catch(() => {}).finally(route);

function route() {
  view?.abort.abort();
  view?.stop?.();
  hideTip();
  const v = view = { abort: new AbortController() };
  const m = location.pathname.match(/^\/m\/(\d+)$/);
  (m ? detail(+m[1], v) : home(v)).catch(err => failed(v, err));
}

// failed handles a view's load error. Network failures keep the view polling
// so it recovers; an HTTP error (say, the monitor was deleted) ends it.
function failed(v, err) {
  if (err.name === 'AbortError') return;
  if (err.offline) return offline();
  if (!err.status) { console.error(err); return toast(err.message, true); } // a bug, not the network
  v.stop?.();
  if (v === view) fill(app, h('div', { class: 'card empty' }, err.status === 404 ? 'Monitor not found.' : err.message));
}

const offline = () => toast('Offline, retrying…', true);

// daySlots maps sparse day buckets onto the last n local days.
function daySlots(buckets, n) {
  const by = new Map(buckets.map(b => [dayKey(b.t), b]));
  return localDays(n).map(t => {
    const b = by.get(dayKey(t)) || { n: 0, up: 0 };
    return { t, n: b.n, up: b.up, label: fmt.date(t), detail: summary(b) };
  });
}

const summary = b => `${fmt.pct(b.up, b.n)} up · ${b.n} checks` + (b.ms ? ` · avg ${fmt.ms(b.ms)}` : '');
const sum = (bs, k) => bs.reduce((a, b) => a + b[k], 0);

function statusDot(m) {
  if (!m.last) return h('span', { class: 'dot', title: 'Pending' });
  return h('span', { class: 'dot ' + (isUp(m.last.code) ? 'up' : 'down'), title: isUp(m.last.code) ? 'Up' : 'Down' });
}

// --- list ---

async function home(v) {
  const load = async () => renderHome(await api('/monitors?days=30&tz=' + tz(), { signal: v.abort.signal }));
  // Poll even if the first load fails, so the page recovers after being offline.
  v.stop = poll(() => load().catch(err => failed(v, err)), 30_000);
  await load();
}

function renderHome(list) {
  document.title = 'blip · status';
  hideTip();
  const down = list.filter(m => m.last && !isUp(m.last.code));
  const head = h('div', { class: 'card summary' },
    h('span', { class: 'dot ' + (down.length ? 'down' : list.length ? 'up' : '') }),
    h('div', {},
      h('h1', {}, !list.length ? 'No monitors yet' : down.length ? `${down.length} of ${list.length} down` : 'All systems operational'),
      h('div', { class: 'muted' }, down.length ? down.map(m => m.name).join(', ') : 'Updated ' + fmt.time(Date.now() / 1000))));

  const cards = list.map(m => h('a', { class: 'card mon', href: '/m/' + m.id, 'data-link': true },
    h('div', { class: 'mon-head' },
      statusDot(m),
      h('h2', {}, m.name),
      !m.public && h('span', { class: 'pill private' }, 'private'),
      h('span', { class: 'muted' }, m.last && isUp(m.last.code) ? fmt.ms(m.last.ms) : m.last ? codeText(m.last.code) : 'pending'),
      h('span', { class: 'pill', title: '30-day uptime' }, fmt.pct(sum(m.days, 'up'), sum(m.days, 'n')))),
    bars(daySlots(m.days, 30), { label: m.name + ', last 30 days' }),
    h('div', { class: 'bars-legend' }, h('span', {}, '30 days ago'), h('span', {}, 'Today'))));
  fill(app, head, h('div', { class: 'stack' }, cards));
}

// --- detail ---

async function detail(id, v) {
  const signal = v.abort.signal;
  // at is the current zoom: level 'days', 'hours' (of day) or 'checks' (of hour).
  const st = { at: { level: 'days' }, m: null, seq: 0, shown: 0, drafts: new Map() };
  const els = { head: h('div'), uptime: h('div', { class: 'card' }), latency: h('div', { class: 'card' }), incidents: h('div', { class: 'card' }) };
  fill(app, h('a', { href: '/', 'data-link': true, class: 'muted' }, '← All monitors'),
    els.head, els.uptime, els.latency, els.incidents);

  // A failed zoom is shown as a toast; losing the monitor (404) ends the view.
  const fail = err => err.status && err.status !== 404 ? toast(err.message, true) : failed(v, err);
  const zoom = at => show(at).catch(fail);

  // show loads and renders a zoom level. Only the newest request may render,
  // and the zoom only changes once its data has arrived.
  async function show(at) {
    const seq = ++st.seq;
    try {
      await render(at, seq);
    } catch (err) {
      if (seq === st.seq) st.shown = seq; // a failed zoom leaves nothing pending
      throw err;
    }
  }

  async function render(at, seq) {
    let slots, from, to, points;
    if (at.level === 'days') {
      to = Date.now() / 1000; from = to - 86400;
      points = await checkPoints(id, from, to, signal);
      slots = daySlots(st.m.days, 90).map(s => ({ ...s, pick: () => zoom({ level: 'hours', day: s.t }) }));
    } else if (at.level === 'hours') {
      const hrs = dayHours(at.day);
      from = hrs[0]; to = hrs.at(-1) + 3600;
      const [buckets, pts] = await Promise.all([api(`/monitors/${id}/hours?from=${from}&to=${to}`, { signal }), checkPoints(id, from, to, signal)]);
      const by = new Map(buckets.map(b => [b.t, b]));
      slots = hrs.map(t => {
        const b = by.get(t) || { n: 0, up: 0 };
        return { t, n: b.n, up: b.up, label: fmt.time(t), detail: summary(b), pick: () => zoom({ ...at, level: 'checks', hour: t }) };
      });
      // Raw checks may have been quantized away; chart the hourly means instead.
      points = pts.length ? pts : buckets.filter(b => b.up).map(b => ({ t: b.t + 1800, ms: b.ms, up: true, label: fmt.time(b.t) + ' (hourly mean)' }));
    } else {
      from = at.hour; to = from + 3600;
      points = await checkPoints(id, from, to, signal);
      slots = points.map(p => ({ t: p.t, n: 1, up: p.up ? 1 : 0, label: p.label, detail: p.up ? fmt.ms(p.ms) : p.text }));
    }
    if (seq !== st.seq) return;
    st.at = at;
    st.shown = seq;
    renderUptime(slots);
    renderLatency(points, from, to);
  }

  function renderHead() {
    const m = st.m;
    document.title = m.name + ' · blip';
    const up = m.last && isUp(m.last.code);
    const week = m.days.filter(d => d.t >= Date.now() / 1000 - 7 * 86400);
    fill(els.head,
      h('div', { class: 'detail-head' },
        statusDot(m),
        h('h1', {}, m.name),
        h('span', { class: 'pill' + (m.public ? '' : ' private') }, m.public ? 'public' : 'private')),
      m.url && h('p', { class: 'muted mono' }, m.method + ' ' + m.url),
      h('div', { class: 'facts' },
        fact(m.last ? (up ? 'Up' : codeText(m.last.code)) : 'Pending', 'Status'),
        fact(m.last ? fmt.ms(m.last.ms) : '—', 'Response'),
        fact(fmt.pct(sum(week, 'up'), sum(week, 'n')), 'Uptime 7d'),
        fact(fmt.pct(sum(m.days, 'up'), sum(m.days, 'n')), 'Uptime 90d'),
        fact('every ' + fmt.interval(m.interval), 'Checked')));
  }

  function renderUptime(slots) {
    const { level, day, hour } = st.at;
    hideTip();
    const days = h('span', {}, h('span', { class: 'wide' }, '90 days'), h('span', { class: 'narrow' }, '30 days'));
    const crumbs = [h('button', { onclick: () => zoom({ level: 'days' }) }, days)];
    if (level !== 'days') crumbs.push(h('span', { class: 'sep' }, '›'), h('button', { onclick: () => zoom({ level: 'hours', day }) }, fmt.date(day)));
    if (level === 'checks') crumbs.push(h('span', { class: 'sep' }, '›'), h('button', { disabled: true }, fmt.time(hour)));
    const hint = { days: 'Select a day to see its hours', hours: 'Select an hour to see each check', checks: 'Every check in this hour' }[level];
    const legend = level === 'days'
      ? [h('span', {}, h('span', { class: 'wide' }, '90 days ago'), h('span', { class: 'narrow' }, '30 days ago')), h('span', {}, 'Today')]
      : [h('span', {}, fmt.time(slots[0].t)), h('span', {}, fmt.time(slots.at(-1).t + 3600))];
    fill(els.uptime,
      h('div', { class: 'section-head' }, h('h2', {}, 'Uptime'), h('span', { class: 'muted' }, hint)),
      h('div', { class: 'crumbs' }, crumbs),
      level === 'checks' && !slots.length
        ? h('div', { class: 'empty' }, 'No raw checks for this hour; older checks are kept only as hourly rollups.')
        : bars(slots, {
          cls: { days: 'days90', hours: '', checks: 'checks' }[level],
          label: hint,
          onPick: level === 'checks' ? null : s => s.pick(),
        }),
      level !== 'checks' && h('div', { class: 'bars-legend' }, legend));
  }

  function renderLatency(points, from, to) {
    const { level, day, hour } = st.at;
    const edge = t => to - from > 6 * 3600 ? fmt.date(t) + ' ' + fmt.time(t) : fmt.time(t);
    const title = { days: 'last 24 hours', hours: fmt.date(day), checks: fmt.date(hour) + ', ' + fmt.time(hour) }[level];
    const ok = points.filter(p => p.up).map(p => p.ms);
    const stats = ok.length ? ` · avg ${fmt.ms(ok.reduce((a, b) => a + b, 0) / ok.length)} · max ${fmt.ms(ok.reduce((a, b) => Math.max(a, b)))}` : '';
    fill(els.latency,
      h('div', { class: 'section-head' }, h('h2', {}, 'Response time'), h('span', { class: 'muted' }, title + stats)),
      latencyChart(points, from, to, st.m.interval * 2.5),
      points.length > 0 && h('div', { class: 'axis' }, h('span', {}, edge(from)), h('span', {}, edge(to))));
  }

  let lastIncidents = '';
  async function loadIncidents() {
    const list = await api(`/monitors/${id}/incidents`, { signal });
    const key = JSON.stringify(list);
    // Polling must not wipe a note being typed, so only redraw on change.
    if (key !== lastIncidents) { lastIncidents = key; renderIncidents(list); }
  }

  function renderIncidents(list) {
    const canWrite = me && me.role !== 'read';
    fill(els.incidents,
      h('div', { class: 'section-head' }, h('h2', {}, 'Incidents'), h('span', { class: 'muted' }, list.length ? list.length + ' recent' : '')),
      list.length ? list.map(inc => incident(inc, canWrite)) : h('div', { class: 'empty' }, 'No incidents recorded.'));
  }

  function incident(inc, canWrite) {
    const end = inc.ended ?? Date.now() / 1000;
    const notes = h('div', {}, inc.notes.map(note));
    let form = null;
    if (canWrite) {
      const ta = h('textarea', {
        placeholder: 'Add a note…', rows: 1, 'aria-label': 'Note', value: st.drafts.get(inc.id) || '',
        oninput: e => st.drafts.set(inc.id, e.target.value),
      });
      const btn = h('button', { type: 'submit' }, 'Add note');
      form = h('form', {
        class: 'note-form', onsubmit: async e => {
          e.preventDefault();
          if (!ta.value.trim()) return;
          btn.disabled = true;
          try {
            notes.append(note(await api(`/incidents/${inc.id}/notes`, { method: 'POST', body: { body: ta.value } })));
            st.drafts.delete(inc.id);
            ta.value = '';
            lastIncidents = ''; // the next poll redraws with the saved note
          } catch (err) { if (err.name !== 'AbortError') toast(err.message, true); } // e.g. the incident was trimmed
          btn.disabled = false;
        },
      }, ta, btn);
    }
    return h('div', { class: 'incident' + (inc.ended ? ' resolved' : '') },
      h('div', { class: 'incident-head' },
        h('h3', {}, inc.ended ? 'Resolved' : 'Ongoing', ' · ', inc.cause || codeText(inc.code)),
        h('span', { class: 'muted' }, fmt.dateTime(inc.start) + ' · ' + fmt.duration(end - inc.start))),
      notes, form);
  }

  // Authors are only sent to signed-in viewers.
  const note = n => h('div', { class: 'note' }, h('p', {}, n.body), h('small', {}, (n.author ? n.author + ' · ' : '') + fmt.dateTime(n.t)));

  async function refresh() {
    st.m = await api(`/monitors/${id}?days=90&tz=${tz()}`, { signal });
    renderHead();
    const tasks = [loadIncidents()];
    // Refresh the overview unless a zoom is in flight; deeper zooms show settled history.
    if (st.at.level === 'days' && st.shown === st.seq) tasks.push(show(st.at));
    await Promise.all(tasks);
  }

  v.stop = poll(() => refresh().catch(fail), 30_000);
  await refresh();
}

function fact(value, label) {
  return h('div', {}, h('b', {}, value), h('span', {}, label));
}

// checkPoints loads raw checks and shapes them for the chart and blocks.
async function checkPoints(id, from, to, signal) {
  const cs = await api(`/monitors/${id}/checks?from=${Math.floor(from)}&to=${Math.ceil(to)}`, { signal });
  return cs.map(c => ({ t: c.t, ms: c.ms, up: isUp(c.code), text: codeText(c.code), label: fmt.date(c.t) + ' ' + fmt.timeSec(c.t) }));
}
