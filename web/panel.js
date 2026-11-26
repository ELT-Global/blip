// Admin panel at /panel: sign-in, enrollment, and the Monitors, Users and
// Settings sections.
import { h, $, fill, api, fmt, codeText, isUp, poll, toast, registerSW } from './lib.js';

const app = $('#app');
const rank = { read: 1, write: 2, root: 3 };
let me; // the signed-in user; null when signed out, undefined when unknown
let view = null;

registerSW();

document.addEventListener('click', e => {
  const a = e.target.closest('a[data-link]');
  if (!a || e.metaKey || e.ctrlKey || e.shiftKey || e.button) return;
  e.preventDefault();
  if (a.pathname !== location.pathname) history.pushState(null, '', a.href);
  route();
});
addEventListener('popstate', route);
addEventListener('hashchange', route); // a new invite link pasted into the enroll page
addEventListener('blip:signedout', () => { if (me) { me = null; route(); } });

// Notice an expired session or a changed role even while a page sits idle.
poll(async () => {
  if (!me) return;
  const u = await api('/me').catch(() => me);
  if (!u || u.role !== me.role) { me = u; route(); }
}, 30_000);

const go = path => { history.replaceState(null, '', path); route(); };
const can = role => me && rank[me.role] >= rank[role];
const fail = x => { if (x.name !== 'AbortError') toast(x.message, true); };

async function route() {
  view?.stop?.();
  view?.abort.abort();
  view = { abort: new AbortController() };
  const path = location.pathname.replace(/\/+$/, '');
  if (path === '/panel/enroll') return enroll(location.hash.slice(1));
  if (me === undefined) {
    try { me = await api('/me'); } catch (x) {
      return authCard(h('h2', {}, 'Can’t reach blip'), h('p', { class: 'muted' }, x.message),
        h('button', { class: 'primary', onclick: route }, 'Retry'));
    }
  }
  if (!me) return login();
  const section = path.split('/')[2] || 'monitors';
  if (!Object.hasOwn(sections, section) || (sections[section].role && !can(sections[section].role))) return go('/panel/monitors');
  shell(section);
  sections[section].render(view).catch(x => {
    if (x.name !== 'AbortError' && x.status !== 401) $('.content').append(h('div', { class: 'err', role: 'alert' }, x.message));
  });
}

// --- auth ---

function authCard(...kids) {
  fill(app, h('div', { class: 'auth' },
    h('a', { class: 'brand', href: '/' }, h('img', { src: '/icon.svg', alt: '' }), 'blip'),
    h('div', { class: 'card' }, kids)));
}

const codeInput = () => h('input', {
  class: 'code-input', name: 'code', inputMode: 'numeric', autocomplete: 'one-time-code',
  pattern: '[0-9]{6}', maxLength: 6, required: true, placeholder: '000000',
});

const errBox = () => h('div', { class: 'err', role: 'alert' });

// submitter wires a form to an async action, showing errors inline.
function submitter(form, err, action) {
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const btn = form.querySelector('button[type=submit]');
    btn.disabled = true;
    err.textContent = '';
    try { await action(new FormData(form)); } catch (x) { err.textContent = x.message; }
    btn.disabled = false;
  });
}

function login() {
  document.title = 'Sign in · blip';
  const err = errBox();
  const form = h('form', {},
    h('h2', {}, 'Sign in'),
    h('label', {}, 'Email', h('input', { name: 'email', type: 'email', autocomplete: 'username', required: true, autofocus: true })),
    h('label', {}, 'Authenticator code', codeInput()),
    err,
    h('button', { class: 'primary', type: 'submit' }, 'Sign in'));
  submitter(form, err, async fd => {
    me = await api('/login', { method: 'POST', body: { email: fd.get('email'), code: fd.get('code') } });
    route();
  });
  authCard(form);
}

async function enroll(token) {
  document.title = 'Set up your account · blip';
  let info;
  try { info = await api('/enroll/info', { method: 'POST', body: { token } }); } catch (x) {
    return authCard(h('h2', {}, 'Invite unavailable'), h('p', { class: 'muted' }, x.message + '. Ask an admin for a new invite.'));
  }
  const err = errBox();
  const form = h('form', {},
    h('h2', {}, 'Set up ' + info.email),
    h('p', { class: 'muted' }, 'Scan this code with an authenticator app, then enter the 6-digit code it shows.'),
    info.qr && h('img', { class: 'qr', src: 'data:image/svg+xml,' + encodeURIComponent(info.qr), alt: 'QR code for your authenticator app' }),
    h('label', {}, 'Or enter this key manually', h('input', { readOnly: true, class: 'mono', value: info.secret, onfocus: e => e.target.select() })),
    h('label', {}, 'Code', codeInput()),
    err,
    h('button', { class: 'primary', type: 'submit' }, 'Activate account'));
  submitter(form, err, async fd => {
    me = await api('/enroll', { method: 'POST', body: { token, code: fd.get('code') } });
    go('/panel/monitors'); // replace, so the spent invite leaves history
  });
  authCard(form);
}

// --- layout ---

function shell(active) {
  const nav = Object.entries(sections).filter(([, s]) => !s.role || can(s.role)).map(([k, s]) =>
    h('a', { class: 'nav' + (k === active ? ' on' : ''), href: '/panel/' + k, 'data-link': true, 'aria-current': k === active && 'page' }, s.title));
  const logout = async () => { await api('/logout', { method: 'POST' }).catch(() => {}); me = null; route(); };
  document.title = sections[active].title + ' · blip';
  fill(app, h('div', { class: 'panel' },
    h('nav', { class: 'side' },
      h('a', { class: 'brand', href: '/' }, h('img', { src: '/icon.svg', alt: '' }), 'blip'),
      nav,
      h('a', { class: 'nav', href: '/' }, 'Status page ↗'),
      h('div', { class: 'foot' },
        h('div', { class: 'who' }, me.email, h('br'), h('span', { class: 'pill' }, me.role)),
        h('div', { class: 'row' }, h('button', { class: 'link', onclick: logout }, 'Sign out')))),
    h('main', { class: 'content' })));
}

const content = () => $('.content');

// --- monitors ---

const intervals = [10, 30, 60, 120, 300, 600, 900, 1800, 3600, 21600, 43200, 86400];

function monitorDialog(m, onSaved) {
  const err = errBox();
  const opts = !m || intervals.includes(m.interval) ? intervals : [...intervals, m.interval].sort((a, b) => a - b);
  const form = h('form', {},
    h('h2', {}, m ? 'Edit monitor' : 'New monitor'),
    h('label', {}, 'Name', h('input', { name: 'name', required: true, maxLength: 100, value: m?.name || '', placeholder: 'API' })),
    h('div', { class: 'grid' },
      h('label', {}, 'Method', h('select', { name: 'method' },
        ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].map(x => h('option', { selected: (m?.method || 'GET') === x }, x)))),
      h('label', {}, 'Frequency', h('select', { name: 'interval' },
        opts.map(s => h('option', { value: s, selected: (m?.interval || 60) === s }, 'every ' + fmt.interval(s))))),
      h('label', {}, 'Visibility', h('select', { name: 'public' },
        h('option', { value: '1', selected: m?.public ?? true }, 'Public'),
        h('option', { value: '0', selected: m && !m.public }, 'Private')))),
    h('label', {}, 'URL', h('input', { name: 'url', type: 'url', required: true, value: m?.url || '', placeholder: 'https://example.com/health' })),
    err,
    h('div', { class: 'row' },
      h('button', { type: 'button', onclick: () => dlg.close() }, 'Cancel'),
      h('button', { class: 'primary', type: 'submit' }, m ? 'Save' : 'Create')));
  const dlg = h('dialog', { 'aria-label': m ? 'Edit monitor' : 'New monitor' }, form);
  submitter(form, err, async fd => {
    const body = { name: fd.get('name'), method: fd.get('method'), url: fd.get('url'), interval: +fd.get('interval'), public: fd.get('public') === '1' };
    await api(m ? '/monitors/' + m.id : '/monitors', { method: m ? 'PUT' : 'POST', body });
    dlg.close();
    toast(m ? 'Monitor saved' : 'Monitor created');
    onSaved();
  });
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
}

async function monitors(v) {
  const box = h('div', { class: 'card table-wrap' });
  const reload = () => load(true).catch(fail);
  content().append(
    h('div', { class: 'section-head' }, h('h1', {}, 'Monitors'),
      can('write') && h('button', { class: 'primary', onclick: () => monitorDialog(null, reload) }, '+ New monitor')),
    box);

  let last = '';
  async function load(force) {
    const list = await api('/monitors?days=1', { signal: v.abort.signal });
    // Redraw only on change, so an idle poll doesn't steal keyboard focus.
    const key = JSON.stringify(list);
    if (key === last && !force) return;
    last = key;
    if (!list.length) {
      return fill(box, h('div', { class: 'empty' }, can('write') ? 'No monitors yet. Create one to start checking.' : 'No monitors yet.'));
    }
    fill(box, h('table', {},
      h('thead', {}, h('tr', {}, ['Status', 'Name', 'Target', 'Every', 'Visibility', 'Last check', ''].map(t => h('th', {}, t)))),
      h('tbody', {}, list.map(m => h('tr', {},
        h('td', {}, h('span', { class: 'dot' + (m.last ? isUp(m.last.code) ? ' up' : ' down' : ''), title: m.last ? isUp(m.last.code) ? 'Up' : 'Down' : 'Pending' })),
        h('td', {}, h('a', { href: '/m/' + m.id }, m.name)),
        h('td', { class: 'url mono', title: m.url }, m.method + ' ' + m.url),
        h('td', {}, fmt.interval(m.interval)),
        h('td', {}, h('span', { class: 'pill' + (m.public ? '' : ' private') }, m.public ? 'public' : 'private')),
        h('td', { class: 'muted' }, m.last ? `${isUp(m.last.code) ? fmt.ms(m.last.ms) : codeText(m.last.code)} · ${fmt.ago(m.last.t)}` : 'pending'),
        h('td', { class: 'actions' }, can('write') && [
          h('button', { onclick: () => monitorDialog(m, reload) }, 'Edit'),
          h('button', {
            class: 'danger', onclick: async () => {
              if (!confirm(`Delete "${m.name}" and all of its history?`)) return;
              await api('/monitors/' + m.id, { method: 'DELETE' }).then(() => toast('Monitor deleted'), fail);
              reload();
            },
          }, 'Delete')]))))));
  }
  v.stop = poll(() => load().catch(fail), 15_000);
  await load();
}

// --- users ---

// copy copies text, falling back to selecting it where the clipboard API is
// unavailable (it needs HTTPS).
function copy(text, input) {
  if (!navigator.clipboard) { input.focus(); input.select(); return toast('Press Ctrl+C (⌘C) to copy'); }
  navigator.clipboard.writeText(text).then(() => toast('Link copied'), () => { input.select(); toast('Copy blocked; the link is selected'); });
}

async function users(v) {
  const err = errBox();
  const invite = h('div', { 'aria-live': 'polite' });
  const form = h('form', { class: 'grid' },
    h('label', {}, 'Email', h('input', { name: 'email', type: 'email', required: true, placeholder: 'someone@example.com' })),
    h('label', {}, 'Permission', h('select', { name: 'role' }, ['read', 'write', 'root'].map(r => h('option', { value: r }, r[0].toUpperCase() + r.slice(1))))),
    h('button', { class: 'primary', type: 'submit' }, 'Invite user'));
  const box = h('div', { class: 'card table-wrap' });
  content().append(h('h1', {}, 'Users'),
    h('div', { class: 'card' }, h('h2', {}, 'Add user'),
      h('p', { class: 'muted' }, 'Read can see private monitors. Write can also manage monitors and add incident notes. Root can also manage users and the database.'),
      form, err, invite),
    box);
  const reload = () => load().catch(fail);

  submitter(form, err, async fd => {
    const u = await api('/users', { method: 'POST', body: { email: fd.get('email'), role: fd.get('role') } });
    form.reset();
    const link = location.origin + u.invite;
    const input = h('input', { readOnly: true, class: 'mono', value: link, 'aria-label': 'Setup link', onfocus: e => e.target.select() });
    fill(invite,
      h('p', {}, `Send this one-time setup link to ${u.email}. It expires in 7 days.`),
      h('div', { class: 'invite' }, input, h('button', { type: 'button', onclick: () => copy(link, input) }, 'Copy')));
    reload();
  });

  // After changing your own access, re-read who you are and re-route.
  const self = () => { me = undefined; route(); };

  async function load() {
    const list = await api('/users', { signal: v.abort.signal });
    fill(box, h('table', {},
      h('thead', {}, h('tr', {}, ['Email', 'Permission', 'Status', 'Added', ''].map(t => h('th', {}, t)))),
      h('tbody', {}, list.map(u => h('tr', {},
        h('td', {}, u.email, u.id === me.id && h('span', { class: 'muted' }, ' (you)')),
        h('td', {}, h('select', {
          'aria-label': 'Permission for ' + u.email,
          onchange: async e => {
            try {
              await api('/users/' + u.id, { method: 'PUT', body: { role: e.target.value } });
              toast('Permission updated');
              if (u.id === me.id) return self();
            } catch (x) { fail(x); }
            reload();
          },
        }, ['read', 'write', 'root'].map(r => h('option', { value: r, selected: u.role === r }, r)))),
        h('td', {}, u.pending ? h('span', { class: 'pill private' }, 'invited') : h('span', { class: 'pill' }, 'active')),
        h('td', { class: 'muted' }, fmt.date(u.created)),
        h('td', { class: 'actions' }, h('button', {
          class: 'danger', onclick: async () => {
            if (!confirm(`Remove ${u.email}?`)) return;
            try {
              await api('/users/' + u.id, { method: 'DELETE' });
              toast('User removed');
              if (u.id === me.id) return self();
            } catch (x) { fail(x); }
            reload();
          },
        }, 'Remove')))))));
  }
  await load();
}

// --- settings ---

async function settings(v) {
  const stats = h('div');
  const err = errBox();
  const form = h('form', { class: 'grid' },
    h('label', {}, 'Keep raw checks (days)', h('input', { name: 'raw_days', type: 'number', min: 0, max: 36500, required: true })),
    h('label', {}, 'Keep hourly rollups (days)', h('input', { name: 'hour_days', type: 'number', min: 0, max: 36500, required: true })),
    h('button', { class: 'primary', type: 'submit' }, 'Save retention'));
  const save = () => api('/db/retention', { method: 'PUT', body: { raw_days: +form.raw_days.value, hour_days: +form.hour_days.value } });
  const busy = async (btn, fn) => { btn.disabled = true; try { await fn(); } catch (x) { fail(x); } btn.disabled = false; };
  const trim = h('button', {
    onclick: () => busy(trim, async () => {
      if (!form.reportValidity()) return;
      await save(); // trim what the form shows, saved or not
      const r = await api('/db/trim', { method: 'POST' });
      toast(`Removed ${r.checks} checks, ${r.hours} hourly rollups, ${r.incidents} incidents`);
      await load();
    }),
  }, 'Trim now');
  const vacuum = h('button', {
    onclick: () => busy(vacuum, async () => {
      await api('/db/vacuum', { method: 'POST' });
      toast('Database compacted');
      await load();
    }),
  }, 'Vacuum');

  content().append(h('h1', {}, 'Settings'),
    h('div', { class: 'card' }, h('h2', {}, 'Database'), h('p', { class: 'muted' }, 'blip stores everything in one SQLite file.'), stats),
    h('div', { class: 'card' },
      h('h2', {}, 'Retention'),
      h('p', { class: 'muted' }, 'Every check is rolled up into hourly totals as it is recorded. Raw checks older than the first limit are deleted, quantizing that history to hourly resolution; rollups and resolved incidents older than the second limit are deleted too. 0 keeps data forever. Trimming runs hourly; Trim now saves these limits and applies them immediately, and Vacuum then rebuilds the file at its smallest size.'),
      form, err,
      h('div', { class: 'row' }, trim, vacuum)));

  submitter(form, err, async () => { await save(); toast('Retention saved'); });

  async function load() {
    const s = await api('/db', { signal: v.abort.signal });
    form.raw_days.value = s.retention.raw_days;
    form.hour_days.value = s.retention.hour_days;
    const stat = (value, label) => h('div', {}, h('b', {}, value), h('span', {}, label));
    fill(stats,
      h('p', { class: 'mono muted' }, s.path),
      h('div', { class: 'stat-list' },
        stat(fmt.bytes(s.file + s.wal), 'Total on disk'),
        stat(fmt.bytes(s.file), 'Database file'),
        stat(fmt.bytes(s.wal), 'Write-ahead log'),
        stat(fmt.bytes(s.free), 'Free pages (reusable)'),
        stat(s.oldest ? fmt.date(s.oldest) : '—', 'Oldest raw check')),
      h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, ['Table', 'Rows', 'Size'].map(t => h('th', {}, t)))),
        h('tbody', {}, s.tables.map(t => h('tr', {},
          h('td', { class: 'mono' }, t.name), h('td', {}, t.rows.toLocaleString()), h('td', {}, fmt.bytes(t.bytes))))))));
  }
  await load();
}

const sections = {
  monitors: { title: 'Monitors', render: monitors },
  users: { title: 'Users', role: 'root', render: users },
  settings: { title: 'Settings', role: 'root', render: settings },
};

route();
