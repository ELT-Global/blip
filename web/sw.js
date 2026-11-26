// Service worker: every same-origin, non-API GET it handles is network-first,
// so a deploy shows up on the next load. When the network is slow (3s) or
// gone, the cached copy is served instead, which can briefly mix versions.
// API calls are never cached.
const CACHE = 'blip-v4';
const SHELL = ['/', '/panel', '/app.css', '/lib.js', '/status.js', '/panel.js', '/icon.svg', '/icon-192.png', '/icon-512.png', '/manifest.webmanifest'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys()
    .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});

// cacheKey maps a request to its cache entry: the app's routes share two
// documents, and other page loads (raw files opened in a tab) aren't cached.
function cacheKey(req, url) {
  if (req.mode !== 'navigate') return req;
  if (url.pathname === '/' || url.pathname.startsWith('/m/')) return '/';
  if (url.pathname === '/panel' || url.pathname.startsWith('/panel/')) return '/panel';
  return null;
}

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin || url.pathname.startsWith('/api/')) return;
  const key = cacheKey(e.request, url);
  if (!key) return;

  const net = fetch(e.request).then(res => {
    if (res.ok) {
      const copy = res.clone();
      caches.open(CACHE).then(c => c.put(key, copy));
    }
    return res;
  });
  const cached = () => caches.match(key);
  const slow = new Promise(r => setTimeout(r, 3000)).then(cached);
  e.respondWith(Promise.race([net, slow])
    .then(res => res || net)
    .catch(() => cached().then(r => r || Response.error())));
});
