const CACHE = 'gatecrash-v4';
// Only static, auth-independent assets are cached.  NOT '/', whose HTML is
// rendered server-side with the login state baked in — a cached copy of the
// shell will bounce a logged-in user back to the login screen after any
// transient navigation-fetch failure (Safari cancels these aggressively).
const PRECACHE = ['/static/manifest.json', '/static/icon-192.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(PRECACHE)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // Only ever touch static assets.  Navigations (the '/' shell) and API calls
  // MUST always hit the network so the server decides login state — never let
  // the SW serve a cached, auth-stale page.  Everything outside /static/ (and
  // any navigation request) falls through to the browser's own handling.
  if (e.request.mode === 'navigate' || !url.pathname.startsWith('/static/')) {
    return;
  }

  // Static assets: cache-first (they're versioned by CACHE name), fall back to
  // the network and populate the cache on a miss.
  e.respondWith(
    caches.match(e.request).then((cached) =>
      cached ||
      fetch(e.request).then((r) => {
        if (r.ok) {
          const clone = r.clone();
          caches.open(CACHE).then((c) => c.put(e.request, clone));
        }
        return r;
      })
    )
  );
});
