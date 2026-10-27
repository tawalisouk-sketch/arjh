/* Pointage DRONEGROUPE — service worker
 * Pages et fichiers : réseau d'abord, copie locale en secours si internet coupe.
 * Les données (/api/...) ne sont JAMAIS mises en cache : toujours lues en direct sur le serveur.
 */
const CACHE = 'pointage-v3';
const SHELL = ['/pointage.html', '/scan.html', '/rh.html', '/pwa.js', '/vendor/qrcode.min.js', '/vendor/jsQR.js'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).catch(() => {}).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;
  e.respondWith(
    fetch(req).then((res) => {
      if (res.ok && res.type === 'basic') {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(url.pathname, copy)).catch(() => {});
      }
      return res;
    }).catch(() => caches.match(url.pathname).then((r) => r || new Response(
      '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#1534A8;color:#fff;font-family:sans-serif;text-align:center;padding:24px">' +
      '<div><h2>Pas de connexion internet</h2><p>Vérifiez la connexion puis rouvrez l\'application.</p></div>',
      { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } })))
  );
});
