// Service Worker para PWA
const CACHE_NAME = 'gym-control-v3';
// Cache solo lo esencial durante la instalacion para evitar demoras
const CORE_ASSETS = [
  '/public/manifest.webmanifest',
  '/public/icons/app-icon.png'
];

// Instalar: cachear assets minimos para que la instalacion sea rapida
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(CORE_ASSETS).catch(() => {
        // Si algún asset falla, continuar sin fallar todo
        console.warn('Algunos assets no pudieron ser cacheados');
      });
    })
  );
  self.skipWaiting();
});

// Activar: limpiar caches antiguas
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch: cache-first para assets, network-first para API
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Ignorar requests externas no-HTML
  if (url.origin !== location.origin && !request.url.includes('.html')) {
    return;
  }

  // Para API (rutas /api/...), intentar red primero
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(request)
        .then((response) => response)
        .catch(() => caches.match(request))
    );
    return;
  }

  // Para assets estáticos (js, css, img, fonts), cachear primero
  if (
    request.url.includes('.js') ||
    request.url.includes('.css') ||
    request.url.includes('.png') ||
    request.url.includes('.jpg') ||
    request.url.includes('.jpeg') ||
    request.url.includes('.gif') ||
    request.url.includes('.woff') ||
    request.url.includes('.woff2') ||
    request.url.includes('fonts.googleapis')
  ) {
    event.respondWith(
      caches.match(request).then((cached) => {
        return (
          cached ||
          fetch(request).then((response) => {
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(request, response.clone());
            });
            return response;
          })
        );
      })
    );
    return;
  }

  // Para HTML y el resto, intentar red primero
  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response.ok) {
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(request, response.clone());
          });
        }
        return response;
      })
      .catch(() => caches.match(request))
  );
});
