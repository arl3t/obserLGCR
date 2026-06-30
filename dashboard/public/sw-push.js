// Handlers de Web Push inyectados al Service Worker generado por Workbox.
// Referenciados desde vite.config.ts via workbox.importScripts.

self.addEventListener("push", (event) => {
  let payload = {};
  try { payload = event.data?.json() ?? {}; } catch (_err) {
    payload = { title: "LegacyHunt", body: event.data?.text() ?? "" };
  }
  const title = payload.title || "LegacyHunt — alerta SOC";
  const body  = payload.body  || "";
  const url   = payload.url   || "/vigilancia";
  const tag   = payload.tag   || "legacyhunt";
  event.waitUntil(self.registration.showNotification(title, {
    body,
    tag,
    icon: "/favicon.svg",
    badge: "/favicon.svg",
    data: { url },
    requireInteraction: payload.score >= 70,
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const targetUrl = event.notification.data?.url || "/vigilancia";
  event.waitUntil((async () => {
    const all = await clients.matchAll({ type: "window", includeUncontrolled: true });
    const existing = all.find((c) => c.url.includes(targetUrl));
    if (existing) { existing.focus(); return; }
    await clients.openWindow(targetUrl);
  })());
});
