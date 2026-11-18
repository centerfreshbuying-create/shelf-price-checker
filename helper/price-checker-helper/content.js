// Runs only on the Shelf Price Checker site. Passes the app's search requests to the helper and the results back.
const post = (m) => window.postMessage(m, location.origin);
window.addEventListener("message", (e) => {
  if (e.source !== window || e.origin !== location.origin) return;
  const d = e.data;
  if (!d || d.pcHelper !== "req" || typeof d.id !== "string") return;
  if (d.kind === "ping") return post({ pcHelper: "res", id: d.id, ok: true, version: chrome.runtime.getManifest().version });
  if (d.kind === "fetch") {
    chrome.runtime.sendMessage({ kind: "fetch", origin: d.origin, urls: d.urls }, (res) => {
      post({ pcHelper: "res", id: d.id, ...(res || { ok: false, error: chrome.runtime.lastError?.message || "no answer" }) });
    });
  }
});
post({ pcHelper: "ready" });
