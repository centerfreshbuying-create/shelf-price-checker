// Shelf Price Checker Helper
// Opens the store's own site in a minimized background window (so the store's "checking your browser" page
// passes the same way it does for you), then runs the store's product search from inside that page.
const STORES = chrome.runtime.getManifest().host_permissions.map((p) => p.replace("/*", ""));
const bare = (u) => { try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return ""; } };
const APP = /^https:\/\/([a-z0-9-]+--)?shelf-price-checker\.netlify\.app$/;
const locks = {};

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg?.kind !== "fetch") return;
  let from = ""; try { from = new URL(sender.url || sender.origin || "").origin; } catch {}
  if (!APP.test(from)) { reply({ ok: false, error: "not allowed" }); return; }
  run(msg).then(reply, (e) => reply({ ok: false, error: String(e?.message || e) }));
  return true; // answer later
});

async function run({ origin, urls }) {
  if (!STORES.includes(origin)) throw new Error("This store isn't one the helper is set up for.");
  if (!Array.isArray(urls) || !urls.length || urls.length > 7) throw new Error("bad request");
  const prefix = origin + "/v2/retailers/{rid}/branches/{bid}/products?";
  if (!urls.every((u) => typeof u === "string" && u.startsWith(prefix))) throw new Error("bad request");
  // one store page at a time per store
  const prev = locks[origin] || Promise.resolve();
  let done; locks[origin] = new Promise((r) => (done = r));
  await prev.catch(() => {});
  try {
    const tabId = await storeTab(origin);
    await passCheck(tabId);
    const [{ result }] = await chrome.scripting.executeScript({ target: { tabId }, world: "MAIN", func: searchInPage, args: [urls] });
    if (!result?.ok) throw new Error(result?.error || "search failed");
    return result;
  } finally { done(); }
}

// Keep one minimized window with one tab per store, reused for later searches.
async function storeTab(origin) {
  const { winId } = await chrome.storage.session.get("winId");
  let win = winId ? await chrome.windows.get(winId, { populate: true }).catch(() => null) : null;
  if (win) {
    const t = win.tabs.find((x) => bare(x.url || x.pendingUrl || "") === bare(origin));
    if (t) return t.id;
    const t2 = await chrome.tabs.create({ windowId: win.id, url: origin + "/", active: false });
    await loaded(t2.id); return t2.id;
  }
  win = await chrome.windows.create({ url: origin + "/", focused: false, state: "minimized" });
  await chrome.storage.session.set({ winId: win.id });
  const id = win.tabs[0].id; await loaded(id); return id;
}
function loaded(tabId) {
  return new Promise((resolve) => {
    const stop = setTimeout(() => { chrome.tabs.onUpdated.removeListener(on); resolve(); }, 30000);
    function on(id, info) { if (id === tabId && info.status === "complete") { clearTimeout(stop); chrome.tabs.onUpdated.removeListener(on); resolve(); } }
    chrome.tabs.onUpdated.addListener(on);
    chrome.tabs.get(tabId).then((t) => { if (t.status === "complete") on(tabId, { status: "complete" }); }).catch(() => {});
  });
}
// Wait (up to 30s) while the store shows its "Just a moment…" page.
async function passCheck(tabId) {
  for (let i = 0; i < 20; i++) {
    const [{ result }] = await chrome.scripting.executeScript({ target: { tabId }, func: () => /just a moment|checking your browser/i.test(document.title) || !!document.querySelector("#challenge-form, #cf-challenge-running") });
    if (!result) return;
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error("The store's site is still checking the browser. Open it in Chrome once, then refresh.");
}

// Runs inside the store's page, exactly like the store's own search box does.
async function searchInPage(urls) {
  try {
    const get = async (path, json) => {
      const r = await fetch(path, { credentials: "include", headers: { accept: json ? "application/json, text/plain, */*" : "text/html" } });
      return r.text();
    };
    let rid = (document.documentElement.innerHTML.match(/retailers\/(\d+)\//) || [])[1];
    if (!rid) rid = ((await get("/", false)).match(/retailers\/(\d+)\//) || [])[1];
    if (!rid) return { ok: false, error: "Couldn't find the store's catalog." };
    const br = JSON.parse(await get(`/v2/retailers/${rid}/branches`, true));
    const bid = br?.branches?.[0]?.id;
    if (!bid) return { ok: false, error: "Couldn't find the store's branch." };
    const pages = [];
    for (const u of urls) {
      const path = u.replace(/^https:\/\/[^/]+/, "").replace("{rid}", rid).replace("{bid}", bid);
      pages.push({ url: u, text: await get(path, true) });
    }
    return { ok: true, pages };
  } catch (e) { return { ok: false, error: String(e?.message || e) }; }
}
