// Shelf Price Checker: full price lists
// The database calls this on each store's schedule: one page of a store's whole catalog per call.
//   { action: "page", store_id, cursor? } -> { items: [{ key, barcode, name, size, price, image, url }], next, pages }
import { createClient } from "npm:@supabase/supabase-js@2";

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36";
const MAX_BYTES = 3_000_000;


// ---------- safety: only fetch public web servers ----------
function privateV4(ip: string): boolean {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b, c] = p;
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) || (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113);
}
function privateV6(ip: string): boolean {
  const s = ip.toLowerCase();
  if (s === "::" || s === "::1") return true;
  const m = s.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (m) return privateV4(m[1]);
  return /^(fc|fd|fe8|fe9|fea|feb|ff)/.test(s) || s.startsWith("64:ff9b:") || s.startsWith("2001:db8") || s.startsWith("::ffff:");
}
// Resolve with the runtime's DNS; if the runtime doesn't allow it, ask a public DNS-over-HTTPS resolver.
let nativeDns = true;
async function resolve(h: string, type: "A" | "AAAA"): Promise<string[]> {
  if (nativeDns) {
    try { return await Deno.resolveDns(h, type); }
    catch (e) { if ((e as Error)?.name === "NotFound") return []; nativeDns = false; }
  }
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=${type}`, { headers: { accept: "application/dns-json" } });
    const j = await r.json();
    return (j.Answer || []).filter((a: any) => a.type === (type === "A" ? 1 : 28)).map((a: any) => String(a.data));
  } catch { return []; }
}
async function checkUrl(raw: string): Promise<URL> {
  let u: URL;
  try { u = new URL(raw); } catch { throw new Error("blocked"); }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("blocked");
  if (u.port && u.port !== "80" && u.port !== "443") throw new Error("blocked");
  if (u.username || u.password) throw new Error("blocked");
  const h = u.hostname.toLowerCase().replace(/\.+$/, "");
  if (!h.includes(".") || h.startsWith("[") || /^[\d.]+$/.test(h) || /^0x/i.test(h)) throw new Error("blocked");
  if (/(^|\.)(localhost|local|internal|intranet|lan|home|corp)$/.test(h)) throw new Error("blocked");
  const [v4, v6] = await Promise.all([resolve(h, "A"), resolve(h, "AAAA")]);
  if (!v4.length && !v6.length) throw new Error("dns");
  if (v4.some(privateV4) || v6.some(privateV6)) throw new Error("blocked");
  return u;
}

async function safeFetch(raw: string, accept = "text/html,application/json;q=0.9,*/*;q=0.8", post?: string) {
  let url = raw;
  for (let hop = 0; hop < 4; hop++) {
    const u = await checkUrl(url);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10000);
    try {
      const res = await fetch(u.toString(), {
        redirect: "manual", signal: ctrl.signal, method: post != null ? "POST" : "GET", body: post ?? undefined,
        headers: { "User-Agent": UA, Accept: accept, "Accept-Language": "en-US,en;q=0.9", ...(post != null ? { "Content-Type": "application/json" } : {}) },
      });
      const loc = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && loc) {
        await res.body?.cancel();
        url = new URL(loc, u).toString();
        continue;
      }
      // read at most MAX_BYTES, still under the timeout
      const chunks: Uint8Array[] = [];
      let size = 0;
      const reader = res.body?.getReader();
      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value); size += value.length;
          if (size >= MAX_BYTES) { await reader.cancel(); break; }
        }
      }
      const buf = new Uint8Array(Math.min(size, MAX_BYTES));
      let off = 0;
      for (const c of chunks) { const n = Math.min(c.length, buf.length - off); buf.set(c.subarray(0, n), off); off += n; if (off >= buf.length) break; }
      return { status: res.status, url: u.toString(), text: new TextDecoder().decode(buf), type: res.headers.get("content-type") || "" };
    } finally { clearTimeout(timer); }
  }
  throw new Error("redirects");
}

// ---------- parsing ----------
const str = (v: unknown) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : undefined);

function toPrice(v: unknown, centsHint = false): number | null {
  if (v == null) return null;
  if (typeof v === "number") {
    if (!isFinite(v) || v <= 0) return null;
    const n = centsHint ? v / 100 : v;
    return n < 100000 ? Math.round(n * 100) / 100 : null;
  }
  if (typeof v === "string") {
    const s = v.replace(/,/g, "");
    const multi = s.match(/(\d+)\s*(?:for|\/)\s*\$\s*(\d*\.?\d+)/i);
    if (multi && +multi[1] > 1) return toPrice(+multi[2] / +multi[1]);
    const m = s.match(/\$\s*(\d*\.?\d+)/) || s.match(/\d*\.\d+|\d+/);
    return m ? toPrice(parseFloat(m[1] ?? m[0]), centsHint && !s.includes(".")) : null;
  }
  if (typeof v === "object" && !Array.isArray(v)) {
    const o = v as Record<string, unknown>;
    if (/UnitPrice/i.test(String(o["@type"] ?? "")) || o.referenceQuantity) return null;
    for (const k of ["price", "amount", "value", "currentPrice", "salePrice", "minPrice", "lowPrice"]) {
      if (k in o) { const p = toPrice(o[k], centsHint); if (p) return p; }
    }
  }
  return null;
}
const decode = (s: string) =>
  s.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
const SIZE_RE = /(\d+(?:\.\d+)?\s?(?:fl\.?\s?oz|oz|lb|lbs|g|kg|ml|l|ct|count|pk|pack)\b)/i;
type Cand = { price: number; name?: string; image?: string; size?: string; url?: string; id?: number | string };
// Self-Point stores (Moisha's…): search results give name, brand, size and the branch's price, but no barcode
function fromSelfPoint(arr: any[], code: string, url: string): Cand[] {
  const origin = new URL(url).origin;
  return arr.map((p) => {
    const b = p.branch || {};
    const sale = [].concat(b.specials || p.specials || []).map((s: any) => toPrice(s?.price ?? s?.salePrice)).filter(Boolean) as number[];
    const price = (sale.length ? Math.min(...sale) : 0) || toPrice(b.salePrice) || toPrice(b.regularPrice) || 0;
    const nm = str(p.names?.["2"]?.long) || str(p.names?.["2"]?.short) || str(p.localName);
    const brand = str(p.brand?.names?.["2"]);
    const name = nm ? decode(brand && !nm.toLowerCase().includes(brand.toLowerCase()) ? `${brand} ${nm}` : nm) : undefined;
    const unit = str(p.unitOfMeasure?.names?.["2"]);
    const size = p.weight && unit ? `${p.weight} ${unit}` : name?.match(SIZE_RE)?.[1];
    const img = str(p.image?.url)?.replace("{{size}}", "medium").replace(/\{\{extension[^}]*\}\}/, "jpg");
    return { price, name, image: img, size, url: origin + "/", id: p.id ?? p.productId };
  }).filter((c) => c.price && c.id != null);
}
// Stores behind a "checking your browser" page are read through Firecrawl's page loader (normal mode, no stealth).
const isBrowserStore = (s: any) => /\{rid\}/.test(String(s?.search_url || ""));
const FC_KEY = Deno.env.get("FIRECRAWL_API_KEY") || "";
async function viaFirecrawl(url: string) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 30000);
  try {
    const res = await fetch("https://api.firecrawl.dev/v2/scrape", {
      method: "POST", signal: ctrl.signal,
      headers: { Authorization: `Bearer ${FC_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ url, formats: ["rawHtml"], proxy: "basic", maxAge: 0, timeout: 25000 }),
    });
    if (!res.ok) { await res.body?.cancel(); throw new Error("fc:" + res.status); }
    const j = await res.json();
    const d = j?.data || {};
    const text = String(d.rawHtml ?? d.html ?? d.markdown ?? "").slice(0, MAX_BYTES);
    return { status: Number(d.metadata?.statusCode) || 200, url, text, type: String(d.metadata?.contentType || "") };
  } catch (e) {
    throw new Error(String((e as Error)?.message || "").startsWith("fc:") ? (e as Error).message : "fc:0");
  } finally { clearTimeout(timer); }
}
// Self-Point store and branch numbers (found once per store; new stores are looked up through Firecrawl)
const SP_IDS: Record<string, [string, string]> = {
  "www.shopevergreenkosher.com": ["1120", "2801"], "www.gourmetglattonline.com": ["1058", "87"], "www.gonpgs.com": ["1135", "951"],
  "www.foodexsupermarket.com": ["1076", "106"], "www.glattmart.com": ["1130", "907"], "www.koshercornersupermarket.com": ["1273", "1672"],
  "www.thepompeopleonline.com": ["1082", "161"], "www.shopsmartkosher.com": ["1264", "1643"],
};
async function spResolve(searchUrl: string): Promise<string> {
  const u = new URL(searchUrl.replace(/\{\w+\}/g, "0"));
  let ids = SP_IDS[u.hostname];
  if (!ids) {
    const home = await viaFirecrawl(u.origin + "/");
    const rid = home.text.match(/retailers\/(\d+)\//)?.[1];
    if (!rid) throw new Error("fc:ids");
    const br = JSON.parse((await viaFirecrawl(`${u.origin}/v2/retailers/${rid}/branches`)).text);
    const bid = br?.branches?.[0]?.id;
    if (!bid) throw new Error("fc:ids");
    ids = SP_IDS[u.hostname] = [rid, String(bid)];
  }
  return searchUrl.replace("{rid}", ids[0]).replace("{bid}", ids[1]);
}
// ---------- full price lists ----------
// One page of a store's whole catalog. The database calls this on each store's schedule and matches the lists to "my store".
async function catalogPage(store: any, cur: any) {
  const su = String(store.search_url || "");
  const origin = new URL(su.replace(/\{\w+\}/g, "0")).origin;
  const page = Math.max(0, Math.floor(Number(cur?.page) || 0));
  const clean = (x: any) => x && x.price && x.name ? x : null;
  if (/\/api\/Catalog\/SearchTermAutoComplete/i.test(su)) {
    const r = await safeFetch(`${origin}/api/AjaxFilter/JsonProductsList?pageNumber=${page + 1}&q=a`, "application/json", "[]");
    if (r.status >= 400) throw new Error("http");
    const j = JSON.parse(r.text); const arr: any[] = JSON.parse(j.productsJson || "[]");
    const imgBase = typeof j.TImgUrl === "string" && /^https:\/\//.test(j.TImgUrl) ? j.TImgUrl : "";
    const items = arr.map((p) => {
      const name = str(p.N) ? decode(str(p.N)!) : "", bc = String(p.SKU || "").replace(/\D/g, "");
      return clean({ key: bc || "id" + p.Id, barcode: bc || null, name, size: name.match(SIZE_RE)?.[1] || null, price: toPrice(p.P_v) || toPrice(p.P),
        image: imgBase && str(p.iU) ? imgBase + encodeURIComponent(p.iU) : null,
        url: typeof j.TUrl === "string" && p.Id ? origin + "/" + j.TUrl.replace("[PRODUCT-ID]", encodeURIComponent(p.Id)) : origin + "/" });
    }).filter(Boolean);
    const last = Number(j.pager?.LastIndex) || 1;
    return { items, next: page + 1 < last ? { page: page + 1 } : null, pages: last };
  }
  const bx = su.match(/^(https:\/\/[^/]+)\/api\/services\/supplier-ms\/public\/api\/v1\/groceries\/_search\?supplierId=(\d+)/);
  if (bx) {
    const r = await safeFetch(`${bx[1]}/api/services/supplier-ms/public/api/v1/groceries/_search?supplierId=${bx[2]}&page=${page}&size=100`, "application/json");
    if (r.status >= 400) throw new Error("http");
    const arr: any[] = JSON.parse(r.text);
    const title = (t: string) => t === t.toUpperCase() ? t.toLowerCase().replace(/\b\p{L}/gu, (c) => c.toUpperCase()) : t;
    const items = arr.map((p) => {
      const g = p.groceryPrice || {}, name = str(p.name) ? title(decode(str(p.name)!)) : "", bc = String(p.upc || p.sku || "").replace(/\D/g, "");
      return clean({ key: bc || "id" + p.id, barcode: bc || null, name, size: name.match(SIZE_RE)?.[1] || null,
        price: (g.specialUsed && toPrice(g.specialPrice)) || toPrice(g.basicPrice) || toPrice(p.searchPrice?.minPrice),
        image: str(p.mainImage?.previewUrl) || str(p.mainImage?.mainUrl) || null, url: p.id ? `${bx[1]}/products/${p.id}${p.seo?.slug ? "-" + p.seo.slug : ""}` : bx[1] + "/" });
    }).filter(Boolean);
    return { items, next: arr.length === 100 && page < 99 ? { page: page + 1 } : null, pages: 100 };
  }
  if (/\/v2\/retailers\/[^/]+\/branches\/[^/]+\/products/.test(su)) {
    const viaFc = isBrowserStore(store);
    if (viaFc && !FC_KEY) throw new Error("fc:nokey");
    const base = (viaFc ? await spResolve(su) : su).split("?")[0];
    // the same filter the store's own site uses: only items that are on sale at this branch right now
    const filters = encodeURIComponent(JSON.stringify({ must: { exists: ["family.id", "family.categoriesPaths.id", "branch.regularPrice"], term: { "branch.isActive": true, "branch.isVisible": true } }, mustNot: { term: { "branch.regularPrice": 0 } } }));
    const url = `${base}?appId=4&filters=${filters}&from=${page * 400}&size=400&sort=${encodeURIComponent(JSON.stringify({ id: "asc" }))}`;
    const r = viaFc ? await viaFirecrawl(url) : await safeFetch(url, "application/json");
    if (r.status >= 400) throw new Error(viaFc ? "fc:" + r.status : "http");
    const j = JSON.parse(r.text.replace(/^[^{]*/, "").replace(/[^}]*$/, ""));
    const arr: any[] = j.products || [];
    const items = fromSelfPoint(arr, "", url).map((c) => clean({ key: "sp" + c.id, barcode: null, name: c.name, size: c.size || null, price: c.price, image: c.image || null, url: c.url }));
    return { items: items.filter(Boolean), next: arr.length === 400 && page < 190 ? { page: page + 1 } : null, pages: null };
  }
  throw new Error("nolist");
}

function friendly(e: unknown) {
  const m = String((e as Error)?.message || "");
  if (m === "fc:nokey") return "Add your Firecrawl key to turn this store on.";
  if (m === "fc:402") return "Firecrawl is out of credits.";
  if (m === "fc:401" || m === "fc:403") return "The Firecrawl key isn't being accepted.";
  if (m.startsWith("fc:")) return "Firecrawl couldn't load this store's site.";
  if (m === "nolist") return "This store's site doesn't offer a full price list.";
  return "Couldn't read this store's price list. It may be down or slow.";
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  let body: any;
  try { body = await req.json(); } catch { return json({ error: "Bad request" }, 400); }
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
  // only the database knows this secret
  const { data: ok } = await admin.rpc("pc_cron_secret_ok", { p: req.headers.get("x-cron-secret") || "" });
  if (!ok) return json({ error: "Not allowed" }, 403);
  const { data: store } = await admin.from("pc_stores").select("*").eq("id", String(body.store_id || "")).maybeSingle();
  if (!store) return json({ error: "Store not found" }, 404);
  try { return json(await catalogPage(store, body.cursor || {})); } catch (e) { return json({ error: friendly(e) }); }
});
