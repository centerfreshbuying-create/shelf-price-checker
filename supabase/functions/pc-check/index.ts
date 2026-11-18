// Shelf Price Checker — server function
//   { action: "lookup", barcode }                      -> product info from public barcode databases
//   { action: "check", product_id, store_id, force?, second? } -> fetch the store's page, extract price, save it
//   { action: "check_product", product_id, area_id? }  -> one item at every store in an area (Excel bulk check)
//   { action: "detect" | "test" }                      -> find a store's product search / try it with a barcode
//   { action: "create_user" | "update_user" | "delete_user" } -> team admins manage users and their locations
//   { action: "cron_refresh" }                         -> hourly re-check of items with price-drop alerts
import { createClient } from "npm:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });
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
const digits = (s: unknown) => String(s ?? "").replace(/\D/g, "").replace(/^0+/, "");
// a store may list the UPC with or without its check digit, leading zeros, or first digit (e.g. 1006903510 for 710069035102)
const mc = (x: unknown, code: string) => {
  const d = digits(x); if (!code || !d) return false;
  if (d === code || (code.length > 7 && d === code.slice(0, -1))) return true;
  if (code.length >= 11 && code.length <= 13 && d.length >= 8) { const c12 = code.padStart(12, "0"); return d === c12.slice(1, 11).replace(/^0+/, ""); }
  return false;
};
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
const firstImage = (v: unknown): string | undefined => {
  if (!v) return undefined;
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return firstImage(v[0]);
  if (typeof v === "object") { const o = v as any; return str(o.url) || str(o.contentUrl) || str(o.src); }
};
const decode = (s: string) =>
  s.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
const SIZE_RE = /(\d+(?:\.\d+)?\s?(?:fl\.?\s?oz|oz|lb|lbs|g|kg|ml|l|ct|count|pk|pack)\b)/i;
const absUrl = (v: unknown, base: string) => { const s = str(v); if (!s) return undefined; try { return new URL(s, base).toString(); } catch { return undefined; } };
const sizeOf = (v: unknown): string | undefined => {
  if (typeof v === "string") return v;
  if (v && typeof v === "object" && (v as any).value != null) return `${(v as any).value} ${(v as any).unitText || (v as any).unitCode || ""}`.trim();
};

type Cand = { price: number; name?: string; image?: string; size?: string; url?: string; hasCode: boolean; codeKnown?: boolean; score: number };

function fromJsonLd(html: string, code: string, base: string): Cand[] {
  const out: Cand[] = [];
  const re = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  const visit = (n: any, depth = 0) => {
    if (!n || typeof n !== "object" || depth > 12) return;
    if (Array.isArray(n)) { for (const x of n) visit(x, depth + 1); return; }
    for (const k of ["@graph", "itemListElement", "item", "hasVariant"]) if (n[k]) visit(n[k], depth + 1);
    if (!/Product/i.test([].concat(n["@type"] || []).join(","))) return;
    const offers: any[] = [].concat(n.offers?.offers || n.offers || []);
    let price: number | null = null;
    for (const o of offers) price = price || toPrice(o?.price ?? o?.lowPrice) || toPrice(o?.priceSpecification);
    if (!price) return;
    const ids = [n.gtin13, n.gtin12, n.gtin14, n.gtin8, n.gtin, n.sku, n.mpn, n.productID].filter(Boolean);
    const hasCode = !!code && ids.some((x) => mc(x, code));
    const name = str(n.name) ? decode(str(n.name)!) : undefined;
    out.push({
      price, name, image: firstImage(n.image),
      size: sizeOf(n.size) || sizeOf(n.weight) || name?.match(SIZE_RE)?.[1],
      url: absUrl(n.url, base) || absUrl(offers[0]?.url, base),
      hasCode, score: (hasCode ? 100 : 0) + 30,
    });
  };
  let m;
  while ((m = re.exec(html))) {
    try { visit(JSON.parse(m[1].trim())); } catch { /* skip block */ }
  }
  return out;
}

const PRICE_KEYS = ["price", "currentPrice", "salePrice", "finalPrice", "priceValue", "regularPrice", "displayPrice", "base_price", "price_min"];
const CENT_KEYS = ["priceInCents", "price_cents", "priceCents"];
const NAME_KEYS = ["name", "title", "productName", "displayName"];
const CODE_KEY = /gtin|upc|ean|barcode|sku/i;

function fromEmbeddedJson(root: unknown, code: string, base: string, shopifyCents: boolean): Cand[] {
  const out: Cand[] = [];
  let budget = 150000;
  const hasCodeIn = (n: any, d = 0): boolean => {
    if (!code || !n || typeof n !== "object" || d > 4) return false;
    for (const k in n) {
      const v = n[k];
      if (CODE_KEY.test(k) && (typeof v === "string" || typeof v === "number") && mc(v, code)) return true;
      if (v && typeof v === "object" && hasCodeIn(v, d + 1)) return true;
    }
    return false;
  };
  const walk = (n: any, depth: number) => {
    if (!n || typeof n !== "object" || depth > 40 || budget-- <= 0) return;
    if (Array.isArray(n)) { for (const x of n) walk(x, depth + 1); return; }
    const ck = CENT_KEYS.find((k) => k in n);
    const pk = PRICE_KEYS.find((k) => k in n);
    const nk = NAME_KEYS.find((k) => typeof n[k] === "string" && n[k].length > 2 && n[k].length < 300);
    if ((ck || pk) && nk) {
      const p = ck ? toPrice(n[ck], true) : toPrice(n[pk!], shopifyCents && Number.isInteger(n[pk!]));
      if (p) {
        const name = decode(n[nk]);
        const hasCode = hasCodeIn(n);
        out.push({
          price: p, name,
          image: firstImage(n.image ?? n.imageUrl ?? n.image_url ?? n.featured_image ?? n.thumbnail ?? n.images),
          size: sizeOf(n.size) || sizeOf(n.packageSize) || name.match(SIZE_RE)?.[1],
          url: absUrl(n.url || n.canonicalUrl || n.productUrl || (str(n.handle) && `/products/${n.handle}`), base),
          hasCode, score: (hasCode ? 100 : 0) + 10,
        });
      }
    }
    for (const k in n) walk(n[k], depth + 1);
  };
  walk(root, 0);
  return out;
}

function scriptJson(html: string): unknown[] {
  const out: unknown[] = [];
  const re = /<script[^>]*(?:id=["']__NEXT_DATA__["']|type=["']application\/json["'])[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html))) { try { out.push(JSON.parse(m[1])); } catch { /* skip */ } }
  return out;
}
function meta(html: string, key: string): string | undefined {
  const tag = html.match(new RegExp(`<meta[^>]+(?:property|name|itemprop)=["']${key}["'][^>]*>`, "i"))?.[0];
  const c = tag?.match(/content=(["'])(.*?)\1/i)?.[2];
  return c ? decode(c) : undefined;
}
function fromMeta(html: string, code: string, url: string): Cand[] {
  const p = toPrice(meta(html, "product:price:amount") || meta(html, "og:price:amount") || meta(html, "price"));
  if (!p) return [];
  const name = meta(html, "og:title") || html.match(/<title>([^<]*)<\/title>/i)?.[1];
  const ids = ["gtin13", "gtin12", "gtin", "sku", "product:retailer_item_id"].map((k) => meta(html, k)).filter(Boolean);
  const hasCode = !!code && ids.some((x) => mc(x, code));
  return [{ price: p, name: name ? decode(name).trim() : undefined, image: meta(html, "og:image"),
    size: name?.match(SIZE_RE)?.[1], url, hasCode, score: (hasCode ? 100 : 0) + 20 }];
}
function extract(page: { text: string; url: string; type: string }, code: string): Cand[] {
  const shopify = /\/products\/[^/]+\.js(on)?(\?|$)/.test(new URL(page.url).pathname + new URL(page.url).search);
  if (page.type.includes("json") || /^\s*[\[{]/.test(page.text)) {
    try {
      const j = JSON.parse(page.text);
      if (typeof j?.productsJson === "string") return fromMcg(j, code, page.url);
      if (Array.isArray(j?.products) && "total" in j && j.products.every((p: any) => p?.branch)) return fromSelfPoint(j.products, code, page.url);
      const bx = Array.isArray(j) ? j : Array.isArray(j?.products) && "matchType" in j ? j.products : null;
      if (bx && (!bx.length || bx[0]?.groceryPrice || bx[0]?.searchPrice)) return fromBnxt(bx, code, page.url);
      return fromEmbeddedJson(j, code, page.url, shopify);
    } catch { /* not json */ }
  }
  const c = [...fromJsonLd(page.text, code, page.url), ...fromMeta(page.text, code, page.url)];
  for (const j of scriptJson(page.text)) c.push(...fromEmbeddedJson(j, code, page.url, false));
  return c;
}
// My Cloud Grocer stores (Certo, Mega 53, Breadberry, Landau's, Mountain Fruit…): each result lists its UPC
function fromMcg(j: any, code: string, url: string): Cand[] {
  let arr: any[] = []; try { arr = JSON.parse(j.productsJson) || []; } catch { /* none */ }
  const origin = new URL(url).origin;
  const imgBase = typeof j.TImgUrl === "string" && /^https:\/\//.test(j.TImgUrl) ? j.TImgUrl : "";
  return arr.map((p) => {
    const hasCode = mc(p.SKU, code), name = str(p.N) ? decode(str(p.N)!) : undefined;
    const link = typeof j.TUrl === "string" && p.Id ? origin + "/" + j.TUrl.replace("[PRODUCT-ID]", encodeURIComponent(p.Id)) : origin + "/";
    return { price: toPrice(p.P_v) || toPrice(p.P) || 0, name, image: imgBase && str(p.iU) ? imgBase + encodeURIComponent(p.iU) : undefined, size: name?.match(SIZE_RE)?.[1], url: link, hasCode, codeKnown: !!p.SKU, score: (hasCode ? 100 : 0) + 10 };
  }).filter((c) => c.price);
}
// bnxtlvl / 3hr stores (Kosher Village, Rubin's, Spot Kosher…): results list the UPC, a regular and a sale price
function fromBnxt(arr: any[], code: string, url: string): Cand[] {
  const origin = new URL(url).origin;
  const title = (s: string) => s === s.toUpperCase() ? s.toLowerCase().replace(/\b\p{L}/gu, (c) => c.toUpperCase()) : s;
  return arr.map((p) => {
    const g = p.groceryPrice || {};
    const price = (g.specialUsed && toPrice(g.specialPrice)) || toPrice(g.basicPrice) || toPrice(p.searchPrice?.minPrice) || 0;
    const name = str(p.name) ? title(decode(str(p.name)!)) : undefined;
    const ids = [p.upc, p.sku].filter(Boolean);
    const hasCode = ids.some((x) => mc(x, code));
    return { price, name, image: str(p.mainImage?.previewUrl) || str(p.mainImage?.mainUrl) || str(p.images?.[0]?.previewUrl),
      size: name?.match(SIZE_RE)?.[1], url: p.id ? `${origin}/products/${p.id}${p.seo?.slug ? "-" + p.seo.slug : ""}` : origin + "/",
      hasCode, codeKnown: ids.length > 0, score: (hasCode ? 100 : 0) + 10 };
  }).filter((c) => c.price);
}
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
    const ids = [p.barcode, p.localBarcode].filter(Boolean);
    const hasCode = ids.some((x) => mc(x, code));
    return { price, name, image: img, size, url: origin + "/", hasCode, codeKnown: ids.length > 0, score: (hasCode ? 100 : 0) + 10 };
  }).filter((c) => c.price);
}
// Name matching: the store's item must use the same key words as ours (or as another store's exact match) and the same size.
const SIZE_WORD = /^(\d+(\.\d+)?|oz|fl|lb|lbs|g|kg|ml|l|ct|count|pk|pack|ounce|ounces|pound|pounds|gram|grams)$/i;
const stem = (x: string) => (x.length > 3 && x.endsWith("s") && !x.endsWith("ss") ? x.slice(0, -1) : x);
// "Orig" for "Original": a shortened filler word is still a filler word
const stopPre = (t: string) => t.length >= 4 && [...STOP].some((w) => w.startsWith(t));
// full = also read the words after a comma (used for our own reference names)
const toks = (s?: string, full = false) => new Set(wordsOf(String(s || "").replace(/(\d)([a-z])/gi, "$1 $2").replace(/,/g, full ? " " : ","))
  .map((x) => stem(x.toLowerCase())).filter((x) => x.length > 1 && !SIZE_WORD.test(x) && !STOP.has(x) && !stopPre(x)));
function grams(s?: string | null): number | null {
  const m = String(s || "").toLowerCase().match(/(\d+(?:\.\d+)?)\s*(fl\.?\s?oz|oz|ounces?|lbs?|pounds?|kg|grams?|g|ml|l)\b/);
  if (!m) return null;
  const n = parseFloat(m[1]), u = m[2].replace(/\s|\./g, "");
  const f: Record<string, number> = { floz: 29.57, oz: 28.35, ounce: 28.35, ounces: 28.35, lb: 453.6, lbs: 453.6, pound: 453.6, pounds: 453.6, kg: 1000, g: 1, gram: 1, grams: 1, ml: 1, l: 1000 };
  return f[u] ? n * f[u] : null;
}
// pack counts: "72 Chewable Tablets", "96 ct"
const countOf = (s?: string | null): number | null => { const m = String(s || "").toLowerCase().match(/(\d+)\s*(?:ct|cnt|count|pk|pack|pcs?|tablets?|chewable tablets|pieces?)\b/); return m ? +m[1] : null; };
// a store may shorten a word ("Lieb" for "Lieber")
const hasTok = (t: string, R: Set<string>) => {
  if (R.has(t)) return true;
  for (const r of R) { if (t.length >= 3 && r.length > t.length && r.startsWith(t)) return true; if (r.length >= 4 && t.length > r.length && t.startsWith(r)) return true; }
  return false;
};
// Returns how well a store's item name matches, or null when it isn't a safe match.
function nameScore(cand: Cand, refs: string[], size?: string | null): { s: number; h: number; z: boolean } | null {
  const C = toks(cand.name);
  const R = new Set<string>(); refs.forEach((r) => toks(r, true).forEach((t) => R.add(t)));
  let hit = 0; C.forEach((t) => { if (hasTok(t, R)) hit++; });
  if (hit < 2) return null; // one shared word ("Barley", "Ketchup") is never enough
  const a = grams(cand.size || cand.name), b = grams(size) ?? refs.map((r) => grams(r)).find((x) => x != null) ?? null;
  const weighed = a != null && b != null;
  if (weighed && Math.abs(a! - b!) / Math.max(a!, b!) > 0.06) return null; // different size
  const ca = countOf(cand.size) ?? countOf(cand.name), cb = refs.map((r) => countOf(r)).find((x) => x != null) ?? null;
  const counted = ca != null && cb != null;
  if (counted && ca !== cb) return null; // different pack count
  const sized = weighed || counted;
  const s = hit / C.size;
  // with no size to confirm it, the store's name must at least carry the brand (the first word of one of our names)
  const lead = new Set<string>(); refs.forEach((r) => { const f = [...toks(r, true)][0]; if (f) lead.add(f); });
  const branded = [...C].some((t) => hasTok(t, lead));
  if (s >= 0.8 && (sized || (hit >= 3 && branded))) return { s, h: hit, z: sized };
  if (s >= 0.6 && hit >= 4 && sized) return { s, h: hit, z: sized }; // same brand words and size, plus the store's own marketing words
  return null;
}
// Store searches only show their top few results, so try several searches: the item's name, names other stores
// already matched by barcode, brand + key word pairs, then single words.
const STOP = new Set(["the", "and", "with", "for", "free", "original", "classic", "new", "pack", "size", "family"]);
function wordsOf(s: string): string[] {
  return String(s || "").replace(/\([^)]*\)/g, " ").replace(/,.*$/, " ").replace(SIZE_RE, " ").replace(/['’]s\b/gi, "").replace(/['’]/g, "")
    .replace(/[^\p{L}\p{N} ]+/gu, " ").replace(/\s+/g, " ").trim().split(" ").filter(Boolean);
}
function searchTerms(name: string, extras: string[] = [], brand = ""): string[] {
  const out: string[] = [], add = (t: string) => { t = t.trim(); if (t.length > 2 && !out.some((x) => x.toLowerCase() === t.toLowerCase())) out.push(t); };
  const w = wordsOf(name), ex = extras.map(wordsOf).filter((x) => x.length);
  add(w.slice(0, 4).join(" "));
  for (const e of ex) add(e.slice(0, 3).join(" "));
  const firsts = [...new Set([wordsOf(brand)[0], ...ex.map((e) => e[0]), w[0]].filter(Boolean))];
  const keys = [...new Set([...w, ...ex.flat()].filter((x) => x.length >= 4 && !STOP.has(x.toLowerCase())))];
  for (const f of firsts) for (const k of keys) if (k.toLowerCase() !== f.toLowerCase()) add(`${f} ${k}`);
  add(w.slice(0, 2).join(" "));
  for (const f of firsts) if (f.length >= 4) add(f);
  return out.slice(0, 7);
}
function sim(a?: string, b?: string): number {
  const t = (s?: string) => new Set(String(s || "").toLowerCase().replace(/[^\p{L}\p{N} ]+/gu, " ").split(/\s+/).filter((x) => x.length > 1));
  const A = t(a), B = t(b); if (!A.size || !B.size) return 0;
  let n = 0; A.forEach((x) => { if (B.has(x)) n++; }); return n / Math.min(A.size, B.size);
}
function productLinks(html: string, base: string, code: string): string[] {
  const host = new URL(base).hostname, links: string[] = [];
  const re = /href=["']([^"'#]+)["']/gi;
  let m;
  while ((m = re.exec(html))) {
    let u: URL;
    try { u = new URL(decode(m[1]), base); } catch { continue; }
    if (u.hostname !== host) continue;
    if ((code && u.pathname.includes(code)) || /\/(product|products|p|ip|dp|item|pd)\//i.test(u.pathname)) links.push(u.toString());
  }
  return [...new Set(links)].sort((a, b) => Number(b.includes(code)) - Number(a.includes(code))).slice(0, 2);
}
const BLOCK_RE = /captcha|are you a robot|access denied|request blocked|unusual traffic|px-captcha|cf-chl|attention required/i;
function buildUrl(tpl: string, barcode: string, name: string) {
  const d = barcode.replace(/\D/g, "");
  return tpl.replaceAll("{barcode}", encodeURIComponent(d))
    .replaceAll("{upc12}", encodeURIComponent(d.padStart(12, "0").slice(-12)))
    .replaceAll("{ean13}", encodeURIComponent(d.padStart(13, "0").slice(-13)))
    .replaceAll("{name}", encodeURIComponent(name || d));
}
function friendly(e: unknown) {
  const m = (e as Error)?.message;
  if (m === "blocked") return "That web address isn't allowed. Use the store's public website.";
  if (m === "dns") return "That website address doesn't exist. Check the store's search link.";
  if (m === "fc:402") return "Firecrawl is out of credits, so this store couldn't be checked. Add credits, then press Refresh.";
  if (m === "fc:401" || m === "fc:403") return "The Firecrawl key isn't being accepted. Check the FIRECRAWL_API_KEY secret.";
  if (m === "fc:429") return "Firecrawl is busy right now. Press Refresh in a minute.";
  if (String(m).startsWith("fc:")) return "Firecrawl couldn't load this store's site. Press Refresh to try again.";
  return "Couldn't reach the site. It may be down, or slow to answer.";
}

// Stores whose sites only open in a real browser (Self-Point stores behind a "checking your browser" page).
// With a Firecrawl key set, the server loads their search through Firecrawl's page loader (normal mode, no stealth).
// Without one, the Price Checker helper add-on can run the searches in the user's own Chrome and hand back the results.
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
function browserTargets(searchUrl: string, barcode: string, name: string, extras: string[], brand: string): string[] {
  return searchTerms(name, extras, brand).slice(0, 5).map((t) => buildUrl(searchUrl, barcode, t));
}

async function runCheck(searchUrl: string, barcode: string, name: string, pinned: string | null, extras: string[] = [], brand = "", size: string | null = null, provided?: Map<string, string>, fc = false): Promise<Record<string, unknown>> {
  const code = digits(barcode);
  const now = new Date().toISOString();
  let result: Record<string, unknown>;
  const byName = !pinned && searchUrl.includes("{name}");
  // My Cloud Grocer stores: their full product search finds the barcode directly, and by name returns every match (not just the top 7)
  const mcg = !pinned && /\/api\/Catalog\/SearchTermAutoComplete/i.test(searchUrl) ? new URL(searchUrl.replace(/\{\w+\}/g, "x")).origin : "";
  try {
    if (byName && !mcg && !/\/supplier-ms\/public\//.test(searchUrl) && !name && !extras.length) throw new Error("noname");
    const full = (q: string) => `${mcg}/api/AjaxFilter/JsonProductsList?pageNumber=1&q=${encodeURIComponent(q)}`;
    const terms = byName ? searchTerms(name, extras, brand) : [];
    // bnxtlvl stores have a direct barcode lookup; try it before the name searches
    const bx = !pinned && searchUrl.match(/^(https:\/\/[^/]+)\/api\/services\/supplier-ms\/public\/api\/v1\/groceries\/_search\?supplierId=(\d+)/);
    const bxCode = bx ? `${bx[1]}/api/services/supplier-ms/public/api/v1/groceries/barcode/${String(barcode).replace(/\D/g, "")}?tenantId=${bx[2]}` : "";
    const targets = pinned ? [pinned] : mcg ? [full(String(barcode).replace(/\D/g, "")), ...terms.slice(0, 5).map(full)]
      : bx ? [bxCode, ...terms.slice(0, 5).map((t) => buildUrl(searchUrl, barcode, t))]
      : byName ? terms.slice(0, fc ? 4 : 7).map((t) => buildUrl(searchUrl, barcode, t)) : [buildUrl(searchUrl, barcode, name || "")];
    if (bx && !name && !extras.length) targets.splice(1);
    const refs = [name, ...extras].filter(Boolean);
    let all: Cand[] = [], page: any = null;
    for (const target of provided ? [...provided.keys()] : targets) {
      if (provided) {
        const text = provided.get(target);
        if (text == null) continue;
        page = { status: /^\s*[\[{]/.test(text) ? 200 : 403, url: target, text, type: "application/json" };
      } else page = fc ? await viaFirecrawl(target) : await safeFetch(target, "application/json, text/html;q=0.8", mcg ? "[]" : undefined);
      let cands = page.status < 400 ? extract(page, code) : [];
      if (!provided && !cands.some((c) => c.hasCode) && page.status < 400 && !pinned && !byName) {
        for (const link of productLinks(page.text, page.url, code)) {
          const p2 = await safeFetch(link).catch(() => null);
          if (!p2 || p2.status >= 400) continue;
          const c2 = extract(p2, code).map((c) => ({ ...c, url: c.url || p2.url }));
          if (c2.some((c) => c.hasCode) || (!cands.length && c2.length)) { cands = c2; page = p2; break; }
        }
      }
      all.push(...cands);
      if (all.some((c) => c.hasCode)) break;
      // each Firecrawl search costs a credit: stop as soon as one result matches on every word and is confirmed by size or brand
      if (fc && byName && cands.some((c) => { const m = nameScore(c, refs, size); return !!m && m.s === 1 && (m.z || m.h >= 3); })) break;
    }
    all.sort((a, b) => b.score - a.score);
    let best = all.find((c) => c.hasCode), match = best ? "exact" : "";
    if (!best && pinned && all.length) { best = all[0]; match = "pinned"; }
    if (!best && all.length) {
      if (byName) {
        // the store lists it under a different barcode (or none): match by the same key words and size
        const top = all.map((c) => ({ c, m: nameScore(c, refs, size) })).filter((x) => x.m)
          .sort((a, b) => b.m!.s - a.m!.s || b.m!.h - a.m!.h || a.c.price - b.c.price)[0];
        if (top) { best = top.c; match = "possible"; }
      } else if (!all.some((c) => c.codeKnown) && new Set(all.map((c) => (c.name || "").toLowerCase())).size <= 1) { best = all[0]; match = "possible"; }
    }
    if (best) {
      result = {
        price: best.price, product_name: best.name?.slice(0, 300) || null, image_url: best.image || null,
        size: best.size ? String(best.size).slice(0, 60) : null, product_url: best.url || page.url,
        match, status: "found", source: "auto", message: null, checked_at: now,
      };
    } else if (all.length) {
      result = { status: "not_found", message: all.some((c) => c.codeKnown)
        ? "This store doesn't seem to carry it. Their search didn't list this barcode."
        : "Several different items came up and none had this barcode. Open the site, find the item, and save its link here." };
    } else if (!page) {
      result = { status: "error", message: "The helper didn't bring back any results. Press Refresh to try again." };
    } else {
      const blocked = [403, 412, 429, 503].includes(page.status) || BLOCK_RE.test(page.text.slice(0, 50000));
      result = {
        status: blocked ? "blocked" : "not_found",
        message: blocked ? "This site blocks automatic price checks. Enter the price by hand, or save the item's page link."
          : page.status >= 400 ? `The site answered with an error (${page.status}). Check the store's search link.`
          : byName ? "This store doesn't seem to carry it. Nothing came up when searching by name."
          : "No price on the page. The site may not carry this item, or loads prices only in a browser.",
      };
    }
  } catch (e) {
    result = (e as Error)?.message === "noname"
      ? { status: "not_found", message: "This store searches by item name. Add the item's name with Edit item, then refresh." }
      : { status: "error", message: friendly(e) };
  }
  return result;
}

// A plain website works too: if the site runs on a platform the checker knows, return its product search link.
async function detectSearchUrl(url: string): Promise<string> {
  if (/\{(barcode|upc12|ean13|name)\}/.test(url)) return url;
  let origin: string; try { origin = new URL(url).origin; } catch { return url; }
  try {
    const a = await safeFetch(`${origin}/api/Catalog/SearchTermAutoComplete?term=milk`, "application/json");
    if (typeof JSON.parse(a.text)?.productsJson === "string") return `${origin}/api/Catalog/SearchTermAutoComplete?term={name}`;
  } catch { /* not MCG */ }
  try {
    const b = await safeFetch(`${origin}/search/suggest.json?q=milk&resources[type]=product`, "application/json");
    if (JSON.parse(b.text)?.resources?.results) return `${origin}/search/suggest.json?q={name}&resources[type]=product&resources[limit]=10`;
  } catch { /* not Shopify */ }
  try {
    const c = await safeFetch(origin + "/");
    const id = c.text.match(/tenant\\*":\{\\*"id\\*":(\d+)/)?.[1];
    if (id && /cms-widgets|bnxtlvl|3hr-/i.test(c.text)) return `${new URL(c.url).origin}/api/services/supplier-ms/public/api/v1/groceries/_search?supplierId=${id}&query={name}&page=0&size=40`;
  } catch { /* not bnxtlvl */ }
  try {
    const h = await safeFetch(origin + "/");
    const rid = h.text.match(/cloudfront\.net\/retailers\/(\d+)\//)?.[1];
    if (rid && /ng-app="ZuZ"|self-point/i.test(h.text)) {
      const br = JSON.parse((await safeFetch(`${origin}/v2/retailers/${rid}/branches`, "application/json")).text);
      const bid = br?.branches?.[0]?.id;
      if (bid) return `${origin}/v2/retailers/${rid}/branches/${bid}/products?appId=4&query={name}&size=40&from=0`;
    }
  } catch { /* not Self-Point, or walled */ }
  return url;
}

// ---------- barcode database ----------
async function lookup(d: string) {
  try {
    const r = await safeFetch(`https://world.openfoodfacts.org/api/v2/product/${d}.json?fields=product_name,brands,quantity,image_front_url,image_url`, "application/json");
    const j = JSON.parse(r.text);
    if (j.status === 1 && j.product?.product_name) return { found: true, name: j.product.product_name, brand: j.product.brands?.split(",")[0]?.trim() || null,
      size: j.product.quantity || null, image: j.product.image_front_url || j.product.image_url || null };
  } catch { /* next */ }
  try {
    const r = await safeFetch(`https://api.upcitemdb.com/prod/trial/lookup?upc=${d}`, "application/json");
    const it = JSON.parse(r.text)?.items?.[0];
    if (it?.title) return { found: true, name: it.title, brand: it.brand || null, size: it.size || it.title.match(SIZE_RE)?.[1] || null, image: it.images?.[0] || null };
  } catch { /* none */ }
  return { found: false };
}

// ---------- one store check, saved ----------
async function doCheck(db: any, prod: any, store: any, force: boolean, owner: string, second = false, pages?: { url: string; text: string }[]) {
  const useFc = isBrowserStore(store) && !pages && !!FC_KEY;
  if (isBrowserStore(store) && !pages && !useFc) {
    // no Firecrawl key: tell the app which searches its helper should run in the browser
    const { data: others } = await db.from("pc_prices").select("product_name").eq("product_id", prod.id).eq("match", "exact").not("product_name", "is", null).limit(5);
    const extras = [...new Set((others || []).map((o: any) => o.product_name).filter(Boolean))] as string[];
    if (!prod.name && !extras.length) return { store_id: store.id, status: "not_found", message: "This store searches by item name. Add the item's name with Edit item, then refresh." };
    return { store_id: store.id, status: "needs_browser", requests: browserTargets(store.search_url, prod.barcode, prod.name || "", extras, prod.brand || "") };
  }
  const { data: existing } = await db.from("pc_prices").select("*").eq("product_id", prod.id).eq("store_id", store.id).maybeSingle();
  // throttle: one real check per item+store every 20 seconds
  // (the second round — searching with a name another store just matched — may run right away, once)
  const recent = existing?.last_attempt_at && Date.now() - new Date(existing.last_attempt_at).getTime() < 20000;
  if (recent && !(second && existing.match !== "exact" && existing.status !== "blocked" && existing.status !== "manual_only")) return existing;
  // a hand-entered price stays unless someone presses refresh on that store
  const keepManual = existing?.source === "manual" && !force;
  const pinned = existing?.pinned_url;
  const now = new Date().toISOString();
  let result: Record<string, unknown>;
  if (!pinned && !/\{(barcode|upc12|ean13|name)\}/.test(store.search_url)) {
    result = { status: existing?.price != null ? "found" : "manual_only", product_url: existing?.product_url || store.search_url,
      message: existing?.price != null ? null : "Prices for this store are entered by hand. Tap Enter price, or Open to look it up on their site." };
  } else {
    // names other stores already matched by barcode make the best extra searches
    const { data: others } = await db.from("pc_prices").select("product_name").eq("product_id", prod.id).eq("match", "exact").not("product_name", "is", null).limit(5);
    const extras = [...new Set((others || []).map((o: any) => o.product_name).filter(Boolean))] as string[];
    let provided: Map<string, string> | undefined;
    if (isBrowserStore(store) && !useFc) {
      // only accept results for searches on this store's own product search
      const prefix = String(store.search_url).split("{name}")[0];
      provided = new Map((pages || []).filter((p) => p && typeof p.url === "string" && p.url.startsWith(prefix) && p.url.length < 800 && typeof p.text === "string")
        .map((p) => [p.url, p.text.slice(0, MAX_BYTES)]));
    }
    if (useFc && !prod.name && !extras.length) {
      result = { status: "not_found", message: "This store searches by item name. Add the item's name with Edit item, then refresh." };
    } else if (useFc) {
      let url = ""; try { url = await spResolve(store.search_url); } catch { /* handled below */ }
      result = url ? await runCheck(url, prod.barcode, prod.name || "", null, extras, prod.brand || "", prod.size || null, undefined, true)
        : { status: "error", message: "Couldn't find this store's catalog through Firecrawl. Press Refresh to try again." };
    } else
    result = await runCheck(store.search_url, prod.barcode, prod.name || "", provided ? null : pinned || null, extras, prod.brand || "", prod.size || null, provided);
    if (provided && result.status === "blocked") result.message = "The store's site is still checking your browser. Open the store's site once in Chrome, then press Refresh.";
    if (keepManual && result.status === "found") result = { status: "found", message: null };
  }
  // a check that finds nothing clears the old automatic price, so a stale or wrong match can't linger
  if (result.status === "not_found" && existing?.source === "auto" && !existing?.pinned_url) Object.assign(result, { price: null, match: null, product_name: null, image_url: null, size: null });
  const row = { owner, product_id: prod.id, store_id: store.id, last_attempt_at: now, ...result };
  const { data: saved, error } = await db.from("pc_prices").upsert(row, { onConflict: "product_id,store_id" }).select().single();
  if (error) throw new Error("Couldn't save the price.");
  // no description yet? take it from the store that matched the barcode exactly
  if (result.match === "exact" && result.product_name && !prod.name) {
    const patch = { name: String(result.product_name).slice(0, 200), size: prod.size || result.size || null, image_url: prod.image_url || result.image_url || null };
    await db.from("pc_products").update(patch).eq("id", prod.id).is("name", null);
    Object.assign(prod, patch);
  }
  return saved;
}
// Round 2: stores that missed get searched again using the names the other stores matched by barcode.
const isAuto = (s: any) => /\{(barcode|upc12|ean13|name)\}/.test(s.search_url) && (!isBrowserStore(s) || !!FC_KEY);
async function secondRound(db: any, prod: any, stores: any[], results: any[], owner: string, started: number, budget: number) {
  if (!results.some((r) => r?.match === "exact")) return results;
  const out = [...results];
  const redo = stores.map((s, i) => ({ s, i })).filter(({ s, i }) => isAuto(s) && out[i] && out[i].match !== "exact" && out[i].match !== "pinned" &&
    out[i].source !== "manual" && ["not_found", "found"].includes(out[i].status));
  await pool(redo, 6, async ({ s, i }) => {
    if (Date.now() - started > budget) return;
    try { out[i] = await doCheck(db, prod, s, false, owner, true); } catch { /* keep round 1 */ }
  });
  return out;
}
async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]); }
  }));
  return out;
}
// fill in a missing item name/picture from the barcode databases (stores that search by name need it)
async function ensureInfo(db: any, prod: any) {
  if (prod.name) return prod;
  const info: any = await lookup(String(prod.barcode).replace(/\D/g, ""));
  if (!info.found) return prod;
  const patch = { name: info.name, brand: prod.brand || info.brand || null, size: prod.size || info.size || null, image_url: prod.image_url || info.image || null };
  const { data } = await db.from("pc_products").update(patch).eq("id", prod.id).select().single();
  return data || { ...prod, ...patch };
}

// ---------- main ----------
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  let body: any;
  try { body = await req.json(); } catch { return json({ error: "Bad request" }, 400); }
  const URL_ = Deno.env.get("SUPABASE_URL")!;
  const admin = createClient(URL_, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });

  // hourly re-check of items people asked to be notified about (called by the database scheduler)
  if (body.action === "cron_refresh") {
    const secret = req.headers.get("x-cron-secret") || "";
    const { data: ok } = await admin.rpc("pc_cron_secret_ok", { p: secret });
    if (!ok) return json({ error: "Not allowed" }, 403);
    const started = Date.now();
    const { data: orgs } = await admin.from("pc_members").select("org");
    const orgSet = [...new Set((orgs || []).map((o: any) => o.org))];
    const { data: alerts } = await admin.from("pc_alerts").select("product_id").eq("active", true).in("owner", orgSet.length ? orgSet : ["00000000-0000-0000-0000-000000000000"]).limit(5000);
    const ids = [...new Set((alerts || []).map((a: any) => a.product_id))];
    if (!ids.length) return json({ checked: 0 });
    const cutoff = new Date(Date.now() - 20 * 3600e3).toISOString();
    // least recently picked first, so no item can block the rest
    const { data: prods } = await admin.from("pc_products").select("*").in("id", ids).or(`cron_at.is.null,cron_at.lt.${cutoff}`).order("cron_at", { ascending: true, nullsFirst: true }).limit(12);
    const due = prods || [];
    if (due.length) await admin.from("pc_products").update({ cron_at: new Date().toISOString() }).in("id", due.map((p: any) => p.id));
    let checked = 0;
    for (const prod0 of due) {
      if (Date.now() - started > 100000) break; // stay well inside the time limit
      const prod = await ensureInfo(admin, prod0);
      const { data: stores } = await admin.from("pc_stores").select("*").eq("owner", prod.owner).eq("enabled", true);
      const auto = (stores || []).filter(isAuto);
      const r1 = await pool(auto, 5, async (s: any) => { try { const r = await doCheck(admin, prod, s, false, prod.owner); checked++; return r; } catch { return null; } });
      await secondRound(admin, prod, auto, r1, prod.owner, started, 100000);
    }
    return json({ products: due.length, checked });
  }

  // one store check asked for by the database itself (the version of the app that opens inside Claude).
  // Only the database knows the secret; the browser never sees it.
  if (body.action === "svc_check") {
    const secret = req.headers.get("x-cron-secret") || "";
    const { data: ok } = await admin.rpc("pc_cron_secret_ok", { p: secret });
    if (!ok) return json({ error: "Not allowed" }, 403);
    const [{ data: prod0 }, { data: store }] = await Promise.all([
      admin.from("pc_products").select("*").eq("id", String(body.product_id || "")).maybeSingle(),
      admin.from("pc_stores").select("*").eq("id", String(body.store_id || "")).maybeSingle(),
    ]);
    if (!prod0 || !store || prod0.owner !== store.owner) return json({ error: "Item or store not found" }, 404);
    try {
      const prod = await ensureInfo(admin, prod0);
      return json(await doCheck(admin, prod, store, !!body.force, prod.owner, !!body.second));
    } catch (e) { return json({ error: (e as Error).message }, 500); }
  }

  // everything else needs a signed-in user
  const sb = createClient(URL_, Deno.env.get("SUPABASE_ANON_KEY")!, {
    global: { headers: { Authorization: req.headers.get("Authorization") || "" } }, auth: { persistSession: false },
  });
  const { data: u } = await sb.auth.getUser();
  if (!u?.user) return json({ error: "Please sign in again." }, 401);
  const { data: me } = await admin.from("pc_members").select("*").eq("user_id", u.user.id).maybeSingle();
  if (!me) return json({ error: "Your account doesn't have access to the price checker yet. Ask your admin to add you." }, 403);
  const org = me.org;

  if (body.action === "lookup") {
    const code = String(body.barcode || "").replace(/\D/g, "");
    if (code.length < 6 || code.length > 14) return json({ error: "A barcode is 6 to 14 digits." }, 400);
    return json(await lookup(code));
  }

  if (body.action === "check") {
    const [{ data: prod }, { data: store }] = await Promise.all([
      sb.from("pc_products").select("*").eq("id", body.product_id).single(),
      sb.from("pc_stores").select("*").eq("id", body.store_id).single(),
    ]);
    if (!prod || !store) return json({ error: "Item or store not found" }, 404);
    const pages = Array.isArray(body.pages) ? body.pages.slice(0, 7) : undefined;
    try { return json(await doCheck(sb, prod, store, !!body.force, org, !!body.second, pages)); } catch (e) { return json({ error: (e as Error).message }, 500); }
  }

  // one item at every store in an area (used by the Excel bulk check)
  if (body.action === "check_product") {
    const { data: prod0 } = await sb.from("pc_products").select("*").eq("id", body.product_id).single();
    if (!prod0) return json({ error: "Item not found" }, 404);
    const prod = await ensureInfo(sb, prod0);
    let q = sb.from("pc_stores").select("*").eq("enabled", true);
    if (body.area_id) q = q.eq("area_id", body.area_id);
    const { data: stores } = await q;
    const started = Date.now();
    const prices = await pool(stores || [], 6, async (s: any) => {
      if (Date.now() - started > 80000) return { store_id: s.id, status: "error", message: "Took too long. Refresh this store on the item page." };
      try { return await doCheck(sb, prod, s, false, org); } catch (e) { return { store_id: s.id, status: "error", message: (e as Error).message }; }
    });
    const final = await secondRound(sb, prod, stores || [], prices, org, started, 85000);
    return json({ product: prod, prices: final });
  }

  if ((body.action === "detect" || body.action === "test") && me.role !== "admin") return json({ error: "Only an admin can set up stores." }, 403);
  if (body.action === "detect") {
    return json({ search_url: await detectSearchUrl(String(body.url || "").slice(0, 600)) });
  }
  if (body.action === "test") {
    const code = String(body.barcode || "").replace(/\D/g, "");
    if (code.length < 6 || code.length > 14) return json({ error: "A barcode is 6 to 14 digits." }, 400);
    const search_url = await detectSearchUrl(String(body.url || "").slice(0, 600));
    if (!/\{(barcode|upc12|ean13|name)\}/.test(search_url)) return json({ search_url, manual: true });
    const info: any = await lookup(code);
    const result = await runCheck(search_url, code, info.name || "", null);
    return json({ search_url, item_name: info.name || null, ...result });
  }

  // ---------- user management (team admins only) ----------
  if (["create_user", "update_user", "delete_user"].includes(body.action)) {
    if (me?.role !== "admin") return json({ error: "Only an admin can manage users." }, 403);
    const { data: orgAreas } = await admin.from("pc_areas").select("id").eq("owner", org);
    const validAreas = new Set((orgAreas || []).map((a: any) => a.id));
    const areaIds: string[] = Array.isArray(body.area_ids) ? body.area_ids.filter((a: string) => validAreas.has(a)) : [];
    const role = body.role === "admin" ? "admin" : "user";
    const name = String(body.name || "").trim().slice(0, 80) || null;
    const setAreas = async (uid: string) => {
      await admin.from("pc_member_areas").delete().eq("user_id", uid);
      if (areaIds.length) await admin.from("pc_member_areas").insert(areaIds.map((a) => ({ user_id: uid, area_id: a })));
    };

    if (body.action === "create_user") {
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: "Enter a valid email address." }, 400);
      if (password.length < 8) return json({ error: "The password needs at least 8 characters." }, 400);
      let uid: string | null = null, created = false;
      const { data: made, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { name } });
      if (made?.user) { uid = made.user.id; created = true; }
      else if (error && /already|registered|exists/i.test(error.message)) {
        // this email already has an account (maybe from another app): add them with their existing password
        for (let page = 1; page <= 20 && !uid; page++) {
          const { data: list } = await admin.auth.admin.listUsers({ page, perPage: 200 });
          const hit = list?.users?.find((x: any) => (x.email || "").toLowerCase() === email);
          if (hit) uid = hit.id;
          if (!list?.users?.length) break;
        }
      } else if (error) {
        return json({ error: /password/i.test(error.message) ? "The password needs at least 8 characters." : error.message }, 400);
      }
      if (!uid) return json({ error: "Couldn't create that user." }, 400);
      const { data: other } = await admin.from("pc_members").select("org").eq("user_id", uid).maybeSingle();
      if (other && other.org !== org) return json({ error: "That person already belongs to another team." }, 400);
      if (other) return json({ error: "That person is already a user. Use Edit to change them." }, 400);
      await admin.from("pc_members").upsert({ user_id: uid, org, role, name, email, created_by_pc: created }, { onConflict: "user_id" });
      await setAreas(uid);
      return json({ user_id: uid, existing_account: !created });
    }

    const uid = String(body.user_id || "");
    const { data: target } = await admin.from("pc_members").select("*").eq("user_id", uid).maybeSingle();
    if (!target || target.org !== org) return json({ error: "User not found." }, 404);

    if (body.action === "update_user") {
      if ("role" in body && role !== "admin" && (uid === u.user.id || uid === org)) return json({ error: uid === org ? "The team's owner always stays an admin." : "You can't remove your own admin access." }, 400);
      const patch: Record<string, unknown> = {};
      if ("role" in body) patch.role = role;
      if ("name" in body) patch.name = name;
      if (Object.keys(patch).length) await admin.from("pc_members").update(patch).eq("user_id", uid);
      if (Array.isArray(body.area_ids)) await setAreas(uid);
      if (body.password) {
        if (String(body.password).length < 8) return json({ error: "The password needs at least 8 characters." }, 400);
        if (!target.created_by_pc && uid !== u.user.id) return json({ error: "This person signs in with an account from another app, so their password can't be changed here." }, 400);
        const { error } = await admin.auth.admin.updateUserById(uid, { password: String(body.password) });
        if (error) return json({ error: error.message }, 400);
      }
      return json({ ok: true });
    }

    if (body.action === "delete_user") {
      if (uid === u.user.id) return json({ error: "You can't remove yourself." }, 400);
      if (uid === org) return json({ error: "The team's owner can't be removed." }, 400);
      await admin.from("pc_alerts").delete().eq("user_id", uid);
      await admin.from("pc_list").delete().eq("user_id", uid);
      await admin.from("pc_notifications").delete().eq("user_id", uid);
      await admin.from("pc_members").delete().eq("user_id", uid);
      if (target.created_by_pc) await admin.auth.admin.deleteUser(uid);
      return json({ ok: true });
    }
  }

  return json({ error: "Unknown action" }, 400);
});
