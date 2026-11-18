// Shelf Price Checker: hand-in point for price lists read in a real browser.
// Needs the short-lived token kept in the database; without it nothing is accepted.
import { createClient } from "npm:@supabase/supabase-js@2";
const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type", "Access-Control-Allow-Methods": "POST, OPTIONS" };
const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "text/plain" } });
function same(a: string, b: string) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  const raw = await req.text();
  if (raw.length > 1_500_000) return json({ error: "Too big" }, 413);
  let body: any; try { body = JSON.parse(raw); } catch { return json({ error: "Bad request" }, 400); }
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
  const { data: cfg } = await admin.from("pc_config").select("k,v").in("k", ["ingest_token", "ingest_until"]);
  const tok = cfg?.find((x: any) => x.k === "ingest_token")?.v || "", until = Date.parse(cfg?.find((x: any) => x.k === "ingest_until")?.v || "");
  if (!tok || tok.length < 32 || !(until > Date.now()) || !same(String(body.token || ""), tok)) return json({ error: "Not allowed" }, 403);
  const items = Array.isArray(body.items) ? body.items.slice(0, 2000) : [];
  const { data, error } = await admin.rpc("pc_ingest", { p_store: String(body.store_id || ""), p_items: items, p_started: String(body.started || ""), p_last: body.last === true });
  if (error) return json({ error: "Couldn't save" }, 400);
  return json({ ok: true, saved: data });
});
