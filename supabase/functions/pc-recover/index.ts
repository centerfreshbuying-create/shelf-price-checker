// Shelf Price Checker: one-time password reset link for an existing member.
// Only the database can call this (it holds the secret); nothing here is reachable from the website.
import { createClient } from "npm:@supabase/supabase-js@2";
const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
Deno.serve(async (req) => {
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  let body: any; try { body = await req.json(); } catch { return json({ error: "Bad request" }, 400); }
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
  const { data: ok } = await admin.rpc("pc_cron_secret_ok", { p: req.headers.get("x-cron-secret") || "" });
  if (!ok) return json({ error: "Not allowed" }, 403);
  const id = String(body.user_id || "");
  const { data: m } = await admin.from("pc_members").select("user_id").eq("user_id", id).maybeSingle();
  if (!m) return json({ error: "Not a member" }, 404);
  const { data: u } = await admin.auth.admin.getUserById(id);
  if (!u?.user?.email) return json({ error: "No email" }, 404);
  const { data, error } = await admin.auth.admin.generateLink({ type: "recovery", email: u.user.email });
  if (error || !data?.properties?.hashed_token) return json({ error: "Couldn't make a link" }, 500);
  return json({ token_hash: data.properties.hashed_token });
});
