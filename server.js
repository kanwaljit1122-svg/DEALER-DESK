const express = require("express");
const { DatabaseSync } = require("node:sqlite");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, "dealer.db"));
db.exec("PRAGMA journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('admin','sales')), active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at INTEGER, user_id INTEGER, action TEXT, deal_id INTEGER, detail TEXT);
`);

try { db.exec("ALTER TABLE users ADD COLUMN perms TEXT"); } catch {}
const PAGE_KEYS = ["p_dash","p_deals","p_trade","p_ledger","p_fin","p_cust","p_rep","p_set"];
const ACT_KEYS = ["add","pay","manage","delete"];
const ALL_KEYS = [...PAGE_KEYS, ...ACT_KEYS, "lite"];
const DEFAULT_STAFF = { p_dash:1,p_deals:1,p_trade:1,p_ledger:1,p_fin:1,p_cust:1,p_rep:1,p_set:0, add:1,pay:1,manage:1,delete:0 };
function cleanPerms(p) {
  const o = {}; ALL_KEYS.forEach(k => o[k] = !!(p && p[k]));
  if (o.lite) { ALL_KEYS.forEach(k => { if (k !== "lite") o[k] = false; }); return o; }
  if (!PAGE_KEYS.some(k => o[k])) o.p_dash = true;
  return o;
}
function permsOf(u) {
  if (u.role === "admin") return Object.fromEntries(ALL_KEYS.map(k => [k, k !== "lite"]));
  try { return u.perms ? cleanPerms(JSON.parse(u.perms)) : cleanPerms(DEFAULT_STAFF); } catch { return cleanPerms(DEFAULT_STAFF); }
}

// Rename the old default display name
db.prepare("UPDATE users SET name='Kanwaljit' WHERE username='admin' AND name='Administrator'").run();
// First run: create admin account
if (!db.prepare("SELECT 1 FROM users LIMIT 1").get()) {
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(6).toString("hex");
  db.prepare("INSERT INTO users(username,name,hash,role) VALUES(?,?,?,'admin')")
    .run("admin", "Kanwaljit", bcrypt.hashSync(pw, 10));
  console.log(`\n== First run: admin created ==\n   username: admin\n   password: ${pw}\n   (change it after login)\n`);
}

const app = express();
app.use(express.json({ limit: "15mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ---- auth helpers
const SESSION_MS = 1000 * 60 * 60 * 24 * 14;
const cookieOf = (req, n) => (req.headers.cookie || "").split(/;\s*/).map(c => c.split("=")).find(c => c[0] === n)?.[1];
const attempts = new Map();
function limited(ip) {
  const now = Date.now(), a = (attempts.get(ip) || []).filter(t => now - t < 15 * 60000);
  attempts.set(ip, a);
  return a.length >= 10;
}
function auth(req, res, next) {
  const t = cookieOf(req, "sid");
  const row = t && db.prepare(`SELECT u.id,u.username,u.name,u.role,u.perms FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token=? AND s.expires>? AND u.active=1`).get(t, Date.now());
  if (!row) return res.status(401).json({ error: "Not logged in" });
  row.perms = permsOf(row); req.user = row; next();
}
const adminOnly = (req, res, next) => req.user.role === "admin" ? next() : res.status(403).json({ error: "Admin only" });
const log = (u, action, deal, detail) => db.prepare("INSERT INTO audit(at,user_id,action,deal_id,detail) VALUES(?,?,?,?,?)").run(Date.now(), u, action, deal, detail || "");

app.post("/api/login", (req, res) => {
  const ip = req.ip;
  if (limited(ip)) return res.status(429).json({ error: "Too many attempts. Try again later." });
  const { username = "", password = "" } = req.body || {};
  const u = db.prepare("SELECT * FROM users WHERE username=? AND active=1").get(String(username).trim().toLowerCase());
  if (!u || !bcrypt.compareSync(String(password), u.hash)) {
    attempts.get(ip).push(Date.now());
    return res.status(401).json({ error: "Wrong username or password" });
  }
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions VALUES(?,?,?)").run(token, u.id, Date.now() + SESSION_MS);
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_MS / 1000}${secure}`);
  res.json({ id: u.id, name: u.name, role: u.role, perms: permsOf(u) });
});
app.post("/api/logout", (req, res) => {
  const t = cookieOf(req, "sid"); if (t) db.prepare("DELETE FROM sessions WHERE token=?").run(t);
  res.setHeader("Set-Cookie", "sid=; Max-Age=0; Path=/"); res.json({ ok: true });
});
app.get("/api/me", auth, (req, res) => res.json(req.user));
app.post("/api/password", auth, (req, res) => {
  const { current = "", next = "" } = req.body || {};
  const u = db.prepare("SELECT hash FROM users WHERE id=?").get(req.user.id);
  if (!bcrypt.compareSync(current, u.hash)) return res.status(400).json({ error: "Current password is wrong" });
  if (next.length < 8) return res.status(400).json({ error: "New password must be 8+ characters" });
  db.prepare("UPDATE users SET hash=? WHERE id=?").run(bcrypt.hashSync(next, 10), req.user.id);
  res.json({ ok: true });
});

// ---- users (admin)
app.get("/api/users", auth, adminOnly, (req, res) =>
  res.json(db.prepare("SELECT id,username,name,role,active,perms FROM users ORDER BY name").all().map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, active: u.active, perms: permsOf(u) }))));
app.post("/api/users", auth, adminOnly, (req, res) => {
  const { username = "", name = "", password = "", role = "sales", perms } = req.body || {};
  const un = username.trim().toLowerCase();
  if (!un || !name.trim() || password.length < 8 || !["admin", "sales"].includes(role))
    return res.status(400).json({ error: "Need username, name, role and a password of 8+ characters" });
  try {
    const r = db.prepare("INSERT INTO users(username,name,hash,role,perms) VALUES(?,?,?,?,?)").run(un, name.trim(), bcrypt.hashSync(password, 10), role, JSON.stringify(cleanPerms(perms || DEFAULT_STAFF)));
    res.json({ id: r.lastInsertRowid });
  } catch { res.status(400).json({ error: "Username already exists" }); }
});
app.put("/api/users/:id", auth, adminOnly, (req, res) => {
  const id = +req.params.id, { active, password, perms } = req.body || {};
  if (id === req.user.id && active === 0) return res.status(400).json({ error: "You cannot deactivate yourself" });
  if (active !== undefined) db.prepare("UPDATE users SET active=? WHERE id=?").run(active ? 1 : 0, id);
  if (perms) db.prepare("UPDATE users SET perms=? WHERE id=?").run(JSON.stringify(cleanPerms(perms)), id);
  if (password) {
    if (password.length < 8) return res.status(400).json({ error: "Password must be 8+ characters" });
    db.prepare("UPDATE users SET hash=? WHERE id=?").run(bcrypt.hashSync(password, 10), id);
  }
  res.json({ ok: true });
});

// ---- shared app state (one JSON document + version for safe multi-user saving)
db.exec(`CREATE TABLE IF NOT EXISTS app_state(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, data TEXT NOT NULL, updated_at INTEGER, user_id INTEGER);
CREATE TABLE IF NOT EXISTS state_history(id INTEGER PRIMARY KEY, version INTEGER, data TEXT, at INTEGER, user_id INTEGER);`);
const stateRow = () => db.prepare("SELECT version,data FROM app_state WHERE id=1").get();
db.exec("CREATE TABLE IF NOT EXISTS acc_done(deal_id TEXT, key TEXT, at INTEGER, user_id INTEGER, PRIMARY KEY(deal_id,key))");
db.exec("CREATE TABLE IF NOT EXISTS handovers(id INTEGER PRIMARY KEY, deal_id TEXT NOT NULL, item_idx INTEGER NOT NULL, product TEXT, qty REAL NOT NULL, date TEXT NOT NULL, user_id INTEGER, at INTEGER)");
const istToday = () => new Date().toLocaleDateString("en-CA", { timeZone: process.env.TIMEZONE || "Asia/Kolkata" });
function handedFor(dealId) {
  const rows = db.prepare(`SELECT h.id,h.deal_id,h.item_idx,h.product,h.qty,h.date,u.name AS by_name FROM handovers h LEFT JOIN users u ON u.id=h.user_id ${dealId ? "WHERE h.deal_id=?" : ""} ORDER BY h.date,h.id`).all(...(dealId ? [dealId] : []));
  const map = {};
  rows.forEach(r => { ((map[r.deal_id] = map[r.deal_id] || {})[r.item_idx] = (map[r.deal_id][r.item_idx] || [])).push({ id: r.id, product: r.product, qty: r.qty, date: r.date, by: r.by_name || "" }); });
  return map;
}
const ACC_KEYS = ["hook", "bw", "ww", "dist", "hood", "draw"];
const PAPER_KEYS = ["p_inv", "p_dc", "p_ins"];
const slugA = s => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 30);
function otherKeys(d) {
  const seen = new Set(), out = [];
  String((d.acc && d.acc.other) || "").split(/[,;\n]/).map(x => x.trim()).filter(Boolean).forEach(t => { const k = slugA(t); if (!k || seen.has(k) || out.length >= 10) return; seen.add(k); out.push("o_" + k); });
  return out;
}
function accInfo() {
  const rows = db.prepare("SELECT deal_id,key,at FROM acc_done").all(), map = {}; let mx = 0;
  rows.forEach(r => { (map[r.deal_id] = map[r.deal_id] || {})[r.key] = 1; mx = Math.max(mx, r.at); });
  const hs = db.prepare("SELECT COUNT(*) n, COALESCE(MAX(id),0) m, COALESCE(MAX(at),0) t FROM handovers").get();
  return { map, stamp: rows.length + "." + mx + "|" + hs.n + "." + hs.m + "." + hs.t };
}
// Staff (lite) view: remove prices and payment history; keep only what staff need.
function liteState(st) {
  const n = v => +v || 0, cases = st.cases || [];
  const act = c => !["Rejected", "Cancelled"].includes(c.status);
  const expected = d => { const cs = cases.filter(c => c.deal === d.id); return cs.length ? cs.filter(act).reduce((s, c) => s + n(c.expected), 0) : n(d.financeExpected); };
  const pend = d => {
    const pays = d.payments || [];
    const net = Math.max(0, n(d.invoice) - n(d.discount) + n(d.other) + n(d.rc) + n(d.ins) - n(d.tradeIn));
    const rec = pays.filter(p => p.cleared).reduce((s, p) => s + n(p.amount), 0);
    const out = d.status === "Cancelled" ? 0 : Math.max(0, net - rec);
    const finRec = pays.filter(p => p.cleared && p.cat === "Finance Disbursement").reduce((s, p) => s + n(p.amount), 0);
    const fin = Math.min(out, Math.max(0, expected(d) - finRec));
    return { pendCust: Math.max(0, out - fin), pendFin: fin };
  };
  return { deals: (st.deals || []).map(d => ({
    id: d.id, date: d.date, deliv: d.deliv || "", cust: d.cust, mob: d.mob || "", village: d.village || "", status: d.status,
    items: (d.items && d.items.length ? d.items : [{ product: d.model, qty: 1 }]).map(i => ({ product: i.product, qty: i.qty })),
    acc: d.acc || {}, paper: d.paper || {}, ...pend(d) })) };
}
app.get("/api/state", auth, (req, res) => {
  const r = stateRow(), ai = accInfo(), lite = !!req.user.perms.lite;
  const ver = r ? r.version : 0;
  if (req.query.since !== undefined && +req.query.since === ver && req.query.acc === ai.stamp) return res.json({ version: ver, changed: false });
  let state = r ? JSON.parse(r.data) : null;
  if (state && lite) state = liteState(state);
  res.json({ version: ver, state, acc: ai.map, accStamp: ai.stamp, handed: handedFor(), lite, changed: true });
});
const canTick = u => u.role === "admin" || u.perms.lite || u.perms.add;
app.get("/api/handover/:deal", auth, (req, res) => res.json({ entries: handedFor(req.params.deal)[req.params.deal] || {}, stamp: accInfo().stamp }));
app.post("/api/handover", auth, (req, res) => {
  if (!canTick(req.user)) return res.status(403).json({ error: "Not allowed" });
  const { deal, item, qty, date } = req.body || {};
  const q = Math.round(Number(qty) * 100) / 100;
  if (!(q > 0)) return res.status(400).json({ error: "Enter a quantity above zero" });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(date || ""))) return res.status(400).json({ error: "Choose the handover date" });
  if (date > istToday()) return res.status(400).json({ error: "The handover date cannot be in the future" });
  const r = stateRow(), d = r && (JSON.parse(r.data).deals || []).find(x => x.id === deal);
  if (!d || d.status === "Cancelled") return res.status(400).json({ error: "Deal not found or cancelled" });
  const items = d.items && d.items.length ? d.items : [{ product: d.model, qty: 1 }], it = items[+item];
  if (!it) return res.status(400).json({ error: "Product not found in this deal" });
  const done = db.prepare("SELECT COALESCE(SUM(qty),0) s FROM handovers WHERE deal_id=? AND item_idx=? AND product=?").get(deal, +item, it.product).s;
  const left = Math.round(((+it.qty || 0) - done) * 100) / 100;
  if (q > left + 1e-9) return res.status(400).json({ error: left > 0 ? `Only ${left} left to hand over for this product` : "This product is already fully handed over" });
  const x = db.prepare("INSERT INTO handovers(deal_id,item_idx,product,qty,date,user_id,at) VALUES(?,?,?,?,?,?,?)").run(deal, +item, it.product, q, date, req.user.id, Date.now());
  log(req.user.id, "handover", null, `${deal} item ${item} qty ${q} on ${date}`);
  res.json({ ok: true, id: Number(x.lastInsertRowid), entries: handedFor(deal)[deal] || {}, stamp: accInfo().stamp });
});
app.delete("/api/handover/:id", auth, (req, res) => {
  const row = db.prepare("SELECT * FROM handovers WHERE id=?").get(+req.params.id);
  if (!row) return res.status(404).json({ error: "Entry not found" });
  if (req.user.role !== "admin" && row.user_id !== req.user.id) return res.status(403).json({ error: "You can remove only your own entries" });
  db.prepare("DELETE FROM handovers WHERE id=?").run(row.id);
  log(req.user.id, "handover-remove", null, `${row.deal_id} item ${row.item_idx} qty ${row.qty}`);
  res.json({ ok: true, entries: handedFor(row.deal_id)[row.deal_id] || {}, stamp: accInfo().stamp });
});
app.post("/api/acc", auth, (req, res) => {
  const p = req.user.perms;
  if (!(req.user.role === "admin" || p.lite || p.add)) return res.status(403).json({ error: "Not allowed" });
  const { deal, key, done } = req.body || {};
  const r = stateRow(), d = r && (JSON.parse(r.data).deals || []).find(x => x.id === deal);
  const okAcc = d && ACC_KEYS.includes(key) && d.acc && d.acc[key] && d.acc[key] !== "No";
  const okPap = d && d.status !== "Cancelled" && PAPER_KEYS.includes(key);
  const okOth = d && d.status !== "Cancelled" && /^o_/.test(key) && otherKeys(d).includes(key);
  if (!okAcc && !okPap && !okOth) return res.status(400).json({ error: "That item is not part of this deal" });
  if (done) db.prepare("INSERT OR REPLACE INTO acc_done(deal_id,key,at,user_id) VALUES(?,?,?,?)").run(deal, key, Date.now(), req.user.id);
  else db.prepare("DELETE FROM acc_done WHERE deal_id=? AND key=?").run(deal, key);
  log(req.user.id, "accessory", null, `${deal} ${key} ${done ? "provided" : "unticked"}`);
  res.json({ ok: true, stamp: accInfo().stamp });
});
app.put("/api/state", auth, (req, res) => {
  if (req.user.perms.lite || !ACT_KEYS.some(k => req.user.perms[k])) return res.status(403).json({ error: "You have view-only access" });
  const { version, state } = req.body || {};
  if (!state || !["deals", "cases", "trade", "otherPays"].every(k => Array.isArray(state[k])))
    return res.status(400).json({ error: "Invalid data" });
  const data = JSON.stringify(state);
  db.exec("BEGIN IMMEDIATE");
  try {
    const cur = stateRow(), curV = cur ? cur.version : 0;
    if (+version !== curV) { db.exec("ROLLBACK"); return res.status(409).json({ error: "Changed by someone else", version: curV }); }
    const nv = curV + 1, now = Date.now();
    if (cur) db.prepare("UPDATE app_state SET version=?,data=?,updated_at=?,user_id=? WHERE id=1").run(nv, data, now, req.user.id);
    else db.prepare("INSERT INTO app_state(id,version,data,updated_at,user_id) VALUES(1,?,?,?,?)").run(nv, data, now, req.user.id);
    db.prepare("INSERT INTO state_history(version,data,at,user_id) VALUES(?,?,?,?)").run(nv, data, now, req.user.id);
    db.prepare("DELETE FROM state_history WHERE id NOT IN (SELECT id FROM state_history ORDER BY id DESC LIMIT 300)").run();
    db.exec("COMMIT");
    res.json({ version: nv });
  } catch (e) { try { db.exec("ROLLBACK"); } catch {} res.status(500).json({ error: "Save failed" }); }
});
app.get("/api/backup", auth, adminOnly, (req, res) => {
  const r = stateRow();
  res.setHeader("Content-Disposition", "attachment; filename=dealer-backup-" + new Date().toISOString().slice(0, 10) + ".json");
  res.type("json").send(r ? r.data : "{}");
});

setInterval(() => db.prepare("DELETE FROM sessions WHERE expires<?").run(Date.now()), 3600000).unref();
app.listen(PORT, () => console.log(`Dealer Desk running on port ${PORT}`));
