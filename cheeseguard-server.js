// ===========================================================
//  CheeseGuard API Server v2.0
//  Node.js + Express — deploy to Render / Railway / Glitch
//
//  npm install express cors crypto uuid
//  node server.js
// ===========================================================

const express = require("express");
const cors    = require("cors");
const crypto  = require("crypto");
const { v4: uuidv4 } = require("uuid");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 3000;

// ── CONFIG ───────────────────────────────────────────────────────────────────

const ADMIN_PASSWORD          = process.env.ADMIN_PASS   || "changeme";
const MAX_VIOLATIONS_TO_KICK  = 3;
const SESSION_TTL_MS          = 1000 * 60 * 60; // 1hr

// ── STORES (swap for DB in production) ───────────────────────────────────────

// apiKeys: { [key]: { label, createdAt, active, gameId } }
const apiKeys = new Map();

// sessions: { [sessionId]: { apiKey, playerId, violations, lastSeen, pendingViolations[], pendingKicks[] } }
const sessions = new Map();

// bans: { [playerId]: { until, reason } }
const bans = new Map();

// ── MIDDLEWARE ───────────────────────────────────────────────────────────────

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"))); // serves dashboard

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────

function requireKey(req, res, next) {
  const key = req.headers["x-api-key"] || req.body?.key;
  if (!key || !apiKeys.has(key) || !apiKeys.get(key).active) {
    return res.status(401).json({ ok: false, error: "INVALID_KEY" });
  }
  req.apiKeyData = apiKeys.get(key);
  req.rawKey = key;
  next();
}

function requireSession(req, res, next) {
  const sid = req.headers["x-session-id"] || req.body?.sessionId;
  const sess = sessions.get(sid);
  if (!sess) return res.status(401).json({ ok: false, error: "INVALID_SESSION" });
  sess.lastSeen = Date.now();
  req.session = sess;
  req.sessionId = sid;
  next();
}

function requireAdmin(req, res, next) {
  if (req.headers["x-admin-password"] !== ADMIN_PASSWORD)
    return res.status(403).json({ ok: false, error: "FORBIDDEN" });
  next();
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

function generateKey() {
  return "cg-" + crypto.randomBytes(4).toString("hex") + "-" + crypto.randomBytes(4).toString("hex");
}

function isPlayerBanned(playerId) {
  const ban = bans.get(playerId);
  if (!ban) return false;
  if (Date.now() > ban.until) { bans.delete(playerId); return false; }
  return true;
}

function flagViolation(sess, sessId, reason, targetId) {
  const id = targetId || sessId;
  sess.violations = (sess.violations || 0) + 1;
  // queue it so /poll picks it up
  (sess.pendingViolations = sess.pendingViolations || []).push({ reason, playerId: id, ts: Date.now() });
  console.log(`[VIOLATION] ${id} (${sess.violations}/${MAX_VIOLATIONS_TO_KICK}) — ${reason}`);
  if (sess.violations >= MAX_VIOLATIONS_TO_KICK) {
    kickSession(sessId, `AUTO_KICK: ${reason}`);
  }
}

function kickSession(sessId, reason) {
  const sess = sessions.get(sessId);
  if (!sess) return;
  (sess.pendingKicks = sess.pendingKicks || []).push({ playerId: sess.playerId || sessId, reason });
  console.log(`[KICK] ${sess.playerId || sessId} — ${reason}`);
  setTimeout(() => sessions.delete(sessId), 5000);
}

// ── GAME ROUTES ───────────────────────────────────────────────────────────────

// Auth — exchange API key for session
app.post("/auth", requireKey, (req, res) => {
  const playerId = req.body.playerId || uuidv4();
  if (isPlayerBanned(playerId)) {
    return res.json({ ok: false, error: "BANNED" });
  }
  const sessionId = uuidv4();
  sessions.set(sessionId, {
    apiKey: req.rawKey,
    playerId,
    violations: 0,
    lastSeen: Date.now(),
    pendingViolations: [],
    pendingKicks: []
  });
  console.log(`[AUTH] key=${req.rawKey} player=${playerId} session=${sessionId}`);
  res.json({ ok: true, sessionId, playerId });
});

// Logout
app.post("/logout", requireKey, requireSession, (req, res) => {
  sessions.delete(req.sessionId);
  res.json({ ok: true });
});

// Poll — return queued violations/kicks for this session
app.get("/poll", requireKey, requireSession, (req, res) => {
  const sess = req.session;
  const violations = (sess.pendingViolations || []).splice(0);
  const kicks      = (sess.pendingKicks      || []).splice(0);
  res.json({ violations, kicks });
});

// Report action (fire-and-forget log)
app.post("/action", requireKey, requireSession, (req, res) => {
  const { action, data } = req.body;
  console.log(`[ACTION] ${req.session.playerId} → ${action} | ${JSON.stringify(data)}`);
  res.json({ ok: true });
});

// Validate action — server decides if it's legal
app.post("/validate", requireKey, requireSession, (req, res) => {
  const { action, data } = req.body;
  const sess = req.session;

  // ── VALIDATION RULES ── customize these for your game ──────────────────
  let valid   = true;
  let verdict = "APPROVED";

  // Example: can't deal more than 50 damage at once
  if (action === "DEAL_DAMAGE") {
    const dmg = Number(data?.amount || 0);
    if (dmg > 50) { valid = false; verdict = "DAMAGE_TOO_HIGH"; }
  }

  // Example: can't pickup items more than 1x per second (server-side timestamp check)
  if (action === "PICKUP") {
    const now = Date.now();
    if (sess._lastPickup && now - sess._lastPickup < 1000) {
      valid = false; verdict = "PICKUP_TOO_FAST";
    } else {
      sess._lastPickup = now;
    }
  }
  // ── END RULES ───────────────────────────────────────────────────────────

  if (!valid) flagViolation(sess, req.sessionId, verdict);
  res.json({ ok: true, valid, verdict });
});

// Client-reported violation
app.post("/violation", requireKey, requireSession, (req, res) => {
  const { reason, delta, targetId } = req.body;
  flagViolation(req.session, req.sessionId, reason || "CLIENT_REPORT", targetId);
  res.json({ ok: true });
});

// Kick a player (only from a host session)
app.post("/kick", requireKey, requireSession, (req, res) => {
  const { playerId, reason } = req.body;
  // Find session by playerId
  for (const [sid, sess] of sessions) {
    if (sess.playerId === playerId) { kickSession(sid, reason || "HOST_KICK"); break; }
  }
  res.json({ ok: true });
});

// Ban a player
app.post("/ban", requireKey, requireSession, (req, res) => {
  const { playerId, durationMins, reason } = req.body;
  const until = Date.now() + Number(durationMins || 60) * 60_000;
  bans.set(playerId, { until, reason: reason || "BANNED" });
  // Kick any live session
  for (const [sid, sess] of sessions) {
    if (sess.playerId === playerId) kickSession(sid, `BANNED: ${reason}`);
  }
  console.log(`[BAN] ${playerId} until ${new Date(until).toISOString()}`);
  res.json({ ok: true });
});

// ── ADMIN ROUTES (password protected) ────────────────────────────────────────

// Generate a new API key
app.post("/admin/keys", requireAdmin, (req, res) => {
  const key = generateKey();
  apiKeys.set(key, {
    label: req.body.label || "Unnamed",
    createdAt: new Date().toISOString(),
    active: true,
    gameId: req.body.gameId || ""
  });
  console.log(`[KEY_CREATED] ${key}`);
  res.json({ ok: true, key });
});

// List all keys
app.get("/admin/keys", requireAdmin, (req, res) => {
  const list = [...apiKeys.entries()].map(([key, data]) => ({
    key, ...data,
    activeSessions: [...sessions.values()].filter(s => s.apiKey === key).length
  }));
  res.json({ ok: true, keys: list });
});

// Revoke a key
app.delete("/admin/keys/:key", requireAdmin, (req, res) => {
  const k = req.params.key;
  if (apiKeys.has(k)) { apiKeys.get(k).active = false; }
  res.json({ ok: true });
});

// List active sessions
app.get("/admin/sessions", requireAdmin, (req, res) => {
  const list = [...sessions.entries()].map(([sid, s]) => ({
    sessionId: sid,
    playerId: s.playerId,
    violations: s.violations,
    lastSeen: new Date(s.lastSeen).toISOString(),
    apiKey: s.apiKey
  }));
  res.json({ ok: true, sessions: list });
});

// List bans
app.get("/admin/bans", requireAdmin, (req, res) => {
  const list = [...bans.entries()].map(([id, b]) => ({
    playerId: id, reason: b.reason, until: new Date(b.until).toISOString()
  }));
  res.json({ ok: true, bans: list });
});

// Admin kick
app.post("/admin/kick", requireAdmin, (req, res) => {
  const { sessionId, reason } = req.body;
  kickSession(sessionId, reason || "ADMIN_KICK");
  res.json({ ok: true });
});

// ── SESSION CLEANUP ───────────────────────────────────────────────────────────

setInterval(() => {
  const now = Date.now();
  for (const [sid, sess] of sessions) {
    if (now - sess.lastSeen > SESSION_TTL_MS) {
      sessions.delete(sid);
      console.log(`[SESSION_EXPIRED] ${sid}`);
    }
  }
}, 30_000);

// ── START ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => console.log(`[CheeseGuard] API server on http://localhost:${PORT}`));
