// KavachRecon — session auth. Per product decision: no passwords; users identify
// themselves by selecting a persona on the login screen (single-tenant tool usage).
// Three concurrent mechanisms so sign-in works everywhere (direct hosting, HTTPS,
// and embedded/iframe previews that block SameSite=Lax or all third-party cookies):
//   1) Authorization: Bearer token (returned by /auth/login) — always works
//   2) kr_session cookie (SameSite=Lax) — direct same-site hosting
//   3) kr_session_ns cookie (SameSite=None; Secure) — embedded iframe contexts
import crypto from 'node:crypto';
import { q, q1, run, now, uid } from './db.js';

const COOKIE = 'kr_session';
const COOKIE_NS = 'kr_session_ns';

export function ensureDefaultUsers() {
  const n = q1(`SELECT COUNT(*) n FROM users`).n;
  if (n === 0) {
    run(`INSERT INTO users (id, name, email, role, created_at) VALUES (?,?,?,?,?)`,
      [uid('usr'), 'Security Analyst', 'analyst@kavachrecon.local', 'analyst', now()]);
    run(`INSERT INTO users (id, name, email, role, created_at) VALUES (?,?,?,?,?)`,
      [uid('usr'), 'Demo Lead', 'lead@kavachrecon.local', 'lead', now()]);
  }
}

/** Creates a session row + sets cookies. Returns the token for the login response. */
export function createSession(res, userId, req) {
  const token = crypto.randomBytes(24).toString('hex');
  const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();
  run(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)`, [token, userId, now(), expires]);
  const maxAge = 60 * 60 * 24 * 30;
  const host = (req?.headers?.['x-forwarded-proto'] || req?.socket?.encrypted) ? true : false;
  // SameSite=None requires Secure; set it whenever the request looks HTTPS-ish (proxy or TLS).
  // Browsers ignore/reject None without Secure, and reject Secure on plain http (except localhost).
  const cookies = [`${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`];
  if (host) cookies.push(`${COOKIE_NS}=${token}; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=${maxAge}`);
  res.setHeader('Set-Cookie', cookies);
  return token;
}

export function destroySession(req, res) {
  const token = bearerToken(req) || parseCookie(req)[COOKIE] || parseCookie(req)[COOKIE_NS];
  if (token) run(`DELETE FROM sessions WHERE token = ?`, [token]);
  res.setHeader('Set-Cookie', [
    `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
    `${COOKIE_NS}=; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=0`,
  ]);
}

function parseCookie(req) {
  const h = req.headers.cookie || '';
  return Object.fromEntries(h.split(';').map(p => p.trim().split('=').map(decodeURIComponent)).filter(a => a[0]));
}
function bearerToken(req) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

export function sessionMiddleware(req, res, next) {
  const token = bearerToken(req) || parseCookie(req)[COOKIE] || parseCookie(req)[COOKIE_NS];
  req.user = null; req.token = null;
  if (token) {
    const s = q1(`SELECT * FROM sessions WHERE token = ?`, [token]);
    if (s && s.expires_at > now()) {
      req.user = q1(`SELECT id, name, email, role FROM users WHERE id = ?`, [s.user_id]);
      if (req.user) req.token = token;
    }
  }
  next();
}

export function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'authentication_required', message: 'Sign in to continue.' });
  next();
}
