// KavachRecon — session auth. Per product decision: no passwords; users identify
// themselves by selecting a persona on the login screen (single-tenant tool usage).
// Sessions work via HttpOnly cookie (direct hosting) AND via Authorization: Bearer
// token (embedded/iframe previews where third-party cookies are blocked).
import crypto from 'node:crypto';
import { q, q1, run, now, uid } from './db.js';

const COOKIE = 'kr_session';

export function ensureDefaultUsers() {
  const n = q1(`SELECT COUNT(*) n FROM users`).n;
  if (n === 0) {
    run(`INSERT INTO users (id, name, email, role, created_at) VALUES (?,?,?,?,?)`,
      [uid('usr'), 'Security Analyst', 'analyst@kavachrecon.local', 'analyst', now()]);
    run(`INSERT INTO users (id, name, email, role, created_at) VALUES (?,?,?,?,?)`,
      [uid('usr'), 'Demo Lead', 'lead@kavachrecon.local', 'lead', now()]);
  }
}

/** Creates a session row. Returns the token so the login response can hand it to the SPA. */
export function createSession(res, userId) {
  const token = crypto.randomBytes(24).toString('hex');
  const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();
  run(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)`, [token, userId, now(), expires]);
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}`);
  return token;
}

export function destroySession(req, res) {
  const token = bearerToken(req) || parseCookie(req)[COOKIE];
  if (token) run(`DELETE FROM sessions WHERE token = ?`, [token]);
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
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
  const token = bearerToken(req) || parseCookie(req)[COOKIE];
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
