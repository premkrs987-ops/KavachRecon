// KavachRecon — API routes
import express from 'express';
import zlib from 'node:zlib';
import {
  q, q1, run, now, uid, audit, getSetting, setSetting,
} from './db.js';
import { createSession, destroySession, requireAuth, ensureDefaultUsers } from './auth.js';
import { ScanEngine, buildSummary } from './scanner/engine.js';
import { generateScanReport, diffScans, findPreviousScan } from './report/pdf.js';
import { generateExecutiveSummary, explainFinding, askScan, surfaceSummary } from './ai/gemini.js';

const router = express.Router();

/* ================= AUTH ================= */
router.get('/auth/users', (req, res) => {
  res.json(q(`SELECT id, name, email, role FROM users ORDER BY created_at`));
});
router.post('/auth/login', (req, res) => {
  const { user_id } = req.body || {};
  let user = user_id ? q1(`SELECT * FROM users WHERE id = ?`, [user_id]) : q1(`SELECT * FROM users ORDER BY created_at LIMIT 1`);
  if (!user) return res.status(404).json({ error: 'no_user' });
  const token = createSession(res, user.id, req);
  audit(user.name, 'auth.login', 'user', user.id, { passwordless: true });
  // token is returned so embedded previews (blocked cookies) can use header auth
  res.json({ id: user.id, name: user.name, email: user.email, role: user.role, token });
});
// Silent session bootstrap — the SPA has no login screen; it calls this on boot.
router.post('/auth/auto', (req, res) => {
  let user = q1(`SELECT * FROM users ORDER BY created_at LIMIT 1`);
  if (!user) { ensureDefaultUsers(); user = q1(`SELECT * FROM users ORDER BY created_at LIMIT 1`); }
  if (!user) return res.status(500).json({ error: 'no_user', message: 'Could not initialise default users.' });
  const token = createSession(res, user.id, req);
  audit(user.name, 'auth.session_started', 'user', user.id, { passwordless: true, silent: true });
  res.json({ id: user.id, name: user.name, email: user.email, role: user.role, token });
});
router.post('/auth/logout', (req, res) => { destroySession(req, res); res.json({ ok: true }); });
router.get('/auth/me', (req, res) => res.json({ user: req.user || null }));

/* ================= WORKSPACES ================= */
router.get('/workspaces', requireAuth, (req, res) => {
  const rows = q(`SELECT * FROM workspaces ORDER BY created_at`);
  res.json(rows.map(w => ({ ...w, targets: q1(`SELECT COUNT(*) n FROM targets WHERE workspace_id = ?`, [w.id]).n, scans: q1(`SELECT COUNT(*) n FROM scans WHERE workspace_id = ?`, [w.id]).n })));
});
router.post('/workspaces', requireAuth, (req, res) => {
  const { name, description = '' } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: 'name_required' });
  const id = uid('ws');
  run(`INSERT INTO workspaces (id, name, description, is_demo, created_by, created_at, updated_at) VALUES (?,?,?,0,?,?,?)`,
    [id, name.trim(), description, req.user.id, now(), now()]);
  audit(req.user.name, 'workspace.create', 'workspace', id, { name });
  res.status(201).json(q1(`SELECT * FROM workspaces WHERE id = ?`, [id]));
});
router.patch('/workspaces/:id', requireAuth, (req, res) => {
  const w = q1(`SELECT * FROM workspaces WHERE id = ?`, [req.params.id]);
  if (!w) return res.status(404).json({ error: 'not_found' });
  const { name = w.name, description = w.description } = req.body || {};
  run(`UPDATE workspaces SET name = ?, description = ?, updated_at = ? WHERE id = ?`, [name.trim() || w.name, description, now(), w.id]);
  audit(req.user.name, 'workspace.update', 'workspace', w.id, { name });
  res.json(q1(`SELECT * FROM workspaces WHERE id = ?`, [w.id]));
});
router.delete('/workspaces/:id', requireAuth, (req, res) => {
  const w = q1(`SELECT * FROM workspaces WHERE id = ?`, [req.params.id]);
  if (!w) return res.status(404).json({ error: 'not_found' });
  if (w.is_demo) return res.status(400).json({ error: 'demo_workspace', message: 'Purge demo data from Settings instead.' });
  run(`DELETE FROM workspaces WHERE id = ?`, [w.id]);
  audit(req.user.name, 'workspace.delete', 'workspace', w.id, { name: w.name });
  res.json({ ok: true });
});

/* ================= TARGETS ================= */
router.get('/targets', requireAuth, (req, res) => {
  const ws = req.query.workspace_id;
  if (!ws) return res.status(400).json({ error: 'workspace_required' });
  const rows = q(`SELECT * FROM targets WHERE workspace_id = ? ORDER BY created_at DESC`, [ws]);
  res.json(rows.map(t => ({
    ...t,
    scope_rules: q(`SELECT * FROM scope_rules WHERE target_id = ? ORDER BY created_at`, [t.id]),
    scan_count: q1(`SELECT COUNT(*) n FROM scans WHERE target_id = ?`, [t.id]).n,
    last_scan: q1(`SELECT status, created_at FROM scans WHERE target_id = ? ORDER BY created_at DESC LIMIT 1`, [t.id]),
  })));
});
router.post('/targets', requireAuth, (req, res) => {
  const { workspace_id, identifier, type, label = '', notes = '' } = req.body || {};
  if (!workspace_id || !identifier?.trim() || !type) return res.status(400).json({ error: 'missing_fields' });
  const clean = identifier.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const detected = type === 'AUTO' ? (/\/\d{1,2}$/.test(clean) || (clean.includes('/') && clean.split('/')[1].match(/^\d{1,2}$/)) ? 'CIDR' : (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean) || clean.includes(':') ? 'IP' : 'DOMAIN')) : type;
  if (!['DOMAIN', 'IP', 'CIDR'].includes(detected)) return res.status(400).json({ error: 'bad_type' });
  if (detected === 'IP' && !/^\d{1,3}(\.\d{1,3}){3}$/.test(clean) && !clean.includes(':')) return res.status(400).json({ error: 'bad_ip' });
  if (detected === 'CIDR' && !/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(clean)) return res.status(400).json({ error: 'bad_cidr' });
  const id = uid('tgt');
  run(`INSERT INTO targets (id, workspace_id, identifier, type, label, notes, active_confirmed, created_at, updated_at) VALUES (?,?,?,?,?,?,0,?,?)`,
    [id, workspace_id, clean, detected, label, notes, now(), now()]);
  audit(req.user.name, 'target.create', 'target', id, { identifier: clean, type: detected });
  res.status(201).json({ ...q1(`SELECT * FROM targets WHERE id = ?`, [id]), scope_rules: [] });
});
router.patch('/targets/:id', requireAuth, (req, res) => {
  const t = q1(`SELECT * FROM targets WHERE id = ?`, [req.params.id]);
  if (!t) return res.status(404).json({ error: 'not_found' });
  const { label = t.label, notes = t.notes, active_confirmed } = req.body || {};
  const confirmed = typeof active_confirmed === 'boolean' ? (active_confirmed ? 1 : 0) : t.active_confirmed;
  if (typeof active_confirmed === 'boolean') {
    audit(req.user.name, active_confirmed ? 'target.active_confirmed' : 'target.active_revoked', 'target', t.id, { identifier: t.identifier });
  }
  run(`UPDATE targets SET label = ?, notes = ?, active_confirmed = ?, updated_at = ? WHERE id = ?`, [label, notes, confirmed, now(), t.id]);
  audit(req.user.name, 'target.update', 'target', t.id, {});
  res.json(q1(`SELECT * FROM targets WHERE id = ?`, [t.id]));
});
router.delete('/targets/:id', requireAuth, (req, res) => {
  const t = q1(`SELECT * FROM targets WHERE id = ?`, [req.params.id]);
  if (!t) return res.status(404).json({ error: 'not_found' });
  run(`DELETE FROM targets WHERE id = ?`, [t.id]);
  audit(req.user.name, 'target.delete', 'target', t.id, { identifier: t.identifier });
  res.json({ ok: true });
});
router.post('/targets/:id/rules', requireAuth, (req, res) => {
  const t = q1(`SELECT * FROM targets WHERE id = ?`, [req.params.id]);
  if (!t) return res.status(404).json({ error: 'not_found' });
  const { kind, pattern, pattern_type, reason = '' } = req.body || {};
  if (!['INCLUDE', 'EXCLUDE'].includes(kind) || !pattern?.trim() || !['DOMAIN', 'IP', 'CIDR', 'WILDCARD'].includes(pattern_type)) {
    return res.status(400).json({ error: 'bad_rule' });
  }
  const id = uid('srule');
  run(`INSERT INTO scope_rules (id, target_id, kind, pattern, pattern_type, reason, created_at) VALUES (?,?,?,?,?,?,?)`,
    [id, t.id, kind, pattern.trim().toLowerCase(), pattern_type, reason, now()]);
  audit(req.user.name, 'scope_rule.create', 'target', t.id, { kind, pattern, pattern_type });
  res.status(201).json(q1(`SELECT * FROM scope_rules WHERE id = ?`, [id]));
});
router.delete('/targets/:id/rules/:rid', requireAuth, (req, res) => {
  const r = q1(`SELECT * FROM scope_rules WHERE id = ? AND target_id = ?`, [req.params.rid, req.params.id]);
  if (!r) return res.status(404).json({ error: 'not_found' });
  run(`DELETE FROM scope_rules WHERE id = ?`, [r.id]);
  audit(req.user.name, 'scope_rule.delete', 'target', req.params.id, { pattern: r.pattern });
  res.json({ ok: true });
});

/* ================= SCANS ================= */
router.get('/scans', requireAuth, (req, res) => {
  const { workspace_id, target_id, status, limit = 100 } = req.query;
  let sql = `SELECT s.*, t.identifier AS target_identifier, t.type AS target_type, w.name AS workspace_name, w.is_demo AS ws_demo FROM scans s JOIN targets t ON t.id = s.target_id JOIN workspaces w ON w.id = s.workspace_id WHERE 1=1`;
  const params = [];
  if (workspace_id) { sql += ` AND s.workspace_id = ?`; params.push(workspace_id); }
  if (target_id) { sql += ` AND s.target_id = ?`; params.push(target_id); }
  if (status) { sql += ` AND s.status = ?`; params.push(status); }
  sql += ` ORDER BY s.created_at DESC LIMIT ?`; params.push(Math.min(+limit || 100, 300));
  res.json(q(sql, params).map(s => ({ ...s, summary: JSON.parse(s.summary || '{}') })));
});
router.get('/scans/:id', requireAuth, (req, res) => {
  const s = q1(`SELECT s.*, t.identifier AS target_identifier, t.type AS target_type, w.name AS workspace_name, w.is_demo AS ws_demo FROM scans s JOIN targets t ON t.id = s.target_id JOIN workspaces w ON w.id = s.workspace_id WHERE s.id = ?`, [req.params.id]);
  if (!s) return res.status(404).json({ error: 'not_found' });
  res.json({
    ...s,
    summary: JSON.parse(s.summary || '{}'),
    config: JSON.parse(s.config || '{}'),
    modules: q(`SELECT * FROM scan_modules WHERE scan_id = ? ORDER BY order_idx`, [s.id]),
    parent: s.parent_scan_id ? q1(`SELECT id, name, status, finished_at FROM scans WHERE id = ?`, [s.parent_scan_id]) : findPreviousScan(s)?.id ? q1(`SELECT id, name, status, finished_at FROM scans WHERE id = ?`, [findPreviousScan(s).id]) : null,
  });
});
router.post('/scans', requireAuth, (req, res) => {
  const { target_id, name, mode, config = {}, parent_scan_id = null, confirm_active = false } = req.body || {};
  const t = q1(`SELECT * FROM targets WHERE id = ?`, [target_id]);
  if (!t) return res.status(404).json({ error: 'target_not_found' });
  if (!name?.trim()) return res.status(400).json({ error: 'name_required' });
  let finalMode = mode === 'ACTIVE_CONFIRMED' ? 'ACTIVE_CONFIRMED' : 'PASSIVE_ONLY';
  if (finalMode === 'ACTIVE_CONFIRMED' && !(confirm_active === true && t.active_confirmed === 1)) {
    return res.status(400).json({ error: 'active_not_confirmed', message: 'Active reconnaissance requires explicit confirmation on both the scan request and the target record.' });
  }
  const id = uid('scan');
  run(`INSERT INTO scans (id, workspace_id, target_id, name, mode, status, config, parent_scan_id, created_by, created_at) VALUES (?,?,?,?,?,'QUEUED',?,?,?,?)`,
    [id, t.workspace_id, t.id, name.trim(), finalMode, JSON.stringify(config), parent_scan_id, req.user.id, now()]);
  audit(req.user.name, `scan.create (${finalMode})`, 'scan', id, { name, target: t.identifier });
  ScanEngine.launch(id);
  res.status(201).json(q1(`SELECT * FROM scans WHERE id = ?`, [id]));
});
router.post('/scans/:id/cancel', requireAuth, (req, res) => {
  ScanEngine.cancel(req.params.id, req.user.name);
  res.json({ ok: true });
});
router.delete('/scans/:id', requireAuth, (req, res) => {
  const s = q1(`SELECT * FROM scans WHERE id = ?`, [req.params.id]);
  if (!s) return res.status(404).json({ error: 'not_found' });
  if (['QUEUED', 'RUNNING'].includes(s.status)) return res.status(400).json({ error: 'scan_running', message: 'Cancel the scan before deleting it.' });
  run(`DELETE FROM findings WHERE scan_id = ?`, [s.id]);
  run(`DELETE FROM evidence WHERE scan_id = ?`, [s.id]);
  for (const tbl of ['dns_records', 'host_ports', 'web_observations', 'endpoints', 'js_routes', 'js_secrets', 'technologies', 'perimeter', 'posture', 'scan_modules']) {
    if (['js_routes', 'js_secrets'].includes(tbl)) {
      run(`DELETE FROM ${tbl} WHERE js_id IN (SELECT id FROM js_resources WHERE scan_id = ?)`, [s.id]);
    } else run(`DELETE FROM ${tbl} WHERE scan_id = ?`, [s.id]);
  }
  run(`DELETE FROM js_resources WHERE scan_id = ?`, [s.id]);
  run(`DELETE FROM ai_outputs WHERE scan_id = ?`, [s.id]);
  run(`DELETE FROM scans WHERE id = ?`, [s.id]);
  audit(req.user.name, 'scan.delete', 'scan', s.id, { name: s.name });
  res.json({ ok: true });
});
router.post('/scans/:id/rerun', requireAuth, (req, res) => {
  const s = q1(`SELECT * FROM scans WHERE id = ?`, [req.params.id]);
  if (!s) return res.status(404).json({ error: 'not_found' });
  const id = uid('scan');
  run(`INSERT INTO scans (id, workspace_id, target_id, name, mode, status, config, parent_scan_id, created_by, created_at) VALUES (?,?,?,?,?,'QUEUED',?,?,?,?)`,
    [id, s.workspace_id, s.target_id, `${s.name.replace(/ \(rerun.*\)$/, '')} (rerun ${new Date().toISOString().slice(5, 16).replace('T', ' ')})`, s.mode, s.config, s.id, req.user.id, now()]);
  audit(req.user.name, 'scan.rerun', 'scan', id, { from: s.id, mode: s.mode });
  ScanEngine.launch(id);
  res.status(201).json(q1(`SELECT * FROM scans WHERE id = ?`, [id]));
});

/* ---------- scan data ---------- */
const scanData = {
  dns: (id) => q(`SELECT * FROM dns_records WHERE scan_id = ? ORDER BY type, name`, [id]),
  network: (id) => q(`SELECT * FROM host_ports WHERE scan_id = ? ORDER BY host, port`, [id]),
  web: (id) => q(`SELECT * FROM web_observations WHERE scan_id = ? ORDER BY url`, [id]),
  endpoints: (id) => q(`SELECT * FROM endpoints WHERE scan_id = ? ORDER BY classification, url`, [id]),
  js: (id) => ({
    resources: q(`SELECT r.*, (SELECT COUNT(*) FROM js_routes rt WHERE rt.js_id = r.id) routes, (SELECT COUNT(*) FROM js_secrets s WHERE s.js_id = r.id AND s.dismissed = 0) secrets FROM js_resources r WHERE r.scan_id = ?`, [id]),
    secrets: q(`SELECT s.*, r.url FROM js_secrets s JOIN js_resources r ON r.id = s.js_id WHERE r.scan_id = ?`, [id]),
    routes: q(`SELECT rt.*, r.url FROM js_routes rt JOIN js_resources r ON r.id = rt.js_id WHERE r.scan_id = ? LIMIT 400`, [id]),
  }),
  tech: (id) => q(`SELECT * FROM technologies WHERE scan_id = ? ORDER BY category, name`, [id]),
  perimeter: (id) => q(`SELECT * FROM perimeter WHERE scan_id = ? ORDER BY kind`, [id]),
  posture: (id) => q(`SELECT * FROM posture WHERE scan_id = ? ORDER BY url, kind`, [id]),
  evidence: (id) => q(`SELECT id, module_key, asset_id, kind, source, summary, content, hash, collected_at FROM evidence WHERE scan_id = ? ORDER BY collected_at`, [id]),
};
router.get('/scans/:id/data/:kind', requireAuth, (req, res) => {
  const fn = scanData[req.params.kind];
  if (!fn) return res.status(400).json({ error: 'bad_kind', kinds: Object.keys(scanData) });
  res.json(typeof fn === 'function' && req.params.kind === 'js' ? fn(req.params.id) : fn(req.params.id));
});
router.get('/scans/:id/compare/:other', requireAuth, (req, res) => {
  const a = q1(`SELECT * FROM scans WHERE id = ?`, [req.params.id]);
  const b = q1(`SELECT * FROM scans WHERE id = ?`, [req.params.other]);
  if (!a || !b) return res.status(404).json({ error: 'not_found' });
  res.json({ current: a.id, baseline: b.id, diff: diffScans(b, a) });
});

/* ================= ASSETS ================= */
router.get('/assets', requireAuth, (req, res) => {
  const { workspace_id, type, search, status, origin, limit = 300, offset = 0 } = req.query;
  if (!workspace_id) return res.status(400).json({ error: 'workspace_required' });
  let sql = `SELECT * FROM assets WHERE workspace_id = ?`; const params = [workspace_id];
  if (type) { sql += ` AND type = ?`; params.push(type); }
  if (status) { sql += ` AND status = ?`; params.push(status); }
  if (origin) { sql += ` AND origin = ?`; params.push(origin); }
  if (search) { sql += ` AND (key LIKE ? OR value LIKE ?)`; params.push(`%${search}%`, `%${search}%`); }
  sql += ` AND verification != 'FALSE_POSITIVE' ORDER BY last_seen DESC LIMIT ? OFFSET ?`;
  params.push(Math.min(+limit || 300, 1000), +offset || 0);
  const rows = q(sql, params);
  const counts = q(`SELECT type, COUNT(*) n FROM assets WHERE workspace_id = ? AND verification != 'FALSE_POSITIVE' GROUP BY type`, [workspace_id]);
  res.json({ items: rows.map(a => ({ ...a, meta: JSON.parse(a.meta || '{}'), evidence_count: q1(`SELECT COUNT(*) n FROM evidence WHERE asset_id = ?`, [a.id]).n })), total: q1(`SELECT COUNT(*) n FROM assets WHERE workspace_id = ? AND verification != 'FALSE_POSITIVE'`, [workspace_id]).n, counts });
});
router.get('/assets/:id', requireAuth, (req, res) => {
  const a = q1(`SELECT * FROM assets WHERE id = ?`, [req.params.id]);
  if (!a) return res.status(404).json({ error: 'not_found' });
  res.json({
    ...a, meta: JSON.parse(a.meta || '{}'),
    evidence: q(`SELECT id, module_key, kind, source, summary, content, collected_at FROM evidence WHERE asset_id = ? ORDER BY collected_at DESC LIMIT 60`, [a.id]),
    edges_out: q(`SELECT e.relation, a2.* FROM asset_edges e JOIN assets a2 ON a2.id = e.dst_id WHERE e.src_id = ?`, [a.id]),
    edges_in: q(`SELECT e.relation, a1.* FROM asset_edges e JOIN assets a1 ON a1.id = e.src_id WHERE e.dst_id = ?`, [a.id]),
    findings: q(`SELECT id, title, classification, severity, risk_score, status FROM findings WHERE asset_id = ?`, [a.id]),
  });
});
router.patch('/assets/:id', requireAuth, (req, res) => {
  const a = q1(`SELECT * FROM assets WHERE id = ?`, [req.params.id]);
  if (!a) return res.status(404).json({ error: 'not_found' });
  const { verification } = req.body || {};
  if (!['UNVERIFIED', 'VERIFIED', 'FALSE_POSITIVE', 'RETIRED'].includes(verification)) return res.status(400).json({ error: 'bad_verification' });
  run(`UPDATE assets SET verification = ? WHERE id = ?`, [verification, a.id]);
  audit(req.user.name, `asset.${verification.toLowerCase()}`, 'asset', a.id, { key: a.key });
  res.json(q1(`SELECT * FROM assets WHERE id = ?`, [a.id]));
});

/* ================= FINDINGS ================= */
router.get('/findings', requireAuth, (req, res) => {
  const { workspace_id, scan_id, classification, severity, status = 'ALL', search, limit = 400 } = req.query;
  let sql = `SELECT f.*, s.name AS scan_name, s.mode AS scan_mode FROM findings f JOIN scans s ON s.id = f.scan_id WHERE 1=1`; const params = [];
  if (workspace_id) { sql += ` AND f.workspace_id = ?`; params.push(workspace_id); }
  if (scan_id) { sql += ` AND f.scan_id = ?`; params.push(scan_id); }
  if (classification) { sql += ` AND f.classification = ?`; params.push(classification); }
  if (severity) { sql += ` AND f.severity = ?`; params.push(severity); }
  if (status && status !== 'ALL') sql += ` AND f.status = ?`, params.push(status);
  if (search) { sql += ` AND (f.title LIKE ? OR f.asset_label LIKE ?)`; params.push(`%${search}%`, `%${search}%`); }
  sql += ` ORDER BY f.risk_score DESC LIMIT ?`; params.push(Math.min(+limit || 400, 1000));
  const rows = q(sql, params);
  const counts = {
    classification: q(`SELECT classification, COUNT(*) n FROM findings ${workspace_id ? 'WHERE workspace_id = ?' : ''} GROUP BY classification`, ...(workspace_id ? [[workspace_id]] : [])),
    severity: q(`SELECT severity, COUNT(*) n FROM findings ${workspace_id ? 'WHERE workspace_id = ?' : ''} GROUP BY severity`, ...(workspace_id ? [[workspace_id]] : [])),
  };
  res.json({ items: rows.map(f => ({ ...f, evidence_ids: JSON.parse(f.evidence_ids || '[]'), meta: JSON.parse(f.meta || '{}') })), counts });
});
router.get('/findings/:id', requireAuth, (req, res) => {
  const f = q1(`SELECT * FROM findings WHERE id = ?`, [req.params.id]);
  if (!f) return res.status(404).json({ error: 'not_found' });
  const ids = JSON.parse(f.evidence_ids || '[]');
  const evidence = ids.length ? q(`SELECT * FROM evidence WHERE id IN (${ids.map(() => '?').join(',')})`, ...ids) : [];
  res.json({ ...f, evidence_ids: ids, meta: JSON.parse(f.meta || '{}'), evidence });
});
router.patch('/findings/:id', requireAuth, (req, res) => {
  const f = q1(`SELECT * FROM findings WHERE id = ?`, [req.params.id]);
  if (!f) return res.status(404).json({ error: 'not_found' });
  const { status } = req.body || {};
  if (!['OPEN', 'VERIFIED', 'RESOLVED', 'RISK_ACCEPTED', 'FALSE_POSITIVE'].includes(status)) return res.status(400).json({ error: 'bad_status' });
  run(`UPDATE findings SET status = ?, updated_at = ? WHERE id = ?`, [status, now(), f.id]);
  // propagate verification to related js_secrets
  if (f.category === 'SECRET_EXPOSURE') {
    const meta = JSON.parse(f.meta || '{}');
    if (meta.secret_id && status === 'VERIFIED') run(`UPDATE js_secrets SET verified = 1 WHERE id = ?`, [meta.secret_id]);
    if (meta.secret_id && status === 'FALSE_POSITIVE') run(`UPDATE js_secrets SET dismissed = 1 WHERE id = ?`, [meta.secret_id]);
  }
  audit(req.user.name, `finding.${status.toLowerCase()}`, 'finding', f.id, { title: f.title });
  res.json(q1(`SELECT * FROM findings WHERE id = ?`, [f.id]));
});

/* ================= GRAPH ================= */
router.get('/graph', requireAuth, (req, res) => {
  const { workspace_id, scan_id } = req.query;
  if (!workspace_id) return res.status(400).json({ error: 'workspace_required' });
  let nodeFilter = `workspace_id = ? AND verification != 'FALSE_POSITIVE'`; const params = [workspace_id];
  if (scan_id) {
    nodeFilter = `id IN (SELECT DISTINCT asset_id FROM evidence WHERE scan_id = ? AND asset_id IS NOT NULL) AND verification != 'FALSE_POSITIVE'`;
    params.length = 0; params.push(scan_id);
  }
  const nodes = q(`SELECT id, type, key, value, status, origin, confidence, first_seen, last_seen FROM assets WHERE ${nodeFilter} LIMIT 900`, params);
  const ids = nodes.map(n => n.id);
  const edges = ids.length ? q(`SELECT e.* FROM asset_edges e WHERE e.workspace_id = ? AND e.src_id IN (${ids.map(() => '?').join(',')}) AND e.dst_id IN (${ids.map(() => '?').join(',')}) LIMIT 1500`, [workspace_id, ...ids, ...ids]) : [];
  res.json({ nodes, edges });
});

/* ================= DASHBOARD ================= */
router.get('/dashboard', requireAuth, (req, res) => {
  const ws = req.query.workspace_id;
  if (!ws) return res.status(400).json({ error: 'workspace_required' });
  const c = (sql, ...p) => q1(sql, p)?.n || 0;
  const demo = q1(`SELECT is_demo FROM workspaces WHERE id = ?`, [ws])?.is_demo === 1;
  const latestScans = q(`SELECT s.id, s.name, s.mode, s.status, s.created_at, s.finished_at, s.is_demo, t.identifier AS target FROM scans s JOIN targets t ON t.id = s.target_id WHERE s.workspace_id = ? ORDER BY s.created_at DESC LIMIT 8`, [ws]);
  const latestScanIds = latestScans.map(s => `'${s.id}'`).join(',');
  const moduleStatus = latestScanIds ? q(`SELECT m.status, COUNT(*) n FROM scan_modules m WHERE m.scan_id IN (${latestScanIds}) GROUP BY m.status`) : [];
  const sev = q(`SELECT severity, COUNT(*) n FROM findings WHERE workspace_id = ? AND status IN ('OPEN','VERIFIED','RISK_ACCEPTED') GROUP BY severity`, [ws]);
  const classification = q(`SELECT classification, COUNT(*) n FROM findings WHERE workspace_id = ? AND status IN ('OPEN','VERIFIED','RISK_ACCEPTED') GROUP BY classification`, [ws]);
  const recentChanges = q(`SELECT a.type, a.key, a.first_seen, a.last_seen, a.origin FROM assets a WHERE a.workspace_id = ? ORDER BY a.last_seen DESC LIMIT 10`, [ws]);
  res.json({
    is_demo_workspace: !!demo,
    totals: {
      assets: c(`SELECT COUNT(*) n FROM assets WHERE workspace_id = ? AND verification != 'FALSE_POSITIVE'`, ws),
      live_hosts: c(`SELECT COUNT(DISTINCT ip) n FROM host_ports hp JOIN scans s ON s.id = hp.scan_id WHERE s.workspace_id = ? AND hp.state IN ('OPEN','OPEN_UNVERIFIED')`, ws),
      domains: c(`SELECT COUNT(*) n FROM assets WHERE workspace_id = ? AND type = 'DOMAIN' AND verification != 'FALSE_POSITIVE'`, ws),
      subdomains: c(`SELECT COUNT(*) n FROM assets WHERE workspace_id = ? AND type = 'SUBDOMAIN' AND verification != 'FALSE_POSITIVE'`, ws),
      ips: c(`SELECT COUNT(*) n FROM assets WHERE workspace_id = ? AND type = 'IP' AND verification != 'FALSE_POSITIVE'`, ws),
      open_ports: c(`SELECT COUNT(*) n FROM host_ports hp JOIN scans s ON s.id = hp.scan_id WHERE s.workspace_id = ? AND hp.state IN ('OPEN','OPEN_UNVERIFIED')`, ws),
      services: c(`SELECT COUNT(DISTINCT service) n FROM host_ports hp JOIN scans s ON s.id = hp.scan_id WHERE s.workspace_id = ? AND hp.service IS NOT NULL AND hp.state IN ('OPEN','OPEN_UNVERIFIED')`, ws),
      web_apps: c(`SELECT COUNT(DISTINCT w.url) n FROM web_observations w JOIN scans s ON s.id = w.scan_id WHERE s.workspace_id = ? AND w.ok = 1`, ws),
      endpoints: c(`SELECT COUNT(*) n FROM endpoints e JOIN scans s ON s.id = e.scan_id WHERE s.workspace_id = ?`, ws),
      technologies: c(`SELECT COUNT(DISTINCT t.name) n FROM technologies t JOIN scans s ON s.id = t.scan_id WHERE s.workspace_id = ?`, ws),
      dns_records: c(`SELECT COUNT(*) n FROM dns_records d JOIN scans s ON s.id = d.scan_id WHERE s.workspace_id = ?`, ws),
      findings: c(`SELECT COUNT(*) n FROM findings WHERE workspace_id = ? AND status IN ('OPEN','VERIFIED','RISK_ACCEPTED')`, ws),
      review_items: c(`SELECT COUNT(*) n FROM findings WHERE workspace_id = ? AND classification IN ('MANUAL_REVIEW','HEURISTIC') AND status = 'OPEN'`, ws),
      evidence: c(`SELECT COUNT(*) n FROM evidence WHERE workspace_id = ?`, ws),
      scans: c(`SELECT COUNT(*) n FROM scans WHERE workspace_id = ?`, ws),
      js_secrets: c(`SELECT COUNT(*) n FROM js_secrets sc JOIN js_resources r ON r.id = sc.js_id JOIN scans s ON s.id = r.scan_id WHERE s.workspace_id = ? AND sc.dismissed = 0`, ws),
    },
    severity: Object.fromEntries(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s => [s, sev.find(x => x.severity === s)?.n || 0])),
    classification: Object.fromEntries(classification.map(x => [x.classification, x.n])),
    module_status: Object.fromEntries(moduleStatus.map(m => [m.status, m.n])),
    latest_scans: latestScans,
    recent_changes: recentChanges,
  });
});

/* ================= AI ================= */
router.get('/ai/outputs', requireAuth, (req, res) => {
  const { scan_id, workspace_id } = req.query;
  let sql = `SELECT id, scan_id, workspace_id, kind, model, prompt_summary, status, created_at FROM ai_outputs WHERE 1=1`; const p = [];
  if (scan_id) { sql += ` AND scan_id = ?`; p.push(scan_id); }
  if (workspace_id) { sql += ` AND workspace_id = ?`; p.push(workspace_id); }
  sql += ` ORDER BY created_at DESC LIMIT 50`;
  res.json(q(sql, ...p));
});
router.get('/ai/outputs/:id', requireAuth, (req, res) => {
  const o = q1(`SELECT * FROM ai_outputs WHERE id = ?`, [req.params.id]);
  if (!o) return res.status(404).json({ error: 'not_found' });
  res.json(o);
});
router.post('/ai/scan/:id/summary', requireAuth, async (req, res) => {
  audit(req.user.name, 'ai.exec_summary', 'scan', req.params.id, {});
  const r = await generateExecutiveSummary(req.params.id, req.body?.model);
  res.status(r.ok ? 201 : 502).json(r);
});
router.post('/ai/scan/:id/ask', requireAuth, async (req, res) => {
  const { question } = req.body || {};
  if (!question?.trim()) return res.status(400).json({ error: 'question_required' });
  audit(req.user.name, 'ai.ask', 'scan', req.params.id, { question: question.slice(0, 120) });
  const r = await askScan(req.params.id, question.trim(), req.body?.model);
  res.status(r.ok ? 201 : 502).json(r);
});
router.post('/ai/finding/:id/explain', requireAuth, async (req, res) => {
  const r = await explainFinding(req.params.id, req.body?.model);
  res.status(r.ok ? 201 : 502).json(r);
});
router.post('/ai/workspace/:id/surface', requireAuth, async (req, res) => {
  const r = await surfaceSummary(req.params.id, req.body?.model);
  res.status(r.ok ? 201 : 502).json(r);
});

/* ================= AUDIT & SETTINGS ================= */
router.get('/audit', requireAuth, (req, res) => {
  const { workspace_id, limit = 120 } = req.query;
  res.json(q(`SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?`, [Math.min(+limit || 120, 500)]));
});
router.get('/settings', requireAuth, (req, res) => {
  const key = getSetting('gemini_api_key');
  res.json({
    gemini_api_key: key ? `${key.slice(0, 6)}…${key.slice(-4)}` : null,
    gemini_api_key_set: !!key,
    gemini_model: getSetting('gemini_model', 'gemini-2.0-flash'),
    versions: { engine: '1.0', builder: '@premkrs' },
  });
});
router.put('/settings', requireAuth, (req, res) => {
  const { gemini_api_key, gemini_model } = req.body || {};
  if (gemini_api_key !== undefined) setSetting('gemini_api_key', gemini_api_key === '' ? '' : gemini_api_key.trim());
  if (gemini_model) setSetting('gemini_model', gemini_model);
  audit(req.user.name, 'settings.update', 'settings', null, { gemini_key_changed: gemini_api_key !== undefined, model: gemini_model });
  const key = getSetting('gemini_api_key');
  res.json({ gemini_api_key: key ? `${key.slice(0, 6)}…${key.slice(-4)}` : null, gemini_api_key_set: !!key, gemini_model: getSetting('gemini_model', 'gemini-2.0-flash') });
});
router.post('/settings/ai/test', requireAuth, async (req, res) => {
  const { surfaceSummary: ss } = await import('./ai/gemini.js');
  const ws = q1(`SELECT id FROM workspaces ORDER BY created_at LIMIT 1`);
  if (!ws) return res.status(400).json({ ok: false, message: 'No workspace exists to test against.' });
  const r = await ss(ws.id);
  res.json(r.ok ? { ok: true, message: 'Gemini reachable — test summary generated.', id: r.id } : { ok: false, message: r.message });
});

/* ================= DEMO DATA ================= */
router.post('/demo/reseed', requireAuth, async (req, res) => {
  if (q1(`SELECT COUNT(*) n FROM workspaces WHERE is_demo = 1`).n) return res.status(400).json({ error: 'exists', message: 'Demo workspace already exists.' });
  const { seedDemoWorkspace } = await import('./seed/seed.js');
  seedDemoWorkspace();
  audit(req.user.name, 'demo.reseed', 'workspace', null, {});
  res.json({ ok: true });
});
router.post('/demo/purge', requireAuth, (req, res) => {
  const ws = q1(`SELECT * FROM workspaces WHERE is_demo = 1`);
  if (!ws) return res.json({ ok: true, purged: false });
  run(`DELETE FROM workspaces WHERE id = ?`, [ws.id]);
  run(`DELETE FROM findings WHERE is_demo = 1`);
  audit(req.user.name, 'demo.purge', 'workspace', ws.id, { name: ws.name });
  res.json({ ok: true, purged: true });
});

/* ================= EXPORTS ================= */
router.get('/scans/:id/export/pdf', requireAuth, async (req, res) => {
  const s = q1(`SELECT id FROM scans WHERE id = ?`, [req.params.id]);
  if (!s) return res.status(404).json({ error: 'not_found' });
  audit(req.user.name, 'export.pdf', 'scan', s.id, {});
  await generateScanReport(s.id, res);
});
router.get('/scans/:id/export/json', requireAuth, (req, res) => {
  const s = q1(`SELECT * FROM scans WHERE id = ?`, [req.params.id]);
  if (!s) return res.status(404).json({ error: 'not_found' });
  const payload = {
    meta: { platform: 'KavachRecon', builder: '@premkrs', exported_at: now(), disclaimer: 'Contains only data collected by KavachRecon during the recorded scan.' },
    scan: { ...s, summary: JSON.parse(s.summary || '{}'), config: JSON.parse(s.config || '{}') },
    target: q1(`SELECT * FROM targets WHERE id = ?`, [s.target_id]),
    modules: q(`SELECT * FROM scan_modules WHERE scan_id = ? ORDER BY order_idx`, [s.id]),
    findings: q(`SELECT * FROM findings WHERE scan_id = ?`, [s.id]),
    ...Object.fromEntries(Object.entries(scanData).map(([k, fn]) => [k, fn(s.id)])),
  };
  audit(req.user.name, 'export.json', 'scan', s.id, {});
  res.setHeader('Content-Disposition', `attachment; filename="KavachRecon_${sanitize(s.name)}.json"`);
  res.json(payload);
});
router.get('/scans/:id/export/assets.csv', requireAuth, (req, res) => {
  const s = q1(`SELECT * FROM scans WHERE id = ?`, [req.params.id]);
  if (!s) return res.status(404).json({ error: 'not_found' });
  const rows = q(`SELECT DISTINCT a.* FROM assets a JOIN evidence e ON e.asset_id = a.id AND e.scan_id = ? ORDER BY a.type, a.key`, [s.id]);
  const csv = toCsv(['type', 'key', 'value', 'status', 'origin', 'confidence', 'verification', 'first_seen', 'last_seen'], rows);
  sendCsv(res, `KavachRecon_assets_${sanitize(s.name)}.csv`, csv);
  audit(req.user.name, 'export.assets_csv', 'scan', s.id, {});
});
router.get('/scans/:id/export/findings.csv', requireAuth, (req, res) => {
  const s = q1(`SELECT * FROM scans WHERE id = ?`, [req.params.id]);
  if (!s) return res.status(404).json({ error: 'not_found' });
  const rows = q(`SELECT finding_key, title, category, classification, severity, risk_score, confidence, asset_label, status, description, impact, recommendation, created_at FROM findings WHERE scan_id = ? ORDER BY risk_score DESC`, [s.id]);
  sendCsv(res, `KavachRecon_findings_${sanitize(s.name)}.csv`, toCsv(Object.keys(rows[0] || { id: '' }), rows));
  audit(req.user.name, 'export.findings_csv', 'scan', s.id, {});
});
router.get('/workspaces/:id/export/assets.csv', requireAuth, (req, res) => {
  const rows = q(`SELECT * FROM assets WHERE workspace_id = ? AND verification != 'FALSE_POSITIVE' ORDER BY type, key`, [req.params.id]);
  sendCsv(res, `KavachRecon_workspace_assets.csv`, toCsv(['type', 'key', 'value', 'status', 'origin', 'confidence', 'verification', 'first_seen', 'last_seen'], rows));
  audit(req.user.name, 'export.workspace_assets_csv', 'workspace', req.params.id, {});
});
router.get('/scans/:id/export/evidence.zip', requireAuth, (req, res) => {
  const s = q1(`SELECT * FROM scans WHERE id = ?`, [req.params.id]);
  if (!s) return res.status(404).json({ error: 'not_found' });
  audit(req.user.name, 'export.evidence_package', 'scan', s.id, {});
  const manifest = {
    platform: 'KavachRecon', builder: '@premkrs', scan: s.id, generated_at: now(),
    note: 'Each evidence record includes its SHA-256 content hash for tamper-evidence.',
  };
  const files = [
    { name: 'manifest.json', data: JSON.stringify(manifest, null, 2) },
    { name: 'evidence.json', data: JSON.stringify(scanData.evidence(s.id), null, 2) },
    { name: 'modules.json', data: JSON.stringify(q(`SELECT * FROM scan_modules WHERE scan_id = ?`, [s.id]), null, 2) },
    { name: 'findings.json', data: JSON.stringify(q(`SELECT * FROM findings WHERE scan_id = ?`, [s.id]), null, 2) },
    { name: 'dns_records.json', data: JSON.stringify(scanData.dns(s.id), null, 2) },
    { name: 'host_ports.json', data: JSON.stringify(scanData.network(s.id), null, 2) },
    { name: 'web_observations.json', data: JSON.stringify(scanData.web(s.id), null, 2) },
    { name: 'endpoints.json', data: JSON.stringify(scanData.endpoints(s.id), null, 2) },
    { name: 'technologies.json', data: JSON.stringify(scanData.tech(s.id), null, 2) },
    { name: 'perimeter.json', data: JSON.stringify(scanData.perimeter(s.id), null, 2) },
    { name: 'posture.json', data: JSON.stringify(scanData.posture(s.id), null, 2) },
  ];
  const zip = buildStoreZip(files);
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="KavachRecon_evidence_${sanitize(s.name)}.zip"`);
  res.send(zip);
});

/* ---------- helpers ---------- */
function toCsv(headers, rows) {
  const esc = (v) => {
    const s = v === null || v === undefined ? '' : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return '\ufeff' + headers.join(',') + '\n' + rows.map(r => headers.map(h => esc(r[h])).join(',')).join('\n');
}
function sendCsv(res, filename, csv) {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(csv);
}
function sanitize(s) { return String(s).replace(/[^\w.-]+/g, '_').slice(0, 40) || 'scan'; }

function buildStoreZip(files) {
  const chunks = []; const central = []; let offset = 0;
  const crcTable = (() => { const t = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
  const crc32 = (buf) => { let c = 0 ^ -1; for (let i = 0; i < buf.length; i++) c = (c >>> 8) ^ crcTable[(c ^ buf[i]) & 0xff]; return (c ^ -1) >>> 0; };
  for (const f of files) {
    const data = Buffer.from(f.data, 'utf8');
    const nameBuf = Buffer.from(f.name);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0, 6); local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10); local.writeUInt16LE(0, 12); local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(nameBuf.length, 26); local.writeUInt16LE(0, 28);
    chunks.push(local, nameBuf, data);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0); cen.writeUInt16LE(20, 4); cen.writeUInt16LE(20, 6); cen.writeUInt16LE(0, 8); cen.writeUInt16LE(0, 10);
    cen.writeUInt16LE(0, 12); cen.writeUInt16LE(0, 14); cen.writeUInt32LE(crc, 16); cen.writeUInt32LE(data.length, 20); cen.writeUInt32LE(data.length, 24);
    cen.writeUInt16LE(nameBuf.length, 28); cen.writeUInt16LE(0, 30); cen.writeUInt16LE(0, 32); cen.writeUInt16LE(0, 34);
    cen.writeUInt16LE(0, 36); cen.writeUInt32LE(0, 38); cen.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([cen, nameBuf]));
    offset += 30 + nameBuf.length + data.length;
  }
  const cdStart = offset;
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(0, 4); eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(cdStart, 16); eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...chunks, cd, eocd]);
}

export default router;
