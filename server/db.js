// KavachRecon — database layer (node:sqlite, zero native deps)
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.KR_DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
export const DB_PATH = path.join(DATA_DIR, 'kavachrecon.db');

export const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

export const now = () => new Date().toISOString();
export const uid = (p = 'id') => `${p}_${crypto.randomBytes(9).toString('hex')}`;
export const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL DEFAULT 'analyst', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '',
  is_demo INTEGER DEFAULT 0, created_by TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  identifier TEXT NOT NULL, type TEXT NOT NULL CHECK(type IN ('DOMAIN','IP','CIDR')),
  label TEXT DEFAULT '', notes TEXT DEFAULT '', active_confirmed INTEGER DEFAULT 0,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scope_rules (
  id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(kind IN ('INCLUDE','EXCLUDE')),
  pattern TEXT NOT NULL, pattern_type TEXT NOT NULL CHECK(pattern_type IN ('DOMAIN','IP','CIDR','WILDCARD')),
  reason TEXT DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  name TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN ('PASSIVE_ONLY','ACTIVE_CONFIRMED')),
  status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED','RUNNING','COMPLETED','COMPLETED_WITH_FAILURES','FAILED','CANCELLED')),
  config TEXT NOT NULL DEFAULT '{}',
  is_demo INTEGER DEFAULT 0,
  parent_scan_id TEXT,
  created_by TEXT, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  summary TEXT DEFAULT '{}', cancel_requested INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scan_modules (
  id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  module_key TEXT NOT NULL, name TEXT NOT NULL, order_idx INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED','RUNNING','COMPLETED','COMPLETED_NO_RESULTS','FAILED','SKIPPED','NOT_APPLICABLE')),
  items_count INTEGER DEFAULT 0, duration_ms INTEGER DEFAULT 0,
  error TEXT, detail TEXT DEFAULT '{}', started_at TEXT, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  scan_id TEXT, type TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
  parent_id TEXT, status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','UNREACHABLE','REMOVED','UNKNOWN')),
  origin TEXT NOT NULL DEFAULT 'SCAN' CHECK(origin IN ('SCAN','DEMO_SEED','USER')),
  confidence TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(confidence IN ('LOW','MEDIUM','HIGH')),
  verification TEXT NOT NULL DEFAULT 'UNVERIFIED' CHECK(verification IN ('UNVERIFIED','VERIFIED','FALSE_POSITIVE','RETIRED')),
  meta TEXT DEFAULT '{}',
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  UNIQUE(workspace_id, type, key)
);
CREATE TABLE IF NOT EXISTS asset_edges (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, src_id TEXT NOT NULL, dst_id TEXT NOT NULL,
  relation TEXT NOT NULL, scan_id TEXT, UNIQUE(workspace_id, src_id, dst_id, relation)
);
CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY, scan_id TEXT, workspace_id TEXT,
  module_key TEXT NOT NULL, asset_id TEXT, kind TEXT NOT NULL, source TEXT NOT NULL,
  summary TEXT NOT NULL, content TEXT DEFAULT '{}', hash TEXT NOT NULL,
  collected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dns_records (
  id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, asset_id TEXT, domain TEXT NOT NULL,
  type TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL, ttl INTEGER,
  meta TEXT DEFAULT '{}', collected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS host_ports (
  id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, asset_id TEXT, host TEXT NOT NULL, ip TEXT,
  port INTEGER NOT NULL, protocol TEXT NOT NULL DEFAULT 'tcp',
  state TEXT NOT NULL CHECK(state IN ('OPEN','OPEN_UNVERIFIED','CLOSED','FILTERED','UNKNOWN')),
  service TEXT, banner TEXT, version TEXT, confidence TEXT DEFAULT 'MEDIUM',
  evidence_id TEXT, collected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS web_observations (
  id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, asset_id TEXT, url TEXT NOT NULL,
  final_url TEXT, status_code INTEGER, ok INTEGER, redirect_chain TEXT DEFAULT '[]',
  title TEXT, server TEXT, content_type TEXT, response_ms INTEGER, headers TEXT DEFAULT '{}',
  tls TEXT, screenshot_path TEXT, evidence_id TEXT, collected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS endpoints (
  id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, asset_id TEXT, url TEXT NOT NULL,
  classification TEXT NOT NULL DEFAULT 'PUBLIC',
  status_code INTEGER, verified INTEGER DEFAULT 0, evidence_id TEXT,
  note TEXT DEFAULT '', collected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS js_resources (
  id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, asset_id TEXT, url TEXT NOT NULL,
  bytes INTEGER, sha256 TEXT, fetched_ok INTEGER DEFAULT 0, evidence_id TEXT, meta TEXT DEFAULT '{}',
  collected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS js_routes (
  id TEXT PRIMARY KEY, js_id TEXT NOT NULL REFERENCES js_resources(id) ON DELETE CASCADE,
  route TEXT NOT NULL, kind TEXT NOT NULL, context TEXT DEFAULT '', evidence_id TEXT
);
CREATE TABLE IF NOT EXISTS js_secrets (
  id TEXT PRIMARY KEY, js_id TEXT NOT NULL REFERENCES js_resources(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, match_redacted TEXT NOT NULL, verified INTEGER DEFAULT 0,
  dismissed INTEGER DEFAULT 0, context TEXT DEFAULT '', confidence TEXT DEFAULT 'LOW', evidence_id TEXT
);
CREATE TABLE IF NOT EXISTS technologies (
  id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, asset_id TEXT, name TEXT NOT NULL,
  version TEXT, category TEXT DEFAULT 'other', detection_method TEXT NOT NULL,
  raw_match TEXT DEFAULT '', confidence TEXT DEFAULT 'MEDIUM', evidence_id TEXT, collected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS perimeter (
  id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, asset_id TEXT, kind TEXT NOT NULL,
  name TEXT NOT NULL, detection_method TEXT NOT NULL, raw_match TEXT DEFAULT '',
  confidence TEXT DEFAULT 'MEDIUM', evidence_id TEXT, collected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS posture (
  id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, asset_id TEXT, url TEXT NOT NULL,
  kind TEXT NOT NULL, state TEXT NOT NULL, header TEXT, value TEXT, detail TEXT DEFAULT '{}',
  evidence_id TEXT, collected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, scan_id TEXT NOT NULL,
  finding_key TEXT NOT NULL, title TEXT NOT NULL, category TEXT NOT NULL,
  classification TEXT NOT NULL CHECK(classification IN ('OBSERVED','VERIFIED','INFERRED','HEURISTIC','MANUAL_REVIEW','CONFIRMED_FINDING')),
  severity TEXT NOT NULL CHECK(severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
  risk_score INTEGER NOT NULL DEFAULT 0, confidence TEXT NOT NULL DEFAULT 'MEDIUM',
  asset_id TEXT, asset_label TEXT DEFAULT '',
  description TEXT NOT NULL, impact TEXT DEFAULT '', recommendation TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','VERIFIED','RESOLVED','RISK_ACCEPTED','FALSE_POSITIVE')),
  evidence_ids TEXT DEFAULT '[]', meta TEXT DEFAULT '{}',
  is_demo INTEGER DEFAULT 0,
  first_seen_scan_id TEXT, last_seen_scan_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  entity TEXT NOT NULL, entity_id TEXT, detail TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS ai_outputs (
  id TEXT PRIMARY KEY, scan_id TEXT, workspace_id TEXT, kind TEXT NOT NULL,
  model TEXT NOT NULL, prompt_summary TEXT, content TEXT NOT NULL,
  grounded_on TEXT DEFAULT '{}', status TEXT DEFAULT 'OK', error TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE INDEX IF NOT EXISTS idx_assets_ws ON assets(workspace_id, type);
CREATE INDEX IF NOT EXISTS idx_ev_scan ON evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_dns_scan ON dns_records(scan_id);
CREATE INDEX IF NOT EXISTS idx_hp_scan ON host_ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_web_scan ON web_observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_ep_scan ON endpoints(scan_id);
CREATE INDEX IF NOT EXISTS idx_tech_scan ON technologies(scan_id);
CREATE INDEX IF NOT EXISTS idx_find_ws ON findings(workspace_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
`);

export function q(sql, params = []) {
  return db.prepare(sql).all(...params);
}
export function q1(sql, params = []) {
  return db.prepare(sql).get(...params);
}
export function run(sql, params = []) {
  return db.prepare(sql).run(...params);
}

export function audit(actor, action, entity, entityId, detail = {}) {
  run(`INSERT INTO audit_log (id, ts, actor, action, entity, entity_id, detail) VALUES (?,?,?,?,?,?,?)`,
    [uid('aud'), now(), actor, action, entity, entityId, JSON.stringify(detail)]);
}

export function getSetting(key, fallback = null) {
  const row = q1(`SELECT value FROM settings WHERE key = ?`, [key]);
  return row ? row.value : fallback;
}
export function setSetting(key, value) {
  run(`INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, [key, String(value)]);
}
