// KavachRecon — scan engine: orchestration, evidence store, module lifecycle
import { db, q, q1, run, now, uid, sha256, audit } from '../db.js';
import { Scope, RateLimiter, Semaphore, sleep } from '../lib/netutil.js';
import { MODULES } from './modules/index.js';

export function riskScore(severity, classification, confidence) {
  const base = { INFO: 5, LOW: 20, MEDIUM: 45, HIGH: 70, CRITICAL: 90 }[severity] ?? 20;
  const clsAdj = { CONFIRMED_FINDING: 6, VERIFIED: 5, INFERRED: 2, OBSERVED: 0, MANUAL_REVIEW: 0, HEURISTIC: -4 }[classification] ?? 0;
  const confAdj = { HIGH: 3, MEDIUM: 0, LOW: -4 }[confidence] ?? 0;
  return Math.max(1, Math.min(100, base + clsAdj + confAdj));
}

export class ScanStore {
  constructor(scan, workspaceId) {
    this.scanId = scan.id; this.workspaceId = workspaceId;
    this.moduleItems = new Map(); // module_key -> count
  }
  bump(moduleKey, n = 1) { this.moduleItems.set(moduleKey, (this.moduleItems.get(moduleKey) || 0) + n); }

  addAsset({ type, key, value, parent_id = null, meta = {}, confidence = 'MEDIUM', origin = 'SCAN', status = 'ACTIVE' }) {
    const k = String(key).toLowerCase();
    const existing = q1(`SELECT * FROM assets WHERE workspace_id = ? AND type = ? AND key = ?`, [this.workspaceId, type, k]);
    if (existing) {
      run(`UPDATE assets SET last_seen = ?, status = ?, scan_id = COALESCE(scan_id, ?) WHERE id = ?`,
        [now(), existing.status === 'REMOVED' ? 'REMOVED' : status, this.scanId, existing.id]);
      return existing.id;
    }
    const id = uid('ast');
    run(`INSERT INTO assets (id, workspace_id, scan_id, type, key, value, parent_id, status, origin, verification, confidence, meta, first_seen, last_seen)
         VALUES (?,?,?,?,?,?,?,?,?,'UNVERIFIED',?,'{}',?,?)`,
      [id, this.workspaceId, this.scanId, type, k, value, parent_id, status, origin, confidence, now(), now()]);
    return id;
  }
  addEdge(srcId, dstId, relation) {
    if (!srcId || !dstId || srcId === dstId) return;
    run(`INSERT OR IGNORE INTO asset_edges (id, workspace_id, src_id, dst_id, relation, scan_id) VALUES (?,?,?,?,?,?)`,
      [uid('edg'), this.workspaceId, srcId, dstId, relation, this.scanId]);
  }
  addEvidence({ module_key, asset_id = null, kind, source, summary, content = {} }) {
    const id = uid('ev');
    const hash = sha256(JSON.stringify({ module_key, kind, source, summary, content }));
    run(`INSERT INTO evidence (id, scan_id, workspace_id, module_key, asset_id, kind, source, summary, content, hash, collected_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [id, this.scanId, this.workspaceId, module_key, asset_id, kind, source, summary, JSON.stringify(content), hash, now()]);
    this.bump(module_key);
    return id;
  }
  addFinding(f) {
    const key = f.finding_key || sha256(`${f.category}|${f.title}|${f.asset_label || ''}`).slice(0, 24);
    const existing = q1(`SELECT * FROM findings WHERE workspace_id = ? AND finding_key = ? AND status IN ('OPEN','VERIFIED','RISK_ACCEPTED')`, [this.workspaceId, key]);
    const classification = f.classification;
    const severity = f.severity;
    const score = f.risk_score ?? riskScore(severity, classification, f.confidence || 'MEDIUM');
    if (existing) {
      run(`UPDATE findings SET last_seen_scan_id = ?, updated_at = ?, severity = ?, classification = ?, risk_score = ?, confidence = ?, description = ?, impact = ?, recommendation = ?, evidence_ids = ?, meta = ? WHERE id = ?`,
        [this.scanId, now(), severity, classification, score, f.confidence || 'MEDIUM', f.description, f.impact || '', f.recommendation || '', JSON.stringify(f.evidence_ids || []), JSON.stringify(f.meta || {}), existing.id]);
      return existing.id;
    }
    const id = uid('fnd');
    run(`INSERT INTO findings (id, workspace_id, scan_id, finding_key, title, category, classification, severity, risk_score, confidence, asset_id, asset_label, description, impact, recommendation, status, evidence_ids, meta, is_demo, first_seen_scan_id, last_seen_scan_id, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?)`,
      [id, this.workspaceId, this.scanId, key, f.title, f.category, classification, severity, score, f.confidence || 'MEDIUM',
       f.asset_id || null, f.asset_label || '', f.description, f.impact || '', f.recommendation || '', 'OPEN',
       JSON.stringify(f.evidence_ids || []), JSON.stringify(f.meta || {}), this.scanId, this.scanId, now(), now()]);
    return id;
  }
}

export class ScanContext {
  constructor(scan, target, workspace, store) {
    this.scan = scan; this.target = target; this.workspace = workspace; this.store = store;
    const cfg = JSON.parse(scan.config || '{}');
    this.cfg = {
      global_rps: 25, per_host_rps: 5, port_timeout_ms: 3000, http_timeout_ms: 9000,
      top_ports: 'quick', max_http_targets: 40, max_js_fetch: 15, ...cfg,
    };
    this.rate = new RateLimiter({ globalRps: this.cfg.global_rps, perHostRps: this.cfg.per_host_rps });
    this.scope = new Scope(
      { identifier: target.identifier, type: target.type },
      this.scopeRules('INCLUDE'), this.scopeRules('EXCLUDE'),
    );
    this.logs = [];
  }
  scopeRules(kind) {
    return q(`SELECT pattern, pattern_type, reason FROM scope_rules WHERE target_id = ? AND kind = ?`, [this.target.id, kind]);
  }
  cancelled() {
    const s = q1(`SELECT cancel_requested, status FROM scans WHERE id = ?`, [this.scan.id]);
    return !!s?.cancel_requested || !['RUNNING', 'QUEUED'].includes(s?.status);
  }
  /** Gate for ANY network operation. Returns null if allowed, else reason string. */
  netGuard(value) {
    const v = this.scope.check(value);
    if (!v.allowed) {
      this.log(`SCOPE-BLOCK ${value}: ${v.reason}`);
      return v.reason;
    }
    return null;
  }
  log(line) {
    this.logs.push(`${new Date().toISOString()} ${line}`);
    if (this.logs.length > 800) this.logs.splice(0, 200);
  }
  setModuleStatus(moduleKey, status, { items = null, error = null, detail = {} } = {}) {
    const m = q1(`SELECT id FROM scan_modules WHERE scan_id = ? AND module_key = ?`, [this.scan.id, moduleKey]);
    if (!m) return;
    const count = items ?? this.store.moduleItems.get(moduleKey) ?? 0;
    run(`UPDATE scan_modules SET status = ?, items_count = ?, error = ?, detail = ?, finished_at = ? WHERE id = ?`,
      [status, count, error, JSON.stringify(detail), now(), m.id]);
  }
}

export class ScanEngine {
  static running = new Map(); // scanId -> controller

  static async launch(scanId) {
    if (ScanEngine.running.has(scanId)) return;
    const ctrl = { cancelled: false };
    ScanEngine.running.set(scanId, ctrl);
    run(`UPDATE scans SET status = 'RUNNING', started_at = ? WHERE id = ? AND status = 'QUEUED'`, [now(), scanId]);
    // fire & forget with own error containment
    ScanEngine.execute(scanId, ctrl).catch(e => {
      console.error('engine fatal', e);
      run(`UPDATE scans SET status = 'FAILED', finished_at = ?, summary = ? WHERE id = ?`, [now(), JSON.stringify({ error: String(e?.message || e) }), scanId]);
      run(`UPDATE scan_modules SET status = 'FAILED', error = COALESCE(error, 'engine failure') WHERE scan_id = ? AND status IN ('QUEUED','RUNNING')`, [scanId]);
    }).finally(() => ScanEngine.running.delete(scanId));
  }

  static cancel(scanId, actor) {
    run(`UPDATE scans SET cancel_requested = 1 WHERE id = ? AND status IN ('QUEUED','RUNNING')`, [scanId]);
    audit(actor, 'scan.cancel_requested', 'scan', scanId, {});
  }

  static async execute(scanId, ctrl) {
    const scan = q1(`SELECT * FROM scans WHERE id = ?`, [scanId]);
    if (!scan) return;
    const target = q1(`SELECT * FROM targets WHERE id = ?`, [scan.target_id]);
    const workspace = q1(`SELECT * FROM workspaces WHERE id = ?`, [scan.workspace_id]);
    const store = new ScanStore(scan, scan.workspace_id);
    const ctx = new ScanContext(scan, target, workspace, store);

    // module rows (cfg.modules allows subsetting, e.g. for quick DNS-only recon)
    run(`DELETE FROM scan_modules WHERE scan_id = ?`, [scanId]);
    const cfgSc = JSON.parse(scan.config || '{}');
    const active = Array.isArray(cfgSc.modules) && cfgSc.modules.length ? MODULES.filter(m => cfgSc.modules.includes(m.key)) : MODULES;
    active.forEach((m, i) => {
      run(`INSERT INTO scan_modules (id, scan_id, module_key, name, order_idx, status) VALUES (?,?,?,?,?,'QUEUED')`,
        [uid('mod'), scanId, m.key, m.name, i]);
    });
    audit('system', 'scan.started', 'scan', scanId, { name: scan.name, mode: scan.mode, target: target.identifier });

    let anyFailure = false;
    for (const mod of active) {
      if (ctx.cancelled() || ctrl.cancelled) {
        run(`UPDATE scan_modules SET status = 'SKIPPED', error = 'scan cancelled by operator' WHERE scan_id = ? AND status = 'QUEUED'`, [scanId]);
        run(`UPDATE scans SET status = 'CANCELLED', finished_at = ? WHERE id = ?`, [now(), scanId]);
        audit('system', 'scan.cancelled', 'scan', scanId, {});
        return;
      }
      const mrow = q1(`SELECT id FROM scan_modules WHERE scan_id = ? AND module_key = ?`, [scanId, mod.key]);
      if (mrow) run(`UPDATE scan_modules SET status = 'RUNNING', started_at = ? WHERE id = ?`, [now(), mrow.id]);
      const t0 = Date.now();
      try {
        if (mod.requiresActive && scan.mode !== 'ACTIVE_CONFIRMED') {
          ctx.setModuleStatus(mod.key, 'NOT_APPLICABLE', { items: 0, detail: { reason: `Active reconnaissance not authorized for this scan (mode = ${scan.mode}). Module requires explicit active confirmation.` } });
        } else if (mod.when && !mod.when(ctx)) {
          ctx.setModuleStatus(mod.key, 'NOT_APPLICABLE', { items: 0, detail: { reason: mod.whenReason || 'Preconditions not met by earlier modules.' } });
        } else {
          const timeoutMs = mod.timeoutMs || 120_000;
          const result = await Promise.race([
            mod.run(ctx),
            sleep(timeoutMs).then(() => { throw new Error(`module timeout after ${timeoutMs}ms`); }),
          ]);
          const items = store.moduleItems.get(mod.key) || 0;
          const st = result?.status || (items > 0 ? 'COMPLETED' : 'COMPLETED_NO_RESULTS');
          ctx.setModuleStatus(mod.key, st, { items, detail: result?.detail || {} });
          if (st === 'FAILED') anyFailure = true;
        }
      } catch (e) {
        anyFailure = true;
        ctx.setModuleStatus(mod.key, 'FAILED', { items: store.moduleItems.get(mod.key) || 0, error: String(e?.message || e), detail: {} });
      }
      const m2 = q1(`SELECT id FROM scan_modules WHERE scan_id = ? AND module_key = ?`, [scanId, mod.key]);
      if (m2) run(`UPDATE scan_modules SET duration_ms = ? WHERE id = ?`, [Date.now() - t0, m2.id]);
    }

    // deterministic findings pass
    try {
      const { deriveFindings } = await import('./findings.js');
      const n = deriveFindings(ctx);
      ctx.log(`findings derived: ${n}`);
    } catch (e) {
      ctx.log(`findings engine error: ${e.message}`);
    }

    const summary = buildSummary(scan.workspace_id, scanId);
    const finalStatus = anyFailure ? 'COMPLETED_WITH_FAILURES' : (ctx.cancelled() ? 'CANCELLED' : 'COMPLETED');
    run(`UPDATE scans SET status = ?, finished_at = ?, summary = ? WHERE id = ?`, [finalStatus, now(), JSON.stringify(summary), scanId]);
    audit('system', 'scan.completed', 'scan', scanId, { status: finalStatus, summary: { assets: summary.totals.assets, findings: summary.totals.findings } });
  }
}

export function buildSummary(workspaceId, scanId) {
  const c = (sql, ...p) => {
    try { return q1(sql, p)?.n || 0; }
    catch (e) { console.error('buildSummary c() FAILED', e.message, 'SQL:', sql.slice(0, 80), 'params:', JSON.stringify(p)); throw e; }
  };
  const modules = q(`SELECT status, COUNT(*) n FROM scan_modules WHERE scan_id = ? GROUP BY status`, [scanId]);
  const failed = modules.find(m => m.status === 'FAILED')?.n || 0;
  const findings = q(`SELECT severity, COUNT(*) n FROM findings WHERE scan_id = ? GROUP BY severity`, [scanId]);
  const sev = Object.fromEntries(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s => [s, findings.find(f => f.severity === s)?.n || 0]));
  return {
    totals: {
      assets: c(`SELECT COUNT(*) n FROM assets WHERE workspace_id = ?`, workspaceId),
      scan_assets: c(`SELECT COUNT(DISTINCT asset_id) n FROM evidence WHERE scan_id = ? AND asset_id IS NOT NULL`, scanId),
      subdomains: c(`SELECT COUNT(*) n FROM assets WHERE workspace_id = ? AND type = 'SUBDOMAIN'`, workspaceId),
      ips: c(`SELECT COUNT(*) n FROM assets WHERE workspace_id = ? AND type = 'IP'`, workspaceId),
      live_hosts: c(`SELECT COUNT(DISTINCT host) n FROM host_ports WHERE scan_id = ? AND state IN ('OPEN','OPEN_UNVERIFIED')`, scanId),
      open_ports: c(`SELECT COUNT(*) n FROM host_ports WHERE scan_id = ? AND state IN ('OPEN','OPEN_UNVERIFIED')`, scanId),
      services: c(`SELECT COUNT(DISTINCT service) n FROM host_ports WHERE scan_id = ? AND service IS NOT NULL AND state IN ('OPEN','OPEN_UNVERIFIED')`, scanId),
      web_apps: c(`SELECT COUNT(*) n FROM web_observations WHERE scan_id = ? AND status_code IS NOT NULL`, scanId),
      endpoints: c(`SELECT COUNT(*) n FROM endpoints WHERE scan_id = ?`, scanId),
      technologies: c(`SELECT COUNT(*) n FROM technologies WHERE scan_id = ?`, scanId),
      dns_records: c(`SELECT COUNT(*) n FROM dns_records WHERE scan_id = ?`, scanId),
      js_resources: c(`SELECT COUNT(*) n FROM js_resources WHERE scan_id = ?`, scanId),
      js_secrets: c(`SELECT COUNT(*) n FROM js_secrets sc JOIN js_resources r ON r.id = sc.js_id WHERE r.scan_id = ? AND sc.dismissed = 0`, scanId),
      findings: c(`SELECT COUNT(*) n FROM findings WHERE scan_id = ?`, scanId),
      review_items: c(`SELECT COUNT(*) n FROM findings WHERE scan_id = ? AND classification IN ('MANUAL_REVIEW','HEURISTIC') AND status = 'OPEN'`, scanId),
      evidence: c(`SELECT COUNT(*) n FROM evidence WHERE scan_id = ?`, scanId),
    },
    severity: sev,
    modules: Object.fromEntries(modules.map(m => [m.status, m.n])),
    failed_modules: failed,
    limitations: failed > 0 ? [`${failed} module(s) failed — exposure could not be fully determined for the areas they cover. See module matrix.`] : [],
}
}
