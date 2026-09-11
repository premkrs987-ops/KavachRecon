// KavachRecon — Gemini AI integration. STRICT GROUNDING:
// prompts are built ONLY from database facts; the model is instructed that
// NO EVIDENCE = NO CLAIM, and every response is stored with its grounding set.
import { q, q1, run, now, uid, getSetting } from '../db.js';

const MODELS = ['gemini-2.0-flash', 'gemini-2.0-flash-lite', 'gemini-1.5-flash', 'gemini-1.5-pro'];

export async function geminiConfigured() {
  const key = getSetting('gemini_api_key');
  return !!key;
}

async function callGemini(prompt, { model = null, system = null } = {}) {
  const key = getSetting('gemini_api_key');
  const mdl = model || getSetting('gemini_model') || 'gemini-2.0-flash';
  if (!key) return { ok: false, error: 'not_configured', message: 'No Gemini API key configured. Add one in Settings → AI to enable AI features.' };
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(mdl)}:generateContent?key=${encodeURIComponent(key)}`;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(new Error('timeout')), 60_000);
  try {
    const res = await fetch(url, {
      method: 'POST', signal: ctrl.signal, headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        ...(system ? { systemInstruction: { parts: [{ text: system }] } } : {}),
        generationConfig: { temperature: 0.2, maxOutputTokens: 4096 },
      }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = body?.error?.message || `HTTP ${res.status}`;
      return { ok: false, error: 'api_error', message: msg };
    }
    const text = body?.candidates?.[0]?.content?.parts?.map(p => p.text).filter(Boolean).join('\n') || '';
    if (!text) return { ok: false, error: 'empty_response', message: 'Model returned no content.' };
    return { ok: true, text, model: mdl };
  } catch (e) {
    return { ok: false, error: 'network_error', message: `Gemini endpoint unreachable from this environment: ${e?.cause?.code || e.message}. AI features require outbound HTTPS access to generativelanguage.googleapis.com.` };
  } finally { clearTimeout(t); }
}

const GROUNDING_SYSTEM = `You are the AI analyst of KavachRecon, an authorized attack-surface intelligence platform.
ABSOLUTE RULES:
1. NO EVIDENCE = NO CLAIM. You may only state facts that appear in the provided SCAN DATA (JSON). If data is absent, say what is absent and that exposure could not be determined.
2. NEVER invent assets, ports, vulnerabilities, technologies, statistics or remediation outcomes.
3. Distinguish every statement by its classification: OBSERVED / VERIFIED / INFERRED / HEURISTIC / MANUAL_REVIEW / CONFIRMED_FINDING as given in the data.
4. A failed or skipped module means coverage is INCOMPLETE — never claim "no vulnerabilities" for it.
5. Observations (e.g. "/admin returns HTTP 200") must be described as potential/uncorroborated, never as confirmed vulnerabilities.
6. Recommendations must be defensive and authorised-audit oriented. Refuse offensive instructions.
7. Be concise, professional, and quantitative where the data allows. Use markdown headings and short bullet lists.`;

export function collectScanContext(scanId, { maxChars = 24_000 } = {}) {
  const scan = q1(`SELECT * FROM scans WHERE id = ?`, [scanId]);
  if (!scan) return null;
  const target = q1(`SELECT * FROM targets WHERE id = ?`, [scan.target_id]);
  const modules = q(`SELECT module_key, name, status, items_count, error FROM scan_modules WHERE scan_id = ? ORDER BY order_idx`, [scanId]);
  const dns = q(`SELECT type, COUNT(*) n FROM dns_records WHERE scan_id = ? GROUP BY type`, [scanId]);
  const ports = q(`SELECT host, ip, port, state, service, banner FROM host_ports WHERE scan_id = ? AND state IN ('OPEN','OPEN_UNVERIFIED') LIMIT 40`, [scanId]);
  const web = q(`SELECT url, final_url, status_code, title, server, content_type FROM web_observations WHERE scan_id = ? AND ok = 1 LIMIT 40`, [scanId]);
  const endpoints = q(`SELECT url, classification, status_code FROM endpoints WHERE scan_id = ? LIMIT 60`, [scanId]);
  const techs = q(`SELECT name, version, category, detection_method, confidence FROM technologies WHERE scan_id = ? LIMIT 40`, [scanId]);
  const perim = q(`SELECT kind, name, detection_method, confidence FROM perimeter WHERE scan_id = ? LIMIT 25`, [scanId]);
  const posture = q(`SELECT url, kind, state, header, value FROM posture WHERE scan_id = ? LIMIT 60`, [scanId]);
  const findings = q(`SELECT title, category, classification, severity, risk_score, confidence, asset_label, status FROM findings WHERE scan_id = ? ORDER BY risk_score DESC LIMIT 60`, [scanId]);
  const js = q(`SELECT s.kind, s.match_redacted, s.verified, r.url FROM js_secrets s JOIN js_resources r ON r.id = s.js_id WHERE r.scan_id = ? LIMIT 20`, [scanId]);
  const ctx = {
    scan: { name: scan.name, mode: scan.mode, status: scan.status, started: scan.started_at, finished: scan.finished_at, summary: JSON.parse(scan.summary || '{}') },
    target: { identifier: target.identifier, type: target.type },
    module_matrix: modules,
    dns_record_counts: dns,
    open_ports: ports.map(p => ({ host: p.host, ip: p.ip, port: p.port, state: p.state, service: p.service, banner: (p.banner || '').slice(0, 80) })),
    web_observations: web,
    endpoints: endpoints,
    technologies: techs,
    perimeter: perim,
    security_posture: posture.map(p => ({ url: p.url, kind: p.kind, state: p.state, value: (p.value || '').slice(0, 60) })),
    findings,
    js_secrets: js,
  };
  let json = JSON.stringify(ctx, null, 1);
  if (json.length > maxChars) json = json.slice(0, maxChars) + '\n…[truncated]';
  return { json, scan, target };
}

export async function generateExecutiveSummary(scanId, model) {
  const c = collectScanContext(scanId);
  if (!c) return { ok: false, error: 'not_found', message: 'Scan not found.' };
  const failed = c.scan.summary?.failed_modules || 0;
  const prompt = `${GROUNDING_SYSTEM}

SCAN DATA (JSON, collected by KavachRecon — the ONLY allowed source of facts):
${c.json}

TASK: Write an executive summary of this authorized scan for a security lead.
Structure:
## Executive Summary
## Key Numbers (only numbers that appear in the data — state them exactly)
## What Was Confirmed vs Observed (use classifications)
## Coverage & Limitations (${failed ? 'modules FAILED — state explicitly that exposure could not be fully determined' : 'state honestly what was NOT covered'})
## Recommended Next Steps (defensive, evidence-linked)
Mark any inference explicitly as INFERRED. Do not add facts absent from the data.`;
  const res = await callGemini(prompt, { model, system: GROUNDING_SYSTEM });
  const id = uid('ai');
  run(`INSERT INTO ai_outputs (id, scan_id, workspace_id, kind, model, prompt_summary, content, grounded_on, status, error, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [id, scanId, c.scan.workspace_id, 'EXEC_SUMMARY', res.model || model || 'gemini', 'Executive summary from scan DB context', res.ok ? res.text : '', JSON.stringify({ scan_context_chars: c.json.length, module_failures: failed }), res.ok ? 'OK' : 'ERROR', res.ok ? null : res.message, now()]);
  return { ok: res.ok, id, ...(!res.ok ? { error: res.error, message: res.message } : {}) };
}

export async function explainFinding(findingId, model) {
  const f = q1(`SELECT * FROM findings WHERE id = ?`, [findingId]);
  if (!f) return { ok: false, error: 'not_found', message: 'Finding not found.' };
  const evid = JSON.parse(f.evidence_ids || '[]');
  const evidence = evid.length ? q(`SELECT id, module_key, kind, source, summary, content, collected_at FROM evidence WHERE id IN (${evid.map(() => '?').join(',')})`, ...evid) : [];
  const data = { finding: { title: f.title, category: f.category, classification: f.classification, severity: f.severity, confidence: f.confidence, description: f.description, impact: f.impact, recommendation: f.recommendation, asset: f.asset_label }, evidence: evidence.map(e => ({ ...e, content: safeSlice(e.content, 1500) })) };
  const prompt = `${GROUNDING_SYSTEM}

FINDING + EVIDENCE (JSON — the only allowed source of facts):
${JSON.stringify(data, null, 1)}

TASK: Explain this finding to a security engineer:
## What We Know (evidence-backed only)
## What This Is NOT (state explicitly what was not verified)
## Potential Impact (mark as INFERRED where not directly evidenced)
## Verification Steps (concrete, authorised)
## Remediation (defensive)`;
  const res = await callGemini(prompt, { model, system: GROUNDING_SYSTEM });
  const id = uid('ai');
  run(`INSERT INTO ai_outputs (id, scan_id, workspace_id, kind, model, prompt_summary, content, grounded_on, status, error, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [id, f.scan_id, f.workspace_id, 'FINDING_EXPLAIN', res.model || 'gemini', `Explanation for finding ${f.id}`, res.ok ? res.text : '', JSON.stringify({ finding_id: f.id, evidence_count: evidence.length }), res.ok ? 'OK' : 'ERROR', res.ok ? null : res.message, now()]);
  return { ok: res.ok, id, ...(!res.ok ? { error: res.error, message: res.message } : {}) };
}

export async function askScan(scanId, question, model) {
  const c = collectScanContext(scanId);
  if (!c) return { ok: false, error: 'not_found', message: 'Scan not found.' };
  const prompt = `${GROUNDING_SYSTEM}

SCAN DATA (JSON — the only allowed source of facts):
${c.json}

OPERATOR QUESTION: ${question}

TASK: Answer the question using ONLY the scan data above. If the answer is not present in the data, say so explicitly and state that exposure could not be determined from the available evidence. Label statements with their classification where relevant. Keep it under 350 words.`;
  const res = await callGemini(prompt, { model, system: GROUNDING_SYSTEM });
  const id = uid('ai');
  run(`INSERT INTO ai_outputs (id, scan_id, workspace_id, kind, model, prompt_summary, content, grounded_on, status, error, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [id, scanId, c.scan.workspace_id, 'ASK', res.model || 'gemini', `Q: ${question.slice(0, 200)}`, res.ok ? res.text : '', JSON.stringify({ question, scan_context_chars: c.json.length }), res.ok ? 'OK' : 'ERROR', res.ok ? null : res.message, now()]);
  return { ok: res.ok, id, ...(!res.ok ? { error: res.error, message: res.message } : {}) };
}

export async function surfaceSummary(workspaceId, model) {
  const ws = q1(`SELECT * FROM workspaces WHERE id = ?`, [workspaceId]);
  if (!ws) return { ok: false, error: 'not_found', message: 'Workspace not found.' };
  const data = {
    workspaces: ws.name,
    assets_by_type: q(`SELECT type, COUNT(*) n FROM assets WHERE workspace_id = ? AND verification != 'FALSE_POSITIVE' GROUP BY type`, [workspaceId]),
    scans: q(`SELECT s.name, s.mode, s.status, s.created_at, t.identifier FROM scans s JOIN targets t ON t.id = s.target_id WHERE s.workspace_id = ? ORDER BY s.created_at DESC LIMIT 20`, [workspaceId]),
    findings: q(`SELECT title, classification, severity, risk_score, confidence, asset_label, status FROM findings WHERE workspace_id = ? ORDER BY risk_score DESC LIMIT 80`, [workspaceId]),
    top_ports: q(`SELECT service, port, COUNT(*) n FROM host_ports hp JOIN scans s ON s.id = hp.scan_id WHERE s.workspace_id = ? AND hp.state = 'OPEN' GROUP BY service, port ORDER BY n DESC LIMIT 20`, [workspaceId]),
    technologies: q(`SELECT name, COUNT(DISTINCT scan_id) n FROM technologies t JOIN scans s ON s.id = t.scan_id WHERE s.workspace_id = ? GROUP BY name ORDER BY n DESC LIMIT 30`, [workspaceId]),
  };
  const prompt = `${GROUNDING_SYSTEM}

WORKSPACE DATA (JSON — the only allowed source of facts):
${JSON.stringify(data, null, 1)}

TASK: Produce an attack-surface briefing for this workspace:
## Attack-Surface Overview (facts only)
## Prioritisation (top assets/hosts that warrant review first, with reasons from the data)
## Finding Posture (counts by classification/severity, exactly as in data)
## Gaps (scans failed/absent — coverage that could not be determined)
Label inferences as INFERRED. Under 500 words.`;
  const res = await callGemini(prompt, { model, system: GROUNDING_SYSTEM });
  const id = uid('ai');
  run(`INSERT INTO ai_outputs (id, scan_id, workspace_id, kind, model, prompt_summary, content, grounded_on, status, error, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [id, null, workspaceId, 'SURFACE', res.model || 'gemini', 'Workspace attack-surface briefing', res.ok ? res.text : '', JSON.stringify({ assets: data.assets_by_type }), res.ok ? 'OK' : 'ERROR', res.ok ? null : res.message, now()]);
  return { ok: res.ok, id, ...(!res.ok ? { error: res.error, message: res.message } : {}) };
}

function safeSlice(s, n) { try { const o = JSON.parse(s || '{}'); return JSON.stringify(o).slice(0, n); } catch { return String(s || '').slice(0, n); } }
