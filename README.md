# KavachRecon — Attack-Surface Intelligence Platform

**KavachRecon** is an authorized cybersecurity reconnaissance and attack-surface intelligence platform.
You add an explicitly authorized target → KavachRecon discovers its digital assets → analyzes DNS, hosts,
ports, web services, technologies, endpoints and security posture → records tamper-evident evidence →
classifies and prioritizes what needs review → summarizes with a grounded AI → and produces a
professional PDF report.

> **Principle:** `REAL DATA → NORMALIZATION → EVIDENCE → VERIFICATION → CLASSIFICATION → RISK → REPORT`
> Never `EMPTY DATA → AI GUESS → FAKE FINDING → FAKE PDF`.

Built by **@premkrs**.

---

## Quick start

```bash
npm install          # installs server + build tooling
npm run build        # builds the React frontend into server/public
npm start            # boots the platform on http://0.0.0.0:8787
```

On first boot KavachRecon:

1. **Executes a real, live passive DNS reconnaissance** of a benign public domain (`example.com`)
   so the dashboard opens with genuinely collected data and evidence.
2. **Seeds a clearly-labelled demo workspace** (`Nimbus Cloud`) with a synthetic, internally-consistent
   dataset so the UI can be explored before running real scans. Every demo record is tagged
   `DEMO_SEED` / `is_demo=1` and badged everywhere; purge it any time from **Settings → Demo data**.

Sign-in is passwordless by product design: identify yourself on the login screen (all actions are
attributed in the audit trail).

## What's inside

| Area | Highlights |
|---|---|
| Targets & scope | Domain/IP/CIDR targets, include/exclude scope rules enforced before **every** network operation, active-recon confirmation (target-level + per-scan), rate limits, scan controls |
| Recon engine | 21 modules — DNS enum, SPF/DMARC/DKIM, subdomain dictionary, wildcard/dangling-CNAME analysis, CT logs (crt.sh), WHOIS/RDAP, ASN mapping (Team Cymru/ARIN), historical DNS, archive URLs, host discovery, port & service scan, HTTP probing, TLS analysis, tech fingerprinting, WAF/CDN, security posture, robots/sitemap, endpoint discovery, JS intelligence (routes/refs/secret patterns), cloud signals, screenshots |
| Module status | Every module reports `QUEUED / RUNNING / COMPLETED / COMPLETED_NO_RESULTS / FAILED / SKIPPED / NOT_APPLICABLE` with reasons. **A failed module is never shown as "no findings".** |
| Inventory | De-duplicated assets (domains, subdomains, IPs, hosts, ports, services, URLs, endpoints, technologies, certificates, JS resources, cloud) with first/last seen, status, source, confidence, verification and evidence links + relationship graph |
| Findings | Deterministic rules only; strict classification `OBSERVED / VERIFIED / INFERRED / HEURISTIC / MANUAL_REVIEW / CONFIRMED_FINDING`; human verify/reject/accept-risk workflow; deterministic risk scoring (severity × classification × confidence) |
| AI (Gemini) | Executive summaries, finding explanations, natural-language Q&A, workspace briefings — grounded strictly on database records with a hard **NO EVIDENCE = NO CLAIM** system rule; outputs stored with model + grounding context |
| Reporting | 19-section professional PDF (cover → executive summary → scope → methodology → module matrix → inventories → DNS/network/web/endpoint/JS intel → tech & perimeter → posture → findings → manual review → comparison → limitations → evidence appendix) with footer *“KavachRecon Intelligence Platform • Built by @premkrs”* |
| Exports | PDF, workspace/scan asset CSV, findings CSV, full JSON, evidence ZIP (SHA-256 content hashes) — all generated from the same rows the dashboard renders |
| Platform | Express + `node:sqlite` (zero native deps), React + Vite frontend, session auth, full audit trail, scan comparison/diffing, force-directed attack-surface graph, responsive dark UI with empty/loading states and optimistic updates |

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `8787` | HTTP port |
| `KR_DATA_DIR` | `./data` | SQLite database directory |
| `KR_DNS_RESOLVERS` | `8.8.8.8, 1.1.1.1` | DNS resolvers used by recon modules |

Gemini: set the API key in **Settings → AI integration** (stored server-side, masked in responses).
If the Gemini endpoint is unreachable from your deployment, AI features fail with an explicit,
honest error — everything else keeps working.

## A note on honest results

KavachRecon refuses to fabricate. If a data source is unreachable (e.g. a sandboxed deployment
without outbound HTTP), the affected modules report `FAILED` with the real error, the dashboard,
report and exports explicitly declare the coverage gap, and no conclusion is drawn for those areas.
Where TCP connects are accepted by transparent middleboxes, ports are recorded as
`OPEN_UNVERIFIED` — never as confirmed services.

## Repository layout

```
server/
  index.js            entrypoint (Express + static + boot)
  db.js               SQLite schema + helpers (node:sqlite)
  auth.js             passwordless session auth
  routes.js           REST API (targets, scans, assets, findings, graph, AI, exports…)
  scanner/            engine + module registry + findings rules
    modules/          dns / passive / active / web module implementations
  report/pdf.js       19-section PDF generator (pdfkit)
  ai/gemini.js        grounded Gemini integration
  seed/               live recon + labelled demo dataset
web/                  React SPA (Vite) — dashboard, scans, assets, findings, graph, reports…
```

MIT License © @premkrs
