// KavachRecon — server entrypoint
import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { sessionMiddleware } from './auth.js';
import { ensureDefaultUsers } from './auth.js';
import { seed } from './seed/seed.js';
import { ScanEngine } from './scanner/engine.js';
import { q1, run, now } from './db.js';
import apiRouter from './routes.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8787;

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));
app.use(sessionMiddleware);

app.use('/api', apiRouter);

// static frontend
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));
app.get(/^\/(?!api\/).*/, (req, res) => {
  const index = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(index)) res.sendFile(index);
  else res.status(503).send('Frontend not built yet. Run: npm run build');
});

// error containment
app.use((err, req, res, next) => {
  console.error('[api error]', err);
  res.status(500).json({ error: 'internal', message: err.message });
});

// process-level resilience: a probe bug must never kill collection silently
process.on('unhandledRejection', (e) => console.error('[unhandledRejection]', e?.code || e?.message || e));
process.on('uncaughtException', (e) => console.error('[uncaughtException]', e?.code || e?.message || e));

async function boot() {
  // mark scans interrupted by a previous process as FAILED — honest state
  const interrupted = q1(`SELECT COUNT(*) n FROM scans WHERE status IN ('RUNNING','QUEUED')`).n;
  if (interrupted) {
    run(`UPDATE scans SET status = 'FAILED', finished_at = ?, summary = ? WHERE status IN ('RUNNING','QUEUED')`,
      [now(), JSON.stringify({ error: 'interrupted by server restart' })]);
    run(`UPDATE scan_modules SET status = 'FAILED', error = COALESCE(error, 'interrupted by server restart') WHERE status IN ('QUEUED','RUNNING')`);
    console.log(`[boot] marked ${interrupted} interrupted scan(s) as FAILED (honest state)`);
  }
  await seed();
  ensureDefaultUsers();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n  KavachRecon Intelligence Platform — listening on http://0.0.0.0:${PORT}`);
    console.log('  Built by @premkrs • Evidence-based recon • No fabricated data\n');
  });
}

boot().catch((e) => { console.error('boot failed:', e); process.exit(1); });
