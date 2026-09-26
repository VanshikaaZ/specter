// The sandbox runner's HTTP endpoint.
//
//   POST /run   {"name": "left-pad", "version": "1.3.0"}   header: x-internal-secret
//   GET  /health
//
// Start:  INTERNAL_SECRET=... node sandbox-runner/server.mjs   (see README.md)
//
// Listens on localhost only unless SANDBOX_HOST says otherwise. It runs real
// malware inside Docker, so it will not start without a proper secret.
import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { runSandbox, ensureImage, dockerAvailable, cleanupLeftovers, BadRequest } from './run.mjs';

const PORT = Number(process.env.SANDBOX_PORT) || 8787;
const HOST = process.env.SANDBOX_HOST || '127.0.0.1';
const MAX_CONCURRENT = Number(process.env.SANDBOX_MAX_CONCURRENT) || 2;
const MAX_BODY_BYTES = 4096;
const FIXTURES_ENABLED = process.env.SANDBOX_ENABLE_FIXTURES === '1';

// Same fail-closed rule as the app's INTERNAL_SECRET, plus: the public dev default
// and the .env.sample placeholder are not secrets.
const SECRET = process.env.INTERNAL_SECRET ?? '';
if (SECRET.length < 16 || SECRET === 'specter-internal' || SECRET.startsWith('change_me')) {
  console.error('INTERNAL_SECRET is missing or is a placeholder (need 16+ characters). Refusing to start.');
  process.exit(1);
}

function authorised(req) {
  const given = Buffer.from(String(req.headers['x-internal-secret'] ?? ''));
  const expected = Buffer.from(SECRET);
  return given.length === expected.length && timingSafeEqual(given, expected);
}

function send(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) { reject(new BadRequest('body too large')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch { reject(new BadRequest('body is not JSON')); }
    });
    req.on('error', reject);
  });
}

let active = 0;

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return send(res, 200, { ok: true, docker: await dockerAvailable() });
    }
    if (req.method !== 'POST' || req.url !== '/run') return send(res, 404, { error: 'not found' });
    if (!authorised(req)) return send(res, 401, { error: 'unauthorised' });

    const body = await readBody(req);
    const target = body.fixture !== undefined
      ? (FIXTURES_ENABLED ? { fixture: String(body.fixture) } : null)
      : { name: body.name, version: body.version };
    if (!target) return send(res, 400, { error: 'fixtures are disabled' });

    if (active >= MAX_CONCURRENT) return send(res, 429, { error: 'runner busy, try again shortly' });
    active++;
    try {
      const started = new Date().toISOString();
      const result = await runSandbox(target);
      console.log(`[sandbox] ${result.target} done in ${result.durationMs}ms (honeypot=${result.honeypotReads?.length ?? 0}, network=${result.network?.length ?? 0})`);
      send(res, 200, { ...result, startedAt: started });
    } finally {
      active--;
    }
  } catch (err) {
    if (err instanceof BadRequest) return send(res, 400, { error: err.message });
    console.error('[sandbox] run failed:', err);
    send(res, 500, { error: 'sandbox run failed' });
  }
});

if (!(await dockerAvailable())) {
  console.error('Docker is not reachable. Start Docker Desktop (or the docker daemon) and try again.');
  process.exit(1);
}
await cleanupLeftovers();
await ensureImage();
server.listen(PORT, HOST, () => {
  console.log(`[sandbox] runner listening on http://${HOST}:${PORT}${FIXTURES_ENABLED ? '  (test fixtures ENABLED)' : ''}`);
});
