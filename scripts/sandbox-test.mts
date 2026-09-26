// End-to-end checks for the sandbox tier (#45), using real Docker:  npm run sandbox-test
//
// Needs Docker running and a network connection (one check installs a real
// package from npm). The first run builds the sandbox image, which takes a
// minute. Offline rule checks are in `npm run verify-sandbox`. Exits 1 if any
// check fails.
//
//   1. isolation: the container that runs packages, checked from the inside
//   2. fixtures:  test packages that read the fake key / reach for the network
//   3. server:    the HTTP endpoint (secret, validation)
//   4. real npm:  a package with a normal postinstall, through the same path the API uses
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import { docker, runArgs, runSandbox, ensureImage, cleanupLeftovers } from '../sandbox-runner/run.mjs';
import { signalsFromSandbox, runSandboxTier, type SandboxResult } from '../src/lib/packages/sandbox';
import { scoreOf, verdictFor, type VerdictSignal } from '../src/lib/packages/analyze';

let failures = 0;
function check(label: string, ok: boolean, extra = '') {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${extra ? `  (${extra})` : ''}`);
}
const verdictOf = (signals: VerdictSignal[]) => verdictFor(signals, scoreOf(signals), []);

await ensureImage();
await cleanupLeftovers();

// ── 1. isolation ─────────────────────────────────────────────────────────

console.log('— isolation (the container that runs packages, seen from inside)');

const volume = `specter-sbx-test-${randomBytes(4).toString('hex')}`;
// Stand-ins for the real secrets a developer's shell has: none may reach the container
process.env.SPECTER_TEST_HOST_SECRET = 'must-not-reach-the-container';
process.env.GITHUB_TOKEN = 'host-github-token-must-not-leak';
process.env.SUPABASE_SECRET_KEY = 'host-supabase-key-must-not-leak';
process.env.INTERNAL_SECRET = 'host-internal-secret-must-not-leak';
await docker(['volume', 'create', volume]);
const probe = await docker(runArgs({
  name: `${volume}-probe`, volume, canary: 'specter-canary-isolation',
  command: ['-c', [
    'echo uid=$(id -u)',
    "echo capeff=$(grep CapEff /proc/self/status | awk '{print $2}')",
    "echo nonewprivs=$(grep NoNewPrivs /proc/self/status | awk '{print $2}')",
    "echo nets=$(ls /sys/class/net | tr '\\n' ' ' | sed 's/ *$//')",
    'echo dockersock=$(ls /var/run/docker.sock /run/docker.sock 2>/dev/null | wc -l)',
    'echo homefiles=$(ls -A /home/sandbox | wc -l)',
    '(touch /etc/specter-write-test 2>/dev/null && echo rootfs=writable) || echo rootfs=readonly',
    "echo hostmounts=$(grep -ciE '/mnt/host|/run/desktop|/host_mnt|virtiofs|9p' /proc/mounts)",
    'echo hostsecrets=$(env | grep -c "must-not")',
    'echo faketokens=$(env | grep -cE "^(GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)=specter-canary-")',
    'echo othertokens=$(env | grep -E "TOKEN|SECRET|KEY" | grep -vc "specter-canary-")',
  ].join('\n')],
}));
await docker(['volume', 'rm', '-f', volume]);
const facts: Record<string, string> = {};
for (const line of String(probe.stdout).split('\n')) {
  const eq = line.indexOf('=');
  if (eq > 0) facts[line.slice(0, eq)] = line.slice(eq + 1).trim();
}

check('runs as an unprivileged user', facts.uid === '10001', `uid=${facts.uid}`);
check('holds no Linux capabilities', /^0+$/.test(facts.capeff ?? 'x'), `CapEff=${facts.capeff}`);
check('cannot gain privileges (no-new-privileges)', facts.nonewprivs === '1');
check('has no network interface except loopback', facts.nets === 'lo', `interfaces: ${facts.nets}`);
check('has no Docker socket', facts.dockersock === '0');
check('has no host folders mounted', facts.hostmounts === '0');
check('starts with an empty home (no real credentials)', facts.homefiles === '0', `${facts.homefiles} files`);
check('cannot write to the root filesystem', facts.rootfs === 'readonly');
check('does not inherit the runner\'s environment', facts.hostsecrets === '0');
check('its only tokens are the four fake ones', facts.faketokens === '4' && facts.othertokens === '0', `fake=${facts.faketokens} other=${facts.othertokens}`);

// ── 2. fixtures ──────────────────────────────────────────────────────────

console.log('— test packages');

const [benign, reader, net, thief] = (await Promise.all([
  runSandbox({ fixture: 'benign-build' }),
  runSandbox({ fixture: 'honeypot-probe' }),
  runSandbox({ fixture: 'net-probe' }),
  runSandbox({ fixture: 'exfil-honeypot' }),
])) as unknown as SandboxResult[];
const count = (items?: unknown[]) => items?.length ?? 0;
const escalated: VerdictSignal[] = [{ type: 'install_script', severity: 'high', title: 't', detail: 'd' }];

check('benign package: installed and ran', benign.phases.install?.ok === true && benign.phases.run?.ok === true);
check('benign package: its build script ran', (benign.events ?? []).some((e) => e.event === 'script' && e.status === 0));
check('benign package: no fake credentials read, no network attempts', count(benign.honeypotReads) === 0 && count(benign.network) === 0);
const benignSignals = signalsFromSandbox(benign, 'benign@1.0.0');
check('benign package: not flagged', benignSignals.every((s) => s.severity === 'info') && verdictOf([...escalated, ...benignSignals]) === 'warn');

check('honeypot reader: the fake SSH key read is recorded', (reader.honeypotReads ?? []).some((h) => h.path === '/home/sandbox/.ssh/id_rsa'));
const readerSignals = signalsFromSandbox(reader, 'reader@1.0.0');
check('honeypot reader: flagged block', verdictOf(readerSignals) === 'block');

const attempts = net.network ?? [];
check('network prober: the DNS lookup and the connection are recorded',
  attempts.some((n) => n.kind === 'dns' && n.host === 'probe.specter-test.invalid')
  && attempts.some((n) => n.kind === 'connect' && n.address === '192.0.2.1'));
check('network prober: the connection was refused, nothing got out',
  attempts.filter((n) => n.kind === 'connect').every((n) => n.kind === 'connect' && n.result === 'ENETUNREACH'));
check('network prober: flagged as contacting an unknown host', signalsFromSandbox(net, 'net@1.0.0').some((s) => s.type === 'sandbox_network' && s.severity === 'high'));

// The acceptance test: reads the fake key and tries to send it out
const stolen = new Set((thief.honeypotReads ?? []).map((h) => h.path));
const thiefAttempts = thief.network ?? [];
const thiefSignals = signalsFromSandbox(thief, 'thief@1.0.0');
check('credential stealer: the fake SSH key, AWS file and npmrc reads are all recorded',
  ['/home/sandbox/.ssh/id_rsa', '/home/sandbox/.aws/credentials', '/home/sandbox/.npmrc'].every((p) => stolen.has(p)), [...stolen].join(', '));
check('credential stealer: its attempts to send data out are recorded',
  thiefAttempts.some((n) => n.kind === 'dns' && n.host === 'exfil.specter-test.invalid')
  && thiefAttempts.some((n) => n.kind === 'connect' && n.address === '192.0.2.1'));
check('credential stealer: none of it left the sandbox (every connection refused)',
  thiefAttempts.filter((n) => n.kind === 'connect').every((n) => n.kind === 'connect' && n.result === 'ENETUNREACH'));
check('credential stealer: flagged block, even with no other signal', verdictOf(thiefSignals) === 'block');
check('credential stealer: flagged block on top of a warn-level package', verdictOf([...escalated, ...thiefSignals]) === 'block');

const left = (await docker(['ps', '-aq', '--filter', 'name=specter-sbx-'])).stdout.trim();
const leftVolumes = (await docker(['volume', 'ls', '-q', '--filter', 'name=specter-sbx-'])).stdout.trim();
check('every container and volume is removed afterwards', left === '' && leftVolumes === '', left + leftVolumes);

// ── 3. the HTTP endpoint ─────────────────────────────────────────────────

console.log('— HTTP endpoint');

const secret = randomBytes(16).toString('hex');
const port = 8799;
const badStart = await new Promise<number | null>((resolve) => {
  const p = spawn(process.execPath, ['sandbox-runner/server.mjs'], { env: { ...process.env, INTERNAL_SECRET: 'specter-internal' }, stdio: 'ignore' });
  p.on('exit', resolve);
});
check('refuses to start with the public default secret', badStart === 1);

const server = spawn(process.execPath, ['sandbox-runner/server.mjs'], {
  env: { ...process.env, INTERNAL_SECRET: secret, SANDBOX_PORT: String(port), SANDBOX_ENABLE_FIXTURES: '1' },
  stdio: ['ignore', 'pipe', 'inherit'],
});
await new Promise<void>((resolve, reject) => {
  const rl = createInterface({ input: server.stdout! });
  rl.on('line', (line) => { if (line.includes('listening')) resolve(); });
  server.on('exit', () => reject(new Error('runner exited before listening')));
});
const url = `http://127.0.0.1:${port}`;
const post = (body: unknown, key?: string) => fetch(`${url}/run`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', ...(key ? { 'x-internal-secret': key } : {}) },
  body: JSON.stringify(body),
});

try {
  check('rejects a request with no secret', (await post({ fixture: 'benign-build' })).status === 401);
  check('rejects a wrong secret', (await post({ fixture: 'benign-build' }, 'x'.repeat(secret.length))).status === 401);
  check('rejects an invalid package name', (await post({ name: 'a; rm -rf /', version: '1.0.0' }, secret)).status === 400);
  check('rejects a version that is not a version', (await post({ name: 'left-pad', version: '--registry=http://evil.invalid' }, secret)).status === 400);
  check('rejects a fixture name that walks out of the folder', (await post({ fixture: '../server' }, secret)).status === 400);
  check('answers /health', (await fetch(`${url}/health`)).status === 200);
  const ok = await post({ fixture: 'benign-build' }, secret);
  const body = await ok.json();
  check('runs a package for a request with the right secret', ok.status === 200 && body.phases?.run?.ok === true);

  // ── 4. a real package, the way the API calls it ──
  console.log('— real npm package via the API path');
  process.env.SANDBOX_RUNNER_URL = url;
  process.env.INTERNAL_SECRET = secret;
  // core-js has a real postinstall script
  const real = await runSandboxTier('core-js', '3.49.0');
  check('core-js@3.49.0 (real postinstall) runs in the sandbox', real.reached && !real.failure, real.failure ?? '');
  check('core-js@3.49.0 is not flagged', real.signals.every((s) => s.severity === 'info' || s.severity === 'low'), real.signals.map((s) => s.type).join(','));

  const missingVersion = await runSandboxTier('left-pad', '999.0.0');
  check('a version that does not exist is skipped with a reason, not an error', missingVersion.reached && missingVersion.signals[0]?.type === 'sandbox_skipped' && !missingVersion.failure);

  process.env.SANDBOX_RUNNER_URL = 'http://127.0.0.1:1';
  const down = await runSandboxTier('left-pad', '1.3.0');
  check('a runner that is down is a recorded failure, never "clean"', down.failure === 'sandbox:unreachable' && down.signals.length === 0 && !down.reached);
  delete process.env.SANDBOX_RUNNER_URL;
  const off = await runSandboxTier('left-pad', '1.3.0');
  check('with no runner configured the tier is skipped silently', !off.failure && off.signals.length === 0 && !off.reached);
} finally {
  server.kill();
}

console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
