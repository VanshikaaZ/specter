// Turns the strace output of one sandbox run into a short structured summary.
//
// Pure functions, no Docker: run.mjs feeds this the trace it collected, and
// test-trace.mjs feeds it hand-written traces. It reports FACTS (which fake
// credential was opened, which host was contacted, which programs ran).
// Whether those facts make a package a `block` is decided by the API side
// (src/lib/packages/sandbox.ts), next to the other verdict rules.
import { posix as path } from 'node:path';

export const HOME = '/home/sandbox';
export const WORK = '/work';

/** The fake credentials plant.mjs writes. Any touch of these is a hard signal. */
export const HONEYPOT_FILES = ['.ssh/id_rsa', '.npmrc', '.aws/credentials', '.git-credentials'].map((p) => `${HOME}/${p}`);

/** Real-looking places a stealer goes to that are not honeypots: reported, but as a weaker signal. */
const SENSITIVE_PATHS = [
  /^\/etc\/shadow$/,
  /\/\.(?:bash|zsh)_history$/,
  /^\/proc\/(?:\d+|self)\/environ$/,
  /\/\.kube\/config$/,
  /\/\.docker\/config\.json$/,
  /\/\.config\/(?:gcloud|gh)(?:\/|$)/,
  /\/\.gnupg(?:\/|$)/,
  /\/\.ssh(?:\/|$)/,
  /^\/var\/run\/docker\.sock$/,
  /^\/run\/docker\.sock$/,
];

// The reader of ~/.npmrc that is not suspicious: npm itself, when a build script calls `npm run ...`
const NPM_CLI = /npm-cli\.js|npx-cli\.js/;

const FILE_CALLS = new Set([
  'open', 'openat', 'openat2', 'creat', 'stat', 'lstat', 'newfstatat', 'statx', 'access', 'faccessat', 'faccessat2',
  'readlink', 'readlinkat', 'unlink', 'unlinkat', 'rename', 'renameat', 'renameat2', 'chmod', 'fchmodat',
  'truncate', 'mkdir', 'mkdirat', 'rmdir', 'symlink', 'symlinkat', 'link', 'linkat', 'utimensat',
]);
const DIRFD_CALLS = new Set([
  'openat', 'openat2', 'newfstatat', 'statx', 'faccessat', 'faccessat2', 'readlinkat', 'unlinkat',
  'renameat', 'renameat2', 'fchmodat', 'mkdirat', 'symlinkat', 'linkat', 'utimensat',
]);
const NET_SEND_CALLS = new Set(['sendto', 'sendmsg', 'sendmmsg']);
const FORK_CALLS = new Set(['clone', 'clone3', 'fork', 'vfork']);

const MAX_LIST = 60;
const MAX_ARGS_CHARS = 240;

// ── strace string handling ───────────────────────────────────────────────

/** Bytes of a C-style string as strace prints it (\n, \xHH, \NNN octal, \\, \"). */
export function unescapeStrace(s) {
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c !== '\\') {
      bytes.push(...Buffer.from(c, 'utf8'));
      continue;
    }
    const n = s[++i];
    if (n === 'x') {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else if (n >= '0' && n <= '7') {
      let oct = n;
      while (oct.length < 3 && s[i + 1] >= '0' && s[i + 1] <= '7') oct += s[++i];
      bytes.push(parseInt(oct, 8) & 0xff);
    } else {
      bytes.push({ n: 10, t: 9, r: 13, a: 7, b: 8, f: 12, v: 11 }[n] ?? n.charCodeAt(0));
    }
  }
  return Buffer.from(bytes);
}

const QUOTED = /"((?:[^"\\]|\\.)*)"/g;
const quotedStrings = (text) => Array.from(text.matchAll(QUOTED), (m) => m[1]);

/** A host name from the question section of a DNS query held in `buf`, or null. */
function dnsName(buf) {
  for (const start of [12, 14]) { // 12: UDP query; 14: TCP query (2-byte length prefix first)
    const labels = [];
    let i = start;
    while (i < buf.length && buf[i] > 0 && buf[i] <= 63) {
      const label = buf.subarray(i + 1, i + 1 + buf[i]).toString('latin1');
      if (label.length !== buf[i] || !/^[a-z0-9_-]+$/i.test(label)) { labels.length = 0; break; }
      labels.push(label);
      i += buf[i] + 1;
    }
    // A question ends in a 0 byte, then a 2-byte type and class IN (0x0001)
    if (labels.length > 0 && buf[i] === 0 && buf[i + 3] === 0 && buf[i + 4] === 1) return labels.join('.').toLowerCase();
  }
  return null;
}

// ── one strace line ──────────────────────────────────────────────────────

/**
 * `1234 openat(AT_FDCWD, "/x", O_RDONLY) = 3` -> { pid, name, args, result, errno }.
 * A call another thread interrupted is printed in two halves; the first half
 * carries the arguments, so it is kept with result = null.
 */
export function parseLine(line) {
  const m = /^(?:(\d+)\s+)?([a-z_][a-z_0-9]*)\((.*)$/.exec(line);
  if (!m) return null;
  const [, pid, name, rest] = m;
  if (rest.endsWith('<unfinished ...>')) {
    return { pid: pid ? Number(pid) : 0, name, args: rest.slice(0, -'<unfinished ...>'.length).trim(), result: null, errno: null };
  }
  const at = rest.lastIndexOf(') = ');
  if (at < 0) return null;
  const tail = /^(-?\d+|\?|0x[0-9a-f]+)\s*(E[A-Z0-9]+)?/i.exec(rest.slice(at + 4));
  return {
    pid: pid ? Number(pid) : 0,
    name,
    args: rest.slice(0, at),
    result: tail && /^-?\d+$/.test(tail[1]) ? Number(tail[1]) : null,
    errno: tail?.[2] ?? null,
  };
}

// ── canary variants (a stolen secret may be encoded before it is sent) ───

export function canaryVariants(canary) {
  const variants = [{ text: canary, encoding: 'plain' }, { text: Buffer.from(canary).toString('hex'), encoding: 'hex' }];
  for (let offset = 0; offset < 3; offset++) {
    // base64 of the canary at each of the 3 possible byte alignments, edges dropped
    // because they depend on the neighbouring bytes
    const b64 = Buffer.from('x'.repeat(offset) + canary).toString('base64');
    variants.push({ text: b64.slice(4, -4), encoding: 'base64' });
  }
  return variants;
}

// ── the summary ──────────────────────────────────────────────────────────

/**
 * @param {string} trace   strace output (`-f`, so lines carry a pid prefix)
 * @param {{canary: string}} options
 */
export function analyzeTrace(trace, { canary }) {
  const cwd = new Map();
  const cmd = new Map();
  const touched = new Set();
  const honeypotReads = new Map();
  const sensitiveReads = new Map();
  const processes = new Map();
  const network = new Map();
  const tokenLeaks = new Map();
  const variants = canary ? canaryVariants(canary) : [];

  const cwdOf = (pid) => cwd.get(pid) ?? WORK;
  const resolve = (p, pid) => (p.startsWith('/') ? path.normalize(p) : path.join(cwdOf(pid), p));

  const checkLeak = (line, syscall, via) => {
    for (const v of variants) {
      const at = line.indexOf(v.text);
      if (at < 0) continue;
      tokenLeaks.set(`${syscall}|${v.encoding}|${via}`, {
        syscall, via, encoding: v.encoding,
        context: line.slice(Math.max(0, at - 40), at + 80),
      });
      return;
    }
  };

  // Network records made from a call another thread interrupted, per pid: their
  // outcome only arrives on the later "<... connect resumed>" line.
  const pendingNet = new Map();

  for (const line of trace.split('\n')) {
    const resumed = /^(?:(\d+)\s+)?<\.\.\. ([a-z_][a-z_0-9]*) resumed>.*\)\s+= (?:-?\d+|\?|0x[0-9a-f]+)\s*(E[A-Z0-9]+)?/i.exec(line);
    if (resumed) {
      const pending = pendingNet.get(resumed[1] ? Number(resumed[1]) : 0);
      if (pending?.name === resumed[2]) {
        pendingNet.delete(resumed[1] ? Number(resumed[1]) : 0);
        if (resumed[3]) for (const rec of pending.records) rec.result = resumed[3];
      }
      continue;
    }
    const call = parseLine(line);
    if (!call) continue;
    const { pid, name, args, result, errno } = call;
    const failed = errno === 'ENOENT';

    // Keep working directories and command lines right across fork/chdir
    if (FORK_CALLS.has(name) && result !== null && result > 0) {
      cwd.set(result, cwdOf(pid));
      if (cmd.has(pid)) cmd.set(result, cmd.get(pid));
      continue;
    }
    if (name === 'chdir') {
      const dir = quotedStrings(args)[0];
      if (dir !== undefined && result === 0) cwd.set(pid, resolve(unescapeStrace(dir).toString(), pid));
      continue;
    }

    if (name === 'execve') {
      const strings = quotedStrings(args);
      const exe = strings[0] === undefined ? '' : unescapeStrace(strings[0]).toString();
      const argv = strings.slice(1).map((s) => unescapeStrace(s).toString());
      // The driver's own launch and its loader are the harness, not the package
      const loaded = /^\nconst name = "([^"]+)"/.exec(argv[2] ?? '')?.[1];
      if (argv.some((a) => a.endsWith('/opt/specter/driver.mjs')) || loaded) {
        cmd.set(pid, loaded ? `require("${loaded}")` : argv.join(' '));
        continue;
      }
      // An execve interrupted by another thread has no result yet, but did start
      if (result === 0 || result === null) cmd.set(pid, argv.join(' '));
      const shown = argv.slice(1).join(' ').slice(0, MAX_ARGS_CHARS);
      const key = `${exe}|${shown}`;
      const ok = result === 0 || result === null;
      const prior = processes.get(key);
      // A shell searching PATH logs one failed execve per directory: keep the entry that worked
      if (!prior || (ok && !prior.ok)) processes.set(key, { path: exe, args: shown, ok });
      checkLeak(line, 'execve', 'execve');
      touchHoneypot(exe, pid, 'execve', result, errno);
      continue;
    }

    if (FILE_CALLS.has(name)) {
      const raw = quotedStrings(args)[0];
      if (raw === undefined) continue;
      const target = unescapeStrace(raw).toString();
      // A path relative to an fd we never tracked can't be resolved
      if (!target.startsWith('/') && DIRFD_CALLS.has(name) && !/^AT_FDCWD/.test(args)) continue;
      touchHoneypot(target, pid, name, result, errno, args);
      continue;
    }

    if (name === 'connect' || NET_SEND_CALLS.has(name)) {
      checkLeak(line, name, 'network');
      const records = recordNetwork(name, args, errno);
      if (result === null && errno === null && line.endsWith('<unfinished ...>')) pendingNet.set(pid, { name, records });
    }
  }

  function touchHoneypot(target, pid, syscall, result, errno, args = '') {
    const resolved = resolve(target, pid);
    touched.add(resolved);
    if (errno === 'ENOENT') return;
    const process = cmd.get(pid) ?? '';
    const isNpm = NPM_CLI.test(process);
    const write = /O_WRONLY|O_RDWR|O_CREAT|O_TRUNC/.test(args) || ['creat', 'unlink', 'unlinkat', 'rename', 'renameat', 'renameat2', 'truncate', 'chmod', 'fchmodat'].includes(syscall);
    const access = syscall === 'execve' ? 'execute' : write ? 'write' : /^(open|openat|openat2|creat)$/.test(syscall) ? 'read' : 'probe';
    const record = { path: resolved, syscall, access, process: process.slice(0, MAX_ARGS_CHARS) };

    if (HONEYPOT_FILES.includes(resolved)) {
      // npm reading its own config is not theft
      if (resolved.endsWith('/.npmrc') && isNpm) return;
      honeypotReads.set(`${resolved}|${access}|${process}`, record);
    } else if (SENSITIVE_PATHS.some((re) => re.test(resolved))) {
      sensitiveReads.set(`${resolved}|${access}`, record);
    }
  }

  function recordNetwork(syscall, args, errno) {
    const result = errno ?? 'sent';
    const records = [];
    const hosts = [];
    if (NET_SEND_CALLS.has(syscall)) {
      for (const s of quotedStrings(args)) {
        const host = dnsName(unescapeStrace(s));
        if (host) hosts.push(host);
      }
    }
    for (const host of hosts) {
      const rec = { kind: 'dns', host, result };
      network.set(`dns|${host}`, rec);
      records.push(rec);
    }

    const family = /sa_family=(AF_[A-Z0-9]+)/.exec(args)?.[1];
    if (family === 'AF_INET' || family === 'AF_INET6') {
      const m = family === 'AF_INET'
        ? /sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)/.exec(args)
        : /sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"/.exec(args);
      if (!m) return records;
      const [, port, address] = m;
      if (/^127\./.test(address) || address === '::1') return records; // loopback never leaves the container
      const rec = { kind: 'connect', address, port: Number(port), family, syscall, result };
      network.set(`connect|${address}|${port}`, rec);
      records.push(rec);
    } else if (family === 'AF_UNIX' && syscall === 'connect') {
      const sock = /sun_path="([^"]*)"/.exec(args)?.[1];
      if (sock && /docker\.sock$/.test(sock)) sensitiveReads.set(`${sock}|connect`, { path: sock, syscall, access: 'connect', process: '' });
    }
    return records;
  }

  const list = (map) => Array.from(map.values()).slice(0, MAX_LIST);
  // A shell searching PATH logs one failed execve per directory; keep those only if the command never ran
  const ran = new Set(Array.from(processes.values()).filter((p) => p.ok).map((p) => `${path.basename(p.path)}|${p.args}`));
  for (const [key, p] of processes) if (!p.ok && ran.has(`${path.basename(p.path)}|${p.args}`)) processes.delete(key);
  return {
    honeypotReads: list(honeypotReads),
    sensitiveReads: list(sensitiveReads),
    tokenLeaks: list(tokenLeaks),
    network: list(network),
    processes: list(processes),
    filesTouched: touched.size,
  };
}
