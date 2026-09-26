import type { VerdictSignal } from './analyze';

/*
 * Sandbox tier (#45): run a flagged version in the throwaway Docker runner
 * (sandbox-runner/) and turn what it did into verdict signals.
 *
 * The runner reports FACTS: which fake credentials were opened, which hosts
 * were contacted, which programs ran. This file decides what those facts mean.
 *
 * OPTIONAL by design. Vercel cannot run Docker, so the runner is a separate
 * service. With SANDBOX_RUNNER_URL unset this tier is skipped silently; if it
 * is set but the runner fails, the failure is recorded (so the verdict is not
 * cached as if the sandbox had said "clean") and everything else still applies.
 */

const RUNNER_TIMEOUT_MS = 200_000; // npm install (up to 120s) + the run (up to 90s), including any wait for a free slot
const BUSY_RETRY_MS = 2_000;

// Hosts a package's install script may legitimately try to reach (downloading a prebuilt binary, say).
// The sandbox has no network, so this only decides how a failed attempt is described.
const KNOWN_HOSTS = [
  'registry.npmjs.org', 'registry.yarnpkg.com', 'github.com', 'codeload.github.com',
  'objects.githubusercontent.com', 'raw.githubusercontent.com', 'nodejs.org',
];

/** Programs an npm package has no business starting, matched on the executable's name. */
const SUSPICIOUS_PROGRAMS: { name: RegExp; severity: 'high' | 'medium'; why: string }[] = [
  { name: /^(?:curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp)$/, severity: 'high', why: 'a network tool' },
  { name: /^(?:python[\d.]*|perl|ruby|php|powershell|pwsh)$/, severity: 'medium', why: 'another scripting runtime' },
  { name: /^(?:crontab|systemctl|launchctl|at)$/, severity: 'high', why: 'a scheduler (persistence)' },
];
const SUSPICIOUS_ARGS: { args: RegExp; why: string }[] = [
  { args: /\/dev\/tcp\//, why: 'a reverse-shell style redirect' },
  { args: /\b(?:ba)?sh\s+-i\b/, why: 'an interactive shell' },
  { args: /base64\s+(?:-d|--decode)/, why: 'decoding a base64 payload' },
  { args: /\|\s*(?:ba)?sh\b/, why: 'piping downloaded text into a shell' },
];

/** What the runner returns (sandbox-runner/analyze-trace.mjs and run.mjs). */
export interface SandboxResult {
  target: string;
  phases: {
    install?: { ok: boolean; timedOut?: boolean; error?: string };
    run?: { ok: boolean; timedOut?: boolean; exitCode?: number | null };
  };
  events?: { event: string; package?: string; hook?: string; status?: number | null }[];
  truncated?: boolean;
  honeypotReads?: { path: string; syscall: string; access: string; process: string }[];
  sensitiveReads?: { path: string; syscall: string; access: string }[];
  tokenLeaks?: { syscall: string; via: string; encoding: string }[];
  network?: ({ kind: 'dns'; host: string } | { kind: 'connect'; address: string; port: number; result: string })[];
  processes?: { path: string; args: string; ok: boolean }[];
  filesTouched?: number;
}

export interface SandboxTierResult {
  signals: VerdictSignal[];
  /** Set when the runner was configured but failed; the verdict must not be cached. */
  failure?: string;
  /** True when the tier produced a result (or a deterministic skip), so tierReached can move to 'sandbox'. */
  reached: boolean;
}

const isKnownHost = (host: string) => KNOWN_HOSTS.some((k) => host === k || host.endsWith(`.${k}`));
const unique = <T,>(items: T[]) => [...new Set(items)];
const list = (items: string[], max = 4) => items.slice(0, max).join(', ') + (items.length > max ? `, +${items.length - max} more` : '');
const baseName = (p: string) => p.slice(p.lastIndexOf('/') + 1);
const short = (path: string) => path.replace('/home/sandbox/', '~/');

/**
 * Signals from one runner result. Pure, so the verdict rules can be tested
 * without Docker (scripts/verify-sandbox.mts).
 */
export function signalsFromSandbox(result: SandboxResult, label: string): VerdictSignal[] {
  const signals: VerdictSignal[] = [];

  // Fake credentials: nothing legitimate reads them. A hard signal, see HARD_SIGNALS in analyze.ts.
  const honeypots = result.honeypotReads ?? [];
  if (honeypots.length > 0) {
    const files = unique(honeypots.map((h) => short(h.path)));
    signals.push({
      type: 'sandbox_honeypot_read',
      severity: 'critical',
      title: 'Read fake credentials planted in the sandbox',
      detail: `${label} touched ${list(files)} while its install scripts ran or when it was loaded. `
        + 'These files were fake, put there as bait; no legitimate package reads them.',
    });
  }

  // A planted secret turning up in a command line or a network call, even encoded
  const leaks = result.tokenLeaks ?? [];
  if (leaks.length > 0) {
    signals.push({
      type: 'sandbox_token_exfil',
      severity: 'critical',
      title: 'Fake secrets appeared in an outgoing command or connection',
      detail: `${label} passed a planted secret to ${list(unique(leaks.map((l) => `${l.via} (${l.encoding})`)))}.`,
    });
  }

  // Network: the sandbox has none, so every attempt failed, but the attempt is the signal
  const unknownHosts: string[] = [];
  const knownHosts: string[] = [];
  for (const n of result.network ?? []) {
    if (n.kind === 'dns') (isKnownHost(n.host) ? knownHosts : unknownHosts).push(n.host);
    else unknownHosts.push(`${n.address}:${n.port}`);
  }
  if (unknownHosts.length > 0) {
    signals.push({
      type: 'sandbox_network',
      severity: 'high',
      title: 'Tried to contact an unknown host',
      detail: `${label} tried to reach ${list(unique(unknownHosts))} from inside the sandbox.`,
    });
  } else if (knownHosts.length > 0) {
    signals.push({
      type: 'sandbox_network',
      severity: 'low',
      title: 'Tried to reach a well-known host',
      detail: `${label} tried to reach ${list(unique(knownHosts))} (typical of a script that downloads a prebuilt binary).`,
    });
  }

  const sensitive = result.sensitiveReads ?? [];
  if (sensitive.length > 0) {
    signals.push({
      type: 'sandbox_sensitive_read',
      severity: 'medium',
      title: 'Looked at sensitive files',
      detail: `${label} accessed ${list(unique(sensitive.map((s) => short(s.path))))}.`,
    });
  }

  const suspicious: { severity: 'high' | 'medium'; text: string }[] = [];
  for (const p of result.processes ?? []) {
    const program = baseName(p.path);
    const byName = SUSPICIOUS_PROGRAMS.find((s) => s.name.test(program));
    if (byName) suspicious.push({ severity: byName.severity, text: `${program} (${byName.why})` });
    const byArgs = SUSPICIOUS_ARGS.find((s) => s.args.test(p.args));
    if (byArgs) suspicious.push({ severity: 'high', text: `${program} ${p.args.slice(0, 60)} (${byArgs.why})` });
  }
  if (suspicious.length > 0) {
    signals.push({
      type: 'sandbox_process',
      severity: suspicious.some((s) => s.severity === 'high') ? 'high' : 'medium',
      title: 'Started programs an npm package should not need',
      detail: `${label} started ${list(unique(suspicious.map((s) => s.text)))}.`,
    });
  }

  if (result.phases.run?.timedOut) {
    signals.push({
      type: 'sandbox_skipped',
      severity: 'info',
      title: 'Sandbox run hit its time limit',
      detail: `${label} was still running when the sandbox stopped it, so later behaviour was not observed.`,
    });
  }

  if (signals.every((s) => s.type === 'sandbox_skipped')) {
    const scripts = (result.events ?? []).filter((e) => e.event === 'script').length;
    signals.push({
      type: 'sandbox_clean',
      severity: 'info',
      title: 'Ran in the sandbox with no suspicious behaviour',
      detail: `${label}: ${scripts} install script(s) run, ${result.processes?.length ?? 0} process(es) started, `
        + 'no fake credentials read and no network attempts.',
    });
  }
  return signals;
}

const skipped = (label: string, reason: string): VerdictSignal => ({
  type: 'sandbox_skipped',
  severity: 'info',
  title: 'Sandbox run skipped',
  detail: `${label}: ${reason}.`,
});

/**
 * Runs the sandbox tier for `name@version`. Never throws.
 */
export async function runSandboxTier(name: string, version: string): Promise<SandboxTierResult> {
  const url = process.env.SANDBOX_RUNNER_URL;
  if (!url) return { signals: [], reached: false };

  const label = `${name}@${version}`;
  const secret = process.env.INTERNAL_SECRET;
  if (!secret) return { signals: [], failure: 'sandbox:no-secret', reached: false };

  try {
    // The runner runs a couple of packages at once and answers 429 to the rest. A
    // lockfile can flag more than that in one go, so wait for a free slot instead
    // of turning a busy runner into a failed (and uncached) verdict.
    const signal = AbortSignal.timeout(RUNNER_TIMEOUT_MS);
    let res: Response;
    for (;;) {
      res = await fetch(`${url.replace(/\/+$/, '')}/run`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-internal-secret': secret },
        body: JSON.stringify({ name, version }),
        signal,
      });
      if (res.status !== 429) break;
      await new Promise((r) => setTimeout(r, BUSY_RETRY_MS));
    }
    if (!res.ok) return { signals: [], failure: `sandbox:http-${res.status}`, reached: false };

    const result = (await res.json()) as SandboxResult;
    if (!result?.phases) return { signals: [], failure: 'sandbox:bad-response', reached: false };

    const install = result.phases.install;
    if (!install?.ok) {
      // A timed-out install is a transient failure; any other failed install (no such
      // version, a native build that needs a toolchain) is the same every time.
      return install?.timedOut
        ? { signals: [], failure: 'sandbox:install-timeout', reached: false }
        : { signals: [skipped(label, `it could not be installed in the sandbox (${install?.error ?? 'unknown error'})`)], reached: true };
    }
    return { signals: signalsFromSandbox(result, label), reached: true };
  } catch (err) {
    return { signals: [], failure: `sandbox:${err instanceof Error && err.name === 'TimeoutError' ? 'timeout' : 'unreachable'}`, reached: false };
  }
}
