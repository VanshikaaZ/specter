// Client for Specter's check API (POST /api/v1/check and /api/v1/check/lockfile).
//
// Fail closed: anything that is not a real verdict from the API (network
// error, rate limit, 5xx, an unfinished analysis, a URL that isn't the API)
// becomes `warn` with an `unverified` reason. Nothing here returns `allow`
// unless the API said so.

import { readFile } from 'node:fs/promises';
import { ACTIONS, clean, toReason, unverified, worst } from './format.mjs';
import { isValidPackageName } from './parseCommand.mjs';
import { resolveVersion, DEFAULT_REGISTRY } from './resolve.mjs';

export const DEFAULT_API_URL = 'https://specter-seven.vercel.app';
const MAX_ROUNDS = 6; // same as specter-guard
const LOCKFILE_ROUND_WAIT_MS = 3000;
const MAX_FLAGGED = 100;
const CONCURRENCY = 4;

export class InputError extends Error {}

/** Settings from the environment; explicit tool arguments override the cooldown ones. */
export function configFromEnv(env = process.env) {
  const hours = env.SPECTER_MIN_RELEASE_AGE_HOURS;
  return {
    apiUrl: (env.SPECTER_API_URL || DEFAULT_API_URL).replace(/\/+$/, ''),
    registry: env.SPECTER_NPM_REGISTRY || DEFAULT_REGISTRY,
    minReleaseAgeHours: hours !== undefined && hours !== '' && Number.isFinite(Number(hours)) ? Number(hours) : undefined,
    strict: env.SPECTER_STRICT === '1' || env.SPECTER_STRICT === 'true' ? true : undefined,
    allow: env.SPECTER_ALLOW ? env.SPECTER_ALLOW.split(',').map((s) => s.trim()).filter(Boolean) : undefined,
  };
}

/** Only the cooldown fields the API accepts, and only when set. */
function cooldownBody(config, args = {}) {
  const body = {};
  const hours = args.minReleaseAgeHours ?? config.minReleaseAgeHours;
  const strict = args.strict ?? config.strict;
  if (hours !== undefined) body.minReleaseAgeHours = hours;
  if (strict !== undefined) body.strict = strict;
  if (config.allow?.length) body.allow = config.allow;
  return body;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * One POST, classified. `json` is null when the answer was not JSON, which
 * means `apiUrl` is not a Specter API (e.g. a deployment without /api/v1).
 */
async function post(url, body, timeoutMs) {
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'specter-guard-mcp/0.1.0' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(Math.max(timeoutMs, 1000)),
    });
  } catch (e) {
    const why = e.name === 'TimeoutError' ? 'timed out' : (e.cause?.code ?? e.message);
    return { status: 0, json: null, error: why };
  }
  const json = await res.json().catch(() => null);
  return { status: res.status, json };
}

function describeFailure(apiUrl, r) {
  if (r.status === 0) return `Could not reach ${apiUrl} (${r.error}).`;
  if (r.status === 429) return `Rate limited by ${apiUrl}: ${clean(r.json?.message ?? 'too many requests', 150)}`;
  if (r.json === null) return `${apiUrl} did not answer as the Specter check API (HTTP ${r.status}). Check SPECTER_API_URL.`;
  return `${apiUrl} answered HTTP ${r.status}: ${clean(r.json.message ?? r.json.error ?? 'no details', 150)}`;
}

/**
 * Checks one package. `args`: { name, version?, minReleaseAgeHours?, strict? }.
 * Throws InputError only for an invalid name; every other problem is a `warn` result.
 */
export async function checkOne(args, { config = configFromEnv(), deadline = Date.now() + 55_000 } = {}) {
  const { name } = args;
  const spec = (args.version ?? '').trim();
  if (!isValidPackageName(name)) throw new InputError(`"${name}" is not a valid npm package name.`);
  const requested = spec ? `${name}@${spec}` : name;

  const resolved = await resolveVersion(name, spec, { registry: config.registry, timeoutMs: Math.min(15_000, deadline - Date.now()) });
  if (!resolved.ok) {
    if (resolved.reason === 'not_found') return notFound(requested, resolved.message);
    if (resolved.reason === 'no_match') return notFound(requested, resolved.message, requested, 'No matching version on npm');
    return unverified(requested, 'Could not verify', resolved.message);
  }
  const version = resolved.version;
  const pkg = `${name}@${version}`;
  const body = { name, version, ...cooldownBody(config, args) };

  for (let round = 1; ; round++) {
    const remaining = deadline - Date.now();
    if (remaining <= 1000) break;
    const r = await post(`${config.apiUrl}/api/v1/check`, body, remaining);

    if (r.status === 200 && r.json?.verdict && r.json.verdict !== 'pending') return fromCheck(r.json, requested);
    if (r.status === 404 && r.json?.error === 'version_not_found') return notFound(requested, `${pkg} is not published on the npm registry and no advisory is known for it.`, pkg);
    if (r.status === 400 && r.json?.error) return unverified(requested, 'Could not verify', describeFailure(config.apiUrl, r), { package: pkg });
    if (r.status !== 202) return unverified(requested, 'Could not verify', describeFailure(config.apiUrl, r), { package: pkg });

    // 202: still analysing server-side; the result lands in the cache, so asking again is cheap
    if (round >= MAX_ROUNDS) break;
    const wait = Math.max(1, Number(r.json?.retryAfterSeconds) || 10) * 1000;
    if (Date.now() + wait >= deadline) break;
    await sleep(wait);
  }
  return unverified(requested, 'Analysis not finished', `Specter is still analysing ${pkg}. Call the check again in about 30 seconds; do not install it until it has a verdict.`, { package: pkg });
}

function notFound(requested, message, pkg = requested, title = 'Not published on npm') {
  return {
    verdict: 'warn',
    package: pkg,
    requested,
    score: null,
    reasons: [{ type: 'not_found', severity: 'medium', title, detail: clean(`${message} Check the name: invented or misspelled package names are a common way to install malware.`, 200) }],
    action: ACTIONS.warn,
    checkedAt: new Date().toISOString(),
    source: 'specter-guard-mcp',
  };
}

/** API PackageCheck → result. */
function fromCheck(c, requested) {
  const verdict = ['allow', 'warn', 'block'].includes(c.verdict) ? c.verdict : 'warn';
  return {
    verdict,
    package: `${c.name}@${c.version}`,
    requested,
    score: typeof c.score === 'number' ? c.score : null,
    reasons: (c.signals ?? []).map(toReason),
    action: ACTIONS[verdict],
    checkedAt: c.analyzedAt ?? new Date().toISOString(),
    source: 'specter-api',
    ...(c.allowlisted ? { allowlisted: clean(c.allowlisted, 250) } : {}),
  };
}

/** Runs fn over items, `limit` at a time, keeping order. */
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  }));
  return out;
}

/** Many packages ({ name, version? } each); overall verdict is the worst one. */
export async function checkPackages(list, opts = {}) {
  const packages = await mapLimit(list, CONCURRENCY, async (p) => {
    try {
      return await checkOne(p, opts);
    } catch (e) {
      if (e instanceof InputError) return unverified(p.name, 'Invalid package name', e.message);
      return unverified(p.name, 'Could not verify', e.message);
    }
  });
  return combine(packages);
}

function combine(packages, note) {
  const verdict = worst(packages.map((p) => p.verdict));
  return { verdict, packages, action: ACTIONS[verdict], ...(note ? { note } : {}) };
}

/** Targets from parseInstallCommand/parseArgv → one combined result. */
export async function checkTargets(targets, opts = {}) {
  if (targets.length === 0) return combine([], 'No npm/npx/pnpm/yarn/bun package install found in this command.');
  const results = await mapLimit(targets, CONCURRENCY, async (t) => {
    if (t.kind === 'package') {
      try {
        return await checkOne({ name: t.name, version: t.spec }, opts);
      } catch (e) {
        return unverified(t.raw, 'Could not verify', e.message);
      }
    }
    if (t.kind === 'lockfile') {
      try {
        return lockfileAsPackage(await checkLockfile({ path: t.path }, opts), t);
      } catch (e) {
        return unverified(t.raw, 'Could not verify', e.message);
      }
    }
    // Distinct from `unverified` (a check that failed): this source is simply out of scope
    const r = unverified(t.raw, 'Cannot verify this source', t.reason);
    r.reasons[0].type = 'unsupported';
    return r;
  });
  return combine(results);
}

/** Folds a lockfile result into one entry of a command result. */
export function lockfileAsPackage(lf, t) {
  const reasons = lf.flagged.flatMap((p) => p.reasons.slice(0, 1).map((r) => ({ ...r, title: `${p.package}: ${r.title}` })));
  if (lf.error) reasons.push(...lf.reasons);
  return {
    verdict: lf.verdict,
    package: `package-lock.json (${lf.checked ?? '?'} packages)`,
    requested: t.raw,
    score: null,
    reasons: reasons.slice(0, 10),
    action: ACTIONS[lf.verdict],
    checkedAt: lf.checkedAt,
    source: lf.source,
  };
}

/**
 * Checks a package-lock.json file (`args.path`), or an already-parsed one
 * (`args.lockfile`). Throws InputError when the file is missing
 * or not a lockfile the API accepts; returns a `warn` result when the API
 * cannot be reached.
 */
export async function checkLockfile(args, { config = configFromEnv(), deadline = Date.now() + 55_000 } = {}) {
  const path = args.path;
  let lockfile = args.lockfile;
  if (!lockfile) {
    try {
      lockfile = JSON.parse(await readFile(path, 'utf8'));
    } catch (e) {
      throw new InputError(e.code === 'ENOENT' ? `No lockfile at ${path}.` : `${path} is not valid JSON (${e.message}).`);
    }
  }
  const cooldown = cooldownBody(config, args);
  const body = Object.keys(cooldown).length ? { lockfile, ...cooldown } : lockfile;

  let last = null;
  let failure = null;
  for (let round = 1; round <= MAX_ROUNDS; round++) {
    const remaining = deadline - Date.now();
    if (remaining <= 1000) break;
    const r = await post(`${config.apiUrl}/api/v1/check/lockfile`, body, remaining);
    if (r.status === 400 && r.json?.error === 'invalid_lockfile') throw new InputError(clean(r.json.message, 300));
    if ((r.status === 200 || r.status === 202) && r.json?.counts) {
      last = r.json;
      if (r.status === 200) break;
      if (Date.now() + LOCKFILE_ROUND_WAIT_MS >= deadline) break;
      await sleep(LOCKFILE_ROUND_WAIT_MS);
      continue;
    }
    failure = describeFailure(config.apiUrl, r);
    break;
  }

  if (!last) {
    return {
      verdict: 'warn', complete: false, counts: { allow: 0, warn: 0, block: 0, pending: 0 }, checked: null, skipped: 0,
      flagged: [], error: true,
      reasons: [{ type: 'unverified', severity: 'medium', title: 'Could not verify', detail: clean(failure ?? 'The lockfile check did not answer in time.', 200) }],
      action: ACTIONS.warn, checkedAt: new Date().toISOString(), source: 'specter-guard-mcp',
    };
  }

  // Incomplete results are never `allow`: unchecked packages are unknown, not clean
  const verdict = last.verdict === 'block' ? 'block' : last.verdict === 'warn' || !last.complete ? 'warn' : 'allow';
  const flaggedAll = last.packages.filter((p) => p.verdict !== 'allow').map((p) =>
    p.verdict === 'pending'
      ? unverified(`${p.name}@${p.version}`, 'Analysis not finished', 'Not analysed within the time budget; check again shortly.')
      : fromCheck(p, `${p.name}@${p.version}`),
  );
  return {
    verdict,
    complete: Boolean(last.complete),
    counts: last.counts,
    checked: last.checked,
    skipped: last.skipped ?? 0,
    flagged: flaggedAll.slice(0, MAX_FLAGGED),
    ...(flaggedAll.length > MAX_FLAGGED ? { flaggedTruncated: flaggedAll.length - MAX_FLAGGED } : {}),
    action: ACTIONS[verdict],
    checkedAt: last.analyzedAt ?? new Date().toISOString(),
    source: 'specter-api',
  };
}
