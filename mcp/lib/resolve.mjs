// "lodash", "lodash@^4", "lodash@latest" → one exact version, the way npm
// would pick it. The check API only takes exact versions.

import semver from 'semver';

export const DEFAULT_REGISTRY = 'https://registry.npmjs.org';

/** @scope/name → @scope%2fname, the registry's URL form. */
const registryPath = (name) => name.replace('/', '%2f');

/**
 * Returns one of
 *   { ok: true, version }
 *   { ok: false, reason: 'not_found' | 'no_match' | 'unreachable', message }
 *
 * An exact version is returned as-is without asking the registry: npm removes
 * malicious versions (event-stream@3.3.6 is gone), but the check API still
 * knows them from OSV, and that verdict must not turn into "not found".
 */
export async function resolveVersion(name, spec, { registry = DEFAULT_REGISTRY, timeoutMs = 15_000 } = {}) {
  const exact = spec ? semver.valid(spec) : null;
  if (exact) return { ok: true, version: exact };

  let doc;
  try {
    const res = await fetch(`${registry.replace(/\/+$/, '')}/${registryPath(name)}`, {
      // Abbreviated metadata: just dist-tags and versions, a fraction of the full document
      headers: { accept: 'application/vnd.npm.install-v1+json' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status === 404) {
      return { ok: false, reason: 'not_found', message: `"${name}" is not published on the npm registry.` };
    }
    if (!res.ok) return { ok: false, reason: 'unreachable', message: `The npm registry answered HTTP ${res.status} for "${name}".` };
    doc = await res.json();
  } catch (e) {
    return { ok: false, reason: 'unreachable', message: `Could not reach the npm registry (${e.cause?.code ?? e.name ?? e.message}).` };
  }

  const tags = doc['dist-tags'] ?? {};
  const versions = doc.versions ?? {};
  const tag = spec || 'latest';
  if (typeof tags[tag] === 'string') return { ok: true, version: tags[tag] };

  const range = semver.validRange(spec);
  if (!range) {
    return { ok: false, reason: 'no_match', message: `"${spec}" is neither a version, a range nor a dist-tag of "${name}".` };
  }
  // npm's own preference: the `latest` tag if it satisfies the range, else the
  // highest matching version, skipping deprecated ones when possible.
  if (tags.latest && semver.satisfies(tags.latest, range)) return { ok: true, version: tags.latest };
  const matching = Object.keys(versions).filter((v) => semver.satisfies(v, range));
  const live = matching.filter((v) => !versions[v]?.deprecated);
  const pick = semver.maxSatisfying(live.length ? live : matching, range);
  if (!pick) return { ok: false, reason: 'no_match', message: `No published version of "${name}" matches "${spec}".` };
  return { ok: true, version: pick };
}
