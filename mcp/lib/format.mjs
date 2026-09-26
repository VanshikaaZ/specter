// Result shape and text rendering shared by the MCP tools, hook and shims.
//
// Signal text comes from package metadata and advisories, which an attacker
// can write. It is cleaned and length-capped here and only ever placed inside
// a result field, never into the instruction text around it.

export const ACTIONS = {
  block: 'DO NOT INSTALL. Remove it if already present.',
  warn: 'Tell the user these reasons and ask before installing.',
  allow: 'OK to install. Pin the exact version that was checked.',
};

const RANK = { allow: 0, warn: 1, block: 2 };
export const worst = (verdicts) => verdicts.reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'allow');

// C0/C1 controls, and bidi overrides that can make text read differently than it is
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g;

export function clean(text, max) {
  const s = String(text ?? '').replace(UNSAFE, '').replace(/\s+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** One API signal → one reason, cleaned. */
export function toReason(s) {
  return {
    type: clean(s.type, 40),
    severity: clean(s.severity, 12),
    title: clean(s.title, 120),
    detail: clean(s.detail, 200),
    ...(s.advisoryId ? { advisoryId: clean(s.advisoryId, 60) } : {}),
  };
}

/** A result for a package that could not be checked: always `warn`, never `allow`. */
export function unverified(requested, title, detail, extra = {}) {
  return {
    verdict: 'warn',
    package: requested,
    requested,
    score: null,
    reasons: [{ type: 'unverified', severity: 'medium', title, detail: clean(detail, 200) }],
    action: ACTIONS.warn,
    checkedAt: new Date().toISOString(),
    source: 'specter-guard-mcp',
    ...extra,
  };
}

const TAG = { block: 'BLOCK', warn: 'WARN ', allow: 'ALLOW' };

function packageLines(r) {
  const lines = [`${TAG[r.verdict]}  ${r.package}${r.score !== null && r.score !== undefined ? ` (score ${r.score})` : ''}${r.package !== r.requested ? `  [requested ${r.requested}]` : ''}`];
  for (const reason of r.reasons.filter((x) => x.severity !== 'info').slice(0, 5)) {
    const id = reason.advisoryId && !reason.detail.includes(reason.advisoryId) ? ` (${reason.advisoryId})` : '';
    lines.push(`  - [${reason.severity}] ${reason.title}: ${reason.detail}${id}`);
  }
  return lines;
}

/** Text form for one result, a multi-package result, or a lockfile result. */
export function toText(result) {
  const lines = [];
  if (result.packages) {
    // Multi-package / command result
    if (result.packages.length === 0) return result.note ?? 'Nothing to check.';
    lines.push(`Overall: ${result.verdict.toUpperCase()} (${result.packages.length} checked)`);
    for (const r of result.packages) lines.push(...packageLines(r));
  } else if (result.counts) {
    // Lockfile result
    const c = result.counts;
    lines.push(`Overall: ${result.verdict.toUpperCase()}  ${result.checked} packages: ${c.block} block, ${c.warn} warn, ${c.pending} unfinished, ${c.allow} allow${result.skipped ? `; ${result.skipped} non-registry entries skipped` : ''}`);
    for (const r of result.flagged.slice(0, 20)) lines.push(...packageLines(r));
    const more = Math.max(0, result.flagged.length - 20) + (result.flaggedTruncated ?? 0);
    if (more) lines.push(`  … and ${more} more flagged packages.`);
    if (result.error) for (const r of result.reasons) lines.push(`  - [${r.severity}] ${r.title}: ${r.detail}`);
  } else {
    lines.push(...packageLines(result));
  }
  lines.push(`Action: ${result.action}`);
  return lines.join('\n');
}
