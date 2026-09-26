// Claude Code PreToolUse hook: runs before every Bash command. When the
// command installs npm packages (or runs one through npx), checks them and
//   block → deny the command
//   warn  → ask the user (never lets the agent decide)
//   allow → no output, the normal permission flow continues
// Anything that fails is `ask` ("could not verify"), never a silent allow.
//
// Registered in .claude/settings.json:
//   { "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [
//       { "type": "command", "command": "node /path/to/specter-mcp.mjs hook claude", "timeout": 90 } ] } ] } }

import { checkTargets, checkLockfile, configFromEnv, lockfileAsPackage } from '../lib/api.mjs';
import { worst } from '../lib/format.mjs';
import { parseInstallCommand } from '../lib/parseCommand.mjs';
import { resolveTree } from '../lib/deep.mjs';

// Below the 90 s hook timeout in the settings snippet, so the hook always
// answers itself instead of being killed.
const BUDGET_MS = 75_000;

/** Short, single-paragraph reason for Claude Code's permission UI. */
function reasonText(result) {
  const flagged = result.packages.filter((p) => p.verdict !== 'allow');
  const parts = flagged.slice(0, 5).map((p) => {
    const r = p.reasons[0];
    const id = r?.advisoryId && !r.detail.includes(r.advisoryId) ? ` (${r.advisoryId})` : '';
    return `${p.verdict.toUpperCase()} ${p.package}: ${r ? `${r.title} - ${r.detail}${id}` : 'flagged'}`;
  });
  if (flagged.length > 5) parts.push(`and ${flagged.length - 5} more`);
  const lead = result.verdict === 'block' ? 'Specter blocked this install.' : 'Specter flagged this install; confirm before running it.';
  return `${lead} ${parts.join(' | ')}`;
}

/** --deep: resolve each npm install's full tree and check it as a lockfile; fall back to the direct check on failure. */
async function deepCheck(targets, opts) {
  const direct = [];
  const byDir = new Map();
  for (const t of targets) {
    if (t.kind === 'package' && t.manager === 'npm' && !t.exec) {
      if (!byDir.has(t.cwd)) byDir.set(t.cwd, []);
      byDir.get(t.cwd).push(t);
    } else direct.push(t);
  }
  const results = [];
  for (const [dir, group] of byDir) {
    try {
      const lockfile = await resolveTree(dir, group.map((t) => t.raw), opts.deadline);
      results.push(lockfileAsPackage(await checkLockfile({ lockfile }, opts), { raw: `npm install ${group.map((t) => t.raw).join(' ')}` }));
    } catch {
      direct.push(...group); // e.g. a workspace project the temp copy can't resolve
    }
  }
  if (direct.length) results.push(...(await checkTargets(direct, opts)).packages);
  const verdict = worst(results.map((r) => r.verdict));
  return { verdict, packages: results };
}

/** Returns the hook's stdout object, or null for "no opinion" (exit 0, no output). */
export async function decide(input, { deep = false, config = configFromEnv() } = {}) {
  if (input?.tool_name !== 'Bash') return null;
  const command = input.tool_input?.command;
  if (typeof command !== 'string') return null;

  const targets = parseInstallCommand(command, input.cwd || process.cwd());
  if (targets.length === 0) return null;

  const opts = { config, deadline: Date.now() + BUDGET_MS };
  let result;
  try {
    result = deep ? await deepCheck(targets, opts) : await checkTargets(targets, opts);
  } catch (e) {
    return out('ask', `Specter could not verify this install (${e.message}). Confirm before running it.`);
  }
  if (result.verdict === 'allow') return null;
  return out(result.verdict === 'block' ? 'deny' : 'ask', reasonText(result));
}

function out(permissionDecision, permissionDecisionReason) {
  return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision, permissionDecisionReason } };
}

async function readStdin() {
  let text = '';
  for await (const chunk of process.stdin) text += chunk;
  return text;
}

export async function runClaudeHook(argv) {
  let result;
  try {
    const input = JSON.parse(await readStdin());
    result = await decide(input, { deep: argv.includes('--deep') });
  } catch (e) {
    result = out('ask', `Specter hook failed (${e.message}). Confirm before running this command.`);
  }
  if (result) process.stdout.write(JSON.stringify(result));
  process.exit(0);
}
