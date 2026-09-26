// The real entry point, spawned the way agents spawn it.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { startStub } from './stub.mjs';

const ENTRY = fileURLToPath(new URL('../specter-mcp.mjs', import.meta.url));
let stub;
let client;

before(async () => {
  stub = await startStub();
  client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [ENTRY], env: { ...process.env, ...stub.env }, stderr: 'ignore' }));
});
after(async () => {
  await client.close();
  await stub.close();
});

test('lists the four read-only tools and sends instructions', async () => {
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name).sort(), ['check_install_command', 'check_lockfile', 'check_package', 'check_packages']);
  for (const t of tools) assert.deepEqual(t.annotations, { readOnlyHint: true, openWorldHint: true, idempotentHint: true });
  assert.match(client.getInstructions(), /If the verdict is "block", do not install it/);
});

test('check_package: block is a normal result with structured content', async () => {
  const r = await client.callTool({ name: 'check_package', arguments: { name: 'bad-pkg' } });
  assert.notEqual(r.isError, true);
  assert.equal(r.structuredContent.verdict, 'block');
  assert.equal(r.structuredContent.package, 'bad-pkg@6.6.6');
  assert.match(r.content[0].text, /^BLOCK {2}bad-pkg@6\.6\.6/);
});

test('check_package: an invalid name is an MCP error', async () => {
  const r = await client.callTool({ name: 'check_package', arguments: { name: 'Not A Name' } });
  assert.equal(r.isError, true);
});

test('check_packages and check_install_command', async () => {
  const many = await client.callTool({ name: 'check_packages', arguments: { packages: [{ name: 'good-pkg' }, { name: 'warn-pkg', version: '1.0.0' }] } });
  assert.equal(many.structuredContent.verdict, 'warn');

  const cmd = await client.callTool({ name: 'check_install_command', arguments: { command: 'cd x && npm install good-pkg@^1 --save-dev && npx bad-pkg' } });
  assert.equal(cmd.structuredContent.verdict, 'block');
  assert.deepEqual(cmd.structuredContent.packages.map((p) => p.package), ['good-pkg@1.2.0', 'bad-pkg@6.6.6']);
});

test('check_lockfile: a missing file is an MCP error', async () => {
  const r = await client.callTool({ name: 'check_lockfile', arguments: { path: 'definitely/missing/package-lock.json' } });
  assert.equal(r.isError, true);
});

function runHook(input, env = stub.env, args = ['hook', 'claude']) {
  return new Promise((done) => {
    const child = spawn(process.execPath, [ENTRY, ...args], { env: { ...process.env, ...env } });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.on('close', (code) => done({ code, out: out ? JSON.parse(out) : null }));
    child.stdin.end(typeof input === 'string' ? input : JSON.stringify(input));
  });
}
const bash = (command) => ({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, cwd: process.cwd() });

test('hook: block → deny with the reason', async () => {
  const { code, out } = await runHook(bash('npm install bad-pkg'));
  assert.equal(code, 0);
  assert.equal(out.hookSpecificOutput.hookEventName, 'PreToolUse');
  assert.equal(out.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /Specter blocked this install\. BLOCK bad-pkg@6\.6\.6: Reported as malicious code/);
});

test('hook: warn → ask; allow and non-install commands → no output', async () => {
  assert.equal((await runHook(bash('npm i warn-pkg@1.0.0'))).out.hookSpecificOutput.permissionDecision, 'ask');
  assert.equal((await runHook(bash('npm install good-pkg'))).out, null);
  assert.equal((await runHook(bash('ls -la && npm test'))).out, null);
  assert.equal((await runHook({ tool_name: 'Read', tool_input: { file_path: 'x' } })).out, null);
});

test('hook: API down → ask, never a silent allow; broken input → ask', async () => {
  const down = await runHook(bash('npm install good-pkg@1.0.0'), { SPECTER_API_URL: 'http://127.0.0.1:9', SPECTER_NPM_REGISTRY: stub.env.SPECTER_NPM_REGISTRY });
  assert.equal(down.out.hookSpecificOutput.permissionDecision, 'ask');
  assert.match(down.out.hookSpecificOutput.permissionDecisionReason, /Could not reach/);

  const broken = await runHook('not json');
  assert.equal(broken.out.hookSpecificOutput.permissionDecision, 'ask');
});

test('print-config emits valid JSON snippets with absolute paths', async () => {
  const out = await new Promise((done) => {
    const child = spawn(process.execPath, [ENTRY, 'print-config', 'cursor']);
    let s = '';
    child.stdout.on('data', (d) => (s += d));
    child.on('close', () => done(s));
  });
  const json = JSON.parse(out.slice(out.indexOf('{')));
  assert.equal(json.mcpServers.specter.args[0], ENTRY);
});
