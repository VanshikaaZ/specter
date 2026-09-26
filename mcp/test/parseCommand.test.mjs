import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseInstallCommand, parseSpec, splitCommands } from '../lib/parseCommand.mjs';

const tmp = mkdtempSync(join(tmpdir(), 'specter-parse-'));
const pkgs = (cmd, cwd = tmp) => parseInstallCommand(cmd, cwd).map((t) => (t.kind === 'package' ? `${t.name}@${t.spec}` : t.kind));

test('npm install with flags, dev deps, scoped and versioned specs', () => {
  assert.deepEqual(pkgs('npm i -D a@1 @s/b'), ['a@1', '@s/b@']);
  assert.deepEqual(pkgs('npm install express lodash@4.17.20 --save-dev'), ['express@', 'lodash@4.17.20']);
  assert.deepEqual(pkgs('npm add --save-exact foo@^1.2.0'), ['foo@^1.2.0']);
  assert.deepEqual(pkgs('npm --prefix sub install --tag beta foo'), ['foo@']);
  assert.deepEqual(pkgs('npm install @scope/pkg@latest'), ['@scope/pkg@latest']);
});

test('non-install npm commands are ignored', () => {
  assert.deepEqual(pkgs('npm run build'), []);
  assert.deepEqual(pkgs('npm test && npm run lint'), []);
  assert.deepEqual(pkgs('npm view lodash version'), []);
  assert.deepEqual(pkgs('echo npm install evil'), []);
  assert.deepEqual(pkgs('git commit -m "npm install evil"'), []);
});

test('npx and npm exec: only the fetched package', () => {
  assert.deepEqual(pkgs('npx -y create-vite@5 my-app --template react'), ['create-vite@5']);
  assert.deepEqual(pkgs('npx --package=typescript@5 -- tsc --version'), ['typescript@5']);
  assert.deepEqual(pkgs('npx -p a -p b cmd'), ['a@', 'b@']);
  assert.deepEqual(pkgs('npm exec -- cowsay hi'), ['cowsay@']);
  assert.deepEqual(pkgs('npx -c "echo hi"'), []);
});

test('npx skips a binary that is already installed locally', () => {
  const proj = mkdtempSync(join(tmpdir(), 'specter-bin-'));
  mkdirSync(join(proj, 'node_modules', '.bin'), { recursive: true });
  writeFileSync(join(proj, 'node_modules', '.bin', 'tsc'), '');
  mkdirSync(join(proj, 'sub'));
  assert.deepEqual(pkgs('npx tsc --noEmit', join(proj, 'sub')), []);
  assert.deepEqual(pkgs('npx tsc@5 --noEmit', proj), ['tsc@5']); // an explicit version is fetched
});

test('pnpm, yarn, bun', () => {
  assert.deepEqual(pkgs('pnpm add -D zod'), ['zod@']);
  assert.deepEqual(pkgs('pnpm --filter web add react@19'), ['react@19']);
  assert.deepEqual(pkgs('pnpm dlx create-next-app@latest'), ['create-next-app@latest']);
  assert.deepEqual(pkgs('yarn add left-pad'), ['left-pad@']);
  assert.deepEqual(pkgs('yarn global add serve'), ['serve@']);
  assert.deepEqual(pkgs('yarn dlx -p cowsay cowsay hi'), ['cowsay@']);
  assert.deepEqual(pkgs('bun add hono'), ['hono@']);
  assert.deepEqual(pkgs('bunx prettier .'), ['prettier@']);
  assert.deepEqual(pkgs('pnpm install'), ['unsupported']);
});

test('compound commands, env prefixes, wrappers and full paths', () => {
  assert.deepEqual(pkgs('cd web && npm i a; CI=1 npm install b | tee log'), ['a@', 'b@']);
  assert.deepEqual(pkgs('sudo npm install -g c'), ['c@']);
  assert.deepEqual(pkgs('"C:\\Program Files\\nodejs\\npm.cmd" install d'), ['d@']);
  assert.deepEqual(pkgs('(npm install e)'), ['e@']);
  assert.deepEqual(pkgs('npm install f \\\n  g'), ['f@', 'g@']);
});

test('bare npm install / npm ci check the lockfile when there is one', () => {
  const proj = mkdtempSync(join(tmpdir(), 'specter-lock-'));
  assert.deepEqual(pkgs('npm ci', proj), ['unsupported']);
  writeFileSync(join(proj, 'package-lock.json'), '{}');
  assert.deepEqual(pkgs('npm ci', proj), ['lockfile']);
  assert.deepEqual(pkgs('npm install', proj), ['lockfile']);
  assert.deepEqual(pkgs('npm install -g'), []);
  const [t] = parseInstallCommand(`cd "${proj}" && npm ci`, tmp);
  assert.equal(t.path, join(proj, 'package-lock.json'));
});

test('non-registry and invalid specs are unsupported, not guessed', () => {
  for (const s of ['git+https://github.com/a/b.git', 'github:a/b', 'a/b', './local', '../x.tgz', 'https://x.test/p.tgz', 'foo@file:../foo', 'foo@workspace:*', 'foo@git+ssh://x']) {
    assert.equal(parseSpec(s).nonRegistry !== undefined, true, s);
  }
  assert.ok(parseSpec('.hidden').nonRegistry || parseSpec('.hidden').invalid);
  assert.ok(parseSpec('Bad Name').invalid);
});

test('npm aliases resolve to the real package', () => {
  assert.deepEqual(parseSpec('my-lodash@npm:lodash@4.17.21'), { name: 'lodash', spec: '4.17.21', alias: 'my-lodash' });
  assert.deepEqual(pkgs('npm i x@npm:@s/y@2'), ['@s/y@2']);
});

test('tokenizer honours quotes', () => {
  assert.deepEqual(splitCommands(`npm i "a" 'b' && echo "x && y"`), [['npm', 'i', 'a', 'b'], ['echo', 'x && y']]);
});
