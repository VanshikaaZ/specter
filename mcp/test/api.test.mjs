import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkOne, checkTargets, checkLockfile, configFromEnv, InputError } from '../lib/api.mjs';
import { resolveVersion } from '../lib/resolve.mjs';
import { toText } from '../lib/format.mjs';
import { parseInstallCommand } from '../lib/parseCommand.mjs';
import { startStub } from './stub.mjs';

let stub;
before(async () => { stub = await startStub(); });
after(() => stub.close());
const opts = () => ({ config: { ...stub.config }, deadline: Date.now() + 20_000 });

test('resolves tags and ranges the way npm does', async () => {
  const reg = { registry: stub.config.registry };
  assert.deepEqual(await resolveVersion('good-pkg', '', reg), { ok: true, version: '1.2.0' });
  assert.deepEqual(await resolveVersion('good-pkg', 'next', reg), { ok: true, version: '2.0.0-beta.1' });
  assert.deepEqual(await resolveVersion('good-pkg', '^1.0.0', reg), { ok: true, version: '1.2.0' }); // latest satisfies
  assert.deepEqual(await resolveVersion('good-pkg', '~1.1.0', reg), { ok: true, version: '1.1.0' });
  assert.deepEqual(await resolveVersion('good-pkg', '>=1.3.0 <2', reg), { ok: true, version: '1.3.0' }); // only a deprecated one matches
  assert.equal((await resolveVersion('good-pkg', '^9', reg)).reason, 'no_match');
  assert.equal((await resolveVersion('no-such-pkg', '', reg)).reason, 'not_found');
  assert.deepEqual(await resolveVersion('@scope/pkg', '', reg), { ok: true, version: '3.0.0' });
});

test('an exact version skips the registry, so unpublished malware still gets its verdict', async () => {
  const before = stub.calls.length;
  const r = await checkOne({ name: 'event-stream', version: '3.3.6' }, opts());
  assert.equal(r.verdict, 'block');
  assert.equal(r.package, 'event-stream@3.3.6');
  assert.ok(!stub.calls.slice(before).some((c) => c.url.startsWith('/registry/')));
});

test('block, warn, allow map straight through with the §5 shape', async () => {
  const b = await checkOne({ name: 'bad-pkg' }, opts());
  assert.equal(b.verdict, 'block');
  assert.equal(b.package, 'bad-pkg@6.6.6');
  assert.equal(b.requested, 'bad-pkg');
  assert.equal(b.score, 15);
  assert.equal(b.action, 'DO NOT INSTALL. Remove it if already present.');
  assert.deepEqual(b.reasons[0], { type: 'osv_malicious', severity: 'critical', title: 'Reported as malicious code', detail: 'GHSA-xxxx: malicious', advisoryId: 'GHSA-xxxx' });
  assert.equal(b.source, 'specter-api');
  assert.match(toText(b), /^BLOCK {2}bad-pkg@6\.6\.6 \(score 15\)/);

  assert.equal((await checkOne({ name: 'good-pkg', version: '^1' }, opts())).verdict, 'allow');
  assert.equal((await checkOne({ name: 'warn-pkg', version: '1.0.0' }, opts())).verdict, 'warn');
});

test('202 is polled until the verdict is ready', async () => {
  const r = await checkOne({ name: 'slow-pkg' }, opts());
  assert.equal(r.verdict, 'allow');
  assert.equal(stub.calls.filter((c) => c.body?.name === 'slow-pkg').length, 2);
});

test('fail closed: rate limit, unreachable API, non-API URL and deadline are warn, never allow', async () => {
  const rate = await checkOne({ name: 'rate-pkg' }, opts());
  assert.equal(rate.verdict, 'warn');
  assert.equal(rate.reasons[0].type, 'unverified');
  assert.match(rate.reasons[0].detail, /Rate limited/);

  const down = await checkOne({ name: 'x', version: '1.0.0' }, { config: { ...stub.config, apiUrl: 'http://127.0.0.1:9' }, deadline: Date.now() + 5000 });
  assert.equal(down.verdict, 'warn');
  assert.match(down.reasons[0].detail, /Could not reach/);

  const html = await checkOne({ name: 'x', version: '1.0.0' }, { config: { ...stub.config, apiUrl: `${stub.config.apiUrl}/noapi` }, deadline: Date.now() + 5000 });
  assert.equal(html.verdict, 'warn');
  assert.match(html.reasons[0].detail, /did not answer as the Specter check API/);

  const late = await checkOne({ name: 'x', version: '1.0.0' }, { config: stub.config, deadline: Date.now() });
  assert.equal(late.verdict, 'warn');
  assert.equal(late.reasons[0].title, 'Analysis not finished');
});

test('made-up package names and unknown versions are flagged as not published', async () => {
  const r = await checkOne({ name: 'no-such-pkg' }, opts());
  assert.equal(r.verdict, 'warn');
  assert.equal(r.reasons[0].type, 'not_found');
  const gone = await checkOne({ name: 'gone-pkg', version: '1.0.0' }, opts());
  assert.equal(gone.verdict, 'warn');
  assert.equal(gone.reasons[0].title, 'Not published on npm');
});

test('invalid names are input errors', async () => {
  await assert.rejects(checkOne({ name: 'Not A Name' }, opts()), InputError);
});

test('signal text from the package is cleaned and capped', async () => {
  const r = await checkOne({ name: 'inject-pkg' }, opts());
  const [reason] = r.reasons;
  assert.equal(reason.title, 'New publisher');
  assert.ok(reason.detail.length <= 200);
  assert.ok(!/[\u0000-\u001f‮]/.test(reason.detail));
  assert.equal(r.verdict, 'warn'); // the text changes nothing
  assert.equal(r.action, 'Tell the user these reasons and ask before installing.');
});

test('cooldown options from env and args reach the API', async () => {
  const cfg = { ...stub.config, minReleaseAgeHours: 24, allow: ['lodash@4.17.21'] };
  await checkOne({ name: 'good-pkg', version: '1.0.0', strict: true }, { config: cfg, deadline: Date.now() + 5000 });
  const call = stub.calls.filter((c) => c.url === '/api/v1/check').at(-1);
  assert.deepEqual(call.body, { name: 'good-pkg', version: '1.0.0', minReleaseAgeHours: 24, strict: true, allow: ['lodash@4.17.21'] });

  const env = configFromEnv({ SPECTER_API_URL: 'http://x/', SPECTER_MIN_RELEASE_AGE_HOURS: '48', SPECTER_STRICT: '1', SPECTER_ALLOW: 'a@1.0.0, b@2.0.0' });
  assert.deepEqual(env, { apiUrl: 'http://x', registry: 'https://registry.npmjs.org', minReleaseAgeHours: 48, strict: true, allow: ['a@1.0.0', 'b@2.0.0'] });
  assert.equal(configFromEnv({}).minReleaseAgeHours, undefined);
});

test('a command: worst verdict wins; unsupported sources are warn', async () => {
  const cmd = await checkTargets(parseInstallCommand('npm i good-pkg bad-pkg github:a/b'), opts());
  assert.equal(cmd.verdict, 'block');
  assert.deepEqual(cmd.packages.map((p) => p.verdict), ['allow', 'block', 'warn']);
  assert.equal(cmd.packages[2].reasons[0].type, 'unsupported');

  const none = await checkTargets(parseInstallCommand('npm run build'), opts());
  assert.equal(none.verdict, 'allow');
  assert.equal(none.packages.length, 0);
});

test('lockfile check: flagged only, bad input is an input error', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'specter-lf-'));
  const path = join(dir, 'package-lock.json');
  writeFileSync(path, JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/good-pkg': {}, 'node_modules/bad-pkg': {} } }));
  const r = await checkLockfile({ path }, opts());
  assert.equal(r.verdict, 'block');
  assert.equal(r.checked, 2);
  assert.deepEqual(r.flagged.map((p) => p.package), ['bad-pkg@1.0.0']);

  const viaCommand = await checkTargets(parseInstallCommand('npm ci', dir), opts());
  assert.equal(viaCommand.verdict, 'block');

  writeFileSync(path, JSON.stringify({ lockfileVersion: 1, dependencies: {} }));
  await assert.rejects(checkLockfile({ path }, opts()), InputError);
  await assert.rejects(checkLockfile({ path: join(dir, 'missing.json') }, opts()), /No lockfile/);
});
