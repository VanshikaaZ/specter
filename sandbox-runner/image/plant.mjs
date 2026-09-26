// Plants fake credentials where real ones live. Runs BEFORE strace starts, so
// writing them is not part of the trace. Every value carries the run's canary
// (SPECTER_CANARY) so a leak of any of them can be recognised in the trace.
import { mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';

const canary = process.env.SPECTER_CANARY;
if (!canary) throw new Error('SPECTER_CANARY not set');
const home = homedir();

const files = {
  '.ssh/id_rsa': `-----BEGIN OPENSSH PRIVATE KEY-----\n${canary}-ssh-key\nZmFrZS1rZXktbm90LXJlYWwtc3BlY3Rlci1zYW5kYm94\n-----END OPENSSH PRIVATE KEY-----\n`,
  '.npmrc': `//registry.npmjs.org/:_authToken=${canary}-npm-file\n`,
  '.aws/credentials': `[default]\naws_access_key_id = ${canary}-aws-id\naws_secret_access_key = ${canary}-aws-secret\n`,
  '.git-credentials': `https://specter:${canary}-git@github.com\n`,
};

for (const [rel, content] of Object.entries(files)) {
  const path = join(home, rel);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, content, { mode: 0o600 });
}
