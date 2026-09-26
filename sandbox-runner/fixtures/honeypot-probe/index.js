// TEST FIXTURE: reads only the fake key the sandbox plants, nothing is sent anywhere.
try { require('fs').readFileSync(require('os').homedir() + '/.ssh/id_rsa', 'utf8'); } catch {}
