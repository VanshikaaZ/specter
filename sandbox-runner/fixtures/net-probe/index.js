// TEST FIXTURE: reserved .invalid domain and RFC 5737 documentation IP, unreachable everywhere.
require('dns').lookup('probe.specter-test.invalid', () => {});
require('http').get({ host: '192.0.2.1', port: 80, timeout: 1500 }, () => {}).on('error', () => {});
