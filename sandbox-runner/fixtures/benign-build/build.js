// A typical postinstall: generate a file inside the package itself.
const fs = require('fs');
const path = require('path');
fs.mkdirSync(path.join(__dirname, 'dist'), { recursive: true });
fs.writeFileSync(path.join(__dirname, 'dist', 'index.js'), "module.exports = { add: (a, b) => a + b };\n");
console.log('built', process.platform, process.arch);
