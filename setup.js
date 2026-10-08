const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const configPath = path.join(__dirname, 'config.json');

function saveHash(hash) {
  let existing = {};
  if (fs.existsSync(configPath)) {
    try { existing = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch (_) {}
  }
  existing.passwordHash = hash;
  fs.writeFileSync(configPath, JSON.stringify(existing, null, 2), 'utf8');
}

async function run() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const question = (q) => new Promise(r => rl.question(q, r));
  try {
    const pw = await question('New password: ');
    const pw2 = await question('Confirm password: ');
    if (pw !== pw2) { console.error('Passwords do not match.'); process.exit(1); }
    if (pw.length < 8) { console.error('Password must be at least 8 characters.'); process.exit(1); }
    const hash = await bcrypt.hash(pw, 12);
    saveHash(hash);
    console.log('Password updated. Restart server to apply changes.');
  } finally {
    rl.close();
  }
}

run().catch(err => { console.error(err.message); process.exit(1); });
