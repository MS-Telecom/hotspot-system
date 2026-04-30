require('dotenv').config();

const readline = require('readline');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('Missing SUPABASE_URL or SUPABASE_KEY in environment.');
  process.exit(1);
}

const username = process.env.OWNER_USERNAME || process.argv[2];
const email = process.env.OWNER_EMAIL || process.argv[3] || null;
let password = process.env.OWNER_PASSWORD || '';

function askHidden(query) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const onData = (char) => {
      char = String(char);
      if (char === '\n' || char === '\r' || char === '\u0004') return;
      readline.moveCursor(process.stdout, -rl.line.length, 0);
      readline.clearLine(process.stdout, 1);
      process.stdout.write(query + '*'.repeat(rl.line.length));
    };
    process.stdin.on('data', onData);
    rl.question(query, (answer) => {
      process.stdin.removeListener('data', onData);
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

async function main() {
  if (!username) {
    console.error('Usage: node scripts/create-owner.js <username> [email]');
    console.error('Or set OWNER_USERNAME, OWNER_EMAIL and temporary OWNER_PASSWORD.');
    process.exit(1);
  }

  if (!password) password = await askHidden('Owner password: ');
  if (!password || password.length < 8) {
    console.error('Password must have at least 8 characters.');
    process.exit(1);
  }

  const supabase = createClient(supabaseUrl, supabaseKey);
  const passwordHash = bcrypt.hashSync(password, 12);

  const { data: existing, error: findError } = await supabase
    .from('admins')
    .select('id')
    .eq('username', username)
    .maybeSingle();
  if (findError) throw findError;

  if (existing) {
    const { error } = await supabase
      .from('admins')
      .update({ email, password: passwordHash, role: 'owner', updated_at: new Date().toISOString() })
      .eq('id', existing.id);
    if (error) throw error;
    console.log(`Owner updated: ${username}`);
    return;
  }

  const { error } = await supabase.from('admins').insert({
    username,
    email,
    password: passwordHash,
    role: 'owner',
    created_at: new Date().toISOString()
  });
  if (error) throw error;
  console.log(`Owner created: ${username}`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
