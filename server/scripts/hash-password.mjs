#!/usr/bin/env node
// Generates a bcrypt hash for ROBIN_TOOLS_AUTH_PASSWORD_HASH (standalone
// deployments with ROBIN_TOOLS_AUTH_MODE=basic).
//
// Usage: node scripts/hash-password.mjs 'your-password'

import bcrypt from 'bcryptjs';

const password = process.argv[2];
if (!password) {
  console.error('Usage: node scripts/hash-password.mjs <password>');
  process.exit(1);
}

const hash = bcrypt.hashSync(password, 12);
console.log(hash);
console.log('\nFor docker-compose --env-file usage, escape $ as $$ (docker compose interpolates .env values):');
console.log(hash.split('$').join('$$'));

