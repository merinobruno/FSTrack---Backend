require('dotenv').config();
const bcrypt = require('bcrypt');
const { getPool, sql } = require('./src/db');

async function main() {
  const workspace = 'fisterra';
  const username = 'admin';
  const password = '1234';
  const fullName = 'Admin';
  const role = 'admin';

  const passwordHash = await bcrypt.hash(password, 10);

  const pool = await getPool();

  const domainResult = await pool
    .request()
    .input('workspace', sql.NVarChar, workspace)
    .query(`
      SELECT id
      FROM domains
      WHERE workspace_code = @workspace
    `);

  if (domainResult.recordset.length === 0) {
    throw new Error('Domain not found');
  }

  const domainId = domainResult.recordset[0].id;

  await pool
    .request()
    .input('domainId', sql.Int, domainId)
    .input('username', sql.NVarChar, username)
    .input('passwordHash', sql.NVarChar, passwordHash)
    .input('fullName', sql.NVarChar, fullName)
    .input('role', sql.NVarChar, role)
    .query(`
      INSERT INTO accounts (domain_id, username, password_hash, full_name, role)
      VALUES (@domainId, @username, @passwordHash, @fullName, @role)
    `);

  console.log('User created successfully');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});