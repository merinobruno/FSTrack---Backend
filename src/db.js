const sql = require('mssql');

const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: {
    encrypt: true,
    trustServerCertificate: false,
  },
};

let pool = null;

async function getPool() {
  if (pool) return pool;
  pool = await sql.connect(config);
  // Ping every 4 min to prevent Azure SQL Serverless from autopausing
  setInterval(async () => {
    try { await pool.request().query('SELECT 1'); } catch {}
  }, 4 * 60 * 1000);
  return pool;
}

module.exports = { sql, getPool };
