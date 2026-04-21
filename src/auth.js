const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { getPool, sql } = require('./db');

const router = express.Router();

router.post('/login', async (req, res) => {
  try {
    const { workspace, username, password } = req.body;

    if (!workspace || !username || !password) {
      return res.status(400).json({
        error: 'workspace, username and password are required',
      });
    }

    const pool = await getPool();

    const result = await pool
      .request()
      .input('workspace', sql.NVarChar, workspace)
      .input('username', sql.NVarChar, username)
      .query(`
        SELECT
          a.id AS account_id,
          a.username,
          a.password_hash,
          a.full_name,
          a.role,
          a.is_active AS account_active,
          d.id AS domain_id,
          d.name AS domain_name,
          d.workspace_code,
          d.is_active AS domain_active
        FROM accounts a
        INNER JOIN domains d ON d.id = a.domain_id
        WHERE d.workspace_code = @workspace
          AND a.username = @username
      `);

    if (result.recordset.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const row = result.recordset[0];

    if (!row.account_active || !row.domain_active) {
      return res.status(403).json({ error: 'Account or domain inactive' });
    }

    const validPassword = await bcrypt.compare(password, row.password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      {
        accountId: row.account_id,
        domainId: row.domain_id,
        username: row.username,
        workspace: row.workspace_code,
        role: row.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      token,
      user: {
        id: row.account_id,
        username: row.username,
        fullName: row.full_name,
        role: row.role,
      },
      domain: {
        id: row.domain_id,
        name: row.domain_name,
        workspace: row.workspace_code,
      },
    });
  } catch (error) {
    console.error('POST /auth/login error', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;