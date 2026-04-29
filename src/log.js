const express = require('express');
const jwt = require('jsonwebtoken');
const { getPool, sql } = require('./db');

const router = express.Router();

function verifyAppToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No autorizado.' });
  }
  try {
    const payload = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    req.accountId = payload.accountId;
    req.domainId = payload.domainId;
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido o expirado.' });
  }
}

router.post('/', verifyAppToken, async (req, res) => {
  try {
    const { form_type, lote, categoria, cantidad, deposito, status, error_detail } = req.body;

    if (!form_type || !status) {
      return res.status(400).json({ error: 'form_type y status son requeridos.' });
    }

    const cantidadInt =
      cantidad != null && cantidad !== '' ? parseInt(cantidad, 10) : null;

    const pool = await getPool();
    await pool.request()
      .input('account_id', sql.Int, req.accountId)
      .input('domain_id',  sql.Int, req.domainId)
      .input('form_type',  sql.NVarChar, form_type)
      .input('lote',       sql.NVarChar, lote       || null)
      .input('categoria',  sql.NVarChar, categoria  || null)
      .input('cantidad',   sql.Int,      isNaN(cantidadInt) ? null : cantidadInt)
      .input('deposito',   sql.NVarChar, deposito   || null)
      .input('status',     sql.NVarChar, status)
      .input('error_detail', sql.NVarChar, error_detail || null)
      .query(`
        INSERT INTO logs
          (account_id, domain_id, form_type, lote, categoria, cantidad, deposito, status, error_detail)
        VALUES
          (@account_id, @domain_id, @form_type, @lote, @categoria, @cantidad, @deposito, @status, @error_detail)
      `);

    return res.json({ ok: true });
  } catch (err) {
    console.error('POST /log error', err);
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

module.exports = router;
