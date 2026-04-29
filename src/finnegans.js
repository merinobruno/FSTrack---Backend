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
    req.domainId = payload.domainId;
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido o expirado.' });
  }
}

router.get('/token', verifyAppToken, async (req, res) => {
  try {
    const pool = await getPool();
    const result = await pool.request()
      .input('domain_id', sql.Int, req.domainId)
      .query(`
        SELECT finnegans_client_id, finnegans_client_secret
        FROM domains
        WHERE id = @domain_id AND is_active = 1
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ error: 'Dominio no encontrado o inactivo.' });
    }

    const { finnegans_client_id, finnegans_client_secret } = result.recordset[0];

    const tokenRes = await fetch(
      `https://api.teamplace.finneg.com/api/oauth/token?grant_type=client_credentials&client_id=${finnegans_client_id}&client_secret=${finnegans_client_secret}`
    );

    if (!tokenRes.ok) {
      return res.status(502).json({ error: 'Error al obtener token de Finnegans.' });
    }

    const token = await tokenRes.text();
    return res.json({ token });
  } catch (err) {
    console.error('GET /finnegans/token error', err);
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

module.exports = router;
