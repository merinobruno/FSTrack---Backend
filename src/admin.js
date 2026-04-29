const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { getPool, sql } = require('./db');

const router = express.Router();

const ADMIN_USERNAME = 'bmerino';
const ADMIN_PASSWORD = 'Bmerino2025%';

function adminSecret() {
  return (process.env.JWT_SECRET || 'fallback') + '_admin';
}

function requireAdmin(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No autorizado.' });
  }
  try {
    const payload = jwt.verify(auth.slice(7), adminSecret());
    if (!payload.admin) return res.status(401).json({ error: 'No autorizado.' });
    next();
  } catch {
    return res.status(401).json({ error: 'Sesión inválida o expirada.' });
  }
}

router.get('/', (_req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(ADMIN_HTML);
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Credenciales incorrectas.' });
  }
  const token = jwt.sign({ admin: true }, adminSecret(), { expiresIn: '8h' });
  return res.json({ token });
});

router.get('/domains', requireAdmin, async (req, res) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT id, name, workspace_code
      FROM domains
      WHERE is_active = 1
      ORDER BY name
    `);
    return res.json({ domains: result.recordset });
  } catch (err) {
    console.error('GET /admin/domains error', err);
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

router.post('/create-domain', requireAdmin, async (req, res) => {
  try {
    const { name, workspace_code, finnegans_client_id, finnegans_client_secret } = req.body;
    if (!name || !workspace_code || !finnegans_client_id || !finnegans_client_secret) {
      return res.status(400).json({ error: 'Todos los campos son requeridos.' });
    }
    const pool = await getPool();
    await pool.request()
      .input('name', sql.NVarChar, name.trim())
      .input('workspace_code', sql.NVarChar, workspace_code.trim().toLowerCase())
      .input('finnegans_client_id', sql.NVarChar, finnegans_client_id.trim())
      .input('finnegans_client_secret', sql.NVarChar, finnegans_client_secret.trim())
      .query(`
        INSERT INTO domains (name, workspace_code, finnegans_client_id, finnegans_client_secret, is_active)
        VALUES (@name, @workspace_code, @finnegans_client_id, @finnegans_client_secret, 1)
      `);
    return res.json({ ok: true, message: `Dominio "${name.trim()}" creado correctamente.` });
  } catch (err) {
    console.error('POST /admin/create-domain error', err);
    if (err.number === 2627 || err.number === 2601) {
      return res.status(409).json({ error: 'Ya existe un dominio con ese workspace_code.' });
    }
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

router.post('/create-account', requireAdmin, async (req, res) => {
  try {
    const { username, password, full_name, role, domain_id } = req.body;
    if (!username || !password || !full_name || !role || !domain_id) {
      return res.status(400).json({ error: 'Todos los campos son requeridos.' });
    }
    const password_hash = await bcrypt.hash(password, 12);
    const pool = await getPool();
    await pool.request()
      .input('username', sql.NVarChar, username.trim())
      .input('password_hash', sql.NVarChar, password_hash)
      .input('full_name', sql.NVarChar, full_name.trim())
      .input('role', sql.NVarChar, role)
      .input('domain_id', sql.Int, parseInt(domain_id, 10))
      .query(`
        INSERT INTO accounts (username, password_hash, full_name, role, is_active, domain_id)
        VALUES (@username, @password_hash, @full_name, @role, 1, @domain_id)
      `);
    return res.json({ ok: true, message: `Cuenta "${username.trim()}" creada correctamente.` });
  } catch (err) {
    console.error('POST /admin/create-account error', err);
    if (err.number === 2627 || err.number === 2601) {
      return res.status(409).json({ error: 'Ya existe una cuenta con ese nombre de usuario en ese dominio.' });
    }
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

router.get('/logs', requireAdmin, async (req, res) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT TOP 200
        l.id,
        l.form_type,
        l.lote,
        l.categoria,
        l.cantidad,
        l.deposito,
        l.status,
        l.error_detail,
        l.created_at,
        a.username,
        a.full_name,
        d.name AS domain_name
      FROM logs l
      INNER JOIN accounts a ON a.id = l.account_id
      INNER JOIN domains  d ON d.id = l.domain_id
      ORDER BY l.created_at DESC
    `);
    return res.json({ logs: result.recordset });
  } catch (err) {
    console.error('GET /admin/logs error', err);
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

module.exports = router;

/* ─── Admin HTML ──────────────────────────────────────────────────────────── */

const ADMIN_HTML = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FSTrack — Admin</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
    }

    .hidden { display: none !important; }

    /* ── LOGIN ─────────────────────────────── */
    #login-panel {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1rem;
    }

    .login-card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 16px;
      padding: 2rem;
      width: 100%;
      max-width: 360px;
    }

    .login-card h1 {
      font-size: 1.5rem;
      font-weight: 700;
      color: #f1f5f9;
      margin-bottom: 0.25rem;
    }

    .login-card .subtitle {
      font-size: 0.875rem;
      color: #64748b;
      margin-bottom: 1.75rem;
    }

    /* ── DASHBOARD ─────────────────────────── */
    #dashboard {
      padding: 1.5rem;
      max-width: 960px;
      margin: 0 auto;
    }

    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1.75rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid #334155;
    }

    header h1 { font-size: 1.25rem; font-weight: 700; color: #f1f5f9; }

    .badge {
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      background: rgba(99,102,241,0.2);
      color: #a5b4fc;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      margin-left: 0.5rem;
      vertical-align: middle;
    }

    /* ── FORMS GRID ─────────────────────────── */
    .forms-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.25rem;
    }

    @media (max-width: 640px) {
      .forms-grid { grid-template-columns: 1fr; }
    }

    /* ── CARD ───────────────────────────────── */
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 16px;
      padding: 1.5rem;
    }

    .card h2 {
      font-size: 0.9375rem;
      font-weight: 600;
      color: #f1f5f9;
      margin-bottom: 1.25rem;
    }

    /* ── FORM ELEMENTS ─────────────────────── */
    .field { margin-bottom: 0.875rem; }

    label {
      display: block;
      font-size: 0.8rem;
      font-weight: 500;
      color: #94a3b8;
      margin-bottom: 0.3rem;
    }

    input, select {
      width: 100%;
      padding: 0.55rem 0.75rem;
      border-radius: 8px;
      border: 1px solid #475569;
      background: #0f172a;
      color: #e2e8f0;
      font-size: 0.875rem;
      outline: none;
      transition: border-color 0.15s;
      -webkit-appearance: none;
    }

    input:focus, select:focus { border-color: #6366f1; }

    select option { background: #1e293b; }

    small {
      display: block;
      font-size: 0.73rem;
      color: #64748b;
      margin-top: 0.25rem;
      line-height: 1.4;
    }

    /* ── BUTTONS ────────────────────────────── */
    .btn {
      padding: 0.6rem 1rem;
      border: none;
      border-radius: 8px;
      font-size: 0.875rem;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.15s;
    }

    .btn:disabled { opacity: 0.45; cursor: not-allowed; }

    .btn-primary {
      width: 100%;
      background: #6366f1;
      color: #fff;
      margin-top: 0.5rem;
    }

    .btn-primary:not(:disabled):hover { opacity: 0.85; }

    .btn-ghost {
      background: transparent;
      color: #94a3b8;
      border: 1px solid #334155;
      font-size: 0.8rem;
    }

    .btn-ghost:hover { color: #f1f5f9; border-color: #475569; }

    /* ── MESSAGES ───────────────────────────── */
    .msg {
      margin-top: 0.75rem;
      font-size: 0.8125rem;
      padding: 0.6rem 0.8rem;
      border-radius: 8px;
      line-height: 1.4;
    }

    .msg.success {
      background: rgba(16,185,129,0.1);
      border: 1px solid rgba(16,185,129,0.3);
      color: #6ee7b7;
    }

    .msg.error {
      background: rgba(239,68,68,0.1);
      border: 1px solid rgba(239,68,68,0.3);
      color: #fca5a5;
    }

    /* ── LOGS TABLE ─────────────────────────── */
    .logs-card { margin-top: 1.25rem; }

    .logs-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
    }

    .logs-table th, .logs-table td {
      padding: 0.5rem 0.75rem;
      text-align: left;
      border-bottom: 1px solid #1e293b;
      white-space: nowrap;
    }

    .logs-table th {
      color: #64748b;
      font-weight: 500;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      background: #0f172a;
    }

    .logs-table tbody tr:hover { background: rgba(255,255,255,0.02); }

    .tag-ok  { color: #6ee7b7; font-weight: 600; }
    .tag-err { color: #fca5a5; font-weight: 600; }
    .err-detail { color: #64748b; font-size: 0.75rem; display: block; margin-top: 2px; white-space: normal; max-width: 260px; }
  </style>
</head>
<body>

  <!-- LOGIN -->
  <div id="login-panel">
    <div class="login-card">
      <h1>FSTrack</h1>
      <p class="subtitle">Panel de administración</p>
      <form id="login-form">
        <div class="field">
          <label for="lu">Usuario</label>
          <input id="lu" type="text" autocomplete="username" required>
        </div>
        <div class="field">
          <label for="lp">Contraseña</label>
          <input id="lp" type="password" autocomplete="current-password" required>
        </div>
        <button class="btn btn-primary" type="submit" id="login-btn">Ingresar</button>
        <p id="login-msg" class="msg hidden"></p>
      </form>
    </div>
  </div>

  <!-- DASHBOARD -->
  <div id="dashboard" class="hidden">
    <header>
      <h1>FSTrack <span class="badge">Admin</span></h1>
      <button class="btn btn-ghost" id="logout-btn">Cerrar sesión</button>
    </header>

    <div class="forms-grid">

      <!-- Crear Dominio -->
      <div class="card">
        <h2>Crear Dominio</h2>
        <form id="domain-form">
          <div class="field">
            <label for="dn">Nombre</label>
            <input id="dn" type="text" placeholder="Fisterra SRL" required>
          </div>
          <div class="field">
            <label for="dw">Workspace Code</label>
            <input id="dw" type="text" placeholder="fisterra" autocomplete="off" required>
            <small>Código único en minúsculas. Los usuarios lo ingresan al iniciar sesión en la app.</small>
          </div>
          <div class="field">
            <label for="dci">Finnegans Client ID</label>
            <input id="dci" type="text" autocomplete="off" required>
          </div>
          <div class="field">
            <label for="dcs">Finnegans Client Secret</label>
            <input id="dcs" type="password" autocomplete="off" required>
          </div>
          <button class="btn btn-primary" type="submit" id="domain-btn">Crear Dominio</button>
          <p id="domain-msg" class="msg hidden"></p>
        </form>
      </div>

      <!-- Crear Cuenta -->
      <div class="card">
        <h2>Crear Cuenta</h2>
        <form id="account-form">
          <div class="field">
            <label for="af">Nombre completo</label>
            <input id="af" type="text" placeholder="Bruno Merino" required>
          </div>
          <div class="field">
            <label for="au">Usuario</label>
            <input id="au" type="text" placeholder="bmerino" autocomplete="off" required>
          </div>
          <div class="field">
            <label for="ap">Contraseña</label>
            <input id="ap" type="password" autocomplete="new-password" required>
          </div>
          <div class="field">
            <label for="ar">Rol</label>
            <select id="ar">
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
          </div>
          <div class="field">
            <label for="ad">Dominio</label>
            <select id="ad" required></select>
          </div>
          <button class="btn btn-primary" type="submit" id="account-btn">Crear Cuenta</button>
          <p id="account-msg" class="msg hidden"></p>
        </form>
      </div>

    </div>

    <!-- Logs -->
    <div class="card logs-card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.25rem;">
        <h2 style="margin:0;">Registros de actividad</h2>
        <button class="btn btn-ghost" id="load-logs-btn">Cargar</button>
      </div>
      <div id="logs-container">
        <p style="color:#64748b;font-size:0.875rem;">Presioná "Cargar" para ver los últimos 200 registros.</p>
      </div>
    </div>

  </div>

  <script>
    var token = sessionStorage.getItem('fstrack_admin_token');

    function show(id) { document.getElementById(id).classList.remove('hidden'); }
    function hide(id) { document.getElementById(id).classList.add('hidden'); }

    function showMsg(id, text, type) {
      var el = document.getElementById(id);
      el.textContent = text;
      el.className = 'msg ' + type;
    }

    function setLoading(btnId, loading) {
      document.getElementById(btnId).disabled = loading;
    }

    function api(method, path, body) {
      var opts = { method: method, headers: { 'Content-Type': 'application/json' } };
      if (token) opts.headers['Authorization'] = 'Bearer ' + token;
      if (body) opts.body = JSON.stringify(body);
      return fetch('/admin' + path, opts).then(function(res) {
        return res.json().catch(function() { return {}; }).then(function(data) {
          return { ok: res.ok, status: res.status, data: data };
        });
      });
    }

    function loadDomains() {
      return api('GET', '/domains').then(function(r) {
        var select = document.getElementById('ad');
        select.innerHTML = '';
        if (r.ok && r.data.domains) {
          if (r.data.domains.length === 0) {
            select.innerHTML = '<option value="">— Sin dominios activos —</option>';
          } else {
            r.data.domains.forEach(function(d) {
              var opt = document.createElement('option');
              opt.value = d.id;
              opt.textContent = d.name + ' (' + d.workspace_code + ')';
              select.appendChild(opt);
            });
          }
        }
      });
    }

    function showDashboard() {
      hide('login-panel');
      show('dashboard');
      loadDomains();
    }

    if (token) showDashboard();

    document.getElementById('login-form').addEventListener('submit', function(e) {
      e.preventDefault();
      setLoading('login-btn', true);
      hide('login-msg');
      api('POST', '/login', {
        username: document.getElementById('lu').value,
        password: document.getElementById('lp').value,
      }).then(function(r) {
        setLoading('login-btn', false);
        if (r.ok) {
          token = r.data.token;
          sessionStorage.setItem('fstrack_admin_token', token);
          showDashboard();
        } else {
          showMsg('login-msg', r.data.error || 'Error al iniciar sesión.', 'error');
        }
      }).catch(function() {
        setLoading('login-btn', false);
        showMsg('login-msg', 'No se pudo conectar al servidor.', 'error');
      });
    });

    document.getElementById('logout-btn').addEventListener('click', function() {
      token = null;
      sessionStorage.removeItem('fstrack_admin_token');
      hide('dashboard');
      show('login-panel');
    });

    document.getElementById('domain-form').addEventListener('submit', function(e) {
      e.preventDefault();
      setLoading('domain-btn', true);
      hide('domain-msg');
      api('POST', '/create-domain', {
        name: document.getElementById('dn').value,
        workspace_code: document.getElementById('dw').value.toLowerCase().trim(),
        finnegans_client_id: document.getElementById('dci').value,
        finnegans_client_secret: document.getElementById('dcs').value,
      }).then(function(r) {
        setLoading('domain-btn', false);
        if (r.ok) {
          showMsg('domain-msg', r.data.message, 'success');
          document.getElementById('domain-form').reset();
          loadDomains();
        } else {
          showMsg('domain-msg', r.data.error || 'Error al crear dominio.', 'error');
        }
      }).catch(function() {
        setLoading('domain-btn', false);
        showMsg('domain-msg', 'No se pudo conectar al servidor.', 'error');
      });
    });

    document.getElementById('account-form').addEventListener('submit', function(e) {
      e.preventDefault();
      setLoading('account-btn', true);
      hide('account-msg');
      api('POST', '/create-account', {
        full_name: document.getElementById('af').value,
        username: document.getElementById('au').value,
        password: document.getElementById('ap').value,
        role: document.getElementById('ar').value,
        domain_id: document.getElementById('ad').value,
      }).then(function(r) {
        setLoading('account-btn', false);
        if (r.ok) {
          showMsg('account-msg', r.data.message, 'success');
          document.getElementById('account-form').reset();
          loadDomains();
        } else {
          showMsg('account-msg', r.data.error || 'Error al crear cuenta.', 'error');
        }
      }).catch(function() {
        setLoading('account-btn', false);
        showMsg('account-msg', 'No se pudo conectar al servidor.', 'error');
      });
    });
    // LOAD LOGS
    document.getElementById('load-logs-btn').addEventListener('click', function() {
      var btn = document.getElementById('load-logs-btn');
      var container = document.getElementById('logs-container');
      btn.disabled = true;
      container.innerHTML = '<p style="color:#64748b;font-size:0.875rem;">Cargando...</p>';

      api('GET', '/logs').then(function(r) {
        btn.disabled = false;
        if (!r.ok) {
          container.innerHTML = '<p style="color:#fca5a5;font-size:0.875rem;">' + (r.data.error || 'Error al cargar registros.') + '</p>';
          return;
        }
        var logs = r.data.logs;
        if (!logs || logs.length === 0) {
          container.innerHTML = '<p style="color:#64748b;font-size:0.875rem;">No hay registros aún.</p>';
          return;
        }
        var html = '<div style="overflow-x:auto;"><table class="logs-table"><thead><tr>' +
          '<th>Fecha</th><th>Usuario</th><th>Dominio</th><th>Formulario</th>' +
          '<th>Lote</th><th>Categoría</th><th>Cantidad</th><th>Depósito</th><th>Estado</th>' +
          '</tr></thead><tbody>';

        logs.forEach(function(l) {
          var d = new Date(l.created_at);
          var dateStr = d.toLocaleDateString('es-AR') + ' ' + d.toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit' });
          var statusHtml = l.status === 'SUCCESS'
            ? '<span class="tag-ok">OK</span>'
            : '<span class="tag-err">ERROR</span>' + (l.error_detail ? '<span class="err-detail">' + l.error_detail + '</span>' : '');
          html += '<tr>' +
            '<td>' + dateStr + '</td>' +
            '<td>' + (l.full_name || l.username) + '</td>' +
            '<td>' + l.domain_name + '</td>' +
            '<td>' + l.form_type + '</td>' +
            '<td>' + (l.lote || '—') + '</td>' +
            '<td>' + (l.categoria || '—') + '</td>' +
            '<td>' + (l.cantidad != null ? l.cantidad : '—') + '</td>' +
            '<td>' + (l.deposito || '—') + '</td>' +
            '<td>' + statusHtml + '</td>' +
            '</tr>';
        });

        html += '</tbody></table></div>';
        container.innerHTML = html;
      }).catch(function() {
        btn.disabled = false;
        container.innerHTML = '<p style="color:#fca5a5;font-size:0.875rem;">No se pudo conectar al servidor.</p>';
      });
    });
  </script>
</body>
</html>`;
