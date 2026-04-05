// ============================================================
// Hotspot System - MS TELECOM
// Backend principal (server.js) - v3.0 MERGED
// Código interno em inglês, comentários em português
// ============================================================

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

// RouterOS API para controle MikroTik (opcional - degrada gracefully)
let RouterOSAPI = null;
try {
  RouterOSAPI = require('node-routeros').RouterOSAPI;
} catch (e) {
  console.warn('node-routeros not installed - MikroTik API features disabled');
}

const app = express();
const PORT = process.env.PORT || 3000;
const API_BASE_URL = process.env.API_BASE_URL || 'https://mstelecom-api.duckdns.org';
const FRONTEND_BASE_URL = process.env.FRONTEND_BASE_URL || 'https://hotspot-system.vercel.app';
const RADIUS_SERVER_IP = process.env.RADIUS_SERVER_IP || '40.233.118.238';
const JWT_SECRET = process.env.JWT_SECRET;

// Validação obrigatória de variáveis de ambiente
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_KEY || !JWT_SECRET) {
  console.error('FATAL: Missing required environment variables: SUPABASE_URL, SUPABASE_KEY, JWT_SECRET');
  process.exit(1);
}

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// ============================================================
// MIDDLEWARES
// ============================================================

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

// Middleware de autenticação JWT
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// ============================================================
// HELPERS
// ============================================================

function removeAccents(value = '') {
  return String(value).normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function slugifyValue(value = '') {
  return removeAccents(String(value))
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function generateStrongPassword(length = 20) {
  return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
}

function parseCurrency(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function jsonOrNull(value) {
  return value && typeof value === 'object' ? value : null;
}

// Log de auditoria
async function registerAuditLog(username, type, objectName, action, ip, userAgent, details = null) {
  try {
    await supabase.from('audit_logs').insert({
      username: username || 'system',
      type: type || 'info',
      object: objectName || 'system',
      action: action || '',
      ip: ip || '',
      user_agent: userAgent || '',
      details: details ? JSON.stringify(details) : null,
      created_at: new Date().toISOString()
    });
  } catch (error) {
    console.error('Audit log error:', error.message);
  }
}

// Log do sistema
async function registerSystemLog(level, source, message, details = null, ip = '', userAgent = '') {
  try {
    await supabase.from('logs').insert({
      level: level || 'info',
      source: source || 'system',
      message,
      details: jsonOrNull(details),
      ip,
      user_agent: userAgent,
      created_at: new Date().toISOString()
    });
  } catch (error) {
    console.error('System log error:', error.message);
  }
}

// ============================================================
// SCHEMA / COMPATIBILITY HELPERS
// ============================================================

// Buscar credenciais MikroTik de forma resiliente
async function getMikrotikCredentials(popIp = null, popId = null) {
  if (popId) {
    const { data, error } = await supabase.from('mikrotik_credentials').select('*').eq('pop_id', popId).maybeSingle();
    if (!error && data) return data;
  }
  if (popIp) {
    const { data, error } = await supabase.from('mikrotik_credentials').select('*').eq('pop_ip', popIp).maybeSingle();
    if (!error && data) return data;
  }
  // Tenta também pelas credenciais armazenadas no próprio POP
  if (popId) {
    const { data, error } = await supabase.from('pops').select('api_user, api_pass, ip').eq('id', popId).maybeSingle();
    if (!error && data && data.api_user && data.api_pass) return data;
  }
  return null;
}

// Salvar/atualizar credenciais MikroTik
async function upsertMikrotikCredentials(payload) {
  const normalized = {
    pop_id: payload.pop_id || null,
    pop_ip: payload.pop_ip || null,
    api_user: payload.api_user || null,
    api_pass: payload.api_pass || null,
    last_seen_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };
  const { error } = await supabase.from('mikrotik_credentials').upsert(normalized, { onConflict: 'pop_id' });
  return !error;
}

// Buscar sessões expiradas ativas
async function getActiveExpiredSessions() {
  const now = new Date().toISOString();
  const { data, error } = await supabase
    .from('hotspot_sessions')
    .select('*')
    .lt('expires_at', now)
    .eq('status', 'active');

  if (!error) return { table: 'hotspot_sessions', data: data || [] };
  return { table: null, data: [] };
}

// Marcar sessão como expirada
async function markSessionExpired(table, sessionId) {
  if (!table) return false;
  const { error } = await supabase.from(table).update({
    status: 'expired',
    updated_at: new Date().toISOString()
  }).eq('id', sessionId);
  return !error;
}

// ============================================================
// MIKROTIK ACCESS CONTROL
// ============================================================

// Revogar acesso - remove IP Binding do MikroTik
async function revokeAccess(macAddress, popIp = '192.168.32.1', apiUser = null, apiPass = null, popId = null) {
  if (!RouterOSAPI) {
    console.warn('revokeAccess: node-routeros not available');
    return false;
  }

  try {
    let username = apiUser;
    let password = apiPass;

    if (!username || !password) {
      const creds = await getMikrotikCredentials(popIp, popId);
      if (creds) {
        username = creds.api_user;
        password = creds.api_pass;
      }
    }

    if (!username || !password) {
      throw new Error('MikroTik API credentials not available');
    }

    const conn = new RouterOSAPI({ host: popIp, user: username, password, port: 8728, timeout: 10 });
    await conn.connect();
    const bindings = await conn.write('/ip/hotspot/ip-binding/print', [`?mac-address=${macAddress}`]);

    for (const binding of bindings || []) {
      await conn.write('/ip/hotspot/ip-binding/remove', [`=.id=${binding['.id']}`]);
    }

    await conn.close();
    return true;
  } catch (error) {
    console.error(`Failed to revoke access for ${macAddress}:`, error.message);
    return false;
  }
}

// Autorizar acesso - IP Binding com type=bypassed + RADIUS
async function authorizeAccess(macAddress, popIp = '192.168.32.1', apiUser = null, apiPass = null, popId = null, durationMinutes = 15) {
  let viaApi = false;
  let viaRadius = false;
  const errors = [];

  // Tentativa 1: via API MikroTik (IP Binding)
  if (RouterOSAPI) {
    try {
      let username = apiUser;
      let password = apiPass;

      if (!username || !password) {
        const creds = await getMikrotikCredentials(popIp, popId);
        if (creds) {
          username = creds.api_user;
          password = creds.api_pass;
        }
      }

      if (username && password) {
        const conn = new RouterOSAPI({ host: popIp, user: username, password, port: 8728, timeout: 10 });
        await conn.connect();
        const existing = await conn.write('/ip/hotspot/ip-binding/print', [`?mac-address=${macAddress}`]);

        if (!existing || existing.length === 0) {
          await conn.write('/ip/hotspot/ip-binding/add', [
            `=mac-address=${macAddress}`,
            '=type=bypassed',
            '=comment=LIBERADO-MS-TELECOM'
          ]);
        }

        await conn.close();
        viaApi = true;
      }
    } catch (error) {
      errors.push(`API: ${error.message}`);
    }
  }

  // Tentativa 2: via RADIUS (radius_replies)
  try {
    const expiresAt = new Date(Date.now() + durationMinutes * 60 * 1000).toISOString();
    const { error } = await supabase.from('radius_replies').upsert({
      username: macAddress,
      attribute: 'Cleartext-Password',
      op: ':=',
      value: macAddress,
      plan_name: 'free_trial',
      status: 'active',
      expires_at: expiresAt,
      updated_at: new Date().toISOString()
    }, { onConflict: 'username' });

    if (error) throw error;
    viaRadius = true;
  } catch (error) {
    errors.push(`RADIUS: ${error.message}`);
  }

  return { success: viaApi || viaRadius, viaApi, viaRadius, errors };
}

// ============================================================
// CRON - REMOVE ACESSOS EXPIRADOS (a cada 60 segundos)
// ============================================================
setInterval(async () => {
  try {
    const { table, data } = await getActiveExpiredSessions();
    if (!table || !data || data.length === 0) return;

    for (const session of data) {
      const mac = session.mac_address;
      if (mac && mac !== 'pending') {
        await revokeAccess(mac, session.pop_ip || '192.168.32.1', null, null, session.pop_id || null);
      }
      await markSessionExpired(table, session.id);
    }

    console.log(`[CRON] expired accesses removed: ${data.length}`);
  } catch (error) {
    console.error('[CRON] expiration cleanup error:', error.message);
  }
}, 60_000);

// ============================================================
// ROTAS DE AUTENTICAÇÃO
// ============================================================

// Login do administrador
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });
    }

    const { data: admin, error } = await supabase
      .from('admins')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !admin) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Comparação de senha (hash SHA-256 ou texto plano para compatibilidade)
    let passwordMatch = false;
    if (admin.password.length === 64) {
      const sha256 = crypto.createHash('sha256').update(password).digest('hex');
      passwordMatch = admin.password === sha256;
    } else {
      passwordMatch = admin.password === password;
    }

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const token = jwt.sign(
      { id: admin.id, username: admin.username, role: admin.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    await registerAuditLog(admin.username, 'auth', 'admin', 'login', req.ip, req.headers['user-agent']);
    await registerSystemLog('info', 'auth', `Login realizado: ${admin.username}`, null, req.ip, req.headers['user-agent']);

    res.json({
      token,
      user: { id: admin.id, username: admin.username, email: admin.email, role: admin.role }
    });
  } catch (err) {
    console.error('Erro no login:', err.message);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Logout
app.post('/api/logout', authMiddleware, async (req, res) => {
  try {
    await registerAuditLog(req.user.username, 'auth', 'admin', 'logout', req.ip, req.headers['user-agent']);
    res.json({ message: 'Logout realizado com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Atualizar perfil do admin
app.put('/api/update-profile', authMiddleware, async (req, res) => {
  try {
    const { email, password } = req.body;
    const updateData = { updated_at: new Date().toISOString() };

    if (email) updateData.email = email;
    if (password) {
      updateData.password = crypto.createHash('sha256').update(password).digest('hex');
    }

    const { error } = await supabase.from('admins').update(updateData).eq('id', req.user.id);
    if (error) throw error;

    await registerAuditLog(req.user.username, 'update', 'admin', 'Perfil atualizado', req.ip, req.headers['user-agent']);
    res.json({ message: 'Perfil atualizado com sucesso' });
  } catch (err) {
    console.error('Erro ao atualizar perfil:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar perfil' });
  }
});

// ============================================================
// ROTAS DE ADMINS (CRUD)
// ============================================================

app.get('/api/admins', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('admins').select('id, username, email, role, created_at').order('id');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar admins' });
  }
});

app.post('/api/admins', authMiddleware, async (req, res) => {
  try {
    const { username, password, email } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuário e senha obrigatórios' });

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    const { data, error } = await supabase.from('admins').insert({
      username, password: hashedPassword, email: email || null, role: 'admin'
    }).select().single();

    if (error) throw error;
    await registerAuditLog(req.user.username, 'create', 'admins', `Admin criado: ${username}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao criar admin' });
  }
});

app.delete('/api/admins/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('admins').delete().eq('id', id);
    if (error) throw error;
    await registerAuditLog(req.user.username, 'delete', 'admins', `Admin excluído: ${id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Admin excluído' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao excluir admin' });
  }
});

// ============================================================
// ROTAS DE USUÁRIOS (CLIENTES)
// ============================================================

app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar usuários:', err.message);
    res.status(500).json({ error: 'Erro ao listar usuários' });
  }
});

app.post('/api/users', authMiddleware, async (req, res) => {
  try {
    const { name, username, mac_address, phone, cpf, email, address, plan_id, plan_name, hotspot_id, status, is_vip } = req.body;

    const { data, error } = await supabase.from('users').insert({
      name, username, mac_address, phone, cpf, email, address,
      plan_id, plan_name, hotspot_id,
      status: status || 'inactive',
      is_vip: is_vip || false
    }).select().single();

    if (error) throw error;
    await registerAuditLog(req.user.username, 'create', 'user', `Usuário criado: ${name}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar usuário:', err.message);
    res.status(500).json({ error: 'Erro ao criar usuário' });
  }
});

app.put('/api/users/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;
    delete updateData.created_at;

    const { data, error } = await supabase.from('users').update(updateData).eq('id', id).select().single();
    if (error) throw error;

    await registerAuditLog(req.user.username, 'update', 'user', `Usuário atualizado: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    console.error('Erro ao atualizar usuário:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar usuário' });
  }
});

app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('users').delete().eq('id', id);
    if (error) throw error;

    await registerAuditLog(req.user.username, 'delete', 'user', `Usuário removido: ${id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Usuário removido com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar usuário:', err.message);
    res.status(500).json({ error: 'Erro ao deletar usuário' });
  }
});

// ============================================================
// ROTAS DE AÇÕES DO USUÁRIO (renew, block, unblock, vip)
// ============================================================

app.post('/api/users/:id/renew', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { plan_name, days = 30 } = req.body;
    const expiresAt = new Date(Date.now() + Number(days) * 24 * 60 * 60 * 1000).toISOString();

    const { data, error } = await supabase.from('users')
      .update({ plan_name, status: 'active', expires_at: expiresAt, updated_at: new Date().toISOString() })
      .eq('id', id).select().single();

    if (error) throw error;
    await registerAuditLog(req.user.username, 'update', 'user', `Plano renovado: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (error) {
    console.error('Renew user error:', error.message);
    res.status(500).json({ error: 'Failed to renew user plan' });
  }
});

app.post('/api/users/:id/block', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase.from('users')
      .update({ status: 'blocked', updated_at: new Date().toISOString() })
      .eq('id', id).select().single();

    if (error) throw error;
    await registerAuditLog(req.user.username, 'update', 'user', `Usuário bloqueado: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (error) {
    console.error('Block user error:', error.message);
    res.status(500).json({ error: 'Failed to block user' });
  }
});

app.post('/api/users/:id/unblock', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase.from('users')
      .update({ status: 'active', updated_at: new Date().toISOString() })
      .eq('id', id).select().single();

    if (error) throw error;
    await registerAuditLog(req.user.username, 'update', 'user', `Usuário desbloqueado: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (error) {
    console.error('Unblock user error:', error.message);
    res.status(500).json({ error: 'Failed to unblock user' });
  }
});

app.post('/api/users/:id/vip', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { is_vip = true } = req.body;
    const { data, error } = await supabase.from('users')
      .update({ is_vip, updated_at: new Date().toISOString() })
      .eq('id', id).select().single();

    if (error) throw error;
    await registerAuditLog(req.user.username, 'update', 'user', `VIP atualizado: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (error) {
    console.error('VIP user error:', error.message);
    res.status(500).json({ error: 'Failed to update VIP status' });
  }
});

// ============================================================
// ROTAS DE PLANOS
// ============================================================

app.get('/api/plans', async (req, res) => {
  try {
    const { data, error } = await supabase.from('plans').select('*').order('price', { ascending: true });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar planos:', err.message);
    res.status(500).json({ error: 'Erro ao listar planos' });
  }
});

app.post('/api/plans', authMiddleware, async (req, res) => {
  try {
    const { name, price, speed_mbps, duration_days, description, active } = req.body;
    const { data, error } = await supabase.from('plans').insert({
      name, price, speed_mbps, duration_days, description,
      active: active !== undefined ? active : true
    }).select().single();

    if (error) throw error;
    await registerAuditLog(req.user.username, 'create', 'plan', `Plano criado: ${name}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar plano:', err.message);
    res.status(500).json({ error: 'Erro ao criar plano' });
  }
});

app.put('/api/plans/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;
    delete updateData.created_at;

    const { data, error } = await supabase.from('plans').update(updateData).eq('id', id).select().single();
    if (error) throw error;

    await registerAuditLog(req.user.username, 'update', 'plan', `Plano atualizado: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    console.error('Erro ao atualizar plano:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar plano' });
  }
});

app.delete('/api/plans/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('plans').delete().eq('id', id);
    if (error) throw error;

    await registerAuditLog(req.user.username, 'delete', 'plan', `Plano removido: ${id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Plano removido com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar plano:', err.message);
    res.status(500).json({ error: 'Erro ao deletar plano' });
  }
});

// Detalhes do plano com contagem de assinantes
app.get('/api/plans/:id/details', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: plan, error } = await supabase.from('plans').select('*').eq('id', id).maybeSingle();
    if (error || !plan) return res.status(404).json({ error: 'Plan not found' });

    const subscribers = await supabase.from('users').select('id', { count: 'exact', head: true }).eq('plan_id', id).eq('status', 'active');
    return res.json({
      ...plan,
      active_subscribers: subscribers.count || 0,
      monthly_revenue: (subscribers.count || 0) * parseCurrency(plan.price)
    });
  } catch (error) {
    console.error('Plan details error:', error.message);
    res.status(500).json({ error: 'Failed to load plan details' });
  }
});

// ============================================================
// ROTAS DE PAGAMENTOS
// ============================================================

app.get('/api/payments', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('payments').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar pagamentos:', err.message);
    res.status(500).json({ error: 'Erro ao listar pagamentos' });
  }
});

app.post('/api/payments', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('payments').insert(req.body).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao criar pagamento' });
  }
});

app.put('/api/payments/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;

    const { data, error } = await supabase.from('payments').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('Erro ao atualizar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar pagamento' });
  }
});

app.delete('/api/payments/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('payments').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Pagamento removido' });
  } catch (err) {
    console.error('Erro ao deletar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao deletar pagamento' });
  }
});

// Check payment by MAC
app.get('/api/check-payment-by-mac', async (req, res) => {
  try {
    const { mac } = req.query;
    if (!mac) return res.status(400).json({ error: 'MAC address is required' });

    const { data, error } = await supabase
      .from('payments')
      .select('*')
      .eq('user_mac', mac)
      .eq('status', 'approved')
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!error && data) {
      return res.json({ paid: true, payment_id: data.id, amount: data.amount, created_at: data.created_at });
    }
    return res.json({ paid: false });
  } catch (error) {
    console.error('Check payment by mac error:', error.message);
    res.status(500).json({ error: 'Failed to check payment by MAC' });
  }
});

// Gerar PIX via Mercado Pago (rota pública)
app.post('/api/payments/generate-pix', async (req, res) => {
  try {
    const { amount, description, email, cpf, name, plan_id, user_mac } = req.body;
    if (!amount || !description) return res.status(400).json({ error: 'Valor e descrição são obrigatórios' });

    const MP_TOKEN = process.env.MERCADOPAGO_ACCESS_TOKEN || process.env.MP_ACCESS_TOKEN;
    if (!MP_TOKEN) return res.status(500).json({ error: 'Token do Mercado Pago não configurado' });

    const externalReference = `HS-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    const mpResponse = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${MP_TOKEN}`,
        'X-Idempotency-Key': externalReference
      },
      body: JSON.stringify({
        transaction_amount: parseFloat(amount),
        description,
        payment_method_id: 'pix',
        payer: {
          email: email || 'cliente@hotspot.com',
          first_name: name || 'Cliente',
          identification: { type: 'CPF', number: cpf || '00000000000' }
        },
        external_reference: externalReference
      })
    });

    const mpData = await mpResponse.json();
    if (!mpResponse.ok) return res.status(400).json({ error: 'Erro ao gerar pagamento PIX', details: mpData });

    const pixCopyPaste = mpData.point_of_interaction?.transaction_data?.qr_code || '';
    const qrCodeBase64 = mpData.point_of_interaction?.transaction_data?.qr_code_base64 || '';

    const { data: payment, error } = await supabase.from('payments').insert({
      user_mac: user_mac || null, plan_id: plan_id || null,
      amount: parseFloat(amount), description, status: 'pending',
      payment_method: 'pix', mercado_pago_id: String(mpData.id),
      pix_copy_paste: pixCopyPaste, qr_code: qrCodeBase64,
      external_reference: externalReference,
      expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString()
    }).select().single();

    if (error) throw error;
    await registerSystemLog('info', 'payment', `PIX gerado: ${externalReference}`, { amount, plan_id });

    res.json({
      id: payment.id, mercado_pago_id: mpData.id,
      pix_copy_paste: pixCopyPaste, qr_code: qrCodeBase64,
      external_reference: externalReference, status: 'pending', amount: parseFloat(amount)
    });
  } catch (err) {
    console.error('Erro ao gerar PIX:', err.message);
    res.status(500).json({ error: 'Erro ao gerar pagamento PIX' });
  }
});

// Verificar status de pagamento por referência ou MP ID
app.get('/api/check-payment', async (req, res) => {
  try {
    const { external_reference, mercado_pago_id } = req.query;
    if (!external_reference && !mercado_pago_id) return res.status(400).json({ error: 'Referência ou ID do pagamento necessário' });

    let query = supabase.from('payments').select('*');
    if (external_reference) query = query.eq('external_reference', external_reference);
    else query = query.eq('mercado_pago_id', mercado_pago_id);

    const { data: payment, error } = await query.single();
    if (error || !payment) return res.status(404).json({ error: 'Pagamento não encontrado' });

    // Se pendente, verificar no Mercado Pago
    if (payment.status === 'pending' && payment.mercado_pago_id) {
      const MP_TOKEN = process.env.MERCADOPAGO_ACCESS_TOKEN || process.env.MP_ACCESS_TOKEN;
      if (MP_TOKEN) {
        try {
          const mpRes = await fetch(`https://api.mercadopago.com/v1/payments/${payment.mercado_pago_id}`, {
            headers: { 'Authorization': `Bearer ${MP_TOKEN}` }
          });
          const mpData = await mpRes.json();
          if (mpData.status === 'approved') {
            await supabase.from('payments').update({
              status: 'approved', confirmed_at: new Date().toISOString(), updated_at: new Date().toISOString()
            }).eq('id', payment.id);
            payment.status = 'approved';
            payment.confirmed_at = new Date().toISOString();
          }
        } catch (mpErr) {
          console.error('Erro ao verificar MP:', mpErr.message);
        }
      }
    }

    res.json(payment);
  } catch (err) {
    console.error('Erro ao verificar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao verificar pagamento' });
  }
});

// Criar pagamento manual (admin)
app.post('/api/create-payment', authMiddleware, async (req, res) => {
  try {
    const { user_id, plan_id, user_mac, amount, description, status, payment_method } = req.body;

    const { data, error } = await supabase.from('payments').insert({
      user_id, plan_id, user_mac,
      amount: parseFloat(amount || 0),
      description: description || 'Pagamento manual',
      status: status || 'approved',
      payment_method: payment_method || 'manual',
      external_reference: `MANUAL-${Date.now()}`,
      confirmed_at: status === 'approved' ? new Date().toISOString() : null
    }).select().single();

    if (error) throw error;
    await registerAuditLog(req.user.username, 'create', 'payment', `Pagamento manual criado: ${data.id}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao criar pagamento' });
  }
});

// Confirmar pagamento manualmente (admin)
app.post('/api/confirm-payment', authMiddleware, async (req, res) => {
  try {
    const { payment_id, user_id, plan_id } = req.body;

    const { data: payment, error: payErr } = await supabase.from('payments').update({
      status: 'approved', confirmed_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }).eq('id', payment_id).select().single();

    if (payErr) throw payErr;

    // Se tiver user_id e plan_id, ativar acesso do usuário
    if (user_id && plan_id) {
      const { data: plan } = await supabase.from('plans').select('*').eq('id', plan_id).single();
      if (plan) {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + (plan.duration_days || 30));
        await supabase.from('users').update({
          status: 'active', plan_id: plan.id, plan_name: plan.name,
          expires_at: expiresAt.toISOString(), updated_at: new Date().toISOString()
        }).eq('id', user_id);
      }
    }

    await registerAuditLog(req.user.username, 'update', 'payment', `Pagamento confirmado: ${payment_id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Pagamento confirmado com sucesso', payment });
  } catch (err) {
    console.error('Erro ao confirmar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao confirmar pagamento' });
  }
});

// ============================================================
// ROTAS DE VOUCHERS
// ============================================================

app.get('/api/vouchers', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('vouchers').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar vouchers:', err.message);
    res.status(500).json({ error: 'Erro ao listar vouchers' });
  }
});

app.post('/api/vouchers', authMiddleware, async (req, res) => {
  try {
    const { plan_name, duration_hours, quantity } = req.body;
    const count = Math.min(quantity || 1, 100);
    const vouchers = [];

    for (let i = 0; i < count; i++) {
      vouchers.push({
        code: crypto.randomBytes(4).toString('hex').toUpperCase(),
        plan_name: plan_name || 'basic',
        duration_hours: duration_hours || 24,
        status: 'active',
        used: false
      });
    }

    const { data, error } = await supabase.from('vouchers').insert(vouchers).select();
    if (error) throw error;

    await registerAuditLog(req.user.username, 'create', 'voucher', `${count} vouchers criados`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar vouchers:', err.message);
    res.status(500).json({ error: 'Erro ao criar vouchers' });
  }
});

app.delete('/api/vouchers/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('vouchers').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Voucher removido' });
  } catch (err) {
    console.error('Erro ao deletar voucher:', err.message);
    res.status(500).json({ error: 'Erro ao deletar voucher' });
  }
});

// Validação/resgate de voucher (rota pública)
app.post('/api/vouchers/validate', async (req, res) => {
  try {
    const { code, mac_address } = req.body;
    if (!code) return res.status(400).json({ error: 'Voucher code is required' });

    const { data: voucher, error } = await supabase
      .from('vouchers')
      .select('*')
      .eq('code', String(code).toUpperCase())
      .maybeSingle();

    if (error || !voucher) return res.status(404).json({ valid: false, error: 'Voucher not found' });
    if (voucher.status === 'used' || voucher.used === true) return res.status(400).json({ valid: false, error: 'Voucher already used' });
    if (voucher.status === 'expired') return res.status(400).json({ valid: false, error: 'Voucher expired' });

    await supabase.from('vouchers').update({
      status: 'used', used: true, used_at: new Date().toISOString(),
      mac_address: mac_address || null, updated_at: new Date().toISOString()
    }).eq('id', voucher.id);

    return res.json({ valid: true, voucher_id: voucher.id, plan_name: voucher.plan_name || null });
  } catch (error) {
    console.error('Voucher validation error:', error.message);
    res.status(500).json({ error: 'Failed to validate voucher' });
  }
});

// ============================================================
// ROTAS DE CAMPANHAS
// ============================================================

app.get('/api/campaigns', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('campaigns').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar campanhas:', err.message);
    res.status(500).json({ error: 'Erro ao listar campanhas' });
  }
});

app.post('/api/campaigns', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('campaigns').insert(req.body).select().single();
    if (error) throw error;
    await registerAuditLog(req.user.username, 'create', 'campaign', `Campanha criada: ${req.body.name}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar campanha:', err.message);
    res.status(500).json({ error: 'Erro ao criar campanha' });
  }
});

app.put('/api/campaigns/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;

    const { data, error } = await supabase.from('campaigns').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('Erro ao atualizar campanha:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar campanha' });
  }
});

app.delete('/api/campaigns/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('campaigns').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Campanha removida' });
  } catch (err) {
    console.error('Erro ao deletar campanha:', err.message);
    res.status(500).json({ error: 'Erro ao deletar campanha' });
  }
});

// ============================================================
// ROTAS DE WEBHOOKS
// ============================================================

app.get('/api/webhooks', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('webhooks').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar webhooks:', err.message);
    res.status(500).json({ error: 'Erro ao listar webhooks' });
  }
});

app.post('/api/webhooks', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('webhooks').insert(req.body).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar webhook:', err.message);
    res.status(500).json({ error: 'Erro ao criar webhook' });
  }
});

app.delete('/api/webhooks/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('webhooks').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Webhook removido' });
  } catch (err) {
    console.error('Erro ao deletar webhook:', err.message);
    res.status(500).json({ error: 'Erro ao deletar webhook' });
  }
});

// ============================================================
// ROTAS DE HOTSPOTS
// ============================================================

app.get('/api/hotspots', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('hotspots').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar hotspots:', err.message);
    res.status(500).json({ error: 'Erro ao listar hotspots' });
  }
});

app.post('/api/hotspots', authMiddleware, async (req, res) => {
  try {
    const {
      name, location, ip,
      installation_type = 'new', wan_interface = 'ether1', lan_interface = 'ether4',
      vlan_id = '', wan_type = 'dhcp', pppoe_user = '', pppoe_pass = '',
      static_ip = '', static_mask = '', static_gw = '',
      hotspot_type = 'new_vlan', existing_vlan = '', physical_port = ''
    } = req.body;

    if (!name) return res.status(400).json({ error: 'Hotspot name is required' });

    const uniqueId = crypto.randomBytes(4).toString('hex').toUpperCase();
    const radiusSecret = generateStrongPassword(18);
    const now = new Date().toISOString();

    const payload = {
      name, unique_id: uniqueId, location: location || 'Undefined',
      ip: ip || '0.0.0.0', status: 'offline', created_at: now, updated_at: now,
      installation_type, wan_interface, lan_interface, vlan_id, wan_type,
      hotspot_type, existing_vlan, physical_port
    };

    const { data, error } = await supabase.from('hotspots').insert(payload).select().single();
    if (error) throw error;

    const script = generateInstallationScript({
      uniqueId, hotspotName: name, installationType: installation_type,
      wanInterface: wan_interface, lanInterface: lan_interface, vlanId: vlan_id,
      wanType: wan_type, pppoeUser: pppoe_user, pppoePass: pppoe_pass,
      staticIp: static_ip, staticMask: static_mask, staticGw: static_gw,
      hotspotType: hotspot_type, existingVlan: existing_vlan, physicalPort: physical_port,
      radiusSecret
    });

    await registerAuditLog(req.user.username, 'create', 'hotspot', `Hotspot criado: ${name}`, req.ip, req.headers['user-agent']);
    return res.status(201).json({
      success: true, id: data.id, unique_id: uniqueId, hotspot: data, script,
      instructions: 'Copy the script to MikroTik terminal via SSH or Winbox'
    });
  } catch (error) {
    console.error('Create hotspot error:', error.message);
    res.status(500).json({ error: 'Failed to create hotspot' });
  }
});

app.put('/api/hotspots/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;

    const { data, error } = await supabase.from('hotspots').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('Erro ao atualizar hotspot:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar hotspot' });
  }
});

app.delete('/api/hotspots/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('hotspots').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Hotspot removido' });
  } catch (err) {
    console.error('Erro ao deletar hotspot:', err.message);
    res.status(500).json({ error: 'Erro ao deletar hotspot' });
  }
});

// ============================================================
// ROTAS DE POPs
// ============================================================

app.get('/api/pops', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('pops').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar POPs:', err.message);
    res.status(500).json({ error: 'Erro ao listar POPs' });
  }
});

app.post('/api/pops', authMiddleware, async (req, res) => {
  try {
    const { name, ip, location } = req.body;
    if (!name) return res.status(400).json({ error: 'POP name is required' });

    const now = new Date().toISOString();
    const { data, error } = await supabase.from('pops').insert({
      name, ip: ip || null, location: location || null,
      status: 'offline', created_at: now, updated_at: now
    }).select().single();

    if (error) throw error;
    await registerAuditLog(req.user.username, 'create', 'pop', `POP criado: ${name}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (error) {
    console.error('Create POP error:', error.message);
    res.status(500).json({ error: 'Failed to create POP' });
  }
});

app.put('/api/pops/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;

    const { data, error } = await supabase.from('pops').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('Erro ao atualizar POP:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar POP' });
  }
});

app.delete('/api/pops/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('pops').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'POP removido' });
  } catch (err) {
    console.error('Erro ao deletar POP:', err.message);
    res.status(500).json({ error: 'Erro ao deletar POP' });
  }
});

// POP Register (rota pública - auto-registro de POP)
app.post('/api/pops/register', async (req, res) => {
  try {
    const { name, ip, location, unique_id, api_user, api_pass } = req.body;
    if (!name) return res.status(400).json({ error: 'POP name is required' });

    const popId = unique_id || slugifyValue(name).toUpperCase();
    const now = new Date().toISOString();

    // Verificar se já existe
    const { data: existing } = await supabase.from('pops').select('id').eq('id', popId).maybeSingle();
    if (existing) {
      await supabase.from('pops').update({
        status: 'online', ip: ip || null, last_seen_at: now, updated_at: now
      }).eq('id', popId);
      return res.json({ success: true, pop_id: popId, action: 'updated' });
    }

    const { data, error } = await supabase.from('pops').insert({
      id: popId, name, unique_id: popId, ip: ip || null,
      location: location || null, status: 'online',
      api_user: api_user || null, api_pass: api_pass || null,
      last_seen_at: now, created_at: now, updated_at: now
    }).select().single();

    if (error) throw error;
    await registerSystemLog('info', 'pop', `POP registrado: ${name} (${popId})`, { ip });
    return res.status(201).json({ success: true, pop_id: popId, action: 'created', pop: data });
  } catch (error) {
    console.error('POP register error:', error.message);
    res.status(500).json({ error: 'Failed to register POP' });
  }
});

// POP Status (rota admin)
app.get('/api/pops/:id/status', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Buscar por id, unique_id ou name
    let pop = null;
    let result = await supabase.from('pops').select('*').eq('id', id).maybeSingle();
    pop = result.data;
    if (!pop) {
      result = await supabase.from('pops').select('*').eq('unique_id', id).maybeSingle();
      pop = result.data;
    }
    if (!pop) {
      result = await supabase.from('pops').select('*').eq('name', id).maybeSingle();
      pop = result.data;
    }
    if (!pop) return res.status(404).json({ error: 'POP not found' });

    // Verificar se está online (last_seen_at < 5 min)
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
    const isOnline = pop.last_seen_at && new Date(pop.last_seen_at) > fiveMinAgo;

    // Buscar sessões ativas
    const { data: sessions } = await supabase.from('hotspot_sessions')
      .select('*').eq('pop_id', pop.id).eq('status', 'active');

    return res.json({
      ...pop,
      is_online: isOnline,
      active_sessions: (sessions || []).length,
      sessions: sessions || []
    });
  } catch (error) {
    console.error('POP status error:', error.message);
    res.status(500).json({ error: 'Failed to get POP status' });
  }
});

// POP Ping/Heartbeat (rota pública - chamada pelo MikroTik scheduler)
app.post('/api/pops/:id/ping', async (req, res) => {
  try {
    const popId = req.params.id;
    const { connected_users, bandwidth_used, api_user, api_pass, ip, name } = req.body;
    const now = new Date().toISOString();

    if (api_user && api_pass) {
      await upsertMikrotikCredentials({ pop_id: popId, pop_ip: ip || null, api_user, api_pass });
    }

    const existing = await supabase.from('pops').select('*').eq('id', popId).maybeSingle();

    if (!existing.error && existing.data) {
      const update = await supabase.from('pops').update({
        status: 'online', last_seen_at: now,
        connected_users: connected_users ?? 0,
        bandwidth_used: bandwidth_used || '0 Mbps',
        ip: ip || existing.data.ip || null,
        updated_at: now
      }).eq('id', popId);

      if (update.error) throw update.error;
    } else {
      const create = await supabase.from('pops').insert({
        id: popId, name: name || popId, status: 'online',
        last_seen_at: now, connected_users: connected_users ?? 0,
        bandwidth_used: bandwidth_used || '0 Mbps',
        ip: ip || null, created_at: now, updated_at: now
      });

      if (create.error) throw create.error;
    }

    return res.json({ status: 'ok', pop_id: popId, timestamp: now });
  } catch (error) {
    console.error('POP ping error:', error.message);
    res.status(500).json({ error: 'Failed to process ping' });
  }
});

// POP Identity (rota pública - chamada pelo MikroTik)
app.post('/api/pop/identity', async (req, res) => {
  try {
    const { pop_id, identity } = req.body;
    if (!pop_id || !identity) return res.status(400).json({ error: 'pop_id and identity are required' });

    const updatePayload = {
      real_name: identity,
      last_identity_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    // Tentar atualizar por id primeiro, depois unique_id, depois name
    let result = await supabase.from('pops').update(updatePayload).eq('id', pop_id).select();
    if (!result.data || result.data.length === 0) {
      result = await supabase.from('pops').update(updatePayload).eq('unique_id', pop_id).select();
    }
    if (!result.data || result.data.length === 0) {
      result = await supabase.from('pops').update(updatePayload).eq('name', pop_id).select();
    }

    if (result.error) throw result.error;
    return res.json({ success: true, matched: (result.data || []).length });
  } catch (error) {
    console.error('Pop identity error:', error.message);
    res.status(500).json({ error: 'Failed to save pop identity' });
  }
});

// POP Installation Script
app.get('/api/pops/:id/script', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: pop, error } = await supabase.from('pops').select('*').eq('id', id).maybeSingle();
    if (error || !pop) return res.status(404).json({ error: 'POP not found' });

    const uniqueId = pop.unique_id || pop.id || slugifyValue(pop.name || id).toUpperCase();
    const radiusSecret = pop.radius_secret || generateStrongPassword(18);

    return res.json({
      pop_id: id,
      script: generateInstallationScript({
        uniqueId, hotspotName: pop.name || id,
        installationType: pop.installation_type || 'new',
        wanInterface: pop.wan_interface || 'ether1',
        lanInterface: pop.lan_interface || 'ether4',
        vlanId: pop.vlan_id || '', wanType: pop.wan_type || 'dhcp',
        hotspotType: pop.hotspot_type || 'new_vlan',
        existingVlan: pop.existing_vlan || '',
        physicalPort: pop.physical_port || '',
        pppoeUser: pop.pppoe_user || '', pppoePass: pop.pppoe_pass || '',
        staticIp: pop.static_ip || '', staticMask: pop.static_mask || '',
        staticGw: pop.static_gw || '', radiusSecret
      })
    });
  } catch (error) {
    console.error('Get POP script error:', error.message);
    res.status(500).json({ error: 'Failed to generate installation script' });
  }
});

// POP Revert Script
app.get('/api/pops/:id/revert-script', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: pop, error } = await supabase.from('pops').select('*').eq('id', id).maybeSingle();
    if (error || !pop) return res.status(404).json({ error: 'POP not found' });

    const uniqueId = pop.unique_id || pop.id || slugifyValue(pop.name || id).toUpperCase();
    return res.json({
      pop_id: id,
      script: generateRevertScript({ uniqueId, hotspotName: pop.name || id })
    });
  } catch (error) {
    console.error('Get POP revert script error:', error.message);
    res.status(500).json({ error: 'Failed to generate revert script' });
  }
});

// ============================================================
// ACCESS / TRIAL / RELEASES
// ============================================================

// Free trial (rota pública)
app.post('/api/free-trial', async (req, res) => {
  try {
    const { mac, pop_ip, api_user, api_pass, pop_id } = req.body;
    if (!mac) return res.status(400).json({ error: 'MAC address is required' });

    const now = new Date();
    const oneHourMs = 60 * 60 * 1000;

    const { data: trial } = await supabase.from('free_trials').select('*').eq('mac', mac).maybeSingle();

    if (trial?.last_trial) {
      const lastTrial = new Date(trial.last_trial);
      if (now - lastTrial < oneHourMs) {
        const minutesRemaining = Math.ceil((oneHourMs - (now - lastTrial)) / 60000);
        return res.status(429).json({ error: `Wait ${minutesRemaining} minutes before another trial` });
      }
    }

    await supabase.from('free_trials').upsert({
      mac, last_trial: now.toISOString(),
      attempts: (trial?.attempts || 0) + 1,
      updated_at: now.toISOString()
    }, { onConflict: 'mac' });

    const result = await authorizeAccess(mac, pop_ip, api_user, api_pass, pop_id, 15);
    if (!result.success) {
      return res.status(500).json({ error: 'Failed to authorize free trial', details: result.errors });
    }

    await registerSystemLog('info', 'free-trial', `Free trial authorized for ${mac}`, { mac, pop_id, viaApi: result.viaApi, viaRadius: result.viaRadius });
    return res.json({ success: true, duration_minutes: 15, via_api: result.viaApi, via_radius: result.viaRadius });
  } catch (error) {
    console.error('Free trial error:', error.message);
    res.status(500).json({ error: 'Failed to authorize free trial' });
  }
});

// Access releases (admin)
app.get('/api/access-releases', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('hotspot_sessions').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    return res.json(data || []);
  } catch (error) {
    console.error('Access releases error:', error.message);
    res.status(500).json({ error: 'Failed to load access releases' });
  }
});

// ============================================================
// ENTRYPOINT (redirecionamento do MikroTik)
// ============================================================

app.get('/entrypoint', (req, res) => {
  const hotspotIdentity = req.query.hotspotIdentity || req.query.server || req.query.server_name || '';
  const userMac = req.query.userMac || req.query.mac || '';
  const hostname = req.query.hostname || req.query.ip || '';
  const target = `${FRONTEND_BASE_URL}/index.html?mac=${encodeURIComponent(userMac)}&ip=${encodeURIComponent(hostname)}&pop=${encodeURIComponent(hotspotIdentity)}`;
  return res.redirect(target);
});

// Validar acesso de usuário (rota pública - chamada pelo MikroTik)
app.post('/api/validate-access', async (req, res) => {
  try {
    const { mac, username } = req.body;
    if (!mac && !username) return res.status(400).json({ error: 'MAC ou username é obrigatório' });

    let query = supabase.from('users').select('*');
    if (mac) query = query.eq('mac_address', mac);
    else query = query.eq('username', username);

    const { data: user } = await query.single();
    if (!user) return res.json({ access: false, reason: 'Usuário não encontrado' });
    if (user.status !== 'active') return res.json({ access: false, reason: 'Conta inativa' });
    if (user.expires_at && new Date(user.expires_at) < new Date()) return res.json({ access: false, reason: 'Plano expirado' });

    // Verificar sessão ativa
    const { data: session } = await supabase.from('hotspot_sessions').select('*')
      .eq('mac_address', mac || user.mac_address).eq('status', 'active')
      .order('created_at', { ascending: false }).limit(1).maybeSingle();

    res.json({
      access: true,
      user: { id: user.id, name: user.name, plan_name: user.plan_name, expires_at: user.expires_at, is_vip: user.is_vip },
      session: session || null
    });
  } catch (err) {
    console.error('Erro ao validar acesso:', err.message);
    res.status(500).json({ error: 'Erro ao validar acesso' });
  }
});

// ============================================================
// ROTAS DO PORTAL PÚBLICO (páginas de clientes finais)
// ============================================================

// Listar planos (público)
app.get('/api/portal/plans', async (req, res) => {
  try {
    const { data, error } = await supabase.from('plans').select('*').eq('active', true).order('price', { ascending: true });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar planos do portal:', err.message);
    res.status(500).json({ error: 'Erro ao listar planos' });
  }
});

// Login do portal (cliente)
app.post('/api/portal/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuário e senha obrigatórios' });

    const { data: user, error } = await supabase.from('users').select('*').eq('username', username).single();
    if (error || !user) return res.status(401).json({ error: 'Credenciais inválidas' });

    // Comparação de senha
    let passwordMatch = false;
    if (user.password && user.password.length === 64) {
      const sha256 = crypto.createHash('sha256').update(password).digest('hex');
      passwordMatch = user.password === sha256;
    } else {
      passwordMatch = user.password === password;
    }

    if (!passwordMatch) return res.status(401).json({ error: 'Credenciais inválidas' });

    const token = jwt.sign({ id: user.id, username: user.username, role: 'user' }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, user: { id: user.id, username: user.username, name: user.name, plan_name: user.plan_name, status: user.status } });
  } catch (err) {
    console.error('Erro no login do portal:', err.message);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Registro do portal (cliente)
app.post('/api/portal/register', async (req, res) => {
  try {
    const { name, username, password, phone, cpf, mac_address } = req.body;
    if (!name || !username || !password) return res.status(400).json({ error: 'Nome, usuário e senha obrigatórios' });

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    const { data, error } = await supabase.from('users').insert({
      name, username, password: hashedPassword,
      phone: phone || null, cpf: cpf || null,
      mac_address: mac_address || null,
      status: 'inactive', is_vip: false
    }).select().single();

    if (error) throw error;
    res.status(201).json({ message: 'Cadastro realizado', user: { id: data.id, username: data.username, name: data.name } });
  } catch (err) {
    console.error('Erro no registro do portal:', err.message);
    res.status(500).json({ error: 'Erro ao registrar' });
  }
});

// Voucher do portal (cliente)
app.post('/api/portal/voucher', async (req, res) => {
  try {
    const { code, mac_address } = req.body;
    if (!code) return res.status(400).json({ error: 'Código do voucher obrigatório' });

    const { data: voucher, error } = await supabase
      .from('vouchers')
      .select('*')
      .eq('code', String(code).toUpperCase())
      .maybeSingle();

    if (error || !voucher) return res.status(404).json({ error: 'Voucher não encontrado' });
    if (voucher.status === 'used' || voucher.used === true) return res.status(400).json({ error: 'Voucher já utilizado' });

    await supabase.from('vouchers').update({
      status: 'used', used: true, used_at: new Date().toISOString(),
      mac_address: mac_address || null, updated_at: new Date().toISOString()
    }).eq('id', voucher.id);

    res.json({ valid: true, plan_name: voucher.plan_name, duration_hours: voucher.duration_hours });
  } catch (err) {
    console.error('Erro ao validar voucher do portal:', err.message);
    res.status(500).json({ error: 'Erro ao validar voucher' });
  }
});

// Criar PIX (portal)
app.post('/api/portal/create-pix', async (req, res) => {
  try {
    const { plan_id, plan_name, amount, user_mac, user_name } = req.body;
    const MP_TOKEN = process.env.MERCADOPAGO_ACCESS_TOKEN || process.env.MP_ACCESS_TOKEN;

    if (!MP_TOKEN) return res.status(500).json({ error: 'Mercado Pago not configured' });

    const idempotencyKey = crypto.randomUUID();
    const response = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${MP_TOKEN}`,
        'X-Idempotency-Key': idempotencyKey
      },
      body: JSON.stringify({
        transaction_amount: Number(amount),
        description: `Hotspot - ${plan_name || 'Plano'}`,
        payment_method_id: 'pix',
        payer: { email: 'cliente@hotspot.com', first_name: user_name || 'Cliente' },
        notification_url: `${API_BASE_URL}/api/webhooks/mercadopago`
      })
    });

    const mpData = await response.json();
    if (!response.ok) throw new Error(mpData.message || 'MP API error');

    const pixData = mpData.point_of_interaction?.transaction_data || {};

    const { data, error } = await supabase.from('payments').insert({
      user_mac: user_mac || null, user_name: user_name || null,
      plan_id: plan_id || null, plan_name: plan_name || null,
      amount: Number(amount), method: 'pix', status: 'pending',
      mp_payment_id: String(mpData.id),
      pix_qr_code: pixData.qr_code || null,
      pix_qr_code_base64: pixData.qr_code_base64 || null,
      created_at: new Date().toISOString()
    }).select().single();

    if (error) throw error;

    res.json({
      payment_id: data.id, mp_payment_id: mpData.id,
      qr_code: pixData.qr_code, qr_code_base64: pixData.qr_code_base64,
      status: 'pending'
    });
  } catch (err) {
    console.error('Erro ao criar PIX:', err.message);
    res.status(500).json({ error: 'Erro ao criar pagamento PIX' });
  }
});

// Verificar pagamento (portal)
app.get('/api/portal/check-payment/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase.from('payments').select('*').eq('id', id).single();
    if (error || !data) return res.status(404).json({ error: 'Pagamento não encontrado' });
    res.json({ status: data.status, payment: data });
  } catch (err) {
    console.error('Erro ao verificar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao verificar pagamento' });
  }
});

// Status do portal (cliente)
app.get('/api/portal/status', async (req, res) => {
  try {
    const { mac } = req.query;
    if (!mac) return res.status(400).json({ error: 'MAC address obrigatório' });

    const { data: user } = await supabase.from('users').select('*').eq('mac_address', mac).maybeSingle();
    const { data: session } = await supabase.from('hotspot_sessions')
      .select('*').eq('mac_address', mac).eq('status', 'active')
      .order('created_at', { ascending: false }).limit(1).maybeSingle();

    res.json({
      user: user || null,
      active_session: session || null,
      has_access: !!session
    });
  } catch (err) {
    console.error('Erro ao verificar status:', err.message);
    res.status(500).json({ error: 'Erro ao verificar status' });
  }
});

// ============================================================
// WEBHOOK MERCADO PAGO
// ============================================================

app.post('/api/webhooks/mercadopago', async (req, res) => {
  try {
    const { type, data: mpData } = req.body;

    if (type === 'payment') {
      const paymentId = mpData?.id;
      if (!paymentId) return res.status(400).json({ error: 'Payment ID missing' });

      const MP_TOKEN = process.env.MERCADOPAGO_ACCESS_TOKEN || process.env.MP_ACCESS_TOKEN;
      if (!MP_TOKEN) return res.status(500).json({ error: 'MP not configured' });

      const response = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
        headers: { 'Authorization': `Bearer ${MP_TOKEN}` }
      });
      const paymentInfo = await response.json();

      if (paymentInfo.status === 'approved') {
        await supabase.from('payments')
          .update({ status: 'approved', updated_at: new Date().toISOString() })
          .eq('mp_payment_id', String(paymentId));

        await registerSystemLog('info', 'mercadopago', `Pagamento aprovado: ${paymentId}`, { amount: paymentInfo.transaction_amount });
      }
    }

    res.json({ received: true });
  } catch (err) {
    console.error('Webhook MP error:', err.message);
    res.status(500).json({ error: 'Webhook processing error' });
  }
});

// ============================================================
// ROTAS DE SETTINGS
// ============================================================

app.get('/api/settings', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('*').order('id');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar configurações' });
  }
});

app.post('/api/settings', authMiddleware, async (req, res) => {
  try {
    const { key, value } = req.body;
    if (!key) return res.status(400).json({ error: 'Key obrigatória' });

    const { data: existing } = await supabase.from('settings').select('*').eq('key', key).maybeSingle();
    if (existing) {
      const { data, error } = await supabase.from('settings').update({ value, updated_at: new Date().toISOString() }).eq('key', key).select().single();
      if (error) throw error;
      return res.json(data);
    }

    const { data, error } = await supabase.from('settings').insert({ key, value }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao salvar configuração' });
  }
});

app.delete('/api/settings/:key', authMiddleware, async (req, res) => {
  try {
    const { key } = req.params;
    const { error } = await supabase.from('settings').delete().eq('key', key);
    if (error) throw error;
    res.json({ message: 'Configuração removida' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao remover configuração' });
  }
});

// Campos de cadastro
app.get('/api/settings/fields', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('*').eq('category', 'fields');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar campos' });
  }
});

app.post('/api/settings/fields', authMiddleware, async (req, res) => {
  try {
    const { fields } = req.body;
    const { error } = await supabase.from('settings').upsert({
      key: 'registration_fields', category: 'fields',
      value: fields, updated_at: new Date().toISOString()
    }, { onConflict: 'key' });
    if (error) throw error;
    await registerAuditLog(req.user.username, 'update', 'settings', 'Campos de cadastro atualizados', req.ip, req.headers['user-agent']);
    res.json({ message: 'Campos salvos com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao salvar campos' });
  }
});

// Configurações do sistema
app.get('/api/settings/system', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('*').eq('category', 'system');
    if (error) throw error;
    const settings = {};
    (data || []).forEach(item => { settings[item.key] = item.value; });
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar configurações do sistema' });
  }
});

app.post('/api/settings/system', authMiddleware, async (req, res) => {
  try {
    const entries = Object.entries(req.body);
    for (const [key, value] of entries) {
      await supabase.from('settings').upsert({
        key, category: 'system',
        value: typeof value === 'object' ? value : { value },
        updated_at: new Date().toISOString()
      }, { onConflict: 'key' });
    }
    await registerAuditLog(req.user.username, 'update', 'settings', 'Configurações do sistema atualizadas', req.ip, req.headers['user-agent']);
    res.json({ message: 'Configurações salvas com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao salvar configurações do sistema' });
  }
});

// Configurações de pagamento
app.get('/api/settings/payment', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('*').eq('category', 'payment');
    if (error) throw error;
    const settings = {};
    (data || []).forEach(item => { settings[item.key] = item.value; });
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar configurações de pagamento' });
  }
});

app.post('/api/settings/payment', authMiddleware, async (req, res) => {
  try {
    const entries = Object.entries(req.body);
    for (const [key, value] of entries) {
      await supabase.from('settings').upsert({
        key, category: 'payment',
        value: typeof value === 'object' ? value : { value },
        updated_at: new Date().toISOString()
      }, { onConflict: 'key' });
    }
    await registerAuditLog(req.user.username, 'update', 'settings', 'Configurações de pagamento atualizadas', req.ip, req.headers['user-agent']);
    res.json({ message: 'Configurações de pagamento salvas com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao salvar configurações de pagamento' });
  }
});

// ============================================================
// ROTAS DE ESTATÍSTICAS
// ============================================================

// Estatísticas gerais (compatível com dashboard camelCase)
app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const [
      { count: totalUsers },
      { count: activeUsers },
      { count: totalPayments },
      { count: pendingPayments },
      { count: totalHotspots },
      { count: totalPops },
      { count: activeSessions },
      { count: totalVouchers }
    ] = await Promise.all([
      supabase.from('users').select('*', { count: 'exact', head: true }),
      supabase.from('users').select('*', { count: 'exact', head: true }).eq('status', 'active'),
      supabase.from('payments').select('*', { count: 'exact', head: true }),
      supabase.from('payments').select('*', { count: 'exact', head: true }).eq('status', 'pending'),
      supabase.from('hotspots').select('*', { count: 'exact', head: true }),
      supabase.from('pops').select('*', { count: 'exact', head: true }),
      supabase.from('hotspot_sessions').select('*', { count: 'exact', head: true }).eq('status', 'active'),
      supabase.from('vouchers').select('*', { count: 'exact', head: true })
    ]);

    // Faturamento total
    const { data: revenueData } = await supabase.from('payments').select('amount').eq('status', 'approved');
    const totalRevenue = (revenueData || []).reduce((sum, p) => sum + parseFloat(p.amount || 0), 0);

    // Faturamento do mês
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);
    const { data: monthRevenueData } = await supabase.from('payments').select('amount')
      .eq('status', 'approved').gte('confirmed_at', startOfMonth.toISOString());
    const monthRevenue = (monthRevenueData || []).reduce((sum, p) => sum + parseFloat(p.amount || 0), 0);

    // POPs online (last_seen_at < 5 min)
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const { count: onlinePops } = await supabase.from('pops').select('*', { count: 'exact', head: true }).gte('last_seen_at', fiveMinAgo);

    res.json({
      totalUsers: totalUsers || 0,
      activeUsers: activeUsers || 0,
      totalPayments: totalPayments || 0,
      pendingPayments: pendingPayments || 0,
      totalHotspots: totalHotspots || 0,
      totalPops: totalPops || 0,
      onlinePops: onlinePops || 0,
      activeSessions: activeSessions || 0,
      totalVouchers: totalVouchers || 0,
      totalRevenue,
      monthRevenue
    });
  } catch (err) {
    console.error('Erro ao buscar estatísticas:', err.message);
    res.status(500).json({ error: 'Erro ao buscar estatísticas' });
  }
});

// Usuários por hora (últimas 24h)
app.get('/api/stats/users-per-hour', authMiddleware, async (req, res) => {
  try {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const { data } = await supabase.from('hotspot_sessions').select('created_at').gte('created_at', twentyFourHoursAgo);

    const hourly = {};
    for (let i = 0; i < 24; i++) hourly[i] = 0;
    (data || []).forEach(s => {
      const hour = new Date(s.created_at).getHours();
      hourly[hour] = (hourly[hour] || 0) + 1;
    });

    res.json(Object.entries(hourly).map(([hour, count]) => ({ hour: parseInt(hour), count })));
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar usuários por hora' });
  }
});

// Tráfego total
app.get('/api/stats/total-traffic', authMiddleware, async (req, res) => {
  try {
    const { data } = await supabase.from('pops').select('bandwidth_used');
    let totalMbps = 0;
    (data || []).forEach(pop => {
      const match = (pop.bandwidth_used || '').match(/[\d.]+/);
      if (match) totalMbps += parseFloat(match[0]);
    });
    res.json({ total_mbps: totalMbps, formatted: `${totalMbps.toFixed(1)} Mbps` });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar tráfego total' });
  }
});

// Pico de banda
app.get('/api/stats/peak-bandwidth', authMiddleware, async (req, res) => {
  try {
    const { data } = await supabase.from('pops').select('bandwidth_used');
    let peakMbps = 0;
    (data || []).forEach(pop => {
      const match = (pop.bandwidth_used || '').match(/[\d.]+/);
      if (match) {
        const val = parseFloat(match[0]);
        if (val > peakMbps) peakMbps = val;
      }
    });
    res.json({ peak_mbps: peakMbps, formatted: `${peakMbps.toFixed(1)} Mbps` });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar pico de banda' });
  }
});

// Comparação (faturamento por plano)
app.get('/api/stats/comparison', authMiddleware, async (req, res) => {
  try {
    const { data: payments } = await supabase.from('payments').select('plan_id, amount').eq('status', 'approved');
    const { data: plans } = await supabase.from('plans').select('id, name');

    const planMap = {};
    (plans || []).forEach(p => { planMap[p.id] = p.name; });

    const comparison = {};
    (payments || []).forEach(p => {
      const planName = planMap[p.plan_id] || 'Outros';
      comparison[planName] = (comparison[planName] || 0) + parseFloat(p.amount || 0);
    });

    res.json(Object.entries(comparison).map(([name, total]) => ({ name, total })));
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar comparação' });
  }
});

// ============================================================
// ROTAS DE LOGS
// ============================================================

app.get('/api/logs', authMiddleware, async (req, res) => {
  try {
    const { limit: queryLimit, level, source } = req.query;
    let query = supabase.from('logs').select('*').order('created_at', { ascending: false });
    if (level) query = query.eq('level', level);
    if (source) query = query.eq('source', source);
    query = query.limit(parseInt(queryLimit) || 200);
    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar logs:', err.message);
    res.status(500).json({ error: 'Erro ao listar logs' });
  }
});

app.get('/api/audit-logs', authMiddleware, async (req, res) => {
  try {
    const { limit: queryLimit, type, username } = req.query;
    let query = supabase.from('audit_logs').select('*').order('created_at', { ascending: false });
    if (type) query = query.eq('type', type);
    if (username) query = query.eq('username', username);
    query = query.limit(parseInt(queryLimit) || 200);
    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar logs de auditoria:', err.message);
    res.status(500).json({ error: 'Erro ao listar logs de auditoria' });
  }
});

// Criar log de auditoria manual
app.post('/api/audit-logs', authMiddleware, async (req, res) => {
  try {
    const { type, object, action } = req.body;
    const { data, error } = await supabase.from('audit_logs').insert({
      username: req.user.username, type, object, action,
      ip: req.ip, user_agent: req.headers['user-agent']
    }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao criar log de auditoria' });
  }
});

// ============================================================
// MIKROTIK SCRIPT GENERATORS
// ============================================================

function generateInstallationScript(params) {
  const {
    uniqueId, hotspotName, installationType = 'new',
    wanInterface = 'ether1', lanInterface = 'ether4', vlanId,
    wanType = 'dhcp', pppoeUser = '', pppoePass = '',
    staticIp = '', staticMask = '', staticGw = '',
    hotspotType = 'new_vlan', existingVlan = '', physicalPort = '',
    radiusSecret, frontendHost = 'hotspot-system.vercel.app',
    apiHost = 'mstelecom-api.duckdns.org'
  } = params;

  const safeName = slugifyValue(hotspotName || uniqueId);
  const apiUser = `ms_api_${safeName}`.slice(0, 15);
  const apiPass = generateStrongPassword(16);

  let outputInterface = lanInterface;
  let outputConfig = '';
  let bridgePortConfig = '';

  if (hotspotType === 'existing_vlan' && existingVlan) {
    outputInterface = `vlan-${uniqueId}`;
    outputConfig = `/interface vlan add name="${outputInterface}" vlan-id=${existingVlan} interface=${lanInterface} comment="MS-TELECOM-${uniqueId}"`;
    bridgePortConfig = `/interface bridge port add bridge="ms-bridge-${uniqueId}" interface="${outputInterface}" comment="MS-TELECOM-${uniqueId}"`;
  } else if (hotspotType === 'physical_port' && physicalPort) {
    outputInterface = physicalPort;
    bridgePortConfig = `/interface bridge port add bridge="ms-bridge-${uniqueId}" interface="${outputInterface}" comment="MS-TELECOM-${uniqueId}"`;
  } else if (vlanId) {
    outputInterface = `vlan-hotspot-${uniqueId}`;
    outputConfig = `/interface vlan add name="${outputInterface}" vlan-id=${vlanId} interface=${lanInterface} comment="MS-TELECOM-${uniqueId}"`;
    bridgePortConfig = `/interface bridge port add bridge="ms-bridge-${uniqueId}" interface="${outputInterface}" comment="MS-TELECOM-${uniqueId}"`;
  } else {
    bridgePortConfig = `/interface bridge port add bridge="ms-bridge-${uniqueId}" interface="${outputInterface}" comment="MS-TELECOM-${uniqueId}"`;
  }

  let wanConfig = '';
  if (installationType === 'new') {
    if (wanType === 'pppoe') {
      wanConfig = `/interface pppoe-client add interface=${wanInterface} user="${pppoeUser}" password="${pppoePass}" disabled=no add-default-route=yes comment="MS-TELECOM-${uniqueId}"`;
    } else if (wanType === 'static') {
      wanConfig = `/ip address add address=${staticIp}/${staticMask} interface=${wanInterface} comment="MS-TELECOM-${uniqueId}"
/ip route add gateway=${staticGw} comment="MS-TELECOM-${uniqueId}"`;
    } else {
      wanConfig = `/ip dhcp-client add interface=${wanInterface} disabled=no comment="MS-TELECOM-${uniqueId}"`;
    }
  } else {
    wanConfig = `# WAN preserved in production mode`;
  }

  return `# ============================================
# MS TELECOM - INSTALLATION SCRIPT
# ID: ${uniqueId}
# HOTSPOT: ${hotspotName}
# TYPE: ${installationType}
# ============================================

# 1. BACKUP
/system backup save name=backup_pre_ms_${uniqueId}
/export file=config_pre_ms_${uniqueId}
:delay 2s

# 2. IDENTITY
/system identity set name="${hotspotName}"
:delay 500ms

# 3. API USER
/user add name="${apiUser}" password="${apiPass}" group=full comment="MS-TELECOM-${uniqueId}"
:delay 500ms

# 4. BRIDGE
/interface bridge add name="ms-bridge-${uniqueId}" comment="MS-TELECOM-${uniqueId}"
:delay 500ms
${outputConfig}
${bridgePortConfig}
:delay 1s

# 5. HOTSPOT IP
/ip address add address=192.168.32.1/20 interface="ms-bridge-${uniqueId}" network=192.168.32.0 comment="MS-TELECOM-${uniqueId}"
:delay 500ms

# 6. DHCP
/ip pool add name="ms-pool-${uniqueId}" ranges=192.168.32.10-192.168.47.254 comment="MS-TELECOM-${uniqueId}"
/ip dhcp-server add address-pool="ms-pool-${uniqueId}" disabled=no interface="ms-bridge-${uniqueId}" name="ms-dhcp-${uniqueId}" lease-time=24h
/ip dhcp-server network add address=192.168.32.0/20 gateway=192.168.32.1 dns-server=8.8.8.8,1.1.1.1 comment="MS-TELECOM-${uniqueId}"
:delay 1s

# 7. WAN
${wanConfig}
:delay 1s

# 8. NAT
/ip firewall nat add action=masquerade chain=srcnat out-interface=${wanInterface} comment="MS-TELECOM-${uniqueId}"
:delay 500ms

# 9. DNS
/ip dns set allow-remote-requests=yes servers=8.8.8.8,1.1.1.1
:delay 500ms

# 10. RADIUS
/radius add address=${RADIUS_SERVER_IP} secret=${radiusSecret} service=hotspot comment="MS-TELECOM-${uniqueId}" timeout=1000ms
/radius incoming set accept=yes
:delay 1s

# 11. HOTSPOT PROFILE
/ip hotspot profile add name="ms-profile-${uniqueId}" hotspot-address=192.168.32.1 login-by=http-chap,http-pap,mac-cookie use-radius=yes radius-default-domain="${uniqueId}" radius-interim-update=10m html-directory=hotspot
:delay 500ms

# 12. HOTSPOT
/ip hotspot add address-pool="ms-pool-${uniqueId}" disabled=no idle-timeout=15m interface="ms-bridge-${uniqueId}" name="${hotspotName}" profile="ms-profile-${uniqueId}"
:delay 1s

# 13. WALLED GARDEN
/ip hotspot walled-garden ip add action=accept disabled=no dst-host=${frontendHost} server="${hotspotName}" comment="MS-TELECOM-${uniqueId}"
/ip hotspot walled-garden ip add action=accept disabled=no dst-host=${apiHost} server="${hotspotName}"
/ip hotspot walled-garden ip add action=accept disabled=no dst-host=cdn.tailwindcss.com server="${hotspotName}"
/ip hotspot walled-garden ip add action=accept disabled=no dst-host=unpkg.com server="${hotspotName}"
/ip hotspot walled-garden ip add action=accept disabled=no dst-host=fonts.googleapis.com server="${hotspotName}"
/ip hotspot walled-garden ip add action=accept disabled=no dst-host=fonts.gstatic.com server="${hotspotName}"
:delay 1s

# 14. HEARTBEAT
/system scheduler add name="ms-heartbeat-${safeName}" interval=00:00:30 on-event="/tool fetch url=\\"${API_BASE_URL}/api/pops/${uniqueId}/ping\\" http-method=post http-data=\\"{\\\\\\"name\\\\\\":\\\\\\"${hotspotName}\\\\\\",\\\\\\"api_user\\\\\\":\\\\\\"${apiUser}\\\\\\",\\\\\\"api_pass\\\\\\":\\\\\\"${apiPass}\\\\\\"}\\" http-header-field=\\"Content-Type: application/json\\" keep-result=no" policy=read,write,test
`;
}

function generateRevertScript({ uniqueId, hotspotName }) {
  return `# ============================================
# MS TELECOM - REVERT SCRIPT
# ID: ${uniqueId}
# HOTSPOT: ${hotspotName}
# ============================================

/system scheduler remove [find name="ms-heartbeat-${slugifyValue(hotspotName || uniqueId)}"]
/ip hotspot remove [find name="${hotspotName}"]
/ip hotspot profile remove [find name="ms-profile-${uniqueId}"]
/radius remove [find comment="MS-TELECOM-${uniqueId}"]
/ip firewall nat remove [find comment="MS-TELECOM-${uniqueId}"]
/ip dhcp-server remove [find name="ms-dhcp-${uniqueId}"]
/ip dhcp-server network remove [find comment="MS-TELECOM-${uniqueId}"]
/ip pool remove [find name="ms-pool-${uniqueId}"]
/ip address remove [find comment="MS-TELECOM-${uniqueId}"]
/interface bridge port remove [find comment="MS-TELECOM-${uniqueId}"]
/interface vlan remove [find comment="MS-TELECOM-${uniqueId}"]
/interface bridge remove [find name="ms-bridge-${uniqueId}"]
/user remove [find comment="MS-TELECOM-${uniqueId}"]
`;
}

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/api/health', (_req, res) => {
  return res.json({
    status: 'ok',
    version: '3.1.0',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    mikrotik_api: !!RouterOSAPI
  });
});

// ============================================================
// START SERVER
// ============================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Hotspot System API v3.1 running on port ${PORT}`);
  console.log(`Frontend: ${FRONTEND_BASE_URL}`);
  console.log(`API: ${API_BASE_URL}`);
  console.log(`MikroTik API: ${RouterOSAPI ? 'enabled' : 'disabled'}`);
});
