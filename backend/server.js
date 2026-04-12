// ============================================================
// 🚀 HOTSPOT SYSTEM - MS TELECOM
// Backend principal (server.js) - VERSÃO DEFINITIVA
// Código interno em inglês, comentários em português
// ============================================================

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const fs = require('fs');

// RouterOS API para controle MikroTik (opcional)
let RouterOSAPI = null;
try {
  RouterOSAPI = require('node-routeros').RouterOSAPI;
} catch (e) {
  console.warn('⚠️ node-routeros não instalado - recursos de API MikroTik desabilitados');
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const PORT = process.env.PORT || 3000;
const API_BASE_URL = process.env.API_BASE_URL || 'https://mstelecom-api.duckdns.org';
const FRONTEND_BASE_URL = process.env.FRONTEND_BASE_URL || 'https://hotspot-system.vercel.app';
const RADIUS_SERVER_IP = process.env.RADIUS_SERVER_IP || '40.233.118.238';
const JWT_SECRET = process.env.JWT_SECRET;

// Constantes do Sistema
const BACKUP_DIR = path.join(__dirname, 'backups');
if (!fs.existsSync(BACKUP_DIR)) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

// CORS configurado para aceitar requisições do frontend no Vercel
app.use(cors({
    origin: [
        'https://hotspot-system.vercel.app',
        'http://localhost:3000',
        'https://mstelecom-api.duckdns.org'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// Validação de variáveis de ambiente
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_KEY || !JWT_SECRET) {
  console.error('❌ FATAL: Variáveis de ambiente obrigatórias faltando: SUPABASE_URL, SUPABASE_KEY, JWT_SECRET');
  process.exit(1);
}

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// ============================================================
// 🛠️ FUNÇÕES UTILITÁRIAS
// ============================================================

// Remove acentos de uma string (útil para slugs)
function removeAccents(str) {
  return String(str).normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

// Gera slug a partir de um texto
function slugify(value) {
  return removeAccents(String(value))
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// Gera senha forte aleatória
function generateStrongPassword(length = 20) {
  return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
}

// Converte para número de forma segura
function parseNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

// Converte para booleano de forma segura
function parseBoolean(value, fallback = false) {
  if (value === undefined) return fallback;
  return ['true', '1', 'yes', 'sim', 'on'].includes(String(value).toLowerCase());
}

// ============================================================
// 📝 LOGS DE AUDITORIA E SISTEMA
// ============================================================

// Registrar log de auditoria (ações de usuários)
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
    console.error('❌ Erro ao registrar log de auditoria:', error.message);
  }
}

// Registrar log do sistema (eventos internos)
async function registerSystemLog(level, source, message, details = null, ip = '', userAgent = '') {
  try {
    await supabase.from('logs').insert({
      level: level || 'info',
      source: source || 'system',
      message,
      details: details ? JSON.stringify(details) : null,
      ip,
      user_agent: userAgent,
      created_at: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Erro ao registrar log do sistema:', error.message);
  }
}

// ============================================================
// 🔐 MIDDLEWARE DE AUTENTICAÇÃO
// ============================================================

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  
  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// ============================================================
// 🔧 MIKROTIK CREDENTIALS HELPERS
// ============================================================

// Buscar credenciais MikroTik
async function getMikrotikCredentials(popIp = null, popId = null) {
  if (popId) {
    const { data, error } = await supabase.from('mikrotik_credentials').select('*').eq('pop_id', popId).maybeSingle();
    if (!error && data) return data;
  }
  if (popIp) {
    const { data, error } = await supabase.from('mikrotik_credentials').select('*').eq('pop_ip', popIp).maybeSingle();
    if (!error && data) return data;
  }
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

// ============================================================
// 🔓 MIKROTIK ACCESS CONTROL
// ============================================================

// Revogar acesso - remove IP Binding do MikroTik
async function revokeAccess(macAddress, popIp = '192.168.32.1', apiUser = null, apiPass = null, popId = null) {
  if (!RouterOSAPI) {
    console.warn('⚠️ revokeAccess: node-routeros não disponível');
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
      throw new Error('Credenciais da API MikroTik não disponíveis');
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
    console.error(`❌ Falha ao revogar acesso para ${macAddress}:`, error.message);
    return false;
  }
}

// Autorizar acesso - IP Binding com type=bypassed + RADIUS
async function authorizeAccess(macAddress, popIp = '192.168.32.1', apiUser = null, apiPass = null, popId = null, durationMinutes = 15, speedMbps = null, planName = 'free_trial') {
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
            '=comment=AUTORIZADO-MS-TELECOM'
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
      plan_name: planName,
      status: 'active',
      expires_at: expiresAt,
      updated_at: new Date().toISOString()
    }, { onConflict: 'username' });

    if (error) throw error;
    viaRadius = true;

    // Inserir Mikrotik-Rate-Limit no radreply se velocidade informada
    if (speedMbps) {
      const rateLimit = `${speedMbps}M/${speedMbps}M`;
      await supabase.from('radreply').upsert({
        username: macAddress,
        attribute: 'Mikrotik-Rate-Limit',
        op: ':=',
        value: rateLimit
      }, { onConflict: 'username,attribute' }).catch(() => {});
    }
  } catch (error) {
    errors.push(`RADIUS: ${error.message}`);
  }

  return { success: viaApi || viaRadius, viaApi, viaRadius, errors };
}

// ============================================================
// ⏱️ CRON JOB - REMOVER ACESSOS EXPIRADOS
// ============================================================

setInterval(async () => {
  try {
    const now = new Date().toISOString();
    
    // 1. Limpar sessões expiradas
    const { data: expiredSessions } = await supabase.from('hotspot_sessions')
      .select('mac_address, pop_ip')
      .eq('status', 'active')
      .lt('expires_at', now);

    for (const session of expiredSessions || []) {
      await revokeAccess(session.mac_address, session.pop_ip);
      await supabase.from('hotspot_sessions').update({ status: 'expired', updated_at: now }).eq('mac_address', session.mac_address);
    }

    // 2. Limpar RADIUS expirado
    const { data: expiredRadius } = await supabase.from('radius_replies')
      .select('username')
      .eq('status', 'active')
      .lt('expires_at', now);

    for (const rad of expiredRadius || []) {
      await supabase.from('radius_replies').update({ status: 'expired', updated_at: now }).eq('username', rad.username);
      await supabase.from('radreply').delete().eq('username', rad.username);
    }

  } catch (error) {
    console.error('❌ Erro no CRON de limpeza:', error.message);
  }
}, 60000); // Executa a cada 1 minuto

// ============================================================
// 🔑 ROTAS DE AUTENTICAÇÃO (ADMIN)
// ============================================================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });

    const { data: admin, error } = await supabase.from('admins').select('*').eq('username', username).single();
    if (error || !admin) return res.status(401).json({ error: 'Credenciais inválidas' });

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    if (admin.password !== hashedPassword && admin.password !== password) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const token = jwt.sign({ id: admin.id, username: admin.username, role: admin.role }, JWT_SECRET, { expiresIn: '24h' });
    
    await registerAuditLog(username, 'login', 'auth', 'Login realizado', req.ip, req.headers['user-agent']);
    
    res.json({ token, user: { id: admin.id, username: admin.username, role: admin.role } });
  } catch (err) {
    console.error('❌ Erro no login:', err.message);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  await registerAuditLog(req.user.username, 'logout', 'auth', 'Logout realizado', req.ip, req.headers['user-agent']);
  res.json({ message: 'Logout realizado com sucesso' });
});

// Aliases de compatibilidade (rotas antigas)
app.post('/api/login', (req, res) => {
  req.url = '/api/auth/login';
  return app._router.handle(req, res);
});

app.post('/api/logout', authMiddleware, (req, res) => {
  req.url = '/api/auth/logout';
  return app._router.handle(req, res);
});

app.put('/api/update-profile', authMiddleware, (req, res) => {
  req.url = '/api/profile';
  return app._router.handle(req, res);
});

app.post('/api/update-profile', authMiddleware, (req, res) => {
  req.url = '/api/profile';
  return app._router.handle(req, res);
});

app.put('/api/atualizar-perfil', authMiddleware, (req, res) => {
  req.url = '/api/profile';
  return app._router.handle(req, res);
});

// Atualizar perfil do administrador logado
app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const { username, email, current_password, new_password } = req.body;
    const adminId = req.user.id;

    const { data: admin, error } = await supabase
      .from('admins')
      .select('*')
      .eq('id', adminId)
      .single();
    if (error || !admin) return res.status(404).json({ error: 'Admin não encontrado' });

    if (new_password) {
      if (!current_password) return res.status(400).json({ error: 'Senha atual obrigatória' });
      const hashedCurrent = crypto.createHash('sha256').update(current_password).digest('hex');
      if (admin.password !== hashedCurrent && admin.password !== current_password) {
        return res.status(401).json({ error: 'Senha atual incorreta' });
      }
    }

    const updateData = { updated_at: new Date().toISOString() };
    if (username) updateData.username = username;
    if (email) updateData.email = email;
    if (new_password) updateData.password = crypto.createHash('sha256').update(new_password).digest('hex');

    const { data, error: updateError } = await supabase
      .from('admins')
      .update(updateData)
      .eq('id', adminId)
      .select()
      .single();

    if (updateError) throw updateError;
    await registerAuditLog(admin.username, 'update', 'admin', 'Perfil atualizado', req.ip, req.headers['user-agent']);
    res.json({ success: true, user: { id: data.id, username: data.username, email: data.email } });
  } catch (err) {
    console.error('❌ Erro ao atualizar perfil:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar perfil' });
  }
});

// ============================================================
// 👥 ROTAS DE USUÁRIOS (CLIENTES)
// ============================================================

// Listar usuários
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const { search, status, plan_id } = req.query;
    let query = supabase.from('users').select('*').order('created_at', { ascending: false });

    if (search) {
      query = query.or(`name.ilike.%${search}%,username.ilike.%${search}%,mac_address.ilike.%${search}%,phone.ilike.%${search}%,cpf.ilike.%${search}%`);
    }
    if (status) query = query.eq('status', status);
    if (plan_id) query = query.eq('plan_id', plan_id);

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('❌ Erro ao listar usuários:', err.message);
    res.status(500).json({ error: 'Erro ao listar usuários' });
  }
});

// Criar usuário
app.post('/api/users', authMiddleware, async (req, res) => {
  try {
    const { name, username, mac_address, phone, cpf, email, address, plan_id, plan_name, hotspot_id, status, is_vip } = req.body;

    const { data, error } = await supabase.from('users').insert({
      name, username, mac_address, phone, cpf, email, address,
      plan_id, plan_name, hotspot_id,
      status: status || 'inactive',
      is_vip: is_vip || false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    }).select().single();

    if (error) throw error;
    await registerAuditLog(req.user.username, 'create', 'user', `Usuário criado: ${name}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('❌ Erro ao criar usuário:', err.message);
    res.status(500).json({ error: 'Erro ao criar usuário' });
  }
});

// Atualizar usuário
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
    console.error('❌ Erro ao atualizar usuário:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar usuário' });
  }
});

// Deletar usuário
app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('users').delete().eq('id', id);
    if (error) throw error;

    await registerAuditLog(req.user.username, 'delete', 'user', `Usuário removido: ${id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Usuário removido com sucesso' });
  } catch (err) {
    console.error('❌ Erro ao deletar usuário:', err.message);
    res.status(500).json({ error: 'Erro ao deletar usuário' });
  }
});

// Renovar plano do usuário
app.post('/api/users/:id/renew', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { plan_id, duration_days } = req.body;

    const { data: plan, error: planError } = await supabase.from('plans').select('*').eq('id', plan_id).single();
    if (planError || !plan) return res.status(400).json({ error: 'Plano não encontrado' });

    const days = duration_days || plan.duration_days || 30;
    const expiresAt = new Date(Date.now() + Number(days) * 24 * 60 * 60 * 1000).toISOString();

    const { data, error } = await supabase.from('users').update({
      plan_id: plan_id, plan_name: plan.name, status: 'active',
      expires_at: expiresAt, updated_at: new Date().toISOString()
    }).eq('id', id).select().single();

    if (error) throw error;
    await registerAuditLog(req.user.username, 'update', 'user', `Plano renovado: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    console.error('❌ Erro ao renovar plano:', err.message);
    res.status(500).json({ error: 'Erro ao renovar plano' });
  }
});

// Bloquear usuário
app.post('/api/users/:id/block', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase.from('users').update({ status: 'blocked', updated_at: new Date().toISOString() }).eq('id', id).select().single();
    if (error) throw error;
    await registerAuditLog(req.user.username, 'update', 'user', `Usuário bloqueado: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    console.error('❌ Erro ao bloquear usuário:', err.message);
    res.status(500).json({ error: 'Erro ao bloquear usuário' });
  }
});

// Desbloquear usuário
app.post('/api/users/:id/unblock', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase.from('users').update({ status: 'active', updated_at: new Date().toISOString() }).eq('id', id).select().single();
    if (error) throw error;
    await registerAuditLog(req.user.username, 'update', 'user', `Usuário desbloqueado: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    console.error('❌ Erro ao desbloquear usuário:', err.message);
    res.status(500).json({ error: 'Erro ao desbloquear usuário' });
  }
});

// Marcar usuário como VIP
app.post('/api/users/:id/vip', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { is_vip = true } = req.body;
    const { data, error } = await supabase.from('users').update({ is_vip, updated_at: new Date().toISOString() }).eq('id', id).select().single();
    if (error) throw error;
    await registerAuditLog(req.user.username, 'update', 'user', `VIP atualizado: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    console.error('❌ Erro ao atualizar VIP:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar VIP' });
  }
});

// Buscar usuário por ID
app.get('/api/users/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: user, error: userError } = await supabase.from('users').select('*').eq('id', id).maybeSingle();
    if (userError || !user) return res.status(404).json({ error: 'Usuário não encontrado' });

    const { data: payments } = await supabase.from('payments').select('amount').eq('user_id', id).eq('status', 'approved');
    const totalSpent = (payments || []).reduce((sum, p) => sum + (Number(p.amount) || 0), 0);

    const { data: lastSession } = await supabase.from('hotspot_sessions').select('created_at').eq('user_id', id).order('created_at', { ascending: false }).limit(1).maybeSingle();

    res.json({ ...user, total_spent: totalSpent, last_access: lastSession?.created_at || user.last_seen_at || null });
  } catch (err) {
    console.error('❌ Erro ao buscar usuário:', err.message);
    res.status(500).json({ error: 'Erro ao buscar usuário' });
  }
});

// Exportar usuários para CSV
app.get('/api/users/export', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*').order('created_at', { ascending: false });
    if (error) throw error;

    const headers = ['Nome', 'Usuário', 'MAC', 'Telefone', 'CPF', 'Email', 'Plano', 'Status', 'Data Cadastro'];
    const rows = (data || []).map(u => [
      u.name || '', u.username || '', u.mac_address || '', u.phone || '', u.cpf || '', u.email || '', u.plan_name || '', u.status || '',
      u.created_at ? new Date(u.created_at).toLocaleDateString('pt-BR') : ''
    ]);

    const csv = [headers, ...rows].map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(';')).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename=users_${new Date().toISOString().slice(0, 10)}.csv`);
    res.send('\uFEFF' + csv);
  } catch (err) {
    console.error('❌ Erro ao exportar usuários:', err.message);
    res.status(500).json({ error: 'Erro ao exportar usuários' });
  }
});

// ============================================================
// 📋 ROTAS DE PLANOS
// ============================================================

// Listar planos
app.get('/api/plans', async (req, res) => {
  try {
    const { data, error } = await supabase.from('plans').select('*').order('price', { ascending: true });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('❌ Erro ao listar planos:', err.message);
    res.status(500).json({ error: 'Erro ao listar planos' });
  }
});

// Criar plano
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
    console.error('❌ Erro ao criar plano:', err.message);
    res.status(500).json({ error: 'Erro ao criar plano' });
  }
});

// Atualizar plano
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
    console.error('❌ Erro ao atualizar plano:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar plano' });
  }
});

// Deletar plano
app.delete('/api/plans/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('plans').delete().eq('id', id);
    if (error) throw error;

    await registerAuditLog(req.user.username, 'delete', 'plan', `Plano removido: ${id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Plano removido com sucesso' });
  } catch (err) {
    console.error('❌ Erro ao deletar plano:', err.message);
    res.status(500).json({ error: 'Erro ao deletar plano' });
  }
});

// ============================================================
// 💳 ROTAS DE PAGAMENTOS
// ============================================================

// Listar pagamentos
app.get('/api/payments', authMiddleware, async (req, res) => {
  try {
    const { status, user_id, mac_address } = req.query;
    let query = supabase.from('payments').select('*, users(name, username)').order('created_at', { ascending: false });

    if (status) query = query.eq('status', status);
    if (user_id) query = query.eq('user_id', user_id);
    if (mac_address) query = query.eq('user_mac', mac_address);

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('❌ Erro ao listar pagamentos:', err.message);
    res.status(500).json({ error: 'Erro ao listar pagamentos' });
  }
});

// Gerar PIX (Mercado Pago)
app.post('/api/payments/generate-pix', async (req, res) => {
  try {
    const { mac_address, plan_name, amount, description, payment_id } = req.body;
    if (!mac_address || !amount) return res.status(400).json({ error: 'MAC e valor são obrigatórios' });

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
        description: description || plan_name || 'Plano WiFi',
        payment_method_id: 'pix',
        payer: {
          email: 'cliente@hotspot.com',
          first_name: 'Cliente',
          identification: {
            type: 'CPF',
            number: '00000000000'
          }
        },
        external_reference: externalReference
      })
    });

    const mpData = await mpResponse.json();
    if (!mpResponse.ok) return res.status(400).json({ error: 'Erro ao gerar pagamento PIX', details: mpData });

    const pixCopyPaste = mpData.point_of_interaction?.transaction_data?.qr_code || '';
    const qrCodeBase64 = mpData.point_of_interaction?.transaction_data?.qr_code_base64 || '';

    let payment;
    let error;

    const paymentData = {
      user_mac: mac_address,
      plan_name: plan_name || null,
      amount: parseFloat(amount),
      description: description || plan_name || 'Plano WiFi',
      status: 'pending',
      payment_method: 'pix',
      mercado_pago_id: String(mpData.id),
      pix_copy_paste: pixCopyPaste,
      qr_code: qrCodeBase64,
      external_reference: externalReference,
      expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
      updated_at: new Date().toISOString()
    };

    if (payment_id) {
      const result = await supabase.from('payments').update(paymentData).eq('id', payment_id).select().single();
      payment = result.data;
      error = result.error;
    } else {
      const result = await supabase.from('payments').insert(paymentData).select().single();
      payment = result.data;
      error = result.error;
    }

    if (error) throw error;

    res.json({
      payment_id: payment.id,
      pix_code: pixCopyPaste,
      qr_code_base64: qrCodeBase64,
      pix_copy_paste: pixCopyPaste,
      qr_code: qrCodeBase64,
      external_reference: externalReference
    });
  } catch (err) {
    console.error('❌ Erro ao gerar PIX:', err.message);
    res.status(500).json({ error: 'Erro ao gerar pagamento PIX' });
  }
});

// Aliases de pagamento (legado)
app.post('/api/create-payment', (req, res) => {
  req.url = '/api/payments/generate-pix';
  return app._router.handle(req, res);
});

app.post('/api/confirm-payment', (req, res) => {
  req.url = '/api/check-payment';
  return app._router.handle(req, res);
});

app.post('/api/criar-pagamento', (req, res) => {
  req.url = '/api/payments/generate-pix';
  return app._router.handle(req, res);
});

app.post('/api/confirmar-pagamento', (req, res) => {
  req.url = '/api/check-payment';
  return app._router.handle(req, res);
});

// Verificar status de pagamento
app.get('/api/check-payment', async (req, res) => {
  try {
    const { external_reference, mercado_pago_id } = req.query;
    if (!external_reference && !mercado_pago_id) return res.status(400).json({ error: 'Referência ou ID do pagamento necessário' });

    let query = supabase.from('payments').select('*');
    if (external_reference) query = query.eq('external_reference', external_reference);
    else query = query.eq('mercado_pago_id', mercado_pago_id);

    const { data: payment, error } = await query.single();
    if (error || !payment) return res.status(404).json({ error: 'Pagamento não encontrado' });

    res.json(payment);
  } catch (err) {
    console.error('❌ Erro ao verificar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao verificar pagamento' });
  }
});

// ============================================================
// 🎟️ ROTAS DE VOUCHERS
// ============================================================

// Listar vouchers
app.get('/api/vouchers', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('vouchers').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('❌ Erro ao listar vouchers:', err.message);
    res.status(500).json({ error: 'Erro ao listar vouchers' });
  }
});

// Criar vouchers (suporta lote via 'count' ou 'quantity')
app.post('/api/vouchers', authMiddleware, async (req, res) => {
  try {
    const { plan_name, amount, expires_at, duration_hours, quantity, count } = req.body;
    const qty = parseInt(quantity || count || 1);
    
    if (qty === 1 && !quantity && !count) {
      // Single voucher
      const { data, error } = await supabase.from('vouchers').insert({
        code: crypto.randomBytes(4).toString('hex').toUpperCase(),
        plan_name, amount: parseFloat(amount) || 0,
        expires_at: expires_at ? new Date(expires_at).toISOString() : null,
        duration_hours: duration_hours || 24,
        status: 'active', used: false, created_at: new Date().toISOString()
      }).select().single();
      if (error) throw error;
      res.status(201).json(data);
    } else {
      // Batch vouchers
      const vouchers = [];
      for (let i = 0; i < Math.min(qty, 100); i++) {
        vouchers.push({
          code: crypto.randomBytes(4).toString('hex').toUpperCase(),
          plan_name, amount: parseFloat(amount) || 0,
          expires_at: expires_at ? new Date(expires_at).toISOString() : null,
          duration_hours: duration_hours || 24,
          status: 'active', used: false, created_at: new Date().toISOString()
        });
      }
      const { data, error } = await supabase.from('vouchers').insert(vouchers).select();
      if (error) throw error;
      res.status(201).json(data);
    }
  } catch (err) {
    console.error('❌ Erro ao criar vouchers:', err.message);
    res.status(500).json({ error: 'Erro ao criar vouchers' });
  }
});

// Atualizar voucher
app.put('/api/vouchers/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;
    const { data, error } = await supabase.from('vouchers').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('❌ Erro ao atualizar voucher:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar voucher' });
  }
});

// Deletar voucher
app.delete('/api/vouchers/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('vouchers').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Voucher removido' });
  } catch (err) {
    console.error('❌ Erro ao deletar voucher:', err.message);
    res.status(500).json({ error: 'Erro ao deletar voucher' });
  }
});

// Validar voucher (público)
// Alias legado PT
app.post('/api/vouchers/validar', (req, res) => {
  req.url = '/api/vouchers/validate';
  return app._router.handle(req, res);
});

app.post('/api/vouchers/validate', async (req, res) => {
  try {
    const { code, mac_address } = req.body;
    const { data: voucher, error } = await supabase.from('vouchers').select('*').eq('code', String(code).toUpperCase()).eq('status', 'active').maybeSingle();
    if (error || !voucher) return res.status(404).json({ error: 'Voucher inválido ou já utilizado' });

    await supabase.from('vouchers').update({
      status: 'used', used: true, used_at: new Date().toISOString(),
      mac_address: mac_address || null, updated_at: new Date().toISOString()
    }).eq('id', voucher.id);

    res.json({ valid: true, plan_name: voucher.plan_name, duration_hours: voucher.duration_hours });
  } catch (err) {
    console.error('❌ Erro ao validar voucher:', err.message);
    res.status(500).json({ error: 'Erro ao validar voucher' });
  }
});

// ============================================================
// 📊 ROTAS DE ESTATÍSTICAS E DASHBOARD
// ============================================================

// ðŸ”§ HELPERS (compatibilidade / schema flexÃ­vel)
function isMissingColumnError(err) {
  const msg = (err && (err.message || err.details || err.hint)) ? `${err.message || ''} ${err.details || ''} ${err.hint || ''}` : '';
  return /Could not find the '.+' column/i.test(msg) || /column .* does not exist/i.test(msg);
}

async function safeInsertWithFallback(table, preferredPayload, fallbackPayload) {
  let result = await supabase.from(table).insert(preferredPayload).select().single();
  if (result.error && isMissingColumnError(result.error) && fallbackPayload) {
    result = await supabase.from(table).insert(fallbackPayload).select().single();
  }
  return result;
}

// Listar POPs (Hotspots)
app.get('/api/pops', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('pops').select('*').order('name', { ascending: true });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('❌ Erro ao listar POPs:', err.message);
    res.status(500).json({ error: 'Erro ao listar POPs' });
  }
});

// Criar POP
app.post('/api/pops', authMiddleware, async (req, res) => {
  try {
    const now = new Date().toISOString();
    const preferred = { ...req.body, status: req.body.status || 'online', created_at: now };
    delete preferred.id;

    const fallback = {
      name: req.body.name,
      ip: req.body.ip,
      api_user: req.body.api_user,
      api_pass: req.body.api_pass,
      location: req.body.location,
      status: req.body.status || 'online',
      created_at: now
    };

    const { data, error } = await safeInsertWithFallback('pops', preferred, fallback);
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    console.error('❌ Erro ao criar POP:', err.message);
    res.status(500).json({ error: 'Erro ao criar POP' });
  }
});

// Atualizar POP
app.put('/api/pops/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: existing, error: existingErr } = await supabase.from('pops').select('*').eq('id', id).single();
    if (existingErr || !existing) return res.status(404).json({ error: 'POP nÃ£o encontrado' });

    const updateData = { updated_at: new Date().toISOString() };
    for (const [k, v] of Object.entries(req.body || {})) {
      if (k === 'id') continue;
      if (Object.prototype.hasOwnProperty.call(existing, k)) updateData[k] = v;
    }
    const { data, error } = await supabase.from('pops').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('❌ Erro ao atualizar POP:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar POP' });
  }
});

// Deletar POP
app.delete('/api/pops/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('pops').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'POP removido com sucesso' });
  } catch (err) {
    console.error('❌ Erro ao deletar POP:', err.message);
    res.status(500).json({ error: 'Erro ao deletar POP' });
  }
});

// Gerar script de configuraÃ§Ã£o para um POP
app.get('/api/pops/:id/script', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: pop, error } = await supabase.from('pops').select('*').eq('id', id).single();
    if (error || !pop) return res.status(404).json({ error: 'POP nÃ£o encontrado' });

    const radiusServer = process.env.RADIUS_SERVER_IP || '40.233.118.238';
    const apiUrl = process.env.API_BASE_URL || 'https://mstelecom-api.duckdns.org';

    const script = `/system identity set name="${pop.name}"\n` +
      `/radius add address=${radiusServer} secret=testing123 service=hotspot authentication-port=1812 accounting-port=1813\n` +
      `/ip hotspot profile set [find] use-radius=yes\n` +
      `/tool fetch url="${apiUrl}/api/pops/${id}/heartbeat" mode=http keep-result=no\n` +
      `/system scheduler add name="heartbeat-${pop.name}" interval=1m on-event="/tool fetch url=\\"${apiUrl}/api/pops/${id}/heartbeat\\" keep-result=no" start-time=startup\n` +
      `/ip hotspot set [find] address-pool=dhcp_pool1\n`;

    res.json({ script });
  } catch (err) {
    console.error('âŒ Erro ao gerar script:', err.message);
    res.status(500).json({ error: 'Erro ao gerar script' });
  }
});

// Receber heartbeat do MikroTik (atualiza status e Ãºltima atividade)
// Gerar script de reversÃ£o para um POP
app.get('/api/pops/:id/revert-script', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: pop, error } = await supabase.from('pops').select('*').eq('id', id).single();
    if (error || !pop) return res.status(404).json({ error: 'POP nÃ£o encontrado' });

    const uniqueTag = `MS-TELECOM-${id}`;
    const script =
      `# ============================================\n` +
      `# MS TELECOM - SCRIPT DE REVERSAO\n` +
      `# POP: ${pop.name || id}\n` +
      `# TAG: ${uniqueTag}\n` +
      `# ============================================\n\n` +
      `# Remove APENAS itens criados pelo Hotspot (por comment/tag)\n` +
      `:foreach i in=[/system scheduler find where comment~\"${uniqueTag}\"] do={/system scheduler remove $i}\n` +
      `:foreach i in=[/ip hotspot find where comment~\"${uniqueTag}\"] do={/ip hotspot remove $i}\n` +
      `:foreach i in=[/ip hotspot profile find where comment~\"${uniqueTag}\"] do={/ip hotspot profile remove $i}\n` +
      `:foreach i in=[/ip pool find where comment~\"${uniqueTag}\"] do={/ip pool remove $i}\n` +
      `:foreach i in=[/ip dhcp-server find where comment~\"${uniqueTag}\"] do={/ip dhcp-server remove $i}\n` +
      `:foreach i in=[/ip address find where comment~\"${uniqueTag}\"] do={/ip address remove $i}\n` +
      `:foreach i in=[/interface bridge find where comment~\"${uniqueTag}\"] do={/interface bridge remove $i}\n` +
      `:foreach i in=[/interface vlan find where comment~\"${uniqueTag}\"] do={/interface vlan remove $i}\n`;

    res.json({ script });
  } catch (err) {
    console.error('âŒ Erro ao gerar script de reversÃ£o:', err.message);
    res.status(500).json({ error: 'Erro ao gerar script de reversÃ£o' });
  }
});

// Ping do POP (compat: antigos chamavam /api/pops/:id/ping)
app.post('/api/pops/:id/ping', async (req, res) => {
  try {
    const { id } = req.params;
    const now = new Date().toISOString();
    const { data: pop, error: popErr } = await supabase.from('pops').select('*').eq('id', id).single();
    if (popErr || !pop) return res.status(404).json({ error: 'POP nÃ£o encontrado' });

    const updateData = { status: 'online', updated_at: now };
    if (Object.prototype.hasOwnProperty.call(pop, 'last_heartbeat')) updateData.last_heartbeat = now;
    if (Object.prototype.hasOwnProperty.call(pop, 'last_seen')) updateData.last_seen = now;
    if (Object.prototype.hasOwnProperty.call(pop, 'users_connected') && req.body && typeof req.body.users_connected !== 'undefined') {
      updateData.users_connected = req.body.users_connected;
    }
    if (Object.prototype.hasOwnProperty.call(pop, 'bandwidth') && req.body && typeof req.body.bandwidth !== 'undefined') {
      updateData.bandwidth = req.body.bandwidth;
    }

    const { error: updateErr } = await supabase.from('pops').update(updateData).eq('id', id);
    if (updateErr) throw updateErr;
    res.json({ status: 'ok', pop_id: id, timestamp: now });
  } catch (err) {
    console.error('âŒ Erro ao processar ping do POP:', err.message);
    res.status(500).json({ error: 'Erro ao processar ping' });
  }
});

// Status do POP (pÃºblico)
app.get('/api/pops/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { data: pop, error } = await supabase.from('pops').select('*').eq('id', id).single();
    if (error || !pop) return res.status(404).json({ error: 'POP nÃ£o encontrado' });

    const last = pop.last_heartbeat || pop.last_seen || pop.updated_at || pop.created_at;
    const seconds = last ? Math.floor((Date.now() - new Date(last).getTime()) / 1000) : null;
    const status = (seconds !== null && seconds > 60) ? 'offline' : (pop.status || 'online');
    res.json({ id, name: pop.name, status, seconds_since_last: seconds });
  } catch (err) {
    console.error('âŒ Erro ao consultar status do POP:', err.message);
    res.status(500).json({ error: 'Erro ao consultar status' });
  }
});

// Registrar POP via MikroTik (pÃºblico)
app.post('/api/pops/register', async (req, res) => {
  try {
    const now = new Date().toISOString();
    const { name, ip, location } = req.body || {};
    if (!name || !ip) return res.status(400).json({ error: 'name e ip sÃ£o obrigatÃ³rios' });

    const popToken = crypto.randomBytes(32).toString('hex');
    const preferred = { ...req.body, name, ip, location, status: 'online', token: popToken, last_heartbeat: now, created_at: now };
    delete preferred.id;
    const fallback = { name, ip, location, status: 'online', created_at: now };

    const { data, error } = await safeInsertWithFallback('pops', preferred, fallback);
    if (error) throw error;

    res.status(201).json({ status: 'success', pop_id: data.id, pop_token: popToken });
  } catch (err) {
    console.error('âŒ Erro ao registrar POP:', err.message);
    res.status(500).json({ error: 'Erro ao registrar POP' });
  }
});

app.post('/api/pops/:id/heartbeat', async (req, res) => {
  try {
    const { id } = req.params;
    await supabase
      .from('pops')
      .update({
        status: 'online',
        last_heartbeat: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .eq('id', id);
    res.sendStatus(200);
  } catch (err) {
    console.error('âŒ Erro no heartbeat:', err.message);
    res.sendStatus(500);
  }
});

app.get('/api/stats/summary', authMiddleware, async (req, res) => {
  try {
    const { data: users } = await supabase.from('users').select('id', { count: 'exact' });
    const { data: activeSessions } = await supabase.from('hotspot_sessions').select('id', { count: 'exact' }).eq('status', 'active');
    const { data: payments } = await supabase.from('payments').select('amount').eq('status', 'approved');
    
    const totalRevenue = (payments || []).reduce((sum, p) => sum + (Number(p.amount) || 0), 0);
    
    res.json({
      total_users: users?.length || 0,
      active_sessions: activeSessions?.length || 0,
      total_revenue: totalRevenue,
      online_pops: 1 // Mock ou buscar de pops ativos
    });
  } catch (err) {
    console.error('❌ Erro ao buscar sumário:', err.message);
    res.status(500).json({ error: 'Erro ao buscar estatísticas' });
  }
});

// Estatísticas de usuários por hora (Dashboard)
app.get('/api/stats/users-per-hour', authMiddleware, async (req, res) => {
  try {
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const { data: sessions, error } = await supabase
      .from('hotspot_sessions')
      .select('created_at')
      .gte('created_at', last24h);

    if (error) throw error;

    const hourlyData = new Array(24).fill(0);
    const now = new Date();

    sessions.forEach(session => {
      const sessionDate = new Date(session.created_at);
      const hourDiff = Math.floor((now - sessionDate) / (1000 * 60 * 60));
      if (hourDiff >= 0 && hourDiff < 24) {
        const hour = sessionDate.getHours();
        hourlyData[hour]++;
      }
    });

    res.json({ data: hourlyData });
  } catch (error) {
    console.error('❌ Erro ao buscar estatísticas reais:', error.message);
    res.status(500).json({ error: 'Erro ao buscar estatísticas por hora' });
  }
});

// Listar sessões ativas (usuários online)
// EstatÃ­sticas de trÃ¡fego total (real quando existir coluna de trÃ¡fego)
app.get('/api/stats/total-traffic', authMiddleware, async (req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const { data: sessions, error } = await supabase
      .from('hotspot_sessions')
      .select('*')
      .gte('created_at', since);

    if (error) throw error;

    let inBytes = 0;
    let outBytes = 0;

    (sessions || []).forEach(s => {
      if (typeof s.bytes_in === 'number') inBytes += s.bytes_in;
      if (typeof s.bytes_out === 'number') outBytes += s.bytes_out;
      if (typeof s.rx_bytes === 'number') inBytes += s.rx_bytes;
      if (typeof s.tx_bytes === 'number') outBytes += s.tx_bytes;
    });

    res.json({
      since,
      total_bytes_in: inBytes,
      total_bytes_out: outBytes,
      total_bytes: inBytes + outBytes
    });
  } catch (err) {
    console.error('âŒ Erro ao buscar trÃ¡fego total:', err.message);
    res.status(500).json({ error: 'Erro ao buscar trÃ¡fego total' });
  }
});

app.get('/api/sessions/active', authMiddleware, async (req, res) => {
  try {
    const now = new Date().toISOString();
    const { data, error } = await supabase
      .from('hotspot_sessions')
      .select('*')
      .eq('status', 'active')
      .gt('expires_at', now);
    
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('❌ Erro ao listar sessões ativas:', err.message);
    res.status(500).json({ error: 'Erro ao listar sessões ativas' });
  }
});

// ============================================================
// 📂 ROTAS DE BACKUP
// ============================================================

app.get('/api/backup', authMiddleware, async (req, res) => {
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);
    const files = fs.readdirSync(BACKUP_DIR);
    res.json(files.map(f => ({ name: f, size: fs.statSync(path.join(BACKUP_DIR, f)).size, date: fs.statSync(path.join(BACKUP_DIR, f)).mtime })));
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar backups' });
  }
});

app.post('/api/backup/create', authMiddleware, async (req, res) => {
  try {
    const filename = `backup_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    const tables = ['users', 'plans', 'vouchers', 'payments', 'pops', 'admins', 'settings'];
    const backupData = {};
    
    for (const table of tables) {
      const { data } = await supabase.from(table).select('*');
      backupData[table] = data || [];
    }
    
    fs.writeFileSync(path.join(BACKUP_DIR, filename), JSON.stringify(backupData, null, 2));
    res.json({ message: 'Backup criado com sucesso', filename });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao criar backup' });
  }
});

// ============================================================
// 🏥 HEALTH CHECK
// ============================================================

app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: '4.0.0',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    mikrotik_api: !!RouterOSAPI
  });
});

// ============================================================
// 📊 ESTATÍSTICAS E DASHBOARD
// ============================================================

// Nota: Rotas de estatísticas e POPs já definidas anteriormente no arquivo.
// Removendo duplicações para evitar conflitos.

// ============================================================
// ⚙️ CONFIGURAÇÕES DE CAMPOS DE CADASTRO
// ============================================================

app.get('/api/settings/fields', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('value').eq('key', 'registration_fields').single();
    if (error && error.code !== 'PGRST116') throw error;
    
    const defaultFields = [
      { field: 'name', label: 'Nome Completo', enabled: true, required: true },
      { field: 'email', label: 'E-mail', enabled: true, required: true },
      { field: 'phone', label: 'Telefone/WhatsApp', enabled: true, required: true },
      { field: 'cpf', label: 'CPF', enabled: false, required: false },
      { field: 'birth_date', label: 'Data de Nascimento', enabled: false, required: false },
      { field: 'gender', label: 'Gênero', enabled: false, required: false }
    ];

    res.json(data ? data.value : defaultFields);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/settings/fields', authMiddleware, async (req, res) => {
  try {
    const fields = req.body;
    const { error } = await supabase.from('settings').upsert({
      key: 'registration_fields',
      value: fields,
      updated_at: new Date().toISOString()
    }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ⚙️ CONFIGURAÇÕES DO SISTEMA (SETTINGS)
// ============================================================

// Buscar configurações gerais
// Buscar configuraÃ§Ãµes consolidadas (compat com HTMLs)
app.get('/api/settings', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('value').eq('key', 'system').maybeSingle();
    if (error) throw error;
    res.json(data?.value || {});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Salvar configuraÃ§Ãµes consolidadas (compat com HTMLs)
app.put('/api/settings', authMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('settings').upsert({
      key: 'system',
      value: req.body,
      updated_at: new Date().toISOString()
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Aliases legado PT (configuraÃ§Ãµes)
app.get('/api/configuracoes', authMiddleware, (req, res) => {
  req.url = '/api/settings';
  return app._router.handle(req, res);
});

app.post('/api/configuracoes', authMiddleware, (req, res) => {
  req.url = '/api/settings';
  req.method = 'PUT';
  return app._router.handle(req, res);
});

app.get('/api/configuracoes/sistema', authMiddleware, (req, res) => {
  req.url = '/api/settings/system';
  return app._router.handle(req, res);
});

app.post('/api/configuracoes/sistema', authMiddleware, (req, res) => {
  req.url = '/api/settings/system';
  req.method = 'PUT';
  return app._router.handle(req, res);
});

app.get('/api/configuracoes/pagamento', authMiddleware, (req, res) => {
  req.url = '/api/settings/payment';
  return app._router.handle(req, res);
});

app.post('/api/configuracoes/pagamento', authMiddleware, (req, res) => {
  req.url = '/api/settings/payment';
  req.method = 'PUT';
  return app._router.handle(req, res);
});

app.get('/api/configuracoes/campos', authMiddleware, (req, res) => {
  req.url = '/api/settings/fields';
  return app._router.handle(req, res);
});

app.post('/api/configuracoes/campos', authMiddleware, (req, res) => {
  req.url = '/api/settings/fields';
  req.method = 'PUT';
  return app._router.handle(req, res);
});

app.get('/api/settings/system', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('value').eq('key', 'system').maybeSingle();
    if (error) throw error;
    res.json(data?.value || {});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Salvar configurações gerais
app.put('/api/settings/system', authMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('settings').upsert({
      key: 'system',
      value: req.body,
      updated_at: new Date().toISOString()
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Buscar configurações de pagamento
app.get('/api/settings/payment', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('value').eq('key', 'payment').maybeSingle();
    if (error) throw error;
    res.json(data?.value || {});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Salvar configurações de pagamento
app.put('/api/settings/payment', authMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('settings').upsert({
      key: 'payment',
      value: req.body,
      updated_at: new Date().toISOString()
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Buscar configurações de teste grátis
// Buscar configuraÃ§Ãµes de integraÃ§Ãµes
app.get('/api/settings/integrations', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('value').eq('key', 'integrations').maybeSingle();
    if (error) throw error;
    res.json(data?.value || {});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Salvar configuraÃ§Ãµes de integraÃ§Ãµes
app.put('/api/settings/integrations', authMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('settings').upsert({
      key: 'integrations',
      value: req.body,
      updated_at: new Date().toISOString()
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/settings/free_trial', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('value').eq('key', 'free_trial').maybeSingle();
    if (error) throw error;
    res.json(data?.value || {});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Salvar configurações de teste grátis
app.put('/api/settings/free_trial', authMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('settings').upsert({
      key: 'free_trial',
      value: req.body,
      updated_at: new Date().toISOString()
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// 👤 ADMINS
// ============================================================

app.post('/api/admins', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    const { data, error } = await supabase.from('admins').insert([{
      username, email, password: hashedPassword, role: 'admin'
    }]).select();
    if (error) throw error;
    res.status(201).json({ id: data[0].id, success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// 🪝 WEBHOOKS
// ============================================================

// Webhook do Mercado Pago (Público)
// Aliases legado
app.post('/api/mercado-pago/webhook', (req, res) => {
  req.url = '/api/webhooks/mercadopago';
  return app._router.handle(req, res);
});

app.post('/api/webhook/pagamento', (req, res) => {
  req.url = '/api/webhooks/mercadopago';
  return app._router.handle(req, res);
});

app.post('/api/webhooks/mercadopago', async (req, res) => {
  try {
    const { action, data, type } = req.body;
    
    // Mercado Pago envia notificações de diferentes tipos, focamos em 'payment'
    if (type === 'payment' || action === 'payment.created' || action === 'payment.updated') {
      const paymentId = data?.id || req.query['data.id'];
      if (!paymentId) return res.status(200).send('OK');

      const MP_TOKEN = process.env.MERCADOPAGO_ACCESS_TOKEN || process.env.MP_ACCESS_TOKEN;
      
      // Buscar detalhes do pagamento no Mercado Pago
      const mpResponse = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
        headers: { 'Authorization': `Bearer ${MP_TOKEN}` }
      });
      
      if (!mpResponse.ok) throw new Error('Falha ao buscar pagamento no Mercado Pago');
      const mpData = await mpResponse.json();

      if (mpData.status === 'approved') {
        // 1. Buscar o registro de pagamento no nosso banco
        const { data: payment, error: payError } = await supabase
          .from('payments')
          .select('*')
          .eq('mercado_pago_id', String(paymentId))
          .maybeSingle();

        if (payError) throw payError;
        
        if (payment && payment.status !== 'approved') {
          // 2. Atualizar status para aprovado
          await supabase.from('payments').update({
            status: 'approved',
            approved_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }).eq('id', payment.id);

          // 3. Liberar acesso no MikroTik/RADIUS
          // Buscamos a duração do plano
          const { data: plan } = await supabase.from('plans').select('*').eq('name', payment.plan_name).maybeSingle();
          const durationMinutes = (plan?.duration_days || 1) * 24 * 60;
          
          await authorizeAccess(
            payment.user_mac, 
            '192.168.32.1', 
            null, null, null, 
            durationMinutes, 
            plan?.speed_mbps || 10, 
            payment.plan_name
          );

          // 4. Registrar sessão
          await supabase.from('hotspot_sessions').insert({
            user_mac: payment.user_mac,
            plan_name: payment.plan_name,
            status: 'active',
            expires_at: new Date(Date.now() + durationMinutes * 60000).toISOString(),
            created_at: new Date().toISOString()
          });

          // 5. Disparar webhooks internos
          const { data: internalWebhooks } = await supabase.from('webhooks').select('*').eq('active', true).eq('event', 'payment.confirmed');
          for (const wh of internalWebhooks || []) {
            fetch(wh.url, {
              method: wh.method || 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ event: 'payment.confirmed', payment_id: payment.id, mac: payment.user_mac })
            }).catch(err => console.error(`❌ Erro ao disparar webhook ${wh.name}:`, err.message));
          }

          await registerSystemLog('info', 'mercadopago', `Pagamento aprovado e acesso liberado: ${payment.user_mac}`);
        }
      }
    }
    
    res.status(200).send('OK');
  } catch (err) {
    console.error('❌ Erro no Webhook Mercado Pago:', err.message);
    res.status(200).send('OK'); // Sempre retornar 200 para o MP não ficar retransmitindo em loop
  }
});

app.get('/api/webhooks', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('webhooks').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/webhooks', authMiddleware, async (req, res) => {
  try {
    const { name, event, url, method, target, active } = req.body;
    const { data, error } = await supabase.from('webhooks').insert([{
      name, event, url, method, target, active
    }]).select();
    if (error) throw error;
    res.status(201).json(data[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Rota de edição via POST (conforme frontend webhooks.html)
app.post('/api/webhooks/:id', authMiddleware, async (req, res) => {
  try {
    const { name, event, url, method, target, active } = req.body;
    const { data, error } = await supabase.from('webhooks').update({
      name, event, url, method, target, active
    }).eq('id', req.params.id).select();
    if (error) throw error;
    res.json(data[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/webhooks/:id', authMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('webhooks').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Alias legado PT
app.post('/api/webhooks/:id/testar', authMiddleware, (req, res) => {
  req.url = `/api/webhooks/${req.params.id}/test`;
  return app._router.handle(req, res);
});

app.post('/api/webhooks/:id/test', authMiddleware, async (req, res) => {
  try {
    const { data: webhook } = await supabase.from('webhooks').select('*').eq('id', req.params.id).single();
    if (!webhook) return res.status(404).json({ error: 'Webhook não encontrado' });
    
    // Simulação de disparo
    console.log(`[TEST] Disparando webhook ${webhook.name} para ${webhook.url}`);
    res.json({ success: true, message: 'Teste disparado com sucesso' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// 📣 CAMPANHAS
// ============================================================

app.get('/api/campaigns', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('campaigns').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/campaigns', authMiddleware, async (req, res) => {
  try {
    const { name, description, coupon_code, status, gender, min_age, max_age, starts_at, ends_at } = req.body;
    const { data, error } = await supabase.from('campaigns').insert([{
      name, description, coupon_code, status, gender, min_age, max_age, starts_at, ends_at
    }]).select();
    if (error) throw error;
    res.status(201).json(data[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/campaigns/:id', authMiddleware, async (req, res) => {
  try {
    const { name, description, coupon_code, status, gender, min_age, max_age, starts_at, ends_at } = req.body;
    const { data, error } = await supabase.from('campaigns').update({
      name, description, coupon_code, status, gender, min_age, max_age, starts_at, ends_at
    }).eq('id', req.params.id).select();
    if (error) throw error;
    res.json(data[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/campaigns/:id', authMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('campaigns').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// 📜 LOGS DE AUDITORIA
// ============================================================

app.get('/api/audit-logs', authMiddleware, async (req, res) => {
  try {
    const { user, action, start_date, end_date, search } = req.query;
    let query = supabase.from('audit_logs').select('*').order('created_at', { ascending: false });

    if (user) query = query.ilike('username', `%${user}%`);
    if (action) query = query.eq('type', action);
    if (start_date) query = query.gte('created_at', start_date);
    if (end_date) query = query.lte('created_at', end_date);
    if (search) {
      query = query.or(`username.ilike.%${search}%,type.ilike.%${search}%,object.ilike.%${search}%,action.ilike.%${search}%`);
    }

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// 💾 BACKUP
// ============================================================

// ============================================================
// ðŸ“ LOGS DO SISTEMA
// ============================================================

app.get('/api/logs', authMiddleware, async (req, res) => {
  try {
    const { start_date, end_date, search, type } = req.query;
    let query = supabase.from('logs').select('*').order('created_at', { ascending: false }).limit(200);

    if (type) query = query.eq('type', type);
    if (start_date) query = query.gte('created_at', start_date);
    if (end_date) query = query.lte('created_at', end_date);
    if (search) {
      query = query.or(`message.ilike.%${search}%,type.ilike.%${search}%,ip.ilike.%${search}%`);
    }

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Listar backups
app.get('/api/backups', authMiddleware, async (req, res) => {
  try {
    if (!fs.existsSync(BACKUP_DIR)) return res.json([]);
    const files = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.endsWith('.json'))
      .map(f => ({
        filename: f,
        size: fs.statSync(path.join(BACKUP_DIR, f)).size,
        created_at: fs.statSync(path.join(BACKUP_DIR, f)).birthtime
      }))
      .sort((a, b) => b.created_at - a.created_at);
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Alias para listar backups (compatibilidade)
app.get('/api/backup/list', authMiddleware, (req, res) => {
  req.url = '/api/backups';
  app._router.handle(req, res);
});

// Download de backup
app.get('/api/backups/download/:filename', authMiddleware, (req, res) => {
  const { filename } = req.params;
  const filePath = path.join(BACKUP_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Arquivo não encontrado' });
  res.download(filePath);
});

// Alias para download de backup (compatibilidade)
app.get('/api/backup/download/:filename', authMiddleware, (req, res) => {
  const { filename } = req.params;
  req.url = `/api/backups/download/${filename}`;
  app._router.handle(req, res);
});

app.post('/api/backup/create', authMiddleware, async (req, res) => {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `backup-${timestamp}.json`;
    const filePath = path.join(BACKUP_DIR, filename);

    // Backup simples das tabelas principais
    const tables = ['users', 'vouchers', 'payments', 'pops', 'plans', 'settings', 'admins', 'webhooks', 'campaigns'];
    const backupData = {};

    for (const table of tables) {
      const { data } = await supabase.from(table).select('*');
      backupData[table] = data || [];
    }

    fs.writeFileSync(filePath, JSON.stringify(backupData, null, 2));
    
    await registerAuditLog(req.user.username, 'backup', 'sistema', `Backup criado: ${filename}`);
    
    res.json({ success: true, filename });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// 🔄 ALIAS E ROTAS DE COMPATIBILIDADE
// ============================================================

// Alias para portal público
app.get('/api/portal/plans', async (req, res) => {
  const { data, error } = await supabase.from('plans').select('*').eq('active', true).order('price');
  if (error) return res.status(500).json({ error: 'Erro ao listar planos' });
  res.json(data || []);
});

app.post('/api/portal/create-pix', async (req, res) => {
  // Encaminha para a rota oficial de geração de PIX
  req.url = '/api/payments/generate-pix';
  app._router.handle(req, res);
});

app.get('/api/portal/check-payment/:id', async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase.from('payments').select('*').eq('id', id).single();
  if (error || !data) return res.status(404).json({ error: 'Pagamento não encontrado' });
  res.json(data);
});

app.post('/api/portal/login', async (req, res) => {
  try {
    const { identifier, password, mac_address } = req.body;
    const { data: user, error } = await supabase.from('users').select('*')
      .or(`username.eq.${identifier},email.eq.${identifier},cpf.eq.${identifier},phone.eq.${identifier}`)
      .single();
    if (error || !user) return res.status(401).json({ error: 'Usuário não encontrado' });

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    if (user.password !== hashedPassword && user.password !== password) return res.status(401).json({ error: 'Senha incorreta' });

    if (mac_address) await supabase.from('users').update({ mac_address, updated_at: new Date().toISOString() }).eq('id', user.id);
    
    const status = (user.status === 'active' && user.expires_at && new Date(user.expires_at) > new Date()) ? 'active' : 'expired';
    res.json({ user_id: user.id, username: user.username, status, plan_id: user.plan_id });
  } catch (err) {
    res.status(500).json({ error: 'Erro no login' });
  }
});

app.post('/api/portal/register', async (req, res) => {
  try {
    const { name, cpf, phone, password, mac_address } = req.body;
    const username = cpf || phone || name.toLowerCase().replace(/\s+/g, '.');
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    
    const { data, error } = await supabase.from('users').insert({
      username, name, cpf: cpf || '', phone: phone || '', password: hashedPassword,
      mac_address: mac_address || '', status: 'pending', created_at: new Date().toISOString()
    }).select().single();
    
    if (error) throw error;
    res.status(201).json({ user_id: data.id, username: data.username });
  } catch (err) {
    res.status(500).json({ error: 'Erro no cadastro' });
  }
});

app.post('/api/portal/voucher', async (req, res) => {
  // Encaminha para a rota oficial de validação de voucher
  req.url = '/api/vouchers/validate';
  app._router.handle(req, res);
});

app.get('/api/portal/status', async (req, res) => {
  try {
    const { mac, mac_address } = req.query;
    const targetMac = mac || mac_address;
    if (!targetMac) return res.json({ connected: false });
    
    const { data: session } = await supabase.from('hotspot_sessions').select('*').eq('mac_address', targetMac).eq('status', 'active').maybeSingle();
    if (session && new Date(session.expires_at) > new Date()) {
      return res.json({ connected: true, expires_at: session.expires_at });
    }
    res.json({ connected: false });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao verificar status' });
  }
});

// Rota pública para verificar status de pagamento por MAC (usada pelo portal)
app.get('/api/portal/payment-status', async (req, res) => {
  try {
    const { mac_address } = req.query;
    if (!mac_address) return res.status(400).json({ error: 'MAC é obrigatório' });

    const { data, error } = await supabase.from('payments')
      .select('*')
      .eq('user_mac', mac_address)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error) throw error;
    res.json(data || { status: 'not_found' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao verificar status de pagamento' });
  }
});

// Rota de compatibilidade para o portal público que chama /api/payments sem token
app.get('/api/payments', async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const { mac_address } = req.query;

  // Se NÃO tem token e tem mac_address, redireciona para a rota pública do portal
  if (!authHeader && mac_address) {
    req.url = '/api/portal/payment-status';
    return app._router.handle(req, res);
  }

  // Caso contrário, segue para o middleware de autenticação e rota admin
  next();
});

// Rota de Teste Grátis (chamada pelo frontend)
app.post('/api/users/test-access', async (req, res) => {
  try {
    const { mac_address, duration_minutes = 15 } = req.body;
    if (!mac_address) return res.status(400).json({ error: 'MAC é obrigatório' });
    
    const result = await authorizeAccess(mac_address, '192.168.32.1', null, null, null, duration_minutes, 5, 'free_trial');
    if (result.success) {
      await supabase.from('hotspot_sessions').insert({
        mac_address, status: 'active', expires_at: new Date(Date.now() + duration_minutes * 60000).toISOString(),
        created_at: new Date().toISOString()
      });
      return res.json({ message: 'Acesso liberado' });
    }
    res.status(500).json({ error: 'Erro ao liberar acesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// ============================================================
// 👤 GESTÃO DE ADMINISTRADORES (ADMINS)
// ============================================================

// Listar todos os administradores
// Free trial (pÃºblico) - 1 uso por MAC
app.post('/api/free-trial', async (req, res) => {
  try {
    const { mac_address } = req.body || {};
    if (!mac_address) return res.status(400).json({ success: false, message: 'MAC Ã© obrigatÃ³rio' });

    let alreadyUsed = false;
    try {
      const { data: ft, error: ftErr } = await supabase
        .from('free_trials')
        .select('id')
        .eq('mac_address', mac_address)
        .maybeSingle();
      if (ftErr) throw ftErr;
      if (ft) alreadyUsed = true;
    } catch (_e) {
      // Se a tabela nÃ£o existir ainda, nÃ£o bloqueia.
    }

    if (alreadyUsed) return res.json({ success: false, message: 'Teste grÃ¡tis jÃ¡ utilizado para este MAC' });

    const duration = 15;
    const expiresAt = new Date(Date.now() + duration * 60000).toISOString();
    const result = await authorizeAccess(mac_address, '192.168.32.1', null, null, null, duration, 5, 'free_trial');

    if (!result.success) return res.status(500).json({ success: false, message: 'Erro ao liberar acesso' });

    await supabase.from('hotspot_sessions').insert({
      mac_address,
      status: 'active',
      expires_at: expiresAt,
      created_at: new Date().toISOString()
    });

    try {
      await supabase.from('free_trials').insert({ mac_address, used_at: new Date().toISOString() });
    } catch (_e) {
      // ignora se nÃ£o existir
    }

    res.json({ success: true, expires_at: expiresAt, message: 'Acesso liberado' });
  } catch (_err) {
    res.status(500).json({ success: false, message: 'Erro interno' });
  }
});

// Validar acesso (pÃºblico)
app.post('/api/access/validate', async (req, res) => {
  try {
    const { mac_address } = req.body || {};
    if (!mac_address) return res.status(400).json({ authorized: false });

    const now = new Date().toISOString();
    const { data: session, error } = await supabase
      .from('hotspot_sessions')
      .select('*')
      .eq('mac_address', mac_address)
      .eq('status', 'active')
      .gt('expires_at', now)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error) throw error;
    if (!session) return res.json({ authorized: false });

    res.json({ authorized: true, expires_at: session.expires_at, session });
  } catch (_err) {
    res.status(500).json({ authorized: false });
  }
});

// Aliases (legado PT)
app.post('/api/liberar-teste', (req, res) => {
  req.url = '/api/users/test-access';
  return app._router.handle(req, res);
});

app.post('/api/validar-acesso', (req, res) => {
  req.url = '/api/access/validate';
  return app._router.handle(req, res);
});

app.post('/api/validate-access', (req, res) => {
  req.url = '/api/access/validate';
  return app._router.handle(req, res);
});

app.post('/api/auth/check', (req, res) => {
  req.url = '/api/access/validate';
  return app._router.handle(req, res);
});

app.get('/api/admins', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('admins')
      .select('id, username, email, role, created_at')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar administradores' });
  }
});

// Criar novo administrador
app.post('/api/admins', authMiddleware, async (req, res) => {
  try {
    const { username, email, password, role = 'admin' } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });
    }

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    
    const { data, error } = await supabase
      .from('admins')
      .insert([{ 
        username, 
        email, 
        password: hashedPassword, 
        role,
        created_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (error) throw error;

    await registerAuditLog(req.user.username, 'create', 'admin', `Criou administrador: ${username}`, req.ip, req.headers['user-agent']);
    
    res.status(201).json({ success: true, id: data.id });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao criar administrador' });
  }
});

// Atualizar administrador
app.put('/api/admins/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, email, password, role } = req.body;
    
    const updateData = {};
    if (username) updateData.username = username;
    if (email) updateData.email = email;
    if (role) updateData.role = role;
    if (password) {
      updateData.password = crypto.createHash('sha256').update(password).digest('hex');
    }

    const { error } = await supabase
      .from('admins')
      .update(updateData)
      .eq('id', id);

    if (error) throw error;

    await registerAuditLog(req.user.username, 'update', 'admin', `Atualizou administrador ID: ${id}`, req.ip, req.headers['user-agent']);
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao atualizar administrador' });
  }
});

// Deletar administrador
app.delete('/api/admins/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Impedir que o admin delete a si mesmo
    if (id == req.user.id) {
      return res.status(400).json({ error: 'Você não pode excluir seu próprio usuário' });
    }

    const { error } = await supabase
      .from('admins')
      .delete()
      .eq('id', id);

    if (error) throw error;

    await registerAuditLog(req.user.username, 'delete', 'admin', `Excluiu administrador ID: ${id}`, req.ip, req.headers['user-agent']);
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao deletar administrador' });
  }
});

// ============================================================
// 🚀 INICIAR SERVIDOR
// ============================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║  🚀 MS TELECOM - HOTSPOT SYSTEM API                         ║
║  ✅ Servidor rodando em: http://localhost:${PORT}              ║
║  ✅ Ambiente: ${process.env.NODE_ENV || 'production'}                      ║
║  ✅ Padrão: Código EN, Comentários PT-BR                     ║
║  ✅ Endpoints: /api/users, /api/plans, /api/payments         ║
║  ✅ Tabelas: users, plans, payments, pops                    ║
║  ✅ Integração: MikroTik API, Mercado Pago, RADIUS           ║
║  ✅ Deploy Automático: GitHub Actions → VPS                  ║
║  ✅ CRON: Remoção automática de acessos expirados            ║
╚══════════════════════════════════════════════════════════════╝
  `);
});
