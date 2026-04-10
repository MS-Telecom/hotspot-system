// ============================================================
// 🚀 HOTSPOT SYSTEM - MS TELECOM FIBER CONNECTIONS
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
    const { mac } = req.query;
    if (!mac) return res.json({ connected: false });
    
    const { data: session } = await supabase.from('hotspot_sessions').select('*').eq('mac_address', mac).eq('status', 'active').maybeSingle();
    if (session && new Date(session.expires_at) > new Date()) {
      return res.json({ connected: true, expires_at: session.expires_at });
    }
    res.json({ connected: false });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao verificar status' });
  }
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
