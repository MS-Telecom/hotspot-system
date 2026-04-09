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

// CORS configurado para aceitar requisições do frontend no Vercel
app.use(cors({
    origin: [
        'https://hotspot-system.vercel.app',
        'http://localhost:3000'
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
    const { data: expiredSessions, error } = await supabase
      .from('hotspot_sessions')
      .select('*')
      .lt('expires_at', now)
      .eq('status', 'active');

    if (error || !expiredSessions || expiredSessions.length === 0) return;

    for (const session of expiredSessions) {
      const mac = session.mac_address;
      if (mac && mac !== 'pending') {
        await revokeAccess(mac, session.pop_ip || '192.168.32.1', null, null, session.pop_id || null);
        // Limpar RADIUS: remover do radius_replies e radreply
        await supabase.from('radius_replies').delete().eq('username', mac).catch(() => {});
        await supabase.from('radreply').delete().eq('username', mac).catch(() => {});
      }
      await supabase.from('hotspot_sessions').update({ status: 'expired', updated_at: new Date().toISOString() }).eq('id', session.id);
    }

    // Também limpar users expirados
    const { data: expiredUsers } = await supabase
      .from('users')
      .select('id, mac_address, status, expires_at')
      .eq('status', 'active')
      .lt('expires_at', now);

    if (expiredUsers && expiredUsers.length > 0) {
      for (const user of expiredUsers) {
        await supabase.from('users').update({ status: 'expired', updated_at: new Date().toISOString() }).eq('id', user.id);
        if (user.mac_address) {
          await supabase.from('radius_replies').delete().eq('username', user.mac_address).catch(() => {});
          await supabase.from('radreply').delete().eq('username', user.mac_address).catch(() => {});
        }
      }
      console.log(`[CRON] ${expiredUsers.length} usuários expirados atualizados`);
    }

    console.log(`[CRON] ${expiredSessions.length} sessões expiradas removidas`);
  } catch (error) {
    console.error('[CRON] Erro na limpeza de expiração:', error.message);
  }
}, 60000);

// ============================================================
// 🔐 ROTAS DE AUTENTICAÇÃO
// ============================================================

// Login do administrador
app.post('/api/auth/login', async (req, res) => {
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

    // Comparação de senha (hash SHA-256 ou texto plano)
    let passwordMatch = false;
    let needsHashUpgrade = false;
    if (admin.password && admin.password.length === 64) {
      const sha256 = crypto.createHash('sha256').update(password).digest('hex');
      passwordMatch = admin.password === sha256;
    } else {
      passwordMatch = admin.password === password;
      if (passwordMatch) needsHashUpgrade = true;
    }

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Auto-hash: se a senha estava em texto plano, converter para SHA-256
    if (needsHashUpgrade) {
      const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
      await supabase.from('admins').update({ password: hashedPassword }).eq('id', admin.id).catch(() => {});
      console.log(`[AUTH] Senha do admin '${admin.username}' convertida para hash SHA-256`);
    }

    const token = jwt.sign(
      { id: admin.id, username: admin.username, role: admin.role || 'admin' },
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
    console.error('❌ Erro no login:', err.message);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Logout
app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  await registerAuditLog(req.user.username, 'auth', 'admin', 'logout', req.ip, req.headers['user-agent']);
  res.json({ message: 'Logout realizado com sucesso' });
});

// Atualizar perfil do admin
app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const { username, email, current_password, new_password } = req.body;
    const updateData = { updated_at: new Date().toISOString() };

    // Validar senha atual se estiver tentando mudar a senha
    if (new_password) {
      if (!current_password) {
        return res.status(400).json({ error: 'Senha atual é obrigatória para definir uma nova senha' });
      }

      const { data: admin, error: adminError } = await supabase.from('admins').select('password').eq('id', req.user.id).single();
      if (adminError || !admin) return res.status(404).json({ error: 'Admin não encontrado' });

      const hashedCurrent = crypto.createHash('sha256').update(current_password).digest('hex');
      if (hashedCurrent !== admin.password) {
        return res.status(401).json({ error: 'Senha atual incorreta' });
      }

      updateData.password = crypto.createHash('sha256').update(new_password).digest('hex');
    }

    if (email) updateData.email = email;
    if (username) updateData.username = username;

    const { error } = await supabase.from('admins').update(updateData).eq('id', req.user.id);
    if (error) throw error;

    await registerAuditLog(req.user.username, 'update', 'admin', 'Perfil atualizado', req.ip, req.headers['user-agent']);
    res.json({ message: 'Perfil atualizado com sucesso' });
  } catch (err) {
    console.error('❌ Erro ao atualizar perfil:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar perfil' });
  }
});

// Aliases de compatibilidade com o frontend
app.post('/api/login', (req, res) => { req.url = '/api/auth/login'; app.handle(req, res); });
app.post('/api/logout', authMiddleware, (req, res) => { req.url = '/api/auth/logout'; app.handle(req, res); });
app.put('/api/update-profile', authMiddleware, (req, res) => {
  req.url = '/api/profile'; app.handle(req, res);
});
app.post('/api/update-profile', authMiddleware, (req, res) => {
  req.method = 'PUT'; req.url = '/api/profile'; app.handle(req, res);
});

// ============================================================
// 👥 ROTAS DE USUÁRIOS (CLIENTES)
// ============================================================

// Listar usuários
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*').order('created_at', { ascending: false });
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

    // Buscar plano
    const { data: plan, error: planError } = await supabase
      .from('plans')
      .select('*')
      .eq('id', plan_id)
      .single();

    if (planError || !plan) {
      return res.status(400).json({ error: 'Plano não encontrado' });
    }

    // Definir duração
    const days = duration_days || plan.duration_days || 30;

    const expiresAt = new Date(Date.now() + Number(days) * 24 * 60 * 60 * 1000).toISOString();

    const { data, error } = await supabase
      .from('users')
      .update({
        plan_id: plan_id,
        plan_name: plan.name,
        status: 'active',
        expires_at: expiresAt,
        updated_at: new Date().toISOString()
      })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    await registerAuditLog(
      req.user.username,
      'update',
      'user',
      `Plano renovado: ${id}`,
      req.ip,
      req.headers['user-agent']
    );

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

    const { data, error } = await supabase
      .from('users')
      .update({
        status: 'blocked',
        updated_at: new Date().toISOString()
      })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    await registerAuditLog(
      req.user.username,
      'update',
      'user',
      `Usuário bloqueado: ${id}`,
      req.ip,
      req.headers['user-agent']
    );

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

    const { data, error } = await supabase
      .from('users')
      .update({
        status: 'active',
        updated_at: new Date().toISOString()
      })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    await registerAuditLog(
      req.user.username,
      'update',
      'user',
      `Usuário desbloqueado: ${id}`,
      req.ip,
      req.headers['user-agent']
    );

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
    const { data, error } = await supabase.from('users')
      .update({ is_vip, updated_at: new Date().toISOString() })
      .eq('id', id).select().single();

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
    
    // Buscar dados básicos do usuário
    const { data: user, error: userError } = await supabase.from('users').select('*').eq('id', id).maybeSingle();
    if (userError || !user) return res.status(404).json({ error: 'Usuário não encontrado' });

    // Calcular total_spent (soma dos pagamentos aprovados)
    const { data: payments } = await supabase.from('payments').select('amount').eq('user_id', id).eq('status', 'approved');
    const totalSpent = (payments || []).reduce((sum, p) => sum + (Number(p.amount) || 0), 0);

    // Buscar last_access (última sessão)
    const { data: lastSession } = await supabase.from('hotspot_sessions').select('created_at').eq('user_id', id).order('created_at', { ascending: false }).limit(1).maybeSingle();

    res.json({
      ...user,
      total_spent: totalSpent,
      last_access: lastSession?.created_at || user.last_seen_at || null
    });
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
      u.name || '',
      u.username || '',
      u.mac_address || '',
      u.phone || '',
      u.cpf || '',
      u.email || '',
      u.plan_name || '',
      u.status || '',
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

// Detalhes do plano com contagem de assinantes
app.get('/api/plans/:id/details', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: plan, error } = await supabase.from('plans').select('*').eq('id', id).maybeSingle();
    if (error || !plan) return res.status(404).json({ error: 'Plano não encontrado' });

    const { count: subscribers } = await supabase.from('users').select('id', { count: 'exact', head: true }).eq('plan_id', id).eq('status', 'active');

    return res.json({
      ...plan,
      active_subscribers: subscribers || 0,
      monthly_revenue: (subscribers || 0) * parseNumber(plan.price)
    });
  } catch (err) {
    console.error('❌ Erro ao buscar detalhes do plano:', err.message);
    res.status(500).json({ error: 'Erro ao buscar detalhes do plano' });
  }
});

// ============================================================
// 💳 ROTAS DE PAGAMENTOS
// ============================================================

// Listar pagamentos
app.get('/api/payments', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('payments')
      .select(`
        *,
        users:user_id (name, mac_address),
        pops:pop_id (name)
      `)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const formattedData = (data || []).map(payment => ({
      ...payment,
      user_name: payment.users?.name || 'N/A',
      mac_address: payment.users?.mac_address || 'N/A',
      pop_name: payment.pops?.name || 'N/A'
    }));

    res.json(formattedData);
  } catch (err) {
    console.error('❌ Erro ao listar pagamentos:', err.message);
    res.status(500).json({ error: 'Erro ao listar pagamentos' });
  }
});

// Criar pagamento
app.post('/api/payments', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('payments').insert(req.body).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    console.error('❌ Erro ao criar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao criar pagamento' });
  }
});

// Atualizar pagamento
app.put('/api/payments/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;

    const { data, error } = await supabase.from('payments').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('❌ Erro ao atualizar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar pagamento' });
  }
});

// Deletar pagamento
app.delete('/api/payments/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('payments').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Pagamento removido' });
  } catch (err) {
    console.error('❌ Erro ao deletar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao deletar pagamento' });
  }
});

// Verificar pagamento por MAC
app.get('/api/check-payment-by-mac', async (req, res) => {
  try {
    const { mac } = req.query;
    if (!mac) return res.status(400).json({ error: 'MAC address é obrigatório' });

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
  } catch (err) {
    console.error('❌ Erro ao verificar pagamento por MAC:', err.message);
    res.status(500).json({ error: 'Erro ao verificar pagamento' });
  }
});

// Gerar PIX via Mercado Pago
app.post('/api/payments/generate-pix', async (req, res) => {
  try {
    const { payment_id, amount, description, email, cpf, name, plan_id, user_mac } = req.body;

    if (!amount || !description) {
      return res.status(400).json({ error: 'Valor e descrição são obrigatórios' });
    }

    const MP_TOKEN = process.env.MERCADOPAGO_ACCESS_TOKEN || process.env.MP_ACCESS_TOKEN;
    if (!MP_TOKEN) {
      return res.status(500).json({ error: 'Token do Mercado Pago não configurado' });
    }

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
          identification: {
            type: 'CPF',
            number: cpf || '00000000000'
          }
        },
        external_reference: externalReference
      })
    });

    const mpData = await mpResponse.json();

    if (!mpResponse.ok) {
      return res.status(400).json({
        error: 'Erro ao gerar pagamento PIX',
        details: mpData
      });
    }

    const pixCopyPaste = mpData.point_of_interaction?.transaction_data?.qr_code || '';
    const qrCodeBase64 = mpData.point_of_interaction?.transaction_data?.qr_code_base64 || '';

    let payment;
    let error;

    if (payment_id) {
      const result = await supabase
        .from('payments')
        .update({
          user_mac: user_mac || null,
          plan_id: plan_id || null,
          amount: parseFloat(amount),
          description,
          status: 'pending',
          payment_method: 'pix',
          mercado_pago_id: String(mpData.id),
          pix_copy_paste: pixCopyPaste,
          qr_code: qrCodeBase64,
          external_reference: externalReference,
          expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('id', payment_id)
        .select()
        .single();

      payment = result.data;
      error = result.error;
    } else {
      const result = await supabase
        .from('payments')
        .insert({
          user_mac: user_mac || null,
          plan_id: plan_id || null,
          amount: parseFloat(amount),
          description,
          status: 'pending',
          payment_method: 'pix',
          mercado_pago_id: String(mpData.id),
          pix_copy_paste: pixCopyPaste,
          qr_code: qrCodeBase64,
          external_reference: externalReference,
          expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString()
        })
        .select()
        .single();

      payment = result.data;
      error = result.error;
    }

    if (error) throw error;

    res.json({
      id: payment.id,
      mercado_pago_id: mpData.id,
      pix_copy_paste: pixCopyPaste,
      qr_code: qrCodeBase64,
      external_reference: externalReference,
      status: 'pending',
      amount: parseFloat(amount)
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

// Criar vouchers
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
    console.error('❌ Erro ao criar vouchers:', err.message);
    res.status(500).json({ error: 'Erro ao criar vouchers' });
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
    if (!code) return res.status(400).json({ error: 'Código do voucher é obrigatório' });

    const { data: voucher, error } = await supabase
      .from('vouchers')
      .select('*')
      .eq('code', String(code).toUpperCase())
      .maybeSingle();

    if (error || !voucher) return res.status(404).json({ valid: false, error: 'Voucher não encontrado' });
    if (voucher.status === 'used' || voucher.used === true) return res.status(400).json({ valid: false, error: 'Voucher já utilizado' });
    if (voucher.status === 'expired') return res.status(400).json({ valid: false, error: 'Voucher expirado' });

    await supabase.from('vouchers').update({
      status: 'used', used: true, used_at: new Date().toISOString(),
      mac_address: mac_address || null, updated_at: new Date().toISOString()
    }).eq('id', voucher.id);

    return res.json({ valid: true, voucher_id: voucher.id, plan_name: voucher.plan_name || null });
  } catch (err) {
    console.error('❌ Erro ao validar voucher:', err.message);
    res.status(500).json({ error: 'Erro ao validar voucher' });
  }
});

// ============================================================
// 📢 ROTAS DE CAMPANHAS
// ============================================================

// Listar campanhas
app.get('/api/campaigns', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('campaigns').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('❌ Erro ao listar campanhas:', err.message);
    res.status(500).json({ error: 'Erro ao listar campanhas' });
  }
});

// Criar campanha
app.post('/api/campaigns', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('campaigns').insert(req.body).select().single();
    if (error) throw error;
    await registerAuditLog(req.user.username, 'create', 'campaign', `Campanha criada: ${req.body.name}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('❌ Erro ao criar campanha:', err.message);
    res.status(500).json({ error: 'Erro ao criar campanha' });
  }
});

// Atualizar campanha
app.put('/api/campaigns/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;

    const { data, error } = await supabase.from('campaigns').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('❌ Erro ao atualizar campanha:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar campanha' });
  }
});

// Deletar campanha
app.delete('/api/campaigns/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('campaigns').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Campanha removida' });
  } catch (err) {
    console.error('❌ Erro ao deletar campanha:', err.message);
    res.status(500).json({ error: 'Erro ao deletar campanha' });
  }
});

// ============================================================
// 🔗 ROTAS DE WEBHOOKS
// ============================================================

// Listar webhooks
app.get('/api/webhooks', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('webhooks').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('❌ Erro ao listar webhooks:', err.message);
    res.status(500).json({ error: 'Erro ao listar webhooks' });
  }
});

// Criar webhook
app.post('/api/webhooks', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('webhooks').insert(req.body).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    console.error('❌ Erro ao criar webhook:', err.message);
    res.status(500).json({ error: 'Erro ao criar webhook' });
  }
});

// Testar webhook
app.post('/api/webhooks/:id/test', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: webhook, error } = await supabase.from('webhooks').select('*').eq('id', id).single();
    if (error || !webhook) return res.status(404).json({ error: 'Webhook não encontrado' });

    const response = await fetch(webhook.url, {
      method: webhook.method || 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        event: webhook.event,
        source: 'ms-telecom',
        timestamp: new Date().toISOString()
      })
    });

    await supabase.from('webhooks').update({
      last_execution: new Date().toISOString(),
      total_events: (webhook.total_events || 0) + 1
    }).eq('id', id);

    res.json({ success: true, status: response.status });
  } catch (err) {
    console.error('❌ Erro ao testar webhook:', err.message);
    res.status(500).json({ error: 'Erro ao testar webhook' });
  }
});

// Deletar webhook
app.delete('/api/webhooks/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('webhooks').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Webhook removido' });
  } catch (err) {
    console.error('❌ Erro ao deletar webhook:', err.message);
    res.status(500).json({ error: 'Erro ao deletar webhook' });
  }
});

// Webhook do Mercado Pago
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
        const { data: paymentRecord } = await supabase.from('payments')
          .update({ status: 'approved', updated_at: new Date().toISOString() })
          .eq('mercado_pago_id', String(paymentId))
          .select()
          .single();

        // Ativar plano do usuário automaticamente
        if (paymentRecord && paymentRecord.user_id && paymentRecord.plan_id) {
          const { data: plan } = await supabase.from('plans').select('duration_days, speed_mbps, name').eq('id', paymentRecord.plan_id).single();
          if (plan) {
            const expiresAt = new Date(Date.now() + (plan.duration_days || 30) * 86400000).toISOString();
            await supabase.from('users').update({ status: 'active', plan_id: paymentRecord.plan_id, plan_name: plan.name, expires_at: expiresAt, updated_at: new Date().toISOString() }).eq('id', paymentRecord.user_id);

            // Liberar acesso RADIUS com velocidade do plano
            const { data: user } = await supabase.from('users').select('mac_address').eq('id', paymentRecord.user_id).single();
            if (user && user.mac_address) {
              const durationMinutes = (plan.duration_days || 30) * 24 * 60;
              await authorizeAccess(user.mac_address, '192.168.32.1', null, null, null, durationMinutes, plan.speed_mbps, plan.name);
              console.log(`[WEBHOOK MP] Acesso liberado para ${user.mac_address} - Plano: ${plan.name}`);
            }
          }
        }
      }
    }

    res.json({ received: true });
  } catch (err) {
    console.error('❌ Erro no webhook do Mercado Pago:', err.message);
    res.status(500).json({ error: 'Erro no webhook' });
  }
});

// ============================================================
// 🖥️ ROTAS DE HOTSPOTS / POPS
// ============================================================

// Listar POPs
app.get('/api/pops', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('pops').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    
    const formattedData = (data || []).map(pop => ({
      ...pop,
      active_clients: pop.connected_users || 0,
      last_activity: pop.last_seen_at || null
    }));

    res.json(formattedData);
  } catch (err) {
    console.error('❌ Erro ao listar POPs:', err.message);
    res.status(500).json({ error: 'Erro ao listar POPs' });
  }
});

// Criar POP
app.post('/api/pops', authMiddleware, async (req, res) => {
  try {
    const { name, ip, location } = req.body;
    if (!name) return res.status(400).json({ error: 'Nome do POP é obrigatório' });

    const now = new Date().toISOString();
    const { data, error } = await supabase.from('pops').insert({
      name, ip: ip || null, location: location || null,
      status: 'offline', created_at: now, updated_at: now
    }).select().single();

    if (error) throw error;
    await registerAuditLog(req.user.username, 'create', 'pop', `POP criado: ${name}`, req.ip, req.headers['user-agent']);
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
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;

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
    res.json({ message: 'POP removido' });
  } catch (err) {
    console.error('❌ Erro ao deletar POP:', err.message);
    res.status(500).json({ error: 'Erro ao deletar POP' });
  }
});

// POP Register (auto-registro)
app.post('/api/pops/register', async (req, res) => {
  try {
    const { name, ip, location, unique_id, api_user, api_pass } = req.body;
    if (!name) return res.status(400).json({ error: 'Nome do POP é obrigatório' });

    const popId = unique_id || slugify(name).toUpperCase();
    const now = new Date().toISOString();

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
  } catch (err) {
    console.error('❌ Erro no registro do POP:', err.message);
    res.status(500).json({ error: 'Erro ao registrar POP' });
  }
});

// POP Status
app.get('/api/pops/:id/status', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

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
    if (!pop) return res.status(404).json({ error: 'POP não encontrado' });

    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
    const isOnline = pop.last_seen_at && new Date(pop.last_seen_at) > fiveMinAgo;

    const { data: sessions } = await supabase.from('hotspot_sessions')
      .select('*').eq('pop_id', pop.id).eq('status', 'active');

    return res.json({
      ...pop,
      is_online: isOnline,
      active_sessions: (sessions || []).length,
      sessions: sessions || []
    });
  } catch (err) {
    console.error('❌ Erro ao obter status do POP:', err.message);
    res.status(500).json({ error: 'Erro ao obter status do POP' });
  }
});

// POP Ping/Heartbeat
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
      await supabase.from('pops').update({
        status: 'online', last_seen_at: now,
        connected_users: connected_users ?? 0,
        bandwidth_used: bandwidth_used || '0 Mbps',
        ip: ip || existing.data.ip || null,
        updated_at: now
      }).eq('id', popId);
    } else {
      await supabase.from('pops').insert({
        id: popId, name: name || popId, status: 'online',
        last_seen_at: now, connected_users: connected_users ?? 0,
        bandwidth_used: bandwidth_used || '0 Mbps',
        ip: ip || null, created_at: now, updated_at: now
      });
    }

    return res.json({ status: 'ok', pop_id: popId, timestamp: now });
  } catch (err) {
    console.error('❌ Erro no ping do POP:', err.message);
    res.status(500).json({ error: 'Erro ao processar ping' });
  }
});

// POP Identity
app.post('/api/pop/identity', async (req, res) => {
  try {
    const { pop_id, identity } = req.body;
    if (!pop_id || !identity) return res.status(400).json({ error: 'pop_id e identity são obrigatórios' });

    const updatePayload = {
      real_name: identity,
      last_identity_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    let result = await supabase.from('pops').update(updatePayload).eq('id', pop_id).select();
    if (!result.data || result.data.length === 0) {
      result = await supabase.from('pops').update(updatePayload).eq('unique_id', pop_id).select();
    }
    if (!result.data || result.data.length === 0) {
      result = await supabase.from('pops').update(updatePayload).eq('name', pop_id).select();
    }

    if (result.error) throw result.error;
    return res.json({ success: true, matched: (result.data || []).length });
  } catch (err) {
    console.error('❌ Erro ao salvar identidade do POP:', err.message);
    res.status(500).json({ error: 'Erro ao salvar identidade' });
  }
});

// Gerar script de instalação MikroTik
app.post('/api/gerar-script-mikrotik', authMiddleware, async (req, res) => {
  try {
    const { nome_pop, tipo } = req.body;
    if (!nome_pop) return res.status(400).json({ error: 'nome_pop é obrigatório' });

    const pop_id = `MS-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const apiUser = `API_${pop_id}`;
    const apiPass = generateStrongPassword(12);
    const radiusSecret = generateStrongPassword(18);

    const now = new Date().toISOString();
    const { data: pop, error } = await supabase.from('pops').insert({
      id: pop_id, name: nome_pop, unique_id: pop_id,
      api_user: apiUser, api_pass: apiPass, radius_secret: radiusSecret,
      status: 'offline', created_at: now, updated_at: now
    }).select().single();

    if (error) throw error;

    const script = `
# ============================================
# MS TELECOM - SCRIPT DE INSTALAÇÃO
# POP ID: ${pop_id}
# Nome: ${nome_pop}
# ============================================

/system backup save name=backup_pre_${pop_id}
/export file=config_pre_${pop_id}
:delay 2s

/system identity set name="${nome_pop}"
:delay 500ms

/user add name="${apiUser}" password="${apiPass}" group=full comment="MS-TELECOM-${pop_id}"
:delay 500ms

/interface bridge add name="ms-bridge-${pop_id}" comment="MS-TELECOM-${pop_id}"
:delay 500ms

/ip address add address=192.168.32.1/20 interface="ms-bridge-${pop_id}" network=192.168.32.0 comment="MS-TELECOM-${pop_id}"
:delay 500ms

/ip pool add name="ms-pool-${pop_id}" ranges=192.168.32.10-192.168.47.254 comment="MS-TELECOM-${pop_id}"
/ip dhcp-server add address-pool="ms-pool-${pop_id}" disabled=no interface="ms-bridge-${pop_id}" name="ms-dhcp-${pop_id}" lease-time=24h
/ip dhcp-server network add address=192.168.32.0/20 gateway=192.168.32.1 dns-server=8.8.8.8,1.1.1.1 comment="MS-TELECOM-${pop_id}"
:delay 1s

/ip dhcp-client add interface=ether1 disabled=no comment="MS-TELECOM-${pop_id}"
:delay 500ms

/ip firewall nat add action=masquerade chain=srcnat out-interface=ether1 comment="MS-TELECOM-${pop_id}"
:delay 500ms

/ip dns set allow-remote-requests=yes servers=8.8.8.8,1.1.1.1
:delay 500ms

/radius add address=${RADIUS_SERVER_IP} secret=${radiusSecret} service=hotspot comment="MS-TELECOM-${pop_id}" timeout=1000ms
/radius incoming set accept=yes
:delay 1s

/ip hotspot profile add name="ms-profile-${pop_id}" hotspot-address=192.168.32.1 login-by=http-chap,http-pap use-radius=yes radius-default-domain="${pop_id}" radius-interim-update=10m
:delay 500ms

/ip hotspot add address-pool="ms-pool-${pop_id}" disabled=no idle-timeout=15m interface="ms-bridge-${pop_id}" name="${nome_pop}" profile="ms-profile-${pop_id}"
:delay 1s

/ip hotspot walled-garden ip add action=accept disabled=no dst-host=${FRONTEND_BASE_URL} server="${nome_pop}" comment="MS-TELECOM-${pop_id}"
/ip hotspot walled-garden ip add action=accept disabled=no dst-host=${API_BASE_URL} server="${nome_pop}"
:delay 1s

/system scheduler add name="ms-heartbeat-${pop_id}" interval=30s on-event="/tool fetch url=\\"${API_BASE_URL}/api/pops/${pop_id}/ping\\" http-method=post http-data=\\"{\\\\\\"name\\\\\\":\\\\\\"${nome_pop}\\\\\\",\\\\\\"api_user\\\\\\":\\\\\\"${apiUser}\\\\\\",\\\\\\"api_pass\\\\\\":\\\\\\"${apiPass}\\\\\\"}\\" keep-result=no"

:put "✅ INSTALAÇÃO CONCLUÍDA"
:put "POP ID: ${pop_id}"
:put "API User: ${apiUser}"
:put "API Pass: ${apiPass}"
`;

    res.json({ pop_id, nome_pop, script, message: 'POP criado com sucesso' });
  } catch (err) {
    console.error('❌ Erro ao gerar script:', err.message);
    res.status(500).json({ error: 'Erro ao gerar script' });
  }
});

// ============================================================
// 🔓 ACCESS / TRIAL
// ============================================================

// Free trial (rota pública)
app.post('/api/free-trial', async (req, res) => {
  try {
    const { mac_address, pop_id } = req.body;
    if (!mac_address) return res.status(400).json({ error: 'MAC address é obrigatório' });

    // 1. Verificar se já existe uso anterior desse MAC
    const { data: existingSession } = await supabase
      .from('hotspot_sessions')
      .select('id')
      .eq('mac_address', mac_address)
      .eq('is_trial', true)
      .maybeSingle();

    if (existingSession) {
      return res.status(403).json({ 
        success: false, 
        message: 'Teste grátis já utilizado para este dispositivo' 
      });
    }

    // 2. Definir tempo padrão (15 minutos)
    const durationMinutes = 15;
    const expiresAt = new Date(Date.now() + durationMinutes * 60 * 1000).toISOString();

    // 3. Criar registro em hotspot_sessions
    const { data: session, error: sessionError } = await supabase
      .from('hotspot_sessions')
      .insert({
        mac_address,
        pop_id: pop_id || null,
        status: 'active',
        is_trial: true,
        duration_minutes: durationMinutes,
        expires_at: expiresAt,
        created_at: new Date().toISOString()
      })
      .select()
      .single();

    if (sessionError) throw sessionError;

    // 4. Chamar função existente authorizeAccess
    // Nota: authorizeAccess(macAddress, popIp, apiUser, apiPass, popId, durationMinutes, speedMbps, planName)
    const result = await authorizeAccess(mac_address, undefined, undefined, undefined, pop_id, durationMinutes, null, 'free_trial');
    
    if (!result.success) {
      return res.status(500).json({ 
        success: false, 
        message: 'Falha ao autorizar acesso no roteador',
        details: result.errors 
      });
    }

    return res.json({
      success: true,
      expires_at: expiresAt,
      message: 'Acesso liberado'
    });
  } catch (err) {
    console.error('❌ Erro no teste grátis:', err.message);
    res.status(500).json({ success: false, message: 'Erro ao processar teste grátis' });
  }
});

// ✅ NOVA ROTA AQUI 👇
app.get('/api/pops/:id/script', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Buscar POP
    const { data: pop, error } = await supabase
      .from('pops')
      .select('*')
      .eq('id', id)
      .single();

    if (error || !pop) {
      return res.status(404).json({ error: 'POP não encontrado' });
    }

    // Gerar script básico (seguro)
    let script = `# Script MikroTik - ${pop.name || 'POP'}\n`;

    if (pop.ip) {
      script += `# IP: ${pop.ip}\n`;
    }

    if (pop.wan_interface) {
      script += `/interface set [find default-name=${pop.wan_interface}] name=WAN\n`;
    }

    if (pop.lan_interface) {
      script += `/interface set [find default-name=${pop.lan_interface}] name=LAN\n`;
    }

    if (pop.vlan_id) {
      script += `/interface vlan add name=vlan${pop.vlan_id} vlan-id=${pop.vlan_id}\n`;
    }

    if (pop.pppoe_username && pop.pppoe_password) {
      script += `/interface pppoe-client add user=${pop.pppoe_username} password=${pop.pppoe_password}\n`;
    }

    if (pop.static_ip) {
      script += `/ip address add address=${pop.static_ip}\n`;
    }

    return res.json({
      success: true,
      script
    });

  } catch (err) {
    console.error('Erro ao gerar script:', err.message);
    return res.status(500).json({
      success: false,
      message: 'Erro ao gerar script'
    });
  }
});

// Validar acesso (rota pública)
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

    const { data: session } = await supabase.from('hotspot_sessions').select('*')
      .eq('mac_address', mac || user.mac_address).eq('status', 'active')
      .order('created_at', { ascending: false }).limit(1).maybeSingle();

    res.json({
      access: true,
      user: { id: user.id, name: user.name, plan_name: user.plan_name, expires_at: user.expires_at, is_vip: user.is_vip },
      session: session || null
    });
  } catch (err) {
    console.error('❌ Erro ao validar acesso:', err.message);
    res.status(500).json({ error: 'Erro ao validar acesso' });
  }
});

// ============================================================
// 📊 ROTAS DE ESTATÍSTICAS
// ============================================================

app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const [
      { count: totalUsers },
      { count: activeUsers },
      { count: totalPayments },
      { count: pendingPayments },
      { count: totalPops },
      { count: activeSessions },
      { count: totalVouchers }
    ] = await Promise.all([
      supabase.from('users').select('*', { count: 'exact', head: true }),
      supabase.from('users').select('*', { count: 'exact', head: true }).eq('status', 'active'),
      supabase.from('payments').select('*', { count: 'exact', head: true }),
      supabase.from('payments').select('*', { count: 'exact', head: true }).eq('status', 'pending'),
      supabase.from('pops').select('*', { count: 'exact', head: true }),
      supabase.from('hotspot_sessions').select('*', { count: 'exact', head: true }).eq('status', 'active'),
      supabase.from('vouchers').select('*', { count: 'exact', head: true })
    ]);

    const { data: revenueData } = await supabase.from('payments').select('amount').eq('status', 'approved');
    const totalRevenue = (revenueData || []).reduce((sum, p) => sum + parseNumber(p.amount), 0);

    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);
    const { data: monthRevenueData } = await supabase.from('payments').select('amount')
      .eq('status', 'approved').gte('confirmed_at', startOfMonth.toISOString());
    const monthRevenue = (monthRevenueData || []).reduce((sum, p) => sum + parseNumber(p.amount), 0);

    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const { count: onlinePops } = await supabase.from('pops').select('*', { count: 'exact', head: true }).gte('last_seen_at', fiveMinAgo);

    res.json({
      totalUsers: totalUsers || 0,
      activeUsers: activeUsers || 0,
      totalPayments: totalPayments || 0,
      pendingPayments: pendingPayments || 0,
      totalPops: totalPops || 0,
      onlinePops: onlinePops || 0,
      activeSessions: activeSessions || 0,
      totalVouchers: totalVouchers || 0,
      totalRevenue,
      monthRevenue
    });
  } catch (err) {
    console.error('❌ Erro ao buscar estatísticas:', err.message);
    res.status(500).json({ error: 'Erro ao buscar estatísticas' });
  }
});

// ============================================================
// ⚙️ ROTAS DE CONFIGURAÇÕES
// ============================================================

// Listar configurações
app.get('/api/settings', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('*').order('id');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar configurações' });
  }
});

// Salvar configuração
app.post('/api/settings', authMiddleware, async (req, res) => {
  try {
    const { key, value } = req.body;
    if (!key) return res.status(400).json({ error: 'Key é obrigatória' });

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

// Deletar configuração
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

// Configurações do sistema (system_settings)
app.get('/api/settings/system', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('system_settings').select('*').single();
    if (error) throw error;
    res.json(data || {});
  } catch (err) {
    console.error('❌ Erro ao buscar configurações do sistema:', err.message);
    res.status(500).json({ error: 'Erro ao buscar configurações do sistema' });
  }
});

app.post('/api/settings/system', authMiddleware, async (req, res) => {
  try {
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    
    // Buscar se já existe um registro (geralmente id=1)
    const { data: existing } = await supabase.from('system_settings').select('id').maybeSingle();
    
    let result;
    if (existing) {
      result = await supabase.from('system_settings').update(updateData).eq('id', existing.id).select().single();
    } else {
      result = await supabase.from('system_settings').insert(updateData).select().single();
    }

    if (result.error) throw result.error;
    
    await registerAuditLog(req.user.username, 'update', 'settings', 'Configurações do sistema atualizadas', req.ip, req.headers['user-agent']);
    res.json({ message: 'Configurações salvas com sucesso', data: result.data });
  } catch (err) {
    console.error('❌ Erro ao salvar configurações do sistema:', err.message);
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
    res.json({ message: 'Configurações de pagamento salvas com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao salvar configurações de pagamento' });
  }
});

// ============================================================
// 📝 ROTAS DE LOGS
// ============================================================

// Logs do sistema
app.get('/api/logs', authMiddleware, async (req, res) => {
  try {
    const { limit = 200, level, source } = req.query;
    let query = supabase.from('logs').select('*').order('created_at', { ascending: false }).limit(parseInt(limit));
    if (level) query = query.eq('level', level);
    if (source) query = query.eq('source', source);
    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('❌ Erro ao listar logs:', err.message);
    res.status(500).json({ error: 'Erro ao listar logs' });
  }
});

// Logs de auditoria
app.get('/api/audit-logs', authMiddleware, async (req, res) => {
  try {
    const { limit = 200, type, username } = req.query;
    let query = supabase.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(parseInt(limit));
    if (type) query = query.eq('type', type);
    if (username) query = query.eq('username', username);
    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('❌ Erro ao listar logs de auditoria:', err.message);
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
// 🔄 ENTRYPOINT (redirecionamento do MikroTik)
// ============================================================

app.get('/entrypoint', (req, res) => {
  const hotspotIdentity = req.query.hotspotIdentity || req.query.server || req.query.server_name || '';
  const userMac = req.query.userMac || req.query.mac || '';
  const hostname = req.query.hostname || req.query.ip || '';
  const target = `${FRONTEND_BASE_URL}/index.html?mac=${encodeURIComponent(userMac)}&ip=${encodeURIComponent(hostname)}&pop=${encodeURIComponent(hotspotIdentity)}`;
  res.redirect(target);
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
// 🔄 ALIAS PARA COMPATIBILIDADE COM FRONTEND
// ============================================================

// Alias /api/hotspots → /api/pops
app.get('/api/hotspots', authMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase.from('pops').select('*').order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        console.error('❌ Erro em /api/hotspots:', err.message);
        res.status(500).json({ error: 'Erro ao listar hotspots' });
    }
});

// Estatísticas - Usuários por hora (dados de exemplo)
app.get('/api/stats/users-per-hour', authMiddleware, async (req, res) => {
    try {
        // Retorna array com 24 zeros (placeholder)
        const hours = Array.from({length: 24}, (_, i) => ({ hour: i, count: 0 }));
        res.json({ data: hours });
    } catch (err) {
        console.error('❌ Erro em /api/stats/users-per-hour:', err.message);
        res.status(500).json({ error: 'Erro ao buscar dados' });
    }
});

// Estatísticas - Tráfego total
app.get('/api/stats/total-traffic', authMiddleware, async (req, res) => {
    try {
        res.json({ total_gb: 0, peak_mbps: 0 });
    } catch (err) {
        console.error('❌ Erro em /api/stats/total-traffic:', err.message);
        res.status(500).json({ error: 'Erro ao buscar tráfego' });
    }
});

// Estatísticas - Comparação por plano
app.get('/api/stats/comparison', authMiddleware, async (req, res) => {
    try {
        const { data: plans } = await supabase.from('plans').select('id, name, price');
        const comparison = (plans || []).map(p => ({
            name: p.name,
            total: 0
        }));
        res.json(comparison);
    } catch (err) {
        console.error('❌ Erro em /api/stats/comparison:', err.message);
        res.status(500).json({ error: 'Erro ao buscar comparação' });
    }
});

// ============================================================
// 💳 ROTAS FALTANTES - PAGAMENTOS
// ============================================================

// Criar pagamento (alias usado pelo financeiro.html)
app.post('/api/create-payment', authMiddleware, async (req, res) => {
  try {
    const { user_id, plan_id, amount, description, payment_method, status } = req.body;
    const { data, error } = await supabase.from('payments').insert({
      user_id: user_id || null,
      plan_id: plan_id || null,
      amount: parseFloat(amount) || 0,
      description: description || '',
      payment_method: payment_method || 'manual',
      status: status || 'pending',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    console.error('❌ Erro em /api/create-payment:', err.message);
    res.status(500).json({ error: 'Erro ao criar pagamento' });
  }
});

// Confirmar pagamento (usado pelo financeiro.html)
app.post('/api/confirm-payment', authMiddleware, async (req, res) => {
  try {
    const { payment_id } = req.body;
    if (!payment_id) return res.status(400).json({ error: 'payment_id é obrigatório' });

    const { data: payment, error: fetchErr } = await supabase.from('payments').select('*').eq('id', payment_id).single();
    if (fetchErr || !payment) return res.status(404).json({ error: 'Pagamento não encontrado' });

    const { error } = await supabase.from('payments').update({
      status: 'approved',
      confirmed_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    }).eq('id', payment_id);
    if (error) throw error;

    // Se tem user_id e plan_id, ativar o plano do usuário
    if (payment.user_id && payment.plan_id) {
      const { data: plan } = await supabase.from('plans').select('duration_days, speed_mbps, name').eq('id', payment.plan_id).single();
      if (plan) {
        const expiresAt = new Date(Date.now() + (plan.duration_days || 30) * 86400000).toISOString();
        await supabase.from('users').update({ status: 'active', plan_id: payment.plan_id, plan_name: plan.name, expires_at: expiresAt, updated_at: new Date().toISOString() }).eq('id', payment.user_id);

        // Liberar acesso RADIUS com velocidade do plano
        const { data: user } = await supabase.from('users').select('mac_address').eq('id', payment.user_id).single();
        if (user && user.mac_address) {
          const durationMinutes = (plan.duration_days || 30) * 24 * 60;
          await authorizeAccess(user.mac_address, '192.168.32.1', null, null, null, durationMinutes, plan.speed_mbps, plan.name);
        }
      }
    }

    res.json({ message: 'Pagamento confirmado com sucesso' });
  } catch (err) {
    console.error('❌ Erro em /api/confirm-payment:', err.message);
    res.status(500).json({ error: 'Erro ao confirmar pagamento' });
  }
});

// ============================================================
// 👤 ROTAS FALTANTES - ADMINS
// ============================================================

// Listar admins
app.get('/api/admins', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('admins').select('id, username, email, role, created_at').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('❌ Erro ao listar admins:', err.message);
    res.status(500).json({ error: 'Erro ao listar admins' });
  }
});

// Criar admin
app.post('/api/admins', authMiddleware, async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    const { data, error } = await supabase.from('admins').insert({
      username, email: email || '', password: hashedPassword, role: role || 'admin',
      created_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }).select('id, username, email, role, created_at').single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    console.error('❌ Erro ao criar admin:', err.message);
    res.status(500).json({ error: 'Erro ao criar admin' });
  }
});

// Deletar admin
app.delete('/api/admins/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('admins').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Admin removido' });
  } catch (err) {
    console.error('❌ Erro ao deletar admin:', err.message);
    res.status(500).json({ error: 'Erro ao deletar admin' });
  }
});

// ============================================================
// 🌐 ROTAS FALTANTES - HOTSPOTS (POST/PUT/DELETE)
// ============================================================

// Criar hotspot
app.post('/api/hotspots', authMiddleware, async (req, res) => {
  try {
    const { name, location, address, dns_name, radius_enabled } = req.body;
    const { data, error } = await supabase.from('hotspots').insert({
      name, location: location || '', address: address || '',
      dns_name: dns_name || '', radius_enabled: radius_enabled || false,
      status: 'active', created_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    console.error('❌ Erro ao criar hotspot:', err.message);
    res.status(500).json({ error: 'Erro ao criar hotspot' });
  }
});

// Atualizar hotspot
app.put('/api/hotspots/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;
    const { data, error } = await supabase.from('hotspots').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('❌ Erro ao atualizar hotspot:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar hotspot' });
  }
});

// Deletar hotspot
app.delete('/api/hotspots/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('hotspots').delete().eq('id', id);
    if (error) throw error;
    res.json({ message: 'Hotspot removido' });
  } catch (err) {
    console.error('❌ Erro ao deletar hotspot:', err.message);
    res.status(500).json({ error: 'Erro ao deletar hotspot' });
  }
});

// ============================================================
// 📡 ROTAS FALTANTES - PORTAL PÚBLICO
// ============================================================

// Listar planos públicos
app.get('/api/portal/plans', async (req, res) => {
  try {
    const { data, error } = await supabase.from('plans').select('id, name, price, speed_mbps, duration_days, description').eq('active', true).order('price');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('❌ Erro em /api/portal/plans:', err.message);
    res.status(500).json({ error: 'Erro ao listar planos' });
  }
});

// Login do portal (usuário final)
app.post('/api/portal/login', async (req, res) => {
  try {
    const { identifier, password, mac_address } = req.body;
    if (!identifier || !password) return res.status(400).json({ error: 'Identificador e senha são obrigatórios' });

    const { data: user, error } = await supabase.from('users').select('*')
      .or(`username.eq.${identifier},email.eq.${identifier},cpf.eq.${identifier},phone.eq.${identifier}`)
      .single();
    if (error || !user) return res.status(401).json({ error: 'Usuário não encontrado' });

    let passwordMatch = false;
    if (user.password && user.password.length === 64) {
      const sha256 = crypto.createHash('sha256').update(password).digest('hex');
      passwordMatch = user.password === sha256;
    } else {
      passwordMatch = user.password === password;
    }
    if (!passwordMatch) return res.status(401).json({ error: 'Senha incorreta' });

    if (mac_address) {
      await supabase.from('users').update({ mac_address, updated_at: new Date().toISOString() }).eq('id', user.id);
    }

    const status = (user.status === 'active' && user.expires_at && new Date(user.expires_at) > new Date()) ? 'active' : 'expired';
    res.json({ user_id: user.id, username: user.username, status, plan_id: user.plan_id });
  } catch (err) {
    console.error('❌ Erro em /api/portal/login:', err.message);
    res.status(500).json({ error: 'Erro no login' });
  }
});

// Registro do portal (usuário final)
app.post('/api/portal/register', async (req, res) => {
  try {
    const { name, cpf, phone, password, mac_address } = req.body;
    if (!name || !password) return res.status(400).json({ error: 'Nome e senha são obrigatórios' });

    const username = cpf || phone || name.toLowerCase().replace(/\s+/g, '.');
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    const { data: existing } = await supabase.from('users').select('id').eq('username', username).maybeSingle();
    if (existing) return res.status(409).json({ error: 'Usuário já cadastrado' });

    const { data, error } = await supabase.from('users').insert({
      username, name, cpf: cpf || '', phone: phone || '',
      password: hashedPassword, mac_address: mac_address || '',
      status: 'pending', created_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }).select().single();
    if (error) throw error;
    res.status(201).json({ user_id: data.id, username: data.username });
  } catch (err) {
    console.error('❌ Erro em /api/portal/register:', err.message);
    res.status(500).json({ error: 'Erro no cadastro' });
  }
});

// Resgatar voucher (portal)
app.post('/api/portal/voucher', async (req, res) => {
  try {
    const { code, mac_address } = req.body;
    if (!code) return res.status(400).json({ error: 'Código do voucher é obrigatório' });

    const { data: voucher, error } = await supabase.from('vouchers').select('*').eq('code', code).eq('status', 'active').single();
    if (error || !voucher) return res.status(404).json({ error: 'Voucher inválido ou já utilizado' });

    await supabase.from('vouchers').update({
      status: 'used', used_by: mac_address || 'unknown', mac_address: mac_address || '',
      used_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }).eq('id', voucher.id);

    // Criar sessão de acesso baseada na duração do voucher
    if (voucher.duration_hours) {
      const durationMs = (voucher.duration_hours || 24) * 3600000;
      await supabase.from('hotspot_sessions').insert({
        mac_address: mac_address || '', access_granted: true, status: 'active',
        expires_at: new Date(Date.now() + durationMs).toISOString(),
        created_at: new Date().toISOString(), updated_at: new Date().toISOString()
      });
    }

    res.json({ message: 'Voucher ativado com sucesso', duration_hours: voucher.duration_hours || 24 });
  } catch (err) {
    console.error('❌ Erro em /api/portal/voucher:', err.message);
    res.status(500).json({ error: 'Erro ao resgatar voucher' });
  }
});

// Gerar PIX (portal)
app.post('/api/portal/create-pix', async (req, res) => {
  try {
    const { user_id, plan_id, plan_name, amount, mac_address } = req.body;
    if (!plan_id || !amount) return res.status(400).json({ error: 'Plano e valor são obrigatórios' });

    const MP_TOKEN = process.env.MERCADOPAGO_ACCESS_TOKEN || process.env.MP_ACCESS_TOKEN;
    if (!MP_TOKEN) return res.status(500).json({ error: 'Token do Mercado Pago não configurado' });

    const externalReference = `HS-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    const mpResponse = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${MP_TOKEN}`, 'X-Idempotency-Key': externalReference },
      body: JSON.stringify({
        transaction_amount: parseFloat(amount),
        description: plan_name || 'Plano Hotspot',
        payment_method_id: 'pix',
        payer: { email: 'cliente@hotspot.com', first_name: 'Cliente', identification: { type: 'CPF', number: '00000000000' } },
        external_reference: externalReference
      })
    });

    const mpData = await mpResponse.json();
    if (!mpResponse.ok) return res.status(400).json({ error: 'Erro ao gerar PIX', details: mpData });

    const pixCopyPaste = mpData.point_of_interaction?.transaction_data?.qr_code || '';
    const qrCodeBase64 = mpData.point_of_interaction?.transaction_data?.qr_code_base64 || '';

    const { data: payment, error } = await supabase.from('payments').insert({
      user_id: user_id || null, plan_id, plan_name: plan_name || '',
      user_mac: mac_address || '', mac_address: mac_address || '',
      amount: parseFloat(amount), description: plan_name || 'Plano Hotspot',
      status: 'pending', payment_method: 'pix', method: 'pix',
      mercado_pago_id: String(mpData.id), mp_payment_id: String(mpData.id),
      pix_copy_paste: pixCopyPaste, pix_qr_code: pixCopyPaste,
      qr_code: qrCodeBase64, pix_qr_code_base64: qrCodeBase64,
      external_reference: externalReference,
      expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
      created_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }).select().single();
    if (error) throw error;

    res.json({
      payment_id: payment.id, mercado_pago_id: mpData.id,
      pix_copy_paste: pixCopyPaste, qr_code_base64: qrCodeBase64,
      external_reference: externalReference, status: 'pending', amount: parseFloat(amount)
    });
  } catch (err) {
    console.error('❌ Erro em /api/portal/create-pix:', err.message);
    res.status(500).json({ error: 'Erro ao gerar pagamento PIX' });
  }
});

// Verificar pagamento (portal)
app.get('/api/portal/check-payment/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { data: payment, error } = await supabase.from('payments').select('id, status, amount, plan_id, user_id').eq('id', id).single();
    if (error || !payment) return res.status(404).json({ error: 'Pagamento não encontrado' });
    res.json(payment);
  } catch (err) {
    console.error('❌ Erro em /api/portal/check-payment:', err.message);
    res.status(500).json({ error: 'Erro ao verificar pagamento' });
  }
});

// Status do usuário (portal)
app.get('/api/portal/status', async (req, res) => {
  try {
    const { mac, ip } = req.query;

    // Tentar buscar sessão ativa por MAC
    if (mac) {
      const { data: session } = await supabase.from('hotspot_sessions').select('*')
        .eq('mac_address', mac).eq('status', 'active')
        .order('created_at', { ascending: false }).limit(1).maybeSingle();

      if (session && session.expires_at && new Date(session.expires_at) > new Date()) {
        const remaining = new Date(session.expires_at) - new Date();
        const hours = Math.floor(remaining / 3600000);
        const minutes = Math.floor((remaining % 3600000) / 60000);
        return res.json({
          connected: true, plan_name: 'Sessão Ativa',
          time_remaining: `${hours}h ${minutes}min`, speed: '-'
        });
      }

      // Tentar buscar usuário por MAC
      const { data: user } = await supabase.from('users').select('*, plans(name, speed_mbps)')
        .eq('mac_address', mac).eq('status', 'active')
        .maybeSingle();

      if (user && user.expires_at && new Date(user.expires_at) > new Date()) {
        const remaining = new Date(user.expires_at) - new Date();
        const hours = Math.floor(remaining / 3600000);
        const minutes = Math.floor((remaining % 3600000) / 60000);
        return res.json({
          connected: true, plan_name: user.plans?.name || 'Plano Ativo',
          time_remaining: `${hours}h ${minutes}min`,
          speed: user.plans?.speed_mbps ? `${user.plans.speed_mbps} Mbps` : '-'
        });
      }
    }

    res.json({ connected: false, plan_name: '-', time_remaining: '-', speed: '-' });
  } catch (err) {
    console.error('❌ Erro em /api/portal/status:', err.message);
    res.status(500).json({ error: 'Erro ao verificar status' });
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
║  ✅ Ambiente: ${process.env.NODE_ENV || 'development'}                     ║
║  ✅ Padrão: Código EN, Comentários PT-BR                     ║
║  ✅ Endpoints: /api/users, /api/plans, /api/payments         ║
║  ✅ Tabelas: users, plans, payments, pops                    ║
║  ✅ Integração: MikroTik API, Mercado Pago, RADIUS           ║
║  ✅ Deploy Automático: GitHub Actions → VPS                  ║
║  ✅ CRON: Remoção automática de acessos expirados            ║
╚══════════════════════════════════════════════════════════════╝
  `);
});
