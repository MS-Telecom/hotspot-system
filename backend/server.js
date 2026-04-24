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
const { exec } = require('child_process');

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
// Captura IP real quando estiver atrás de proxy (Vercel/Cloudflare/Nginx)
app.set('trust proxy', true);
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
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return String(forwarded).split(',')[0].trim();
  return req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || null;
}

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

function generatePopId() {
  // Mantem padrao humano e evita depender de default/serial no banco.
  return `MS-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
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
  if (error) throw error;
  return normalized;
}

// ============================================================
// 🔓 MIKROTIK ACCESS CONTROL
// ============================================================

// ============================================================
// FREERADIUS CLIENTS SYNC (clients.conf from POPs)
// ============================================================

const FREERADIUS_CLIENTS_PATH =
  process.env.FREERADIUS_CLIENTS_PATH || '/etc/freeradius/3.0/clients.d/ms-telecom-pops.conf';
const FREERADIUS_TMP_CLIENTS_PATH =
  process.env.FREERADIUS_TMP_CLIENTS_PATH || path.join(__dirname, 'tmp', 'ms-telecom-pops.conf');
const FREERADIUS_MAIN_CLIENTS_CONF = process.env.FREERADIUS_MAIN_CLIENTS_CONF || '/etc/freeradius/3.0/clients.conf';
const FREERADIUS_INCLUDE_LINE = `$INCLUDE ${FREERADIUS_CLIENTS_PATH}`;
const FREERADIUS_VALIDATE_CMD = process.env.FREERADIUS_VALIDATE_CMD || 'sudo /usr/sbin/freeradius -C';
const FREERADIUS_RELOAD_CMD = process.env.FREERADIUS_RELOAD_CMD || 'sudo /usr/bin/systemctl reload freeradius';

let freeradiusSyncInFlight = null;

function execAsync(command, timeoutMs = 15000) {
  return new Promise((resolve) => {
    exec(command, { timeout: timeoutMs }, (error, stdout, stderr) => {
      resolve({ error, stdout: String(stdout || ''), stderr: String(stderr || '') });
    });
  });
}

function sanitizeFreeradiusClientName(value) {
  return (
    String(value || 'pop')
      .trim()
      .replace(/[^A-Za-z0-9_]/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 48) || 'pop'
  );
}

function buildFreeradiusClientsConf(pops) {
  const header = [
    '# ======================================================================',
    '# AUTO-GENERATED FILE - DO NOT EDIT MANUALLY',
    '# Generated by hotspot-system backend from table: pops',
    `# Generated at: ${new Date().toISOString()}`,
    '# ======================================================================',
    ''
  ].join('\n');

  const blocks = (pops || [])
    .filter((p) => p && p.ip && p.radius_secret)
    .map((p) => {
      const clientName = sanitizeFreeradiusClientName(`ms_${p.unique_id || p.id || p.name}`);
      const commentName = (p.name || '').replace(/[\r\n]/g, ' ').trim();
      return [
        `# POP: ${commentName || (p.unique_id || p.id || '')}`,
        `client ${clientName} {`,
        `  ipaddr = ${p.ip}`,
        `  secret = ${p.radius_secret}`,
        '  nas_type = other',
        '}',
        ''
      ].join('\n');
    })
    .join('\n');

  return header + blocks;
}

async function syncFreeradiusClientsFromDb() {
  if (!FREERADIUS_CLIENTS_PATH) {
    return { ok: false, error: 'FREERADIUS_CLIENTS_PATH is not configured' };
  }

  if (freeradiusSyncInFlight) return freeradiusSyncInFlight;

  freeradiusSyncInFlight = (async () => {
    try {
      const { data: pops, error } = await supabase
        .from('pops')
        .select('id, unique_id, name, ip, radius_secret, status')
        .order('name', { ascending: true });
      if (error) throw error;

      const conf = buildFreeradiusClientsConf(pops || []);

      // Write in a local tmp path first (PM2 runs as ubuntu and cannot write to /etc directly).
      fs.mkdirSync(path.dirname(FREERADIUS_TMP_CLIENTS_PATH), { recursive: true });
      fs.writeFileSync(FREERADIUS_TMP_CLIENTS_PATH, conf);

      // Validate the config before moving it to /etc.
      const validateRes = await execAsync(FREERADIUS_VALIDATE_CMD);
      if (validateRes.error) {
        throw new Error(`FreeRADIUS config validation failed: ${validateRes.stderr || validateRes.stdout}`);
      }

      // Copy to /etc with sudo.
      const copyRes = await execAsync(`sudo cp ${FREERADIUS_TMP_CLIENTS_PATH} ${FREERADIUS_CLIENTS_PATH}`);
      if (copyRes.error) {
        throw new Error(`Failed to copy clients config to /etc: ${copyRes.stderr}`);
      }

      // Ensure $INCLUDE line exists in main clients.conf.
      const checkInclude = await execAsync(`grep -F "${FREERADIUS_INCLUDE_LINE}" ${FREERADIUS_MAIN_CLIENTS_CONF}`);
      if (checkInclude.error) {
        await execAsync(`sudo sh -c 'echo "${FREERADIUS_INCLUDE_LINE}" >> ${FREERADIUS_MAIN_CLIENTS_CONF}'`);
      }

      // Reload FreeRADIUS.
      const reloadRes = await execAsync(FREERADIUS_RELOAD_CMD);
      if (reloadRes.error) {
        throw new Error(`FreeRADIUS reload failed: ${reloadRes.stderr}`);
      }

      console.log('[FreeRADIUS] clients synced successfully.');
      return { ok: true };
    } catch (err) {
      console.error('[FreeRADIUS] sync error:', err.message);
      return { ok: false, error: err.message };
    } finally {
      freeradiusSyncInFlight = null;
    }
  })();

  return freeradiusSyncInFlight;
}

// ============================================================
// 📡 RADIUS ACCESS HELPERS
// ============================================================

async function authorizeAccess(username, nasIp, password = null, ipAddress = null, popId = null, durationMinutes = 60, priority = 10, planName = 'default') {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + durationMinutes * 60000).toISOString();
  
  const payload = {
    username,
    nas_ip: nasIp,
    password: password || 'nopass',
    ip_address: ipAddress,
    pop_id: popId,
    priority,
    plan_name: planName,
    status: 'active',
    expires_at: expiresAt,
    created_at: now.toISOString(),
    updated_at: now.toISOString()
  };

  const { error } = await supabase.from('radius_replies').upsert(payload, { onConflict: 'username' });
  if (error) throw error;

  return { success: true, expiresAt };
}

async function revokeAccess(username, nasIp = null) {
  const query = supabase.from('radius_replies').update({ status: 'expired', updated_at: new Date().toISOString() }).eq('username', username);
  if (nasIp) query.eq('nas_ip', nasIp);
  const { error } = await query;
  if (error) throw error;
  return { success: true };
}

// ============================================================
// 👤 USER & SESSION HELPERS
// ============================================================

function stripUnknownColumn(payload, errorMessage) {
  const match = errorMessage.match(/column "([^"]+)" of relation "[^"]+" does not exist/);
  if (match) {
    const col = match[1];
    const next = { ...payload };
    delete next[col];
    return next;
  }
  return payload;
}

async function findOrCreateHotspotUser({ macAddress, ipAddress, planName, status, popId, expiresAt }) {
  const cleanMac = String(macAddress || '').trim();
  const now = new Date().toISOString();
  
  const { data: existing } = await supabase
    .from('users')
    .select('*')
    .eq('mac_address', cleanMac)
    .maybeSingle();

  const base = {
    mac_address: cleanMac,
    last_ip: ipAddress,
    last_plan: planName,
    status: status || 'active',
    last_seen_at: now,
    updated_at: now
  };

  const optional = {
    ...(popId ? { last_pop_id: popId } : {}),
    ...(expiresAt ? { expires_at: expiresAt } : {})
  };

  if (existing) {
    let updatePayload = { ...base, ...optional };
    for (let i = 0; i < 4; i++) {
      const { data, error } = await supabase
        .from('users')
        .update(updatePayload)
        .eq('id', existing.id)
        .select('*')
        .maybeSingle();

      if (!error) return data;
      const next = stripUnknownColumn(updatePayload, error.message);
      if (next === updatePayload) throw error;
      updatePayload = next;
    }
    throw new Error('Failed to update user');
  }

  let insertPayload = { ...base, ...optional, created_at: now };
  for (let i = 0; i < 4; i++) {
    const { data, error } = await supabase
      .from('users')
      .insert(insertPayload)
      .select('*')
      .maybeSingle();

    if (!error) return data;
    const next = stripUnknownColumn(insertPayload, error.message);
    if (next === insertPayload) throw error;
    insertPayload = next;
  }

  throw new Error('Failed to create user');
}

async function handleFreeTrialAccess({ macAddress, durationMinutes = 15, ipAddress = null, popId = null, popIp = null }) {
  const cleanMac = String(macAddress || '').trim();
  if (!cleanMac) return { ok: false, status: 400, body: { error: 'MAC é obrigatório' } };

  const minutes = Number(durationMinutes || 15);
  const expiresAt = new Date(Date.now() + minutes * 60000).toISOString();
  const mikrotikIp = popIp || '192.168.32.1';

  // 0) Enforce free-trial limit using `free_trials` (best-effort; won't block if the table isn't available).
  try {
    const { data: ft, error: ftErr } = await supabase
      .from('free_trials')
      .select('id')
      .eq('mac', cleanMac)
      .maybeSingle();

    if (ftErr) throw ftErr;
    if (ft) return { ok: false, status: 429, body: { error: 'Teste grátis já utilizado para este MAC' } };
  } catch (_e) {
    // If the table doesn't exist yet, don't block the flow.
  }

  // 1) Ensure RADIUS credential (and IP binding when possible).
  const result = await authorizeAccess(cleanMac, mikrotikIp, null, null, popId, minutes, 5, 'free_trial');
  if (!result.success) return { ok: false, status: 500, body: { error: 'Erro ao liberar acesso' } };

  // 2) Ensure basic user row exists for this device.
  const user = await findOrCreateHotspotUser({
    macAddress: cleanMac,
    ipAddress,
    planName: 'free_trial',
    status: 'trial',
    popId,
    expiresAt
  });

  // 3) Register session linked to the user.
  const now = new Date().toISOString();
  const sessionPayload = {
    user_id: user.id,
    mac_address: cleanMac,
    access_granted: true,
    status: 'active',
    expires_at: expiresAt,
    ...(popId ? { pop_id: popId } : {}),
    ...(popIp ? { pop_ip: popIp } : {}),
    created_at: now,
    updated_at: now
  };

  const { error: sessionErr } = await supabase.from('hotspot_sessions').insert(sessionPayload);
  if (sessionErr) throw sessionErr;

  // 4) Mark the free-trial as used (best-effort; doesn't fail the session if it can't write).
  try {
    // A tabela free_trials usa 'mac' e não tem 'used_at' (usa created_at automático).
    await supabase.from('free_trials').insert({ mac: cleanMac });
  } catch (_e) {
    // ignore
  }

  return { ok: true, status: 200, body: { message: 'Acesso liberado', expires_at: expiresAt, user_id: user.id } };
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
    }

  } catch (error) {
    console.error('❌ Erro no CRON de limpeza:', error.message);
  }
}, 60000); // Executa a cada 1 minuto

// ============================================================
// 🔑 ROTAS DE AUTENTICAÇÃO (ADMIN)
// ============================================================

// Aliases legados (português/curtos) -> padrão novo
app.post('/api/login', (req, res, next) => {
  // Encaminha para /api/auth/login
  req.url = '/api/auth/login';
  next();
});
app.post('/api/logout', authMiddleware, (req, res, next) => {
  req.url = '/api/auth/logout';
  next();
});

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
    
    await registerAuditLog(username, 'login', 'auth', 'Login realizado', getClientIp(req), req.headers['user-agent']);
    
    res.json({ token, user: { id: admin.id, username: admin.username, role: admin.role } });
  } catch (err) {
    console.error('❌ Erro no login:', err.message);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// ... (Restante do arquivo omitido para brevidade, mas mantido na escrita real)
