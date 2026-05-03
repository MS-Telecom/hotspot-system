// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸Ãƒâ€¦Ã‚Â¡ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ HOTSPOT SYSTEM - MS TELECOM
// Backend principal (server.js) - VERSÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢O DEFINITIVA
// CÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³digo interno em inglÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âªs, comentÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rios em portuguÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âªs
// ============================================================

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');

// RouterOS API para controle MikroTik (opcional)
let RouterOSAPI = null;
try {
  RouterOSAPI = require('node-routeros').RouterOSAPI;
} catch (e) {
  console.warn('ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã‚Â¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¸Ãƒâ€šÃ‚Â node-routeros nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o instalado - recursos de API MikroTik desabilitados');
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Captura IP real quando estiver atrÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡s de proxy (Vercel/Cloudflare/Nginx)
app.set('trust proxy', true);
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
const PORT = process.env.PORT || 3000;
const API_BASE_URL = process.env.API_BASE_URL || 'https://mstelecom-api.duckdns.org';
const FRONTEND_BASE_URL = process.env.FRONTEND_BASE_URL || 'https://hotspot-system.vercel.app';
const RADIUS_SERVER_IP = process.env.RADIUS_SERVER_IP || '40.233.118.238';
const RADIUS_CLIENT_MODE = (process.env.RADIUS_CLIENT_MODE || 'global').toLowerCase(); // global | vpn_legacy
const RADIUS_GLOBAL_SECRET = process.env.RADIUS_GLOBAL_SECRET || '';
const RADIUS_VPN_SERVER_IP = process.env.RADIUS_VPN_SERVER_IP || process.env.RADIUS_VPN_SERVER_IP || '10.254.1.1';
const RADIUS_GLOBAL_FALLBACK_SECRET = process.env.RADIUS_GLOBAL_FALLBACK_SECRET || RADIUS_GLOBAL_SECRET || '';
const PRELOGIN_ALLOWED_HOSTS = [
  FRONTEND_BASE_URL,
  API_BASE_URL
];
const FORBIDDEN_WALLED_GARDEN_PATTERNS = [
  'gstatic',
  'googleapis',
  'connectivitycheck',
  'generate_204',
  'generate',
  'clients3.google',
  'google.cn',
  'play.googleapis',
  'google.com',
  'www.gstatic.com',
  'cdn.tailwindcss.com',
  'cdnjs.cloudflare.com',
  'unpkg.com',
  '*.vercel.app',
  'cdn.vercel.app',
  'neverssl.com',
  'mercadopago',
  'mercadopago.com.br',
  'captive.apple.com',
  'msftconnecttest.com',
  'msftncsi.com'
];

// Legacy VPN (RouterOS v6) - tunnel IP per POP, FreeRADIUS clients matched by vpn_ip.
const VPN_PUBLIC_ENDPOINT = process.env.VPN_PUBLIC_ENDPOINT || '';
const VPN_INTERNAL_RADIUS_IP = process.env.VPN_INTERNAL_RADIUS_IP || '10.250.0.1';
const VPN_L2TP_IPSEC_PSK = process.env.VPN_L2TP_IPSEC_PSK || '';

// L2TP provisioning (VPS as concentrator)
const VPN_IP_POOL_START = process.env.VPN_IP_POOL_START || '10.254.1.10';
const VPN_IP_POOL_END = process.env.VPN_IP_POOL_END || '10.254.1.200';
const CHAP_SECRETS_PATH = process.env.CHAP_SECRETS_PATH || '/etc/ppp/chap-secrets';
const XL2TPD_SERVICE_NAME = process.env.XL2TPD_SERVICE_NAME || 'xl2tpd';
const JWT_SECRET = process.env.JWT_SECRET;

// Constantes do Sistema
const BACKUP_DIR = path.join(__dirname, 'backups');
if (!fs.existsSync(BACKUP_DIR)) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

// CORS configurado para aceitar requisiÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes do frontend no Vercel
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

// ValidaÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o de variÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡veis de ambiente
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_KEY || !JWT_SECRET) {
  console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ FATAL: VariÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡veis de ambiente obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rias faltando: SUPABASE_URL, SUPABASE_KEY, JWT_SECRET');
  process.exit(1);
}

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

function createApiRateLimit({ windowMs = 60 * 1000, max = 60 } = {}) {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    validate: { trustProxy: false },
    keyGenerator: (req) => getClientIp(req) || req.ip,
    message: { error: 'Muitas tentativas. Tente novamente em instantes.' }
  });
}

const loginLimiter = createApiRateLimit({ windowMs: 15 * 60 * 1000, max: 8 });
const paymentLimiter = createApiRateLimit({ windowMs: 60 * 1000, max: 12 });
const portalWriteLimiter = createApiRateLimit({ windowMs: 60 * 1000, max: 20 });
const accessLimiter = createApiRateLimit({ windowMs: 60 * 1000, max: 12 });
const voucherLimiter = createApiRateLimit({ windowMs: 60 * 1000, max: 20 });

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂºÃƒâ€šÃ‚Â ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¸Ãƒâ€šÃ‚Â FUNÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ES UTILITÃƒÆ’Ã†â€™Ãƒâ€šÃ‚ÂRIAS
// ============================================================

// Remove acentos de uma string (ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºtil para slugs)
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return String(forwarded).split(',')[0].trim();
  return req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || null;
}

function normalizeMac(value) {
  const raw = String(value || '').trim().toUpperCase();
  if (!raw) return '';
  const hex = raw.replace(/[^A-F0-9]/g, '');
  if (hex.length !== 12) return raw;
  return hex.match(/.{1,2}/g).join(':');
}

function getMacVariants(value) {
  const normalized = normalizeMac(value);
  const compact = normalized ? normalized.replace(/:/g, '') : '';
  return [...new Set([normalized, compact, String(value || '').trim().toUpperCase()].filter(Boolean))];
}

function getPopRefFromPayload(source = {}) {
  return source.pop_id ?? source.pop ?? source.pop_unique_id ?? source.hotspot_id ?? source.hotspot ?? source.server_name ?? null;
}

async function resolvePopContext(popRef, popIp = null) {
  const ref = String(popRef || '').trim();
  if (!ref) return { pop_id: null, pop_name: null, pop_location: null, pop_ip: popIp || null };

  for (const field of ['id', 'unique_id', 'name']) {
    try {
      const { data, error } = await supabase
        .from('pops')
        .select('*')
        .eq(field, ref)
        .limit(1)
        .maybeSingle();
      if (!error && data) {
        return {
          pop_id: data.id || ref,
          pop_name: data.name || data.unique_id || ref,
          pop_location: data.location || null,
          pop_ip: popIp || data.ip || data.vpn_ip || data.radius_client_ip || null
        };
      }
    } catch (_error) {}
  }

  return { pop_id: ref, pop_name: null, pop_location: null, pop_ip: popIp || null };
}

function normalizeCpf(value) {
  const raw = String(value ?? '').trim();
  if (!raw || raw === '-' || raw.toLowerCase() === 'n/a') return null;
  const digits = raw.replace(/\D/g, '');
  return digits || null;
}

function normalizeEmail(value) {
  const raw = String(value ?? '').trim().toLowerCase();
  return raw || null;
}

async function findDuplicateUserField(field, value, excludeId = null) {
  if (!value) return null;
  let query = supabase.from('users').select('id').eq(field, value);
  if (excludeId) query = query.neq('id', excludeId);
  query = query.limit(1).maybeSingle();
  const { data, error } = await query;
  if (error) throw error;
  return data || null;
}

function getHostnameFromUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    return new URL(raw.includes('://') ? raw : `https://${raw}`).hostname.toLowerCase();
  } catch (_error) {
    return raw.replace(/^https?:\/\//i, '').split(/[/?#:]/)[0].replace(/\/+$/, '').toLowerCase();
  }
}

function isForbiddenWalledGardenHost(host) {
  const normalized = String(host || '').trim().toLowerCase();
  if (!normalized) return false;
  return FORBIDDEN_WALLED_GARDEN_PATTERNS.some((pattern) => {
    const p = String(pattern || '').toLowerCase();
    if (p.startsWith('*.')) return normalized === p || normalized === p.slice(2);
    return normalized.includes(p);
  });
}

function getPreloginAllowedHosts() {
  const hosts = PRELOGIN_ALLOWED_HOSTS
    .map(getHostnameFromUrl)
    .filter(Boolean);
  return [...new Set(hosts)];
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

// Gera senha forte aleatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³ria
function generateStrongPassword(length = 20) {
  return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
}

function generateVpnPassword() {
  return generateStrongPassword(24);
}

function ipToInt(ip) {
  const parts = String(ip || '').trim().split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function intToIp(num) {
  const n = Number(num) >>> 0;
  return [
    (n >>> 24) & 255,
    (n >>> 16) & 255,
    (n >>> 8) & 255,
    n & 255
  ].join('.');
}

// Converte para nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºmero de forma segura
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
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œÃƒâ€šÃ‚Â LOGS DE AUDITORIA E SISTEMA
// ============================================================

// Registrar log de auditoria (aÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes de usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rios)
async function registerAuditLog(username, type, objectName, action, ip, userAgent, details = null) {
  try {
    await supabase.from('audit_logs').insert({
      username: username || 'system',
      type: type || 'info',
      object: objectName || 'system',
      action: action || '',
      ip: ip || '',
      user_agent: userAgent || '',
      details: details ? JSON.stringify(scrubSecretObject(details)) : null,
      created_at: new Date().toISOString()
    });
  } catch (error) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao registrar log de auditoria:', error.message);
  }
}

// Registrar log do sistema (eventos internos)
async function registerSystemLog(level, source, message, details = null, ip = '', userAgent = '') {
  try {
    await supabase.from('logs').insert({
      level: level || 'info',
      source: source || 'system',
      message,
      details: details ? JSON.stringify(scrubSecretObject(details)) : null,
      ip,
      user_agent: userAgent,
      created_at: new Date().toISOString()
    });
  } catch (error) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao registrar log do sistema:', error.message);
  }
}

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂÃƒâ€šÃ‚Â MIDDLEWARE DE AUTENTICAÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢O
// ============================================================

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized', reason: 'missing_or_invalid_token' });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized', reason: 'missing_or_invalid_token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    const role = String(req.user?.role || '').toLowerCase();
    if (!roles.includes(role)) {
      return res.status(403).json({ error: 'Forbidden', reason: 'insufficient_role' });
    }
    next();
  };
}

const ADMIN_ROLES = new Set(['owner', 'admin', 'operator', 'finance']);

function hashPassword(password) {
  return bcrypt.hashSync(String(password), 12);
}

function verifyPasswordHash(storedHash, password) {
  const stored = String(storedHash || '');
  const plain = String(password || '');
  if (!stored || !plain) return { ok: false, legacySha256: false };
  if (stored.startsWith('$2a$') || stored.startsWith('$2b$') || stored.startsWith('$2y$')) {
    return { ok: bcrypt.compareSync(plain, stored), legacySha256: false };
  }
  const legacySha256 = crypto.createHash('sha256').update(plain).digest('hex');
  return { ok: stored === legacySha256, legacySha256: stored === legacySha256 };
}

function getBearerOrBodyToken(req) {
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) return authHeader.split(' ')[1];
  return req.headers['x-pop-token'] || req.query.token || req.body?.token || '';
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function buildPopToken(popId) {
  return crypto.createHmac('sha256', JWT_SECRET).update(`pop:${popId}`).digest('hex');
}

function scrubSecretObject(value) {
  if (!value || typeof value !== 'object') return value;
  const secretKeys = /(secret|token|key|password|pass|psk|radius|vpn|supabase|mercado|ssh)/i;
  if (Array.isArray(value)) return value.map(scrubSecretObject);
  return Object.fromEntries(Object.entries(value).map(([key, val]) => {
    if (secretKeys.test(key)) return [key, 'configured'];
    return [key, scrubSecretObject(val)];
  }));
}

function stripSecretFields(value) {
  if (!value || typeof value !== 'object') return value;
  const secretKeys = /(secret|token|key|password|pass|psk|radius|vpn|supabase|mercado|mercadopago|ssh)/i;
  if (Array.isArray(value)) return value.map(stripSecretFields);
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !secretKeys.test(key))
    .map(([key, val]) => [key, stripSecretFields(val)]));
}

async function getPopTokenRecord(popId) {
  const { data } = await supabase
    .from('settings')
    .select('value')
    .eq('key', `pop_token_${popId}`)
    .maybeSingle();
  return data?.value || null;
}

async function ensurePopToken(popId) {
  const token = buildPopToken(popId);
  const tokenHash = hashToken(token);
  const existing = await getPopTokenRecord(popId);
  if (existing?.token_hash !== tokenHash) {
    await supabase.from('settings').upsert({
      key: `pop_token_${popId}`,
      value: { token_hash: tokenHash, token_hint: token.slice(-6) },
      updated_at: new Date().toISOString()
    }, { onConflict: 'key' });
  }
  return token;
}

async function validatePopToken(req, popId) {
  const token = String(getBearerOrBodyToken(req) || '');
  if (!token) return false;
  const record = await getPopTokenRecord(popId);
  if (!record) return false;
  if (record.token_hash) return hashToken(token) === record.token_hash;
  if (record.token) return token === record.token;
  return false;
}

async function requirePopToken(req, res, popId) {
  const ok = await validatePopToken(req, popId);
  if (!ok) {
    res.status(401).json({ error: 'Unauthorized', reason: 'missing_or_invalid_pop_token' });
    return false;
  }
  return true;
}

function validatePopRegisterToken(req) {
  const expected = process.env.POP_REGISTER_TOKEN || process.env.POP_SHARED_SECRET || '';
  const token = String(getBearerOrBodyToken(req) || '');
  return !!expected && token === expected;
}

function sanitizeBackupRecord(table, record) {
  const blockedKeys = /(password|api_pass|radius_secret|vpn_password|token|secret|key|psk|credential)/i;
  const out = {};
  for (const [key, value] of Object.entries(record || {})) {
    if (blockedKeys.test(key)) continue;
    if (table === 'settings' && /token|secret|key|password|psk|radius|vpn|mercado|supabase|ssh/i.test(String(record.key || ''))) continue;
    out[key] = value;
  }
  return out;
}


app.get('/api/system/walled-garden-hosts', authMiddleware, (req, res) => {
  try {
    res.json({
      allowed_hosts: getPreloginAllowedHosts(),
      forbidden_patterns: FORBIDDEN_WALLED_GARDEN_PATTERNS,
      frontend_host: getHostnameFromUrl(FRONTEND_BASE_URL),
      api_host: getHostnameFromUrl(API_BASE_URL)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂÃƒâ€šÃ‚Â§ MIKROTIK CREDENTIALS HELPERS
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
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ MIKROTIK ACCESS CONTROL
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
const FREERADIUS_VALIDATE_CMD = process.env.FREERADIUS_VALIDATE_CMD || '/usr/sbin/freeradius -C';
const FREERADIUS_RELOAD_CMD = process.env.FREERADIUS_RELOAD_CMD || '/usr/bin/systemctl reload freeradius';
const FREERADIUS_RESTART_CMD = process.env.FREERADIUS_RESTART_CMD || '/usr/bin/systemctl restart freeradius';

let freeradiusSyncInFlight = null;

function execAsync(command, timeoutMs = 15000) {
  return new Promise((resolve) => {
    exec(command, { timeout: timeoutMs }, (error, stdout, stderr) => {
      resolve({ error, stdout: String(stdout || ''), stderr: String(stderr || '') });
    });
  });
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
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
    .filter((p) => {
      if (!p) return false;
      const clientIp = String(p.vpn_ip || p.radius_client_ip || '').trim();
      if (!clientIp) return false;
      if (clientIp === '0.0.0.0' || clientIp === '0.0.0.0/0') return false;
      if (!p.radius_secret) return false;
      return true;
    })
    .map((p) => {
      const baseId = String(p.unique_id || p.id || p.name || '').trim();
      const clientName = sanitizeFreeradiusClientName(`ms_${baseId}_vpn`);
      const commentName = (p.name || '').replace(/[\r\n]/g, ' ').trim();
      const clientIp = String(p.vpn_ip || p.radius_client_ip || '').trim();
      return [
        `# POP: ${commentName || (p.unique_id || p.id || '')}`,
        `client ${clientName} {`,
        `  ipaddr = ${clientIp}`,
        `  secret = ${p.radius_secret}`,
        `  shortname = ${baseId}-vpn`,
        '  nastype = mikrotik',
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
      if (RADIUS_CLIENT_MODE === 'global') {
        if (!RADIUS_GLOBAL_FALLBACK_SECRET) throw new Error('RADIUS_GLOBAL_FALLBACK_SECRET is required when RADIUS_CLIENT_MODE=global');
        return { ok: true, skipped: true };
      }

      if (RADIUS_CLIENT_MODE !== 'vpn_legacy') {
        throw new Error(`Invalid RADIUS_CLIENT_MODE: ${RADIUS_CLIENT_MODE}. Use global|vpn_legacy.`);
      }

      const { data: pops, error } = await supabase
        .from('pops')
        .select('id, unique_id, name, ip, vpn_ip, radius_client_ip, radius_secret, status')
        .order('name', { ascending: true });
      if (error) {
        if (
          looksLikeMissingColumnError(error, 'vpn_ip', 'pops') ||
          looksLikeMissingColumnError(error, 'radius_client_ip', 'pops')
        ) {
          throw new Error('Database schema missing required VPN columns in pops (vpn_ip, radius_client_ip). Apply migration first.');
        }
        throw error;
      }

      const missing = (pops || []).filter((p) => {
        const clientIp = String(p?.vpn_ip || p?.radius_client_ip || '').trim();
        return p && (!clientIp || clientIp === '0.0.0.0' || clientIp === '0.0.0.0/0' || !p.radius_secret);
      });
      if (missing.length > 0) {
        const ids = missing.map((p) => p.unique_id || p.id).join(', ');
        throw new Error(`Missing vpn_ip/radius_client_ip/radius_secret for POP(s): ${ids}`);
      }

      const conf = buildFreeradiusClientsConf(pops || []);

      // Write in a local tmp path first (PM2 runs as ubuntu and cannot write to /etc directly).
      fs.mkdirSync(path.dirname(FREERADIUS_TMP_CLIENTS_PATH), { recursive: true });
      fs.writeFileSync(FREERADIUS_TMP_CLIENTS_PATH, conf, { encoding: 'utf8' });

      // 1. Garante que o diretÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rio de destino do FreeRADIUS exista no VPS
      const { error: mkdirError } = await execAsync(`sudo mkdir -p ${path.dirname(FREERADIUS_CLIENTS_PATH)}`);
      if (mkdirError) throw new Error(`Erro ao criar diretÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rio FreeRADIUS: ${mkdirError.stderr}`);

      // 2. Copia o arquivo temporÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio para o destino final no VPS
      await execAsync(`sudo cp ${FREERADIUS_CLIENTS_PATH} ${FREERADIUS_CLIENTS_PATH}.bak 2>/dev/null || true`);
      const { error: cpError } = await execAsync(`sudo cp ${FREERADIUS_TMP_CLIENTS_PATH} ${FREERADIUS_CLIENTS_PATH}`);
      if (cpError) throw new Error(`Erro ao copiar arquivo FreeRADIUS: ${cpError.stderr}`);

      // 3. Garante que o clients.conf principal inclua nosso arquivo
      // LÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âª o conteÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºdo do clients.conf principal do VPS
      const { stdout: mainClientsConfContent, error: catError } = await execAsync(`sudo cat ${FREERADIUS_MAIN_CLIENTS_CONF}`);
      if (catError) throw new Error(`Erro ao ler clients.conf: ${catError.stderr}`);

      if (!mainClientsConfContent.includes(FREERADIUS_INCLUDE_LINE)) {
        // Se a linha de include nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o existe, adiciona-a
        const includeLine = `$INCLUDE ${FREERADIUS_CLIENTS_PATH}`;
        const { error: grepError } = await execAsync(`sudo /bin/grep -Fqx ${shellQuote(includeLine)} ${FREERADIUS_MAIN_CLIENTS_CONF}`);
        if (grepError) {
          const { error: teeError } = await execAsync(`printf '%s\\n' ${shellQuote(includeLine)} | sudo /usr/bin/tee -a ${FREERADIUS_MAIN_CLIENTS_CONF} >/dev/null`);
          if (teeError) throw new Error(`Erro ao adicionar include: ${teeError.stderr}`);
        }
      }

      // 4. Valida e recarrega FreeRADIUS
      const { error: validateError, stdout: validateOut, stderr: validateErr } = await execAsync(`sudo ${FREERADIUS_VALIDATE_CMD}`, 60000);
      if (validateError) throw new Error(`ValidaÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o FreeRADIUS falhou: ${validateErr || validateOut}`);

      const { error: reloadError, stdout: reloadOut, stderr: reloadErr } = await execAsync(`sudo ${FREERADIUS_RELOAD_CMD}`, 60000);
      if (reloadError) {
        const { error: restartError, stdout: restartOut, stderr: restartErr } = await execAsync(`sudo ${FREERADIUS_RESTART_CMD}`, 60000);
        if (restartError) throw new Error(`Recarga FreeRADIUS falhou: ${restartErr || restartOut || reloadErr || reloadOut}`);
      }

    } catch (err) {
      console.error("ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao sincronizar clientes FreeRADIUS:", err.message);
      await registerSystemLog(
        "error",
        "FreeRADIUS Sync",
        "Erro ao sincronizar clientes FreeRADIUS",
        { error: err.message, stack: err.stack }
      );
      return { ok: false, error: err.message };
    } finally {
      freeradiusSyncInFlight = null;
    }
    console.log(`[FreeRADIUS] clients synced successfully.`);
    return { ok: true };
  })();

  return freeradiusSyncInFlight;
}
// Revogar acesso - remove IP Binding do MikroTik
async function revokeAccess(macAddress, popIp = '192.168.32.1', apiUser = null, apiPass = null, popId = null) {
  if (!RouterOSAPI) {
    console.warn('ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã‚Â¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¸Ãƒâ€šÃ‚Â revokeAccess: node-routeros nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o disponÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­vel');
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
      throw new Error('Credenciais da API MikroTik nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o disponÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­veis');
    }

    const conn = new RouterOSAPI({ host: popIp, user: username, password, port: 8728, timeout: 10 });
    await conn.connect();
    const bindings = await conn.write('/ip/hotspot/ip-binding/print', [`?mac-address=${macAddress}`]);

    for (const binding of bindings || []) {
      await conn.write('/ip/hotspot/ip-binding/remove', [`=.id=${binding['.id']}`]);
    }

    const removeRows = async (printPath, removePath, query = [`?mac-address=${macAddress}`], onlyAutoUser = false) => {
      try {
        const rows = await conn.write(printPath, query);
        for (const row of rows || []) {
          if (onlyAutoUser) {
            const comment = String(row.comment || '');
            if (row.name !== macAddress && !comment.includes('MS-TELECOM-AUTO')) continue;
          }
          await conn.write(removePath, [`=.id=${row['.id']}`]);
        }
      } catch (_err) {}
    };

    await removeRows('/ip/hotspot/active/print', '/ip/hotspot/active/remove');
    await removeRows('/ip/hotspot/cookie/print', '/ip/hotspot/cookie/remove');
    await removeRows('/ip/hotspot/host/print', '/ip/hotspot/host/remove');
    await removeRows('/ip/hotspot/user/print', '/ip/hotspot/user/remove', [`?name=${macAddress}`], true);

    await conn.close();
    return true;
  } catch (error) {
    console.error(`ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Falha ao revogar acesso para ${macAddress}:`, error.message);
    return false;
  }
}

// Autorizar acesso - IP Binding com type=bypassed + RADIUS
async function authorizeAccess(macAddress, popIp = '192.168.32.1', apiUser = null, apiPass = null, popId = null, durationMinutes = 15, speedMbps = null, planName = 'free_trial', durationSeconds = null) {
  macAddress = normalizeMac(macAddress);
  if (!macAddress) return { success: false, viaApi: false, viaRadius: false, errors: ['MAC invalido'] };

  const accessPlan = String(planName || '').toLowerCase();
  const isVipAccess = accessPlan === 'vip' || accessPlan === 'prime_access';
  let viaApi = false;
  let viaRadius = false;
  const errors = [];

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

  try {
    const nowIso = new Date().toISOString();
    const sessionTimeoutSeconds = isVipAccess ? null : (
      Number.isFinite(Number(durationSeconds)) && Number(durationSeconds) > 0
        ? Math.floor(Number(durationSeconds))
        : Math.max(10, Math.floor(Number(durationMinutes || 0) * 60))
    );
    const expiresAt = isVipAccess ? null : new Date(Date.now() + sessionTimeoutSeconds * 1000).toISOString();

    const upsertRadiusReply = async (payload) => {
      const attempt = await supabase.from('radius_replies').upsert(payload, { onConflict: 'username,attribute' });
      if (!attempt.error) return;

      const msg = String(attempt.error.message || '');
      if (msg.includes('no unique or exclusion constraint') || msg.includes('ON CONFLICT')) {
        const del = await supabase
          .from('radius_replies')
          .delete()
          .eq('username', payload.username)
          .eq('attribute', payload.attribute);
        if (del.error) throw del.error;

        const ins = await supabase.from('radius_replies').insert(payload);
        if (ins.error) throw ins.error;
        return;
      }

      throw attempt.error;
    };

    await upsertRadiusReply({
      username: macAddress,
      attribute: 'Cleartext-Password',
      op: ':=',
      value: macAddress,
      plan_name: planName,
      status: 'active',
      expires_at: expiresAt,
      updated_at: nowIso
    });

    if (isVipAccess) {
      await supabase.from('radius_replies').delete().eq('username', macAddress).eq('attribute', 'Session-Timeout');
      await supabase.from('radius_replies').delete().eq('username', macAddress).eq('attribute', 'Mikrotik-Group');
    } else {
      await upsertRadiusReply({
        username: macAddress,
        attribute: 'Session-Timeout',
        op: ':=',
        value: String(sessionTimeoutSeconds),
        plan_name: planName,
        status: 'active',
        expires_at: expiresAt,
        updated_at: nowIso
      });

      if (popId) {
        await upsertRadiusReply({
          username: macAddress,
          attribute: 'Mikrotik-Group',
          op: ':=',
          value: `ms-user-profile-${popId}`,
          plan_name: planName,
          status: 'active',
          expires_at: expiresAt,
          updated_at: nowIso
        });
      }
    }

    viaRadius = true;
  } catch (error) {
    errors.push(`RADIUS: ${error.message}`);
  }

  return { success: viaApi || viaRadius, viaApi, viaRadius, errors };
}

// Creates/updates a basic user row for a MAC so the device appears in the admin panel.
// Creates/updates a basic user row for a MAC so the device appears in the admin panel.
async function findOrCreateHotspotUser({ macAddress, ipAddress = null, planName = 'free_trial', status = 'trial', popId = null, expiresAt = null }) {
  const now = new Date().toISOString();
  const cleanMac = normalizeMac(macAddress);
  if (!cleanMac) throw new Error('macAddress is required');

  // `users.hotspot_id` is bigint in some deployments; only set it when popId is numeric.
  const hotspotId = popId && /^\d+$/.test(String(popId)) ? parseInt(String(popId), 10) : null;

  const { data: existing, error: findErr } = await supabase
    .from('users')
    .select('*')
    .in('mac_address', getMacVariants(cleanMac))
    .limit(1)
    .maybeSingle();

  if (findErr) throw findErr;

  const base = {
    username: cleanMac,
    mac_address: cleanMac,
    updated_at: now
  };

  // Optional fields (may not exist in every schema).
  const optional = {
    ...(expiresAt ? { expires_at: expiresAt } : {}),
    ...(hotspotId ? { hotspot_id: hotspotId } : {}),
    ...(ipAddress ? { last_ip: ipAddress } : {}),
    last_seen_at: now
  };

  const stripUnknownColumn = (payload, message) => {
    const m = String(message || '');
    const match = m.match(/column "([^"]+)"/i) || m.match(/Could not find the '([^']+)' column/i);
    if (!match) return payload;
    const col = match[1];
    if (Object.prototype.hasOwnProperty.call(payload, col)) {
      const { [col]: _removed, ...rest } = payload;
      return rest;
    }
    return payload;
  };

  if (existing) {
    // DO NOT overwrite manual name or active plan status if it's already set
    const isManual = existing.name && !existing.name.startsWith('Device ');
    const hasActivePlan = (existing.status === 'active' || existing.status === 'paid' || existing.status === 'vip') && 
                         existing.plan_name && 
                         existing.plan_name !== 'free_trial' &&
                         (!existing.expires_at || new Date(existing.expires_at) > new Date());

    let updatePayload = { 
      ...base, 
      ...optional,
      name: isManual ? existing.name : `Device ${cleanMac}`,
      status: hasActivePlan ? existing.status : (status || existing.status || 'trial'),
      plan_name: hasActivePlan ? existing.plan_name : (planName || existing.plan_name || 'free_trial')
    };
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

  let insertPayload = {
    ...base,
    ...optional,
    name: `Device ${cleanMac}`,
    status: status || 'trial',
    plan_name: planName || 'free_trial',
    created_at: now
  };
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
function firstFiniteNumber(...values) {
  for (const value of values) {
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return null;
}

function normalizeFreeTrialConfig(value = {}) {
  const durationRaw = firstFiniteNumber(
    value.duration_seconds,
    value.duration_minutes !== undefined ? Number(value.duration_minutes) * 60 : undefined,
    900
  );
  const cooldownRaw = firstFiniteNumber(
    value.cooldown_seconds,
    value.cooldown_minutes !== undefined ? Number(value.cooldown_minutes) * 60 : undefined,
    value.cooldown_hours !== undefined ? Number(value.cooldown_hours) * 3600 : undefined,
    value.reuse_cooldown_hours !== undefined ? Number(value.reuse_cooldown_hours) * 3600 : undefined,
    86400
  );

  return {
    enabled: value.enabled === true,
    duration_seconds: Math.max(10, Math.floor(durationRaw || 900)),
    cooldown_seconds: Math.max(0, Math.floor(cooldownRaw || 0))
  };
}

async function getFreeTrialConfig() {
  try {
    const { data, error } = await supabase.from('settings').select('value').eq('key', 'free_trial').maybeSingle();
    if (error) throw error;
    return normalizeFreeTrialConfig(data?.value || {});
  } catch (error) {
    await registerSystemLog('error', 'free_trial', 'Erro ao carregar configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o de teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis', { error: error.message });
    return normalizeFreeTrialConfig({ enabled: false });
  }
}

function isActivePaidUser(user) {
  if (!user) return false;
  const status = String(user.status || '').toLowerCase();
  const planName = String(user.plan_name || '').toLowerCase();
  const expiresAt = user.expires_at ? new Date(user.expires_at).getTime() : null;
  const hasFutureExpiry = expiresAt && expiresAt > Date.now();
  const activeStatus = ['active', 'paid', 'vip'].includes(status);
  const paidPlan = planName && planName !== 'free_trial' && planName !== 'trial' && planName !== 'teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis';
  return (hasFutureExpiry || activeStatus) && paidPlan;
}

function getTrialCooldownUntil(record, cfg) {
  if (!record) return null;
  const configuredCooldown = Math.floor(Number(cfg.cooldown_seconds ?? 0));
  const storedCooldown = Math.floor(Number(record.cooldown_seconds ?? 0));
  const cooldownSeconds = Math.max(0, Number.isFinite(configuredCooldown) && configuredCooldown > 0 ? configuredCooldown : storedCooldown);
  if (cooldownSeconds <= 0) return null;

  // Reuso deve seguir a configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o atual do painel. NÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o use cooldown_until antigo
  // quando existe expires_at, pois ele pode ter sido gravado com outra configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o.
  if (record.expires_at) return new Date(new Date(record.expires_at).getTime() + cooldownSeconds * 1000).toISOString();

  const lastUsed = record.last_used_at || record.used_at || record.first_used_at || record.created_at || null;
  if (!lastUsed) return record.cooldown_until || null;

  const configuredDuration = Math.floor(Number(cfg.duration_seconds ?? 0));
  const storedDuration = Math.floor(Number(record.duration_seconds ?? 0));
  const durationSeconds = Math.max(0, Number.isFinite(configuredDuration) && configuredDuration > 0 ? configuredDuration : storedDuration);
  return new Date(new Date(lastUsed).getTime() + (durationSeconds + cooldownSeconds) * 1000).toISOString();
}

function isTrialSessionRecord(session) {
  if (!session) return false;
  const planName = String(session.plan_name || '').toLowerCase();
  const status = String(session.status || '').toLowerCase();
  if (planName && planName !== 'free_trial' && planName !== 'trial') return false;
  return planName === 'free_trial' || planName === 'trial' || status === 'trial' || session.access_granted === true;
}

async function getLastTrialSession(macVariants) {
  const { data, error } = await supabase
    .from('hotspot_sessions')
    .select('*')
    .in('mac_address', macVariants)
    .or('plan_name.eq.free_trial,plan_name.eq.trial,status.eq.trial,access_granted.eq.true')
    .order('expires_at', { ascending: false })
    .limit(10);

  if (error) throw error;
  return (data || []).find(isTrialSessionRecord) || null;
}

function removeMissingColumnFromPayload(payload, error) {
  const message = String(error?.message || error?.details || error?.hint || '');
  const match = message.match(/column "([^"]+)"/i) || message.match(/Could not find the '([^']+)' column/i);
  if (!match || !Object.prototype.hasOwnProperty.call(payload, match[1])) return null;
  const { [match[1]]: _removed, ...next } = payload;
  return next;
}

async function saveHotspotSession(payload) {
  const cleanMac = normalizeMac(payload?.mac_address);
  if (!cleanMac) return { error: new Error('mac_address is required') };

  let existing = null;
  try {
    const { data } = await supabase
      .from('hotspot_sessions')
      .select('id')
      .in('mac_address', getMacVariants(cleanMac))
      .eq('status', 'active')
      .order('updated_at', { ascending: false })
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();
    existing = data || null;
  } catch (_error) {}

  let current = { ...payload, mac_address: cleanMac };
  delete current.pop_name;
  delete current.pop_location;
  delete current.last_pop_name;
  delete current.last_pop_location;
  delete current.pop_unique_id;
  delete current.hotspot;
  for (let i = 0; i < 8; i++) {
    const result = existing?.id
      ? await supabase.from('hotspot_sessions').update({ ...current, updated_at: current.updated_at || new Date().toISOString() }).eq('id', existing.id)
      : await supabase.from('hotspot_sessions').insert(current);

    if (!result.error) return result;
    const next = removeMissingColumnFromPayload(current, result.error);
    if (!next) return result;
    current = next;
  }

  return { error: new Error('Failed to save hotspot session') };
}

async function handleFreeTrialAccess({ macAddress, ipAddress = null, popId = null, popIp = null }) {
  const cleanMac = normalizeMac(macAddress);
  if (!cleanMac) return { ok: false, status: 400, body: { error: 'MAC ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â© obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rio', reason: 'missing_mac' } };

  const nowIso = new Date().toISOString();
  const cfg = await getFreeTrialConfig();
  const durationSeconds = Math.max(10, Math.floor(Number(cfg.duration_seconds || 900)));
  const cooldownSeconds = Math.max(0, Math.floor(Number(cfg.cooldown_seconds || 0)));
  const expiresAtDate = new Date(Date.now() + durationSeconds * 1000);
  const expiresAt = expiresAtDate.toISOString();
  const cooldownUntil = new Date(expiresAtDate.getTime() + cooldownSeconds * 1000).toISOString();
  const popRef = popId || null;
  const popContext = await resolvePopContext(popRef, popIp || ipAddress || null);
  const effectivePopId = popContext.pop_id || popId || null;
  const effectivePopIp = popContext.pop_ip || popIp || ipAddress || null;

  if (!popRef) {
    console.warn('[free_trial] missing POP ref in payload', {
      mac_address: cleanMac,
      pop_id: null,
      pop: null,
      pop_unique_id: null,
      hotspot: null
    });
    await registerSystemLog('warning', 'free_trial', 'Payload sem identificador de POP', {
      mac_address: cleanMac,
      pop_id: null,
      pop: null,
      pop_unique_id: null,
      hotspot: null
    });
  }

  if (!cfg.enabled) return { ok: false, status: 403, body: { error: 'Teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis desativado', reason: 'trial_disabled' } };

  try {
    const { data: user } = await supabase.from('users').select('*').in('mac_address', getMacVariants(cleanMac)).limit(1).maybeSingle();
    if (isActivePaidUser(user)) {
      const planName = user.plan_name || 'Premium';
      const planExpiresAt = user.expires_at || null;
      const durationForPlan = planExpiresAt ? Math.max(10, Math.ceil((new Date(planExpiresAt).getTime() - Date.now()) / 1000)) : 30 * 24 * 60 * 60;
      const { data: plan } = await supabase.from('plans').select('*').eq('name', planName).maybeSingle();
      await authorizeAccess(cleanMac, effectivePopIp || '192.168.32.1', null, null, effectivePopId || user.hotspot_id || null, Math.ceil(durationForPlan / 60), plan?.speed_mbps || 10, planName, durationForPlan);
      await saveHotspotSession({
        ...(user?.id ? { user_id: user.id } : {}),
        mac_address: cleanMac,
        access_granted: true,
        status: 'active',
        expires_at: planExpiresAt,
        plan_name: planName,
        ...(effectivePopId ? { pop_id: effectivePopId } : {}),
        ...(effectivePopIp ? { pop_ip: effectivePopIp } : {}),
        created_at: nowIso,
        updated_at: nowIso
      });
      return { ok: true, status: 200, body: { message: 'Plano ativo encontrado. Liberando acesso...', expires_at: planExpiresAt, reason: 'manual_plan_active', show_free_trial: false } };
    }
  } catch (error) {
    await registerSystemLog('error', 'free_trial', 'Erro ao verificar plano ativo antes do teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis', { mac: cleanMac, error: error.message });
  }

  try {
    const { data: session } = await supabase
      .from('hotspot_sessions')
      .select('*')
      .in('mac_address', getMacVariants(cleanMac))
      .eq('status', 'active')
      .gt('expires_at', nowIso)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (session) {
      if (effectivePopId && (!session.pop_id || !session.pop_ip)) {
        await saveHotspotSession({
          ...session,
          pop_id: effectivePopId,
          ...(effectivePopIp ? { pop_ip: effectivePopIp } : {}),
          updated_at: nowIso
        });
      }
      return { ok: true, status: 200, body: { message: 'Acesso jÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡ ativo', expires_at: session.expires_at, reason: 'active_session', show_free_trial: false } };
    }
  } catch (error) {
    await registerSystemLog('error', 'free_trial', 'Erro ao verificar sessÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o ativa de teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis', { mac: cleanMac, error: error.message });
  }

  let previousTrial = null;
  let freeTrialLookupFailed = false;
  try {
    const { data: ft } = await supabase
      .from('free_trials')
      .select('*')
      .in('mac_address', getMacVariants(cleanMac))
      .order('updated_at', { ascending: false })
      .limit(1)
      .maybeSingle();
    previousTrial = ft || null;

    const effectiveUntil = getTrialCooldownUntil(previousTrial, { duration_seconds: durationSeconds, cooldown_seconds: cooldownSeconds });

    if (effectiveUntil && new Date(effectiveUntil).getTime() > Date.now()) {
      const retryAfterSeconds = Math.max(1, Math.ceil((new Date(effectiveUntil).getTime() - Date.now()) / 1000));
      await registerSystemLog('info', 'free_trial', 'Teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis negado por cooldown', { mac: cleanMac, retry_after_seconds: retryAfterSeconds, cooldown_until: effectiveUntil });
      return { ok: false, status: 429, body: { success: false, error: 'Teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis jÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡ utilizado', reason: 'cooldown', retry_after_seconds: retryAfterSeconds, show_free_trial: false } };
    }
  } catch (error) {
    freeTrialLookupFailed = true;
    await registerSystemLog('error', 'free_trial', 'Erro ao verificar cooldown de teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis', { mac: cleanMac, error: error.message });
  }

  try {
    const lastTrialSession = await getLastTrialSession(getMacVariants(cleanMac));
    const sessionCooldownUntil = getTrialCooldownUntil(lastTrialSession, { duration_seconds: durationSeconds, cooldown_seconds: cooldownSeconds });
    if (sessionCooldownUntil && new Date(sessionCooldownUntil).getTime() > Date.now()) {
      const retryAfterSeconds = Math.max(1, Math.ceil((new Date(sessionCooldownUntil).getTime() - Date.now()) / 1000));
      await registerSystemLog('info', 'free_trial', 'Teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis negado por cooldown de sessÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o', { mac: cleanMac, retry_after_seconds: retryAfterSeconds, cooldown_until: sessionCooldownUntil });
      return { ok: false, status: 429, body: { success: false, error: 'Teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis jÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡ utilizado', reason: 'cooldown', retry_after_seconds: retryAfterSeconds, show_free_trial: false } };
    }
  } catch (error) {
    await registerSystemLog('error', 'free_trial', 'Erro ao verificar cooldown por sessÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o', { mac: cleanMac, error: error.message });
    if (freeTrialLookupFailed) {
      return { ok: false, status: 503, body: { success: false, error: 'Erro ao verificar cooldown do teste gratis', reason: 'cooldown_check_failed', show_free_trial: false } };
    }
  }

  const auth = await authorizeAccess(cleanMac, effectivePopIp || '192.168.32.1', null, null, effectivePopId, Math.ceil(durationSeconds / 60), 5, 'free_trial', durationSeconds);
  if (!auth.success) return { ok: false, status: 500, body: { error: 'Erro ao liberar RADIUS', reason: 'radius_error', details: auth.errors } };

  let user = null;
  try {
    user = await findOrCreateHotspotUser({ macAddress: cleanMac, ipAddress, planName: 'free_trial', status: 'trial', popId: effectivePopId, expiresAt });
  } catch (error) {
    await registerSystemLog('error', 'free_trial', 'RADIUS liberado, mas falhou ao criar/atualizar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio', { mac: cleanMac, error: error.message });
  }

  try {
    const sessionPayload = {
      ...(user?.id ? { user_id: user.id } : {}),
      mac_address: cleanMac,
      access_granted: true,
      status: 'active',
      expires_at: expiresAt,
      plan_name: 'free_trial',
      ...(effectivePopId ? { pop_id: effectivePopId } : {}),
      ...(effectivePopIp ? { pop_ip: effectivePopIp } : {}),
      created_at: nowIso,
      updated_at: nowIso
    };
    const { error: sessionErr } = await saveHotspotSession(sessionPayload);
    if (sessionErr) throw sessionErr;
  } catch (error) {
    await registerSystemLog('error', 'free_trial', 'RADIUS liberado, mas falhou ao gravar sessÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o', { mac: cleanMac, error: error.message });
  }

  try {
    const payload = {
      mac_address: cleanMac,
      first_used_at: previousTrial?.first_used_at || nowIso,
      last_used_at: nowIso,
      used_at: nowIso,
      cooldown_until: cooldownUntil,
      duration_seconds: durationSeconds,
      cooldown_seconds: cooldownSeconds,
      attempts: Number(previousTrial?.attempts || 0) + 1,
      expires_at: expiresAt,
      updated_at: nowIso,
      ...(effectivePopId ? { pop_id: effectivePopId } : {})
    };
    const up = await supabase.from('free_trials').upsert(payload, { onConflict: 'mac_address' });
    if (up.error) throw up.error;
  } catch (error) {
    await registerSystemLog('error', 'free_trial', 'RADIUS liberado, mas falhou ao gravar histÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rico de teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis', { mac: cleanMac, error: error.message });
  }

  await registerSystemLog('info', 'free_trial', 'Teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis liberado', { mac: cleanMac, expires_at: expiresAt, cooldown_until: cooldownUntil });
  return { ok: true, status: 200, body: { message: 'Acesso liberado', expires_at: expiresAt, user_id: user?.id || null, duration_seconds: durationSeconds, cooldown_seconds: cooldownSeconds, cooldown_until: cooldownUntil, show_free_trial: false } };
}
// ============================================================

setInterval(async () => {
  try {
    const now = new Date().toISOString();
    
    // 1. Limpar sessÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes expiradas
    const { data: expiredSessions } = await supabase.from('hotspot_sessions')
      .select('id, mac_address, pop_ip')
      .eq('status', 'active')
      .lt('expires_at', now);

    for (const session of expiredSessions || []) {
      if (session.mac_address) await revokeAccess(session.mac_address, session.pop_ip);
      await supabase.from('hotspot_sessions').update({ status: 'expired', updated_at: now }).eq('id', session.id);
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
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro no CRON de limpeza:', error.message);
  }
}, 60000); // Executa a cada 1 minuto

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“ ROTAS DE AUTENTICAÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢O (ADMIN)
// ============================================================

// Aliases legados (portuguÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âªs/curtos) -> padrÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o novo
app.post('/api/login', (req, res, next) => {
  // Encaminha para /api/auth/login
  req.url = '/api/auth/login';
  next();
});
app.post('/api/logout', authMiddleware, (req, res, next) => {
  req.url = '/api/auth/logout';
  next();
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'UsuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio e senha sÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rios' });

    const { data: admin, error } = await supabase.from('admins').select('*').eq('username', username).single();
    if (error || !admin) return res.status(401).json({ error: 'Credenciais invÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡lidas' });

    const passwordCheck = verifyPasswordHash(admin.password, password);
    if (!passwordCheck.ok) {
      return res.status(401).json({ error: 'Credenciais invÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡lidas' });
    }
    if (passwordCheck.legacySha256) {
      await supabase.from('admins').update({
        password: hashPassword(password),
        updated_at: new Date().toISOString()
      }).eq('id', admin.id);
    }

    const role = admin.role || 'admin';
    const token = jwt.sign({ id: admin.id, username: admin.username, role }, JWT_SECRET, { expiresIn: '24h' });
    
    await registerAuditLog(username, 'login', 'auth', 'Login realizado', getClientIp(req), req.headers['user-agent']);
    
    res.json({ token, user: { id: admin.id, username: admin.username, role } });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro no login:', err.message);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  await registerAuditLog(req.user.username, 'logout', 'auth', 'Logout realizado', getClientIp(req), req.headers['user-agent']);
  res.json({ message: 'Logout realizado com sucesso' });
});

// Alias legado
app.get('/api/perfil', authMiddleware, (req, res, next) => {
  req.url = '/api/profile';
  next();
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
    if (error || !admin) return res.status(404).json({ error: 'Admin nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });

    if (new_password) {
      if (!current_password) return res.status(400).json({ error: 'Senha atual obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³ria' });
      const currentCheck = verifyPasswordHash(admin.password, current_password);
      if (!currentCheck.ok) {
        return res.status(401).json({ error: 'Senha atual incorreta' });
      }
    }

    const updateData = { updated_at: new Date().toISOString() };
    if (username) updateData.username = username;
    if (Object.prototype.hasOwnProperty.call(req.body, 'email')) updateData.email = normalizeEmail(email);
    if (new_password) updateData.password = hashPassword(new_password);

    const { data, error: updateError } = await supabase
      .from('admins')
      .update(updateData)
      .eq('id', adminId)
      .select()
      .single();

    if (updateError) throw updateError;
    await registerAuditLog(admin.username, 'update', 'admin', 'Perfil atualizado', getClientIp(req), req.headers['user-agent']);
    res.json({ success: true, user: { id: data.id, username: data.username, email: data.email } });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao atualizar perfil:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar perfil' });
  }
});

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“Ãƒâ€šÃ‚Â¥ ROTAS DE USUÃƒÆ’Ã†â€™Ãƒâ€šÃ‚ÂRIOS (CLIENTES)
// ============================================================

// Listar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rios
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
    const enriched = await enrichUsersWithSessionInfo(data || []);
    res.json(enriched);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao listar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rios:', err.message);
    res.status(500).json({ error: 'Erro ao listar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rios' });
  }
});

// Criar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio
app.post('/api/users', authMiddleware, async (req, res) => {
  try {
    const { name, username, mac_address, phone, cpf, email, address, plan_id, plan_name, hotspot_id, status, is_vip } = req.body;
    const cleanMac = normalizeMac(mac_address);
    const now = new Date();
    let plan = null;
    let expiresAt = null;

    if (plan_id) {
      const { data: planData, error: planError } = await supabase.from('plans').select('*').eq('id', plan_id).maybeSingle();
      if (planError) throw planError;
      if (!planData) return res.status(404).json({ error: 'Plano nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });
      plan = planData;
      expiresAt = new Date(now.getTime() + Number(plan.duration_days || 30) * 24 * 60 * 60 * 1000).toISOString();
    }

    const normalizedCpf = normalizeCpf(cpf);
    const normalizedEmail = normalizeEmail(email);
    if (normalizedCpf && await findDuplicateUserField('cpf', normalizedCpf)) {
      return res.status(409).json({ error: 'CPF ja cadastrado em outro cliente', reason: 'duplicate_cpf' });
    }
    if (normalizedEmail && await findDuplicateUserField('email', normalizedEmail)) {
      return res.status(409).json({ error: 'E-mail ja cadastrado em outro cliente', reason: 'duplicate_email' });
    }

    const payload = {
      name,
      username: username || cleanMac || undefined,
      mac_address: cleanMac || null,
      phone,
      cpf: normalizedCpf,
      email: normalizedEmail,
      address,
      plan_id: plan ? plan.id : (plan_id || null),
      plan_name: plan ? plan.name : (plan_name || null),
      hotspot_id,
      status: plan ? 'active' : (status || 'inactive'),
      is_vip: is_vip || false,
      ...(expiresAt ? { expires_at: expiresAt } : {}),
      created_at: now.toISOString(),
      updated_at: now.toISOString()
    };

    const { data, error } = await supabase.from('users').insert(payload).select().single();
    if (error) throw error;

    if (cleanMac && plan) {
      const durationSeconds = Math.max(10, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 1000));
      await authorizeAccess(cleanMac, '192.168.32.1', null, null, hotspot_id, Math.ceil(durationSeconds / 60), plan.speed_mbps || 10, plan.name, durationSeconds);
    }

    await registerAuditLog(req.user.username, 'create', 'user', `UsuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio criado: ${name || cleanMac || data.id}`, getClientIp(req), req.headers['user-agent'], { user_id: data.id, plan_id: plan?.id || null });
    res.status(201).json(data);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao criar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio:', err.message);
    if (String(err.message || '').includes('users_cpf_key')) {
      return res.status(409).json({ error: 'CPF ja cadastrado em outro cliente', reason: 'duplicate_cpf' });
    }
    if (String(err.message || '').includes('users_email_key')) {
      return res.status(409).json({ error: 'E-mail ja cadastrado em outro cliente', reason: 'duplicate_email' });
    }
    res.status(500).json({ error: 'Erro ao criar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio' });
  }
});

// Atualizar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio
app.put('/api/users/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const body = req.body || {};
    const updateData = { ...body, updated_at: new Date().toISOString() };
    delete updateData.id;
    delete updateData.created_at;
    Object.keys(updateData).forEach((key) => {
      if (updateData[key] === undefined || Number.isNaN(updateData[key])) delete updateData[key];
    });

    if (Object.prototype.hasOwnProperty.call(body, 'mac_address')) {
      const cleanMac = normalizeMac(body.mac_address);
      updateData.mac_address = cleanMac || null;
      if (!body.username && cleanMac) updateData.username = cleanMac;
    }

    if (Object.prototype.hasOwnProperty.call(body, 'cpf')) {
      const normalizedCpf = normalizeCpf(body.cpf);
      if (normalizedCpf && await findDuplicateUserField('cpf', normalizedCpf, id)) {
        return res.status(409).json({ error: 'CPF ja cadastrado em outro cliente', reason: 'duplicate_cpf' });
      }
      updateData.cpf = normalizedCpf;
    }

    if (Object.prototype.hasOwnProperty.call(body, 'email')) {
      const normalizedEmail = normalizeEmail(body.email);
      if (normalizedEmail && await findDuplicateUserField('email', normalizedEmail, id)) {
        return res.status(409).json({ error: 'E-mail ja cadastrado em outro cliente', reason: 'duplicate_email' });
      }
      updateData.email = normalizedEmail;
    }

    let plan = null;
    if (Object.prototype.hasOwnProperty.call(body, 'plan_id') && body.plan_id !== '' && body.plan_id !== null && body.plan_id !== undefined) {
      const planId = Number(body.plan_id);
      if (!Number.isFinite(planId)) return res.status(400).json({ error: 'Plano invÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡lido' });

      const { data: planData, error: planError } = await supabase.from('plans').select('*').eq('id', planId).maybeSingle();
      if (planError) throw planError;
      if (!planData) return res.status(404).json({ error: 'Plano nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });
      plan = planData;
      const days = Number(plan.duration_days || 30);
      updateData.expires_at = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
      updateData.status = 'active';
      updateData.plan_name = plan.name;
      updateData.plan_id = plan.id;
    } else {
      delete updateData.plan_id;
      if (updateData.plan_name === '' || updateData.plan_name === null) delete updateData.plan_name;
      if (updateData.status === '' || updateData.status === null) delete updateData.status;
      if (updateData.expires_at === '' || updateData.expires_at === null) delete updateData.expires_at;
    }

    const { data, error } = await supabase.from('users').update(updateData).eq('id', id).select().single();
    if (error) throw error;

    if (data.mac_address && data.status === 'active' && data.plan_name && data.plan_name !== 'free_trial') {
      const activePlan = plan || (await supabase.from('plans').select('*').eq('name', data.plan_name).maybeSingle()).data;
      const durationSeconds = data.expires_at
        ? Math.max(10, Math.ceil((new Date(data.expires_at).getTime() - Date.now()) / 1000))
        : Number(activePlan?.duration_days || 30) * 24 * 60 * 60;
      await authorizeAccess(data.mac_address, '192.168.32.1', null, null, data.hotspot_id, Math.ceil(durationSeconds / 60), activePlan?.speed_mbps || 10, data.plan_name, durationSeconds);
    }

    await registerAuditLog(req.user.username, 'update', 'user', `UsuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio atualizado: ${id}`, getClientIp(req), req.headers['user-agent'], { user_id: id, plan_id: data.plan_id || null });
    res.json(data);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao atualizar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio:', err.message);
    await registerSystemLog('error', 'users', 'Erro ao atualizar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio', { user_id: req.params.id, error: err.message }, getClientIp(req), req.headers['user-agent']);
    if (String(err.message || '').includes('users_cpf_key')) {
      return res.status(409).json({ error: 'CPF ja cadastrado em outro cliente', reason: 'duplicate_cpf' });
    }
    if (String(err.message || '').includes('users_email_key')) {
      return res.status(409).json({ error: 'E-mail ja cadastrado em outro cliente', reason: 'duplicate_email' });
    }
    res.status(500).json({ error: err.message || 'Erro ao atualizar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio' });
  }
});
// Deletar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio
app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: user } = await supabase.from('users').select('*').eq('id', id).maybeSingle();
    const disconnect = user ? await revokeAndDisconnectUser(user, 'deleted') : { radius_revoked: false, disconnect_status: 'not_applicable', disconnect_method: 'none' };

    const { error } = await supabase.from('users').delete().eq('id', id);
    if (error) throw error;

    await registerAuditLog(req.user.username, 'delete', 'user', `UsuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio removido: ${id}`, getClientIp(req), req.headers['user-agent'], { user_id: id, mac_address: user?.mac_address || null, pop_id: disconnect.pop_id || user?.pop_id || user?.last_pop_id || null });
    res.json({
      success: true,
      user_id: id,
      mac_address: user?.mac_address || null,
      pop_id: disconnect.pop_id || user?.pop_id || user?.last_pop_id || null,
      blocked: false,
      deleted: true,
      radius_revoked: disconnect.radius_revoked,
      disconnect_status: disconnect.disconnect_status,
      disconnect_method: disconnect.disconnect_method,
      message: 'Usuario removido com sucesso'
    });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao deletar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio:', err.message);
    res.status(500).json({ error: 'Erro ao deletar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio' });
  }
});

// Renovar plano do usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio
app.post('/api/users/:id/renew', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { plan_id, duration_days } = req.body;

    const { data: plan, error: planError } = await supabase.from('plans').select('*').eq('id', plan_id).single();
    if (planError || !plan) return res.status(400).json({ error: 'Plano nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });

    const days = duration_days || plan.duration_days || 30;
    const expiresAt = new Date(Date.now() + Number(days) * 24 * 60 * 60 * 1000).toISOString();

    const { data, error } = await supabase.from('users').update({
      plan_id: plan_id, plan_name: plan.name, status: 'active',
      expires_at: expiresAt, updated_at: new Date().toISOString()
    }).eq('id', id).select().single();

    if (error) throw error;
    if (data.mac_address) {
      const durationSeconds = Math.max(10, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 1000));
      await authorizeAccess(data.mac_address, '192.168.32.1', null, null, data.hotspot_id, Math.ceil(durationSeconds / 60), plan.speed_mbps || 10, plan.name, durationSeconds);
    }
    await registerAuditLog(req.user.username, 'update', 'user', `Plano renovado: ${id}`, getClientIp(req), req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao renovar plano:', err.message);
    res.status(500).json({ error: 'Erro ao renovar plano' });
  }
});

// Bloquear usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio
app.post('/api/users/:id/block', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const now = new Date().toISOString();
    const preferred = { status: 'blocked', blocked_at: now, blocked_reason: req.body?.reason || null, updated_at: now };
    const fallback = { status: 'blocked', updated_at: now };
    const { data, error } = await safeUpdateWithFallback('users', id, preferred, fallback);
    if (error) throw error;
    const disconnect = await revokeAndDisconnectUser(data, 'blocked');
    await registerAuditLog(req.user.username, 'update', 'user', `UsuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio bloqueado: ${id}`, getClientIp(req), req.headers['user-agent'], { user_id: id, mac_address: data?.mac_address || null });
    res.json({
      success: true,
      user: data,
      user_id: id,
      mac_address: data?.mac_address || null,
      pop_id: disconnect.pop_id || data?.pop_id || data?.last_pop_id || null,
      blocked: true,
      deleted: false,
      radius_revoked: disconnect.radius_revoked,
      disconnect_status: disconnect.disconnect_status,
      disconnect_method: disconnect.disconnect_method,
      message: 'Usuario bloqueado'
    });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao bloquear usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio:', err.message);
    res.status(500).json({ error: 'Erro ao bloquear usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio' });
  }
});

// Desbloquear usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio
app.post('/api/users/:id/unblock', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase.from('users').update({ status: 'active', updated_at: new Date().toISOString() }).eq('id', id).select().single();
    if (error) throw error;
    await registerAuditLog(req.user.username, 'update', 'user', `UsuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio desbloqueado: ${id}`, getClientIp(req), req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao desbloquear usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio:', err.message);
    res.status(500).json({ error: 'Erro ao desbloquear usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio' });
  }
});

// Marcar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio como VIP
app.post('/api/users/:id/vip', authMiddleware, updatePrimeAccessHandler);

async function updatePrimeAccessHandler(req, res) {
  try {
    const { id } = req.params;
    const enabledValue = Object.prototype.hasOwnProperty.call(req.body || {}, 'enabled') ? req.body.enabled : req.body?.is_vip;
    const vipEnabled = enabledValue !== false;
    const { vip_notes = null } = req.body || {};
    const now = new Date().toISOString();
    const { data: current } = await supabase.from('users').select('*').eq('id', id).maybeSingle();

    const preferred = vipEnabled
      ? { is_vip: true, vip_since: now, vip_notes, status: 'active', expires_at: null, updated_at: now }
      : { is_vip: false, vip_since: null, vip_notes, updated_at: now };
    const fallback = vipEnabled
      ? { is_vip: true, status: 'active', expires_at: null, updated_at: now }
      : { is_vip: false, updated_at: now };

    if (!vipEnabled && String(current?.status || '').toLowerCase() !== 'blocked') {
      const validUntil = current?.expires_at ? new Date(current.expires_at).getTime() : 0;
      preferred.status = validUntil > Date.now() ? (current.status || 'active') : 'inactive';
      fallback.status = preferred.status;
    }

    const { data, error } = await safeUpdateWithFallback('users', id, preferred, fallback);
    if (error) throw error;

    if (data.mac_address && vipEnabled && String(data.status || '').toLowerCase() !== 'blocked') {
      await authorizeAccess(data.mac_address, '192.168.32.1', null, null, null, null, null, 'prime_access', null);
    } else if (data.mac_address && !vipEnabled) {
      await revokeRadiusAccess(data.mac_address);
    }

    await registerAuditLog(req.user.username, 'prime_access', 'user', `Acesso Prime atualizado: ${id}`, getClientIp(req), req.headers['user-agent'], { user_id: id, enabled: vipEnabled });
    res.json({ success: true, user: data, message: vipEnabled ? 'Cliente marcado como Acesso Prime' : 'Acesso Prime removido deste cliente' });
  } catch (err) {
    console.error('Erro ao atualizar Acesso Prime:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar Acesso Prime' });
  }
}

app.patch('/api/users/:id/vip', authMiddleware, updatePrimeAccessHandler);
app.patch('/api/users/:id/prime-access', authMiddleware, updatePrimeAccessHandler);

// Exportar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rios para CSV
app.get('/api/users/export', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*').order('created_at', { ascending: false });
    if (error) throw error;

    const headers = ['Nome', 'UsuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio', 'MAC', 'Telefone', 'CPF', 'Email', 'Plano', 'Status', 'Data Cadastro'];
    const rows = (data || []).map(u => [
      u.name || '', u.username || '', u.mac_address || '', u.phone || '', u.cpf || '', u.email || '', u.plan_name || '', u.status || '',
      u.created_at ? new Date(u.created_at).toLocaleDateString('pt-BR') : ''
    ]);

    const csv = [headers, ...rows].map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(';')).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename=users_${new Date().toISOString().slice(0, 10)}.csv`);
    res.send('\uFEFF' + csv);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao exportar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rios:', err.message);
    res.status(500).json({ error: 'Erro ao exportar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rios' });
  }
});

// Buscar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio por ID
app.get('/api/users/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: user, error: userError } = await supabase.from('users').select('*').eq('id', id).maybeSingle();
    if (userError || !user) return res.status(404).json({ error: 'UsuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });

    const { data: payments } = await supabase.from('payments').select('amount').eq('user_id', id).eq('status', 'approved');
    const totalSpent = (payments || []).reduce((sum, p) => sum + (Number(p.amount) || 0), 0);

    const { data: lastSession } = await supabase.from('hotspot_sessions').select('created_at').eq('user_id', id).order('created_at', { ascending: false }).limit(1).maybeSingle();

    const [enriched] = await enrichUsersWithSessionInfo([{ ...user, total_spent: totalSpent, last_access: lastSession?.created_at || user.last_seen_at || null }]);
    res.json(enriched || { ...user, total_spent: totalSpent, last_access: lastSession?.created_at || user.last_seen_at || null });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao buscar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio:', err.message);
    res.status(500).json({ error: 'Erro ao buscar usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio' });
  }
});



// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¹ ROTAS DE PLANOS
// ============================================================

// Listar planos
app.get('/api/plans', async (req, res) => {
  try {
    const { data, error } = await supabase.from('plans').select('*').order('price', { ascending: true });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao listar planos:', err.message);
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
    await registerAuditLog(req.user.username, 'create', 'plan', `Plano criado: ${name}`, getClientIp(req), req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao criar plano:', err.message);
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

    await registerAuditLog(req.user.username, 'update', 'plan', `Plano atualizado: ${id}`, getClientIp(req), req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao atualizar plano:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar plano' });
  }
});

// Deletar plano
app.delete('/api/plans/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('plans').delete().eq('id', id);
    if (error) throw error;

    await registerAuditLog(req.user.username, 'delete', 'plan', `Plano removido: ${id}`, getClientIp(req), req.headers['user-agent']);
    res.json({ message: 'Plano removido com sucesso' });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao deletar plano:', err.message);
    res.status(500).json({ error: 'Erro ao deletar plano' });
  }
});

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢Ãƒâ€šÃ‚Â³ ROTAS DE PAGAMENTOS
// ============================================================

// Listar pagamentos
app.get('/api/payments', authMiddleware, async (req, res) => {
  try {
    const { status, user_id, mac_address } = req.query;
    let query = supabase.from('payments').select('*, users(name, username)').order('created_at', { ascending: false });

    if (status) query = query.eq('status', status);
    if (user_id) query = query.eq('user_id', user_id);
    if (mac_address) query = query.in('user_mac', getMacVariants(mac_address));

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao listar pagamentos:', err.message);
    res.status(500).json({ error: 'Erro ao listar pagamentos' });
  }
});

// Gerar PIX (Mercado Pago)
app.post('/api/payments/generate-pix', paymentLimiter, async (req, res) => {
  try {
    const { mac_address, plan_id, plan_name, description, payment_id } = req.body;
    const cleanMac = normalizeMac(mac_address);
    if (!cleanMac || (!plan_id && !plan_name)) return res.status(400).json({ error: 'MAC e plano sÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rios' });

    let planQuery = supabase.from('plans').select('*');
    planQuery = plan_id ? planQuery.eq('id', plan_id) : planQuery.eq('name', plan_name);

    const { data: plan, error: planError } = await planQuery.limit(1).maybeSingle();
    if (planError) throw planError;
    if (!plan) return res.status(404).json({ error: 'Plano nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });
    if (plan.active === false || plan.status === 'inactive') return res.status(400).json({ error: 'Plano indisponÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­vel' });

    const planAmount = Number(plan.price);
    if (!Number.isFinite(planAmount) || planAmount <= 0) return res.status(400).json({ error: 'Plano sem valor vÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡lido' });

    const selectedPlanName = plan.name || plan_name || null;
    const paymentDescription = description || selectedPlanName || 'Plano WiFi';

    const MP_TOKEN = process.env.MERCADOPAGO_ACCESS_TOKEN || process.env.MP_ACCESS_TOKEN;
    if (!MP_TOKEN) return res.status(500).json({ error: 'Token do Mercado Pago nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o configurado' });

    const externalReference = `HS-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    const mpResponse = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${MP_TOKEN}`,
        'X-Idempotency-Key': externalReference
      },
      body: JSON.stringify({
        transaction_amount: planAmount,
        description: paymentDescription,
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
      user_mac: cleanMac,
      plan_name: selectedPlanName,
      amount: planAmount,
      description: paymentDescription,
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
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao gerar PIX:', err.message);
    res.status(500).json({ error: 'Erro ao gerar pagamento PIX' });
  }
});
// Verificar status de pagamento
app.get('/api/check-payment', async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const { external_reference, mercado_pago_id, mac, mac_address } = req.query;
    const macFilter = normalizeMac(mac || mac_address || '');

    if (macFilter) {
      const { data: payment, error } = await supabase
        .from('payments')
        .select('*')
        .in('user_mac', getMacVariants(macFilter))
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (error) throw error;
      return res.json(payment || { status: 'not_found' });
    }

    if (!external_reference && !mercado_pago_id) return res.status(400).json({ error: 'ReferÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âªncia, ID ou MAC do pagamento necessÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio' });

    let query = supabase.from('payments').select('*');
    if (external_reference) query = query.eq('external_reference', external_reference);
    else query = query.eq('mercado_pago_id', mercado_pago_id);

    const { data: payment, error } = await query.single();
    if (error || !payment) return res.status(404).json({ error: 'Pagamento nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });

    res.json(payment);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao verificar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao verificar pagamento' });
  }
});

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸Ãƒâ€¦Ã‚Â½Ãƒâ€¦Ã‚Â¸ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¸Ãƒâ€šÃ‚Â ROTAS DE VOUCHERS
// ============================================================

// Listar vouchers
app.get('/api/vouchers', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('vouchers').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao listar vouchers:', err.message);
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
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao criar vouchers:', err.message);
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
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao atualizar voucher:', err.message);
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
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao deletar voucher:', err.message);
    res.status(500).json({ error: 'Erro ao deletar voucher' });
  }
});

// Validar voucher (pÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºblico)
// Alias legado PT
app.post('/api/vouchers/validate', voucherLimiter, async (req, res) => {
  try {
    const { code, mac_address } = req.body;
    const cleanMac = normalizeMac(mac_address);
    const { data: voucher, error } = await supabase.from('vouchers').select('*').eq('code', String(code).toUpperCase()).eq('status', 'active').maybeSingle();
    if (error || !voucher) return res.status(404).json({ error: 'Voucher invÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡lido ou jÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡ utilizado' });

    await supabase.from('vouchers').update({
      status: 'used', used: true, used_at: new Date().toISOString(),
      mac_address: cleanMac || null, updated_at: new Date().toISOString()
    }).eq('id', voucher.id);

    res.json({ valid: true, plan_name: voucher.plan_name, duration_hours: voucher.duration_hours });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao validar voucher:', err.message);
    res.status(500).json({ error: 'Erro ao validar voucher' });
  }
});

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œÃƒâ€¦Ã‚Â  ROTAS DE ESTATÃƒÆ’Ã†â€™Ãƒâ€šÃ‚ÂSTICAS E DASHBOARD
// ============================================================

// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂÃƒâ€šÃ‚Â§ HELPERS (compatibilidade / schema flexÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­vel)
function isMissingColumnError(err) {
  const msg = (err && (err.message || err.details || err.hint)) ? `${err.message || ''} ${err.details || ''} ${err.hint || ''}` : '';
  return /Could not find the '.+' column/i.test(msg) || /column .* does not exist/i.test(msg);
}

async function safeInsertWithFallback(table, preferredPayload, fallbackPayload) {
  let result = await supabase.from(table).insert(preferredPayload).select().single();

  // Se o payload preferido falhar (coluna ausente, tipo invÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡lido, etc), tenta o fallback.
  // Isso evita 500 quando o frontend envia campos "extras" que nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o existem na tabela.
  if (result.error && fallbackPayload) {
    result = await supabase.from(table).insert(fallbackPayload).select().single();
  }

  return result;
}

async function safeUpdateWithFallback(table, id, preferredPayload, fallbackPayload = null) {
  let result = await supabase.from(table).update(preferredPayload).eq('id', id).select().single();
  if (result.error && fallbackPayload) {
    result = await supabase.from(table).update(fallbackPayload).eq('id', id).select().single();
  }
  return result;
}

function numberOrZero(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function normalizeTrafficBytes(record = {}) {
  const rx = numberOrZero(record.rx_bytes ?? record.bytes_in ?? record.input_octets ?? record.acct_input_octets);
  const tx = numberOrZero(record.tx_bytes ?? record.bytes_out ?? record.output_octets ?? record.acct_output_octets);
  const total = numberOrZero(record.total_bytes ?? record.traffic_bytes ?? record.bytes_total) || rx + tx;
  return { rx_bytes: rx, tx_bytes: tx, total_bytes: total };
}

function formatBytes(bytes) {
  let value = numberOrZero(bytes);
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 2)} ${units[unit]}`;
}

function isNotExpired(expiresAt) {
  if (!expiresAt) return true;
  const ms = new Date(expiresAt).getTime();
  return !Number.isFinite(ms) || ms > Date.now();
}

function deriveClientOperationalStatus(user = {}) {
  const raw = String(user.status || '').toLowerCase();
  if (raw === 'blocked' || user.blocked === true) return 'blocked';
  if (user.is_vip === true || raw === 'vip') return 'vip';
  const expired = user.expires_at && !isNotExpired(user.expires_at);
  if (expired || raw === 'inactive' || raw === 'expired') return 'inactive';
  if (['active', 'paid', 'trial'].includes(raw)) return 'active';
  return 'inactive';
}

function sessionPopId(session = {}) {
  return session.pop_id || session.last_pop_id || session.popId || null;
}

function sessionLocalIp(session = {}) {
  return session.local_ip || session.ip_address || session.client_ip || session.framed_ip_address || session.ip || null;
}

function sessionTime(session = {}) {
  return session.started_at || session.created_at || session.updated_at || null;
}

async function getLatestSessionsByUsers(users = []) {
  const byKey = new Map();
  const userIds = [...new Set(users.map(u => u.id).filter(Boolean))];
  const macs = [...new Set(users.flatMap(u => getMacVariants(u.mac_address || u.username || '')).filter(Boolean))];
  const rows = [];

  if (userIds.length) {
    const { data, error } = await supabase
      .from('hotspot_sessions')
      .select('*')
      .in('user_id', userIds)
      .order('updated_at', { ascending: false })
      .order('created_at', { ascending: false })
      .limit(1000);
    if (!error) rows.push(...(data || []));
    else await registerSystemLog('warning', 'users', 'Falha ao buscar sessoes por user_id', { error: error.message });
  }

  if (macs.length) {
    const { data, error } = await supabase
      .from('hotspot_sessions')
      .select('*')
      .in('mac_address', macs)
      .order('updated_at', { ascending: false })
      .order('created_at', { ascending: false })
      .limit(1000);
    if (!error) rows.push(...(data || []));
    else await registerSystemLog('warning', 'users', 'Falha ao buscar sessoes por MAC', { error: error.message });
  }

  for (const session of rows) {
    const keys = [
      session.user_id ? `user:${session.user_id}` : null,
      ...getMacVariants(session.mac_address || '').map(mac => `mac:${normalizeMac(mac) || mac}`)
    ].filter(Boolean);
    for (const key of keys) {
      if (!byKey.has(key)) byKey.set(key, session);
    }
  }

  return byKey;
}

async function enrichUsersWithSessionInfo(users = []) {
  if (!users.length) return [];
  const sessionByKey = await getLatestSessionsByUsers(users);
  const popIds = [...new Set([
    ...[...sessionByKey.values()].map(sessionPopId),
    ...users.map(u => u.pop_id || u.last_pop_id)
  ].filter(Boolean))];
  const popMap = new Map();

  if (popIds.length) {
    const { data, error } = await supabase.from('pops').select('id, name, unique_id, location').in('id', popIds);
    if (!error) (data || []).forEach(pop => popMap.set(String(pop.id), pop));
  }

  const macs = [...new Set(users.flatMap(u => getMacVariants(u.mac_address || u.username || '')).filter(Boolean))];
  const trialByMac = new Map();
  if (macs.length) {
    const { data, error } = await supabase
      .from('free_trials')
      .select('*')
      .in('mac_address', macs)
      .order('updated_at', { ascending: false })
      .limit(1000);
    if (!error) {
      (data || []).forEach(trial => {
        const key = normalizeMac(trial.mac_address || '');
        if (key && !trialByMac.has(key)) trialByMac.set(key, trial);
      });
    }
  }

  return users.map(user => {
    const mac = normalizeMac(user.mac_address || user.username || '');
    const session = sessionByKey.get(`user:${user.id}`) || (mac ? sessionByKey.get(`mac:${mac}`) : null) || null;
    const popId = sessionPopId(session || {}) || user.pop_id || user.last_pop_id || null;
    const pop = popId ? popMap.get(String(popId)) : null;
    const trial = mac ? trialByMac.get(mac) : null;
    const popName = session?.pop_name || pop?.name || user.pop_name || user.last_pop_name || null;
    const popLocation = session?.pop_location || pop?.location || user.pop_location || user.last_pop_location || null;
    return {
      ...user,
      operational_status: deriveClientOperationalStatus(user),
      last_pop_id: popId || user.last_pop_id || user.pop_id || null,
      last_pop_name: popName,
      last_pop_location: popLocation,
      pop_id: user.pop_id || popId || null,
      pop_name: user.pop_name || popName,
      pop_location: user.pop_location || popLocation,
      local_ip: sessionLocalIp(session || {}) || user.local_ip || user.ip_address || null,
      last_connection_at: sessionTime(session || {}) || user.last_seen_at || user.updated_at || null,
      cooldown_until: trial?.cooldown_until || session?.cooldown_until || user.cooldown_until || null
    };
  });
}

async function createPopCommand(popId, commandType, payload) {
  if (!popId) return null;
  const now = new Date().toISOString();
  const preferred = {
    pop_id: popId,
    command_type: commandType,
    payload,
    status: 'pending',
    attempts: 0,
    created_at: now
  };
  const fallback = { pop_id: popId, command_type: commandType, payload, status: 'pending', created_at: now };
  const { data, error } = await safeInsertWithFallback('pop_commands', preferred, fallback);
  if (error) {
    await registerSystemLog('error', 'pop_commands', 'Erro ao criar comando para POP', { pop_id: popId, command_type: commandType, error: error.message });
    return null;
  }
  return data;
}

async function revokeRadiusAccess(macAddress) {
  const mac = normalizeMac(macAddress);
  if (!mac) return false;
  const variants = getMacVariants(mac);
  const now = new Date().toISOString();
  const update = await supabase
    .from('radius_replies')
    .update({ status: 'revoked', expires_at: now, updated_at: now })
    .in('username', variants);
  if (!update.error) return true;

  const del = await supabase.from('radius_replies').delete().in('username', variants);
  return !del.error;
}

async function queueDisconnectCommandForUser(user, reason = 'disconnect_user') {
  const mac = normalizeMac(user?.mac_address || user?.username || '');
  if (!mac) return null;

  let popId = null;
  let popIp = null;

  const variants = getMacVariants(mac);

  const { data: session, error: sessionError } = await supabase
    .from('hotspot_sessions')
    .select('*')
    .in('mac_address', variants)
    .order('updated_at', { ascending: false })
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (sessionError) {
    await registerSystemLog('warning', 'pop_commands', 'Falha ao buscar ultima sessao para comando de desconexao', {
      mac_address: mac,
      error: sessionError.message
    });
  }

  const sessionPop = sessionPopId(session || {});
  if (sessionPop) popId = sessionPop;
  if (session?.pop_ip) popIp = session.pop_ip;

  if (!popId) {
    await registerSystemLog('warning', 'pop_commands', 'POP nao identificado para comando de desconexao', {
      user_id: user?.id || null,
      mac_address: mac,
      reason
    });
    return null;
  }

  return createPopCommand(popId, 'disconnect_hotspot_user', {
    mac_address: mac,
    username: mac,
    reason,
    pop_ip: popIp || null
  });
}

async function revokeAndDisconnectUser(user, reason = 'disconnect_user') {
  const mac = normalizeMac(user?.mac_address || user?.username || '');
  if (!mac) {
    return {
      radius_revoked: false,
      disconnect_status: 'not_applicable',
      disconnect_method: 'none',
      error: 'MAC ausente'
    };
  }

  const radiusRevoked = await revokeRadiusAccess(mac);

  let directDone = false;
  let directError = null;

  try {
    directDone = await revokeAccess(
      mac,
      user?.pop_ip || user?.ip || '192.168.32.1',
      null,
      null,
      user?.pop_id || user?.last_pop_id || null
    );
  } catch (err) {
    directError = err.message;
    await registerSystemLog('warning', 'users', 'Falha ao revogar acesso direto', {
      user_id: user?.id || null,
      mac_address: mac,
      error: err.message
    });
  }

  if (directDone) {
    return {
      radius_revoked: radiusRevoked,
      disconnect_status: 'done',
      disconnect_method: 'routeros_api',
      pop_id: user?.pop_id || user?.last_pop_id || null
    };
  }

  const command = await queueDisconnectCommandForUser(user, reason);

  if (command) {
    return {
      radius_revoked: radiusRevoked,
      disconnect_status: 'queued',
      disconnect_method: 'pop_command_queue',
      command_id: command.id,
      pop_id: command.pop_id || null
    };
  }

  return {
    radius_revoked: radiusRevoked,
    disconnect_status: 'failed',
    disconnect_method: 'none',
    pop_id: null,
    error: directError || 'POP nao identificado para fila de comandos'
  };
}

function getPopMetricPayload(popId, source = {}) {
  const traffic = normalizeTrafficBytes(source);
  return {
    pop_id: popId,
    active_users: Math.max(0, Math.floor(Number(source.active_users ?? source.users_connected ?? source.active_clients ?? 0) || 0)),
    rx_bytes: traffic.rx_bytes,
    tx_bytes: traffic.tx_bytes,
    total_bytes: traffic.total_bytes,
    peak_bandwidth_mbps: numberOrZero(source.peak_bandwidth_mbps ?? source.bandwidth_mbps ?? source.bandwidth),
    uptime: source.uptime || null,
    identity: source.identity || null,
    routeros_version: source.routeros_version || source.version || null,
    created_at: new Date().toISOString()
  };
}

async function storePopMetric(popId, source = {}) {
  const payload = getPopMetricPayload(popId, source);
  const { error } = await supabase.from('pop_metrics').insert(payload);
  if (error) {
    await registerSystemLog('warning', 'pop_metrics', 'Falha ao gravar metricas do POP', { pop_id: popId, error: error.message });
    return null;
  }
  return payload;
}

async function buildDashboardMetrics() {
  const now = new Date();
  const todayStart = new Date(now);
  todayStart.setHours(0, 0, 0, 0);
  const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000).toISOString();
  const nowIso = now.toISOString();

  const { data: users } = await supabase.from('users').select('id, status, expires_at, hotspot_id, pop_id');
  const { data: pops } = await supabase.from('pops').select('*');

  let activeSessions = [];
  try {
    const { data } = await supabase
      .from('hotspot_sessions')
      .select('*')
      .eq('status', 'active')
      .gt('expires_at', nowIso)
      .limit(5000);
    activeSessions = data || [];
  } catch (_err) {}

  let metricsToday = [];
  try {
    const { data } = await supabase
      .from('pop_metrics')
      .select('*')
      .gte('created_at', todayStart.toISOString())
      .order('created_at', { ascending: false })
      .limit(5000);
    metricsToday = data || [];
  } catch (_err) {}

  const readTrafficTable = async (tableName) => {
    try {
      const { data, error } = await supabase.from(tableName).select('*').limit(5000);
      return error ? [] : (data || []);
    } catch (_err) {
      return [];
    }
  };

  const accountingRows = [
    ...(await readTrafficTable('radacct')),
    ...(await readTrafficTable('accounting'))
  ];

  const latestMetricByPop = new Map();
  for (const metric of metricsToday) {
    const key = String(metric.pop_id || '');
    if (key && !latestMetricByPop.has(key)) latestMetricByPop.set(key, metric);
  }

  const userPopById = new Map((users || []).map(user => [String(user.id), user.pop_id || user.hotspot_id || null]));
  const activeSessionsByPop = new Map();
  for (const session of activeSessions) {
    const popId = sessionPopId(session) || userPopById.get(String(session.user_id || ''));
    if (!popId) continue;
    activeSessionsByPop.set(String(popId), (activeSessionsByPop.get(String(popId)) || 0) + 1);
  }

  const freshMetrics = [...latestMetricByPop.values()].filter(metric => String(metric.created_at || '') >= fiveMinutesAgo);
  const metricOnlineUsers = freshMetrics.reduce((sum, metric) => sum + numberOrZero(metric.active_users), 0);
  const onlineUsers = metricOnlineUsers || activeSessions.length;
  const peakUsersToday = Math.max(onlineUsers, ...metricsToday.map(metric => numberOrZero(metric.active_users)));

  const sessionTraffic = activeSessions.reduce((sum, session) => sum + normalizeTrafficBytes(session).total_bytes, 0);
  const metricTraffic = [...latestMetricByPop.values()].reduce((sum, metric) => sum + normalizeTrafficBytes(metric).total_bytes, 0);
  const accountingTraffic = accountingRows.reduce((sum, row) => sum + normalizeTrafficBytes(row).total_bytes, 0);
  const totalTrafficBytes = Math.max(sessionTraffic, metricTraffic, accountingTraffic);
  const peakBandwidthMbps = Math.max(0, ...metricsToday.map(metric => numberOrZero(metric.peak_bandwidth_mbps)));

  const dashboardPops = (pops || []).map(pop => {
    const popId = String(pop.id);
    const metric = latestMetricByPop.get(popId);
    const metricFresh = metric && String(metric.created_at || '') >= fiveMinutesAgo;
    const traffic = normalizeTrafficBytes(metric || {});
    const lastHeartbeat = pop.last_heartbeat_at || pop.last_heartbeat || pop.last_seen_at || pop.last_seen || pop.updated_at || null;
    const lastActivity = metric?.created_at || lastHeartbeat;
    return {
      id: pop.id,
      unique_id: pop.unique_id,
      name: pop.name,
      location: pop.location,
      status: pop.status,
      active_users: metricFresh ? numberOrZero(metric.active_users) : (activeSessionsByPop.get(popId) || numberOrZero(pop.active_clients || pop.users_connected)),
      last_heartbeat_at: lastHeartbeat,
      last_activity_at: lastActivity,
      traffic_total_bytes: traffic.total_bytes,
      peak_bandwidth_mbps: numberOrZero(metric?.peak_bandwidth_mbps)
    };
  });

  const onlinePops = (pops || []).filter(pop => {
    const last = pop.last_heartbeat || pop.last_seen_at || pop.last_seen || pop.updated_at;
    return String(pop.status || '').toLowerCase() === 'online' && (!last || (Date.now() - new Date(last).getTime()) <= 2 * 60 * 1000);
  }).length;

  return {
    online_users: onlineUsers,
    peak_users_today: peakUsersToday,
    total_traffic_bytes: totalTrafficBytes,
    total_traffic_human: formatBytes(totalTrafficBytes),
    peak_bandwidth_mbps: Number(peakBandwidthMbps.toFixed(2)),
    online_pops: onlinePops,
    offline_pops: Math.max(0, (pops || []).length - onlinePops),
    total_customers: users?.length || 0,
    pops: dashboardPops
  };
}

function looksLikeMissingColumnError(err, columnName = null, tableName = null) {
  if (!err) return false;
  const msg = `${err.message || ''} ${err.details || ''} ${err.hint || ''}`;
  if (columnName && new RegExp(`Could not find the '${columnName}' column`, 'i').test(msg)) return true;
  if (tableName && new RegExp(`${tableName}.*does not exist`, 'i').test(msg)) return true;
  return isMissingColumnError(err);
}

function buildPopApiUsername(uniqueId) {
  return `API_${String(uniqueId || '').trim()}`.replace(/[^A-Za-z0-9_]/g, '_').slice(0, 32);
}

function buildL2tpChapSecrets(pops) {
  const header = [
    '# ======================================================================',
    '# AUTO-GENERATED BLOCK - MS TELECOM POPs (DO NOT EDIT INSIDE)',
    `# Generated at: ${new Date().toISOString()}`,
    '# ======================================================================',
  ].join('\n');

  const lines = (pops || [])
    .filter((p) => p && p.vpn_enabled === true && String(p.vpn_type || '').toLowerCase() === 'l2tp_ipsec')
    .filter((p) => p.vpn_username && p.vpn_password && (p.vpn_ip || p.radius_client_ip))
    .map((p) => {
      const username = String(p.vpn_username).trim();
      const password = String(p.vpn_password).replace(/"/g, '\\"');
      const ip = String(p.vpn_ip || p.radius_client_ip).trim();
      // chap-secrets: client  server  secret  IP
      return `"${username}"  ms-l2tp  "${password}"  ${ip}`;
    });

  return [header, ...lines].join('\n') + '\n';
}

async function syncL2tpChapSecretsFromDb() {
  try {
    const { data: pops, error } = await supabase
      .from('pops')
      .select('id, unique_id, vpn_enabled, vpn_type, vpn_ip, radius_client_ip, vpn_username, vpn_password')
      .order('unique_id', { ascending: true });

    if (error) {
      if (
        looksLikeMissingColumnError(error, 'vpn_enabled', 'pops') ||
        looksLikeMissingColumnError(error, 'vpn_ip', 'pops') ||
        looksLikeMissingColumnError(error, 'vpn_username', 'pops') ||
        looksLikeMissingColumnError(error, 'vpn_password', 'pops')
      ) {
        throw new Error('Database schema missing required VPN columns in pops. Apply migration first.');
      }
      throw error;
    }

    const managedBlock = buildL2tpChapSecrets(pops || []);

    // Read existing chap-secrets (best-effort). Preserve anything outside our managed markers.
    const beginMarker = '# BEGIN MS-TELECOM POPS';
    const endMarker = '# END MS-TELECOM POPS';

    let existing = '';
    const readRes = await execAsync(`sudo cat ${CHAP_SECRETS_PATH}`);
    if (!readRes.error) existing = readRes.stdout || '';

    const before = existing.split(beginMarker)[0] || '';
    const afterSplit = existing.split(endMarker);
    const after = afterSplit.length > 1 ? afterSplit.slice(1).join(endMarker) : '';

    const nextContent =
      (before.trimEnd() ? before.trimEnd() + '\n' : '') +
      `${beginMarker}\n` +
      managedBlock +
      `${endMarker}\n` +
      (after.trimStart() ? after.trimStart() : '');

    const tmpPath = path.join(__dirname, 'tmp', 'chap-secrets');
    fs.mkdirSync(path.dirname(tmpPath), { recursive: true });
    fs.writeFileSync(tmpPath, nextContent, { encoding: 'utf8' });

    await execAsync(`sudo cp ${CHAP_SECRETS_PATH} ${CHAP_SECRETS_PATH}.bak 2>/dev/null || true`);
    const { error: cpError, stderr: cpErr } = await execAsync(`sudo cp ${tmpPath} ${CHAP_SECRETS_PATH}`);
    if (cpError) throw new Error(`chap-secrets copy failed: ${cpErr}`);

    const { error: restartError, stderr: restartErr } = await execAsync(`sudo /usr/bin/systemctl restart ${XL2TPD_SERVICE_NAME}`, 60000);
    if (restartError) throw new Error(`xl2tpd restart failed: ${restartErr}`);

    console.log('[L2TP] chap-secrets synced successfully.');
    return { ok: true };
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao sincronizar chap-secrets:', err.message);
    await registerSystemLog('error', 'L2TP Sync', 'Erro ao sincronizar chap-secrets', { error: err.message });
    return { ok: false, error: err.message };
  }
}

async function allocateNextVpnIp() {
  const start = ipToInt(VPN_IP_POOL_START);
  const end = ipToInt(VPN_IP_POOL_END);
  if (start === null || end === null || start >= end) {
    throw new Error('Invalid VPN IP pool range (VPN_IP_POOL_START/VPN_IP_POOL_END)');
  }

  const { data, error } = await supabase.from('pops').select('vpn_ip');
  if (error) {
    if (looksLikeMissingColumnError(error, 'vpn_ip', 'pops')) {
      throw new Error('Database schema missing required column pops.vpn_ip. Apply migration first.');
    }
    throw error;
  }

  const used = new Set();
  for (const row of data || []) {
    const v = String(row?.vpn_ip || '').trim();
    const n = ipToInt(v);
    if (n !== null) used.add(n);
  }

  for (let cur = start; cur <= end; cur++) {
    if (!used.has(cur)) return intToIp(cur);
  }

  throw new Error('VPN IP pool exhausted');
}

async function ensurePopProvisioningMaterial(pop) {
  const now = new Date().toISOString();
  const warnings = [];

  const popId = pop?.id;
  if (!popId) throw new Error('POP id is required');

  const uniqueId = pop.unique_id || popId;
  const nextRadiusSecret = pop.radius_secret || generateStrongPassword(18);
  let nextVpnIp = pop.vpn_ip || '';
  const nextVpnEnabled = (pop.vpn_enabled === undefined || pop.vpn_enabled === null) ? true : !!pop.vpn_enabled;
  const nextVpnType = pop.vpn_type || 'l2tp_ipsec';
  const nextVpnUsername = pop.vpn_username || uniqueId;
  const nextVpnPassword = pop.vpn_password || generateVpnPassword();

  if (nextVpnEnabled && nextVpnType === 'l2tp_ipsec') {
    try {
      if (!nextVpnIp) {
        nextVpnIp = await allocateNextVpnIp();
      }
    } catch (err) {
      warnings.push(`VPN IP não gerada: ${err.message}`);
      nextVpnIp = pop.vpn_ip || '';
    }
  } else if (nextVpnEnabled && nextVpnType === 'sstp' && !nextVpnIp) {
    try {
      nextVpnIp = await allocateNextVpnIp();
    } catch (err) {
      warnings.push(`VPN IP não gerada: ${err.message}`);
      nextVpnIp = pop.vpn_ip || '';
    }
  }

  // Persist POP radius_secret + unique_id as the official source of truth.
  const updateData = {
    unique_id: uniqueId,
    radius_secret: nextRadiusSecret,
    updated_at: now
  };
  if (pop.vpn_enabled !== undefined || pop.vpn_enabled !== null || nextVpnEnabled !== undefined) updateData.vpn_enabled = nextVpnEnabled;
  if (pop.vpn_type !== undefined || nextVpnType) updateData.vpn_type = nextVpnType;
  if (nextVpnIp) updateData.vpn_ip = nextVpnIp;
  if (nextVpnUsername) updateData.vpn_username = nextVpnUsername;
  if (nextVpnPassword) updateData.vpn_password = nextVpnPassword;

  try {
    const { data: updated, error } = await supabase
      .from('pops')
      .update(updateData)
      .eq('id', popId)
      .select('*')
      .single();

    if (error) throw error;
    pop = updated;
  } catch (error) {
    warnings.push(`Persistência do POP incompleta: ${error.message}`);
    pop = {
      ...pop,
      unique_id: uniqueId,
      radius_secret: nextRadiusSecret,
      vpn_ip: nextVpnIp,
      vpn_username: nextVpnUsername,
      vpn_password: nextVpnPassword,
      vpn_type: nextVpnType,
      vpn_enabled: nextVpnEnabled
    };
  }

  // Persist MikroTik API credentials in mikrotik_credentials (official source of truth).
  const { data: existingCreds, error: credErr } = await supabase
    .from('mikrotik_credentials')
    .select('*')
    .eq('pop_id', popId)
    .maybeSingle();

  if (credErr) warnings.push(`Credenciais MikroTik não lidas: ${credErr.message}`);

  const apiUser = existingCreds?.api_user || buildPopApiUsername(pop.unique_id || popId);
  const apiPass = existingCreds?.api_pass || generateStrongPassword(12);

  if (!existingCreds?.api_user || !existingCreds?.api_pass || existingCreds?.pop_ip !== (pop.ip || null)) {
    try {
      await upsertMikrotikCredentials({
        pop_id: popId,
        pop_ip: pop.ip || null,
        api_user: apiUser,
        api_pass: apiPass
      });
    } catch (e) {
      warnings.push(`Persistência de credenciais MikroTik incompleta: ${e.message}`);
    }
  }

  const popHeartbeatToken = await ensurePopToken(popId);

  return {
    ...pop,
    api_user: apiUser,
    api_pass: apiPass,
    radius_secret: pop.radius_secret || nextRadiusSecret,
    vpn_enabled: pop.vpn_enabled ?? nextVpnEnabled,
    vpn_type: pop.vpn_type || nextVpnType,
    vpn_ip: pop.vpn_ip || nextVpnIp,
    vpn_username: pop.vpn_username || nextVpnUsername,
    vpn_password: pop.vpn_password || nextVpnPassword,
    pop_heartbeat_token: popHeartbeatToken,
    warnings
  };
}

// Listar POPs (Hotspots)
app.get('/api/pops', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('pops').select('*').order('name', { ascending: true });
    if (error) throw error;
    // Normaliza status: so fica online se recebeu heartbeat recente
    const nowMs = Date.now();
    const normalized = (data || []).map(p => {
      const hb = p.last_heartbeat || p.last_seen_at || p.updated_at || null;
      if (!hb) return { ...p, status: 'offline' };
      const diffSec = Math.floor((nowMs - new Date(hb).getTime()) / 1000);
      const isOnline = diffSec >= 0 && diffSec <= 90; // tolerancia
      return { ...p, status: isOnline ? 'online' : 'offline' };
    });
    res.json(normalized);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao listar POPs:', err.message);
    res.status(500).json({ error: 'Erro ao listar POPs' });
  }
});

// Criar POP
app.post('/api/pops', authMiddleware, async (req, res) => {
  try {
    const now = new Date().toISOString();

    // Normaliza alguns campos comuns (evita erro de tipo quando a coluna for numÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â©rica)
    const normalized = { ...(req.body || {}) };
    // Evita erro de schema quando o frontend envia campos nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o existentes (ex: last_heartbeat)
    delete normalized.last_heartbeat;
    // Nunca persistir placeholder/marcador como senha real.
    if (normalized.vpn_password === '' || normalized.vpn_password === null || typeof normalized.vpn_password === 'undefined' || String(normalized.vpn_password).trim() === '********') {
      delete normalized.vpn_password;
    }
    for (const k of ['vlan_id', 'radius_auth_port', 'radius_acct_port', 'session_time', 'idle_timeout', 'bandwidth', 'shared_users']) {
      if (Object.prototype.hasOwnProperty.call(normalized, k)) {
        const v = normalized[k];
        if (v === '' || v === null || typeof v === 'undefined') normalized[k] = null;
        else if (typeof v === 'string' && /^\d+$/.test(v.trim())) normalized[k] = Number(v.trim());
      }
    }

    // Alguns bancos antigos exigem id obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rio (sem default). Se vier vazio, geramos.
    if (!normalized.id && !normalized.unique_id) {
      const newId = generatePopId();
      normalized.id = newId;
      normalized.unique_id = newId;
    }

    // Ao criar, o POP inicia offline ate receber heartbeat do MikroTik
    // Obs: nao seta `last_heartbeat` aqui porque nem todo schema tem essa coluna.
    const preferred = { ...normalized, status: 'offline', created_at: now, updated_at: now };
    delete preferred.last_heartbeat;
    delete preferred.id;

    // Fallback mÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­nimo (compatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­vel com esquemas antigos/novos)
    const fallback = {
      name: normalized.name,
      ip: normalized.ip || null,
      location: normalized.location || null,
      status: 'offline',
      created_at: now,
      updated_at: now
    };

    let { data, error } = await safeInsertWithFallback('pops', preferred, fallback);

    // Se o banco exigir id not-null e nao tiver default, tenta inserir novamente com id explicitamente.
    if (error && String(error.message || '').includes('null value in column \"id\"')) {
      const forcedId = generatePopId();
      const forcedPreferred = { ...preferred, id: forcedId, unique_id: forcedId };
      const forcedFallback = { ...fallback, id: forcedId, unique_id: forcedId };
      ({ data, error } = await safeInsertWithFallback('pops', forcedPreferred, forcedFallback));
    }
    if (error) throw error;

    // Persist provisioning material (POP radius_secret + MikroTik API credentials) before generating the script.
    const enrichedPop = await ensurePopProvisioningMaterial(data);

    // Guarda configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o avanÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ada (para gerar script completo mesmo se a tabela pops nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o tiver todas as colunas)
    try {
      await supabase.from('settings').upsert({
        key: `pop_config_${data.id}`,
        value: normalized,
        updated_at: now
      }, { onConflict: 'key' });
    } catch (_e) {
      // ignora se settings nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o existir/estruturar diferente
    }

    // Gera script completo imediatamente para o frontend copiar no fluxo de criacao
    let script = '';
    try {
      script = buildPopInstallScript(enrichedPop, normalized);
    } catch (scriptErr) {
      script = buildPopInstallScript({ ...enrichedPop, vpn_enabled: false }, normalized);
      enrichedPop.warnings = [...(enrichedPop.warnings || []), `Script VPN omitido: ${scriptErr.message}`];
    }

    const radiusSync = await syncFreeradiusClientsFromDb();
    if (!radiusSync.ok) {
      console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ FreeRADIUS sync failed after POP create:', radiusSync.error);
    }

    const l2tpSync = await syncL2tpChapSecretsFromDb();
    if (!l2tpSync.ok) {
      console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ L2TP chap-secrets sync failed after POP create:', l2tpSync.error);
    }

    res.status(201).json({ ...enrichedPop, script, freeradius_sync: radiusSync.ok ? 'ok' : 'failed', l2tp_sync: l2tpSync.ok ? 'ok' : 'failed' });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao criar POP:', err.message);
    res.status(500).json({ error: 'Erro ao criar POP' });
  }
});

function buildPopInstallScript(pop, config = {}) {
  const popId = pop.unique_id || `MS-${pop.id}`;
  const popName = pop.name || `POP-${popId}`;
  const tag = `MS-TELECOM-${popId}`;

  const apiUser = pop.api_user || buildPopApiUsername(popId);
  const apiPass = pop.api_pass || generateStrongPassword(12);
  const radiusSecret = (RADIUS_CLIENT_MODE === 'global') ? RADIUS_GLOBAL_SECRET : (pop.radius_secret || '');

  const wanInterface = config.wan_interface || 'ether1';
  const lanInterface = config.lan_interface || 'ether2';
  const wanType = config.wan_type || 'dhcp'; // dhcp | pppoe | static
  const pppoeUser = config.pppoe_username || '';
  const pppoePass = config.pppoe_password || '';
  const staticIp = config.static_ip || '';
  const staticMask = config.static_mask || '';
  const staticGw = config.static_gateway || '';

  let installationType = String(config.installation_type || config.installation || 'new').toLowerCase(); // new | production | trunk
  if (installationType === 'existing') installationType = 'production';
  const isTrunk = installationType === 'trunk';
  const trunkTopology = String(config.trunk_topology || 'single').toLowerCase(); // single | dual
  const trunkUplinkInterface = config.trunk_uplink_interface || wanInterface;
  const trunkInternetVlanId = config.trunk_internet_vlan_id ? String(config.trunk_internet_vlan_id).trim() : '';
  const trunkClientVlanId = config.trunk_client_vlan_id ? String(config.trunk_client_vlan_id).trim() : '';

  const vlanId = config.vlan_id ? String(config.vlan_id).trim() : '';
  const idleTimeout = config.idle_timeout ? `${config.idle_timeout}m` : '15m';
  const sessionTime = config.session_time ? `${config.session_time}m` : '';
  const sharedUsers = parseNumber(config.shared_users, 0);
  const bandwidthRaw = parseNumber(config.bandwidth, 0);
  const bandwidthMbps = bandwidthRaw > 1024 ? Math.max(1, Math.round(bandwidthRaw / 1024)) : Math.max(0, Math.round(bandwidthRaw));
  const rateLimit = bandwidthMbps > 0 ? `${bandwidthMbps}M/${bandwidthMbps}M` : '';
  const redirectUrl = config.redirect_url || '';

  const radiusServer = process.env.RADIUS_SERVER_IP || '40.233.118.238';
  const apiUrl = process.env.API_BASE_URL || 'https://mstelecom-api.duckdns.org';
  const frontendUrl = FRONTEND_BASE_URL || 'https://hotspot-system.vercel.app';
  const heartbeatToken = pop.pop_heartbeat_token || '';
  const heartbeatUrlForRouterOs = heartbeatToken ? `${apiUrl}/api/pops/${pop.id}/heartbeat\\?token=${heartbeatToken}` : `${apiUrl}/api/pops/${pop.id}/heartbeat`;
  const commandsUrlForRouterOs = heartbeatToken ? `${apiUrl}/api/pops/${pop.id}/commands.rsc\\?token=${heartbeatToken}` : `${apiUrl}/api/pops/${pop.id}/commands.rsc`;

  const vpnEnabled = parseBoolean(pop.vpn_enabled, false) || parseBoolean(config.vpn_enabled, false);
  const vpnType = String(pop.vpn_type || config.vpn_type || '').toLowerCase();
  const vpnIp = String(pop.vpn_ip || '').trim();
  const vpnUsername = String(pop.vpn_username || '').trim();
  const vpnPassword = String(pop.vpn_password || '').trim();
  const vpnReady = vpnEnabled && vpnType === 'l2tp_ipsec'
    ? (RADIUS_CLIENT_MODE === 'vpn_legacy' && !!vpnIp && !!vpnUsername && !!vpnPassword && !!VPN_PUBLIC_ENDPOINT && !!VPN_L2TP_IPSEC_PSK)
    : vpnEnabled && vpnType === 'sstp'
      ? (RADIUS_CLIENT_MODE === 'vpn_legacy' && !!vpnIp && !!vpnUsername && !!vpnPassword && !!VPN_PUBLIC_ENDPOINT)
      : false;

  const vpnBlock = vpnReady && vpnType === 'l2tp_ipsec'
    ? (
      `# VPN (L2TP/IPsec - RouterOS v6)\n` +
      `/ppp profile add name="MS-VPN" use-encryption=yes comment="${tag}"\n` +
      `/interface l2tp-client add name="ms-vpn-${popId}" connect-to=${VPN_PUBLIC_ENDPOINT} user="${vpnUsername}" password="${vpnPassword}" profile="MS-VPN" use-ipsec=yes ipsec-secret="${VPN_L2TP_IPSEC_PSK}" add-default-route=no keepalive-timeout=30 disabled=no comment="${tag}"\n` +
      `:delay 2s\n` +
      `/ip service set api address=${VPN_INTERNAL_RADIUS_IP}/32\n` +
      `:delay 500ms\n`
    )
    : (vpnReady && vpnType === 'sstp'
      ? (
        `# VPN (SSTP - RouterOS v6)\n` +
        `/ppp profile add name="MS-VPN" use-encryption=yes comment="${tag}"\n` +
        `/interface sstp-client add name="ms-vpn-${popId}" connect-to=${VPN_PUBLIC_ENDPOINT} user="${vpnUsername}" password="${vpnPassword}" profile="MS-VPN" add-default-route=no disabled=no comment="${tag}"\n` +
        `:delay 2s\n` +
        `/ip service set api address=${VPN_INTERNAL_RADIUS_IP}/32\n` +
        `:delay 500ms\n`
      )
      : (vpnEnabled
        ? `# VPN não gerada: configuração incompleta ou modo RADIUS sem VPN\n`
        : ''));

  const radiusClientIp = String(pop.vpn_ip || pop.radius_client_ip || '').trim();

  const radiusVpnBlock = radiusClientIp
    ? (
      `/radius add service=hotspot address=${RADIUS_VPN_SERVER_IP} src-address=${radiusClientIp} secret="${radiusSecret}" authentication-port=1812 accounting-port=1813 timeout=3s domain="${popId}" protocol=udp comment="${tag}-radius-vpn"\n`
    )
    : `# VPN IP ausente: RADIUS primario via VPN nao gerado\n`;

  const radiusPublicFallbackBlock = RADIUS_GLOBAL_FALLBACK_SECRET
    ? (
      `/radius add service=hotspot address=${RADIUS_SERVER_IP} secret="${RADIUS_GLOBAL_FALLBACK_SECRET}" authentication-port=1812 accounting-port=1813 timeout=5s domain="${popId}" protocol=udp comment="${tag}-radius-public-fallback"\n`
    )
    : `# RADIUS fallback publico nao gerado: RADIUS_GLOBAL_FALLBACK_SECRET ausente\n`;

  const radiusBlock =
    (radiusSecret ? radiusVpnBlock : `# RADIUS primário não gerado: radius_secret ausente\n`) +
    radiusPublicFallbackBlock +
    `/radius incoming set accept=yes\n` +
    `:delay 1s\n`;

  // Do not allow Google/gstatic/googleapis/connectivitycheck/generate_204 in pre-login Walled Garden.
  // Android uses these endpoints for captive portal validation. If they return HTTP 204 before authentication,
  // Android marks the hotspot as VALIDATED and CaptivePortalLogin will not open.
  const wgHosts = getPreloginAllowedHosts();
  const wgCleanupPattern = 'gstatic|googleapis|connectivitycheck|generate_204|generate|clients3|google.cn|play.googleapis|google.com|www.gstatic.com|cdn.tailwindcss.com|cdnjs.cloudflare.com|unpkg.com|vercel.app|cdn.vercel.app|neverssl.com|mercadopago|captive.apple.com|msftconnecttest.com|msftncsi.com';
  const wgCleanupLines = [
    `/ip hotspot walled-garden remove [find where dst-host~"${wgCleanupPattern}"]`,
    `/ip hotspot walled-garden ip remove [find where dst-host~"${wgCleanupPattern}"]`,
    `/ip dns cache flush`
  ].join('\n');
  const wgLines = wgHosts.map(h => `/ip hotspot walled-garden ip add action=accept disabled=no dst-host=${h} server="${popName}" comment="${tag}"`).join('\n');

  const wanBlock = (() => {
    if (installationType === 'production') {
      return `# WAN (Production Mode) - nao altera WAN\n`;
    }
    if (isTrunk) {
      // Trunk: WAN vem de uma VLAN transportada pela interface uplink (wanInterface)
      // Por padrÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o, usa DHCP nessa VLAN para obter acesso a Internet/Rotas (via MikroTik principal).
      const useWanVlan = trunkInternetVlanId || vlanId;
      const uplink = trunkUplinkInterface;
      if (useWanVlan) {
        const wanVlan = `ms-wan-vlan-${useWanVlan}`;
        return (
          `# WAN (TRUNK VLAN - DHCP)\n` +
          `/interface vlan add name="${wanVlan}" interface=${uplink} vlan-id=${useWanVlan} comment="${tag}"\n` +
          `/ip dhcp-client add interface="${wanVlan}" disabled=no comment="${tag}"\n` +
          `/ip firewall nat add action=masquerade chain=srcnat out-interface="${wanVlan}" comment="${tag}"\n`
        );
      }
      return (
        `# WAN (TRUNK - DHCP)\n` +
        `/ip dhcp-client add interface=${uplink} disabled=no comment="${tag}"\n` +
        `/ip firewall nat add action=masquerade chain=srcnat out-interface=${uplink} comment="${tag}"\n`
      );
    }
    if (wanType === 'pppoe') {
      return (
        `# WAN (PPPoE)\n` +
        `/interface pppoe-client add interface=${wanInterface} user="${pppoeUser}" password="${pppoePass}" disabled=no comment="${tag}"\n` +
        `/ip firewall nat add action=masquerade chain=srcnat out-interface=${wanInterface} comment="${tag}"\n`
      );
    }
    if (wanType === 'static') {
      const mask = staticMask || '24';
      return (
        `# WAN (IP EstÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tico)\n` +
        `/ip address add address=${staticIp}/${mask} interface=${wanInterface} comment="${tag}"\n` +
        (staticGw ? `/ip route add gateway=${staticGw} comment="${tag}"\n` : '') +
        `/ip firewall nat add action=masquerade chain=srcnat out-interface=${wanInterface} comment="${tag}"\n`
      );
    }
    return (
      `# WAN (DHCP)\n` +
      `/ip dhcp-client add interface=${wanInterface} disabled=no comment="${tag}"\n` +
      `/ip firewall nat add action=masquerade chain=srcnat out-interface=${wanInterface} comment="${tag}"\n`
    );
  })();

  // VLAN do Hotspot:
  // - Default: se vlanId foi preenchido, cria VLAN em cima da lanInterface.
  // - TRUNK single: cria VLAN de clientes em cima da trunkUplinkInterface (mesma porta trunk).
  const trunkClientSingleEnabled = isTrunk && trunkTopology === 'single' && !!trunkClientVlanId;
  const trunkClientDualEnabled = isTrunk && trunkTopology === 'dual' && !!vlanId;

  const vlanLine = trunkClientSingleEnabled
    ? `/interface vlan add name="ms-vlan-${trunkClientVlanId}" interface=${trunkUplinkInterface} vlan-id=${trunkClientVlanId} comment="${tag}"\n`
    : trunkClientDualEnabled
      ? `/interface vlan add name="ms-vlan-${vlanId}" interface=${lanInterface} vlan-id=${vlanId} comment="${tag}"\n`
      : (!isTrunk && vlanId)
        ? `/interface vlan add name="ms-vlan-${vlanId}" interface=${lanInterface} vlan-id=${vlanId} comment="${tag}"\n`
        : '';

  const clientIface = trunkClientSingleEnabled
    ? `"ms-vlan-${trunkClientVlanId}"`
    : (trunkClientDualEnabled || (!isTrunk && vlanId))
      ? `"ms-vlan-${vlanId}"`
      : lanInterface;

const hotspotLine = `/ip hotspot add address-pool="ms-pool-${popId}" disabled=no idle-timeout=${idleTimeout} interface="ms-bridge-${popId}" name="${popName}" profile="ms-profile-${popId}"\n`;

  const userProfileTuningLine = (() => {
    const profileName = `ms-user-profile-${popId}`;
    const setParts = [
      sessionTime ? ` session-timeout=${sessionTime}` : '',
      rateLimit ? ` rate-limit=${rateLimit}` : '',
      sharedUsers > 0 ? ` shared-users=${sharedUsers}` : ''
    ].join('');

    // Create/update a POP-specific user profile; do NOT touch the global "default" profile.
    return (
      `# Perfil de usuario (POP especifico - nao altera o default global)\n` +
      `:if ([:len [/ip hotspot user profile find name="${profileName}"]] = 0) do={\n` +
      `  /ip hotspot user profile add name="${profileName}"${setParts} comment="${tag}"\n` +
      `} else={\n` +
      `  /ip hotspot user profile set [find name="${profileName}"]${setParts}\n` +
      `}\n`
    );
  })();

  const redirectLine = redirectUrl ? `# Redirect URL (opcional)\n/ip hotspot profile set [find name="ms-profile-${popId}"] login-by=http-chap,http-pap\n` : '';

  // HTML do portal no MikroTik (login.html/alogin.html -> /entrypoint)
  const portalUrl = `${frontendUrl}/portal`;
  const loginHtml = `<html><head><meta http-equiv="refresh" content="0; url=${portalUrl}\\?mac=\\$(mac)&ip=\\$(ip)&hotspot=\\$(server-name)&pop_id=${encodeURIComponent(pop.id)}&pop=${encodeURIComponent(pop.id)}&pop_unique_id=${encodeURIComponent(pop.unique_id || pop.id)}&loginUrl=\\$(link-login-only)&orig=\\$(link-orig)&error=\\$(error)" /><meta http-equiv="pragma" content="no-cache"><meta http-equiv="expires" content="-1"></head></html>`;
  const aloginHtml = `<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"/><meta http-equiv="refresh" content="2; url=\\$(link-redirect)"><meta http-equiv="pragma" content="no-cache"><meta http-equiv="expires" content="-1"><title>MS Telecom - Redirecionamento</title><style>body{margin:0;padding:24px;background-color:#dff2fd;font-family:Arial,sans-serif;height:100vh;display:flex;flex-direction:column;align-items:center}.card{background-color:#fff;padding:30px 40px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);text-align:left;display:flex;align-items:center;gap:10px}.success-icon{color:green;font-size:36px}.success-text{color:green;font-weight:bold;font-size:20px;line-height:1.4}.redirect{margin-top:20px;font-size:16px;font-weight:bold;color:#333;display:flex;align-items:center;gap:6px}.action{margin-top:24px;font-size:16px;color:#555}.spinner{width:16px;height:16px;border:2px solid #ccc;border-top:2px solid #333;border-radius:50%;animation:spin 1s linear infinite}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}</style><script>function startClock(){\\$(if popup=='true')open('\\$(link-status)','hotspot_status','toolbar=0,location=0,directories=0,status=0,menubars=0,resizable=1,width=290,height=200');\\$(endif)location.href=unescape('\\$(link-redirect-esc)');}</script></head><body onLoad="startClock()"><div class="card"><div class="success-icon">ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â</div><div class="success-text">Autenticacao realizada com sucesso!</div></div><div class="redirect">Redirecionando ...<div class="spinner"></div></div><div class="action">Se nada acontecer, clique <a href="\\$(link-redirect)">aqui</a>.</div></body></html>`;

  const hotspotHtmlBlock =
    `# HTML do Hotspot (Portal)\n` +
    `:execute {/ip hotspot reset-html "${popName}"}\n` +
    `:delay 5000ms;\n` +
    `:global hotspotDir [/ip hotspot profile get [find name="ms-profile-${popId}"] value-name=html-directory];\n` +
    `/file set ($hotspotDir . "/login.html") contents="${loginHtml.replace(/"/g, '\\"')}"\n` +
    `/file set ($hotspotDir . "/alogin.html") contents="${aloginHtml.replace(/"/g, '\\"')}"\n`;
  return (
`# ============================================
# MS TELECOM - SCRIPT COMPLETO DE INSTALACAO
# POP ID: ${popId}
# Nome: ${popName}
# ============================================

/system backup save name=backup_pre_${popId}
/export file=config_pre_${popId}
:delay 2s

:if (${installationType === 'production' ? 'true' : 'false'}) do={
  # Production Mode: nao altera identity
} else={
  /system identity set name="${popName}"
  :delay 500ms
}

/user add name="${apiUser}" password="${apiPass}" group=full comment="${tag}"
:delay 500ms

${vlanLine}/interface bridge add name="ms-bridge-${popId}" comment="${tag}"
:delay 500ms

/interface bridge port add bridge="ms-bridge-${popId}" interface=${clientIface} comment="${tag}"
:delay 500ms

/ip address add address=192.168.32.1/20 interface="ms-bridge-${popId}" network=192.168.32.0 comment="${tag}"
:delay 500ms

/ip pool add name="ms-pool-${popId}" ranges=192.168.32.10-192.168.47.254 comment="${tag}"
/ip dhcp-server add address-pool="ms-pool-${popId}" disabled=no interface="ms-bridge-${popId}" name="ms-dhcp-${popId}" lease-time=24h
/ip dhcp-server network add address=192.168.32.0/20 gateway=192.168.32.1 dns-server=8.8.8.8,1.1.1.1 comment="${tag}"
:delay 1s

${wanBlock}

/ip dns set allow-remote-requests=yes servers=8.8.8.8,1.1.1.1
:delay 500ms

${vpnBlock}${radiusBlock}

:global hotspotDir
:set hotspotDir "ms-${popId}"
/ip hotspot profile add name="ms-profile-${popId}" hotspot-address=192.168.32.1 login-by=http-chap,http-pap html-directory=$hotspotDir use-radius=yes radius-default-domain="${popId}" radius-interim-update=10m
:delay 500ms

${hotspotLine}:delay 1s

# Walled Garden (dominios liberados antes do login)
${wgCleanupLines}
${wgLines}
:delay 1s

${hotspotHtmlBlock}
:delay 1s

${userProfileTuningLine}${redirectLine}

:do { /system scheduler remove [find name="ms-heartbeat-${popId}"] } on-error={}
/system scheduler add comment="${tag}" interval=30s name="ms-heartbeat-${popId}" on-event="{/tool fetch http-method=post url=\\\"${heartbeatUrlForRouterOs}\\\" keep-result=no;}" policy=read,test start-time=startup

:do { /system scheduler remove [find name="ms-commands-${popId}"] } on-error={}
/system scheduler add comment="${tag}" interval=10s name="ms-commands-${popId}" on-event="{/tool fetch http-method=get url=\\\"${commandsUrlForRouterOs}\\\" dst-path=ms-commands.rsc keep-result=yes; /import file-name=ms-commands.rsc; :do { /file remove ms-commands.rsc } on-error={};}" policy=read,write,test start-time=startup

:put \"OK - INSTALACAO CONCLUIDA\"
:put \"POP ID: ${popId}\"
:put \"API User: ${apiUser}\"
:put \"API Pass: ${apiPass}\"
`
  );
}

// Atualizar POP
app.put('/api/pops/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: existing, error: existingErr } = await supabase.from('pops').select('*').eq('id', id).single();
    if (existingErr || !existing) return res.status(404).json({ error: 'POP nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });

    const updateData = { updated_at: new Date().toISOString() };
    const body = { ...(req.body || {}) };
    // Nunca sobrescrever senha VPN com placeholder/vazio.
    if (body.vpn_password === '' || body.vpn_password === null || typeof body.vpn_password === 'undefined' || String(body.vpn_password).trim() === '********') {
      delete body.vpn_password;
    }
    for (const [k, v] of Object.entries(body)) {
      if (k === 'id') continue;
      if (Object.prototype.hasOwnProperty.call(existing, k)) updateData[k] = v;
    }

    const { data, error } = await supabase.from('pops').update(updateData).eq('id', id).select().single();
    if (error) throw error;

    // Persist last config snapshot for script generation (best-effort).
    try {
      const cfg = { ...(body || {}) };
      delete cfg.last_heartbeat;
      await supabase.from('settings').upsert({ key: `pop_config_${id}`, value: cfg, updated_at: updateData.updated_at }, { onConflict: 'key' });
    } catch (_e) {}

    const enrichedPop = await ensurePopProvisioningMaterial(data);

    const radiusSync = await syncFreeradiusClientsFromDb();
    if (!radiusSync.ok) {
      console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ FreeRADIUS sync failed after POP update:', radiusSync.error);
    }

    const l2tpSync = await syncL2tpChapSecretsFromDb();
    if (!l2tpSync.ok) {
      console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ L2TP chap-secrets sync failed after POP update:', l2tpSync.error);
    }

    res.json({ ...enrichedPop, freeradius_sync: radiusSync.ok ? 'ok' : 'failed', l2tp_sync: l2tpSync.ok ? 'ok' : 'failed' });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao atualizar POP:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar POP' });
  }
});
// Deletar POP
app.delete('/api/pops/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Remove associated MikroTik credentials (new official model).
    try {
      await supabase.from('mikrotik_credentials').delete().eq('pop_id', id);
    } catch (_e) {}

    // Remove stored config snapshot.
    try {
      await supabase.from('settings').delete().eq('key', `pop_config_${id}`);
    } catch (_e) {}

    // Remove stored POP token.
    try {
      await supabase.from('settings').delete().eq('key', `pop_token_${id}`);
    } catch (_e) {}

    // Best-effort cleanup of pending commands.
    try {
      await supabase.from('pop_commands').delete().eq('pop_id', id).eq('status', 'pending');
    } catch (_e) {}

    const { error } = await supabase.from('pops').delete().eq('id', id);
    if (error) throw error;

    const radiusSync = await syncFreeradiusClientsFromDb();
    if (!radiusSync.ok) {
      console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ FreeRADIUS sync failed after POP delete:', radiusSync.error);
    }

    const l2tpSync = await syncL2tpChapSecretsFromDb();
    if (!l2tpSync.ok) {
      console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ L2TP chap-secrets sync failed after POP delete:', l2tpSync.error);
    }

    res.json({ message: 'POP removido com sucesso', freeradius_sync: radiusSync.ok ? 'ok' : 'failed', l2tp_sync: l2tpSync.ok ? 'ok' : 'failed' });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao deletar POP:', err.message);
    res.status(500).json({ error: 'Erro ao deletar POP' });
  }
});
// Alias legado (portuguÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âªs)
app.put('/api/perfil', authMiddleware, (req, res, next) => {
  req.url = '/api/profile';
  next();
});

// Obter configuracao consolidada de um POP (para modal de detalhes)
app.get('/api/pops/:id/config', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: pop, error: popErr } = await supabase
      .from('pops')
      .select('*')
      .eq('id', id)
      .single();
    if (popErr || !pop) return res.status(404).json({ error: 'POP nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });

    let config = {};
    try {
      const { data: cfg } = await supabase
        .from('settings')
        .select('value')
        .eq('key', `pop_config_${id}`)
        .maybeSingle();
      config = cfg?.value || {};
    } catch (_e) {}

    // Retorna sempre os dados do POP + o config salvo (quando existir)
    res.json({ pop, config });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao obter config do POP:', err.message);
    res.status(500).json({ error: 'Erro ao obter config do POP' });
  }
});

// Gerar script de configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o para um POP
app.get('/api/pops/:id/script', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: pop, error } = await supabase.from('pops').select('*').eq('id', id).single();
    if (error || !pop) return res.status(404).json({ error: 'POP nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });

    let config = {};
    try {
      const { data: cfg } = await supabase.from('settings').select('value').eq('key', `pop_config_${id}`).maybeSingle();
      config = cfg?.value || {};
    } catch (_e) {}

    const enrichedPop = await ensurePopProvisioningMaterial(pop);
    let script = '';
    try {
      script = buildPopInstallScript(enrichedPop, config);
    } catch (scriptErr) {
      script = buildPopInstallScript({ ...enrichedPop, vpn_enabled: false }, config);
      enrichedPop.warnings = [...(enrichedPop.warnings || []), `Script VPN omitido: ${scriptErr.message}`];
    }

    const radiusSync = await syncFreeradiusClientsFromDb();
    if (!radiusSync.ok) {
      console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ FreeRADIUS sync failed after script generation:', radiusSync.error);
    }

    const l2tpSync = await syncL2tpChapSecretsFromDb();
    if (!l2tpSync.ok) {
      console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ L2TP chap-secrets sync failed after script generation:', l2tpSync.error);
    }

    res.json({ script, freeradius_sync: radiusSync.ok ? 'ok' : 'failed', l2tp_sync: l2tpSync.ok ? 'ok' : 'failed', warnings: enrichedPop.warnings || [] });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao gerar script:', err.message);
    res.status(500).json({ error: 'Erro ao gerar script' });
  }
});
// Receber heartbeat do MikroTik (atualiza status e ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºltima atividade)
// Gerar script de reversÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o para um POP
app.get('/api/pops/:id/revert-script', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: pop, error } = await supabase.from('pops').select('*').eq('id', id).single();
    if (error || !pop) return res.status(404).json({ error: 'POP nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });

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
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao gerar script de reversÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o:', err.message);
    res.status(500).json({ error: 'Erro ao gerar script de reversÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o' });
  }
});

// One-time backfill: allocate missing VPN fields for existing POPs (admin only)
app.post('/api/admin/pops/vpn-backfill', authMiddleware, async (req, res) => {
  try {
    const { data: pops, error } = await supabase.from('pops').select('*').order('created_at', { ascending: true });
    if (error) throw error;

    const updated = [];
    for (const pop of pops || []) {
      const needs =
        !pop.vpn_ip ||
        !pop.vpn_username ||
        !pop.vpn_password ||
        !pop.vpn_type ||
        pop.vpn_enabled === undefined ||
        pop.vpn_enabled === null;

      if (!needs) continue;

      const enriched = await ensurePopProvisioningMaterial(pop);
      updated.push({ id: enriched.id, unique_id: enriched.unique_id, vpn_ip: enriched.vpn_ip, vpn_username: enriched.vpn_username });
    }

    const l2tpSync = await syncL2tpChapSecretsFromDb();
    const radiusSync = await syncFreeradiusClientsFromDb();

    res.json({
      success: true,
      updated_count: updated.length,
      updated,
      l2tp_sync: l2tpSync.ok ? 'ok' : 'failed',
      freeradius_sync: radiusSync.ok ? 'ok' : 'failed'
    });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ vpn-backfill error:', err.message);
    res.status(500).json({ error: 'Erro no backfill VPN' });
  }
});

// Ping do POP (compat: antigos chamavam /api/pops/:id/ping)
app.post('/api/pops/:id/ping', async (req, res) => {
  try {
    const { id } = req.params;
    if (!(await requirePopToken(req, res, id))) return;
    const now = new Date().toISOString();
    const metrics = { ...(req.query || {}), ...(req.body || {}) };
    const { data: pop, error: popErr } = await supabase.from('pops').select('*').eq('id', id).single();
    if (popErr || !pop) return res.status(404).json({ error: 'POP nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });

    const updateData = { status: 'online', updated_at: now };
    if (Object.prototype.hasOwnProperty.call(pop, 'last_heartbeat')) updateData.last_heartbeat = now;
    if (Object.prototype.hasOwnProperty.call(pop, 'last_seen')) updateData.last_seen = now;
    if (Object.prototype.hasOwnProperty.call(pop, 'users_connected') && typeof metrics.users_connected !== 'undefined') {
      updateData.users_connected = metrics.users_connected;
    }
    if (Object.prototype.hasOwnProperty.call(pop, 'active_clients') && typeof metrics.active_users !== 'undefined') {
      updateData.active_clients = metrics.active_users;
    }
    if (Object.prototype.hasOwnProperty.call(pop, 'bandwidth') && typeof (metrics.bandwidth || metrics.peak_bandwidth_mbps) !== 'undefined') {
      updateData.bandwidth = metrics.bandwidth || metrics.peak_bandwidth_mbps;
    }

    const { error: updateErr } = await supabase.from('pops').update(updateData).eq('id', id);
    if (updateErr) throw updateErr;
    await storePopMetric(id, metrics);
    res.json({ status: 'ok', pop_id: id, timestamp: now });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao processar ping do POP:', err.message);
    res.status(500).json({ error: 'Erro ao processar ping' });
  }
});

// Status do POP (pÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºblico)
app.get('/api/pops/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { data: pop, error } = await supabase.from('pops').select('*').eq('id', id).single();
    if (error || !pop) return res.status(404).json({ error: 'POP nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });

    const last = pop.last_heartbeat || pop.last_seen_at || pop.last_seen || pop.updated_at || pop.created_at;
    const seconds = last ? Math.floor((Date.now() - new Date(last).getTime()) / 1000) : null;
    const status = (seconds !== null && seconds > 60) ? 'offline' : (pop.status || 'online');
    res.json({ id, name: pop.name, status, seconds_since_last: seconds });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao consultar status do POP:', err.message);
    res.status(500).json({ error: 'Erro ao consultar status' });
  }
});

// Registrar POP via MikroTik (pÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºblico)
app.post('/api/pops/register', async (req, res) => {
  try {
    if (!validatePopRegisterToken(req)) {
      return res.status(401).json({ error: 'Unauthorized', reason: 'missing_or_invalid_pop_register_token' });
    }
    const now = new Date().toISOString();
    const { name, ip, location } = req.body || {};
    if (!name || !ip) return res.status(400).json({ error: 'name e ip sÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rios' });

    const popToken = crypto.randomBytes(32).toString('hex');
    // NÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o insere `token` na tabela pops porque o schema atual nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o possui essa coluna.
    const preferred = { ...req.body, name, ip, location, status: 'online', created_at: now, updated_at: now };
    delete preferred.id;
    const fallback = { name, ip, location, status: 'online', created_at: now };

    const { data, error } = await safeInsertWithFallback('pops', preferred, fallback);
    if (error) throw error;

    // Guarda o token em settings para validaÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o futura (se necessÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio)
    try {
      await supabase.from('settings').upsert({
        key: `pop_token_${data.id}`,
        value: { token_hash: hashToken(popToken), token_hint: popToken.slice(-6) },
        updated_at: now
      }, { onConflict: 'key' });
    } catch (_e) {}

    res.status(201).json({ status: 'success', pop_id: data.id, pop_token: popToken });
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao registrar POP:', err.message);
    res.status(500).json({ error: 'Erro ao registrar POP' });
  }
});

app.post('/api/pops/:id/heartbeat', async (req, res) => {
  try {
    const { id } = req.params;
    if (!(await requirePopToken(req, res, id))) return;
    const now = new Date().toISOString();
    const metrics = { ...(req.query || {}), ...(req.body || {}) };
    const { data: pop, error: popErr } = await supabase.from('pops').select('*').eq('id', id).single();
    if (popErr || !pop) return res.sendStatus(404);

    const updateData = { status: 'online', updated_at: now };
    if (Object.prototype.hasOwnProperty.call(pop, 'last_heartbeat')) updateData.last_heartbeat = now;
    if (Object.prototype.hasOwnProperty.call(pop, 'last_seen')) updateData.last_seen = now;
    if (Object.prototype.hasOwnProperty.call(pop, 'last_seen_at')) updateData.last_seen_at = now;
    if (Object.prototype.hasOwnProperty.call(pop, 'users_connected') && typeof metrics.active_users !== 'undefined') updateData.users_connected = metrics.active_users;
    if (Object.prototype.hasOwnProperty.call(pop, 'active_clients') && typeof metrics.active_users !== 'undefined') updateData.active_clients = metrics.active_users;
    if (Object.prototype.hasOwnProperty.call(pop, 'bandwidth') && typeof (metrics.bandwidth || metrics.peak_bandwidth_mbps) !== 'undefined') updateData.bandwidth = metrics.bandwidth || metrics.peak_bandwidth_mbps;

    await supabase.from('pops').update(updateData).eq('id', id);
    await storePopMetric(id, metrics);
    res.sendStatus(200);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro no heartbeat:', err.message);
    res.sendStatus(500);
  }
});

app.get('/api/pops/:popId/commands', async (req, res) => {
  try {
    const { popId } = req.params;
    if (!(await requirePopToken(req, res, popId))) return;
    const { data, error } = await supabase
      .from('pop_commands')
      .select('*')
      .eq('pop_id', popId)
      .eq('status', 'pending')
      .order('created_at', { ascending: true })
      .limit(20);
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    await registerSystemLog('warning', 'pop_commands', 'Falha ao buscar comandos pendentes', { pop_id: req.params.popId, error: err.message });
    res.json([]);
  }
});

app.post('/api/pops/:popId/commands/:commandId/result', async (req, res) => {
  try {
    const { popId, commandId } = req.params;
    if (!(await requirePopToken(req, res, popId))) return;
    const now = new Date().toISOString();
    const status = String(req.body?.status || req.query.status || 'done').toLowerCase() === 'failed' ? 'failed' : 'done';
    const preferred = {
      status,
      attempts: Number(req.body?.attempts || 1),
      last_error: req.body?.error || req.query.error || null,
      executed_at: now
    };
    const fallback = { status, executed_at: now };
    const { error } = await safeUpdateWithFallback('pop_commands', commandId, preferred, fallback);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    await registerSystemLog('warning', 'pop_commands', 'Falha ao confirmar comando do POP', { pop_id: req.params.popId, command_id: req.params.commandId, error: err.message });
    res.status(500).json({ error: 'Erro ao confirmar comando' });
  }
});

app.get('/api/pops/:popId/commands.rsc', async (req, res) => {
  try {
    const { popId } = req.params;
    if (!(await requirePopToken(req, res, popId))) return;
    const token = String(getBearerOrBodyToken(req) || '');
    const { data, error } = await supabase
      .from('pop_commands')
      .select('*')
      .eq('pop_id', popId)
      .eq('status', 'pending')
      .order('created_at', { ascending: true })
      .limit(10);
    if (error) throw error;

    const apiUrl = API_BASE_URL;
    const lines = [':put "MS Telecom POP commands"'];
    for (const command of data || []) {
      if (command.command_type !== 'disconnect_hotspot_user' && command.command_type !== 'disconnect_user') continue;
      const mac = normalizeMac(command.payload?.mac_address || command.payload?.mac || '');
      if (!mac) continue;
      const resultUrl = `${apiUrl}/api/pops/${popId}/commands/${command.id}/result\\?token=${encodeURIComponent(token)}&status=done`;
      lines.push(`:do { /ip hotspot active remove [find user="${mac}"] } on-error={}`);
      lines.push(`:do { /ip hotspot active remove [find mac-address="${mac}"] } on-error={}`);
      lines.push(`:do { /ip hotspot cookie remove [find user="${mac}"] } on-error={}`);
      lines.push(`:do { /ip hotspot cookie remove [find mac-address="${mac}"] } on-error={}`);
      lines.push(`:do { /ip hotspot host remove [find mac-address="${mac}"] } on-error={}`);
      lines.push(`:do { /tool fetch http-method=post url="${resultUrl}" keep-result=no } on-error={}`);
    }
    res.type('text/plain').send(lines.join('\n') + '\n');
  } catch (err) {
    await registerSystemLog('warning', 'pop_commands', 'Falha ao gerar script de comandos do POP', { pop_id: req.params.popId, error: err.message });
    res.type('text/plain').send(':put "no commands"\n');
  }
});

app.get('/api/dashboard/metrics', authMiddleware, async (req, res) => {
  try {
    const metrics = await buildDashboardMetrics();
    res.json(metrics);
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao buscar mÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â©tricas do dashboard:', err.message);
    res.status(500).json({ error: 'Erro ao buscar mÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â©tricas do dashboard' });
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
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao buscar sumÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio:', err.message);
    res.status(500).json({ error: 'Erro ao buscar estatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­sticas' });
  }
});

// EstatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­sticas de usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rios por hora (Dashboard)
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
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao buscar estatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­sticas reais:', error.message);
    res.status(500).json({ error: 'Erro ao buscar estatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­sticas por hora' });
  }
});

// Listar sessÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes ativas (usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rios online)
// EstatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­sticas de trÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡fego total (real quando existir coluna de trÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡fego)
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
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao buscar trÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡fego total:', err.message);
    res.status(500).json({ error: 'Erro ao buscar trÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡fego total' });
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
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao listar sessÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes ativas:', err.message);
    res.status(500).json({ error: 'Erro ao listar sessÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes ativas' });
  }
});

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ ROTAS DE BACKUP
// ============================================================

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸Ãƒâ€šÃ‚ÂÃƒâ€šÃ‚Â¥ HEALTH CHECK
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

// Rotas pÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºblicas para o portal
app.get('/api/public/plans', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('plans')
      .select('*')
      .eq('active', true)
      .order('price', { ascending: true });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar planos' });
  }
});

app.get('/api/public/free-trial-config', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('settings')
      .select('value')
      .eq('key', 'free_trial')
      .maybeSingle();
    if (error) throw error;
    const config = data?.value || { enabled: false, duration_minutes: 15, cooldown_hours: 24 };
    res.json(config);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o do teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis' });
  }
});

// Debug: retorna IP real visto pelo backend
app.get('/api/test-ip', (req, res) => {
  res.json({
    ip: getClientIp(req),
    x_forwarded_for: req.headers['x-forwarded-for'] || null,
    remote_address: req.socket?.remoteAddress || null
  });
});

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸Ãƒâ€¦Ã¢â‚¬â„¢Ãƒâ€šÃ‚Â ENTRYPOINT (MikroTik -> API -> Portal)
// ============================================================

app.get('/entrypoint', (req, res) => {
  const q = req.query || {};
  const mac = (q.mac || q.mac_address || q.called || q['mac-address'] || '').toString();
  const ip = (q.ip || q.ip_address || q.nasip || '').toString();
  const pop = (q.pop || q.pop_id || q.hotspot || '').toString();

  const url = new URL('/portal.html', FRONTEND_BASE_URL);
  if (mac) url.searchParams.set('mac', mac);
  if (ip) url.searchParams.set('ip', ip);
  if (pop) url.searchParams.set('pop', pop);

  return res.redirect(302, url.toString());
});

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œÃƒâ€¦Ã‚Â  ESTATÃƒÆ’Ã†â€™Ãƒâ€šÃ‚ÂSTICAS E DASHBOARD
// ============================================================

// Nota: Rotas de estatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­sticas e POPs jÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡ definidas anteriormente no arquivo.
// Removendo duplicaÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes para evitar conflitos.

// ============================================================
// ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã‚Â¡ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¸Ãƒâ€šÃ‚Â CONFIGURAÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ES DE CAMPOS DE CADASTRO
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
      { field: 'gender', label: 'GÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âªnero', enabled: false, required: false }
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

async function getPortalRegistrationFields() {
  const defaultFields = [
    { field: 'name', label: 'Nome Completo', enabled: true, required: true },
    { field: 'phone', label: 'Telefone/WhatsApp', enabled: true, required: true },
    { field: 'email', label: 'E-mail', enabled: false, required: false },
    { field: 'cpf', label: 'CPF', enabled: false, required: false },
    { field: 'birth_date', label: 'Data de Nascimento', enabled: false, required: false },
    { field: 'gender', label: 'GÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âªnero', enabled: false, required: false },
    { field: 'terms', label: 'Aceite dos termos', enabled: false, required: false }
  ];

  const { data, error } = await supabase.from('settings').select('value').eq('key', 'registration_fields').maybeSingle();
  if (error) throw error;
  return Array.isArray(data?.value) && data.value.length ? data.value : defaultFields;
}

function sanitizePortalRegistration(body, fields) {
  const enabled = new Set((fields || []).filter(f => f.enabled !== false).map(f => f.field));
  const payload = {};
  if (enabled.has('name') && body.name) payload.name = String(body.name).trim();
  if (enabled.has('phone') && body.phone) payload.phone = String(body.phone).replace(/[^\d+]/g, '');
  if (enabled.has('email')) payload.email = String(body.email || '').trim() || null;
  if (enabled.has('cpf')) payload.cpf = String(body.cpf || '').replace(/\D/g, '') || null;
  if (enabled.has('birth_date') && body.birth_date) payload.birth_date = body.birth_date;
  if (enabled.has('gender') && body.gender) payload.gender = String(body.gender).trim();
  return payload;
}

function getMissingRegistrationFields(user, fields) {
  return (fields || [])
    .filter(f => f.enabled !== false && f.required === true)
    .map(f => f.field)
    .filter(field => {
      if (field === 'terms') return false;
      const value = user ? user[field] : '';
      return value === null || value === undefined || String(value).trim() === '';
    });
}

app.get('/api/portal/registration-fields', async (_req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const fields = await getPortalRegistrationFields();
    res.json(fields.filter(f => f.enabled !== false));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/portal/registration-status', async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const cleanMac = normalizeMac(req.query.mac || req.query.mac_address);
    if (!cleanMac) return res.json({ exists: false, complete: true, missing_fields: [] });

    const fields = await getPortalRegistrationFields();
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .in('mac_address', getMacVariants(cleanMac))
      .maybeSingle();
    if (error) throw error;

    const missing = getMissingRegistrationFields(user, fields);
    res.json({
      exists: !!user,
      first_connection: !user,
      complete: missing.length === 0,
      missing_fields: missing,
      user: user ? { name: user.name || '' } : null
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// ============================================================
// ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã‚Â¡ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¸Ãƒâ€šÃ‚Â CONFIGURAÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ES DO SISTEMA (SETTINGS)
// ============================================================

// Buscar configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes gerais
// Buscar configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes consolidadas (compat com HTMLs)
app.get('/api/settings', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('value').eq('key', 'system').maybeSingle();
    if (error) throw error;
    res.json(scrubSecretObject(data?.value || {}));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Salvar configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes consolidadas (compat com HTMLs)
app.put('/api/settings', authMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('settings').upsert({
      key: 'system',
      value: stripSecretFields(req.body),
      updated_at: new Date().toISOString()
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Aliases legado PT (configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes)
app.get('/api/settings/system', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('value').eq('key', 'system').maybeSingle();
    if (error) throw error;
    res.json(scrubSecretObject(data?.value || {}));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Salvar configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes gerais
app.put('/api/settings/system', authMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('settings').upsert({
      key: 'system',
      value: stripSecretFields(req.body),
      updated_at: new Date().toISOString()
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Buscar configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes de pagamento
app.get('/api/settings/payment', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('value').eq('key', 'payment').maybeSingle();
    if (error) throw error;
    res.json(scrubSecretObject(data?.value || {}));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Salvar configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes de pagamento
app.put('/api/settings/payment', authMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from('settings').upsert({
      key: 'payment',
      value: stripSecretFields(req.body),
      updated_at: new Date().toISOString()
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Buscar configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes de teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis
// Buscar configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes de integraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes
app.get('/api/settings/integrations', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('value').eq('key', 'integrations').maybeSingle();
    if (error) throw error;
    res.json(scrubSecretObject(data?.value || {}));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Salvar configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes de integraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes
app.put('/api/settings/integrations', authMiddleware, async (req, res) => {
  try {
    const blockedSecretKeys = /(supabase.*key|radius.*secret|mercado.*token|mercadopago.*token|vpn.*psk|ssh.*key|password|api_pass|secret|token)/i;
    const sanitized = {};
    for (const [key, value] of Object.entries(req.body || {})) {
      if (blockedSecretKeys.test(key)) continue;
      sanitized[key] = value;
    }
    const { error } = await supabase.from('settings').upsert({
      key: 'integrations',
      value: sanitized,
      updated_at: new Date().toISOString()
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/settings/free_trial', async (req, res) => {
  try {
    const cfg = await getFreeTrialConfig();
    const out = {
      enabled: cfg.enabled,
      duration_seconds: cfg.duration_seconds,
      cooldown_seconds: cfg.cooldown_seconds,
      duration_minutes: Math.max(1, Math.ceil(cfg.duration_seconds / 60)),
      reuse_cooldown_hours: Math.ceil(cfg.cooldown_seconds / 3600),
      cooldown_hours: Math.ceil(cfg.cooldown_seconds / 3600)
    };
    res.set('Cache-Control', 'no-store');
    res.json(out);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// Salvar configuraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes de teste grÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis
app.put('/api/settings/free_trial', authMiddleware, async (req, res) => {
  try {
    const value = normalizeFreeTrialConfig(req.body && typeof req.body === 'object' ? req.body : {});

    const { error } = await supabase.from('settings').upsert(
      {
        key: 'free_trial',
        value,
        updated_at: new Date().toISOString()
      },
      { onConflict: 'key' }
    );
    if (error) throw error;
    res.set('Cache-Control', 'no-store');
    res.json({ success: true, value });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸Ãƒâ€šÃ‚ÂªÃƒâ€šÃ‚Â WEBHOOKS
// ============================================================

// Webhook do Mercado Pago (PÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºblico)
// Aliases legado
app.post('/api/webhooks/mercadopago', async (req, res) => {
  try {
    const { action, data, type } = req.body;
    
    // Mercado Pago envia notificaÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âµes de diferentes tipos, focamos em 'payment'
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
          // Buscamos a duraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o do plano
          const { data: plan } = await supabase.from('plans').select('*').eq('name', payment.plan_name).maybeSingle();
          const durationMinutes = (plan?.duration_days || 1) * 24 * 60;
          const cleanMac = normalizeMac(payment.user_mac);
          
          await authorizeAccess(
            cleanMac,
            '192.168.32.1', 
            null, null, null, 
            durationMinutes, 
            plan?.speed_mbps || 10, 
            payment.plan_name
          );

          // 4. Registrar sessÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o
          await supabase.from('hotspot_sessions').insert({
            mac_address: cleanMac,
            plan_name: payment.plan_name,
            status: 'active',
            expires_at: new Date(Date.now() + durationMinutes * 60000).toISOString(),
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          });

          // 5. Disparar webhooks internos
          const { data: internalWebhooks } = await supabase.from('webhooks').select('*').eq('active', true).eq('event', 'payment.confirmed');
          for (const wh of internalWebhooks || []) {
            fetch(wh.url, {
              method: wh.method || 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ event: 'payment.confirmed', payment_id: payment.id, mac: payment.user_mac })
            }).catch(err => console.error(`ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro ao disparar webhook ${wh.name}:`, err.message));
          }

          await registerSystemLog('info', 'mercadopago', `Pagamento aprovado e acesso liberado: ${payment.user_mac}`);
        }
      }
    }
    
    res.status(200).send('OK');
  } catch (err) {
    console.error('ÃƒÆ’Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒâ€¦Ã¢â‚¬â„¢ Erro no Webhook Mercado Pago:', err.message);
    res.status(200).send('OK'); // Sempre retornar 200 para o MP nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o ficar retransmitindo em loop
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

// Rota de ediÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o via POST (conforme frontend webhooks.html)
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

app.post('/api/webhooks/:id/test', authMiddleware, async (req, res) => {
  try {
    const { data: webhook } = await supabase.from('webhooks').select('*').eq('id', req.params.id).single();
    if (!webhook) return res.status(404).json({ error: 'Webhook nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });
    
    // SimulaÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o de disparo
    console.log(`[TEST] Disparando webhook ${webhook.name} para ${webhook.url}`);
    res.json({ success: true, message: 'Teste disparado com sucesso' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œÃƒâ€šÃ‚Â£ CAMPANHAS
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
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œÃƒâ€¦Ã¢â‚¬Å“ LOGS DE AUDITORIA
// ============================================================

app.get('/api/audit-logs', authMiddleware, async (req, res) => {
  try {
    const { user, type, action, start_date, end_date, search } = req.query;
    let query = supabase.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(300);

    if (user) query = query.ilike('username', `%${user}%`);
    if (type) query = query.eq('type', type);
    if (action) query = query.eq('action', action);
    if (start_date) query = query.gte('created_at', start_date);
    if (end_date) query = query.lte('created_at', end_date);
    if (search) {
      query = query.or(`username.ilike.%${search}%,type.ilike.%${search}%,object.ilike.%${search}%,action.ilike.%${search}%,ip.ilike.%${search}%,user_agent.ilike.%${search}%,details.ilike.%${search}%`);
    }

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢Ãƒâ€šÃ‚Â¾ BACKUP
// ============================================================

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œÃƒâ€šÃ‚Â LOGS DO SISTEMA
// ============================================================

app.get('/api/logs', authMiddleware, async (req, res) => {
  try {
    const { start_date, end_date, search, type, level } = req.query;
    let query = supabase.from('logs').select('*').order('created_at', { ascending: false }).limit(200);

    if (type) query = query.eq('source', type);
    if (level) query = query.eq('level', level);
    if (start_date) query = query.gte('created_at', start_date);
    if (end_date) query = query.lte('created_at', end_date);
    if (search) {
      query = query.or(`message.ilike.%${search}%,source.ilike.%${search}%,level.ilike.%${search}%,ip.ilike.%${search}%,user_agent.ilike.%${search}%,details.ilike.%${search}%`);
    }

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// Listar backups
app.get('/api/backup/list', authMiddleware, requireRole('owner'), async (req, res) => {
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

// Download de backup
app.get('/api/backup/download/:filename', authMiddleware, requireRole('owner'), (req, res) => {
  const filename = path.basename(req.params.filename || '');
  if (!/^[\w.-]+\.json$/.test(filename)) return res.status(400).json({ error: 'Nome de arquivo invÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡lido' });
  const filePath = path.join(BACKUP_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Arquivo nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });
  res.download(filePath);
});

app.post('/api/backup/create', authMiddleware, requireRole('owner'), async (req, res) => {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `backup-${timestamp}.json`;
    const filePath = path.join(BACKUP_DIR, filename);

    // Backup simples das tabelas principais
    const tables = ['users', 'vouchers', 'payments', 'pops', 'plans', 'settings', 'admins', 'webhooks', 'campaigns', 'mikrotik_credentials'];
    const backupData = {};

    for (const table of tables) {
      const { data } = await supabase.from(table).select('*');
      backupData[table] = (data || []).map((record) => sanitizeBackupRecord(table, record));
    }

    fs.writeFileSync(filePath, JSON.stringify(backupData, null, 2));
    
    await registerAuditLog(req.user.username, 'backup', 'sistema', `Backup criado: ${filename}`);
    
    res.json({ success: true, filename });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾ ALIAS E ROTAS DE COMPATIBILIDADE
// ============================================================

// Alias para portal pÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºblico
app.get('/api/portal/plans', async (req, res) => {
  const { data, error } = await supabase.from('plans').select('*').eq('active', true).order('price');
  if (error) return res.status(500).json({ error: 'Erro ao listar planos' });
  res.json(data || []);
});

app.post('/api/portal/create-pix', paymentLimiter, async (req, res) => {
  try {
    const { mac_address } = req.body || {};
    const cleanMac = normalizeMac(mac_address);
    if (cleanMac) {
      // Libera acesso temporario para realizar pagamento (janela curta)
      const durationMinutes = 5;
      const expiresAt = new Date(Date.now() + durationMinutes * 60000).toISOString();

      const result = await authorizeAccess(cleanMac, '192.168.32.1', null, null, null, durationMinutes, 5, 'payment_window');
      if (result?.success) {
        await supabase.from('hotspot_sessions').insert({
          mac_address: cleanMac,
          status: 'active',
          expires_at: expiresAt,
          created_at: new Date().toISOString()
        });
      }
    }
  } catch (_e) {
    // ignora erro de janela temporaria (nao bloqueia a geracao do PIX)
  }

  // Encaminha para a rota oficial de geraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o de PIX
  req.url = '/api/payments/generate-pix';
  return app._router.handle(req, res);
});

app.get('/api/portal/check-payment/:id', async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase.from('payments').select('*').eq('id', id).single();
  if (error || !data) return res.status(404).json({ error: 'Pagamento nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });
  res.json(data);
});

app.post('/api/portal/login', async (req, res) => {
  try {
    const { identifier, password, mac_address } = req.body;
    const { data: user, error } = await supabase.from('users').select('*')
      .or(`username.eq.${identifier},email.eq.${identifier},cpf.eq.${identifier},phone.eq.${identifier}`)
      .single();
    if (error || !user) return res.status(401).json({ error: 'UsuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    if (user.password !== hashedPassword && user.password !== password) return res.status(401).json({ error: 'Senha incorreta' });

    const cleanMac = normalizeMac(mac_address);
    if (cleanMac) await supabase.from('users').update({ mac_address: cleanMac, updated_at: new Date().toISOString() }).eq('id', user.id);
    
    const status = (user.status === 'active' && user.expires_at && new Date(user.expires_at) > new Date()) ? 'active' : 'expired';
    res.json({ user_id: user.id, username: user.username, status, plan_id: user.plan_id });
  } catch (err) {
    res.status(500).json({ error: 'Erro no login' });
  }
});

async function handlePortalRegister(req, res) {
  try {
    const cleanMac = normalizeMac(req.body.mac_address || req.body.mac);
    if (!cleanMac) return res.status(400).json({ error: 'MAC obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rio' });

    const fields = await getPortalRegistrationFields();
    const missingBody = (fields || [])
      .filter(f => f.enabled !== false && f.required === true)
      .map(f => f.field)
      .filter(field => field !== 'terms' && !String(req.body[field] || '').trim());
    if (missingBody.length) return res.status(400).json({ error: 'Campos obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rios ausentes', missing_fields: missingBody });

    const payload = sanitizePortalRegistration(req.body, fields);
    const now = new Date().toISOString();

    const { data: existing, error: existingError } = await supabase
      .from('users')
      .select('*')
      .in('mac_address', getMacVariants(cleanMac))
      .maybeSingle();
    if (existingError) throw existingError;

    if (existing) {
      const updatePayload = { ...payload, updated_at: now };
      const { data, error } = await supabase.from('users').update(updatePayload).eq('id', existing.id).select().single();
      if (error) throw error;
      return res.json({ user_id: data.id, username: data.username, existing: true });
    }

    const username = cleanMac;
    const password = req.body.password || `portal-${cleanMac.replace(/:/g, '')}`;
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    const insertPayload = {
      username,
      password: hashedPassword,
      mac_address: cleanMac,
      status: 'pending',
      created_at: now,
      updated_at: now,
      ...payload
    };

    const { data, error } = await supabase.from('users').insert(insertPayload).select().single();
    if (error) throw error;
    res.status(201).json({ user_id: data.id, username: data.username });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Erro no cadastro' });
  }
}

app.post('/api/portal/register-device', portalWriteLimiter, handlePortalRegister);
app.post('/api/portal/register', portalWriteLimiter, handlePortalRegister);
app.post('/api/portal/voucher', async (req, res) => {
  // Encaminha para a rota oficial de validaÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o de voucher
  req.url = '/api/vouchers/validate';
  app._router.handle(req, res);
});

app.get('/api/portal/status', async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const { mac, mac_address } = req.query;
    const targetMac = normalizeMac(mac || mac_address);
    if (!targetMac) return res.json({ connected: false });
    
    const { data: session } = await supabase.from('hotspot_sessions').select('*').in('mac_address', getMacVariants(targetMac)).eq('status', 'active').maybeSingle();
    if (session && new Date(session.expires_at) > new Date()) {
      return res.json({ connected: true, expires_at: session.expires_at });
    }
    res.json({ connected: false });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao verificar status' });
  }
});
// Rota pÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºblica para verificar status de pagamento por MAC (usada pelo portal)
app.get('/api/portal/payment-status', async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const { mac_address } = req.query;
    const cleanMac = normalizeMac(mac_address);
    if (!cleanMac) return res.status(400).json({ error: 'MAC ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â© obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rio' });

    const { data, error } = await supabase.from('payments')
      .select('*')
      .in('user_mac', getMacVariants(cleanMac))
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error) throw error;
    res.json(data || { status: 'not_found' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao verificar status de pagamento' });
  }
});
// Rota de compatibilidade para o portal pÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºblico que chama /api/payments sem token
app.get('/api/payments', async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const { mac_address } = req.query;

  // Se NÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢O tem token e tem mac_address, redireciona para a rota pÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºblica do portal
  if (!authHeader && mac_address) {
    req.url = '/api/portal/payment-status';
    return app._router.handle(req, res);
  }

  // Caso contrÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio, segue para o middleware de autenticaÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o e rota admin
  next();
});

// Rota de Teste GrÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tis (chamada pelo frontend)
app.post('/api/users/test-access', accessLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const macAddress = body.mac_address || body.mac;
    const ipAddress = body.ip_address ?? body.ip ?? null;
    const popId = getPopRefFromPayload(body);
    const popIp = body.pop_ip ?? null;

    const out = await handleFreeTrialAccess({ macAddress, durationMinutes: null, ipAddress, popId, popIp });
    return res.status(out.status).json(out.body);
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Legacy alias to ease tests / older clients.
app.post('/api/liberar-teste', async (req, res) => {
  try {
    const body = req.body || {};
    const macAddress = body.mac_address || body.mac;
    const ipAddress = body.ip_address || body.ip || null;
    const popId = getPopRefFromPayload(body);
    const popIp = body.pop_ip || null;

    const out = await handleFreeTrialAccess({ macAddress, durationMinutes: null, ipAddress, popId, popIp });
    return res.status(out.status).json(out.body);
  } catch (_err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“Ãƒâ€šÃ‚Â¤ GESTÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢O DE ADMINISTRADORES (ADMINS)
// ============================================================

// Listar todos os administradores
// Free trial (pÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºblico) - 1 uso por MAC
app.post('/api/free-trial', accessLimiter, async (req, res) => {
  try {
    const { mac_address, mac } = req.body || {};
    if (!mac_address && !mac) return res.status(400).json({ success: false, message: 'MAC ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â© obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rio' });

    const out = await handleFreeTrialAccess({
      macAddress: mac_address || mac,
      durationMinutes: null,
      ipAddress: req.body?.ip_address ?? req.body?.ip ?? null,
      popId: getPopRefFromPayload(req.body || {}),
      popIp: req.body?.pop_ip ?? req.body?.ip_address ?? req.body?.ip ?? null
    });

    if (!out.ok) return res.status(out.status).json({ success: false, message: out.body?.error || 'Erro ao liberar acesso', ...out.body });
    res.json({ success: true, expires_at: out.body?.expires_at, message: out.body?.message || 'Acesso liberado', user_id: out.body?.user_id, ...out.body });
  } catch (_err) {
    res.status(500).json({ success: false, message: 'Erro interno' });
  }
});
// Validar acesso (pÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºblico)
app.post('/api/access/validate', async (req, res) => {
  try {
    const { mac_address } = req.body || {};
    const cleanMac = normalizeMac(mac_address);
    if (!cleanMac) return res.status(400).json({ authorized: false });

    const now = new Date().toISOString();
    const { data: session, error } = await supabase
      .from('hotspot_sessions')
      .select('*')
      .in('mac_address', getMacVariants(cleanMac))
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

// Access status (public): used by captive portal to auto-liberate devices with an active paid plan/session.
app.get('/api/access/status', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const macRaw = String(req.query.mac || req.query.mac_address || '').trim();
  const cleanMac = normalizeMac(macRaw);
  if (!cleanMac) return res.status(400).json({ allowed: false, reason: 'missing_mac', show_free_trial: false });

  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const popId = getPopRefFromPayload(req.query);
  const popIp = req.query.pop_ip ?? null;
  const popContext = await resolvePopContext(popId, popIp);
  const effectivePopId = popContext.pop_id || popId || null;
  const effectivePopIp = popContext.pop_ip || popIp || null;

  try {
    const variants = getMacVariants(cleanMac);

    const { data: user } = await supabase
      .from('users')
      .select('*')
      .in('mac_address', variants)
      .order('updated_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (isActivePaidUser(user)) {
      const planName = user.plan_name || 'Premium';
      const durationForPlan = user.expires_at
        ? Math.max(10, Math.ceil((new Date(user.expires_at).getTime() - nowMs) / 1000))
        : 30 * 24 * 60 * 60;
      const { data: plan } = await supabase.from('plans').select('*').eq('name', planName).maybeSingle();
      await authorizeAccess(cleanMac, effectivePopIp || '192.168.32.1', null, null, effectivePopId || user.hotspot_id || null, Math.ceil(durationForPlan / 60), plan?.speed_mbps || 10, planName, durationForPlan);
      await saveHotspotSession({
        ...(user?.id ? { user_id: user.id } : {}),
        mac_address: cleanMac,
        access_granted: true,
        status: 'active',
        expires_at: user.expires_at || null,
        plan_name: planName,
        ...(effectivePopId ? { pop_id: effectivePopId } : {}),
        ...(effectivePopIp ? { pop_ip: effectivePopIp } : {}),
        ...(popContext.pop_name ? { pop_name: popContext.pop_name } : {}),
        ...(popContext.pop_location ? { pop_location: popContext.pop_location } : {}),
        created_at: nowIso,
        updated_at: nowIso
      });
      return res.json({ allowed: true, reason: 'manual_plan_active', show_free_trial: false, expires_at: user.expires_at || null });
    }

    const { data: payment } = await supabase
      .from('payments')
      .select('*')
      .in('user_mac', variants)
      .in('status', ['approved', 'confirmed', 'pago', 'paid'])
      .order('approved_at', { ascending: false, nullsFirst: false })
      .order('updated_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (payment) {
      const { data: plan } = await supabase.from('plans').select('*').eq('name', payment.plan_name).maybeSingle();
      const approvedAt = new Date(payment.approved_at || payment.updated_at || payment.created_at || nowIso).getTime();
      const durationDays = Number(plan?.duration_days || 1);
      const expiresAt = new Date(approvedAt + durationDays * 24 * 60 * 60 * 1000).toISOString();
      if (new Date(expiresAt).getTime() > nowMs) {
        const durationSeconds = Math.max(10, Math.ceil((new Date(expiresAt).getTime() - nowMs) / 1000));
        await authorizeAccess(cleanMac, effectivePopIp || '192.168.32.1', null, null, effectivePopId, Math.ceil(durationSeconds / 60), plan?.speed_mbps || 10, payment.plan_name || 'paid_plan', durationSeconds);
        await saveHotspotSession({
          mac_address: cleanMac,
          access_granted: true,
          status: 'active',
          expires_at: expiresAt,
          plan_name: payment.plan_name || 'paid_plan',
          ...(effectivePopId ? { pop_id: effectivePopId } : {}),
          ...(effectivePopIp ? { pop_ip: effectivePopIp } : {}),
          ...(popContext.pop_name ? { pop_name: popContext.pop_name } : {}),
          ...(popContext.pop_location ? { pop_location: popContext.pop_location } : {}),
          created_at: nowIso,
          updated_at: nowIso
        });
        return res.json({ allowed: true, reason: 'paid_plan_active', show_free_trial: false, expires_at: expiresAt });
      }
    }

    const { data: session } = await supabase
      .from('hotspot_sessions')
      .select('*')
      .in('mac_address', variants)
      .eq('status', 'active')
      .gt('expires_at', nowIso)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (session) {
      if (effectivePopId && (!session.pop_id || !session.pop_name || !session.pop_location)) {
        await saveHotspotSession({
          ...session,
          pop_id: effectivePopId,
          ...(effectivePopIp ? { pop_ip: effectivePopIp } : {}),
          ...(popContext.pop_name ? { pop_name: popContext.pop_name } : {}),
          ...(popContext.pop_location ? { pop_location: popContext.pop_location } : {}),
          updated_at: nowIso
        });
      }
      return res.json({ allowed: true, reason: 'active_session', show_free_trial: false, expires_at: session.expires_at });
    }

    const cfg = await getFreeTrialConfig();
    if (!cfg.enabled) {
      return res.json({ allowed: false, reason: 'no_access', show_free_trial: false });
    }

    try {
      const { data: ft } = await supabase
        .from('free_trials')
        .select('*')
        .in('mac_address', variants)
        .order('updated_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      if (ft) {
        const effectiveUntil = getTrialCooldownUntil(ft, cfg);

        if (effectiveUntil && new Date(effectiveUntil).getTime() > nowMs) {
          const retryAfterSeconds = Math.max(1, Math.ceil((new Date(effectiveUntil).getTime() - nowMs) / 1000));
          await registerSystemLog('info', 'free_trial', 'Status de acesso em cooldown', { mac: cleanMac, retry_after_seconds: retryAfterSeconds, cooldown_until: effectiveUntil });
          return res.json({ allowed: false, reason: 'cooldown', show_free_trial: false, retry_after_seconds: retryAfterSeconds });
        }
      }
    } catch (error) {
      await registerSystemLog('error', 'free_trial', 'Erro ao verificar cooldown em free_trials', { mac: cleanMac, error: error.message });
    }

    try {
      const lastTrialSession = await getLastTrialSession(variants);
      const sessionCooldownUntil = getTrialCooldownUntil(lastTrialSession, cfg);
      if (sessionCooldownUntil && new Date(sessionCooldownUntil).getTime() > nowMs) {
        const retryAfterSeconds = Math.max(1, Math.ceil((new Date(sessionCooldownUntil).getTime() - nowMs) / 1000));
        await registerSystemLog('info', 'free_trial', 'Status de acesso em cooldown por sessao', { mac: cleanMac, retry_after_seconds: retryAfterSeconds, cooldown_until: sessionCooldownUntil });
        return res.json({ allowed: false, reason: 'cooldown', show_free_trial: false, retry_after_seconds: retryAfterSeconds });
      }
    } catch (error) {
      await registerSystemLog('error', 'free_trial', 'Erro ao verificar cooldown por sessao no status', { mac: cleanMac, error: error.message });
    }

    return res.json({ allowed: false, reason: 'trial_available', show_free_trial: true });
  } catch (error) {
    console.error('Erro ao verificar status de acesso:', error);
    await registerSystemLog('error', 'access_status', 'Erro ao verificar status de acesso', { mac: cleanMac, error: error.message });
    res.status(500).json({ allowed: false, reason: 'internal_error', show_free_trial: false });
  }
});
app.post('/api/auth/check', (req, res) => {
  req.url = '/api/access/validate';
  return app._router.handle(req, res);
});

app.get('/api/admins', authMiddleware, requireRole('owner'), async (req, res) => {
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
app.post('/api/admins', authMiddleware, requireRole('owner'), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const role = String(req.body.role || 'admin').toLowerCase();
    
    if (!username || !password) {
      return res.status(400).json({ error: 'UsuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio e senha sÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rios' });
    }
    if (!ADMIN_ROLES.has(role) || role === 'owner') {
      return res.status(403).json({ error: 'Role nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o permitida', reason: 'role_escalation_blocked' });
    }

    const hashedPassword = hashPassword(password);
    
    const { data, error } = await supabase
      .from('admins')
      .insert([{ 
        username, 
        email: normalizeEmail(email),
        password: hashedPassword, 
        role,
        created_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (error) throw error;

    await registerAuditLog(req.user.username, 'create', 'admin', `Criou administrador: ${username}`, getClientIp(req), req.headers['user-agent']);
    
    res.status(201).json({ success: true, id: data.id });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao criar administrador' });
  }
});

// Atualizar administrador
app.put('/api/admins/:id', authMiddleware, requireRole('owner'), async (req, res) => {
  try {
    const { id } = req.params;
    const { username, email, password, role } = req.body;
    const requestedRole = role ? String(role).toLowerCase() : null;
    if (requestedRole && (!ADMIN_ROLES.has(requestedRole) || requestedRole === 'owner')) {
      return res.status(403).json({ error: 'Role nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o permitida', reason: 'role_escalation_blocked' });
    }
    if (String(id) === String(req.user.id) && requestedRole) {
      return res.status(403).json({ error: 'NÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â© permitido alterar o prÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³prio role', reason: 'self_role_change_blocked' });
    }
    
    const updateData = {};
    if (username) updateData.username = username;
    if (Object.prototype.hasOwnProperty.call(req.body, 'email')) updateData.email = normalizeEmail(email);
    if (requestedRole) updateData.role = requestedRole;
    if (password) {
      updateData.password = hashPassword(password);
    }

    const { error } = await supabase
      .from('admins')
      .update(updateData)
      .eq('id', id);

    if (error) throw error;

    await registerAuditLog(req.user.username, 'update', 'admin', `Atualizou administrador ID: ${id}`, getClientIp(req), req.headers['user-agent']);
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao atualizar administrador' });
  }
});

// Deletar administrador
app.delete('/api/admins/:id', authMiddleware, requireRole('owner'), async (req, res) => {
  try {
    const { id } = req.params;

    // Impedir que o admin delete a si mesmo
    if (id == req.user.id) {
      return res.status(400).json({ error: 'VocÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âª nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o pode excluir seu prÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³prio usuÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rio' });
    }

    const { data: target, error: targetError } = await supabase
      .from('admins')
      .select('id, role')
      .eq('id', id)
      .maybeSingle();
    if (targetError) throw targetError;
    if (!target) return res.status(404).json({ error: 'Administrador nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado' });
    if (target.role === 'owner') {
      const { count, error: countError } = await supabase
        .from('admins')
        .select('id', { count: 'exact', head: true })
        .eq('role', 'owner');
      if (countError) throw countError;
      if ((count || 0) <= 1) {
        return res.status(409).json({ error: 'NÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â© permitido excluir o ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Âºltimo owner', reason: 'last_owner_blocked' });
      }
    }

    const { error } = await supabase
      .from('admins')
      .delete()
      .eq('id', id);

    if (error) throw error;

    await registerAuditLog(req.user.username, 'delete', 'admin', `Excluiu administrador ID: ${id}`, getClientIp(req), req.headers['user-agent']);
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao deletar administrador' });
  }
});

// ============================================================
// ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸Ãƒâ€¦Ã‚Â¡ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ INICIAR SERVIDOR
// ============================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â
ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“  ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸Ãƒâ€¦Ã‚Â¡ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ MS TELECOM - HOTSPOT SYSTEM API                         ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“
ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ Servidor rodando em: http://localhost:${PORT}              ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“
ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ Ambiente: ${process.env.NODE_ENV || 'production'}                      ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“
ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ PadrÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o: CÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³digo EN, ComentÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡rios PT-BR                     ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“
ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ Endpoints: /api/users, /api/plans, /api/payments         ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“
ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ Tabelas: users, plans, payments, pops                    ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“
ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ IntegraÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o: MikroTik API, Mercado Pago, RADIUS           ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“
ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ Deploy AutomÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tico: GitHub Actions ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ VPS                  ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“
ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ CRON: RemoÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o automÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡tica de acessos expirados            ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“
ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚ÂÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢Ãƒâ€šÃ‚Â
  `);
});
