// ============================================
// 🚀 HOTSPOT SYSTEM - SERVER COMPLETO
// ============================================
// Descrição: Servidor principal do sistema de Hotspot.
// Padrões: Código em inglês, comentários em português.
// Deploy: Automático via GitHub Actions
// ============================================

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { RouterOSAPI } = require('node-routeros');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// ============================================
// 🔑 CONFIGURAÇÕES (Variáveis de Ambiente)
// ============================================
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;
const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000';
const RADIUS_SERVER_IP = process.env.RADIUS_SERVER_IP || '40.233.118.238';
const RADIUS_SECRET = process.env.RADIUS_SECRET || '';
const MIKROTIK_HOST = process.env.MIKROTIK_HOST || '';
const MIKROTIK_USER = process.env.MIKROTIK_USER || '';
const MIKROTIK_PASS = process.env.MIKROTIK_PASS || '';
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN || '';
const MP_WEBHOOK_URL = process.env.MP_WEBHOOK_URL || '';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '10', 10);

if (!supabaseUrl || !supabaseKey || !JWT_SECRET) {
    console.error('❌ ERRO: Variáveis de ambiente não configuradas!');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// ============================================
// 🛠️ FUNÇÕES UTILITÁRIAS
// ============================================

function removeAccents(str) {
    return str.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function generateStrongPassword(length = 16) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    let password = '';
    for (let i = 0; i < length; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
}

function safeString(value, fallback = '') {
    if (value === null || value === undefined) {
        return fallback;
    }
    return String(value);
}

function safeNumber(value, fallback = 0) {
    const numericValue = Number(value);
    return Number.isFinite(numericValue) ? numericValue : fallback;
}

function safeBoolean(value, fallback = false) {
    if (value === null || value === undefined || value === '') {
        return fallback;
    }

    if (typeof value === 'boolean') {
        return value;
    }

    const normalizedValue = safeString(value).trim().toLowerCase();
    return ['true', '1', 'sim', 'yes', 'ativo', 'active'].includes(normalizedValue);
}

function generateSecureCode(prefix = 'MS', size = 8) {
    const normalizedSize = Math.max(6, safeNumber(size, 8));
    const randomCode = crypto
        .randomBytes(Math.ceil(normalizedSize / 2))
        .toString('hex')
        .slice(0, normalizedSize)
        .toUpperCase();

    return `${prefix}-${randomCode}`;
}

function normalizeMacAddress(value) {
    const rawValue = safeString(value).trim().toUpperCase();
    const alphanumeric = rawValue.replace(/[^0-9A-F]/g, '');

    if (alphanumeric.length !== 12) {
        return rawValue;
    }

    return alphanumeric.match(/.{1,2}/g).join(':');
}

function isBcryptHash(value) {
    return typeof value === 'string' && /^\$2[aby]\$\d{2}\$/.test(value);
}

async function verifyAdminPassword(admin, plainPassword) {
    if (!admin || !plainPassword) {
        return false;
    }

    if (isBcryptHash(admin.password)) {
        return bcrypt.compare(plainPassword, admin.password);
    }

    return admin.password === plainPassword;
}

async function buildAdminAuthResponse(admin) {
    const token = jwt.sign(
        { id: admin.id, username: admin.username, role: admin.role },
        JWT_SECRET,
        { expiresIn: '24h' }
    );

    return {
        token,
        admin: {
            id: admin.id,
            username: admin.username,
            email: admin.email || null,
            role: admin.role || 'admin'
        }
    };
}

function normalizePaymentStatus(status) {
    const statusMap = {
        confirmado: 'confirmed',
        paid: 'confirmed',
        pago: 'confirmed',
        pendente: 'pending',
        pending: 'pending',
        cancelado: 'canceled',
        cancelled: 'canceled',
        canceled: 'canceled',
        ativo: 'active',
        active: 'active',
        bloqueado: 'blocked',
        blocked: 'blocked',
        offline: 'offline',
        online: 'online'
    };

    if (!status) {
        return 'pending';
    }

    const normalizedStatus = statusMap[safeString(status).toLowerCase()];
    return normalizedStatus || safeString(status).toLowerCase();
}

function formatPlan(plan = {}) {
    const name = plan.name || plan.nome || 'Plano';
    const price = safeNumber(plan.price ?? plan.valor);
    const speedMbps = safeNumber(plan.speed_mbps ?? plan.banda_mbps);
    const durationDays = safeNumber(plan.duration_days ?? plan.duracao_dias ?? 30, 30);
    const description = plan.description || plan.descricao || '';
    const createdAt = plan.created_at || plan.criado_em || null;
    const updatedAt = plan.updated_at || plan.atualizado_em || createdAt;

    return {
        id: plan.id,
        name,
        price,
        speed_mbps: speedMbps,
        duration_days: durationDays,
        description,
        active: plan.active !== false,
        created_at: createdAt,
        updated_at: updatedAt,
        nome: name,
        valor: price,
        banda_mbps: speedMbps,
        duracao_dias: durationDays,
        descricao: description
    };
}

function formatUser(user = {}) {
    const name = user.name || user.nome || user.username || 'Cliente';
    const mac = user.mac || user.mac_address || user.value || user.username || null;
    const plan = user.plan || user.plan_name || user.plano || user.plano_nome || '';
    const status = normalizePaymentStatus(user.status || 'offline');
    const createdAt = user.created_at || user.criado_em || null;

    return {
        id: user.id,
        name,
        username: user.username || name,
        mac,
        mac_address: mac,
        phone: user.phone || user.telefone || null,
        cpf: user.cpf || null,
        email: user.email || null,
        address: user.address || user.endereco || null,
        plan,
        plan_name: plan,
        status,
        created_at: createdAt,
        updated_at: user.updated_at || createdAt,
        is_vip: Boolean(user.is_vip || user.vip),
        total_spent: safeNumber(user.total_spent || user.total_gasto),
        last_access: user.last_access || user.ultimo_acesso || null,
        nome: name,
        telefone: user.phone || user.telefone || null,
        endereco: user.address || user.endereco || null,
        plano: plan,
        criado_em: createdAt
    };
}

function formatHotspot(hotspot = {}) {
    const lastHeartbeat = hotspot.last_heartbeat || hotspot.updated_at || hotspot.ultima_atividade || null;
    const status = hotspot.status
        ? normalizePaymentStatus(hotspot.status)
        : lastHeartbeat && (new Date() - new Date(lastHeartbeat)) / 1000 <= 120
            ? 'online'
            : 'offline';
    const connectedUsers = safeNumber(hotspot.connected_users ?? hotspot.active_clients ?? hotspot.clientes_ativos);

    return {
        id: hotspot.id,
        unique_id: hotspot.unique_id || hotspot.pop_id || hotspot.id,
        name: hotspot.name || hotspot.nome || 'Hotspot',
        location: hotspot.location || hotspot.localizacao || hotspot.endereco || '',
        ip: hotspot.ip || hotspot.pop_ip || '',
        status,
        active_clients: connectedUsers,
        connected_users: connectedUsers,
        bandwidth_used: hotspot.bandwidth_used || hotspot.banda_usada || '0 Mbps',
        last_activity: lastHeartbeat ? new Date(lastHeartbeat).toLocaleString('pt-BR') : '-',
        updated_at: lastHeartbeat,
        created_at: hotspot.created_at || hotspot.criado_em || null,
        wan_interface: hotspot.wan_interface || null,
        lan_interface: hotspot.lan_interface || null,
        vlan_id: hotspot.vlan_id || null,
        tipo_instalacao: hotspot.tipo_instalacao || 'novo',
        hotspot_tipo: hotspot.hotspot_tipo || 'vlan',
        nome: hotspot.name || hotspot.nome || 'Hotspot',
        localizacao: hotspot.location || hotspot.localizacao || hotspot.endereco || '',
        clientes_ativos: connectedUsers,
        ultima_atividade: lastHeartbeat ? new Date(lastHeartbeat).toLocaleString('pt-BR') : '-'
    };
}

function formatAuditLog(log = {}) {
    const username = log.username || log.usuario || 'system';
    const type = log.type || log.tipo || 'event';
    const object = log.object || log.objeto || '';
    const action = log.action || log.acao || log.message || log.mensagem || '';
    const createdAt = log.created_at || log.criado_em || null;

    return {
        id: log.id,
        username,
        type,
        object,
        action,
        ip: log.ip || 'desconhecido',
        user_agent: log.user_agent || null,
        created_at: createdAt,
        usuario: username,
        tipo: type,
        objeto: object,
        acao: action
    };
}

function formatWebhook(webhook = {}) {
    const events = Array.isArray(webhook.events || webhook.eventos)
        ? (webhook.events || webhook.eventos)
        : safeString(webhook.events || webhook.eventos || webhook.evento || 'pagamento.confirmado')
            .split(',')
            .map(event => event.trim())
            .filter(Boolean);
    const active = webhook.ativo !== undefined
        ? safeBoolean(webhook.ativo, true)
        : webhook.active !== undefined
            ? safeBoolean(webhook.active, true)
            : safeString(webhook.status).toLowerCase() !== 'falha';
    const createdAt = webhook.created_at || webhook.criado_em || null;
    const lastRun = webhook.last_run || webhook.ultima_execucao || null;

    return {
        id: webhook.id,
        name: webhook.name || webhook.nome || 'Webhook',
        events,
        url: webhook.url || webhook.endpoint || '',
        endpoint: webhook.url || webhook.endpoint || '',
        method: webhook.method || webhook.metodo || 'POST',
        target: webhook.target || webhook.alvo || 'todos',
        active,
        status: active ? 'ativo' : 'falha',
        created_at: createdAt,
        last_run: lastRun,
        total_events: safeNumber(webhook.total_events ?? webhook.total_eventos),
        nome: webhook.name || webhook.nome || 'Webhook',
        evento: events[0] || 'pagamento.confirmado',
        eventos: events,
        metodo: webhook.method || webhook.metodo || 'POST',
        alvo: webhook.target || webhook.alvo || 'todos',
        ativo: active,
        ultima_execucao: lastRun,
        total_eventos: safeNumber(webhook.total_events ?? webhook.total_eventos)
    };
}

function formatVoucher(voucher = {}) {
    const createdAt = voucher.created_at || voucher.criado_em || null;
    const usedAt = voucher.used_at || voucher.usado_em || voucher.data_uso || null;
    const expiresAt = voucher.expires_at || voucher.validade_ate || null;
    const used = safeBoolean(voucher.used ?? voucher.usado, false);

    return {
        id: voucher.id,
        code: voucher.code || voucher.codigo || '',
        plan: voucher.plan || voucher.plano || '',
        amount: safeNumber(voucher.amount ?? voucher.valor),
        expires_at: expiresAt,
        used,
        used_by: voucher.used_by || voucher.usado_por || null,
        used_at: usedAt,
        created_at: createdAt,
        codigo: voucher.code || voucher.codigo || '',
        plano: voucher.plan || voucher.plano || '',
        valor: safeNumber(voucher.amount ?? voucher.valor),
        validade_ate: expiresAt,
        usado: used,
        usado_por: voucher.used_by || voucher.usado_por || null,
        data_uso: usedAt,
        usado_em: usedAt
    };
}

function formatPayment(payment = {}, lookups = {}) {
    const user = lookups.users?.get(payment.user_id || payment.usuario_id || payment.cliente_id);
    const plan = lookups.plans?.get(payment.plano_id || payment.plan_id);
    const hotspot = lookups.hotspots?.get(payment.pop_id || payment.hotspot_id);
    const amount = safeNumber(payment.amount ?? payment.valor);
    const createdAt = payment.created_at || payment.criado_em || payment.data || null;
    const status = normalizePaymentStatus(payment.status);
    const userName = payment.user_name || payment.usuario_nome || user?.nome || user?.username || user?.name || payment.cliente || payment.user_id || 'Cliente';
    const planName = payment.plan_name || payment.plano_nome || plan?.nome || plan?.name || payment.plano || payment.plano_id || '-';
    const hotspotName = payment.hotspot_name || payment.pop_nome || hotspot?.nome || hotspot?.name || payment.pop || payment.localidade || payment.hotspot || '-';
    const macAddress = payment.mac || payment.mac_address || user?.mac_address || user?.mac || null;

    return {
        id: payment.id,
        user_id: payment.user_id || payment.usuario_id || null,
        plan_id: payment.plan_id || payment.plano_id || null,
        pop_id: payment.pop_id || payment.hotspot_id || null,
        amount,
        payment_method: payment.payment_method || payment.metodo || 'pix',
        status,
        created_at: createdAt,
        updated_at: payment.updated_at || createdAt,
        pix_copy_paste: payment.pix_copy_paste || payment.pix_copia_cola || null,
        qr_code: payment.qr_code || payment.qr_code_url || null,
        mercado_pago_id: payment.mercado_pago_id || null,
        user_name: userName,
        plan_name: planName,
        hotspot_name: hotspotName,
        mac: macAddress,
        valor: amount,
        metodo: payment.payment_method || payment.metodo || 'PIX',
        usuario_id: payment.user_id || payment.usuario_id || null,
        cliente: userName,
        plano: planName,
        plano_id: payment.plan_id || payment.plano_id || null,
        criado_em: createdAt,
        pop: hotspotName,
        localidade: hotspotName,
        data: createdAt,
        status_original: payment.status || null
    };
}

function buildLookups(rows = []) {
    return new Map((rows || []).filter(Boolean).map(row => [row.id, row]));
}

function buildHotspotScript(hotspot) {
    const radiusCommand = RADIUS_SECRET
        ? `/radius add service=hotspot address=${RADIUS_SERVER_IP} secret=${RADIUS_SECRET} authentication-port=1812 accounting-port=1813 comment="MS-TELECOM"`
        : '';

    const heartbeatTarget = `${API_BASE_URL}/api/pops/${encodeURIComponent(hotspot.id)}/heartbeat`;
    const scriptLines = [
        `# Script para ${hotspot.name}`,
        `/system identity set name="${hotspot.name}"`,
        `/system scheduler add name="heartbeat-${hotspot.name}" interval=1m on-event="/tool fetch http-method=post url=\\"${heartbeatTarget}\\" http-data=\\"{\\\\\\"connected_users\\\\\\":0,\\\\\\"bandwidth_used\\\\\\":\\\\\\"0 Mbps\\\\\\"}\\" keep-result=no" start-time=startup`
    ];

    if (radiusCommand) {
        scriptLines.push(radiusCommand);
    }

    return scriptLines.join('\n');
}

async function fetchPaymentsWithLookups() {
    const { data: payments, error } = await supabase
        .from('pagamentos')
        .select('*')
        .order('created_at', { ascending: false });

    if (error) {
        throw error;
    }

    const userIds = [...new Set((payments || []).map(payment => payment.user_id || payment.usuario_id).filter(Boolean))];
    const planIds = [...new Set((payments || []).map(payment => payment.plano_id || payment.plan_id).filter(Boolean))];
    const popIds = [...new Set((payments || []).map(payment => payment.pop_id).filter(Boolean))];

    const [
        usersResult,
        plansResult,
        hotspotsResult
    ] = await Promise.all([
        userIds.length
            ? supabase.from('usuarios').select('id, username, nome, mac_address, pop_id').in('id', userIds)
            : Promise.resolve({ data: [], error: null }),
        planIds.length
            ? supabase.from('planos').select('*').in('id', planIds)
            : Promise.resolve({ data: [], error: null }),
        popIds.length
            ? supabase.from('pops').select('*').in('id', popIds)
            : Promise.resolve({ data: [], error: null })
    ]);

    if (usersResult.error) throw usersResult.error;
    if (plansResult.error) throw plansResult.error;
    if (hotspotsResult.error) throw hotspotsResult.error;

    return (payments || []).map(payment => formatPayment(payment, {
        users: buildLookups(usersResult.data),
        plans: buildLookups(plansResult.data),
        hotspots: buildLookups(hotspotsResult.data)
    }));
}

async function resolvePaymentForPix(body = {}) {
    const candidateId = body.payment_id || body.pagamento_id || body.id;

    if (!candidateId) {
        return null;
    }

    const { data: payment, error } = await supabase
        .from('pagamentos')
        .select('*')
        .eq('id', candidateId)
        .single();

    if (error) {
        return null;
    }

    return payment;
}

async function findUserByMacOrUsername(macAddress) {
    const normalizedMac = normalizeMacAddress(macAddress);

    if (!normalizedMac) {
        return null;
    }

    const macResult = await supabase
        .from('usuarios')
        .select('*')
        .eq('mac_address', normalizedMac)
        .maybeSingle();

    if (macResult.error) {
        throw macResult.error;
    }

    if (macResult.data) {
        return macResult.data;
    }

    const usernameResult = await supabase
        .from('usuarios')
        .select('*')
        .eq('username', normalizedMac)
        .maybeSingle();

    if (usernameResult.error) {
        throw usernameResult.error;
    }

    return usernameResult.data;
}

async function fetchPaymentDetails(paymentRecord) {
    const payment = typeof paymentRecord === 'object'
        ? paymentRecord
        : await resolvePaymentForPix({ payment_id: paymentRecord });

    if (!payment) {
        throw new Error('Pagamento não encontrado');
    }

    const userId = payment.user_id || payment.usuario_id;
    const planId = payment.plan_id || payment.plano_id;

    const [userResult, planResult] = await Promise.all([
        supabase.from('usuarios').select('*').eq('id', userId).maybeSingle(),
        supabase.from('planos').select('*').eq('id', planId).maybeSingle()
    ]);

    if (userResult.error) {
        throw userResult.error;
    }

    if (planResult.error) {
        throw planResult.error;
    }

    if (!userResult.data || !planResult.data) {
        throw new Error('Usuário ou plano não encontrado');
    }

    return {
        payment,
        user: userResult.data,
        plan: planResult.data
    };
}

async function resolvePopContext(options = {}) {
    const context = {
        user: options.user || null,
        pop: null,
        popId: options.popId || options.pop_id || options.payment?.pop_id || options.user?.pop_id || null,
        popIp: options.popIp || options.pop_ip || options.payment?.pop_ip || options.user?.pop_ip || null,
        apiUser: options.apiUser || options.api_user || null,
        apiPass: options.apiPass || options.api_pass || null
    };

    const userId = options.userId || options.user_id || options.payment?.user_id || options.payment?.usuario_id;
    if (!context.user && userId) {
        const userResult = await supabase
            .from('usuarios')
            .select('*')
            .eq('id', userId)
            .maybeSingle();

        if (userResult.error) {
            throw userResult.error;
        }

        context.user = userResult.data;
        context.popId = context.popId || context.user?.pop_id || null;
    }

    const normalizedMac = normalizeMacAddress(options.mac || options.mac_address || context.user?.mac_address || context.user?.username);
    if (!context.popId && !context.popIp && normalizedMac) {
        const sessionResult = await supabase
            .from('hotspot_sessions')
            .select('pop_id, created_at')
            .eq('mac_address', normalizedMac)
            .order('created_at', { ascending: false })
            .limit(1);

        if (sessionResult.error) {
            throw sessionResult.error;
        }

        const lastSession = sessionResult.data?.[0];
        context.popId = lastSession?.pop_id || context.popId;
    }

    if (context.popId) {
        const popResult = await supabase
            .from('pops')
            .select('*')
            .eq('id', context.popId)
            .maybeSingle();

        if (popResult.error) {
            throw popResult.error;
        }

        context.pop = popResult.data || null;
    }

    if (!context.pop && context.popIp) {
        const popByIpResult = await supabase
            .from('pops')
            .select('*')
            .eq('ip', context.popIp)
            .maybeSingle();

        if (popByIpResult.error) {
            throw popByIpResult.error;
        }

        context.pop = popByIpResult.data || null;
    }

    if (context.pop) {
        context.popId = context.pop.id || context.popId;
        context.popIp = context.pop.ip || context.pop.pop_ip || context.popIp;
        context.apiUser = context.apiUser || context.pop.api_user || null;
        context.apiPass = context.apiPass || context.pop.api_pass || null;
    }

    if ((!context.apiUser || !context.apiPass) && context.popIp) {
        const credsResult = await supabase
            .from('mikrotiks_credenciais')
            .select('api_user, api_pass')
            .eq('pop_ip', context.popIp)
            .maybeSingle();

        if (credsResult.error && credsResult.error.code !== 'PGRST116') {
            throw credsResult.error;
        }

        if (credsResult.data) {
            context.apiUser = context.apiUser || credsResult.data.api_user || null;
            context.apiPass = context.apiPass || credsResult.data.api_pass || null;
        }
    }

    context.popIp = context.popIp || MIKROTIK_HOST || null;
    context.apiUser = context.apiUser || MIKROTIK_USER || null;
    context.apiPass = context.apiPass || MIKROTIK_PASS || null;

    return context;
}

async function ensureActiveHotspotSession({ userId, popId, macAddress, expiresAt }) {
    const now = new Date().toISOString();
    const normalizedMac = normalizeMacAddress(macAddress);
    const activeSessionResult = await supabase
        .from('hotspot_sessions')
        .select('*')
        .eq('user_id', userId)
        .eq('status', 'active')
        .order('created_at', { ascending: false })
        .limit(1);

    if (activeSessionResult.error) {
        throw activeSessionResult.error;
    }

    const activeSession = activeSessionResult.data?.[0] || null;

    if (activeSession) {
        const sessionUpdate = {
            pop_id: popId || activeSession.pop_id || null,
            mac_address: normalizedMac,
            access_granted: true,
            expires_at: expiresAt,
            updated_at: now
        };

        const { data, error } = await supabase
            .from('hotspot_sessions')
            .update(sessionUpdate)
            .eq('id', activeSession.id)
            .select('*')
            .single();

        if (error) {
            throw error;
        }

        return data;
    }

    const sessionInsert = {
        user_id: userId,
        pop_id: popId || null,
        mac_address: normalizedMac,
        access_granted: true,
        status: 'active',
        expires_at: expiresAt,
        created_at: now,
        updated_at: now
    };

    const { data, error } = await supabase
        .from('hotspot_sessions')
        .insert(sessionInsert)
        .select('*')
        .single();

    if (error) {
        throw error;
    }

    return data;
}

async function createMercadoPagoPixForPayment(payment, overrides = {}) {
    if (!MP_ACCESS_TOKEN) {
        throw new Error('Mercado Pago não configurado no ambiente');
    }

    const { payment: currentPayment, user } = await fetchPaymentDetails(payment);
    const amount = safeNumber(overrides.amount ?? overrides.valor ?? currentPayment.valor);

    if (!amount) {
        throw new Error('Valor inválido para gerar PIX');
    }

    const externalReference = `payment-${currentPayment.id}`;
    const idempotencyKey = overrides.idempotencyKey || `pix-${currentPayment.id}`;
    const payerEmail = user?.email || `pagamento-${currentPayment.id}@mstelecom.local`;

    const requestPayload = {
        transaction_amount: amount,
        description: overrides.description || overrides.descricao || `Pagamento Hotspot #${currentPayment.id}`,
        payment_method_id: 'pix',
        external_reference: externalReference,
        payer: {
            email: payerEmail,
            first_name: user?.nome || user?.username || 'Cliente'
        }
    };

    if (MP_WEBHOOK_URL) {
        requestPayload.notification_url = MP_WEBHOOK_URL;
    }

    const mercadoPagoResponse = await axios.post(
        'https://api.mercadopago.com/v1/payments',
        requestPayload,
        {
            headers: {
                'Authorization': `Bearer ${MP_ACCESS_TOKEN}`,
                'Content-Type': 'application/json',
                'X-Idempotency-Key': idempotencyKey
            }
        }
    );

    const transactionData = mercadoPagoResponse.data?.point_of_interaction?.transaction_data || {};
    const qrCode = transactionData.qr_code_base64
        ? `data:image/png;base64,${transactionData.qr_code_base64}`
        : null;
    const pixCopyPaste = transactionData.qr_code || null;

    const { error: updateError } = await supabase
        .from('pagamentos')
        .update({
            mercado_pago_id: safeString(mercadoPagoResponse.data?.id || currentPayment.mercado_pago_id, currentPayment.mercado_pago_id)
        })
        .eq('id', currentPayment.id);

    if (updateError) {
        throw updateError;
    }

    return {
        payment_id: currentPayment.id,
        qr_code: qrCode,
        pix_copy_paste: pixCopyPaste,
        pix_copia_cola: pixCopyPaste,
        mercado_pago_id: safeString(mercadoPagoResponse.data?.id || currentPayment.mercado_pago_id, currentPayment.mercado_pago_id)
    };
}

async function confirmPaymentAccess(paymentRecord, options = {}) {
    const { payment, user, plan } = await fetchPaymentDetails(paymentRecord);
    const planDurationDays = safeNumber(plan.duration_days ?? plan.duracao_dias, 30);
    const normalizedMac = normalizeMacAddress(options.mac || options.mac_address || user.mac_address || user.username);

    if (!normalizedMac) {
        throw new Error('MAC do cliente não está disponível');
    }

    const popContext = await resolvePopContext({
        ...options,
        payment,
        user,
        userId: payment.user_id || payment.usuario_id,
        mac: normalizedMac
    });
    const expirationDate = new Date();
    expirationDate.setDate(expirationDate.getDate() + planDurationDays);

    const paymentUpdate = {
        status: 'confirmado'
    };

    if (options.mercadoPagoId) {
        paymentUpdate.mercado_pago_id = options.mercadoPagoId;
    }

    const { error: paymentUpdateError } = await supabase
        .from('pagamentos')
        .update(paymentUpdate)
        .eq('id', payment.id);

    if (paymentUpdateError) {
        throw paymentUpdateError;
    }

    const userUpdate = {
        plano_id: payment.plano_id || payment.plan_id,
        status: 'active',
        expires_at: expirationDate.toISOString()
    };

    if (popContext.popId) {
        userUpdate.pop_id = popContext.popId;
    }

    const { error: userUpdateError } = await supabase
        .from('usuarios')
        .update(userUpdate)
        .eq('id', payment.user_id || payment.usuario_id);

    if (userUpdateError) {
        throw userUpdateError;
    }

    const accessResult = await authorizeAccess(normalizedMac, {
        ...popContext,
        user,
        userId: payment.user_id || payment.usuario_id,
        mac: normalizedMac,
        durationMinutes: 15
    });

    if (!accessResult.success) {
        throw new Error(accessResult.errors?.join(' | ') || 'Falha ao liberar acesso');
    }

    const session = await ensureActiveHotspotSession({
        userId: payment.user_id || payment.usuario_id,
        popId: popContext.popId,
        macAddress: normalizedMac,
        expiresAt: expirationDate.toISOString()
    });

    return {
        success: true,
        payment_id: payment.id,
        user,
        plan,
        session,
        pop_id: popContext.popId,
        pop_ip: popContext.popIp,
        expires_at: expirationDate.toISOString(),
        access: accessResult
    };
}

async function revokeHotspotAccess(session = {}) {
    const normalizedMac = normalizeMacAddress(session.mac_address || session.mac);

    if (!normalizedMac || normalizedMac === 'PENDING') {
        return false;
    }

    const popContext = await resolvePopContext({
        popId: session.pop_id,
        mac: normalizedMac
    });

    if (!popContext.popIp || !popContext.apiUser || !popContext.apiPass) {
        return false;
    }

    const conn = new RouterOSAPI({
        host: popContext.popIp,
        user: popContext.apiUser,
        password: popContext.apiPass,
        port: 8728,
        timeout: 10
    });

    try {
        await conn.connect();
        const bindings = await conn.write('/ip/hotspot/ip-binding/print', [`?mac-address=${normalizedMac}`]);

        for (const binding of bindings || []) {
            await conn.write('/ip/hotspot/ip-binding/remove', [`=.id=${binding['.id']}`]);
        }

        return true;
    } finally {
        try {
            await conn.close();
        } catch (closeError) {
            console.warn('⚠️ Falha ao fechar conexão MikroTik:', closeError.message);
        }
    }
}

async function fetchUnifiedUsers() {
    const [usersResult, radiusResult] = await Promise.all([
        supabase.from('usuarios').select('*'),
        supabase.from('radreply').select('*')
    ]);

    if (usersResult.error) {
        throw usersResult.error;
    }

    if (radiusResult.error) {
        throw radiusResult.error;
    }

    const radiusByUsername = new Map((radiusResult.data || []).map(row => [row.username, row]));
    const radiusByMac = new Map((radiusResult.data || []).map(row => [row.value, row]));
    const mergedUsers = [];
    const mergedRadiusIds = new Set();

    for (const appUser of usersResult.data || []) {
        const radiusUser = radiusByUsername.get(appUser.username) || radiusByMac.get(appUser.mac_address);
        if (radiusUser?.id) {
            mergedRadiusIds.add(radiusUser.id);
        }

        mergedUsers.push(formatUser({
            ...radiusUser,
            ...appUser,
            id: appUser.id,
            name: appUser.nome || appUser.username || radiusUser?.username,
            username: appUser.username || radiusUser?.username,
            mac: appUser.mac_address || radiusUser?.value,
            phone: appUser.telefone || radiusUser?.phone,
            email: appUser.email || radiusUser?.email,
            address: appUser.endereco || radiusUser?.address,
            plan: appUser.plan_name || appUser.plan || radiusUser?.plan,
            status: appUser.status || radiusUser?.status,
            created_at: appUser.created_at || radiusUser?.created_at
        }));
    }

    for (const radiusUser of radiusResult.data || []) {
        if (mergedRadiusIds.has(radiusUser.id)) {
            continue;
        }

        mergedUsers.push(formatUser(radiusUser));
    }

    return mergedUsers;
}

async function findUnifiedUserById(userId) {
    const [appUserResult, radiusUserResult] = await Promise.all([
        supabase.from('usuarios').select('*').eq('id', userId).maybeSingle(),
        supabase.from('radreply').select('*').eq('id', userId).maybeSingle()
    ]);

    if (appUserResult.error) {
        throw appUserResult.error;
    }

    if (radiusUserResult.error) {
        throw radiusUserResult.error;
    }

    if (!appUserResult.data && !radiusUserResult.data) {
        return null;
    }

    const appUser = appUserResult.data;
    let radiusUser = radiusUserResult.data;

    if (!radiusUser && appUser?.username) {
        const linkedRadiusResult = await supabase
            .from('radreply')
            .select('*')
            .eq('username', appUser.username)
            .maybeSingle();

        if (linkedRadiusResult.error) {
            throw linkedRadiusResult.error;
        }

        radiusUser = linkedRadiusResult.data;
    }

    return formatUser({
        ...radiusUser,
        ...appUser,
        id: appUser?.id || radiusUser?.id,
        name: appUser?.nome || appUser?.username || radiusUser?.username,
        username: appUser?.username || radiusUser?.username,
        mac: appUser?.mac_address || radiusUser?.value,
        phone: appUser?.telefone || radiusUser?.phone,
        email: appUser?.email || radiusUser?.email,
        address: appUser?.endereco || radiusUser?.address,
        plan: appUser?.plan_name || appUser?.plan || radiusUser?.plan,
        status: appUser?.status || radiusUser?.status,
        created_at: appUser?.created_at || radiusUser?.created_at
    });
}

async function registerAuditLog(username, type, object, action, ip, userAgent) {
    try {
        // Usando a tabela logs_auditoria que já existe
        await supabase.from('logs_auditoria').insert({
            username,
            tipo: type,
            objeto: object || '',
            acao: action || '',
            ip: ip || 'desconhecido',
            user_agent: userAgent || 'desconhecido',
            created_at: new Date().toISOString()
        });
        console.log(`📝 LOG: ${type} - ${username}`);
    } catch (error) {
        console.error('❌ Erro ao registrar log:', error);
    }
}

// ============================================
// 📊 FUNÇÕES DE ESTATÍSTICAS (VERSÃO REAL)
// ============================================

/**
 * Registra acesso de usuário para estatísticas
 * Chamar dentro de /api/validate-access e /api/free-trial
 */
async function registerAccessLog(userId, username, macAddress, popId, sessionId, bytesIn = 0, bytesOut = 0) {
    try {
        // Usando a tabela acessos_hotspot que já existe
        await supabase.from('acessos_hotspot').insert({
            user_id: userId,
            username: username,
            mac_address: macAddress,
            pop_id: popId,
            access_time: new Date().toISOString(),
            session_id: sessionId,
            bytes_in: bytesIn,
            bytes_out: bytesOut
        });
        console.log(`📊 Log de acesso registrado: ${username}`);
    } catch (error) {
        console.error('❌ Erro ao registrar log de acesso:', error);
    }
}

/**
 * Busca usuários por hora a partir de acessos_hotspot REAL
 */
async function getRealUsersPerHour(startDate, endDate) {
    const { data, error } = await supabase
        .from('acessos_hotspot')
        .select('access_time')
        .gte('access_time', startDate.toISOString())
        .lte('access_time', endDate.toISOString());

    if (error) {
        console.error('❌ Erro ao buscar acessos_hotspot:', error);
        // Fallback: usar hotspot_sessions
        const { data: sessions, error: sessionError } = await supabase
            .from('hotspot_sessions')
            .select('created_at')
            .gte('created_at', startDate.toISOString())
            .lte('created_at', endDate.toISOString());
        
        if (sessionError) throw sessionError;
        
        const hourCount = {};
        for (let i = 0; i < 24; i++) hourCount[i] = 0;
        sessions.forEach(session => {
            const hour = new Date(session.created_at).getHours();
            hourCount[hour]++;
        });
        return Object.entries(hourCount).map(([hour, count]) => ({ hour: parseInt(hour), count }));
    }

    const hourCount = {};
    for (let i = 0; i < 24; i++) hourCount[i] = 0;
    data.forEach(log => {
        const hour = new Date(log.access_time).getHours();
        hourCount[hour]++;
    });

    return Object.entries(hourCount).map(([hour, count]) => ({ hour: parseInt(hour), count }));
}

/**
 * Busca tráfego total REAL a partir de bandwidth_history
 */
async function getRealTotalTraffic(startDate, endDate) {
    // Tentar pegar de bandwidth_history primeiro
    const { data, error } = await supabase
        .from('bandwidth_history')
        .select('bytes_in, bytes_out')
        .gte('timestamp', startDate.toISOString())
        .lte('timestamp', endDate.toISOString());

    if (error || !data || data.length === 0) {
        // Fallback: usar acessos_hotspot
        const { data: logs, error: logError } = await supabase
            .from('acessos_hotspot')
            .select('bytes_in, bytes_out')
            .gte('access_time', startDate.toISOString())
            .lte('access_time', endDate.toISOString());
        
        if (logError) throw logError;
        
        const totalBytesIn = logs.reduce((sum, l) => sum + (l.bytes_in || 0), 0);
        const totalBytesOut = logs.reduce((sum, l) => sum + (l.bytes_out || 0), 0);
        const totalBytes = totalBytesIn + totalBytesOut;
        
        return {
            bytes_in: totalBytesIn,
            bytes_out: totalBytesOut,
            total_bytes: totalBytes,
            megabytes: totalBytes / (1024 * 1024),
            gigabytes: totalBytes / (1024 * 1024 * 1024)
        };
    }

    const totalBytesIn = data.reduce((sum, b) => sum + (b.bytes_in || 0), 0);
    const totalBytesOut = data.reduce((sum, b) => sum + (b.bytes_out || 0), 0);
    const totalBytes = totalBytesIn + totalBytesOut;

    return {
        bytes_in: totalBytesIn,
        bytes_out: totalBytesOut,
        total_bytes: totalBytes,
        megabytes: totalBytes / (1024 * 1024),
        gigabytes: totalBytes / (1024 * 1024 * 1024)
    };
}

/**
 * Busca pico de banda REAL a partir de bandwidth_history
 */
async function getRealPeakBandwidth(startDate, endDate) {
    const { data, error } = await supabase
        .from('bandwidth_history')
        .select('timestamp, bandwidth_mbps, connected_users, bytes_in, bytes_out')
        .gte('timestamp', startDate.toISOString())
        .lte('timestamp', endDate.toISOString())
        .order('bandwidth_mbps', { ascending: false })
        .limit(1);

    if (error || !data || data.length === 0) {
        // Fallback: dados baseados em hotspot_sessions
        const { data: sessions, error: sessionError } = await supabase
            .from('hotspot_sessions')
            .select('created_at, bytes_in, bytes_out')
            .gte('created_at', startDate.toISOString())
            .lte('created_at', endDate.toISOString());
        
        if (sessionError) throw sessionError;
        
        let peakMbps = 0;
        sessions.forEach(session => {
            const totalBytes = (session.bytes_in || 0) + (session.bytes_out || 0);
            const mbps = (totalBytes * 8) / (1024 * 1024);
            if (mbps > peakMbps) peakMbps = mbps;
        });
        
        return {
            peak_bandwidth_mbps: peakMbps,
            peak_bandwidth_mbps_rounded: Math.round(peakMbps * 100) / 100,
            data_points: sessions.slice(-100).map(s => ({
                timestamp: s.created_at,
                bandwidth_mbps: ((s.bytes_in || 0) + (s.bytes_out || 0)) * 8 / (1024 * 1024)
            }))
        };
    }

    return {
        peak_bandwidth_mbps: data[0].bandwidth_mbps,
        peak_bandwidth_mbps_rounded: Math.round(data[0].bandwidth_mbps * 100) / 100,
        data_points: data.slice(-100).map(d => ({
            timestamp: d.timestamp,
            bandwidth_mbps: d.bandwidth_mbps,
            connected_users: d.connected_users
        }))
    };
}

/**
 * Busca comparação REAL entre períodos
 */
async function getRealComparisonStats(currentStart, currentEnd, previousStart, previousEnd) {
    const [currentTraffic, previousTraffic] = await Promise.all([
        getRealTotalTraffic(currentStart, currentEnd),
        getRealTotalTraffic(previousStart, previousEnd)
    ]);

    const [currentUsers, previousUsers] = await Promise.all([
        getRealUsersPerHour(currentStart, currentEnd),
        getRealUsersPerHour(previousStart, previousEnd)
    ]);

    const [currentPeak, previousPeak] = await Promise.all([
        getRealPeakBandwidth(currentStart, currentEnd),
        getRealPeakBandwidth(previousStart, previousEnd)
    ]);

    const totalCurrentUsers = currentUsers.reduce((sum, h) => sum + h.count, 0);
    const totalPreviousUsers = previousUsers.reduce((sum, h) => sum + h.count, 0);

    const trafficVariation = previousTraffic.total_bytes > 0
        ? ((currentTraffic.total_bytes - previousTraffic.total_bytes) / previousTraffic.total_bytes) * 100
        : 0;

    const usersVariation = totalPreviousUsers > 0
        ? ((totalCurrentUsers - totalPreviousUsers) / totalPreviousUsers) * 100
        : 0;

    const bandwidthVariation = previousPeak.peak_bandwidth_mbps > 0
        ? ((currentPeak.peak_bandwidth_mbps - previousPeak.peak_bandwidth_mbps) / previousPeak.peak_bandwidth_mbps) * 100
        : 0;

    return {
        current_period: {
            traffic: currentTraffic,
            total_users: totalCurrentUsers,
            peak_bandwidth: currentPeak.peak_bandwidth_mbps
        },
        previous_period: {
            traffic: previousTraffic,
            total_users: totalPreviousUsers,
            peak_bandwidth: previousPeak.peak_bandwidth_mbps
        },
        variation: {
            traffic_percent: trafficVariation,
            users_percent: usersVariation,
            bandwidth_percent: bandwidthVariation
        }
    };
}

// ============================================
// 🔧 FUNÇÃO: LIBERAR ACESSO (IP BINDING + RADIUS)
// ============================================

async function authorizeAccess(mac, popIp = null, apiUser = null, apiPass = null) {
    let viaAPI = false;
    let viaRADIUS = false;
    let errors = [];

    // TENTATIVA 1: API Direta (IP Binding)
    try {
        let user = apiUser;
        let pass = apiPass;

        if (!user || !pass) {
            // Usando a tabela mikrotiks_credenciais
            const { data: creds } = await supabase
                .from('mikrotiks_credenciais')
                .select('api_user, api_pass')
                .eq('pop_ip', popIp)
                .single();
            if (creds) {
                user = creds.api_user;
                pass = creds.api_pass;
            }
        }

        if (!user || !pass) {
            throw new Error('Credenciais não disponíveis');
        }

        const conn = new RouterOSAPI({
            host: popIp,
            user: user,
            password: pass,
            port: 8728,
            timeout: 10
        });

        await conn.connect();

        const existingBindings = await conn.write('/ip/hotspot/ip-binding/print', [
            `?mac-address=${mac}`
        ]);

        if (existingBindings.length === 0) {
            await conn.write('/ip/hotspot/ip-binding/add', [
                `=mac-address=${mac}`,
                '=type=bypassed',
                '=comment=AUTORIZADO-MS-TELECOM'
            ]);
            console.log(`✅ IP Binding criado para ${mac}`);
        }

        await conn.close();
        viaAPI = true;

    } catch (error) {
        errors.push(`API: ${error.message}`);
        console.log(`⚠️ API falhou: ${error.message}`);
    }

    // TENTATIVA 2: RADIUS (Supabase)
    try {
        const expirationDate = new Date();
        expirationDate.setMinutes(expirationDate.getMinutes() + 15);

        // Usando a tabela radreply
        const { data: existingUser } = await supabase
            .from('radreply')
            .select('id')
            .eq('username', mac)
            .single();

        if (existingUser) {
            await supabase
                .from('radreply')
                .update({
                    status: 'active',
                    expires_at: expirationDate.toISOString(),
                    updated_at: new Date().toISOString()
                })
                .eq('username', mac);
        } else {
            await supabase
                .from('radreply')
                .insert({
                    username: mac,
                    attribute: 'Reply-Message',
                    op: ':=',
                    value: mac,
                    plan: 'test_gratis',
                    status: 'active',
                    expires_at: expirationDate.toISOString(),
                    created_at: new Date().toISOString()
                });
        }

        viaRADIUS = true;
        console.log(`✅ Usuário ${mac} liberado via RADIUS`);
    } catch (error) {
        errors.push(`RADIUS: ${error.message}`);
        console.log(`⚠️ RADIUS falhou: ${error.message}`);
    }

    return { success: viaAPI || viaRADIUS, viaAPI, viaRADIUS, errors };
}

// ============================================
// 🔐 MIDDLEWARE DE AUTENTICAÇÃO
// ============================================

async function authorizeAccess(mac, popIpOrOptions = null, apiUser = null, apiPass = null) {
    const options = typeof popIpOrOptions === 'object' && popIpOrOptions !== null
        ? popIpOrOptions
        : { popIp: popIpOrOptions, apiUser, apiPass };
    const normalizedMac = normalizeMacAddress(mac);
    const popContext = await resolvePopContext({
        ...options,
        mac: normalizedMac
    });
    const durationMinutes = safeNumber(options.durationMinutes ?? options.tempo ?? 15, 15);
    const expirationDate = new Date();
    expirationDate.setMinutes(expirationDate.getMinutes() + durationMinutes);
    const errors = [];
    let viaAPI = false;
    let viaRADIUS = false;

    if (popContext.popIp && popContext.apiUser && popContext.apiPass) {
        const conn = new RouterOSAPI({
            host: popContext.popIp,
            user: popContext.apiUser,
            password: popContext.apiPass,
            port: 8728,
            timeout: 10
        });

        try {
            await conn.connect();

            const existingBindings = await conn.write('/ip/hotspot/ip-binding/print', [
                `?mac-address=${normalizedMac}`
            ]);

            if ((existingBindings || []).length === 0) {
                await conn.write('/ip/hotspot/ip-binding/add', [
                    `=mac-address=${normalizedMac}`,
                    '=type=bypassed',
                    '=comment=AUTORIZADO-MS-TELECOM'
                ]);
            }

            viaAPI = true;
            console.log(`✅ Acesso liberado via MikroTik API para ${normalizedMac}`);
        } catch (error) {
            errors.push(`API: ${error.message}`);
            console.log(`⚠️ API falhou: ${error.message}`);
        } finally {
            try {
                await conn.close();
            } catch (closeError) {
                console.warn('⚠️ Falha ao fechar conexão MikroTik:', closeError.message);
            }
        }
    } else {
        errors.push('API: POP ou credenciais do MikroTik não configurados');
    }

    try {
        const { data: existingRows, error: radiusReadError } = await supabase
            .from('radreply')
            .select('id, username')
            .eq('username', normalizedMac);

        if (radiusReadError) {
            throw radiusReadError;
        }

        if ((existingRows || []).length > 0) {
            const { error: radiusUpdateError } = await supabase
                .from('radreply')
                .update({
                    status: 'active',
                    expires_at: expirationDate.toISOString(),
                    updated_at: new Date().toISOString()
                })
                .eq('username', normalizedMac);

            if (radiusUpdateError) {
                throw radiusUpdateError;
            }

            viaRADIUS = true;
            console.log(`✅ Acesso atualizado via RADIUS para ${normalizedMac}`);
        } else {
            errors.push('RADIUS: usuário não encontrado para atualização sem senha em texto puro');
        }
    } catch (error) {
        errors.push(`RADIUS: ${error.message}`);
        console.log(`⚠️ RADIUS falhou: ${error.message}`);
    }

    return {
        success: viaAPI || viaRADIUS,
        viaAPI,
        viaRADIUS,
        errors,
        pop_id: popContext.popId,
        pop_ip: popContext.popIp
    };
}

const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Token não fornecido' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Token inválido' });
    }
};

// ============================================
// 🔥 AUTENTICAÇÃO - LOGIN ADMIN
// ============================================

// Endpoint em português (original)
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'];

        if (!username || !password) {
            return res.status(400).json({ error: 'Usuário e senha obrigatórios' });
        }

        // Usando a tabela admins
        const { data: admin, error } = await supabase
            .from('admins')
            .select('*')
            .eq('username', username)
            .single();

        const passwordIsValid = await verifyAdminPassword(admin, password);

        if (error || !admin || !passwordIsValid) {
            await registerAuditLog(username || 'desconhecido', 'error', 'authentication', 'Login falhou', clientIp, userAgent);
            return res.status(401).json({ error: 'Usuário ou senha incorretos' });
        }

        await registerAuditLog(admin.username, 'login', 'authentication', 'Login realizado', clientIp, userAgent);
        console.log(`✅ Login: ${username}`);

        return res.json(await buildAdminAuthResponse(admin));
    } catch (error) {
        console.error('❌ Erro no login:', error);
        return res.status(500).json({ error: 'Erro ao fazer login' });
    }
});

// Endpoint em inglês (novo padrão)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'];

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const { data: admin, error } = await supabase
            .from('admins')
            .select('*')
            .eq('username', username)
            .single();

        const passwordIsValid = await verifyAdminPassword(admin, password);

        if (error || !admin || !passwordIsValid) {
            await registerAuditLog(username || 'unknown', 'error', 'authentication', 'Login failed', clientIp, userAgent);
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        await registerAuditLog(admin.username, 'login', 'authentication', 'Login successful', clientIp, userAgent);
        console.log(`✅ Login: ${username}`);

        return res.json(await buildAdminAuthResponse(admin));
    } catch (error) {
        console.error('❌ Error during login:', error);
        return res.status(500).json({ error: 'Error during login' });
    }
});

// ============================================
// 📊 DASHBOARD
// ============================================

app.get('/api/dashboard', verifyToken, async (req, res) => {
    try {
        const { data: users } = await supabase.from('usuarios').select('*');
        const { data: payments } = await supabase.from('pagamentos').select('*').eq('status', 'confirmado');
        const { data: pops } = await supabase.from('pops').select('*');
        const { data: sessions } = await supabase.from('hotspot_sessions').select('*').eq('status', 'active');

        const totalRevenue = payments?.reduce((sum, p) => sum + (p.valor || 0), 0) || 0;

        return res.json({
            totalUsers: users?.length || 0,
            confirmedPayments: payments?.length || 0,
            totalRevenue,
            onlinePops: pops?.filter(p => (new Date() - new Date(p.last_heartbeat)) / (1000 * 60) < 15).length || 0,
            totalPops: pops?.length || 0,
            activeSessions: sessions?.length || 0
        });
    } catch (error) {
        console.error('❌ Erro no dashboard:', error);
        res.status(500).json({ error: 'Erro ao buscar dashboard' });
    }
});

// Endpoint dashboard em inglês
app.get('/api/dashboard/stats', verifyToken, async (req, res) => {
    try {
        const { data: users } = await supabase.from('usuarios').select('*');
        const { data: payments } = await supabase.from('pagamentos').select('*').eq('status', 'confirmado');
        const { data: pops } = await supabase.from('pops').select('*');
        const { data: sessions } = await supabase.from('hotspot_sessions').select('*').eq('status', 'active');

        const totalRevenue = payments?.reduce((sum, p) => sum + (p.valor || 0), 0) || 0;

        return res.json({
            total_users: users?.length || 0,
            confirmed_payments: payments?.length || 0,
            total_revenue: totalRevenue,
            online_pops: pops?.filter(p => (new Date() - new Date(p.last_heartbeat)) / (1000 * 60) < 15).length || 0,
            total_pops: pops?.length || 0,
            active_sessions: sessions?.length || 0
        });
    } catch (error) {
        console.error('❌ Error fetching dashboard:', error);
        res.status(500).json({ error: 'Error fetching dashboard stats' });
    }
});

// ============================================
// 📊 ESTATÍSTICAS REAIS (COM DADOS DO BANCO)
// ============================================

// Usuários por hora (português) - VERSÃO REAL
app.get('/api/stats/usuarios-por-hora', verifyToken, async (req, res) => {
    try {
        const { days = 7 } = req.query;
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - parseInt(days));

        const usersPerHour = await getRealUsersPerHour(startDate, endDate);
        res.json({ success: true, data: usersPerHour, period: { start: startDate, end: endDate } });
    } catch (error) {
        console.error('❌ Erro ao buscar usuários por hora:', error);
        res.status(500).json({ error: 'Erro ao buscar estatísticas', details: error.message });
    }
});

// Usuários por hora (inglês) - VERSÃO REAL
app.get('/api/stats/users-per-hour', verifyToken, async (req, res) => {
    try {
        const { days = 7 } = req.query;
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - parseInt(days));

        const usersPerHour = await getRealUsersPerHour(startDate, endDate);
        res.json({ success: true, data: usersPerHour, period: { start: startDate, end: endDate } });
    } catch (error) {
        console.error('❌ Error fetching users per hour:', error);
        res.status(500).json({ error: 'Error fetching statistics', details: error.message });
    }
});

// Tráfego total (português) - VERSÃO REAL
app.get('/api/stats/trafego-total', verifyToken, async (req, res) => {
    try {
        const { days = 7 } = req.query;
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - parseInt(days));

        const traffic = await getRealTotalTraffic(startDate, endDate);
        res.json({ success: true, data: traffic, period: { start: startDate, end: endDate } });
    } catch (error) {
        console.error('❌ Erro ao buscar tráfego total:', error);
        res.status(500).json({ error: 'Erro ao buscar estatísticas', details: error.message });
    }
});

// Tráfego total (inglês) - VERSÃO REAL
app.get('/api/stats/total-traffic', verifyToken, async (req, res) => {
    try {
        const { days = 7 } = req.query;
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - parseInt(days));

        const traffic = await getRealTotalTraffic(startDate, endDate);
        res.json({ success: true, data: traffic, period: { start: startDate, end: endDate } });
    } catch (error) {
        console.error('❌ Error fetching total traffic:', error);
        res.status(500).json({ error: 'Error fetching statistics', details: error.message });
    }
});

// Pico de banda (português) - VERSÃO REAL
app.get('/api/stats/pico-banda', verifyToken, async (req, res) => {
    try {
        const { days = 7 } = req.query;
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - parseInt(days));

        const peak = await getRealPeakBandwidth(startDate, endDate);
        res.json({ success: true, data: peak, period: { start: startDate, end: endDate } });
    } catch (error) {
        console.error('❌ Erro ao buscar pico de banda:', error);
        res.status(500).json({ error: 'Erro ao buscar estatísticas', details: error.message });
    }
});

// Pico de banda (inglês) - VERSÃO REAL
app.get('/api/stats/peak-bandwidth', verifyToken, async (req, res) => {
    try {
        const { days = 7 } = req.query;
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - parseInt(days));

        const peak = await getRealPeakBandwidth(startDate, endDate);
        res.json({ success: true, data: peak, period: { start: startDate, end: endDate } });
    } catch (error) {
        console.error('❌ Error fetching peak bandwidth:', error);
        res.status(500).json({ error: 'Error fetching statistics', details: error.message });
    }
});

// Comparação entre períodos (português) - VERSÃO REAL
app.get('/api/stats/comparacao', verifyToken, async (req, res) => {
    try {
        const { days = 7 } = req.query;
        const currentEnd = new Date();
        const currentStart = new Date();
        currentStart.setDate(currentStart.getDate() - parseInt(days));

        const previousEnd = new Date(currentStart);
        const previousStart = new Date(currentStart);
        previousStart.setDate(previousStart.getDate() - parseInt(days));

        const comparison = await getRealComparisonStats(currentStart, currentEnd, previousStart, previousEnd);
        res.json({ success: true, data: comparison });
    } catch (error) {
        console.error('❌ Erro ao buscar comparação:', error);
        res.status(500).json({ error: 'Erro ao buscar estatísticas', details: error.message });
    }
});

// Comparação entre períodos (inglês) - VERSÃO REAL
app.get('/api/stats/comparison', verifyToken, async (req, res) => {
    try {
        const { days = 7 } = req.query;
        const currentEnd = new Date();
        const currentStart = new Date();
        currentStart.setDate(currentStart.getDate() - parseInt(days));

        const previousEnd = new Date(currentStart);
        const previousStart = new Date(currentStart);
        previousStart.setDate(previousStart.getDate() - parseInt(days));

        const comparison = await getRealComparisonStats(currentStart, currentEnd, previousStart, previousEnd);
        res.json({ success: true, data: comparison });
    } catch (error) {
        console.error('❌ Error fetching comparison:', error);
        res.status(500).json({ error: 'Error fetching statistics', details: error.message });
    }
});

// ============================================
// 💳 PAGAMENTO - CRIAR
// ============================================

const createPaymentHandler = async (req, res) => {
    try {
        const userId = req.body.user_id || req.body.usuario_id;
        const planId = req.body.plan_id || req.body.plano_id;
        const amount = safeNumber(req.body.amount ?? req.body.valor);
        const popId = req.body.pop_id || req.body.hotspot_id || null;

        if (!userId || !planId || !amount) {
            return res.status(400).json({ error: 'Dados obrigatórios ausentes para criar o pagamento' });
        }

        const paymentInsert = {
            user_id: userId,
            plano_id: planId,
            valor: amount,
            status: 'pendente',
            created_at: new Date().toISOString()
        };

        if (popId) {
            paymentInsert.pop_id = popId;
        }

        const { data, error } = await supabase
            .from('pagamentos')
            .insert(paymentInsert)
            .select('*')
            .single();

        if (error) {
            throw error;
        }

        if (!MP_ACCESS_TOKEN) {
            return res.status(503).json({
                success: false,
                payment_id: data.id,
                amount,
                error: 'Mercado Pago não configurado no ambiente'
            });
        }

        const pixData = await createMercadoPagoPixForPayment(data, {
            amount,
            description: req.body.description || req.body.descricao
        });

        return res.status(201).json({
            success: true,
            amount,
            ...pixData
        });
    } catch (error) {
        console.error('❌ Erro ao criar pagamento:', error.response?.data || error.message || error);
        return res.status(500).json({ error: 'Erro ao criar pagamento' });
    }
};

const confirmPaymentHandler = async (req, res) => {
    try {
        const paymentId = req.body.payment_id || req.body.pagamento_id;

        if (!paymentId) {
            return res.status(400).json({ error: 'payment_id é obrigatório' });
        }

        const payment = await resolvePaymentForPix({ payment_id: paymentId });
        if (!payment) {
            return res.status(404).json({ error: 'Pagamento não encontrado' });
        }

        const confirmation = await confirmPaymentAccess(payment, req.body);

        return res.json({
            status: 'confirmed',
            payment_id: confirmation.payment_id,
            user: confirmation.user.username || confirmation.user.nome,
            plan: confirmation.plan.nome || confirmation.plan.name,
            session_id: confirmation.session.id,
            pop_id: confirmation.pop_id,
            pop_ip: confirmation.pop_ip,
            expires_at: confirmation.expires_at,
            message: 'Pagamento confirmado! Acesso liberado.'
        });
    } catch (error) {
        const message = error.message || 'Erro ao confirmar pagamento';
        const statusCode = message.includes('não encontrado') ? 404 : 500;
        console.error('❌ Erro ao confirmar pagamento:', error);
        return res.status(statusCode).json({ error: message });
    }
};

const verifyPaymentHandler = async (req, res) => {
    try {
        const mac = normalizeMacAddress(req.query.mac || req.query.mac_address);

        if (!mac) {
            return res.status(400).json({ pago: false, error: 'MAC não informado' });
        }

        const user = await findUserByMacOrUsername(mac);
        if (!user) {
            return res.json({ pago: false, message: 'Cliente não encontrado para este MAC' });
        }

        const paymentsResult = await supabase
            .from('pagamentos')
            .select('*')
            .or(`user_id.eq.${user.id},usuario_id.eq.${user.id}`)
            .order('created_at', { ascending: false })
            .limit(20);

        if (paymentsResult.error) {
            throw paymentsResult.error;
        }

        let payment = (paymentsResult.data || []).find(row => normalizePaymentStatus(row.status) === 'confirmed') || null;

        if (!payment) {
            const remoteCandidate = (paymentsResult.data || []).find(row => row.mercado_pago_id);

            if (remoteCandidate && MP_ACCESS_TOKEN) {
                const mercadoPagoStatus = await axios.get(
                    `https://api.mercadopago.com/v1/payments/${remoteCandidate.mercado_pago_id}`,
                    {
                        headers: {
                            'Authorization': `Bearer ${MP_ACCESS_TOKEN}`
                        }
                    }
                );

                if (normalizePaymentStatus(mercadoPagoStatus.data?.status) === 'confirmed') {
                    payment = remoteCandidate;
                }
            }
        }

        if (!payment) {
            return res.json({ pago: false, message: 'Pagamento ainda não confirmado' });
        }

        const confirmation = await confirmPaymentAccess(payment, { mac });
        return res.json({
            pago: true,
            payment_id: confirmation.payment_id,
            session_id: confirmation.session.id,
            expires_at: confirmation.expires_at,
            pop_id: confirmation.pop_id,
            pop_ip: confirmation.pop_ip
        });
    } catch (error) {
        console.error('❌ Erro ao verificar pagamento:', error);
        return res.status(500).json({ pago: false, error: 'Erro ao verificar pagamento' });
    }
};

const mercadoPagoWebhookHandler = async (req, res) => {
    try {
        const notificationPaymentId = req.body?.data?.id || req.query['data.id'] || req.body?.id;

        if (!notificationPaymentId) {
            return res.status(400).json({ received: false, error: 'ID do pagamento não informado pelo webhook' });
        }

        if (!MP_ACCESS_TOKEN) {
            return res.status(503).json({ received: false, error: 'Mercado Pago não configurado no ambiente' });
        }

        const mercadoPagoPayment = await axios.get(
            `https://api.mercadopago.com/v1/payments/${notificationPaymentId}`,
            {
                headers: {
                    'Authorization': `Bearer ${MP_ACCESS_TOKEN}`
                }
            }
        );
        const remotePayment = mercadoPagoPayment.data || {};
        const externalReference = safeString(remotePayment.external_reference);
        const localPaymentId = externalReference.startsWith('payment-')
            ? externalReference.replace('payment-', '')
            : null;

        if (!localPaymentId) {
            return res.status(404).json({ received: false, error: 'Pagamento local não identificado' });
        }

        const localPayment = await resolvePaymentForPix({ payment_id: localPaymentId });
        if (!localPayment) {
            return res.status(404).json({ received: false, error: 'Pagamento local não encontrado' });
        }

        const remoteStatus = normalizePaymentStatus(remotePayment.status);
        if (remoteStatus !== 'confirmed') {
            const fallbackStatus = remoteStatus === 'canceled' ? 'cancelado' : 'pendente';
            await supabase
                .from('pagamentos')
                .update({
                    status: fallbackStatus,
                    mercado_pago_id: safeString(remotePayment.id, localPayment.mercado_pago_id)
                })
                .eq('id', localPayment.id);

            return res.status(200).json({ received: true, status: fallbackStatus });
        }

        const confirmation = await confirmPaymentAccess(localPayment, {
            mercadoPagoId: safeString(remotePayment.id, localPayment.mercado_pago_id)
        });

        return res.status(200).json({
            received: true,
            payment_id: confirmation.payment_id,
            session_id: confirmation.session.id,
            status: 'confirmed'
        });
    } catch (error) {
        console.error('❌ Erro no webhook do Mercado Pago:', error.response?.data || error.message || error);
        return res.status(500).json({ received: false, error: 'Erro ao processar webhook do Mercado Pago' });
    }
};

app.post('/api/create-payment', createPaymentHandler);
app.post('/api/payments/create', createPaymentHandler);
app.post('/api/confirm-payment', confirmPaymentHandler);
app.post('/api/payments/confirm', confirmPaymentHandler);
app.get('/api/verificar-pagamento', verifyPaymentHandler);
app.get('/api/verify-payment', verifyPaymentHandler);
app.post('/api/mercado-pago/webhook', mercadoPagoWebhookHandler);
app.post('/api/webhook/pagamento', mercadoPagoWebhookHandler);

app.post('/api/create-payment', async (req, res) => {
    try {
        const { user_id, plan_id, amount } = req.body;

        if (!user_id || !plan_id || !amount) {
            return res.status(400).json({ error: 'Dados incompletos' });
        }

        // Usando a tabela pagamentos
        const { data, error } = await supabase
            .from('pagamentos')
            .insert({
                user_id,
                plano_id: plan_id,
                valor: amount,
                status: 'pendente',
                mercado_pago_id: null,
                created_at: new Date()
            })
            .select();

        if (error) throw error;

        console.log(`✅ Pagamento criado: ${data[0].id}`);
        return res.json({
            payment_id: data[0].id,
            amount,
            qr_code: null,
            pix_copy_paste: `00020126580014br.gov.bcb.pix0136${data[0].id}`
        });
    } catch (error) {
        console.error('❌ Erro ao criar pagamento:', error);
        return res.status(500).json({ error: 'Erro ao criar pagamento' });
    }
});

// Endpoint em inglês
app.post('/api/payments/create', async (req, res) => {
    try {
        const { user_id, plan_id, amount } = req.body;

        if (!user_id || !plan_id || !amount) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const { data, error } = await supabase
            .from('pagamentos')
            .insert({
                user_id,
                plano_id: plan_id,
                valor: amount,
                status: 'pendente',
                mercado_pago_id: null,
                created_at: new Date()
            })
            .select();

        if (error) throw error;

        console.log(`✅ Payment created: ${data[0].id}`);
        return res.json({
            payment_id: data[0].id,
            amount,
            qr_code: null,
            pix_copy_paste: `00020126580014br.gov.bcb.pix0136${data[0].id}`
        });
    } catch (error) {
        console.error('❌ Error creating payment:', error);
        return res.status(500).json({ error: 'Error creating payment' });
    }
});

// ============================================
// 💳 PAGAMENTO - CONFIRMAR (COM LIBERAÇÃO)
// ============================================

app.post('/api/confirm-payment', async (req, res) => {
    try {
        const { payment_id } = req.body;

        if (!payment_id) {
            return res.status(400).json({ error: 'payment_id obrigatório' });
        }

        // Usando a tabela pagamentos
        const { data: payment, error: paymentError } = await supabase
            .from('pagamentos')
            .select('*')
            .eq('id', payment_id)
            .single();

        if (paymentError || !payment) {
            return res.status(404).json({ error: 'Pagamento não encontrado' });
        }

        if (payment.status === 'confirmado') {
            return res.json({ status: 'confirmed', message: 'Pagamento já confirmado' });
        }

        await supabase.from('pagamentos').update({ status: 'confirmado' }).eq('id', payment_id);

        // Usando a tabela usuarios
        const { data: user } = await supabase.from('usuarios').select('*').eq('id', payment.user_id).single();
        const { data: plan } = await supabase.from('planos').select('*').eq('id', payment.plano_id).single();

        if (!user || !plan) {
            return res.status(404).json({ error: 'Usuário ou plano não encontrado' });
        }

        await supabase.from('usuarios').update({
            plano_id: payment.plano_id,
            status: 'active',
            expires_at: new Date(Date.now() + (plan.duracao_dias || 30) * 24 * 60 * 60 * 1000).toISOString()
        }).eq('id', payment.user_id);

        const expirationDate = new Date();
        expirationDate.setDate(expirationDate.getDate() + (plan.duracao_dias || 30));
        const mac = user.mac_address || user.username;

        await authorizeAccess(mac);

        const { data: session } = await supabase
            .from('hotspot_sessions')
            .insert({
                user_id: payment.user_id,
                pop_id: payment.pop_id || user.pop_id || null,
                mac_address: mac,
                access_granted: true,
                status: 'active',
                expires_at: expirationDate.toISOString(),
                created_at: new Date().toISOString()
            })
            .select();

        console.log(`✅ Pagamento confirmado: ${payment_id}`);
        return res.json({
            status: 'confirmed',
            payment_id,
            user: user.username,
            plan: plan.nome,
            session_id: session[0].id,
            expires_at: expirationDate.toISOString(),
            message: 'Pagamento confirmado! Acesso liberado.'
        });

    } catch (error) {
        console.error('❌ Erro ao confirmar pagamento:', error);
        res.status(500).json({ error: 'Erro ao confirmar pagamento', details: error.message });
    }
});

// Endpoint em inglês
app.post('/api/payments/confirm', async (req, res) => {
    try {
        const { payment_id } = req.body;

        if (!payment_id) {
            return res.status(400).json({ error: 'payment_id is required' });
        }

        const { data: payment, error: paymentError } = await supabase
            .from('pagamentos')
            .select('*')
            .eq('id', payment_id)
            .single();

        if (paymentError || !payment) {
            return res.status(404).json({ error: 'Payment not found' });
        }

        if (payment.status === 'confirmado') {
            return res.json({ status: 'confirmed', message: 'Payment already confirmed' });
        }

        await supabase.from('pagamentos').update({ status: 'confirmado' }).eq('id', payment_id);

        const { data: user } = await supabase.from('usuarios').select('*').eq('id', payment.user_id).single();
        const { data: plan } = await supabase.from('planos').select('*').eq('id', payment.plano_id).single();

        if (!user || !plan) {
            return res.status(404).json({ error: 'User or plan not found' });
        }

        await supabase.from('usuarios').update({
            plano_id: payment.plano_id,
            status: 'active',
            expires_at: new Date(Date.now() + (plan.duracao_dias || 30) * 24 * 60 * 60 * 1000).toISOString()
        }).eq('id', payment.user_id);

        const expirationDate = new Date();
        expirationDate.setDate(expirationDate.getDate() + (plan.duracao_dias || 30));
        const mac = user.mac_address || user.username;

        await authorizeAccess(mac);

        const { data: session } = await supabase
            .from('hotspot_sessions')
            .insert({
                user_id: payment.user_id,
                pop_id: payment.pop_id || user.pop_id || null,
                mac_address: mac,
                access_granted: true,
                status: 'active',
                expires_at: expirationDate.toISOString(),
                created_at: new Date().toISOString()
            })
            .select();

        console.log(`✅ Payment confirmed: ${payment_id}`);
        return res.json({
            status: 'confirmed',
            payment_id,
            user: user.username,
            plan: plan.nome,
            session_id: session[0].id,
            expires_at: expirationDate.toISOString(),
            message: 'Payment confirmed! Access granted.'
        });

    } catch (error) {
        console.error('❌ Error confirming payment:', error);
        res.status(500).json({ error: 'Error confirming payment', details: error.message });
    }
});

// ============================================
// 🎁 TESTE GRÁTIS
// ============================================

const freeTrialHandler = async (req, res) => {
    const mac = normalizeMacAddress(req.body.mac);
    const durationMinutes = Math.max(5, safeNumber(req.body.tempo ?? req.body.duration_minutes, 15));
    const popId = req.body.pop_id || req.body.popId || null;
    const popIp = req.body.pop_ip || req.body.popIp || null;
    const apiUser = req.body.api_user || req.body.apiUser || null;
    const apiPass = req.body.api_pass || req.body.apiPass || null;

    if (!mac) {
        return res.status(400).json({ error: 'MAC não informado' });
    }

    try {
        const { data: existingTrial, error: existingTrialError } = await supabase
            .from('testes_gratis')
            .select('*')
            .eq('mac', mac)
            .maybeSingle();

        if (existingTrialError) {
            throw existingTrialError;
        }

        const now = new Date();
        const oneHour = 60 * 60 * 1000;

        if (existingTrial?.last_trial) {
            const lastTrial = new Date(existingTrial.last_trial);
            if (now - lastTrial < oneHour) {
                const minutesLeft = Math.ceil((oneHour - (now - lastTrial)) / 60000);
                return res.status(429).json({ error: `Aguarde ${minutesLeft} minutos` });
            }
        }

        const { error: upsertError } = await supabase
            .from('testes_gratis')
            .upsert({
                mac,
                last_trial: now.toISOString(),
                attempts: safeNumber(existingTrial?.attempts, 0) + 1
            });

        if (upsertError) {
            throw upsertError;
        }

        const result = await authorizeAccess(mac, {
            popId,
            popIp,
            apiUser,
            apiPass,
            durationMinutes
        });

        if (!result.success) {
            return res.status(500).json({ error: 'Falha ao liberar acesso', details: result.errors });
        }

        return res.json({
            success: true,
            message: `Teste grátis liberado por ${durationMinutes} minutos`,
            method: result.viaAPI ? 'api' : 'radius',
            pop_id: result.pop_id,
            pop_ip: result.pop_ip
        });
    } catch (error) {
        console.error('❌ Erro no teste grátis:', error);
        return res.status(500).json({ error: error.message });
    }
};

app.post('/api/liberar-teste', freeTrialHandler);
app.post('/api/free-trial', freeTrialHandler);
app.post('/api/trial/free', freeTrialHandler);

app.post('/api/free-trial', async (req, res) => {
    const { mac, pop_ip, api_user, api_pass } = req.body;
    if (!mac) return res.status(400).json({ error: 'MAC não informado' });

    try {
        // Usando a tabela testes_gratis
        const { data: existingTrial } = await supabase
            .from('testes_gratis')
            .select('*')
            .eq('mac', mac)
            .single();

        const now = new Date();
        const oneHour = 60 * 60 * 1000;

        if (existingTrial) {
            const lastTrial = new Date(existingTrial.last_trial);
            if (now - lastTrial < oneHour) {
                const minutesLeft = Math.ceil((oneHour - (now - lastTrial)) / 60000);
                return res.status(429).json({ error: `Aguarde ${minutesLeft} minutos` });
            }
        }

        await supabase.from('testes_gratis').upsert({
            mac,
            last_trial: now.toISOString(),
            attempts: (existingTrial?.attempts || 0) + 1
        });

        const result = await authorizeAccess(mac, pop_ip, api_user, api_pass);

        if (result.success) {
            res.json({ success: true, message: 'Teste grátis liberado por 15 minutos', method: result.viaAPI ? 'api' : 'radius' });
        } else {
            res.status(500).json({ error: 'Falha ao liberar acesso', details: result.errors });
        }
    } catch (error) {
        console.error('❌ Erro no teste grátis:', error);
        res.status(500).json({ error: error.message });
    }
});

// Endpoint em inglês
app.post('/api/trial/free', async (req, res) => {
    const { mac, pop_ip, api_user, api_pass } = req.body;
    if (!mac) return res.status(400).json({ error: 'MAC address is required' });

    try {
        const { data: existingTrial } = await supabase
            .from('testes_gratis')
            .select('*')
            .eq('mac', mac)
            .single();

        const now = new Date();
        const oneHour = 60 * 60 * 1000;

        if (existingTrial) {
            const lastTrial = new Date(existingTrial.last_trial);
            if (now - lastTrial < oneHour) {
                const minutesLeft = Math.ceil((oneHour - (now - lastTrial)) / 60000);
                return res.status(429).json({ error: `Please wait ${minutesLeft} minutes` });
            }
        }

        await supabase.from('testes_gratis').upsert({
            mac,
            last_trial: now.toISOString(),
            attempts: (existingTrial?.attempts || 0) + 1
        });

        const result = await authorizeAccess(mac, pop_ip, api_user, api_pass);

        if (result.success) {
            res.json({ success: true, message: 'Free trial granted for 15 minutes', method: result.viaAPI ? 'api' : 'radius' });
        } else {
            res.status(500).json({ error: 'Failed to grant access', details: result.errors });
        }
    } catch (error) {
        console.error('❌ Error in free trial:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// 🔓 VALIDAR ACESSO
// ============================================

app.post('/api/validate-access', async (req, res) => {
    try {
        const { username, mac_address, pop_id } = req.body;

        if (!username || !mac_address || !pop_id) {
            return res.json({ access_granted: false, reason: 'Parâmetros faltando' });
        }

        // Usando a tabela usuarios
        const { data: user } = await supabase.from('usuarios').select('*').eq('username', username).single();
        if (!user) return res.json({ access_granted: false, reason: 'Usuário não encontrado' });

        const { data: session } = await supabase
            .from('hotspot_sessions')
            .select('*')
            .eq('user_id', user.id)
            .eq('status', 'active')
            .gte('expires_at', new Date().toISOString())
            .single();

        if (!session) return res.json({ access_granted: false, reason: 'Sem sessão ativa' });

        await supabase.from('hotspot_sessions').update({ mac_address, pop_id, updated_at: new Date().toISOString() }).eq('id', session.id);

        // REGISTRAR LOG DE ACESSO PARA ESTATÍSTICAS
        await registerAccessLog(
            user.id,
            user.username,
            mac_address,
            pop_id,
            session.id,
            req.body.bytes_in || 0,
            req.body.bytes_out || 0
        );

        console.log(`✅ Acesso validado: ${username}`);
        return res.json({ access_granted: true, user: user.username, session_id: session.id, expires_at: session.expires_at });
    } catch (error) {
        console.error('❌ Erro ao validar acesso:', error);
        return res.json({ access_granted: false, reason: 'Erro ao validar' });
    }
});

// Endpoint em inglês
app.post('/api/access/validate', async (req, res) => {
    try {
        const { username, mac_address, pop_id } = req.body;

        if (!username || !mac_address || !pop_id) {
            return res.json({ access_granted: false, reason: 'Missing parameters' });
        }

        const { data: user } = await supabase.from('usuarios').select('*').eq('username', username).single();
        if (!user) return res.json({ access_granted: false, reason: 'User not found' });

        const { data: session } = await supabase
            .from('hotspot_sessions')
            .select('*')
            .eq('user_id', user.id)
            .eq('status', 'active')
            .gte('expires_at', new Date().toISOString())
            .single();

        if (!session) return res.json({ access_granted: false, reason: 'No active session' });

        await supabase.from('hotspot_sessions').update({ mac_address, pop_id, updated_at: new Date().toISOString() }).eq('id', session.id);

        // REGISTRAR LOG DE ACESSO PARA ESTATÍSTICAS
        await registerAccessLog(
            user.id,
            user.username,
            mac_address,
            pop_id,
            session.id,
            req.body.bytes_in || 0,
            req.body.bytes_out || 0
        );

        console.log(`✅ Access validated: ${username}`);
        return res.json({ access_granted: true, user: user.username, session_id: session.id, expires_at: session.expires_at });
    } catch (error) {
        console.error('❌ Error validating access:', error);
        return res.json({ access_granted: false, reason: 'Validation error' });
    }
});

// ============================================
// 🖥️ POPS (HEARTBEAT)
// ============================================

app.post('/api/pops/:pop_id/ping', async (req, res) => {
    try {
        const { pop_id } = req.params;
        const { connected_users, bandwidth_used } = req.body;
        const now = new Date().toISOString();

        const { data: pop } = await supabase.from('pops').select('*').eq('id', pop_id).single();
        if (!pop) return res.status(404).json({ error: 'POP não encontrado' });

        await supabase.from('pops').update({
            status: 'online',
            last_heartbeat: now,
            connected_users: connected_users || 0,
            bandwidth_used: bandwidth_used || '0 Mbps'
        }).eq('id', pop_id);

        return res.json({ status: 'ok', pop_id, pop_name: pop.name, timestamp: now });
    } catch (error) {
        console.error('❌ Erro no ping:', error);
        res.status(500).json({ error: 'Erro ao processar ping' });
    }
});

app.get('/api/pops', async (req, res) => {
    try {
        const { data: pops } = await supabase.from('pops').select('*');
        const popsWithStatus = pops?.map(p => ({
            ...p,
            status: (new Date() - new Date(p.last_heartbeat)) / 1000 > 60 ? 'offline' : 'online'
        })) || [];
        return res.json(popsWithStatus);
    } catch (error) {
        console.error('❌ Erro ao listar POPs:', error);
        res.status(500).json({ error: 'Erro ao listar POPs' });
    }
});

// Endpoints em inglês
app.post('/api/pops/:pop_id/heartbeat', async (req, res) => {
    try {
        const { pop_id } = req.params;
        const { connected_users, bandwidth_used } = req.body;
        const now = new Date().toISOString();

        const { data: pop } = await supabase.from('pops').select('*').eq('id', pop_id).single();
        if (!pop) return res.status(404).json({ error: 'POP not found' });

        await supabase.from('pops').update({
            status: 'online',
            last_heartbeat: now,
            connected_users: connected_users || 0,
            bandwidth_used: bandwidth_used || '0 Mbps'
        }).eq('id', pop_id);

        return res.json({ status: 'ok', pop_id, pop_name: pop.name, timestamp: now });
    } catch (error) {
        console.error('❌ Error in heartbeat:', error);
        res.status(500).json({ error: 'Error processing heartbeat' });
    }
});

app.get('/api/pops/list', async (req, res) => {
    try {
        const { data: pops } = await supabase.from('pops').select('*');
        const popsWithStatus = pops?.map(p => ({
            ...p,
            status: (new Date() - new Date(p.last_heartbeat)) / 1000 > 60 ? 'offline' : 'online'
        })) || [];
        return res.json(popsWithStatus);
    } catch (error) {
        console.error('❌ Error listing POPs:', error);
        res.status(500).json({ error: 'Error listing POPs' });
    }
});

// ============================================
// 📊 BANDWIDTH HISTORY - RECEBER DADOS DOS POPS
// ============================================

/**
 * Endpoint para POPs enviarem dados de banda periodicamente
 * Chamar a cada 1-5 minutos de cada MikroTik
 */
app.post('/api/pops/:pop_id/bandwidth', async (req, res) => {
    try {
        const { pop_id } = req.params;
        const { bandwidth_mbps, connected_users, bytes_in, bytes_out } = req.body;

        if (!bandwidth_mbps && !connected_users) {
            return res.status(400).json({ error: 'bandwidth_mbps or connected_users required' });
        }

        // Inserir histórico de banda
        await supabase.from('bandwidth_history').insert({
            pop_id: pop_id,
            timestamp: new Date().toISOString(),
            bandwidth_mbps: bandwidth_mbps || 0,
            connected_users: connected_users || 0,
            bytes_in: bytes_in || 0,
            bytes_out: bytes_out || 0
        });

        // Atualizar status do POP
        await supabase.from('pops').update({
            connected_users: connected_users,
            bandwidth_used: `${bandwidth_mbps || 0} Mbps`,
            last_heartbeat: new Date().toISOString()
        }).eq('id', pop_id);

        console.log(`📊 Bandwidth data received from POP ${pop_id}: ${bandwidth_mbps} Mbps, ${connected_users} users`);
        res.json({ status: 'ok', message: 'Bandwidth data recorded' });
    } catch (error) {
        console.error('❌ Error recording bandwidth:', error);
        res.status(500).json({ error: 'Error recording bandwidth data' });
    }
});

// Endpoint em português para compatibilidade
app.post('/api/pops/:pop_id/banda', async (req, res) => {
    try {
        const { pop_id } = req.params;
        const { bandwidth_mbps, connected_users, bytes_in, bytes_out } = req.body;

        if (!bandwidth_mbps && !connected_users) {
            return res.status(400).json({ error: 'bandwidth_mbps ou connected_users obrigatório' });
        }

        await supabase.from('bandwidth_history').insert({
            pop_id: pop_id,
            timestamp: new Date().toISOString(),
            bandwidth_mbps: bandwidth_mbps || 0,
            connected_users: connected_users || 0,
            bytes_in: bytes_in || 0,
            bytes_out: bytes_out || 0
        });

        await supabase.from('pops').update({
            connected_users: connected_users,
            bandwidth_used: `${bandwidth_mbps || 0} Mbps`,
            last_heartbeat: new Date().toISOString()
        }).eq('id', pop_id);

        console.log(`📊 Dados de banda recebidos do POP ${pop_id}: ${bandwidth_mbps} Mbps, ${connected_users} usuários`);
        res.json({ status: 'ok', message: 'Dados de banda registrados' });
    } catch (error) {
        console.error('❌ Erro ao registrar banda:', error);
        res.status(500).json({ error: 'Erro ao registrar dados de banda' });
    }
});

// ============================================
// 📋 PLANOS
// ============================================

app.get('/api/plans', verifyToken, async (req, res) => {
    try {
        const { data: plans } = await supabase.from('planos').select('*').eq('active', true);
        return res.json((plans || []).map(formatPlan));
    } catch (error) {
        console.error('❌ Erro ao listar planos:', error);
        res.status(500).json({ error: 'Erro ao listar planos' });
    }
});

app.post('/api/plans', verifyToken, async (req, res) => {
    try {
        const { name, price, bandwidth_mbps, duration_days, description } = req.body;

        if (!name || !price || !bandwidth_mbps || !duration_days) {
            return res.status(400).json({ error: 'Campos obrigatórios' });
        }

        const { data: plan, error } = await supabase
            .from('planos')
            .insert({
                nome: name,
                valor: parseFloat(price),
                banda_mbps: parseInt(bandwidth_mbps),
                duracao_dias: parseInt(duration_days),
                descricao: description || '',
                active: true,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
            .select();

        if (error) throw error;
        console.log(`✅ Plano criado: ${name}`);
        return res.json({ status: 'success', plan: formatPlan(plan[0]) });
    } catch (error) {
        console.error('❌ Erro ao criar plano:', error);
        res.status(500).json({ error: 'Erro ao criar plano' });
    }
});

// Endpoints em inglês
app.get('/api/plans/list', verifyToken, async (req, res) => {
    try {
        const { data: plans } = await supabase.from('planos').select('*').eq('active', true);
        return res.json((plans || []).map(formatPlan));
    } catch (error) {
        console.error('❌ Error listing plans:', error);
        res.status(500).json({ error: 'Error listing plans' });
    }
});

app.post('/api/plans/create', verifyToken, async (req, res) => {
    try {
        const { name, price, bandwidth_mbps, duration_days, description } = req.body;

        if (!name || !price || !bandwidth_mbps || !duration_days) {
            return res.status(400).json({ error: 'Required fields missing' });
        }

        const { data: plan, error } = await supabase
            .from('planos')
            .insert({
                nome: name,
                valor: parseFloat(price),
                banda_mbps: parseInt(bandwidth_mbps),
                duracao_dias: parseInt(duration_days),
                descricao: description || '',
                active: true,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
            .select();

        if (error) throw error;
        console.log(`✅ Plan created: ${name}`);
        return res.json({ status: 'success', plan: formatPlan(plan[0]) });
    } catch (error) {
        console.error('❌ Error creating plan:', error);
        res.status(500).json({ error: 'Error creating plan' });
    }
});

// ============================================
// 👥 USUÁRIOS
// ============================================

app.get('/api/users', verifyToken, async (req, res) => {
    try {
        res.json(await fetchUnifiedUsers());
    } catch (error) {
        console.error('❌ Erro ao listar usuários:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/users', verifyToken, async (req, res) => {
    const { name, mac, phone, cpf, email, address, plan } = req.body;
    if (!name || !mac) return res.status(400).json({ error: "Nome e MAC obrigatórios" });

    try {
        const { data, error } = await supabase.from('radreply').insert({
            username: name, 
            value: mac, 
            phone: phone || null, 
            cpf: cpf || null,
            email: email || null, 
            address: address || null, 
            plan: plan || 'test',
            status: 'offline', 
            created_at: new Date().toISOString()
        }).select().single();

        if (error) throw error;

        res.json({ success: true, message: "Cliente cadastrado!", user: formatUser(data) });
    } catch (error) {
        console.error('Erro ao cadastrar:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/users/:id', verifyToken, async (req, res) => {
    try {
        await supabase.from('radreply').delete().eq('id', parseInt(req.params.id));
        res.json({ success: true });
    } catch (error) {
        console.error('Erro ao deletar:', error);
        res.status(500).json({ error: error.message });
    }
});

// Endpoints em inglês
app.get('/api/users/list', verifyToken, async (req, res) => {
    try {
        res.json(await fetchUnifiedUsers());
    } catch (error) {
        console.error('❌ Error listing users:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/users/create', verifyToken, async (req, res) => {
    const { name, mac, phone, cpf, email, address, plan } = req.body;
    if (!name || !mac) return res.status(400).json({ error: "Name and MAC are required" });

    try {
        const { data, error } = await supabase.from('radreply').insert({
            username: name, 
            value: mac, 
            phone: phone || null, 
            cpf: cpf || null,
            email: email || null, 
            address: address || null, 
            plan: plan || 'test',
            status: 'offline', 
            created_at: new Date().toISOString()
        }).select().single();

        if (error) throw error;

        res.json({ success: true, message: "Client registered!", user: formatUser(data) });
    } catch (error) {
        console.error('Error registering:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/users/delete/:id', verifyToken, async (req, res) => {
    try {
        await supabase.from('radreply').delete().eq('id', parseInt(req.params.id));
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// 🔐 PERFIL, LOGOUT E CONTRATOS ADMIN
// ============================================

const updateProfileHandler = async (req, res) => {
    try {
        const { username, email } = req.body;
        const currentPassword = req.body.current_password || req.body.senha_atual || null;
        const newPassword = req.body.new_password || req.body.nova_senha || null;
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'];

        const { data: admin, error } = await supabase
            .from('admins')
            .select('*')
            .eq('id', req.user.id)
            .single();

        if (error || !admin) {
            return res.status(404).json({ success: false, error: 'Administrador não encontrado' });
        }

        const updatePayload = {};

        if (username && username !== admin.username) {
            updatePayload.username = username;
        }

        if (email !== undefined) {
            updatePayload.email = email || null;
        }

        if (newPassword) {
            if (!currentPassword) {
                return res.status(400).json({ success: false, error: 'Senha atual obrigatória para trocar a senha' });
            }

            const passwordIsValid = await verifyAdminPassword(admin, currentPassword);
            if (!passwordIsValid) {
                return res.status(401).json({ success: false, error: 'Senha atual inválida' });
            }

            updatePayload.password = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        }

        if (Object.keys(updatePayload).length === 0) {
            const authPayload = await buildAdminAuthResponse(admin);
            return res.json({ success: true, admin: authPayload.admin });
        }

        const { data: updatedAdmin, error: updateError } = await supabase
            .from('admins')
            .update(updatePayload)
            .eq('id', req.user.id)
            .select('*')
            .single();

        if (updateError) {
            throw updateError;
        }

        await registerAuditLog(
            updatedAdmin.username,
            'profile_update',
            'admin_profile',
            'Perfil administrativo atualizado',
            clientIp,
            userAgent
        );

        return res.json({
            success: true,
            admin: {
                id: updatedAdmin.id,
                username: updatedAdmin.username,
                email: updatedAdmin.email || null,
                role: updatedAdmin.role || 'admin'
            }
        });
    } catch (error) {
        console.error('❌ Erro ao atualizar perfil:', error);
        return res.status(500).json({ success: false, error: 'Erro ao atualizar perfil' });
    }
};

app.put('/api/update-profile', verifyToken, updateProfileHandler);
app.put('/api/atualizar-perfil', verifyToken, updateProfileHandler);

app.post('/api/logout', verifyToken, async (req, res) => {
    try {
        const username = req.body.username || req.user.username || 'desconhecido';
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'];

        await registerAuditLog(username, 'logout', 'authentication', 'Logout realizado', clientIp, userAgent);
        return res.json({ success: true });
    } catch (error) {
        console.error('❌ Erro ao registrar logout:', error);
        return res.status(500).json({ success: false, error: 'Erro ao registrar logout' });
    }
});

// ============================================
// 💳 PAGAMENTOS - LISTAGEM E PIX
// ============================================

const listPaymentsHandler = async (req, res) => {
    try {
        return res.json(await fetchPaymentsWithLookups());
    } catch (error) {
        console.error('❌ Erro ao listar pagamentos:', error);
        return res.status(500).json({ error: 'Erro ao listar pagamentos' });
    }
};

app.get('/api/payments', verifyToken, listPaymentsHandler);
app.get('/api/pagamentos', verifyToken, listPaymentsHandler);

const generatePixHandler = async (req, res) => {
    try {
        const payment = await resolvePaymentForPix(req.body);

        if (!payment) {
            return res.status(404).json({ error: 'Pagamento não encontrado' });
        }

        if (!MP_ACCESS_TOKEN) {
            return res.status(503).json({ error: 'Mercado Pago não configurado no ambiente' });
        }

        const amount = safeNumber(req.body.amount ?? req.body.valor ?? payment.valor);
        if (!amount) {
            return res.status(400).json({ error: 'Valor inválido para gerar PIX' });
        }

        const description = req.body.description || req.body.descricao || `Pagamento Hotspot #${payment.id}`;
        const externalReference = `payment-${payment.id}`;
        const idempotencyKey = `pix-${payment.id}`;

        const { data: linkedUser } = await supabase
            .from('usuarios')
            .select('email, username, nome')
            .eq('id', payment.user_id)
            .maybeSingle();

        const payerEmail = linkedUser?.email || `pagamento-${payment.id}@mstelecom.local`;

        const mercadoPagoResponse = await axios.post(
            'https://api.mercadopago.com/v1/payments',
            {
                transaction_amount: amount,
                description,
                payment_method_id: 'pix',
                external_reference: externalReference,
                payer: {
                    email: payerEmail,
                    first_name: linkedUser?.nome || linkedUser?.username || 'Cliente'
                }
            },
            {
                headers: {
                    'Authorization': `Bearer ${MP_ACCESS_TOKEN}`,
                    'Content-Type': 'application/json',
                    'X-Idempotency-Key': idempotencyKey
                }
            }
        );

        const transactionData = mercadoPagoResponse.data?.point_of_interaction?.transaction_data || {};
        const qrCode = transactionData.qr_code_base64
            ? `data:image/png;base64,${transactionData.qr_code_base64}`
            : null;
        const pixCopyPaste = transactionData.qr_code || null;

        const paymentUpdate = { mercado_pago_id: safeString(mercadoPagoResponse.data?.id || payment.mercado_pago_id, payment.mercado_pago_id) };
        const { error: updateError } = await supabase
            .from('pagamentos')
            .update(paymentUpdate)
            .eq('id', payment.id);

        if (updateError) {
            console.warn('⚠️ Não foi possível persistir todos os dados do PIX:', updateError.message);
        }

        return res.json({
            success: true,
            payment_id: payment.id,
            qr_code: qrCode,
            pix_copy_paste: pixCopyPaste,
            pix_copia_cola: pixCopyPaste,
            mercado_pago_id: paymentUpdate.mercado_pago_id
        });
    } catch (error) {
        console.error('❌ Erro ao gerar PIX:', error.response?.data || error.message || error);
        return res.status(500).json({ error: 'Erro ao gerar PIX real no Mercado Pago' });
    }
};

app.post('/api/payments/generate-pix', verifyToken, generatePixHandler);
app.post('/api/pagamentos/gerar-pix', verifyToken, generatePixHandler);

// ============================================
// 📝 LOGS DE AUDITORIA
// ============================================

app.get('/api/webhooks', verifyToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('webhooks')
            .select('*')
            .order('created_at', { ascending: false });

        if (error) {
            throw error;
        }

        return res.json((data || []).map(formatWebhook));
    } catch (error) {
        console.error('❌ Erro ao carregar webhooks:', error);
        return res.status(500).json({ error: 'Erro ao carregar webhooks' });
    }
});

app.post('/api/webhooks', verifyToken, async (req, res) => {
    try {
        const name = req.body.name || req.body.nome;
        const events = Array.isArray(req.body.events || req.body.eventos)
            ? (req.body.events || req.body.eventos)
            : safeString(req.body.event || req.body.evento)
                .split(',')
                .map(event => event.trim())
                .filter(Boolean);
        const url = req.body.url || req.body.endpoint;
        const method = req.body.method || req.body.metodo || 'POST';
        const target = req.body.target || req.body.alvo || 'todos';
        const active = req.body.active !== undefined
            ? safeBoolean(req.body.active, true)
            : safeBoolean(req.body.ativo, true);

        if (!name || !events.length || !url) {
            return res.status(400).json({ error: 'Nome, evento e URL são obrigatórios' });
        }

        const { data, error } = await supabase
            .from('webhooks')
            .insert({
                nome: name,
                evento: events[0],
                url,
                metodo: method,
                alvo: target,
                ativo: active,
                created_at: new Date().toISOString()
            })
            .select('*')
            .single();

        if (error) {
            throw error;
        }

        return res.json({ success: true, data: formatWebhook(data) });
    } catch (error) {
        console.error('❌ Erro ao criar webhook:', error);
        return res.status(500).json({ error: 'Erro ao criar webhook' });
    }
});

app.post('/api/webhooks/:id/testar', verifyToken, async (req, res) => {
    try {
        const { data: webhook, error } = await supabase
            .from('webhooks')
            .select('*')
            .eq('id', req.params.id)
            .maybeSingle();

        if (error) {
            throw error;
        }

        if (!webhook) {
            return res.status(404).json({ error: 'Webhook não encontrado' });
        }

        const payload = {
            test: true,
            event: webhook.evento || 'pagamento.confirmado',
            timestamp: new Date().toISOString()
        };

        const response = await axios({
            url: webhook.url,
            method: webhook.metodo || 'POST',
            data: payload,
            timeout: 5000,
            validateStatus: () => true
        });

        const { error: updateError } = await supabase
            .from('webhooks')
            .update({
                ultima_execucao: new Date().toISOString(),
                total_eventos: safeNumber(webhook.total_eventos, 0) + 1,
                ativo: response.status >= 200 && response.status < 300
            })
            .eq('id', req.params.id);

        if (updateError) {
            throw updateError;
        }

        if (response.status < 200 || response.status >= 300) {
            return res.status(502).json({ error: `Destino respondeu com status ${response.status}` });
        }

        return res.json({ success: true });
    } catch (error) {
        console.error('❌ Erro ao testar webhook:', error);
        return res.status(500).json({ error: 'Erro ao testar webhook' });
    }
});

app.delete('/api/webhooks/:id', verifyToken, async (req, res) => {
    try {
        const { error } = await supabase
            .from('webhooks')
            .delete()
            .eq('id', req.params.id);

        if (error) {
            throw error;
        }

        return res.json({ success: true });
    } catch (error) {
        console.error('❌ Erro ao deletar webhook:', error);
        return res.status(500).json({ error: 'Erro ao deletar webhook' });
    }
});

app.get('/api/vouchers', verifyToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('vouchers')
            .select('*')
            .order('created_at', { ascending: false });

        if (error) {
            throw error;
        }

        return res.json((data || []).map(formatVoucher));
    } catch (error) {
        console.error('❌ Erro ao carregar vouchers:', error);
        return res.status(500).json({ error: 'Erro ao carregar vouchers' });
    }
});

app.post('/api/vouchers', verifyToken, async (req, res) => {
    try {
        const plan = req.body.plan || req.body.plano;
        const amount = safeNumber(req.body.amount ?? req.body.valor);
        const expiresAt = req.body.expires_at || req.body.validade_ate || null;
        const code = req.body.code || req.body.codigo || generateSecureCode('MS', 8);

        if (!plan) {
            return res.status(400).json({ error: 'Plano é obrigatório' });
        }

        const { data, error } = await supabase
            .from('vouchers')
            .insert({
                codigo: code,
                plano: plan,
                valor: amount,
                validade_ate: expiresAt,
                usado: false,
                created_at: new Date().toISOString()
            })
            .select('*')
            .single();

        if (error) {
            throw error;
        }

        return res.json({ success: true, ...formatVoucher(data) });
    } catch (error) {
        console.error('❌ Erro ao criar voucher:', error);
        return res.status(500).json({ error: 'Erro ao criar voucher' });
    }
});

app.put('/api/vouchers/:id', verifyToken, async (req, res) => {
    try {
        const updatePayload = {
            plano: req.body.plan || req.body.plano,
            valor: req.body.amount !== undefined || req.body.valor !== undefined
                ? safeNumber(req.body.amount ?? req.body.valor)
                : undefined,
            validade_ate: req.body.expires_at || req.body.validade_ate || null,
            usado: req.body.used !== undefined
                ? safeBoolean(req.body.used, false)
                : req.body.usado !== undefined
                    ? safeBoolean(req.body.usado, false)
                    : undefined
        };

        Object.keys(updatePayload).forEach(key => updatePayload[key] === undefined && delete updatePayload[key]);

        const { data, error } = await supabase
            .from('vouchers')
            .update(updatePayload)
            .eq('id', req.params.id)
            .select('*')
            .single();

        if (error) {
            throw error;
        }

        return res.json({ success: true, ...formatVoucher(data) });
    } catch (error) {
        console.error('❌ Erro ao atualizar voucher:', error);
        return res.status(500).json({ error: 'Erro ao atualizar voucher' });
    }
});

app.post('/api/vouchers/validar', async (req, res) => {
    try {
        const code = req.body.code || req.body.codigo;
        const mac = normalizeMacAddress(req.body.mac || req.body.mac_address);

        if (!code || !mac) {
            return res.status(400).json({ error: 'Código e MAC são obrigatórios' });
        }

        const { data: voucher, error } = await supabase
            .from('vouchers')
            .select('*')
            .eq('codigo', code)
            .maybeSingle();

        if (error) {
            throw error;
        }

        if (!voucher || safeBoolean(voucher.usado, false)) {
            return res.status(404).json({ error: 'Voucher inválido ou já utilizado' });
        }

        if (voucher.validade_ate && new Date(voucher.validade_ate) < new Date()) {
            return res.status(400).json({ error: 'Voucher expirado' });
        }

        const { error: useError } = await supabase
            .from('vouchers')
            .update({
                usado: true,
                usado_por: mac,
                usado_em: new Date().toISOString()
            })
            .eq('id', voucher.id);

        if (useError) {
            throw useError;
        }

        const accessResult = await authorizeAccess(mac, {
            popId: req.body.pop_id || null,
            popIp: req.body.pop_ip || null,
            apiUser: req.body.api_user || null,
            apiPass: req.body.api_pass || null,
            durationMinutes: 60
        });

        return res.json({
            success: true,
            plan: voucher.plano,
            amount: safeNumber(voucher.valor),
            method: accessResult.viaAPI ? 'api' : 'radius',
            pop_id: accessResult.pop_id,
            pop_ip: accessResult.pop_ip
        });
    } catch (error) {
        console.error('❌ Erro ao validar voucher:', error);
        return res.status(500).json({ error: 'Erro ao validar voucher' });
    }
});

app.delete('/api/vouchers/:id', verifyToken, async (req, res) => {
    try {
        const { error } = await supabase
            .from('vouchers')
            .delete()
            .eq('id', req.params.id);

        if (error) {
            throw error;
        }

        return res.json({ success: true });
    } catch (error) {
        console.error('❌ Erro ao deletar voucher:', error);
        return res.status(500).json({ error: 'Erro ao deletar voucher' });
    }
});

const listAuditLogsHandler = async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit || '200', 10), 1000);
        const usernameFilter = req.query.username || req.query.usuario;
        const typeFilter = req.query.type || req.query.tipo;
        const startDate = req.query.start_date || req.query.data_inicio;
        const endDate = req.query.end_date || req.query.data_fim;

        let query = supabase
            .from('logs_auditoria')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(limit);

        if (usernameFilter) {
            query = query.ilike('username', `%${usernameFilter}%`);
        }

        if (typeFilter) {
            query = query.eq('tipo', typeFilter);
        }

        if (startDate) {
            query = query.gte('created_at', new Date(startDate).toISOString());
        }

        if (endDate) {
            const endDateTime = new Date(endDate);
            endDateTime.setHours(23, 59, 59, 999);
            query = query.lte('created_at', endDateTime.toISOString());
        }

        const { data, error } = await query;
        if (error) {
            throw error;
        }

        return res.json({ success: true, logs: (data || []).map(formatAuditLog) });
    } catch (error) {
        console.error('❌ Erro ao listar logs de auditoria:', error);
        return res.status(500).json({ success: false, error: 'Erro ao listar logs de auditoria' });
    }
};

app.get('/api/audit-logs', verifyToken, listAuditLogsHandler);
app.get('/api/logs-auditoria', verifyToken, listAuditLogsHandler);

// ============================================
// 📡 HOTSPOTS
// ============================================

app.get('/api/hotspots', verifyToken, async (req, res) => {
    try {
        const { data: hotspots, error } = await supabase.from('pops').select('*').order('created_at', { ascending: false });
        if (error) {
            throw error;
        }

        return res.json((hotspots || []).map(formatHotspot));
    } catch (error) {
        console.error('❌ Erro ao listar hotspots:', error);
        return res.status(500).json({ error: 'Erro ao listar hotspots' });
    }
});

app.post('/api/hotspots', verifyToken, async (req, res) => {
    try {
        const name = safeString(req.body.name).trim();
        if (!name) {
            return res.status(400).json({ error: 'Nome do hotspot é obrigatório' });
        }

        const now = new Date().toISOString();
        const uniqueId = removeAccents(name)
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '');

        const fullInsertPayload = {
            name,
            unique_id: uniqueId || `hotspot-${Date.now()}`,
            location: req.body.location || 'Localização não definida',
            ip: req.body.ip || null,
            status: 'offline',
            connected_users: 0,
            bandwidth_used: '0 Mbps',
            last_heartbeat: null,
            tipo_instalacao: req.body.tipo_instalacao || 'novo',
            wan_interface: req.body.wan_interface || null,
            lan_interface: req.body.lan_interface || null,
            vlan_id: req.body.vlan_id || null,
            hotspot_tipo: req.body.hotspot_tipo || 'vlan',
            vlan_existente: req.body.vlan_existente || null,
            porta_fisica: req.body.porta_fisica || null,
            wan_tipo: req.body.wan_tipo || null,
            pppoe_user: req.body.pppoe_user || null,
            pppoe_pass: req.body.pppoe_pass || null,
            static_ip: req.body.static_ip || null,
            static_mask: req.body.static_mask || null,
            static_gw: req.body.static_gw || null,
            created_at: now,
            updated_at: now
        };

        let insertResult = await supabase.from('pops').insert(fullInsertPayload).select('*').single();

        if (insertResult.error) {
            insertResult = await supabase
                .from('pops')
                .insert({
                    name,
                    unique_id: fullInsertPayload.unique_id,
                    location: fullInsertPayload.location,
                    ip: fullInsertPayload.ip,
                    status: 'offline',
                    connected_users: 0,
                    bandwidth_used: '0 Mbps',
                    created_at: now,
                    updated_at: now
                })
                .select('*')
                .single();
        }

        if (insertResult.error) {
            throw insertResult.error;
        }

        const hotspot = formatHotspot(insertResult.data);
        return res.json({
            success: true,
            id: hotspot.id,
            unique_id: hotspot.unique_id,
            hotspot,
            script: buildHotspotScript(hotspot)
        });
    } catch (error) {
        console.error('❌ Erro ao criar hotspot:', error);
        return res.status(500).json({ error: 'Erro ao criar hotspot' });
    }
});

app.get('/api/hotspots/:hotspotName/script', verifyToken, async (req, res) => {
    try {
        const targetName = decodeURIComponent(req.params.hotspotName).toLowerCase();
        const { data: hotspots, error } = await supabase.from('pops').select('*');

        if (error) {
            throw error;
        }

        const rawHotspot = (hotspots || []).find(hotspot =>
            safeString(hotspot.name).toLowerCase() === targetName ||
            safeString(hotspot.unique_id).toLowerCase() === targetName
        );

        if (!rawHotspot) {
            return res.status(404).json({ error: 'Hotspot não encontrado' });
        }

        const hotspot = formatHotspot(rawHotspot);
        return res.json({ success: true, hotspot, script: buildHotspotScript(hotspot) });
    } catch (error) {
        console.error('❌ Erro ao gerar script do hotspot:', error);
        return res.status(500).json({ error: 'Erro ao gerar script do hotspot' });
    }
});

app.delete('/api/hotspots/:id', verifyToken, async (req, res) => {
    try {
        const { error } = await supabase.from('pops').delete().eq('id', req.params.id);
        if (error) {
            throw error;
        }

        return res.json({ success: true });
    } catch (error) {
        console.error('❌ Erro ao deletar hotspot:', error);
        return res.status(500).json({ error: 'Erro ao deletar hotspot' });
    }
});

// ============================================
// 👤 DETALHE E AÇÕES DE USUÁRIOS
// ============================================

app.get('/api/users/:id', verifyToken, async (req, res) => {
    try {
        const user = await findUnifiedUserById(req.params.id);

        if (!user) {
            return res.status(404).json({ error: 'Cliente não encontrado' });
        }

        const [{ data: payments }, { data: accessLogs }, { data: sessions }] = await Promise.all([
            supabase.from('pagamentos').select('valor, created_at, data').eq('user_id', user.id),
            supabase.from('acessos_hotspot').select('access_time').eq('user_id', user.id).order('access_time', { ascending: false }).limit(1),
            user.mac
                ? supabase.from('hotspot_sessions').select('created_at').eq('mac_address', user.mac).order('created_at', { ascending: false }).limit(1)
                : Promise.resolve({ data: [] })
        ]);

        const totalSpent = (payments || []).reduce((total, payment) => total + safeNumber(payment.valor), 0);
        const lastAccess = accessLogs?.[0]?.access_time || sessions?.[0]?.created_at || null;

        return res.json({
            ...user,
            total_spent: totalSpent,
            total_gasto: totalSpent,
            last_access: lastAccess ? new Date(lastAccess).toLocaleString('pt-BR') : '-',
            ultimo_acesso: lastAccess ? new Date(lastAccess).toLocaleString('pt-BR') : '-'
        });
    } catch (error) {
        console.error('❌ Erro ao buscar usuário:', error);
        return res.status(500).json({ error: 'Erro ao buscar usuário' });
    }
});

app.put('/api/users/:id', verifyToken, async (req, res) => {
    try {
        const requestedStatus = req.body.status;
        if (!requestedStatus) {
            return res.status(400).json({ error: 'Status é obrigatório' });
        }

        const userId = req.params.id;
        const normalizedStatus = normalizePaymentStatus(requestedStatus);
        const [appUserResult, radiusUserResult] = await Promise.all([
            supabase.from('usuarios').select('*').eq('id', userId).maybeSingle(),
            supabase.from('radreply').select('*').eq('id', userId).maybeSingle()
        ]);

        if (appUserResult.error) throw appUserResult.error;
        if (radiusUserResult.error) throw radiusUserResult.error;

        const pendingUpdates = [];

        if (appUserResult.data) {
            pendingUpdates.push(supabase.from('usuarios').update({ status: normalizedStatus }).eq('id', userId));
        }

        if (radiusUserResult.data) {
            pendingUpdates.push(supabase.from('radreply').update({ status: normalizedStatus }).eq('id', userId));
        }

        if (!radiusUserResult.data && appUserResult.data?.username) {
            pendingUpdates.push(supabase.from('radreply').update({ status: normalizedStatus }).eq('username', appUserResult.data.username));
        }

        await Promise.all(pendingUpdates);

        const updatedUser = await findUnifiedUserById(userId);
        return res.json({ success: true, user: updatedUser });
    } catch (error) {
        console.error('❌ Erro ao atualizar usuário:', error);
        return res.status(500).json({ error: 'Erro ao atualizar usuário' });
    }
});

app.post('/api/users/:id/vip', verifyToken, async (req, res) => {
    try {
        const userId = req.params.id;
        const [appUserResult, radiusUserResult] = await Promise.all([
            supabase.from('usuarios').select('*').eq('id', userId).maybeSingle(),
            supabase.from('radreply').select('*').eq('id', userId).maybeSingle()
        ]);

        if (appUserResult.error) throw appUserResult.error;
        if (radiusUserResult.error) throw radiusUserResult.error;

        let updated = false;

        if (appUserResult.data) {
            if (Object.prototype.hasOwnProperty.call(appUserResult.data, 'is_vip')) {
                await supabase.from('usuarios').update({ is_vip: true }).eq('id', userId);
                updated = true;
            } else if (Object.prototype.hasOwnProperty.call(appUserResult.data, 'vip')) {
                await supabase.from('usuarios').update({ vip: true }).eq('id', userId);
                updated = true;
            }
        }

        if (radiusUserResult.data && !updated) {
            if (Object.prototype.hasOwnProperty.call(radiusUserResult.data, 'is_vip')) {
                await supabase.from('radreply').update({ is_vip: true }).eq('id', userId);
                updated = true;
            } else if (Object.prototype.hasOwnProperty.call(radiusUserResult.data, 'vip')) {
                await supabase.from('radreply').update({ vip: true }).eq('id', userId);
                updated = true;
            }
        }

        if (!updated) {
            return res.status(409).json({ error: 'Estrutura atual do banco não possui campo VIP compatível' });
        }

        return res.json({ success: true });
    } catch (error) {
        console.error('❌ Erro ao marcar usuário como VIP:', error);
        return res.status(500).json({ error: 'Erro ao marcar usuário como VIP' });
    }
});

// ============================================
// 🏥 HEALTH CHECK
// ============================================

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/entrypoint', (req, res) => {
    const { hotspotIdentity, userMac, hostname } = req.query;
    const frontendUrl = `https://hotspot-system.vercel.app/index.html?mac=${userMac}&ip=${hostname}&pop=${hotspotIdentity}`;
    res.redirect(frontendUrl);
});

// ============================================
// ⏱️ CRON JOB - REMOVER ACESSOS EXPIRADOS
// ============================================

setInterval(async () => {
    try {
        const now = new Date();
        const { data: expiredSessions } = await supabase
            .from('hotspot_sessions')
            .select('*')
            .lt('expires_at', now.toISOString())
            .eq('status', 'active');

        for (const session of expiredSessions || []) {
            if (session.mac_address && session.mac_address !== 'pending') {
                await revokeHotspotAccess(session);
            }
            await supabase.from('hotspot_sessions').update({ status: 'expired' }).eq('id', session.id);
        }
    } catch (error) {
        console.error('❌ Erro no CRON:', error);
    }
}, 60000);

// ============================================
// 🚀 INICIAR SERVIDOR
// ============================================

app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║  🚀 MS TELECOM - HOTSPOT SYSTEM API                          ║
║  ✅ Servidor: http://localhost:${PORT}                          ║
║  ✅ Deploy Automático: GitHub Actions → VPS                  ║
║  ✅ Padrão: Código EN, Comentários PT-BR                     ║
║  ✅ Estatísticas REAIS com dados do banco                    ║
╚══════════════════════════════════════════════════════════════╝
    `);
});
