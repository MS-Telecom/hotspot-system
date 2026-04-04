// ============================================================
// Hotspot System - MS TELECOM
// Backend principal (server.js)
// Código interno em inglês, comentários em português
// ============================================================

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuração do Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// Segredo JWT
const JWT_SECRET = process.env.JWT_SECRET || 'ms-telecom-jwt-secret-default';

// ============================================================
// MIDDLEWARES
// ============================================================

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir arquivos estáticos da pasta public
app.use(express.static(path.join(__dirname, '../public')));

// Middleware de autenticação JWT
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// Função auxiliar para registrar log de auditoria
async function logAudit(username, type, object, action, ip, userAgent) {
  try {
    await supabase.from('audit_logs').insert({
      username,
      type,
      object,
      action,
      ip: ip || '',
      user_agent: userAgent || ''
    });
  } catch (err) {
    console.error('Erro ao registrar log de auditoria:', err.message);
  }
}

// Função auxiliar para registrar log do sistema
async function logSystem(level, source, message, details, ip, userAgent) {
  try {
    await supabase.from('logs').insert({
      level,
      source,
      message,
      details: details || null,
      ip: ip || '',
      user_agent: userAgent || ''
    });
  } catch (err) {
    console.error('Erro ao registrar log do sistema:', err.message);
  }
}

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

    // Comparação de senha (hash ou texto plano para compatibilidade)
    let passwordMatch = false;
    if (admin.password.startsWith('$2') || admin.password.length === 64) {
      // Hash bcrypt ou SHA-256
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

    await logAudit(admin.username, 'auth', 'admin', 'login', req.ip, req.headers['user-agent']);
    await logSystem('info', 'auth', `Login realizado: ${admin.username}`, null, req.ip, req.headers['user-agent']);

    res.json({
      token,
      user: {
        id: admin.id,
        username: admin.username,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (err) {
    console.error('Erro no login:', err.message);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Logout
app.post('/api/logout', authMiddleware, async (req, res) => {
  try {
    await logAudit(req.user.username, 'auth', 'admin', 'logout', req.ip, req.headers['user-agent']);
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

    const { error } = await supabase
      .from('admins')
      .update(updateData)
      .eq('id', req.user.id);

    if (error) throw error;

    await logAudit(req.user.username, 'update', 'admin', 'Perfil atualizado', req.ip, req.headers['user-agent']);
    res.json({ message: 'Perfil atualizado com sucesso' });
  } catch (err) {
    console.error('Erro ao atualizar perfil:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar perfil' });
  }
});

// ============================================================
// ROTAS DE USUÁRIOS (CLIENTES)
// ============================================================

// Listar usuários
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar usuários:', err.message);
    res.status(500).json({ error: 'Erro ao listar usuários' });
  }
});

// Criar usuário
app.post('/api/users', authMiddleware, async (req, res) => {
  try {
    const { name, username, mac_address, phone, cpf, email, address, plan_id, plan_name, hotspot_id, status, is_vip } = req.body;

    const { data, error } = await supabase
      .from('users')
      .insert({
        name, username, mac_address, phone, cpf, email, address,
        plan_id, plan_name, hotspot_id,
        status: status || 'inactive',
        is_vip: is_vip || false
      })
      .select()
      .single();

    if (error) throw error;

    await logAudit(req.user.username, 'create', 'user', `Usuário criado: ${name}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar usuário:', err.message);
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

    const { data, error } = await supabase
      .from('users')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    await logAudit(req.user.username, 'update', 'user', `Usuário atualizado: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    console.error('Erro ao atualizar usuário:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar usuário' });
  }
});

// Deletar usuário
app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabase
      .from('users')
      .delete()
      .eq('id', id);

    if (error) throw error;

    await logAudit(req.user.username, 'delete', 'user', `Usuário removido: ${id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Usuário removido com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar usuário:', err.message);
    res.status(500).json({ error: 'Erro ao deletar usuário' });
  }
});

// ============================================================
// ROTAS DE PLANOS
// ============================================================

// Listar planos
app.get('/api/plans', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('plans')
      .select('*')
      .order('price', { ascending: true });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar planos:', err.message);
    res.status(500).json({ error: 'Erro ao listar planos' });
  }
});

// Criar plano
app.post('/api/plans', authMiddleware, async (req, res) => {
  try {
    const { name, price, speed_mbps, duration_days, description, active } = req.body;

    const { data, error } = await supabase
      .from('plans')
      .insert({
        name, price, speed_mbps, duration_days, description,
        active: active !== undefined ? active : true
      })
      .select()
      .single();

    if (error) throw error;

    await logAudit(req.user.username, 'create', 'plan', `Plano criado: ${name}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar plano:', err.message);
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

    const { data, error } = await supabase
      .from('plans')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    await logAudit(req.user.username, 'update', 'plan', `Plano atualizado: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    console.error('Erro ao atualizar plano:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar plano' });
  }
});

// Deletar plano
app.delete('/api/plans/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabase
      .from('plans')
      .delete()
      .eq('id', id);

    if (error) throw error;

    await logAudit(req.user.username, 'delete', 'plan', `Plano removido: ${id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Plano removido com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar plano:', err.message);
    res.status(500).json({ error: 'Erro ao deletar plano' });
  }
});

// ============================================================
// ROTAS DE PAGAMENTOS
// ============================================================

// Listar pagamentos
app.get('/api/payments', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('payments')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar pagamentos:', err.message);
    res.status(500).json({ error: 'Erro ao listar pagamentos' });
  }
});

// Gerar PIX via Mercado Pago
app.post('/api/payments/generate-pix', async (req, res) => {
  try {
    const { amount, description, email, cpf, name, plan_id, user_mac } = req.body;

    if (!amount || !description) {
      return res.status(400).json({ error: 'Valor e descrição são obrigatórios' });
    }

    const externalReference = `HS-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    // Integração com Mercado Pago
    const mpAccessToken = process.env.MP_ACCESS_TOKEN;
    if (!mpAccessToken) {
      return res.status(500).json({ error: 'Token do Mercado Pago não configurado' });
    }

    const mpPayload = {
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
    };

    const mpResponse = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${mpAccessToken}`,
        'X-Idempotency-Key': externalReference
      },
      body: JSON.stringify(mpPayload)
    });

    const mpData = await mpResponse.json();

    if (!mpResponse.ok) {
      console.error('Erro Mercado Pago:', mpData);
      return res.status(400).json({ error: 'Erro ao gerar pagamento PIX', details: mpData });
    }

    const pixCopyPaste = mpData.point_of_interaction?.transaction_data?.qr_code || '';
    const qrCodeBase64 = mpData.point_of_interaction?.transaction_data?.qr_code_base64 || '';

    // Salvar pagamento no banco
    const { data: payment, error } = await supabase
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

    if (error) throw error;

    await logSystem('info', 'payment', `PIX gerado: ${externalReference}`, { amount, plan_id }, req.ip, req.headers['user-agent']);

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
    console.error('Erro ao gerar PIX:', err.message);
    res.status(500).json({ error: 'Erro ao gerar pagamento PIX' });
  }
});

// Verificar status de pagamento
app.get('/api/check-payment', async (req, res) => {
  try {
    const { external_reference, mercado_pago_id } = req.query;

    if (!external_reference && !mercado_pago_id) {
      return res.status(400).json({ error: 'Referência ou ID do pagamento necessário' });
    }

    let query = supabase.from('payments').select('*');
    if (external_reference) {
      query = query.eq('external_reference', external_reference);
    } else {
      query = query.eq('mercado_pago_id', mercado_pago_id);
    }

    const { data: payment, error } = await query.single();
    if (error || !payment) {
      return res.status(404).json({ error: 'Pagamento não encontrado' });
    }

    // Verificar no Mercado Pago se ainda pendente
    if (payment.status === 'pending' && payment.mercado_pago_id) {
      const mpAccessToken = process.env.MP_ACCESS_TOKEN;
      if (mpAccessToken) {
        try {
          const mpRes = await fetch(`https://api.mercadopago.com/v1/payments/${payment.mercado_pago_id}`, {
            headers: { 'Authorization': `Bearer ${mpAccessToken}` }
          });
          const mpData = await mpRes.json();

          if (mpData.status === 'approved') {
            await supabase.from('payments').update({
              status: 'approved',
              confirmed_at: new Date().toISOString(),
              updated_at: new Date().toISOString()
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

// Criar pagamento manual
app.post('/api/create-payment', authMiddleware, async (req, res) => {
  try {
    const { user_id, plan_id, user_mac, amount, description, status, payment_method } = req.body;

    const { data, error } = await supabase
      .from('payments')
      .insert({
        user_id, plan_id, user_mac,
        amount: parseFloat(amount || 0),
        description: description || 'Pagamento manual',
        status: status || 'approved',
        payment_method: payment_method || 'manual',
        external_reference: `MANUAL-${Date.now()}`,
        confirmed_at: status === 'approved' ? new Date().toISOString() : null
      })
      .select()
      .single();

    if (error) throw error;

    await logAudit(req.user.username, 'create', 'payment', `Pagamento manual criado: ${data.id}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao criar pagamento' });
  }
});

// Confirmar pagamento manualmente
app.post('/api/confirm-payment', authMiddleware, async (req, res) => {
  try {
    const { payment_id, user_id, plan_id } = req.body;

    const { data: payment, error: payErr } = await supabase
      .from('payments')
      .update({
        status: 'approved',
        confirmed_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .eq('id', payment_id)
      .select()
      .single();

    if (payErr) throw payErr;

    // Se tiver user_id e plan_id, ativar acesso do usuário
    if (user_id && plan_id) {
      const { data: plan } = await supabase.from('plans').select('*').eq('id', plan_id).single();
      if (plan) {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + (plan.duration_days || 30));

        await supabase.from('users').update({
          status: 'active',
          plan_id: plan.id,
          plan_name: plan.name,
          expires_at: expiresAt.toISOString(),
          updated_at: new Date().toISOString()
        }).eq('id', user_id);
      }
    }

    await logAudit(req.user.username, 'update', 'payment', `Pagamento confirmado: ${payment_id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Pagamento confirmado com sucesso', payment });
  } catch (err) {
    console.error('Erro ao confirmar pagamento:', err.message);
    res.status(500).json({ error: 'Erro ao confirmar pagamento' });
  }
});

// ============================================================
// ROTAS DE VOUCHERS
// ============================================================

// Listar vouchers
app.get('/api/vouchers', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('vouchers')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar vouchers:', err.message);
    res.status(500).json({ error: 'Erro ao listar vouchers' });
  }
});

// Criar voucher
app.post('/api/vouchers', authMiddleware, async (req, res) => {
  try {
    const { plan_name, amount, expires_at, quantity } = req.body;
    const count = parseInt(quantity) || 1;
    const vouchers = [];

    for (let i = 0; i < count; i++) {
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      vouchers.push({
        code,
        plan_name: plan_name || '',
        amount: parseFloat(amount || 0),
        used: false,
        expires_at: expires_at || null
      });
    }

    const { data, error } = await supabase
      .from('vouchers')
      .insert(vouchers)
      .select();

    if (error) throw error;

    await logAudit(req.user.username, 'create', 'voucher', `${count} voucher(s) criado(s)`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar voucher:', err.message);
    res.status(500).json({ error: 'Erro ao criar voucher' });
  }
});

// Atualizar voucher
app.put('/api/vouchers/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;

    const { data, error } = await supabase
      .from('vouchers')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('Erro ao atualizar voucher:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar voucher' });
  }
});

// Deletar voucher
app.delete('/api/vouchers/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('vouchers').delete().eq('id', id);
    if (error) throw error;

    await logAudit(req.user.username, 'delete', 'voucher', `Voucher removido: ${id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Voucher removido com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar voucher:', err.message);
    res.status(500).json({ error: 'Erro ao deletar voucher' });
  }
});

// ============================================================
// ROTAS DE CAMPANHAS
// ============================================================

// Listar campanhas
app.get('/api/campaigns', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('campaigns')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar campanhas:', err.message);
    res.status(500).json({ error: 'Erro ao listar campanhas' });
  }
});

// Criar campanha
app.post('/api/campaigns', authMiddleware, async (req, res) => {
  try {
    const { name, description, coupon_code, status, starts_at, ends_at } = req.body;

    const { data, error } = await supabase
      .from('campaigns')
      .insert({
        name, description, coupon_code,
        status: status || 'active',
        starts_at, ends_at
      })
      .select()
      .single();

    if (error) throw error;

    await logAudit(req.user.username, 'create', 'campaign', `Campanha criada: ${name}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar campanha:', err.message);
    res.status(500).json({ error: 'Erro ao criar campanha' });
  }
});

// Atualizar campanha
app.put('/api/campaigns/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updated_at: new Date().toISOString() };
    delete updateData.id;

    const { data, error } = await supabase
      .from('campaigns')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    await logAudit(req.user.username, 'update', 'campaign', `Campanha atualizada: ${id}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    console.error('Erro ao atualizar campanha:', err.message);
    res.status(500).json({ error: 'Erro ao atualizar campanha' });
  }
});

// Deletar campanha
app.delete('/api/campaigns/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('campaigns').delete().eq('id', id);
    if (error) throw error;

    await logAudit(req.user.username, 'delete', 'campaign', `Campanha removida: ${id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Campanha removida com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar campanha:', err.message);
    res.status(500).json({ error: 'Erro ao deletar campanha' });
  }
});

// ============================================================
// ROTAS DE WEBHOOKS
// ============================================================

// Listar webhooks
app.get('/api/webhooks', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('webhooks')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar webhooks:', err.message);
    res.status(500).json({ error: 'Erro ao listar webhooks' });
  }
});

// Criar webhook
app.post('/api/webhooks', authMiddleware, async (req, res) => {
  try {
    const { name, event, url, method, target, active } = req.body;

    const { data, error } = await supabase
      .from('webhooks')
      .insert({
        name, event, url,
        method: method || 'POST',
        target: target || 'all',
        active: active !== undefined ? active : true
      })
      .select()
      .single();

    if (error) throw error;

    await logAudit(req.user.username, 'create', 'webhook', `Webhook criado: ${name}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar webhook:', err.message);
    res.status(500).json({ error: 'Erro ao criar webhook' });
  }
});

// Deletar webhook
app.delete('/api/webhooks/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('webhooks').delete().eq('id', id);
    if (error) throw error;

    await logAudit(req.user.username, 'delete', 'webhook', `Webhook removido: ${id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Webhook removido com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar webhook:', err.message);
    res.status(500).json({ error: 'Erro ao deletar webhook' });
  }
});

// ============================================================
// ROTAS DE CONFIGURAÇÕES
// ============================================================

// Obter campos de cadastro
app.get('/api/settings/fields', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('settings')
      .select('*')
      .eq('category', 'fields');

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar campos' });
  }
});

// Salvar campos de cadastro
app.post('/api/settings/fields', authMiddleware, async (req, res) => {
  try {
    const { fields } = req.body;

    // Upsert: atualizar ou criar
    const { error } = await supabase
      .from('settings')
      .upsert({
        key: 'registration_fields',
        category: 'fields',
        value: fields,
        updated_at: new Date().toISOString()
      }, { onConflict: 'key' });

    if (error) throw error;

    await logAudit(req.user.username, 'update', 'settings', 'Campos de cadastro atualizados', req.ip, req.headers['user-agent']);
    res.json({ message: 'Campos salvos com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao salvar campos' });
  }
});

// Obter configurações do sistema
app.get('/api/settings/system', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('settings')
      .select('*')
      .eq('category', 'system');

    if (error) throw error;

    // Transformar em objeto chave-valor
    const settings = {};
    (data || []).forEach(item => {
      settings[item.key] = item.value;
    });

    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar configurações do sistema' });
  }
});

// Salvar configurações do sistema
app.post('/api/settings/system', authMiddleware, async (req, res) => {
  try {
    const entries = Object.entries(req.body);
    for (const [key, value] of entries) {
      await supabase
        .from('settings')
        .upsert({
          key,
          category: 'system',
          value: typeof value === 'object' ? value : { value },
          updated_at: new Date().toISOString()
        }, { onConflict: 'key' });
    }

    await logAudit(req.user.username, 'update', 'settings', 'Configurações do sistema atualizadas', req.ip, req.headers['user-agent']);
    res.json({ message: 'Configurações salvas com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao salvar configurações do sistema' });
  }
});

// Obter configurações de pagamento
app.get('/api/settings/payment', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('settings')
      .select('*')
      .eq('category', 'payment');

    if (error) throw error;

    const settings = {};
    (data || []).forEach(item => {
      settings[item.key] = item.value;
    });

    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar configurações de pagamento' });
  }
});

// Salvar configurações de pagamento
app.post('/api/settings/payment', authMiddleware, async (req, res) => {
  try {
    const entries = Object.entries(req.body);
    for (const [key, value] of entries) {
      await supabase
        .from('settings')
        .upsert({
          key,
          category: 'payment',
          value: typeof value === 'object' ? value : { value },
          updated_at: new Date().toISOString()
        }, { onConflict: 'key' });
    }

    await logAudit(req.user.username, 'update', 'settings', 'Configurações de pagamento atualizadas', req.ip, req.headers['user-agent']);
    res.json({ message: 'Configurações de pagamento salvas com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao salvar configurações de pagamento' });
  }
});

// ============================================================
// ROTAS DE HOTSPOTS
// ============================================================

// Listar hotspots
app.get('/api/hotspots', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('hotspots')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Erro ao listar hotspots:', err.message);
    res.status(500).json({ error: 'Erro ao listar hotspots' });
  }
});

// Criar hotspot
app.post('/api/hotspots', authMiddleware, async (req, res) => {
  try {
    const { name, location, address, pop_id, radius_enabled, dns_name } = req.body;

    const { data, error } = await supabase
      .from('hotspots')
      .insert({
        name, location, address, pop_id,
        status: 'active',
        radius_enabled: radius_enabled || false,
        dns_name
      })
      .select()
      .single();

    if (error) throw error;

    await logAudit(req.user.username, 'create', 'hotspot', `Hotspot criado: ${name}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    console.error('Erro ao criar hotspot:', err.message);
    res.status(500).json({ error: 'Erro ao criar hotspot' });
  }
});

// Deletar hotspot
app.delete('/api/hotspots/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('hotspots').delete().eq('id', id);
    if (error) throw error;

    await logAudit(req.user.username, 'delete', 'hotspot', `Hotspot removido: ${id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Hotspot removido com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar hotspot:', err.message);
    res.status(500).json({ error: 'Erro ao deletar hotspot' });
  }
});

// ============================================================
// ROTAS DE POPs E PING
// ============================================================

// Listar POPs
app.get('/api/pops', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('pops')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar POPs' });
  }
});

// Ping de POP (heartbeat) - cria automaticamente se não existir
app.post('/api/pops/:id/ping', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, ip, connected_users, bandwidth_used, unique_id } = req.body;

    // Verificar se POP existe
    const { data: existing } = await supabase
      .from('pops')
      .select('id')
      .eq('id', id)
      .single();

    if (existing) {
      // Atualizar heartbeat
      await supabase.from('pops').update({
        status: 'online',
        last_seen_at: new Date().toISOString(),
        ip: ip || undefined,
        connected_users: connected_users || 0,
        bandwidth_used: bandwidth_used || '0 Mbps',
        updated_at: new Date().toISOString()
      }).eq('id', id);
    } else {
      // Criar POP automaticamente
      await supabase.from('pops').insert({
        id,
        name: name || `POP-${id}`,
        unique_id: unique_id || id,
        ip: ip || req.ip,
        status: 'online',
        last_seen_at: new Date().toISOString(),
        connected_users: connected_users || 0,
        bandwidth_used: bandwidth_used || '0 Mbps'
      });
    }

    res.json({ status: 'ok', message: 'Ping recebido' });
  } catch (err) {
    console.error('Erro no ping do POP:', err.message);
    res.status(500).json({ error: 'Erro ao processar ping' });
  }
});

// ============================================================
// ROTAS DE TESTE GRATUITO E VALIDAÇÃO DE ACESSO
// ============================================================

// Liberar teste gratuito
app.post('/api/free-trial', async (req, res) => {
  try {
    const { mac } = req.body;
    if (!mac) {
      return res.status(400).json({ error: 'MAC address é obrigatório' });
    }

    // Buscar configurações de teste gratuito
    const { data: settingsData } = await supabase
      .from('settings')
      .select('*')
      .in('key', ['free_trial_minutes', 'free_trial_hours_limit']);

    const settings = {};
    (settingsData || []).forEach(s => {
      settings[s.key] = s.value?.value || s.value;
    });

    const trialMinutes = parseInt(settings.free_trial_minutes) || 30;
    const hoursLimit = parseInt(settings.free_trial_hours_limit) || 24;

    // Verificar se já usou teste recentemente
    const { data: existing } = await supabase
      .from('free_trials')
      .select('*')
      .eq('mac', mac)
      .single();

    if (existing) {
      const lastTrial = new Date(existing.last_trial);
      const hoursSince = (Date.now() - lastTrial.getTime()) / (1000 * 60 * 60);

      if (hoursSince < hoursLimit) {
        return res.status(429).json({
          error: `Teste gratuito já utilizado. Tente novamente em ${Math.ceil(hoursLimit - hoursSince)} horas.`
        });
      }

      // Atualizar registro
      await supabase.from('free_trials').update({
        last_trial: new Date().toISOString(),
        attempts: existing.attempts + 1,
        updated_at: new Date().toISOString()
      }).eq('id', existing.id);
    } else {
      // Criar novo registro
      await supabase.from('free_trials').insert({
        mac,
        last_trial: new Date().toISOString(),
        attempts: 1
      });
    }

    const expiresAt = new Date(Date.now() + trialMinutes * 60 * 1000);

    // Criar sessão de hotspot
    await supabase.from('hotspot_sessions').insert({
      mac_address: mac,
      access_granted: true,
      status: 'active',
      expires_at: expiresAt.toISOString()
    });

    await logSystem('info', 'free-trial', `Teste gratuito liberado: ${mac}`, { trialMinutes }, req.ip, req.headers['user-agent']);

    res.json({
      message: 'Teste gratuito liberado',
      duration_minutes: trialMinutes,
      expires_at: expiresAt.toISOString()
    });
  } catch (err) {
    console.error('Erro ao liberar teste gratuito:', err.message);
    res.status(500).json({ error: 'Erro ao liberar teste gratuito' });
  }
});

// Validar acesso do usuário
app.post('/api/validate-access', async (req, res) => {
  try {
    const { mac, username } = req.body;

    if (!mac && !username) {
      return res.status(400).json({ error: 'MAC ou username é obrigatório' });
    }

    // Buscar usuário por MAC ou username
    let query = supabase.from('users').select('*');
    if (mac) {
      query = query.eq('mac_address', mac);
    } else {
      query = query.eq('username', username);
    }

    const { data: user } = await query.single();

    if (!user) {
      return res.json({ access: false, reason: 'Usuário não encontrado' });
    }

    if (user.status !== 'active') {
      return res.json({ access: false, reason: 'Conta inativa' });
    }

    if (user.expires_at && new Date(user.expires_at) < new Date()) {
      return res.json({ access: false, reason: 'Plano expirado' });
    }

    // Verificar sessão ativa
    const { data: session } = await supabase
      .from('hotspot_sessions')
      .select('*')
      .eq('mac_address', mac || user.mac_address)
      .eq('status', 'active')
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    res.json({
      access: true,
      user: {
        id: user.id,
        name: user.name,
        plan_name: user.plan_name,
        expires_at: user.expires_at,
        is_vip: user.is_vip
      },
      session: session || null
    });
  } catch (err) {
    console.error('Erro ao validar acesso:', err.message);
    res.status(500).json({ error: 'Erro ao validar acesso' });
  }
});

// ============================================================
// ROTAS DE ESTATÍSTICAS
// ============================================================

// Estatísticas gerais
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
      supabase.from('vouchers').select('*', { count: 'exact', head: true }).eq('used', false)
    ]);

    // Faturamento total (pagamentos aprovados)
    const { data: revenueData } = await supabase
      .from('payments')
      .select('amount')
      .eq('status', 'approved');

    const totalRevenue = (revenueData || []).reduce((sum, p) => sum + parseFloat(p.amount || 0), 0);

    // Faturamento do mês
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);

    const { data: monthRevenueData } = await supabase
      .from('payments')
      .select('amount')
      .eq('status', 'approved')
      .gte('confirmed_at', startOfMonth.toISOString());

    const monthRevenue = (monthRevenueData || []).reduce((sum, p) => sum + parseFloat(p.amount || 0), 0);

    // POPs online
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const { count: onlinePops } = await supabase
      .from('pops')
      .select('*', { count: 'exact', head: true })
      .gte('last_seen_at', fiveMinutesAgo);

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

    const { data } = await supabase
      .from('hotspot_sessions')
      .select('created_at')
      .gte('created_at', twentyFourHoursAgo);

    // Agrupar por hora
    const hourly = {};
    for (let i = 0; i < 24; i++) {
      hourly[i] = 0;
    }

    (data || []).forEach(session => {
      const hour = new Date(session.created_at).getHours();
      hourly[hour] = (hourly[hour] || 0) + 1;
    });

    const result = Object.entries(hourly).map(([hour, count]) => ({
      hour: parseInt(hour),
      count
    }));

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar usuários por hora' });
  }
});

// Tráfego total
app.get('/api/stats/total-traffic', authMiddleware, async (req, res) => {
  try {
    const { data } = await supabase
      .from('pops')
      .select('bandwidth_used');

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
    const { data } = await supabase
      .from('pops')
      .select('bandwidth_used');

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
    const { data: payments } = await supabase
      .from('payments')
      .select('plan_id, amount')
      .eq('status', 'approved');

    const { data: plans } = await supabase.from('plans').select('id, name');

    const planMap = {};
    (plans || []).forEach(p => { planMap[p.id] = p.name; });

    const comparison = {};
    (payments || []).forEach(p => {
      const planName = planMap[p.plan_id] || 'Outros';
      comparison[planName] = (comparison[planName] || 0) + parseFloat(p.amount || 0);
    });

    const result = Object.entries(comparison).map(([name, total]) => ({ name, total }));
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar comparação' });
  }
});

// ============================================================
// ROTAS DE LOGS E AUDITORIA
// ============================================================

// Listar logs do sistema
app.get('/api/logs', authMiddleware, async (req, res) => {
  try {
    const { limit: queryLimit, level, source } = req.query;
    let query = supabase.from('logs').select('*').order('created_at', { ascending: false });

    if (level) query = query.eq('level', level);
    if (source) query = query.eq('source', source);
    query = query.limit(parseInt(queryLimit) || 100);

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar logs' });
  }
});

// Listar logs de auditoria
app.get('/api/audit-logs', authMiddleware, async (req, res) => {
  try {
    const { limit: queryLimit, type, username } = req.query;
    let query = supabase.from('audit_logs').select('*').order('created_at', { ascending: false });

    if (type) query = query.eq('type', type);
    if (username) query = query.eq('username', username);
    query = query.limit(parseInt(queryLimit) || 100);

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar logs de auditoria' });
  }
});

// Criar log de auditoria manual
app.post('/api/audit-logs', authMiddleware, async (req, res) => {
  try {
    const { type, object, action } = req.body;

    const { data, error } = await supabase
      .from('audit_logs')
      .insert({
        username: req.user.username,
        type, object, action,
        ip: req.ip,
        user_agent: req.headers['user-agent']
      })
      .select()
      .single();

    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao criar log de auditoria' });
  }
});

// ============================================================
// ROTA DE ENTRYPOINT (portal captivo)
// ============================================================

app.get('/entrypoint', (req, res) => {
  const { mac, ip, username, link_login, link_orig } = req.query;
  // Redirecionar para o portal do usuário com parâmetros
  const params = new URLSearchParams({
    mac: mac || '',
    ip: ip || '',
    username: username || '',
    link_login: link_login || '',
    link_orig: link_orig || ''
  });
  res.redirect(`/portal-usuario.html?${params.toString()}`);
});

// ============================================================
// ROTA DE SAÚDE
// ============================================================

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '2.0.0'
  });
});

// ============================================================
// WEBHOOK DO MERCADO PAGO (receber notificações de pagamento)
// ============================================================

app.post('/api/webhooks/mercadopago', async (req, res) => {
  try {
    const { type, data: mpData } = req.body;

    if (type === 'payment') {
      const paymentId = mpData?.id;
      if (!paymentId) return res.sendStatus(200);

      const mpAccessToken = process.env.MP_ACCESS_TOKEN;
      if (!mpAccessToken) return res.sendStatus(200);

      // Buscar detalhes do pagamento no MP
      const mpRes = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
        headers: { 'Authorization': `Bearer ${mpAccessToken}` }
      });
      const mpPayment = await mpRes.json();

      if (mpPayment.status === 'approved') {
        // Atualizar pagamento local
        const { data: localPayment } = await supabase
          .from('payments')
          .select('*')
          .eq('mercado_pago_id', String(paymentId))
          .single();

        if (localPayment && localPayment.status !== 'approved') {
          await supabase.from('payments').update({
            status: 'approved',
            confirmed_at: new Date().toISOString(),
            webhook_payload: req.body,
            updated_at: new Date().toISOString()
          }).eq('id', localPayment.id);

          // Ativar acesso do usuário se aplicável
          if (localPayment.user_id && localPayment.plan_id) {
            const { data: plan } = await supabase.from('plans').select('*').eq('id', localPayment.plan_id).single();
            if (plan) {
              const expiresAt = new Date();
              expiresAt.setDate(expiresAt.getDate() + (plan.duration_days || 30));

              await supabase.from('users').update({
                status: 'active',
                plan_id: plan.id,
                plan_name: plan.name,
                expires_at: expiresAt.toISOString(),
                updated_at: new Date().toISOString()
              }).eq('id', localPayment.user_id);
            }
          }

          await logSystem('info', 'webhook', `Pagamento aprovado via webhook: ${paymentId}`, mpPayment, req.ip, req.headers['user-agent']);
        }
      }
    }

    res.sendStatus(200);
  } catch (err) {
    console.error('Erro no webhook MP:', err.message);
    res.sendStatus(200);
  }
});

// ============================================================
// ROTAS DE ADMINS (CRUD)
// ============================================================

// Listar admins
app.get('/api/admins', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('admins').select('id, username, email, role, created_at').order('id');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar admins' });
  }
});

// Criar admin
app.post('/api/admins', authMiddleware, async (req, res) => {
  try {
    const { username, password, email } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuário e senha obrigatórios' });
    const { data, error } = await supabase.from('admins').insert({ username, password, email: email || null, role: 'admin' }).select().single();
    if (error) throw error;
    await logAudit(req.user.username, 'create', 'admins', `Admin criado: ${username}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao criar admin' });
  }
});

// Excluir admin
app.delete('/api/admins/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('admins').delete().eq('id', id);
    if (error) throw error;
    await logAudit(req.user.username, 'delete', 'admins', `Admin excluído: ${id}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Admin excluído' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao excluir admin' });
  }
});

// ============================================================
// ROTAS DE SETTINGS (genérico key-value)
// ============================================================

// Listar todas as configurações
app.get('/api/settings', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('*').order('key');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar configurações' });
  }
});

// Criar/atualizar configuração
app.post('/api/settings', authMiddleware, async (req, res) => {
  try {
    const { key, value } = req.body;
    if (!key) return res.status(400).json({ error: 'Chave obrigatória' });
    const { data, error } = await supabase.from('settings').upsert({ key, value: typeof value === 'object' ? value : { value }, updated_at: new Date().toISOString() }, { onConflict: 'key' }).select().single();
    if (error) throw error;
    await logAudit(req.user.username, 'update', 'settings', `Configuração atualizada: ${key}`, req.ip, req.headers['user-agent']);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao salvar configuração' });
  }
});

// Excluir configuração
app.delete('/api/settings/:key', authMiddleware, async (req, res) => {
  try {
    const { key } = req.params;
    const { error } = await supabase.from('settings').delete().eq('key', key);
    if (error) throw error;
    await logAudit(req.user.username, 'delete', 'settings', `Configuração excluída: ${key}`, req.ip, req.headers['user-agent']);
    res.json({ message: 'Configuração excluída' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao excluir configuração' });
  }
});

// ============================================================
// ROTAS DO PORTAL PÚBLICO (captive portal - sem auth)
// ============================================================

// Listar planos públicos
app.get('/api/portal/plans', async (req, res) => {
  try {
    const { data, error } = await supabase.from('plans').select('*').order('price', { ascending: true });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar planos' });
  }
});

// Login do portal (usuário final)
app.post('/api/portal/login', async (req, res) => {
  try {
    const { identifier, password, mac_address } = req.body;
    if (!identifier || !password) return res.status(400).json({ error: 'CPF/telefone e senha obrigatórios' });

    // Buscar por CPF ou telefone
    let user = null;
    const { data: byCpf } = await supabase.from('users').select('*').eq('cpf', identifier).single();
    if (byCpf) { user = byCpf; }
    else {
      const { data: byPhone } = await supabase.from('users').select('*').eq('phone', identifier).single();
      if (byPhone) user = byPhone;
    }

    if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });
    if (user.password !== password) return res.status(401).json({ error: 'Senha incorreta' });

    // Atualizar MAC se fornecido
    if (mac_address && mac_address !== user.mac_address) {
      await supabase.from('users').update({ mac_address, updated_at: new Date().toISOString() }).eq('id', user.id);
    }

    await logSystem('info', 'portal', `Login portal: ${user.name || user.cpf}`, null, req.ip, req.headers['user-agent']);

    res.json({
      user_id: user.id,
      name: user.name,
      status: user.status || 'inactive',
      plan_name: user.plan_name || null,
      expires_at: user.expires_at || null
    });
  } catch (err) {
    console.error('Erro portal login:', err.message);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Registro do portal (usuário final)
app.post('/api/portal/register', async (req, res) => {
  try {
    const { name, cpf, phone, password, mac_address } = req.body;
    if (!name || !cpf || !password) return res.status(400).json({ error: 'Nome, CPF e senha obrigatórios' });

    // Verificar se já existe
    const { data: existing } = await supabase.from('users').select('id').eq('cpf', cpf).single();
    if (existing) return res.status(409).json({ error: 'CPF já cadastrado' });

    const { data: user, error } = await supabase.from('users').insert({
      name, cpf, phone: phone || null, password, mac_address: mac_address || null,
      status: 'inactive', created_at: new Date().toISOString()
    }).select().single();

    if (error) throw error;

    await logSystem('info', 'portal', `Novo cadastro: ${name} (${cpf})`, null, req.ip, req.headers['user-agent']);
    res.status(201).json({ user_id: user.id, name: user.name });
  } catch (err) {
    console.error('Erro portal register:', err.message);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Resgatar voucher
app.post('/api/portal/voucher', async (req, res) => {
  try {
    const { code, mac_address } = req.body;
    if (!code) return res.status(400).json({ error: 'Código do voucher obrigatório' });

    const { data: voucher, error } = await supabase.from('vouchers').select('*').eq('code', code.toUpperCase()).single();
    if (error || !voucher) return res.status(404).json({ error: 'Voucher não encontrado' });
    if (voucher.status === 'used') return res.status(400).json({ error: 'Voucher já utilizado' });
    if (voucher.status === 'expired') return res.status(400).json({ error: 'Voucher expirado' });

    // Marcar como usado
    await supabase.from('vouchers').update({
      status: 'used', used_at: new Date().toISOString(), mac_address: mac_address || null,
      updated_at: new Date().toISOString()
    }).eq('id', voucher.id);

    await logSystem('info', 'portal', `Voucher resgatado: ${code}`, { mac_address }, req.ip, req.headers['user-agent']);
    res.json({ message: 'Voucher ativado com sucesso', duration_hours: voucher.duration_hours || 24 });
  } catch (err) {
    console.error('Erro portal voucher:', err.message);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Gerar PIX para pagamento
app.post('/api/portal/create-pix', async (req, res) => {
  try {
    const { user_id, plan_id, plan_name, amount, mac_address } = req.body;
    if (!plan_id || !amount) return res.status(400).json({ error: 'Plano e valor obrigatórios' });

    const mpAccessToken = process.env.MP_ACCESS_TOKEN;
    if (!mpAccessToken) return res.status(500).json({ error: 'Pagamento não configurado' });

    // Criar pagamento no Mercado Pago
    const mpRes = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${mpAccessToken}`,
        'X-Idempotency-Key': `${user_id || 'anon'}-${plan_id}-${Date.now()}`
      },
      body: JSON.stringify({
        transaction_amount: parseFloat(amount),
        description: `Hotspot - ${plan_name || 'Plano'}`,
        payment_method_id: 'pix',
        payer: { email: 'cliente@hotspot.local' }
      })
    });
    const mpPayment = await mpRes.json();

    if (!mpPayment.id) return res.status(500).json({ error: 'Erro ao gerar pagamento' });

    // Salvar no banco
    const { data: payment, error } = await supabase.from('payments').insert({
      user_id: user_id || null,
      plan_id,
      plan_name: plan_name || '',
      amount: parseFloat(amount),
      method: 'pix',
      status: 'pending',
      mercado_pago_id: String(mpPayment.id),
      pix_qr_code: mpPayment.point_of_interaction?.transaction_data?.qr_code || '',
      pix_qr_code_base64: mpPayment.point_of_interaction?.transaction_data?.qr_code_base64 || '',
      mac_address: mac_address || null,
      created_at: new Date().toISOString()
    }).select().single();

    if (error) throw error;

    res.json({
      payment_id: payment.id,
      mercado_pago_id: mpPayment.id,
      pix_copy_paste: mpPayment.point_of_interaction?.transaction_data?.qr_code || '',
      qr_code_base64: mpPayment.point_of_interaction?.transaction_data?.qr_code_base64 || '',
      status: 'pending'
    });
  } catch (err) {
    console.error('Erro portal create-pix:', err.message);
    res.status(500).json({ error: 'Erro ao gerar pagamento' });
  }
});

// Verificar status de pagamento
app.get('/api/portal/check-payment/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { data: payment, error } = await supabase.from('payments').select('*').eq('id', id).single();
    if (error || !payment) return res.status(404).json({ error: 'Pagamento não encontrado' });

    // Se ainda pendente, verificar no MP
    if (payment.status === 'pending' && payment.mercado_pago_id) {
      const mpAccessToken = process.env.MP_ACCESS_TOKEN;
      if (mpAccessToken) {
        try {
          const mpRes = await fetch(`https://api.mercadopago.com/v1/payments/${payment.mercado_pago_id}`, {
            headers: { 'Authorization': `Bearer ${mpAccessToken}` }
          });
          const mpPayment = await mpRes.json();
          if (mpPayment.status === 'approved' && payment.status !== 'approved') {
            await supabase.from('payments').update({
              status: 'approved', confirmed_at: new Date().toISOString(), updated_at: new Date().toISOString()
            }).eq('id', payment.id);

            // Ativar usuário
            if (payment.user_id && payment.plan_id) {
              const { data: plan } = await supabase.from('plans').select('*').eq('id', payment.plan_id).single();
              if (plan) {
                const expiresAt = new Date();
                expiresAt.setHours(expiresAt.getHours() + (plan.duration_hours || 24));
                await supabase.from('users').update({
                  status: 'active', plan_id: plan.id, plan_name: plan.name,
                  expires_at: expiresAt.toISOString(), updated_at: new Date().toISOString()
                }).eq('id', payment.user_id);
              }
            }
            return res.json({ status: 'approved' });
          }
        } catch (mpErr) { console.error('Erro ao verificar MP:', mpErr.message); }
      }
    }

    res.json({ status: payment.status });
  } catch (err) {
    console.error('Erro portal check-payment:', err.message);
    res.status(500).json({ error: 'Erro ao verificar pagamento' });
  }
});

// Status do usuário (portal)
app.get('/api/portal/status', async (req, res) => {
  try {
    const { mac, ip } = req.query;
    let user = null;

    if (mac) {
      const { data } = await supabase.from('users').select('*').eq('mac_address', mac).single();
      if (data) user = data;
    }

    if (!user) return res.json({ plan_name: '-', time_remaining: '-', speed: '-' });

    let timeRemaining = '-';
    if (user.expires_at) {
      const diff = new Date(user.expires_at) - new Date();
      if (diff > 0) {
        const hours = Math.floor(diff / 3600000);
        const mins = Math.floor((diff % 3600000) / 60000);
        timeRemaining = `${hours}h ${mins}min`;
      } else {
        timeRemaining = 'Expirado';
      }
    }

    res.json({
      plan_name: user.plan_name || '-',
      time_remaining: timeRemaining,
      speed: user.speed_limit || '-',
      status: user.status || 'inactive'
    });
  } catch (err) {
    console.error('Erro portal status:', err.message);
    res.status(500).json({ error: 'Erro ao buscar status' });
  }
});

// ============================================================
// INICIAR SERVIDOR
// ============================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor Hotspot System rodando na porta ${PORT}`);
  console.log(`Ambiente: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
