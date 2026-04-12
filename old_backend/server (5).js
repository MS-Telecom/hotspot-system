const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const RouterOSAPI = require('node-routeros').RouterOSAPI;
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ms-telecom-secret-2024';
const BACKUP_DIR = path.join(__dirname, 'backups');

// Configuração Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

app.use(cors());
app.use(express.json());

// ============================================================
// 🛡️ MIDDLEWARES
// ============================================================

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
};

// ============================================================
// 📝 LOGS DE AUDITORIA (FUNÇÃO AUXILIAR)
// ============================================================

async function registerAuditLog(username, type, object, action, ip = '0.0.0.0', userAgent = 'N/A') {
  try {
    await supabase.from('audit_logs').insert([{
      username,
      type,
      object,
      action,
      ip_address: ip,
      user_agent: userAgent,
      created_at: new Date().toISOString()
    }]);
  } catch (err) {
    console.error('❌ Erro ao registrar log de auditoria:', err.message);
  }
}

// ============================================================
// 👤 AUTH & PROFILE
// ============================================================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const { data: admin, error } = await supabase.from('admins').select('*').eq('username', username).single();

    if (error || !admin) return res.status(401).json({ error: 'Credenciais inválidas' });

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    if (admin.password !== hashedPassword) return res.status(401).json({ error: 'Credenciais inválidas' });

    const token = jwt.sign({ id: admin.id, username: admin.username, role: admin.role }, JWT_SECRET, { expiresIn: '24h' });
    
    await registerAuditLog(username, 'login', 'sistema', 'Login realizado com sucesso', req.ip, req.headers['user-agent']);
    
    res.json({ token, user: { id: admin.id, username: admin.username, email: admin.email, role: admin.role } });
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const { username, email, senha_atual, nova_senha } = req.body;
    const { data: admin } = await supabase.from('admins').select('*').eq('id', req.user.id).single();

    if (nova_senha) {
      const currentHash = crypto.createHash('sha256').update(senha_atual).digest('hex');
      if (admin.password !== currentHash) return res.status(400).json({ error: 'Senha atual incorreta' });
      
      const newHash = crypto.createHash('sha256').update(nova_senha).digest('hex');
      await supabase.from('admins').update({ username, email, password: newHash }).eq('id', req.user.id);
    } else {
      await supabase.from('admins').update({ username, email }).eq('id', req.user.id);
    }

    await registerAuditLog(req.user.username, 'update', 'perfil', 'Perfil atualizado', req.ip, req.headers['user-agent']);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao atualizar perfil' });
  }
});

// ============================================================
// 📡 POPS / HOTSPOTS
// ============================================================

app.get('/api/pops', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('pops').select('*').order('name');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar POPs' });
  }
});

app.post('/api/pops', authMiddleware, async (req, res) => {
  try {
    const popData = { ...req.body, created_at: new Date().toISOString() };
    const { data, error } = await supabase.from('pops').insert([popData]).select();
    if (error) throw error;
    
    await registerAuditLog(req.user.username, 'create', 'pop', `Novo POP criado: ${popData.name}`, req.ip, req.headers['user-agent']);
    res.status(201).json(data[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao criar POP' });
  }
});

app.put('/api/pops/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase.from('pops').update(req.body).eq('id', id).select();
    if (error) throw error;
    res.json(data[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao atualizar POP' });
  }
});

app.delete('/api/pops/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase.from('pops').delete().eq('id', id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao deletar POP' });
  }
});

app.post('/api/pops/:id/heartbeat', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await supabase.from('pops').update({ updated_at: new Date().toISOString(), status: 'online' }).eq('id', id);
    res.sendStatus(200);
  } catch (err) {
    res.sendStatus(500);
  }
});

app.get('/api/pops/:id/script', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: pop } = await supabase.from('pops').select('*').eq('id', id).single();
    
    const script = `/tool fetch url="https://mstelecom-api.duckdns.org/api/pops/${id}/heartbeat" mode=https keep-result=no`;
    res.json({ script });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao gerar script' });
  }
});

// ============================================================
// 📊 ESTATÍSTICAS
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
      online_pops: 1
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar estatísticas' });
  }
});

app.get('/api/stats/users-per-hour', authMiddleware, async (req, res) => {
  try {
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const { data: sessions } = await supabase.from('hotspot_sessions').select('created_at').gte('created_at', last24h);

    const hourlyData = new Array(24).fill(0);
    const now = new Date();

    sessions?.forEach(session => {
      const sessionDate = new Date(session.created_at);
      const hourDiff = Math.floor((now - sessionDate) / (1000 * 60 * 60));
      if (hourDiff >= 0 && hourDiff < 24) {
        const hour = sessionDate.getHours();
        hourlyData[hour]++;
      }
    });

    res.json({ data: hourlyData });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar estatísticas por hora' });
  }
});

// ============================================================
// ⚙️ CONFIGURAÇÕES (SETTINGS)
// ============================================================

app.get('/api/settings/:key', authMiddleware, async (req, res) => {
  try {
    const { key } = req.params;
    const { data, error } = await supabase.from('settings').select('value').eq('key', key).maybeSingle();
    if (error) throw error;
    res.json(data?.value || {});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/settings/:key', authMiddleware, async (req, res) => {
  try {
    const { key } = req.params;
    const { error } = await supabase.from('settings').upsert({
      key,
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

app.get('/api/admins', authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from('admins').select('id, username, email, role, created_at');
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admins/create', authMiddleware, async (req, res) => {
  try {
    const { username, email, password, role = 'admin' } = req.body;
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    const { data, error } = await supabase.from('admins').insert([{ username, email, password: hashedPassword, role }]).select();
    if (error) throw error;
    res.status(201).json({ id: data[0].id, success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admins/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    if (id == req.user.id) return res.status(400).json({ error: 'Não é possível deletar o próprio administrador' });
    const { error } = await supabase.from('admins').delete().eq('id', id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// 💾 BACKUP
// ============================================================

app.get('/api/backups', authMiddleware, async (req, res) => {
  try {
    if (!fs.existsSync(BACKUP_DIR)) return res.json([]);
    const files = fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.json')).map(f => ({
      filename: f,
      size: fs.statSync(path.join(BACKUP_DIR, f)).size,
      created_at: fs.statSync(path.join(BACKUP_DIR, f)).birthtime
    })).sort((a, b) => b.created_at - a.created_at);
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/backup/create', authMiddleware, async (req, res) => {
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);
    const filename = `backup-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    const tables = ['users', 'plans', 'vouchers', 'payments', 'pops', 'admins', 'settings'];
    const backupData = {};
    for (const table of tables) {
      const { data } = await supabase.from(table).select('*');
      backupData[table] = data || [];
    }
    fs.writeFileSync(path.join(BACKUP_DIR, filename), JSON.stringify(backupData, null, 2));
    res.json({ success: true, filename });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao criar backup' });
  }
});

app.get('/api/backups/download/:filename', authMiddleware, (req, res) => {
  const filePath = path.join(BACKUP_DIR, req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Arquivo não encontrado' });
  res.download(filePath);
});

// ============================================================
// 🏥 HEALTH CHECK
// ============================================================

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', version: '4.0.0', timestamp: new Date().toISOString() });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor rodando em: http://localhost:${PORT}`);
});
