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