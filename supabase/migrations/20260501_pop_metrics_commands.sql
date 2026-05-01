CREATE TABLE IF NOT EXISTS public.pop_metrics (
  id BIGSERIAL PRIMARY KEY,
  pop_id BIGINT,
  active_users INTEGER DEFAULT 0,
  rx_bytes BIGINT DEFAULT 0,
  tx_bytes BIGINT DEFAULT 0,
  total_bytes BIGINT DEFAULT 0,
  peak_bandwidth_mbps NUMERIC DEFAULT 0,
  uptime TEXT,
  identity TEXT,
  routeros_version TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pop_metrics_pop_created_at ON public.pop_metrics(pop_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pop_metrics_created_at ON public.pop_metrics(created_at DESC);

CREATE TABLE IF NOT EXISTS public.pop_commands (
  id BIGSERIAL PRIMARY KEY,
  pop_id BIGINT,
  command_type TEXT NOT NULL,
  payload JSONB DEFAULT '{}'::jsonb,
  status TEXT DEFAULT 'pending',
  attempts INTEGER DEFAULT 0,
  last_error TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  executed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_pop_commands_pop_status_created_at ON public.pop_commands(pop_id, status, created_at ASC);

ALTER TABLE public.users ADD COLUMN IF NOT EXISTS is_vip BOOLEAN DEFAULT FALSE;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS vip_since TIMESTAMPTZ;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS vip_notes TEXT;
