-- DB MIGRATION (SUGERIDA) - somente colunas realmente necessarias
-- Execute no Supabase SQL Editor.

-- 1) POPs: (opcional) garantir campos de sessao/controle se voce decidir persistir no pops em vez de settings
-- OBS: hoje esses campos estao indo para settings key=pop_config_<id>.
-- ALTER TABLE public.pops ADD COLUMN IF NOT EXISTS session_time integer;
-- ALTER TABLE public.pops ADD COLUMN IF NOT EXISTS idle_timeout integer;
-- ALTER TABLE public.pops ADD COLUMN IF NOT EXISTS shared_users integer;
-- ALTER TABLE public.pops ADD COLUMN IF NOT EXISTS redirect_url text;
-- ALTER TABLE public.pops ADD COLUMN IF NOT EXISTS mode text;

-- 2) POPs: (nao recomendado) last_heartbeat (nao necessario; use last_seen_at)
-- ALTER TABLE public.pops ADD COLUMN IF NOT EXISTS last_heartbeat timestamptz;

-- 3) Hotspot Sessions: (opcional) armazenar ip do cliente (se quiser auditoria por sessao)
-- ALTER TABLE public.hotspot_sessions ADD COLUMN IF NOT EXISTS client_ip text;

