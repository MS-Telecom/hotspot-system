-- Hotspot canonical schema fixes.
-- Idempotent migration. Run manually in Supabase SQL editor; do not run automatically during deploy.

CREATE TABLE IF NOT EXISTS public.free_trials (
  id BIGSERIAL PRIMARY KEY,
  mac_address TEXT,
  first_used_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  cooldown_until TIMESTAMPTZ,
  duration_seconds INTEGER,
  cooldown_seconds INTEGER,
  attempts INTEGER DEFAULT 0,
  pop_id TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'free_trials' AND column_name = 'mac')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'free_trials' AND column_name = 'mac_address') THEN
    ALTER TABLE public.free_trials RENAME COLUMN mac TO mac_address;
  ELSIF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'free_trials' AND column_name = 'mac') THEN
    UPDATE public.free_trials SET mac_address = mac WHERE mac_address IS NULL AND mac IS NOT NULL;
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'free_trials' AND column_name = 'last_trial')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'free_trials' AND column_name = 'last_used_at') THEN
    ALTER TABLE public.free_trials RENAME COLUMN last_trial TO last_used_at;
  ELSIF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'free_trials' AND column_name = 'last_trial') THEN
    UPDATE public.free_trials SET last_used_at = last_trial WHERE last_used_at IS NULL AND last_trial IS NOT NULL;
  END IF;
END $$;

ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS mac_address TEXT;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS first_used_at TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS used_at TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS cooldown_until TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS duration_seconds INTEGER;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS cooldown_seconds INTEGER;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS attempts INTEGER DEFAULT 0;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS pop_id TEXT;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();
UPDATE public.free_trials SET mac_address = NULL WHERE mac_address = '';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'free_trials_mac_address_key')
     AND NOT EXISTS (
       SELECT mac_address FROM public.free_trials WHERE mac_address IS NOT NULL GROUP BY mac_address HAVING count(*) > 1
     ) THEN
    ALTER TABLE public.free_trials ADD CONSTRAINT free_trials_mac_address_key UNIQUE (mac_address);
  END IF;
END $$;

ALTER TABLE public.users ADD COLUMN IF NOT EXISTS mac_address TEXT;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS plan_name TEXT;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();
UPDATE public.users SET mac_address = NULL WHERE mac_address = '';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_mac_address_key')
     AND NOT EXISTS (
       SELECT mac_address FROM public.users WHERE mac_address IS NOT NULL AND mac_address <> '' GROUP BY mac_address HAVING count(*) > 1
     ) THEN
    ALTER TABLE public.users ADD CONSTRAINT users_mac_address_key UNIQUE (mac_address);
  END IF;
END $$;

ALTER TABLE public.radius_replies ADD COLUMN IF NOT EXISTS username TEXT;
ALTER TABLE public.radius_replies ADD COLUMN IF NOT EXISTS attribute TEXT;
ALTER TABLE public.radius_replies ADD COLUMN IF NOT EXISTS op TEXT DEFAULT ':=';
ALTER TABLE public.radius_replies ADD COLUMN IF NOT EXISTS value TEXT;
ALTER TABLE public.radius_replies ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';
ALTER TABLE public.radius_replies ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE public.radius_replies ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();

DO $$
BEGIN
  ALTER TABLE public.radius_replies DROP CONSTRAINT IF EXISTS radius_replies_username_key;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'radius_replies_username_attribute_unique')
     AND NOT EXISTS (
       SELECT username, attribute FROM public.radius_replies WHERE username IS NOT NULL AND attribute IS NOT NULL GROUP BY username, attribute HAVING count(*) > 1
     ) THEN
    ALTER TABLE public.radius_replies ADD CONSTRAINT radius_replies_username_attribute_unique UNIQUE (username, attribute);
  END IF;
END $$;

ALTER TABLE public.hotspot_sessions ADD COLUMN IF NOT EXISTS mac_address TEXT;
ALTER TABLE public.hotspot_sessions ADD COLUMN IF NOT EXISTS status TEXT;
ALTER TABLE public.hotspot_sessions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE public.hotspot_sessions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'hotspot_sessions' AND column_name = 'user_mac') THEN
    UPDATE public.hotspot_sessions SET mac_address = user_mac WHERE mac_address IS NULL AND user_mac IS NOT NULL;
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_hotspot_sessions_mac_status_expires ON public.hotspot_sessions (mac_address, status, expires_at);

CREATE TABLE IF NOT EXISTS public.logs (
  id BIGSERIAL PRIMARY KEY,
  level TEXT,
  source TEXT,
  message TEXT,
  details TEXT,
  ip TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE public.logs ADD COLUMN IF NOT EXISTS level TEXT;
ALTER TABLE public.logs ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE public.logs ADD COLUMN IF NOT EXISTS message TEXT;
ALTER TABLE public.logs ADD COLUMN IF NOT EXISTS details TEXT;
ALTER TABLE public.logs ADD COLUMN IF NOT EXISTS ip TEXT;
ALTER TABLE public.logs ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE public.logs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now();
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'logs' AND column_name = 'details' AND data_type <> 'text') THEN
    ALTER TABLE public.logs ALTER COLUMN details TYPE TEXT USING details::text;
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_logs_created_at ON public.logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_source_level ON public.logs (source, level);

CREATE TABLE IF NOT EXISTS public.audit_logs (
  id BIGSERIAL PRIMARY KEY,
  username TEXT,
  type TEXT,
  object TEXT,
  action TEXT,
  ip TEXT,
  user_agent TEXT,
  details TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS username TEXT;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS type TEXT;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS object TEXT;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS action TEXT;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS ip TEXT;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS details TEXT;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now();
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'audit_logs' AND column_name = 'admin_username') THEN
    UPDATE public.audit_logs SET username = COALESCE(username, admin_username);
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'audit_logs' AND column_name = 'target_type') THEN
    UPDATE public.audit_logs SET object = COALESCE(object, target_type);
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'audit_logs' AND column_name = 'ip_address') THEN
    UPDATE public.audit_logs SET ip = COALESCE(ip, ip_address);
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'audit_logs' AND column_name = 'details' AND data_type <> 'text') THEN
    ALTER TABLE public.audit_logs ALTER COLUMN details TYPE TEXT USING details::text;
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON public.audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_username_type ON public.audit_logs (username, type);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'settings_key_key')
     AND NOT EXISTS (SELECT key FROM public.settings GROUP BY key HAVING count(*) > 1) THEN
    ALTER TABLE public.settings ADD CONSTRAINT settings_key_key UNIQUE (key);
  END IF;
END $$;
