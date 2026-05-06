-- Schema migration for the official POP credentials model.
-- Apply in Supabase SQL editor (or via migrations pipeline).

-- POPs: source of truth for radius_secret (+ unique_id identifier).
ALTER TABLE public.pops
  ADD COLUMN IF NOT EXISTS unique_id text;

ALTER TABLE public.pops
  ADD COLUMN IF NOT EXISTS radius_secret text;

-- Optional (legacy/backward compatibility only; backend stores API creds in mikrotik_credentials):
ALTER TABLE public.pops
  ADD COLUMN IF NOT EXISTS api_user text;

ALTER TABLE public.pops
  ADD COLUMN IF NOT EXISTS api_pass text;

-- MikroTik credentials: source of truth for API user/pass per POP.
ALTER TABLE public.mikrotik_credentials
  ADD COLUMN IF NOT EXISTS pop_id text;

ALTER TABLE public.mikrotik_credentials
  ADD COLUMN IF NOT EXISTS pop_ip text;

ALTER TABLE public.mikrotik_credentials
  ADD COLUMN IF NOT EXISTS api_user text;

ALTER TABLE public.mikrotik_credentials
  ADD COLUMN IF NOT EXISTS api_pass text;

ALTER TABLE public.mikrotik_credentials
  ADD COLUMN IF NOT EXISTS last_seen_at timestamp with time zone;

ALTER TABLE public.mikrotik_credentials
  ADD COLUMN IF NOT EXISTS updated_at timestamp with time zone;
