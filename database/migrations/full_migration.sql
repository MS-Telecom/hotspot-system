-- 1. Normalização da tabela free_trials
DO $$ 
BEGIN
    -- Renomear colunas se existirem no formato antigo
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='free_trials' AND column_name='mac') THEN
        ALTER TABLE public.free_trials RENAME COLUMN mac TO mac_address;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='free_trials' AND column_name='last_trial') THEN
        ALTER TABLE public.free_trials RENAME COLUMN last_trial TO last_used_at;
    END IF;
END $$;

ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS first_used_at TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS used_at TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS cooldown_until TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS duration_seconds INT;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS cooldown_seconds INT;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS pop_id TEXT;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS attempts INT DEFAULT 1;

-- Garantir UNIQUE no mac_address
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'free_trials_mac_address_key') THEN
        ALTER TABLE public.free_trials ADD CONSTRAINT free_trials_mac_address_key UNIQUE (mac_address);
    END IF;
END $$;

-- 2. Normalização da tabela users
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_mac_address_key') THEN
        ALTER TABLE public.users ADD CONSTRAINT users_mac_address_key UNIQUE (mac_address);
    END IF;
END $$;

-- 3. Normalização da tabela radius_replies
DO $$ 
BEGIN
    -- Remover constraint antiga se existir
    ALTER TABLE public.radius_replies DROP CONSTRAINT IF EXISTS radius_replies_username_key;
    -- Adicionar constraint composta
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'radius_replies_username_attribute_unique') THEN
        ALTER TABLE public.radius_replies ADD CONSTRAINT radius_replies_username_attribute_unique UNIQUE (username, attribute);
    END IF;
END $$;

-- 4. Índices na tabela hotspot_sessions
CREATE INDEX IF NOT EXISTS idx_hotspot_sessions_mac_status_expires ON public.hotspot_sessions (mac_address, status, expires_at);

-- 5. Garantir que a tabela logs e audit_logs existam com as colunas corretas
CREATE TABLE IF NOT EXISTS public.logs (
    id BIGSERIAL PRIMARY KEY,
    message TEXT,
    level TEXT,
    source TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.audit_logs (
    id BIGSERIAL PRIMARY KEY,
    admin_username TEXT,
    action TEXT,
    target_type TEXT,
    target_id TEXT,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
