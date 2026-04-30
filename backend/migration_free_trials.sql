-- Desativar a segurança de nível de linha temporariamente para alterações de schema
ALTER TABLE public.free_trials DISABLE ROW LEVEL SECURITY;

-- Renomear colunas existentes para o novo padrão
ALTER TABLE public.free_trials RENAME COLUMN mac TO mac_address;
ALTER TABLE public.free_trials RENAME COLUMN last_trial TO last_used_at;

-- Adicionar as novas colunas que não existem
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS first_used_at TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS used_at TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS cooldown_until TIMESTAMPTZ;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS duration_seconds INT;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS cooldown_seconds INT;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS pop_id TEXT;
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;

-- Garantir que a coluna de tentativas exista e tenha um padrão
ALTER TABLE public.free_trials ADD COLUMN IF NOT EXISTS attempts INT DEFAULT 1;

-- Adicionar constraint UNIQUE na coluna mac_address se não existir
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint 
    WHERE conname = 'free_trials_mac_address_key' AND conrelid = 'public.free_trials'::regclass
  ) THEN
    ALTER TABLE public.free_trials ADD CONSTRAINT free_trials_mac_address_key UNIQUE (mac_address);
  END IF;
END;
$$;

-- Reativar a segurança de nível de linha
ALTER TABLE public.free_trials ENABLE ROW LEVEL SECURITY;

-- Comentários para documentação
COMMENT ON COLUMN public.free_trials.mac_address IS 'Endereço MAC do dispositivo (chave única).';
COMMENT ON COLUMN public.free_trials.first_used_at IS 'Timestamp do primeiro uso do teste grátis.';
COMMENT ON COLUMN public.free_trials.last_used_at IS 'Timestamp do último uso do teste grátis.';
COMMENT ON COLUMN public.free_trials.expires_at IS 'Timestamp de quando o acesso do teste grátis expira.';
COMMENT ON COLUMN public.free_trials.cooldown_until IS 'Timestamp de quando o cooldown termina e um novo teste pode ser usado.';
COMMENT ON COLUMN public.free_trials.duration_seconds IS 'Duração do teste grátis em segundos.';
COMMENT ON COLUMN public.free_trials.cooldown_seconds IS 'Duração do cooldown em segundos.';
COMMENT ON COLUMN public.free_trials.attempts IS 'Número de tentativas de uso do teste grátis.';

