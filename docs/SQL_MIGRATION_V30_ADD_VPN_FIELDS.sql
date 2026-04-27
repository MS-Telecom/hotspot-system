-- Minimal, safe, idempotent migration for VPN legacy + RADIUS client IP fields.
-- Does not drop data and does not delete POPs.

ALTER TABLE public.pops ADD COLUMN IF NOT EXISTS vpn_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE public.pops ADD COLUMN IF NOT EXISTS vpn_ip TEXT;
ALTER TABLE public.pops ADD COLUMN IF NOT EXISTS vpn_type TEXT DEFAULT 'l2tp_ipsec';
ALTER TABLE public.pops ADD COLUMN IF NOT EXISTS vpn_username TEXT;
ALTER TABLE public.pops ADD COLUMN IF NOT EXISTS vpn_password TEXT;
ALTER TABLE public.pops ADD COLUMN IF NOT EXISTS radius_client_ip TEXT;

