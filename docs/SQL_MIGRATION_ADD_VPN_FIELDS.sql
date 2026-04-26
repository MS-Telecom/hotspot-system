-- Safe migration: add legacy VPN + RADIUS fields for RouterOS v6 production mode.
-- Do not drop data; do not delete POPs.

ALTER TABLE IF EXISTS pops
  ADD COLUMN IF NOT EXISTS unique_id text,
  ADD COLUMN IF NOT EXISTS radius_secret text,
  ADD COLUMN IF NOT EXISTS vpn_ip inet,
  ADD COLUMN IF NOT EXISTS vpn_type text,
  ADD COLUMN IF NOT EXISTS vpn_username text,
  ADD COLUMN IF NOT EXISTS vpn_password text,
  ADD COLUMN IF NOT EXISTS vpn_enabled boolean DEFAULT false,
  ADD COLUMN IF NOT EXISTS updated_at timestamptz;

