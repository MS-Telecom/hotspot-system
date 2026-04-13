# DB Reconciliation (historico SQL vs Supabase atual)

Fonte schema atual: "C:\Users\Dell\Downloads\Supabase Snippet List User Tables in Schemas.csv"

## Tabelas public (colunas)

- admins: created_at, email, id, password, role, updated_at, username
- audit_logs: action, created_at, id, ip, object, type, updated_at, user_agent, username
- campaigns: coupon_code, created_at, description, ends_at, id, name, starts_at, status, updated_at
- free_trials: attempts, created_at, id, last_trial, mac, updated_at
- hotspot_sessions: access_granted, created_at, expires_at, id, mac_address, pop_id, pop_ip, status, updated_at, user_id
- logs: created_at, details, id, ip, level, message, source, user_agent
- mikrotik_credentials: api_pass, api_user, created_at, id, last_ping, last_seen_at, pop_id, pop_ip, pop_name, updated_at
- payments: amount, confirmed_at, created_at, description, expires_at, external_reference, id, mac_address, mercado_pago_id, method, mp_payment_id, payment_method, pix_copy_paste, pix_qr_code, pix_qr_code_base64, plan_id, plan_name, qr_code, status, updated_at, user_id, user_mac, user_name, webhook_payload
- plans: active, created_at, description, duration_days, id, name, price, speed_mbps, updated_at
- pops: api_pass, api_port, api_user, bandwidth_used, connected_users, created_at, existing_vlan, hotspot_type, id, installation_type, ip, lan_interface, last_identity_at, last_seen_at, location, name, physical_port, pppoe_pass, pppoe_user, radius_secret, real_name, static_gw, static_ip, static_mask, status, unique_id, updated_at, vlan_id, wan_interface, wan_type
- radius_replies: attribute, created_at, expires_at, id, op, plan_name, status, updated_at, username, value
- radreply: address, attribute, cpf, created_at, email, expires_at, id, is_vip, op, phone, plan, status, updated_at, username, value
- settings: category, created_at, id, key, updated_at, value
- users: address, cpf, created_at, email, expires_at, hotspot_id, id, is_vip, mac_address, name, password, phone, plan_id, plan_name, speed_limit, status, updated_at, username
- vouchers: amount, code, created_at, duration_hours, expires_at, id, mac_address, plan_name, status, updated_at, used, used_at, used_by
- webhooks: active, created_at, event, id, last_execution, method, name, target, total_events, updated_at, url

## Mapeamento de campos (legado -> atual)

- last_heartbeat -> pops.last_seen_at [MAPPED] (Use last_seen_at; no column last_heartbeat in current schema)
- last_seen -> pops.last_seen_at [MAPPED] (Renamed to last_seen_at)
- ultimo_ping -> pops.last_seen_at [MAPPED] (Renamed to last_seen_at)
- last_ping -> mikrotik_credentials.last_ping [EXISTS] (Already exists in mikrotik_credentials)
- users_connected -> pops.connected_users [MAPPED] (Renamed to connected_users (int))
- bandwidth -> pops.bandwidth_used [MAPPED] (Renamed/changed semantics (text))
- token -> (none) [MISSING_IN_POPs] (Not in current pops schema; may be stored in settings pop_config_* instead)
- radius_auth_port -> (none) [MISSING_IN_POPs] (Not in current pops schema; may be stored in settings pop_config_* instead)
- radius_acct_port -> (none) [MISSING_IN_POPs] (Not in current pops schema; may be stored in settings pop_config_* instead)
- session_time -> (none) [MISSING_IN_POPs] (Not in current pops schema; may be stored in settings pop_config_* instead)
- idle_timeout -> (none) [MISSING_IN_POPs] (Not in current pops schema; may be stored in settings pop_config_* instead)
- shared_users -> (none) [MISSING_IN_POPs] (Not in current pops schema; may be stored in settings pop_config_* instead)
- redirect_url -> (none) [MISSING_IN_POPs] (Not in current pops schema; may be stored in settings pop_config_* instead)
- mode -> (none) [MISSING_IN_POPs] (Not in current pops schema; may be stored in settings pop_config_* instead)

## Onde aparecem termos legados nos SQL do historico

### bandwidth
- C:\GitHub\historico\FASE2_SQL_COMMANDS (2).sql
- C:\GitHub\historico\FASE2_SQL_COMMANDS.sql

### last_seen
- C:\GitHub\historico\create-tables (2).sql
- C:\GitHub\historico\create-tables.sql

### token
- C:\GitHub\historico\database-schema (2).sql
- C:\GitHub\historico\database-schema.sql
- C:\GitHub\historico\database-schema-corrigido (2).sql
- C:\GitHub\historico\database-schema-corrigido.sql
- C:\GitHub\historico\database-update-fase1 (2).sql
- C:\GitHub\historico\database-update-fase1.sql
- C:\GitHub\historico\fix-pops-table.sql
- C:\GitHub\historico\schema.sql

### ultimo_ping
- C:\GitHub\historico\database-schema (2).sql
- C:\GitHub\historico\database-schema.sql
- C:\GitHub\historico\database-schema-corrigido (2).sql
- C:\GitHub\historico\database-schema-corrigido.sql

### updated_at
- C:\GitHub\historico\CRIAR_TABELAS_SUPABASE (2).sql
- C:\GitHub\historico\CRIAR_TABELAS_SUPABASE.sql
- C:\GitHub\historico\FASE2_SQL_COMMANDS (2).sql
- C:\GitHub\historico\FASE2_SQL_COMMANDS.sql
- C:\GitHub\historico\fix_tables.sql
- C:\GitHub\historico\MS-Telecom-Supabase-Tables.sql

