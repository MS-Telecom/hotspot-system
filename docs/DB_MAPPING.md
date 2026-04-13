# Mapeamento Definitivo de Banco (Legado -> Atual)

Este documento padroniza os nomes usados no banco atual (Supabase) e mostra como tabelas/colunas antigas se traduzem hoje, evitando duplicar colunas com o mesmo significado.

Fonte do schema atual: `C:\Users\Dell\Downloads\Supabase Snippet List User Tables in Schemas.csv`

## Tabelas (legado -> atual)

- clients -> users
- sessions -> hotspot_sessions
- acessos_hotspot -> hotspot_sessions (conceito) / radius_replies+radreply (controle)
- hotspots -> pops
- planos -> plans
- pagamentos -> payments
- configuracoes/configuracoes_* -> settings (jsonb)
- logs_auditoria -> audit_logs
- logs_sistema -> logs
- comando_queue -> (nao existe; substituido por chamadas diretas API/RADIUS + logs)

## POPs / Hotspots (public.pops)

- last_heartbeat / last_seen / ultimo_ping / ultimo_ping -> pops.last_seen_at
- users_connected -> pops.connected_users
- bandwidth -> pops.bandwidth_used (texto)
- ip_publico / pop_ip -> pops.ip
- nome -> pops.name
- atualizado_em -> pops.updated_at
- criado_em -> pops.created_at

Campos de instalacao (ja existem na tabela pops):
- installation_type, wan_interface, lan_interface, vlan_id, wan_type, hotspot_type, existing_vlan, physical_port
- pppoe_user, pppoe_pass, static_ip, static_mask, static_gw

## Usuarios (public.users)

- clients.mac -> users.mac_address
- clients.nome -> users.name
- clients.telefone -> users.phone
- clients.cpf -> users.cpf
- data_expiracao / expira_em -> users.expires_at

## Sessoes (public.hotspot_sessions)

- sessions.mac -> hotspot_sessions.mac_address
- sessions.pop_id -> hotspot_sessions.pop_id
- sessions.start_time -> hotspot_sessions.created_at
- sessions.end_time -> hotspot_sessions.expires_at (quando finalizado)
- status -> hotspot_sessions.status

## Pagamentos (public.payments)

- valor -> payments.amount
- plano -> payments.plan_name / plan_id
- status -> payments.status
- payment_id / mercado_pago_id -> payments.mercado_pago_id / mp_payment_id
- mac -> payments.mac_address / user_mac

## Configuracoes (public.settings)

- settings.chave/valor (texto) -> settings.key + settings.value (jsonb)
- configuracoes/campos -> settings (ex.: key='fields', category='general')

## Logs

- logs-auditoria -> audit_logs
- logs-sistema -> logs
