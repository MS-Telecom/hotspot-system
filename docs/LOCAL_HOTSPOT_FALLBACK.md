# Local Hotspot Fallback (cache de usuarios no MikroTik)

## Objetivo

RADIUS e o caminho principal. Este fallback cria um **cache local de usuarios do Hotspot** dentro do MikroTik para manter operacao mesmo quando:

- FreeRADIUS estiver fora do ar
- VPN (modo futuro) estiver fora do ar
- API MikroTik estiver indisponivel

## Como funciona

1) O backend expõe um endpoint publico protegido por **token por POP**:

- `GET /api/mikrotik/local-users.rsc?pop=<POP_ID>&token=<TOKEN>`

2) O MikroTik executa um scheduler periodico:

- baixa o `.rsc` via `/tool fetch`
- importa via `/import`
- cria/atualiza usuarios locais:
  - `username = MAC`
  - `password = MAC`
  - `comment = MS-TELECOM-LOCAL-CACHE`

## Seguranca

- Token individual por POP (`pops.local_sync_token`).
- Endpoint nao usa JWT (chamado pelo MikroTik).
- Nao depende de IP publico (Starlink/4G/CGNAT suportado).

## Remocao segura (prune)

Por padrao, **nao remove** nenhum usuario:

- `LOCAL_CACHE_PRUNE=false`

Se ativar:

- remove apenas usuarios com `comment = MS-TELECOM-LOCAL-CACHE` que nao estao mais na lista ativa.
- nunca remove usuarios manuais sem esse comment.

## Escopo (roaming)

- `LOCAL_CACHE_SCOPE=global` (padrao): replica todos os clientes ativos para todos os POPs (roaming total).
- `LOCAL_CACHE_SCOPE=pop`: cada POP recebe apenas clientes com sessoes ativas naquele POP.
- `LOCAL_CACHE_SCOPE=group`: replica por grupo/regiao (usa `LOCAL_CACHE_GROUP_FIELD` se existir em `pops`).

## Como aplicar em POP ja instalado

No painel/API:

- `GET /api/pops/:id/local-sync-script` (auth)

Copie o snippet retornado e cole no MikroTik.

