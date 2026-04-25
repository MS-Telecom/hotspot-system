# Arquitetura RADIUS (global vs VPN)

## Por que nao da para escolher secret por NAS-Identifier

O FreeRADIUS precisa escolher o *client* (e portanto o shared secret) **antes** de descriptografar o pacote.
Essa escolha e feita pelo **IP de origem**.

Campos como `NAS-Identifier`, `Called-Station-Id`, `User-Name` e dominios (ex: `radius-default-domain`)
servem para auditoria/autorizacao logica **depois** que o pacote ja foi aceito e descriptografado.

Sem IP fixo por POP (Starlink/4G/CGNAT), nao existe como manter secret unico por POP via internet publica.

## Modos suportados

### 1) Modo global (sem VPN)

Uso: ambiente real com IP dinamico/CGNAT.

- `RADIUS_CLIENT_MODE=global`
- `RADIUS_GLOBAL_SECRET` definido
- MikroTik usa `RADIUS_GLOBAL_SECRET` no `/radius add`.
- FreeRADIUS usa um client catch-all (`0.0.0.0/0`) com o mesmo secret.

Vantagens:

- Funciona com Starlink/4G/CGNAT/IP dinamico.
- Nao depende de IP publico fixo.

Trade-off:

- Um unico secret para todos os NAS.

### 2) Modo VPN (por POP)

Uso: futuro com WireGuard/VPN e IP fixo do tunel por POP.

- `RADIUS_CLIENT_MODE=vpn`
- Cada POP precisa ter `vpn_ip` ou `radius_client_ip` (IP do tunel)
- Cada POP tem `radius_secret` individual
- Backend sincroniza clients em:
  - `/etc/freeradius/3.0/clients.d/ms-telecom-pops.conf`
  - include garantido em `/etc/freeradius/3.0/clients.conf`

Vantagens:

- Secret unico por POP.
- Melhor isolamento.

Requisito:

- IP fixo de tunel por POP (nao usar IP publico aleatorio).

