# Arquitetura RADIUS com VPN (RouterOS v6 - legacy)

## Objetivo

Permitir **radius_secret individual por POP** sem depender de IP publico (Starlink/4G/CGNAT/IP dinamico),
usando uma VPN compatível com RouterOS v6 (L2TP/IPsec ou SSTP).

## Por que IP publico nao serve

O FreeRADIUS seleciona o *client* (e o shared secret) pelo **IP de origem** do pacote.
Com IP dinamico/CGNAT, o IP publico nao e uma identidade confiavel para o POP.

## Modo de producao (recomendado)

Use:

- `RADIUS_CLIENT_MODE=vpn_legacy`

Requisitos por POP (tabela `pops`):

- `vpn_enabled=true`
- `vpn_ip` (IP fixo do tunel, ex: `10.250.0.11`)
- `vpn_type` (`l2tp_ipsec` ou `sstp`)
- `vpn_username`
- `vpn_password`
- `radius_secret` (individual por POP)
- `unique_id`

Variaveis no backend:

- `VPN_PUBLIC_ENDPOINT` (IP/DNS publico do concentrador)
- `VPN_INTERNAL_RADIUS_IP` (IP interno do concentrador, ex: `10.250.0.1`)
- `VPN_L2TP_IPSEC_PSK` (somente para `vpn_type=l2tp_ipsec`)

## FreeRADIUS (clients por POP)

Arquivo gerado:

- `/etc/freeradius/3.0/clients.d/ms-telecom-pops.conf`

Cada POP vira:

```conf
client ms_POPID {
  ipaddr = <vpn_ip>
  secret = <radius_secret>
  shortname = <unique_id>
  nastype = mikrotik
}
```

Include necessário em:

- `/etc/freeradius/3.0/clients.conf`

Linha literal:

```conf
$INCLUDE /etc/freeradius/3.0/clients.d/ms-telecom-pops.conf
```

## Script MikroTik (RouterOS v6)

Quando `vpn_enabled=true`, o script:

- cria o túnel L2TP/IPsec (ou SSTP)
- aponta o RADIUS para `VPN_INTERNAL_RADIUS_IP`
- configura `src-address=<vpn_ip>` no RADIUS

Assim o FreeRADIUS sempre enxerga o POP pelo IP fixo do túnel.

## Portas

- UDP 1812 (auth)
- UDP 1813 (accounting)
- Porta da VPN (conforme tipo):
  - L2TP/IPsec: UDP 500, UDP 4500, UDP 1701
  - SSTP: TCP 443 (ou porta configurada)

