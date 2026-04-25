# Troubleshooting RADIUS (MikroTik + FreeRADIUS)

## Sintoma comum

- O MikroTik envia `Access-Request` para o VPS.
- O FreeRADIUS recebe o pacote (aparece no `freeradius -X`).
- Mesmo assim o cliente **nao autentica** e **nao aparece** em:
  - `/ip hotspot active print`

Mensagens tipicas no FreeRADIUS:

- `Double-check the shared secret`
- `The shared secret is incorrect`
- `Cleartext password does not match` (quando o pacote foi descriptografado mas o usuario/senha nao bate)

## Causa mais comum

O *shared secret* do client configurado no FreeRADIUS esta diferente do secret configurado no MikroTik.

Importante: o FreeRADIUS escolhe o client/secret **pelo IP de origem** (antes de descriptografar `User-Password`).
Sem VPN (Starlink/4G/CGNAT/IP dinamico), nao da para depender de IP publico fixo por POP.

## Diagnostico rapido

No VPS:

```bash
sudo tcpdump -ni any -vvv 'udp port 1812 or udp port 1813'
sudo systemctl stop freeradius
sudo pkill freeradius || true
sudo freeradius -X
```

No MikroTik:

```mikrotik
/radius print detail
/ip hotspot active print
```

Se o FreeRADIUS mostrar aviso de shared secret, alinhe os secrets (ver abaixo).

## Solucao (modo sem VPN - recomendado)

Use **um secret global** para todos os POPs:

- `RADIUS_CLIENT_MODE=global`
- `RADIUS_GLOBAL_SECRET=<mesmo_secret_do_freeradius>`

FreeRADIUS (`/etc/freeradius/3.0/clients.conf`) deve ter um client catch-all:

```conf
client mikrotik_any {
  ipaddr = 0.0.0.0/0
  secret = RADIUS_GLOBAL_SECRET
  shortname = mikrotik
  nas_type = other
}
```

E o script gerado pelo painel deve conter:

```mikrotik
/radius add address=<RADIUS_SERVER_IP> secret=<RADIUS_GLOBAL_SECRET> service=hotspot ...
```

## Solucao (modo com VPN - futuro)

Use secret por POP (requer IP fixo do tunel):

- `RADIUS_CLIENT_MODE=vpn`
- Cada POP precisa ter `vpn_ip` ou `radius_client_ip` preenchido no banco.
- Cada POP precisa ter `radius_secret` persistido.

O backend sincroniza um arquivo separado:

- `/etc/freeradius/3.0/clients.d/ms-telecom-pops.conf`

E garante um include em:

- `/etc/freeradius/3.0/clients.conf`

Linha exata:

```conf
$INCLUDE /etc/freeradius/3.0/clients.d/ms-telecom-pops.conf
```

