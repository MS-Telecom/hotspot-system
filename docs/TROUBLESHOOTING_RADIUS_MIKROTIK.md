# Troubleshooting RADIUS, Hotspot e VPN Legacy MikroTik

Este documento registra os problemas reais encontrados em bancada no fluxo:

```text
Cliente Wi-Fi -> Portal -> API -> FreeRADIUS -> MikroTik Hotspot Active
```

A bancada usada para validar o fluxo foi o POP `MS-44AC67` / `MS-WiFi-POP-01`.

## Fluxo correto do teste gratis

1. Cliente conecta no SSID Hotspot.
2. MikroTik abre `login.html` local.
3. `login.html` redireciona para o portal com `mac`, `ip`, `hotspot`, `loginUrl`, `orig` e `error`.
4. Usuario clica em **Teste gratis**.
5. API grava autorizacao do MAC na tabela canonica RADIUS.
6. Portal redireciona o navegador para o login do MikroTik usando `username=MAC` e `password=MAC`.
7. MikroTik envia `Access-Request` para o FreeRADIUS.
8. FreeRADIUS consulta o banco e responde `Access-Accept`.
9. Cliente aparece em:

```mikrotik
/ip hotspot active print
```

10. Internet e liberada.

## Active vs Users no MikroTik

Quando a autenticacao vem do RADIUS, o cliente **nao precisa aparecer** em:

```mikrotik
/ip hotspot user print
```

A lista `Users` e a base local de usuarios do MikroTik. Para RADIUS, o comportamento esperado e aparecer em:

```mikrotik
/ip hotspot active print
```

Se aparecer em `Active` e navegar, a autenticacao RADIUS funcionou.

## Caso 1: MikroTik envia Access-Request, mas FreeRADIUS nao responde

### Sintomas

No MikroTik:

```text
RADIUS server is not responding
timeout
No route to host
```

Na VPS:

```bash
sudo tcpdump -ni any -vvv 'udp port 1812 or udp port 1813'
```

Nao aparece nenhum pacote.

### Causa

O pacote nao chegou ao processo FreeRADIUS. Pode ser:

- porta UDP 1812/1813 bloqueada no firewall da VPS;
- porta UDP 1812/1813 bloqueada na cloud/OCI;
- rota/WAN/NAT do MikroTik;
- FreeRADIUS parado ou sem escutar.

### Diagnostico

Na VPS:

```bash
sudo systemctl status freeradius --no-pager
sudo ss -lunp | grep -E ':1812|:1813'
sudo tcpdump -ni any -vvv 'udp port 1812 or udp port 1813'
sudo iptables -L INPUT -n --line-numbers
```

No MikroTik:

```mikrotik
/radius print detail
/ping <IP_PUBLICO_DA_VPS> count=5
/tool traceroute <IP_PUBLICO_DA_VPS>
```

### Correcao minima

Na VPS:

```bash
sudo iptables -C INPUT -p udp --dport 1812 -j ACCEPT 2>/dev/null || sudo iptables -I INPUT 1 -p udp --dport 1812 -j ACCEPT
sudo iptables -C INPUT -p udp --dport 1813 -j ACCEPT 2>/dev/null || sudo iptables -I INPUT 2 -p udp --dport 1813 -j ACCEPT
sudo netfilter-persistent save
sudo systemctl enable freeradius
sudo systemctl restart freeradius
```

Na OCI/Oracle, liberar tambem regras de ingress UDP para:

```text
1812 RADIUS auth
1813 RADIUS accounting
```

## Caso 2: Access-Request chega, usuario existe, mas da Access-Reject

### Sintomas

No `freeradius -X`:

```text
User found in radcheck/radius_replies
Cleartext-Password := "MAC"
pap: ERROR: Cleartext password does not match "known good" password
WARNING: Unprintable characters in the password. Double-check the shared secret on the server and the NAS!
Sent Access-Reject
```

### Causa

O `secret` configurado no MikroTik e diferente do `secret` configurado no FreeRADIUS para aquele client.

O FreeRADIUS usa o shared secret para decodificar `User-Password`. Se o secret estiver errado, a senha chega como bytes invalidos e o PAP falha.

### Diagnostico

Na VPS:

```bash
sudo systemctl stop freeradius
sudo pkill freeradius || true
sudo freeradius -X
```

No MikroTik:

```mikrotik
/radius print detail
```

Comparar:

```text
MikroTik /radius secret == FreeRADIUS client secret
```

### Correcao manual de bancada

Editar o client correspondente no FreeRADIUS para usar o mesmo `secret` do MikroTik, validar e reiniciar:

```bash
sudo freeradius -C
sudo systemctl restart freeradius
```

Resultado esperado no `freeradius -X`:

```text
User authenticated successfully
Sent Access-Accept
```

Depois o cliente deve aparecer em:

```mikrotik
/ip hotspot active print
```

## Caso 3: Accounting 1813 falha apos Access-Accept

### Sintomas

No MikroTik:

```text
sending Accounting-Request ... to <VPS>:1813
No route to host
RADIUS accounting request not sent: no response
```

### Causa

Autenticacao UDP 1812 funcionou, mas accounting UDP 1813 nao esta liberado, persistido ou respondendo.

### Correcao

Liberar e persistir UDP 1813:

```bash
sudo iptables -C INPUT -p udp --dport 1813 -j ACCEPT 2>/dev/null || sudo iptables -I INPUT 2 -p udp --dport 1813 -j ACCEPT
sudo netfilter-persistent save
sudo systemctl restart freeradius
```

Validar:

```bash
sudo tcpdump -ni any -vvv 'udp port 1812 or udp port 1813'
```

Esperado:

```text
Access-Request -> 1812
Access-Accept  <- 1812
Accounting-Request -> 1813
Accounting-Response <- 1813
```

## Caso 4: FreeRADIUS so volta depois de restart manual

### Sintoma

Apos reboot da VPS, o teste gratis falha. Ao executar:

```bash
sudo systemctl restart freeradius
sudo systemctl status freeradius --no-pager
```

volta a funcionar.

### Causas provaveis

- FreeRADIUS subindo antes da rede/SQL ficar disponivel;
- processo manual `freeradius -X` ou `freeradius` ficou fora do systemd;
- regras de firewall nao persistidas;
- arquivo de client/secret sobrescrito por sincronizacao incompleta.

### Correcao operacional

```bash
sudo pkill freeradius || true
sudo systemctl daemon-reload
sudo systemctl enable freeradius
sudo systemctl restart freeradius
sudo ss -lunp | grep -E ':1812|:1813'
```

Opcional: override para reiniciar automaticamente:

```bash
sudo systemctl edit freeradius
```

Conteudo:

```ini
[Unit]
Wants=network-online.target
After=network-online.target

[Service]
Restart=always
RestartSec=10
```

Aplicar:

```bash
sudo systemctl daemon-reload
sudo systemctl restart freeradius
```

## Caso 5: VPN L2TP/IPsec para RouterOS v6

### Por que usar L2TP/IPsec

WireGuard exige RouterOS v7. Para MikroTiks em RouterOS v6, o caminho de VPN legado validado em bancada e L2TP/IPsec.

A VPN e necessaria para que cada POP tenha um IP fixo interno e, assim, possa usar seu proprio `radius_secret` no FreeRADIUS.

Exemplo usado em bancada:

```text
VPS L2TP: 10.254.1.1
MS-44AC67: 10.254.1.11
```

### Portas necessarias na VPS e OCI

```text
UDP 500   IPsec IKE
UDP 4500  IPsec NAT-T
UDP 1701  L2TP
UDP 1812  RADIUS auth
UDP 1813  RADIUS accounting
```

Validar chegada dos pacotes:

```bash
sudo tcpdump -ni ens3 -vvv 'udp port 500 or udp port 4500 or udp port 1701'
```

### Etapa A: pacotes nao chegam na VPS

Se o MikroTik tenta conectar e o `tcpdump` nao mostra UDP 500/4500/1701, o bloqueio esta antes do Ubuntu, geralmente na OCI/Oracle Security List ou NSG.

Liberar ingress UDP 500, 4500 e 1701 no painel da Oracle.

### Etapa B: PSK errada

Sintomas no StrongSwan:

```text
invalid ID_V1 payload length, decryption failed?
could not decrypt payloads
message parsing failed
```

Causa: IPsec PSK diferente entre:

```text
VPS: /etc/ipsec.secrets
MikroTik: ipsec-secret
```

Formato na VPS:

```conf
: PSK "SUA_PSK"
```

No MikroTik:

```mikrotik
/interface l2tp-client set l2tp-ms-vps ipsec-secret="SUA_PSK"
```

### Etapa C: proposal ESP sem match

Sintoma:

```text
no matching proposal found, sending NO_PROPOSAL_CHOSEN
```

O MikroTik RouterOS v6 ofereceu:

```text
ESP:AES_CBC_256/HMAC_SHA1_96/MODP_1024
ESP:AES_CBC_192/HMAC_SHA1_96/MODP_1024
ESP:AES_CBC_128/HMAC_SHA1_96/MODP_1024
```

Correcao em `/etc/ipsec.conf`: usar `esp` compativel e nao `phase2alg` antigo.

Exemplo:

```conf
esp=aes256-sha1-modp1024,aes192-sha1-modp1024,aes128-sha1-modp1024!
```

Resultado esperado:

```text
IKE_SA L2TP-PSK established
CHILD_SA L2TP-PSK established
```

### Etapa D: xl2tpd nega peer

Sintoma:

```text
control_finish: Denied connection to unauthorized peer <IP>
Connection closed ... No Authorization
```

Causa: `xl2tpd` exigindo autenticacao de tunnel L2TP.

Em `/etc/xl2tpd/xl2tpd.conf`, usar:

```conf
require authentication = no
```

Config validada em bancada:

```conf
[global]
port = 1701

[lns default]
ip range = 10.254.1.10-10.254.1.200
local ip = 10.254.1.1
require chap = yes
refuse pap = yes
require authentication = no
name = ms-l2tp
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
```

### Etapa E: pppd aborta por opcao invalida

Sintoma:

```text
pppd: In file /etc/ppp/options.xl2tpd: unrecognized option 'crtscts'
xl2tpd: child_handler : pppd exited for call 1 with code 2
```

Causa: `crtscts` e opcao de controle de fluxo de porta serial fisica. Em L2TP/PPP virtual ela pode ser invalida e abortar o `pppd`.

Remover tambem opcoes legadas de serial como `lock` e `connect-delay`.

Conteudo final validado/sugerido para `/etc/ppp/options.xl2tpd`:

```conf
# Opcoes minimas para L2TP/IPsec com MikroTik RouterOS v6
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 1.1.1.1
noccp
auth
idle 1800
mtu 1400
mru 1400
nodefaultroute
proxyarp
silent
require-mschap-v2
require-mppe-128
```

### Validar conexao L2TP

Na VPS:

```bash
sudo journalctl -u strongswan-starter -u xl2tpd --since "5 minutes ago" --no-pager | tail -120
ip addr
```

No MikroTik:

```mikrotik
/interface l2tp-client print detail where name="l2tp-ms-vps"
/ip address print where interface=l2tp-ms-vps
/ping 10.254.1.1 count=5
```

Esperado:

```text
MikroTik conectado
VPS ve sessao PPP
POP recebe IP fixo da VPN, ex: 10.254.1.11
Ping para 10.254.1.1 responde
```

## RADIUS por VPN legacy

Depois que a VPN estiver conectada, o RADIUS do MikroTik deve apontar para o IP interno da VPS na VPN:

```mikrotik
/radius set [find service=hotspot] address=10.254.1.1 src-address=10.254.1.11 secret="SECRET_DO_POP" authentication-port=1812 accounting-port=1813 timeout=3s
```

E o FreeRADIUS deve cadastrar o client pelo IP fixo da VPN:

```conf
client ms_44ac67 {
    ipaddr = 10.254.1.11
    secret = SECRET_DO_POP
    shortname = MS-44AC67
    nastype = mikrotik
}
```

Assim cada POP pode usar `radius_secret` proprio sem depender de IP publico, Starlink, 4G ou CGNAT.

## Tabelas SQL canonicas

O backend deve gravar autorizacao RADIUS na tabela canonica:

```text
radius_replies
```

Nao usar `radcheck`/`radreply` como solucao final. Se existirem, devem ser tratados como legado/provisorio.

Check recomendado:

```sql
SELECT id, username, attribute, value, op
FROM radius_replies
WHERE username = %{SQL-User-Name}
  AND attribute = 'Cleartext-Password'
  AND status = 'active'
  AND (expires_at IS NULL OR expires_at > NOW());
```

Reply recomendado:

```sql
SELECT id, username, attribute, value, op
FROM radius_replies
WHERE username = %{SQL-User-Name}
  AND attribute <> 'Cleartext-Password'
  AND status = 'active'
  AND (expires_at IS NULL OR expires_at > NOW());
```

## Checklist final pos-reboot

Na VPS:

```bash
sudo systemctl status freeradius --no-pager
sudo systemctl status strongswan-starter --no-pager
sudo systemctl status xl2tpd --no-pager
sudo ss -lunp | grep -E ':500|:4500|:1701|:1812|:1813'
sudo iptables -L INPUT -n --line-numbers
```

No MikroTik:

```mikrotik
/interface l2tp-client print detail
/radius print detail
/ip hotspot active print
```

Teste funcional:

1. Conectar cliente no Wi-Fi.
2. Clicar **Teste gratis**.
3. Confirmar `Access-Accept` no FreeRADIUS.
4. Confirmar cliente em `/ip hotspot active print`.
5. Confirmar accounting UDP 1813 respondendo.
