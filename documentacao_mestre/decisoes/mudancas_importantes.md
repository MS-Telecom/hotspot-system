# Mudancas importantes

## 2026-04-13

- Hotspot profile: removidos `comment` e `radius-interim-update` para compatibilidade com RouterOS 6.47.9.
- Frontend: modal de detalhes agora tolera valores nao string.
- Frontend: modo "MikroTik Secundario (Trunk VLAN)" esconde campos LAN/VLAN/Tipo de saida quando topologia=single.

## 2026-04-14

- O core do hotspot passa a seguir a regra fixa: interface/VLAN escolhida entram na bridge; IP, DHCP e hotspot ficam sempre na `ms-bridge-<ID>`.
- O `login.html` local do MikroTik fica reduzido ao papel de redirecionar para o `portal.html` externo com parametros nativos do hotspot.
- O `html-directory` do hotspot deixa de ser generico e passa a ser proprio por POP (`ms-<ID>`).
- O ambiente de campo ficou operacional apos ajuste manual no MikroTik para heartbeat/portal; isso deve permanecer documentado como workaround temporario ate virar correcao definitiva no fluxo.
