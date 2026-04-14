# Solucoes confirmadas

## 2026-04-13 - Hotspot profile compatibilidade ROS 6.47.9

- Ajuste: remover `radius-interim-update` e `comment` do `/ip hotspot profile add`.
- Motivo: RouterOS 6.47.9 rejeita esses parametros no profile.
- Efeito: hotspot profile e hotspot sao criados sem erro; HTML e gravado no diretorio do profile.

## 2026-04-14 - Core do hotspot fechado na bridge

- Ajuste: `/ip dhcp-server add` sem `comment`, `/ip hotspot add` sempre na `ms-bridge-<ID>`, `login-by=http-chap,http-pap` e `html-directory="ms-<ID>"`.
- Motivo: manter compatibilidade com RouterOS 6.47.9 e coerencia da topologia (interface/VLAN entram na bridge; IP/DHCP/hotspot ficam na bridge).
- Efeito: o script deixa de montar apenas a base da rede e passa a fechar a instalacao do hotspot.

## 2026-04-14 - Redirecionamento do login para o portal externo

- Ajuste: `login.html` local passou a redirecionar para `portal.html` com `mac`, `ip`, `hotspot`, `loginUrl`, `orig` e `error`.
- Motivo: o hotspot precisa servir apenas a pagina local minima e entregar a interface completa no frontend.
- Efeito: o portal real pode ser carregado fora do HTML local do MikroTik.

## 2026-04-14 - Walled Garden ampliado para dependencias do portal

- Ajuste: inclusao dos hosts necessarios do portal, Vercel, API, fontes e dependencias externas.
- Motivo: evitar carregamento parcial do portal pelo hotspot.
- Efeito: o portal passou a abrir no ambiente real; em alguns testes ainda foi necessario ajuste manual complementar no MikroTik.

## 2026-04-14 - Operacao estabilizada com ajuste manual em campo

- Ajuste aplicado em campo: alteracao manual no MikroTik para fazer o POP aparecer online e exibir o portal corretamente.
- Motivo: o fluxo ainda nao estava totalmente fechado sem intervencao operacional.
- Efeito: ambiente operacional restabelecido.
- Observacao: registrar este passo como workaround temporario, nao como solucao definitiva de produto.

## 2026-04-13 - Modal de detalhes resiliente

- Ajuste: `escapeHtml` converte qualquer valor para string antes de `replace`.
- Motivo: alguns campos do POP sao numericos/booleanos.
- Efeito: modal de detalhes abre sem erro.

## 2026-04-13 - Trunk VLAN UI por topologia

- Ajuste: esconder LAN/VLAN/Tipo de saida quando topologia=single e manter quando topologia=dual.
- Motivo: evitar confusao e inputs invalidos no modo "Uma porta".
- Efeito: tela consistente com o comportamento do backend.
