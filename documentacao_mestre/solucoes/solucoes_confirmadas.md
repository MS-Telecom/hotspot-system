# Solucoes confirmadas

## 2026-04-13 - Hotspot profile compatibilidade ROS 6.47.9

- Ajuste: remover `radius-interim-update` e `comment` do `/ip hotspot profile add`.
- Motivo: RouterOS 6.47.9 rejeita esses parametros no profile.
- Efeito: hotspot profile e hotspot sao criados sem erro; HTML e gravado no diretorio do profile.

## 2026-04-13 - Modal de detalhes resiliente

- Ajuste: `escapeHtml` converte qualquer valor para string antes de `replace`.
- Motivo: alguns campos do POP sao numericos/booleanos.
- Efeito: modal de detalhes abre sem erro.

## 2026-04-13 - Trunk VLAN UI por topologia

- Ajuste: esconder LAN/VLAN/Tipo de saida quando topologia=single e manter quando topologia=dual.
- Motivo: evitar confusao e inputs invalidos no modo "Uma porta".
- Efeito: tela consistente com o comportamento do backend.
