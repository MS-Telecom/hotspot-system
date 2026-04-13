# Problemas resolvidos

## 2026-04-13 - RouterOS 6.47.9: erro no hotspot profile

- Sintoma: `expected end of command` ao executar `/ip hotspot profile add`, seguido de falha no `/ip hotspot add` e ausencia de `login.html`/`alogin.html`.
- Causa: parametros incompativeis no RouterOS 6.47.9 dentro do `hotspot profile add`:
  - `radius-interim-update=10m` (sem aspas) ou `comment=` no profile.
- Solucao: remover `radius-interim-update` e `comment` do `/ip hotspot profile add`.
- Resultado: profile cria, hotspot cria e HTML eh gravado em `flash/ms-<ID>`.

## 2026-04-13 - Modal de detalhes do POP quebra no frontend

- Sintoma: console com `TypeError: str.replace is not a function` e modal "Erro ao carregar detalhes".
- Causa: `escapeHtml` assumia string e recebia numeros/valores nao string.
- Solucao: converter qualquer valor para string antes do `.replace`.
- Resultado: modal de detalhes abre mesmo com valores numericos/booleanos.

## 2026-04-13 - Campos do modo Trunk exibidos incorretamente

- Sintoma: campos LAN/VLAN/Tipo de saida apareciam no modo "Uma porta (trunk)".
- Causa: falta de regra de exibicao por topologia.
- Solucao: ocultar LAN/VLAN/Tipo de saida quando topologia=single e manter quando topologia=dual.
- Resultado: UI coerente com o fluxo de trunk.
