# Problemas resolvidos

## 2026-04-13 - RouterOS 6.47.9: erro no hotspot profile

- Sintoma: `expected end of command` ao executar `/ip hotspot profile add`, seguido de falha no `/ip hotspot add` e ausencia de `login.html`/`alogin.html`.
- Causa: parametros incompativeis no RouterOS 6.47.9 dentro do `hotspot profile add`:
  - `radius-interim-update=10m` (sem aspas) ou `comment=` no profile.
- Solucao: remover `radius-interim-update` e `comment` do `/ip hotspot profile add`.
- Resultado: profile cria, hotspot cria e HTML eh gravado em `flash/ms-<ID>`.

## 2026-04-14 - Script gerado montava rede parcial, mas nao fechava o hotspot

- Sintoma: script concluia com mensagem final, mas no MikroTik nao apareciam `dhcp-server`, `hotspot`, `login.html` e `alogin.html`.
- Causa:
  - `/ip dhcp-server add` com `comment=` em RouterOS 6.47.9;
  - hotspot fora da bridge em geracoes antigas;
  - `login-by=http-chap,http-pap,http-cookie` quebrando compatibilidade;
  - fluxo de HTML frágil, dependente de etapas anteriores que ja tinham falhado.
- Solucao:
  - remover `comment` do `/ip dhcp-server add`;
  - fixar `/ip hotspot add` na `ms-bridge-<ID>`;
  - usar `login-by=http-chap,http-pap`;
  - usar `html-directory="ms-<ID>"`;
  - regravar `login.html`/`alogin.html` no diretório do hotspot.
- Resultado: hotspot sobe com IP/DHCP/Hotspot na bridge, arquivos HTML sao criados e o portal passa a abrir.

## 2026-04-14 - Portal aparecia local/feio no redirecionamento do hotspot

- Sintoma: o portal real na Vercel abria completo no navegador, mas no acesso via hotspot aparecia sem CSS/JS ou com renderizacao parcial.
- Causa: combinacao de fluxo local do `login.html` com dependencias externas nem sempre liberadas pelo walled garden.
- Solucao:
  - `login.html` passou a redirecionar para `portal.html` com parametros do MikroTik;
  - ampliacao dos hosts do walled garden para o portal e dependencias necessarias.
- Resultado: o portal passou a abrir pelo hotspot. Em campo, ainda houve ajuste operacional manual no MikroTik para estabilizar o fluxo.

## 2026-04-14 - Heartbeat/online exigiu ajuste operacional em campo

- Sintoma: POP nao aparecia online de forma consistente durante os testes.
- Causa: fluxo de heartbeat/portal ainda dependente de ajuste operacional no MikroTik em alguns cenarios reais.
- Solucao aplicada em campo: ajuste manual no MikroTik para restabelecer o heartbeat e a exibicao do portal.
- Status: operacional no ambiente testado, mas ainda deve ser tratado como pendencia para eliminacao definitiva do ajuste manual.

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
