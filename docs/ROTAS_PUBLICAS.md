# Rotas Publicas do Portal

Este documento descreve as rotas publicas usadas pelo `public/portal.html`.

## GET `/api/public/plans`

- Retorna os planos ativos (`active = true`) ordenados por preco.
- Uso no portal:
  - Renderizacao dinamica dos cards de plano.
  - Remove dependencia de planos hardcoded no HTML.
- Retorno esperado: array de objetos de plano.

## GET `/api/public/free-trial-config`

- Retorna a configuracao de teste gratis salva em `settings.key = free_trial`.
- Fallback padrao:
  - `enabled: false`
  - `duration_minutes: 15`
  - `cooldown_hours: 24`
- Uso no portal:
  - Se `enabled = false`, esconder botoes de teste gratis.
  - Se `enabled = true`, exibir botoes com duracao dinamica.

## Comportamento dinamico do portal

Com as rotas acima:

1. O portal mostra somente os planos cadastrados no painel.
2. O teste gratis aparece/some conforme configuracao do painel.
3. Nao ha valores fixos de planos ou duracao no fluxo principal.
