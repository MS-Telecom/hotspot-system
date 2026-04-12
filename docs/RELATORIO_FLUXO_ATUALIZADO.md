# Relatorio de Analise do Fluxo do Sistema Hotspot MS Telecom (Atualizado)

Este documento foi derivado do arquivo:
`Relatorio de Analise do Fluxo do Sistema Hotspot MS Telecom.md` (gerado a partir de analises anteriores).

Objetivo: manter uma base unica e atualizada do fluxo do sistema, com pendencias e correcoes registradas.

## 1. Visao geral do fluxo (portal)

1. Conexao inicial:
   - Usuario conecta ao Wi-Fi do MikroTik e e redirecionado ao portal cativo.
   - Portal recebe parametros (ex: `mac`, `ip`, `pop`) via URL.
   - Portal identifica o MAC e exibe planos / login / cadastro / voucher.

2. Escolha de plano / pagamento:
   - Usuario escolhe plano.
   - PIX e gerado e exibido (QR + copia e cola).
   - Sistema acompanha confirmacao e libera acesso (tempo/velocidade conforme plano).

3. Teste gratis:
   - Usuario solicita teste.
   - Sistema libera por tempo configurado.
   - Ao expirar, acesso e revogado.

## 2. Backend (API) - pontos relevantes

- Rotas publicas do portal: `/api/portal/*`
- Rotas admin protegidas por JWT: `/api/*` (com `Authorization: Bearer <token>`)
- Integracao MikroTik/RADIUS: liberacao e revogacao de acesso.

## 3. Status das pendencias do relatorio original

### 3.1. IP real (proxy / 127.0.0.1)

- Problema (historico):
  - Logs/auditoria registravam `127.0.0.1` quando a API ficava atras de proxy reverso.
  - Sintoma: campo IP na auditoria mostrava `127.0.0.1` e nao o IP real do cliente.

- Solucao aplicada:
  - Ajuste de infraestrutura no Nginx para repassar headers:
    - `X-Real-IP`
    - `X-Forwarded-For`
    - `X-Forwarded-Proto`
  - Validacao: endpoint `/api/test-ip` passou a retornar `ip` real do cliente.

- Quando foi corrigido:
  - 12/04/2026 (infra na VPS).

### 3.2. Acesso a dominios antes de autenticar (Walled Garden)

- Status:
  - Pendente de consolidacao no script final do MikroTik.

- Observacao:
  - O Walled Garden precisa permitir acesso aos dominios necessarios para o portal e pagamento antes da autenticacao.

### 3.3. Reexibicao de cobranca PIX pendente (mesmo MAC)

- Status:
  - Pendente de validacao completa do fluxo no portal.

### 3.4. CRON de expiracao / cleanup de sessoes

- Status:
  - Pendente de validacao em ambiente real (confirmar revogacao no MikroTik/RADIUS para todos os tipos de sessao).

## 4. Checklist rapido de validacao

- [ ] Portal carrega planos: `GET /api/portal/plans`
- [ ] Portal gera PIX: `POST /api/portal/create-pix`
- [ ] Portal confere pagamento: `GET /api/portal/check-payment/:id`
- [ ] Teste IP: `GET /api/test-ip` retorna IP real
- [ ] Auditoria: novas acoes registram IP real (nao `127.0.0.1`)

## 5. Notas de manutencao

- Sempre registrar em "pendente / corrigido" com:
  - sintoma
  - causa
  - solucao
  - como testar
  - data

