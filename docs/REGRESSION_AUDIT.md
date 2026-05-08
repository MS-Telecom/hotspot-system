# Regression Audit

Estado do repositório auditado em `985075b` com o trabalho atual de `public/portal.html` ainda modificado no workspace.

## 1. Resumo executivo

O projeto entrou em um padrão recorrente de regressões por substituição parcial de HTMLs e backend: ao corrigir uma área, handlers, helpers e regras de elegibilidade eram removidos em outra. Os pontos mais sensíveis hoje são:

- portal: pagamento, teste grátis, modal do PIX, polling, expiração e redirecionamento
- painel: normalização de métricas, status de clientes, modais e autoatualização
- backend: regras centrais de acesso, expiração, pagamento aprovado/expirado, revogação e RADIUS
- hotspots/POP: script MikroTik, heartbeat, walled garden, token, radius por POP

## 2. Funcionalidades que devem existir

- Portal carrega planos, teste grátis e cadastro sem travar
- PIX/mock gera pagamento, aprova automaticamente e libera acesso
- Já paguei só verifica pagamento específico iniciado
- Plano expirado não libera acesso
- Teste grátis segue fluxo próprio
- Dashboard mostra métricas, clientes ativos, últimos pagamentos e POPs consistentes
- Hotspots/POP gera script e modal sem quebrar login/token/RADIUS
- Logs gravam auditoria e eventos operacionais
- Backend normaliza pagamento, expiração, acesso e revogação

## 3. Funcionalidades confirmadas no HEAD

| Área | Confirmado no HEAD | Observação |
|---|---|---|
| Portal | modal de pagamento, polling, teste grátis, check-payment por ID | `985075b`, `472a68d`, `6a042c3`, `5da22d6`, `c97e0bf` |
| Painel | autoatualização do dashboard, normalização de dados | `dd8fd06`, `053bfd7` |
| Hotspots/POP | script público, radius secreto por POP, correções de token/walled garden | `830619a`, `a02cdfb`, `dbb4250`, `ea42fbf`, `7baf7da`, `838e651` |
| Backend | pagamentos, exclusão com revogação, UTF-8, CORS, ws/Supabase | `947a412`, `1510c99`, `4495013`, `76403d2`, `3202702`, `f28d17c` |
| Layout/HTML | menus padronizados e textos corrigidos | `a9f86ed`, `c3a13f8`, `1a0846a`, `1f607dd` |

## 4. Funcionalidades ausentes ou suspeitas de regressão

| Severidade | Área | Sintoma | Commit âncora bom | Possível commit de perda |
|---|---|---|---|---|
| CRÍTICA | Portal | handler de teste grátis desapareceu em alguns ajustes | `472a68d` | `985075b`, `c7bfbb8` |
| CRÍTICA | Portal | handler de cancelar pagamento desapareceu em ajustes do modal | `6a042c3`, `472a68d` | `985075b` |
| CRÍTICA | Portal | Já paguei chegou a liberar sem pagamento/ID | `5cb68f2`, `7bf28ba`, `c97e0bf` | `c7bfbb8`, `985075b` |
| ALTA | Portal | plano expirado voltou a ser tratado como ativo em alguns fluxos | `c97e0bf`, `6c1de9f`, `4495013` | `c7bfbb8`, `985075b` |
| ALTA | Portal | carregamento de planos travou em “Carregando planos...” | `6a042c3`, `74f0536` | `c7bfbb8` |
| ALTA | Painel | modal de detalhes sem `closePlanDetailsModal` | `053bfd7`, `dd8fd06` | `c7bfbb8` |
| ALTA | Dashboard/Financeiro | métricas e clientes ativos ficaram inconsistentes após aprovação | `053bfd7`, `6c1de9f` | `c7bfbb8`, `985075b` |
| ALTA | Backend | pagamento approved/pending/expired misturou regra de acesso | `c97e0bf`, `6c1de9f`, `4495013` | `985075b`, `c7bfbb8` |
| MÉDIA | Logs | telas de logs e auditoria foram revertidas em parte | `9bd4d6b`, `60f0b6c`, `30269cc` | `3aed29a`, `a091cf0` |
| ALTA | Hotspots | token/login/walled garden/script POP já quebraram por refatoração | `012d6cc`, `62c8735`, `830619a`, `a02cdfb` | vários ajustes no bloco `server.js` e HTMLs do POP |

## 5. Commits âncora e leitura funcional

### Portal / pagamento / teste grátis

- `3ad5751` — portal dinâmico e configuração de teste grátis
- `1bdc8ee` — UX do cadastro no portal
- `9505e69` — melhorias do cadastro inicial
- `5da22d6` — fluxo mock do PIX
- `c97e0bf` — aprovação do mock reconhecida
- `472a68d` — teste grátis e elegibilidade restaurados
- `6a042c3` — lista de planos restaurada
- `985075b` — modal do pagamento

### Dashboard / financeiro / painel

- `94389ea` — merge old functionalities into new design
- `74ac0e6` — merge remaining pages
- `955c15f` — financeiro com PIX e CSV
- `dd8fd06` — dashboard autoatualizado
- `053bfd7` — normalização de dados do painel
- `c3a13f8` — HTMLs corrigidos e frontend padronizado

### Logs

- `9bd4d6b` — logs do sistema restaurados
- `60f0b6c` — conflito de merge em logs
- `30269cc` — endpoint de free-trial e logs
- `3aed29a` / `a091cf0` — reverts

### Hotspots / POP / MikroTik

- `012d6cc` — hotspot core compatível com Quark
- `62c8735` — modais de detalhes e script
- `41677d7` — pop config endpoint
- `ea03033` — trunk guidance
- `09365ad` — trunk mode topology
- `dbb4250` — preserva token no heartbeat
- `ea42fbf` — walled garden não quebra script
- `7baf7da` — ms commands no script
- `838e651` — escapes do script
- `54d0484` — login HTML do POP
- `830619a` — radius público no script
- `a02cdfb` — radius secret próprio no POP

### Backend / RADIUS / pagamento

- `5623db3` — RADIUS rate-limit, cleanup, auto-hash, sync
- `08bb75e` — rotas essenciais, webhook, stats
- `02c46f9` — rotas backend e consistência portal
- `5f5094e` — backend server corrigido
- `947a412` — fluxo PIX finalizado
- `1510c99` — matchedUser corrigido
- `6c1de9f` — consistência pós-pagamento e duração de planos
- `4495013` — revogação ao excluir cliente

## 6. Estratégia de restauração segura

1. Portal: restaurar handlers perdidos sem tocar no modal.
2. Portal: separar claramente teste grátis, pagamento e status de acesso.
3. Backend: centralizar helpers de pagamento/expiração/acesso.
4. Dashboard/financeiro: normalizar status e contadores em uma única fonte.
5. Hotspots/POP: tratar script e login como artefatos protegidos.
6. Logs: validar rota, fonte e leitura antes de mexer no visual.

## 7. Checklist de teste por módulo

### Portal

- planos carregam
- teste grátis aparece quando elegível
- modal do PIX abre
- copiar PIX funciona
- cancelar fecha modal
- Já paguei sem PIX não libera
- mock aprovado redireciona
- plano expirado não libera

### Painel

- métricas atualizam
- últimos pagamentos aparecem
- clientes ativos batem com sessões
- modal de plano fecha sem erro

### Backend

- pagamento pendente não libera
- pagamento aprovado libera
- expired/cancelled não libera
- exclusão revoga acesso

### Hotspots/POP

- script gera sem quebrar login
- token do heartbeat preservado
- walled garden não quebra o script

### Logs

- rota retorna dados
- auditoria grava eventos
- tela exibe registros

## 8. Próximos pontos de atenção

- Não aceitar correção que remova handler existente sem substituição equivalente.
- Não misturar acesso temporário com plano pago.
- Não tratar `allowed=true` como prova de pagamento sem `reason` confiável.
- Não reintroduzir scroll forçado no portal.
