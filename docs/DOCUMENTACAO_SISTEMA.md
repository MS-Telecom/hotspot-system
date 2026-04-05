# Documentação Completa do Sistema MS TELECOM Hotspot

Este documento detalha a arquitetura, infraestrutura, backend, banco de dados e frontend do sistema MS TELECOM Hotspot, construído para gerenciar provedores de internet via MikroTik.

---

## 1. Estrutura do Projeto

O projeto está organizado em um repositório centralizado no GitHub (`MS-Telecom/hotspot-system`), separando claramente o backend (Node.js) do frontend (HTML/JS estático).

### Árvore de Diretórios

```text
hotspot-system/
├── backend/
│   └── server.js           # Código-fonte único e completo da API Node.js
├── deploy/
│   ├── nginx.conf          # Configuração do proxy reverso Nginx
│   └── setup-vps.sh        # Script de instalação automatizada na VPS
├── docs/                   # Documentação do sistema
├── public/                 # Frontend estático (Páginas HTML, CSS, JS)
│   ├── index.html          # Landing page
│   ├── login.html          # Login administrativo
│   ├── dashboard.html      # Painel principal
│   ├── portal.html         # Captive portal para clientes finais
│   └── [outras 14 páginas] # CRUDs e relatórios
├── .env.example            # Template de variáveis de ambiente
├── package.json            # Dependências do backend Node.js
└── vercel.json             # Configuração de deploy do frontend na Vercel
```

### Distribuição dos Componentes

| Componente | Hospedagem | Descrição |
|------------|------------|-----------|
| **Código Fonte** | GitHub | Repositório privado `MS-Telecom/hotspot-system`. Contém todo o código. |
| **Backend (API)** | VPS Ubuntu | Roda o `server.js` via PM2, exposto via Nginx no domínio `mstelecom-api.duckdns.org`. |
| **Frontend** | Vercel | Hospeda a pasta `public/` no domínio `hotspot-system.vercel.app`. |
| **Banco de Dados** | Supabase | PostgreSQL gerenciado, contendo 17 tabelas. |

---

## 2. Deploy e Infraestrutura

A infraestrutura foi desenhada para ser resiliente e de fácil atualização, separando o frontend serverless do backend stateful.

### Frontend (Vercel)
O deploy do frontend é **100% automatizado** via integração nativa da Vercel com o GitHub.
- **Workflow**: Qualquer push para a branch `main` no GitHub aciona automaticamente um novo build na Vercel.
- **Configuração**: O arquivo `vercel.json` define a pasta `public` como diretório de saída (Output Directory) e configura headers de segurança (X-Frame-Options, X-Content-Type-Options).

### Backend (VPS)
O backend roda em uma VPS Ubuntu (IP: `40.233.118.238`) gerenciado pelo PM2.
- **Process Manager**: O PM2 mantém o processo Node.js rodando continuamente e o reinicia automaticamente em caso de falha ou reinicialização do servidor (via `pm2 startup systemd`).
- **Proxy Reverso**: O Nginx recebe as requisições HTTPS na porta 443 (com certificado Let's Encrypt) e repassa para o Node.js na porta 3000.

### Como atualizar o sistema após uma mudança

**Para o Frontend:**
Basta fazer o commit e push para o GitHub. A Vercel atualizará automaticamente em segundos.

**Para o Backend (VPS):**
Como o backend não usa GitHub Actions, a atualização é feita via SSH:
```bash
# 1. Acesse a VPS
ssh ubuntu@40.233.118.238

# 2. Vá para a pasta do projeto e puxe as novidades
cd /home/ubuntu/hotspot-system
git pull origin main

# 3. Instale novas dependências (se houver)
npm install --production

# 4. Reinicie o serviço
pm2 restart hotspot-system
```

---

## 3. Server.js (Backend)

O arquivo `backend/server.js` é o coração do sistema. Ele é uma API REST construída com Express.js, conectada ao Supabase e com integração direta ao MikroTik via API (`node-routeros`).

### Autenticação
- **Painel Admin**: Utiliza JWT (JSON Web Tokens). O login gera um token válido por 24h. Todas as rotas administrativas são protegidas pelo `authMiddleware` que valida este token.
- **Portal Público**: Rotas abertas ou protegidas por validação de MAC Address.
- **MikroTik**: A comunicação com os roteadores usa credenciais geradas dinamicamente e salvas no banco de dados.

### Integrações Externas
- **MikroTik**: Utiliza a biblioteca `node-routeros` para conectar aos roteadores via API (porta 8728). Permite criar usuários, liberar acesso (IP Binding bypass), bloquear e derrubar conexões ativas.
- **Mercado Pago**: Integração via Webhook (`/api/webhooks/mercadopago`) para receber notificações de pagamentos PIX aprovados e liberar o acesso do cliente automaticamente.

### Lista de Endpoints (71 rotas)

**Autenticação e Perfil**
- `POST /api/login` - Login administrativo
- `POST /api/logout` - Invalida sessão
- `PUT /api/update-profile` - Atualiza dados do admin logado

**Administradores**
- `GET / POST /api/admins` - Lista/Cria admins
- `DELETE /api/admins/:id` - Remove admin

**Usuários (Clientes)**
- `GET / POST /api/users` - Lista/Cria clientes
- `PUT / DELETE /api/users/:id` - Atualiza/Remove cliente
- `POST /api/users/:id/renew` - Renova plano manualmente
- `POST /api/users/:id/block` - Bloqueia acesso
- `POST /api/users/:id/unblock` - Desbloqueia acesso
- `POST /api/users/:id/vip` - Alterna status VIP

**Planos**
- `GET / POST /api/plans` - Lista/Cria planos
- `PUT / DELETE /api/plans/:id` - Atualiza/Remove plano
- `GET /api/plans/:id/details` - Detalhes e assinantes do plano

**Pagamentos e Financeiro**
- `GET / POST /api/payments` - Lista/Cria pagamentos
- `PUT / DELETE /api/payments/:id` - Atualiza/Remove pagamento
- `POST /api/create-payment` - Cria pagamento manual
- `POST /api/confirm-payment` - Confirma pagamento manualmente
- `POST /api/payments/generate-pix` - Gera PIX via Mercado Pago
- `GET /api/check-payment` - Verifica status por referência
- `GET /api/check-payment-by-mac` - Verifica pagamento por MAC

**Vouchers**
- `GET / POST /api/vouchers` - Lista/Cria vouchers
- `DELETE /api/vouchers/:id` - Remove voucher
- `POST /api/vouchers/validate` - Valida e consome voucher (Público)

**Campanhas e Webhooks**
- `GET / POST / PUT / DELETE /api/campaigns` - CRUD de campanhas
- `GET / POST / DELETE /api/webhooks` - CRUD de webhooks

**Hotspots e POPs (MikroTik)**
- `GET / POST / PUT / DELETE /api/hotspots` - CRUD de Hotspots
- `GET / POST / PUT / DELETE /api/pops` - CRUD de POPs
- `POST /api/pops/register` - Auto-registro de POP
- `GET /api/pops/:id/status` - Status detalhado do POP
- `POST /api/pops/:id/ping` - Heartbeat do MikroTik (Público)
- `POST /api/pop/identity` - Identificação do roteador (Público)
- `GET /api/pops/:id/script` - Gera script de instalação MikroTik
- `GET /api/pops/:id/revert-script` - Gera script de reversão MikroTik

**Portal Público (Captive Portal)**
- `GET /entrypoint` - Redirecionamento inicial do MikroTik
- `POST /api/validate-access` - Valida acesso (chamado pelo MikroTik)
- `GET /api/portal/plans` - Lista planos ativos
- `POST /api/portal/login` - Login do cliente final
- `POST /api/portal/register` - Cadastro de novo cliente
- `POST /api/portal/voucher` - Resgate de voucher
- `POST /api/portal/create-pix` - Inicia compra via PIX
- `GET /api/portal/check-payment/:id` - Polling de status do PIX
- `GET /api/portal/status` - Status da conexão atual
- `POST /api/free-trial` - Libera acesso cortesia (15 min)

**Configurações e Sistema**
- `GET / POST /api/settings` - Configurações genéricas
- `DELETE /api/settings/:key` - Remove configuração
- `GET / POST /api/settings/fields` - Campos de cadastro
- `GET / POST /api/settings/system` - Configurações do sistema
- `GET / POST /api/settings/payment` - Configurações de pagamento
- `POST /api/webhooks/mercadopago` - Recebe notificações do MP

**Estatísticas e Logs**
- `GET /api/stats` - Métricas gerais do dashboard
- `GET /api/stats/users-per-hour` - Gráfico de acessos
- `GET /api/stats/total-traffic` - Tráfego total
- `GET /api/stats/peak-bandwidth` - Pico de banda
- `GET /api/stats/comparison` - Faturamento por plano
- `GET /api/logs` - Logs do sistema
- `GET / POST /api/audit-logs` - Logs de auditoria
- `GET /api/access-releases` - Histórico de liberações
- `GET /api/health` - Health check da API

---

## 4. Supabase (Banco de Dados)

O banco de dados PostgreSQL hospedado no Supabase contém 17 tabelas. O Row Level Security (RLS) está **desabilitado** (`rowsecurity: false`) em todas as tabelas, pois a segurança e autorização são feitas inteiramente no backend Node.js.

### Lista de Tabelas

1. **`admins`**: Usuários do painel administrativo (id, username, password, role).
2. **`users`**: Clientes finais do provedor (id, username, password, mac_address, plan_id, status, expires_at).
3. **`plans`**: Planos de internet oferecidos (id, name, price, speed_mbps, duration_days).
4. **`payments`**: Histórico de transações e PIX (id, user_id, amount, status, mp_payment_id).
5. **`vouchers`**: Códigos pré-pagos de acesso (id, code, duration_hours, used).
6. **`hotspots`**: Locais físicos de acesso (id, name, unique_id, radius_secret).
7. **`pops`**: Pontos de Presença / Roteadores MikroTik (id, ip, status, last_seen_at, api_user, api_pass).
8. **`hotspot_sessions`**: Sessões ativas de clientes (id, user_id, mac_address, status).
9. **`mikrotik_credentials`**: Credenciais dinâmicas da API dos roteadores.
10. **`free_trials`**: Controle de uso do acesso cortesia por MAC Address (evita abusos).
11. **`campaigns`**: Campanhas de marketing e cupons.
12. **`webhooks`**: Configurações de webhooks de saída.
13. **`settings`**: Configurações dinâmicas do sistema (chave/valor JSON).
14. **`logs`**: Logs de sistema e erros.
15. **`audit_logs`**: Trilha de auditoria de ações dos administradores.
16. **`radius_replies`**: Respostas formatadas para o servidor RADIUS.
17. **`radreply`**: Tabela padrão do FreeRADIUS (compatibilidade legada).

---

## 5. Vercel (Frontend)

O frontend é composto inteiramente por arquivos HTML, CSS e JS estáticos, sem uso de frameworks reativos complexos, garantindo carregamento ultrarrápido.

- **Configuração**: O projeto na Vercel aponta para a pasta `public/` do repositório.
- **Páginas**: Todos os arquivos `.html` estão na raiz da pasta `public/`.
- **Redirecionamento MikroTik**: Funciona perfeitamente. O MikroTik redireciona o usuário não autenticado para a API (`/entrypoint`), que por sua vez redireciona para o Vercel (`/index.html?mac=...&ip=...&pop=...`), passando os parâmetros necessários via URL para que o portal saiba quem é o cliente e em qual roteador ele está conectado.

---

## 6. GitHub

O repositório `MS-Telecom/hotspot-system` é o ponto central de verdade do código.

- **Workflows**: Atualmente não há GitHub Actions configurados (`.github/workflows/` está vazio). O deploy para a Vercel é feito pela integração nativa da própria Vercel, não por Actions.
- **Secrets**: As variáveis de ambiente não estão no GitHub. Elas residem diretamente na Vercel (para o frontend, se necessário) e no arquivo `.env` da VPS (para o backend).

---

## 7. Comandos Úteis (VPS)

Todos os comandos abaixo devem ser executados via SSH na VPS (`ssh ubuntu@40.233.118.238`).

### Gerenciamento do Servidor (PM2)

**Ver status do backend:**
```bash
pm2 list
```

**Reiniciar o backend (após atualizações):**
```bash
pm2 restart hotspot-system
```

**Parar o backend:**
```bash
pm2 stop hotspot-system
```

**Ver logs em tempo real:**
```bash
pm2 logs hotspot-system
```

**Ver apenas logs de erro:**
```bash
pm2 logs hotspot-system --err
```

### Testes e Manutenção

**Testar se a API está respondendo localmente:**
```bash
curl http://localhost:3000/api/health
```

**Testar se a API está respondendo externamente (via Nginx):**
```bash
curl https://mstelecom-api.duckdns.org/api/health
```

**Verificar configuração do Nginx:**
```bash
sudo nginx -t
```

**Reiniciar Nginx:**
```bash
sudo systemctl restart nginx
```

**Fazer backup do banco de dados (Supabase):**
O backup do banco de dados deve ser feito diretamente pelo painel do Supabase (Project Settings > Database > Backups), pois é um serviço gerenciado. O código-fonte já está salvo no GitHub.
