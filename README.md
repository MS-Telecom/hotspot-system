# MS TELECOM - Hotspot System v2.0

Sistema completo de gerenciamento de provedores de internet via MikroTik, com portal cativo, controle de planos, integração de pagamentos PIX (Mercado Pago) e controle de banda via RADIUS.

## 🏗️ Arquitetura do Sistema

O sistema é dividido em três camadas principais:

1. **Frontend (Vercel)**: Aplicação estática (HTML/JS/Tailwind) hospedada na Vercel.
2. **Backend (VPS)**: API Node.js/Express rodando em uma VPS Ubuntu via PM2.
3. **Banco de Dados (Supabase)**: PostgreSQL gerenciado com 17 tabelas.

### Fluxo de Funcionamento (Hotspot)

1. O cliente conecta no Wi-Fi do MikroTik.
2. O MikroTik serve o `login.html` local do hotspot.
3. O `login.html` redireciona para o portal externo na Vercel (`portal.html`) com parâmetros do MikroTik (`mac`, `ip`, `hotspot`, `loginUrl`, `orig`, `error`).
4. O cliente escolhe um plano e paga via PIX (Mercado Pago).
5. O Webhook do Mercado Pago avisa a API.
6. A API ativa o usuário e insere as regras de velocidade (`Mikrotik-Rate-Limit`) na tabela `radreply`.
7. O cliente navega com a velocidade contratada.
8. O CRON da API monitora a expiração e remove o acesso automaticamente.

## 🚀 Deploy e Infraestrutura

### Frontend (Vercel)
- **Domínio**: `hotspot-system.vercel.app`
- **Deploy**: Automático via GitHub (qualquer push na branch `main` atualiza o site).
- **Diretório**: `/public`

### Backend (VPS)
- **IP**: `40.233.118.238`
- **Domínio API**: `mstelecom-api.duckdns.org`
- **Deploy**: Automático via GitHub Actions (`.github/workflows/deploy.yml`).
- **Gerenciador**: PM2 (`pm2 status hotspot-system`)

## 🗄️ Estrutura do Banco de Dados (Supabase)

O banco de dados possui 17 tabelas, todas com nomes e colunas em inglês:

- `admins`: Usuários do painel administrativo.
- `users`: Clientes finais do provedor.
- `plans`: Planos de internet (`duration_days`, `speed_mbps`).
- `payments`: Histórico de transações e PIX.
- `vouchers`: Códigos pré-pagos de acesso (`duration_hours`).
- `hotspots`: Locais físicos de acesso.
- `pops`: Roteadores MikroTik.
- `hotspot_sessions`: Sessões ativas de clientes.
- `mikrotik_credentials`: Credenciais da API dos roteadores.
- `free_trials`: Controle de uso do acesso cortesia.
- `campaigns`: Campanhas de marketing.
- `webhooks`: Configurações de webhooks.
- `settings`: Configurações dinâmicas do sistema.
- `logs`: Logs de sistema e erros.
- `audit_logs`: Trilha de auditoria.
- `radius_replies`: Respostas formatadas para o servidor RADIUS.
- `radreply`: Tabela padrão do FreeRADIUS para controle de banda.

## 🔌 Dicionário de API (Principais Endpoints)

A API possui mais de 70 rotas. As principais são:

### Autenticação e Admin
- `POST /api/auth/login`: Login administrativo (com auto-hash de senha).
- `GET /api/users`: Lista clientes.
- `GET /api/plans`: Lista planos.

### Portal Público
- `GET /api/portal/plans`: Lista planos ativos para o portal.
- `POST /api/portal/create-pix`: Gera PIX via Mercado Pago.
- `GET /api/portal/check-payment/:id`: Verifica status do PIX.
- `POST /api/free-trial`: Libera acesso cortesia (15 min).

### Integração MikroTik
- `POST /api/pops/:id/heartbeat`: Heartbeat do MikroTik (mantém o POP online).
- `GET /api/hotspots/:id/script`: Gera script de instalação para o MikroTik.
- `POST /api/webhooks/mercadopago`: Recebe confirmação de pagamento e libera acesso.

## ⚙️ Guia de Configuração do MikroTik

Para adicionar um novo roteador MikroTik ao sistema:

1. Acesse o painel administrativo (`/hotspots.html`).
2. Clique em "Novo Hotspot" e preencha os dados.
3. Após criar, clique no botão "Script" na tabela.
4. Copie o script gerado.
5. Abra o Winbox, vá em `New Terminal` e cole o script.

O script fará automaticamente:
- Configuração do servidor RADIUS apontando para a VPS.
- Criação do perfil de Hotspot com DHCP/IP/hotspot sempre fechando na bridge.
- Liberação do Walled Garden (Mercado Pago, Vercel, API).
- Criação do Scheduler de Heartbeat (ping a cada 30s).

## ✅ Correcoes recentes (2026-04-13)

- RouterOS 6.47.9: removidos `comment` e `radius-interim-update` do `/ip hotspot profile add` (evita erro de parser e falha ao criar hotspot).
- Modal de detalhes: `escapeHtml` agora tolera valores nao string.
- Trunk VLAN: campos LAN/VLAN/Tipo de saida ocultos quando topologia=single.
- Hotspot core: `/ip dhcp-server add` sem `comment`, `/ip hotspot add` na `ms-bridge-*`, `login-by=http-chap,http-pap` e `html-directory="ms-<ID>"`.
- HTML do hotspot: `login.html` agora redireciona para `portal.html` com `loginUrl=$(link-login-only)` e `alogin.html` permanece como página local pós-autenticação.
- Walled Garden: liberados os hosts necessários do portal (`hotspot-system.vercel.app`, `*.vercel.app`, `mstelecom-api.duckdns.org`, Google Fonts, CDN usada pelo portal e Mercado Pago).

## ⚠️ Observacao operacional atual

- Durante os testes de campo, o POP passou a aparecer online e o portal passou a abrir apos um ajuste manual no MikroTik.
- Esse comportamento ficou operacional, mas a documentacao deve considerar esse ponto como provisório ate o fluxo de heartbeat/portal ficar fechado de ponta a ponta sem ajuste manual.

## 🔐 Variáveis de Ambiente (.env)

O backend requer as seguintes variáveis no arquivo `.env` da VPS:

```env
PORT=3000
API_BASE_URL=https://mstelecom-api.duckdns.org
FRONTEND_BASE_URL=https://hotspot-system.vercel.app
SUPABASE_URL=https://sua-url.supabase.co
SUPABASE_KEY=sua-chave-anon-ou-service
JWT_SECRET=seu-segredo-jwt
MERCADOPAGO_ACCESS_TOKEN=APP_USR-seu-token
RADIUS_SERVER_IP=40.233.118.238
```

## 🛠️ Manutenção e Comandos Úteis (VPS)

Acesse a VPS via SSH: `ssh ubuntu@40.233.118.238`

```bash
# Ver status da API
pm2 status hotspot-system

# Ver logs em tempo real
pm2 logs hotspot-system

# Reiniciar a API manualmente
pm2 restart hotspot-system
```

## Credenciais Padrão

| Campo | Valor |
|-------|-------|
| Usuário | `admin` |
| Senha | `44F766@2` |

> Altere a senha imediatamente após o primeiro login.

## Licença

Propriedade de MS TELECOM. Todos os direitos reservados.
