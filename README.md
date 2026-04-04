# MS TELECOM - Hotspot System v2.0

Sistema completo de gerenciamento de hotspots Wi-Fi com portal captivo, pagamentos PIX (Mercado Pago), vouchers, campanhas e integração MikroTik.

## Arquitetura

```
Frontend (Vercel)          Backend (VPS)           Database (Supabase)
hotspot-system.vercel.app  mstelecom-api.duckdns   PostgreSQL + Auth
      |                         |                        |
      +---- HTTPS/REST ---------+-------- SQL -----------+
```

| Componente | Tecnologia | Hospedagem |
|-----------|-----------|------------|
| Frontend | HTML + TailwindCSS + Lucide | Vercel (static) |
| Backend | Node.js + Express | VPS (Oracle/DuckDNS) |
| Database | PostgreSQL | Supabase |
| Pagamentos | Mercado Pago PIX API | - |

## Estrutura do Projeto

```
hotspot-system/
├── backend/
│   └── server.js          # API completa (Express)
├── public/                # Frontend (18 páginas HTML)
│   ├── index.html         # Landing page
│   ├── login.html         # Login admin
│   ├── dashboard.html     # Dashboard com gráficos
│   ├── hotspots.html      # CRUD hotspots + script MikroTik
│   ├── pops.html          # POPs (heartbeat)
│   ├── cadastro.html      # Listagem de clientes
│   ├── cliente-detalhe.html # Detalhe/edição do cliente
│   ├── financeiro.html    # Pagamentos + PIX
│   ├── vouchers.html      # Geração de vouchers
│   ├── campanhas.html     # Campanhas promocionais
│   ├── webhooks.html      # Webhooks de eventos
│   ├── configuracoes.html # Planos, settings, admins
│   ├── logs.html          # Logs do sistema
│   ├── logs-auditoria.html # Logs de auditoria
│   ├── portal.html        # Portal captivo (end-user)
│   ├── status.html        # Status da conexão
│   ├── sucesso.html       # Pagamento confirmado
│   ├── erro.html          # Página de erro
│   └── planos.html        # Planos públicos
├── deploy/
│   ├── setup-vps.sh       # Script de deploy VPS
│   └── nginx.conf         # Configuração nginx
├── package.json
├── vercel.json
├── .env.example
└── README.md
```

## Deploy

### Frontend (Vercel)
1. Conecte o repositório GitHub ao projeto Vercel
2. Framework: Other
3. Output Directory: `public`
4. Deploy automático a cada push

### Backend (VPS)
```bash
ssh root@your-vps "bash -s" < deploy/setup-vps.sh
ssh root@your-vps "nano /opt/hotspot-system/.env"
ssh root@your-vps "systemctl restart hotspot-system"
```

## Credenciais Padrão

| Campo | Valor |
|-------|-------|
| Usuário | `admin` |
| Senha | `admin123` |

> Altere a senha imediatamente após o primeiro login.

## Licença

Propriedade de MS TELECOM. Todos os direitos reservados.
