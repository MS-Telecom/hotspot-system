# 📘 Manual Completo do Sistema MS TELECOM Hotspot

Este documento consolida toda a arquitetura, funcionalidades e guias operacionais do sistema **MS TELECOM**, integrando o backend (Node.js/RADIUS), o frontend (11 páginas mescladas) e a infraestrutura MikroTik.

---

## 🚀 1. Visão Geral da Arquitetura

O sistema é uma solução completa de gestão de Hotspot WiFi com autenticação RADIUS, controle de banda e faturamento automatizado.

| Componente | Tecnologia | Função |
| :--- | :--- | :--- |
| **Backend** | Node.js (Express) | API REST, Lógica de Negócio, Webhooks e Jobs CRON. |
| **Banco de Dados** | Supabase (PostgreSQL) | Armazenamento de usuários, planos, hotspots e logs. |
| **Autenticação** | FreeRADIUS | Protocolo de autenticação e tarifação (AAA). |
| **Frontend** | HTML5 / Tailwind CSS | Painel administrativo moderno e responsivo. |
| **Infraestrutura** | MikroTik (RouterOS) | Gateway de rede e controle de acesso dos clientes. |
| **Pagamentos** | Mercado Pago | Processamento de PIX e ativação automática de planos. |

---

## 🛠️ 2. Funcionalidades do Backend (server.js)

O backend foi otimizado para garantir a sincronia entre o banco de dados e o servidor RADIUS.

### 2.1. Autenticação e Segurança
- **Auto-Hash de Senhas:** O sistema aceita senhas em texto plano no primeiro login e as converte automaticamente para **SHA-256 (bcrypt)**, garantindo segurança legada e moderna.
- **JWT Auth:** Todas as rotas administrativas são protegidas por tokens JWT.

### 2.2. Integração RADIUS (radreply)
- **Controle de Banda:** Ao ativar um plano, o sistema escreve o atributo `Mikrotik-Rate-Limit` na tabela `radius_replies` (ou `radreply`), definindo a velocidade do cliente (ex: `10M/10M`).
- **Limpeza Automática:** O Job CRON remove entradas do RADIUS assim que a sessão do usuário expira, desconectando-o imediatamente.

### 2.3. Jobs CRON (Automação)
- **Verificação de Expiração:** Roda periodicamente para marcar usuários como `expired` e limpar as tabelas de autenticação RADIUS.
- **Heartbeat:** Monitora a saúde dos POPs (Hotspots) e atualiza o status online/offline no painel.

---

## 🖥️ 3. Guia das Páginas do Painel (Frontend)

Todas as 11 páginas foram mescladas para unir o design moderno com as funções avançadas.

| Página | Funcionalidades Principais |
| :--- | :--- |
| **Dashboard** | Gráficos de faturamento, status dos POPs em tempo real e métricas de usuários. |
| **Hotspots** | Cadastro de POPs com suporte a WAN, PPPoE, VLAN e geração de script MikroTik. |
| **Financeiro** | Gestão de transações, gráficos Chart.js, exportação CSV e cobrança manual de pendentes. |
| **Clientes** | Detalhes completos do usuário, histórico de conexões e alteração manual de planos. |
| **Vouchers** | Geração de códigos de acesso temporários com duração em horas. |
| **Campanhas** | Envio de notificações e gestão de marketing para os clientes do Hotspot. |
| **Perfil de Cadastro** | Configuração dinâmica de quais campos (CPF, Tel, etc.) são obrigatórios no portal. |
| **Logs Auditoria** | Rastro completo de quem alterou o quê no sistema administrativo. |
| **Webhooks** | Configuração de integrações externas e logs de chamadas da API. |

---

## 📡 4. Integração com MikroTik

Para que o sistema funcione, o MikroTik deve estar configurado para apontar para o servidor RADIUS da MS TELECOM.

### 4.1. Configuração do RADIUS no RouterOS
```bash
/radius add address=[IP_DO_SERVIDOR] secret=[RADIUS_SECRET] service=hotspot
/ip hotspot profile set [NOME_DO_PERFIL] use-radius=yes
```

### 4.2. Script de Monitoramento (Heartbeat)
O MikroTik deve chamar o endpoint de heartbeat para informar que está online:
```bash
/tool fetch url="https://mstelecom-api.duckdns.org/api/heartbeat?nas_id=[ID_DO_POP]" keep-result=no
```

---

## 💳 5. Fluxo de Pagamento (Mercado Pago)

1. O cliente acessa o **Portal de Login** e escolhe um plano.
2. O sistema gera um **QR Code PIX** via API do Mercado Pago.
3. Após o pagamento, o Mercado Pago envia um **Webhook** para o backend.
4. O backend valida o pagamento, ativa o plano do usuário e **escreve a velocidade no RADIUS**.
5. O cliente é liberado para navegar automaticamente.

---

## 📋 6. Variáveis de Ambiente (.env)

Configurações críticas que devem estar na VPS:
- `DATABASE_URL`: Conexão com o Supabase.
- `JWT_SECRET`: Chave para assinatura de tokens.
- `MP_ACCESS_TOKEN`: Token de produção do Mercado Pago.
- `RADIUS_SECRET`: Senha de comunicação entre MikroTik e RADIUS.

---

## 🛡️ 7. Manutenção e Suporte

- **Logs do Sistema:** Verifique a página `logs.html` para erros de execução do Node.js.
- **Logs de Auditoria:** Verifique `logs-auditoria.html` para ações de administradores.
- **Banco de Dados:** O Supabase oferece interface visual para correções diretas em tabelas se necessário.

---
**MS TELECOM - Sistema de Gestão de Hotspot v2.0**  
*Documentação gerada em 06/04/2026*
