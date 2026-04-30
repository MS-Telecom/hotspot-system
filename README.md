# MS Telecom Hotspot System

Sistema interno da MS Telecom para portal cativo, planos, clientes, POPs MikroTik, RADIUS e pagamentos PIX.

## Arquitetura

- Frontend publico: `public/portal.html` hospedado no Vercel.
- Painel administrativo: HTMLs em `public/`.
- Backend principal: `backend/server.js` em Node.js/Express na VPS.
- Banco: Supabase/PostgreSQL.
- Credenciais RADIUS canonicas: `radius_replies`.

## Segurança de administradores

Nao existe credencial padrao no repositorio.

O primeiro `owner` deve ser criado ou recuperado somente pela VPS, usando:

```bash
cd /home/ubuntu/hotspot-system
node scripts/create-owner.js <usuario> <email opcional>
```

Tambem e possivel usar variaveis temporarias:

```bash
OWNER_USERNAME=owner OWNER_EMAIL=owner@example.com OWNER_PASSWORD='senha-temporaria-forte' node scripts/create-owner.js
```

Depois disso, administradores so devem ser criados pelo painel por usuario com role `owner`.

Roles suportadas:

- `owner`
- `admin`
- `operator`
- `finance`

## Variaveis de ambiente

Use `.env.example` como referencia. Secrets reais devem ficar somente no `.env` da VPS.

Nunca colocar no GitHub:

- Supabase key real
- Mercado Pago token real
- RADIUS secret
- VPN PSK
- SSH key
- senhas de MikroTik
- tokens de POP

## Cadastro do cliente no portal

O cadastro publico de cliente e feito no `portal.html`, respeitando o Perfil de Cadastro.

Rotas publicas usadas pelo cadastro:

- `GET /api/portal/registration-fields`
- `GET /api/portal/registration-status?mac=<MAC>`
- `POST /api/portal/register-device`

## Deploy

O workflow `.github/workflows/deploy.yml` instala dependencias na raiz do projeto e inicia o PM2 com `backend/server.js`.

## Licenca

Propriedade de MS Telecom. Todos os direitos reservados.