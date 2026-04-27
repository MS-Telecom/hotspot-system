# Configuração do FreeRADIUS com Tabela Única (radius_replies)

Este documento registra a configuração oficial do FreeRADIUS para o projeto MS TELECOM, utilizando a tabela canônica `radius_replies` para todas as operações de autorização.

## Informações Gerais
- **Caminho do Arquivo na VPS**: `/etc/freeradius/3.0/mods-config/sql/main/postgresql/queries.conf`
- **Runtime Oficial**: Tabela `radius_replies`
- **Status das Tabelas Legadas**: As tabelas `radcheck`, `radreply` e `replies` **não devem existir** ou devem estar vazias. Toda a lógica reside em `radius_replies`.

## Queries de Autorização (queries.conf)

### 1. authorize_check_query
Busca itens de verificação, principalmente a senha do dispositivo.
```sql
authorize_check_query = "\
	SELECT id, username, attribute, value, op \
	FROM radius_replies \
	WHERE username = '%{SQL-User-Name}' \
	AND status = 'active' \
	AND (expires_at IS NULL OR expires_at > NOW()) \
	AND attribute IN ('Cleartext-Password', 'User-Password', 'Crypt-Password', 'MD5-Password') \
	ORDER BY id"
```

### 2. authorize_reply_query
Busca atributos de resposta para o NAS (MikroTik), como limites de velocidade e tempo.
```sql
authorize_reply_query = "\
	SELECT id, username, attribute, value, op \
	FROM radius_replies \
	WHERE username = '%{SQL-User-Name}' \
	AND status = 'active' \
	AND (expires_at IS NULL OR expires_at > NOW()) \
	AND attribute NOT IN ('Cleartext-Password', 'User-Password', 'Crypt-Password', 'MD5-Password') \
	ORDER BY id"
```

## Comandos de Operação e Validação

### Validar Sintaxe do FreeRADIUS
```bash
sudo freeradius -C
```

### Reiniciar o Serviço
```bash
sudo systemctl restart freeradius
```

### Verificar Status
```bash
sudo systemctl status freeradius --no-pager
```

### Testar Autenticação (Debug Mode)
Para validar um `Access-Accept` e ver as queries em tempo real:
1. Pare o serviço: `sudo systemctl stop freeradius`
2. Rode em modo debug: `sudo freeradius -X`
3. Realize um teste de acesso (ex: Teste Grátis no portal)
4. Verifique no log se a consulta está sendo feita na tabela `radius_replies` e se retorna os atributos esperados.

## Estrutura da Tabela `radius_replies`
A tabela deve possuir uma constraint única composta: `UNIQUE (username, attribute)`. Isso permite que um mesmo MAC tenha múltiplas entradas (Password, Session-Timeout, etc).

```sql
ALTER TABLE public.radius_replies ADD CONSTRAINT radius_replies_username_attribute_unique UNIQUE (username, attribute);
```
