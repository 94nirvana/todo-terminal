# todo-terminal

Aplicação web full-stack de lista de tarefas com uma interface inspirada em
terminal, construída com HTML, CSS, JavaScript e Node.js. Não possui dependências
de runtime: usa apenas módulos nativos do Node.js (`node:http`, `node:crypto`,
`node:fs`).

Os controles de segurança incluem CSP estrita sem `unsafe-inline`, sessões
opacas em cookies `HttpOnly`, proteção CSRF, allowlist de campos, autorização
avaliada no recurso, rate limiting, allowlists de host/origin e logs estruturados
sem PII. Consulte o modelo de ameaças e os ADRs para decisões e riscos residuais.

## Requisitos

- Node.js >= 20.11
- npm (distribuído com Node.js)

O projeto não requer instalação de pacotes. Os testes foram escritos para Node.js
e usam o test runner nativo.

## Instalação e execução

```bash
npm start       # http://127.0.0.1:3000
```

Para executar em modo de desenvolvimento com reinício automático:

```bash
npm run dev
```

Na primeira execução, crie uma conta na tela de login usando uma senha com no
mínimo 12 caracteres.

## Comandos disponíveis

| Comando | Descrição |
|---|---|
| `help` | lista de comandos |
| `ls [open\|done\|all]` | lista tarefas |
| `add <titulo> [--pri high\|normal\|low] [--desc texto]` | cria tarefa |
| `done <#\|id>` / `undone <#\|id>` | conclui / reabre tarefa |
| `edit <#\|id> <novo titulo>` | edita título |
| `rm <#\|id>` | remove tarefa |
| `stats` | resumo |
| `whoami`, `date`, `clear`, `logout` | utilitários |

Atalhos: `Tab` completa, `↑`/`↓` histórico, `Ctrl+L` limpa, `Ctrl+C` cancela a linha.

## Desenvolvimento e testes

```bash
npm test       # 38 testes unitários, de integração e de abuso
npm run check  # verificação de sintaxe
```

## Arquitetura

```
server.js          Inicialização HTTP, headers, roteamento, timeouts e shutdown
src/config.js      Configuração validada e valores padrão seguros
src/security.js    CSP/headers, rate limit, limite de corpo e cookies
src/validation.js  Validação de entrada e allowlist de campos
src/auth.js        scrypt, sessões opacas, CSRF e rotação de sessão
src/api.js         API /api/v1, idempotência e rate limit por rota
src/store.js       Domínio e persistência JSON atômica
src/static.js      Assets estáticos com allowlist e resolução canônica
src/logger.js      Logs JSON com requestId e redação de campos sensíveis
public/            Interface web do terminal
test/              Testes unitários, de integração e de abuso
docs/              Modelo de ameaças, decisões de arquitetura e OpenAPI
```

## Controles de segurança implementados

| Controle | Onde |
|---|---|
| CSP `default-src 'none'` + `frame-ancestors 'none'` + `object-src 'none'` | `src/security.js` |
| `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP/COEP | `src/security.js` |
| HSTS automático quando há TLS | `src/security.js` |
| Sessão opaca `HttpOnly`/`SameSite=Strict`/`Secure`, expiração ociosa e absoluta, rotação no login | `src/auth.js` |
| Token CSRF por sessão + verificação de `Origin` | `src/auth.js` |
| Senha com scrypt (N=16384), salt por usuário, comparação constante, resposta uniforme | `src/auth.js` |
| Allowlist de campos (anti mass-assignment), normalização Unicode, limite de tamanho | `src/validation.js` |
| Autorização no recurso (IDOR → 404), `ownerId` em toda operação | `src/store.js`, `src/api.js` |
| Rate limiting por IP (global, escrita, autenticação, por conta) com `429` + `Retry-After` | `src/security.js`, `src/api.js` |
| Limite de payload (16 KB), `Content-Type` allowlisted, `Transfer-Encoding` rejeitado | `src/security.js` |
| Host allowlist (anti Host Header Injection) e `Origin` allowlist | `src/security.js` |
| Path traversal: allowlist de extensões + resolução canônica | `src/static.js` |
| Sem stack trace ao cliente; logs JSON sem PII/segredos | `src/logger.js` |
| Idempotência (`Idempotency-Key`) em criação | `src/api.js` |
| Timeouts HTTP explícitos, `maxHeadersCount`, shutdown gracioso | `server.js` |

## Configuração

As variáveis abaixo são opcionais. Configuração inválida faz o processo falhar
ao iniciar, em vez de degradar silenciosamente.

| Variável | Padrão | Descrição |
|---|---|---|
| `PORT` / `HOST` | `3000` / `127.0.0.1` | Bind do servidor |
| `TRUSTED_ORIGINS` | `http://127.0.0.1:3000,http://localhost:3000` | Allowlist de origem (CSRF) |
| `TRUSTED_HOSTS` | `127.0.0.1,localhost` | Allowlist de Host |
| `TRUST_PROXY_HTTPS` | `false` | Habilita HSTS/`Secure` quando o TLS termina no proxy |
| `SESSION_IDLE_MINUTES` / `SESSION_ABSOLUTE_HOURS` | `30` / `12` | Expiração de sessão |
| `RATE_LIMIT_MAX` / `_WRITE_MAX` / `_AUTH_MAX` | `120` / `60` / `10` | Rate limiting |
| `MAX_BODY_BYTES` | `16384` | Limite de payload |
| `SCRYPT_N` | `16384` | Custo de hash de senha |
| `LOG_LEVEL` | `info` (prod) | `debug`/`info`/`warn`/`error`/`silent` |

## Implantação em produção

O repositório não inclui configuração de proxy, TLS ou hospedagem. Antes de
publicar uma instância, configure e verifique no ambiente de implantação:

1. `NODE_ENV=production`.
2. TLS no proxy reverso e `TRUST_PROXY_HTTPS=true` somente quando o proxy garantir
   HTTPS e encaminhar cabeçalhos confiáveis.
3. `TRUSTED_ORIGINS` e `TRUSTED_HOSTS` com os domínios exatos da aplicação.
4. Sanitização de cabeçalhos encaminhados no proxy; não confie em valores
   fornecidos diretamente pelo cliente.
5. Diretório `data/` com acesso restrito e backups cifrados.
6. Rate limiting adicional na borda, sem substituir os controles da aplicação.

## Limitações conhecidas (risco residual explícito)

- Persistência em arquivo: **sem concorrência de escrita** e sem escala horizontal.
- Sem criptografia em repouso (dados de lista de tarefas não são PII sensível).
- Rate limit é **por processo**: com múltiplas réplicas, o limite efetivo dobra.
- Sem MFA, sem recuperação de senha, sem auditoria persistente de eventos de segurança.
- Logs em stdout (sem rotação): quem opera define a rotação.

## Documentação

- [Modelo de ameaças](docs/THREAT-MODEL.md)
- [Especificação OpenAPI](docs/openapi.yaml)
- [Decisões de arquitetura](docs/)

## Licença

Distribuído sob a licença MIT. Consulte [LICENSE](LICENSE).