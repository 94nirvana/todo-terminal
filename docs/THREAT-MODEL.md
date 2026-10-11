# Modelo de Ameaça (STRIDE por fluxo)

Escopo: aplicação `todo.sh` — UI de terminal + API REST `/api/v1` + persistência em arquivo.
Ativos: (1) integridade/lista de tarefas, (2) credenciais, (3) sessão, (4) disponibilidade do processo.

| # | Fluxo | Ameaças STRIDE | Controle implementado | Risco residual |
|---|-------|----------------|-----------------------|-----------------|
| F1 | Navegador → servidor (bootstrap) | Spoofing (Host), Tampering (caminho), DoS | Allowlist de `Host`, CSP estrita, allowlist de extensões, resolução canônica, `Etag`/`304` | Baixo |
| F2 | Login/registro | Spoofing, Elevation | scrypt (N=16384), salt 16B, `timingSafeEqual`, resposta uniforme, rate limit por IP e por conta, message igual para usuário inexistente | Enumeração de e-mail Timing (mitigada com hash dummy) |
| F3 | Sessão | Spoofing, Repudiation | Cookie opaco HttpOnly/SameSite=Strict/Secure, apenas hash persistido, expiração ociosa (30 min) e absoluta (12 h), rotação no login | Fixação de sessão (mitigada por rotação + CSRF) |
| F4 | Escritas (POST/PATCH/DELETE) | Tampering, Repudiation, Elevation | Token CSRF por sessão + verificação de `Origin`, allowlist de campos, idempotência, rate limit de escrita, resposta `no-store` | Cliente não-navegador sem `Origin` depende só do token CSRF |
| F5 | Leitura de tarefas | Information disclosure, Elevation (IDOR) | Autorização avaliada **no recurso** (`ownerId`), 404 para recurso alheio, paginação/filtro limitados, view pública sem campos internos | Vazamento de existência via diferença de timing é mínimo |
| F6 | Persistência | Tampering, Denial of service | Escrita atômica, `0600`, limite de usuários e de tamanho de título, normalização de entrada | Sem criptografia em repouso (aceito) |
| F7 | Logs | Information disclosure | Logs estruturados com `requestId`, allowlist de campos sensíveis redacted, e-mail nunca logado, sem stack trace ao cliente | Volume de log em disco (rotação não implementada) |
| F8 | Transporte | Information disclosure, Tampering | HSTS automático sob TLS, `Secure` sob proxy TLS | **TLS não terminado pela aplicação**: exige proxy/Borg com TLS configurado |

## Threat modeling notes (o que **não** foi feito e por quê)

- **SSRF**: não existe código que faça requisição HTTP a partir de entrada do usuário.
  Portanto SSRF é eliminável por construção, não por allowlist.
- **XXE**: não há parser XML em lugar nenhum.
- **Command injection**: nenhum subprocesso é executado com entrada do usuário;
  `child_process` não é usado na aplicação.
- **Deserialização insegura**: o único formato desserializado é JSON via `JSON.parse`
  de corpo limitado a 16 KB e com content-type allowlisted.
- **Cache poisoning**: respostas autenticadas com `Cache-Control: no-store`.

## Verification (como comprovar)

```bash
npm test          # 33 testes: unitários + integração + cenários de abuso
npm run check     # sintaxe de todos os módulos
```

Cobertura de abuso automatizada: IDOR (store e API), CSRF (token ausente/inválido/Origin),
Host header injection, path traversal, mass assignment, payload grande, força bruta
(rate limit), vazamento de segredo em resposta/log, sessão expirada.