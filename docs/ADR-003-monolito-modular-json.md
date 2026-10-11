# ADR-003: Monólito modular com persistência em arquivo JSON

## Status
Aceito — com prazo de validade explícito

## Contexto
Escopo pequeno: To-Do List multiusuário, volume baixo (limite `MAX_USERS=100`),
um processo Node. Não há requisito de disponibilidade alta nem análise complexa.

## Decisão
Monólito modular em camadas explícitas:

```
src/security.js  src/validation.js   -> Borda (confianca zero)
src/auth.js      src/api.js           -> Aplicacao (casos de uso)
src/store.js                          -> Dominio + Infra (repositorio)
```

Persistência em arquivo JSON com escrita **atômica** (`tmp` + `fsync` + `rename`),
modo `0600`. O domínio não conhece HTTP, Node ou framework — apenas a interface
`JsonStore`. Nenhum SQL é executado (portanto, **SQLi é eliminável por construção**,
não por disciplina).

## Alternativas
- **SQLite (`node:sqlite`, nativo no Node 22)**: considerado — traria transações reais
  e `statement_timeout`. Rejeitado agora por simplicidade; **é o próximo passo**
  quando houver concorrência de escrita relevante.
- **PostgreSQL**: rejeitado — complexidade operacional (operação, backup, rede)
  desproporcional ao escopo; introduz também risco de SQLi.
- **MongoDB / redis**: rejeitado — mesmo custo operacional, sem benefício.

## Consequências
Positivo: zero dependência, zero serviço externo, backup = copiar arquivos,
rollback = reverter arquivos.
Negativo: **sem concorrência de escrita** (single process), crescimento de arquivo,
busca O(n). Risco de corrupção mitigado por rename atômico; arquivo corrompido
**não** é sobrescrito silenciosamente (o processo falha explícito).

## Riscos residuais
- **Perda de dados por falha de disco** → mitigado por `fsync` antes do rename;
  RPO ainda é "última escrita" e precisa de backup externo.
- **Sem criptografia em repouso** → risco aceito: dados de lista de tarefas não são
  PII sensível por si só. **Se isso mudar**, criptografar campos em repouso ou
  usar volume cifrado do provedor.
- **Escala horizontal** → bloqueante; exige extrair o `JsonStore` para interface
  compartilhada (Redis/Postgres). A interface já está isolada para permitir isso.