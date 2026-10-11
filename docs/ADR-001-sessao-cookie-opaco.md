# ADR-001: Sessão opaca em cookie HttpOnly em vez de JWT

## Status
Aceito

## Contexto
Aplicação web full-stack servida na mesma origem (UI estática + API `/api/v1`).
Necessidade de autenticação com revogação imediata e sem estado sensível no cliente.

## Decisão
Cookie de sessão **opaco** (`todo_sid`), `HttpOnly`, `SameSite=Strict`, `Secure`
(quando TLS está terminado antes da aplicação), com identificador aleatório de
256 bits. O servidor persiste apenas o **SHA-256** do token; a sessão guarda
`userId`, `csrfToken`, `createdAt` (expiração absoluta) e `lastSeenAt`
(expiração ociosa). O ID da sessão é **rotacionado a cada login**.

## Alternativas
- **JWT em `localStorage`**: rejeitado — XSS passa a exfiltrar token de longa duração e não há revogação simples.
- **JWT em cookie**: rejeitado — revogação exigiria blocklist, o que aumenta a complexidade sem ganho real para este caso.
- **Sessão em memória (sem persistência)**: rejeitado — reinício derrubaria todas as sessões e impede auditoria.

## Consequências
Positivo: revogação imediata (`logout`/troca de senha), superfície de XSS reduzida,
nenhum segredo em storage do cliente.
Negativo: estado no servidor; cada requisição consulta o armazenamento; sem
compartilhamento horizontal sem store externo (Redis).

## Riscos residuais
- **Fixação de sessão** → mitigado por rotação do ID no login e por token CSRF por sessão.
- **Cookie sem `Secure` em ambiente sem TLS** → risco assumido em desenvolvimento; mitigado
  por HSTS automático quando TLS está presente e por recusa de HSTS sem TLS.
- **Persistência em arquivo** → mitigado com escrita atômica e permissão `0600`.