# ADR-002: CSP estrita sem `unsafe-inline` e zero dependências de runtime

## Status
Aceito

## Contexto
O front-end é uma simulação de terminal. A vontade de injetar scripts/estilos
dinâmicos é alta (spinners, cores por prioridade, autocomplete), e é exatamente
esse o vetor clássico de XSS (CSP permissiva + `innerHTML` + dados do servidor).

## Decisão
1. **CSP `default-src 'none'`**, com `script-src 'self'`, `style-src 'self'`,
   `img-src 'self' data:`, `connect-src 'self'`, `object-src 'none'`,
   `base-uri 'none'`, `form-action 'none'`, `frame-ancestors 'none'`.
   Sem `unsafe-inline`, sem `unsafe-eval`, sem CDNs.
2. **Zero dependências de runtime**: apenas módulos nativos do Node
   (`node:http`, `node:crypto`, `node:fs`). Sem `package-lock` de terceiros,
   sem superfície de supply chain, sem SBOM de terceiros (SBOM gerado: aplicação
   própria, dependências = runtime Node).
3. No cliente, **nunca** `innerHTML`/`insertAdjacentHTML`/`eval`/`setTimeout(string)`:
   todo texto do servidor entra por `textContent`.
4. Estilos por classe (`.todo-high`, `.todo-done`), nunca por atributo `style`
   interpolado — evita `style`-based exfiltration e mantém a CSP sem `unsafe-inline`.

## Alternativas
- **`'unsafe-inline'` com nonce por requisição**: rejeitado para este escopo —
  o nonce adiciona complexidade e o ganho real é pequeno, já que não há template
  de servidor. Se houver SSR no futuro, reavaliar com nonce por resposta.
- **Framework (React/Vue)**: rejeitado — bundle de dependências, runtime de build e
  superfície maior, sem benefício para ~450 linhas de UI.
- **Bootstrap/Material**: rejeitado — CDN viola `default-src 'none'` e adiciona
  dependência externa com histórico de CVE (supply chain).

## Consequências
Positivo: XSS e 常 difícil de introduzir; nenhuma dependência para auditar/patchear;
build reprodutível (`node server.js` e suficiente).
Negativo: menos ergonomicidade para UI dinâmica; sem `template literals` de HTML;
política de segurança precisa ser mantida manualmente.

## Riscos residuais
- **XSSStored via bug futuro no cliente** → mitigado por `textContent` em toda a
  renderização e por teste automatizado que falha se `innerHTML` voltar ao código.
- **CSP não cobre DOM clobbering** → mitigado com validação de esquema na API
  (o servidor é quem decide o formato).