'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const http = require('node:http');

const TEST_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'todo-http-test-'));
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent';
process.env.PORT = '0';
process.env.TRUSTED_ORIGINS = 'http://127.0.0.1';
process.env.TRUSTED_HOSTS = '127.0.0.1,localhost';
process.env.RATE_LIMIT_MAX = '100000';
process.env.RATE_LIMIT_AUTH_MAX = '1000';
process.env.RATE_LIMIT_WRITE_MAX = '10000';

const config = require('../src/config');
config.paths.data = TEST_ROOT;
config.paths.users = path.join(TEST_ROOT, 'users.json');
config.paths.todos = path.join(TEST_ROOT, 'todos.json');
config.paths.sessions = path.join(TEST_ROOT, 'sessions.json');

const { server } = require('../server');

let baseUrl;
const PASSWORD = 'senha-super-segura-123';

const clients = new Map();

function client(name) {
  if (!clients.has(name)) clients.set(name, { cookie: null, csrf: null });
  return clients.get(name);
}

async function call(name, method, url, { body, headers = {}, csrf = true, rawBody } = {}) {
  const state = client(name);
  const finalHeaders = { ...headers };
  if (state.cookie) finalHeaders.Cookie = state.cookie;
  if (csrf && state.csrf && ['POST', 'PATCH', 'DELETE'].includes(method)) {
    finalHeaders['X-CSRF-Token'] = state.csrf;
  }
  if (body !== undefined || rawBody !== undefined) {
    finalHeaders['Content-Type'] = 'application/json';
  }
  const response = await fetch(`${baseUrl}${url}`, {
    method,
    headers: finalHeaders,
    body: rawBody !== undefined ? rawBody : (body !== undefined ? JSON.stringify(body) : undefined),
    redirect: 'manual',
  });
  const setCookie = response.headers.getSetCookie?.() ?? [];
  for (const cookie of setCookie) {
    const [pair] = cookie.split(';');
    if (pair.startsWith(`${config.session.cookieName}=`)) {
      state.cookie = pair.endsWith('=') ? null : pair;
    }
  }
  let data = null;
  if (response.status !== 204) {
    try { data = await response.json(); } catch { data = null; }
  }
  return { status: response.status, headers: response.headers, data };
}

async function login(name, email) {
  await call(name, 'POST', '/api/v1/auth/register', { body: { email, password: PASSWORD } });
  const session = await call(name, 'GET', '/api/v1/session');
  client(name).csrf = session.data.csrfToken;
}

test.before(async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => {
  server.close();
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
});

test('health responde sem vazar informacao interna', async () => {
  const res = await call('anon', 'GET', '/api/v1/health');
  assert.equal(res.status, 200);
  assert.deepEqual(res.data, { status: 'ok' });
});

test('cabecalhos de seguranca presentes e restritos', async () => {
  const res = await call('anon', 'GET', '/');
  assert.equal(res.status, 200);
  const csp = res.headers.get('content-security-policy');
  assert.ok(csp.includes("default-src 'none'"));
  assert.ok(csp.includes("frame-ancestors 'none'"));
  assert.ok(csp.includes("object-src 'none'"));
  assert.ok(!csp.includes('unsafe-inline'));
  assert.ok(!csp.includes('unsafe-eval'));
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.equal(res.headers.get('x-powered-by'), null);
});

test('registro cria sessao HttpOnly/SameSite e devolve usuario sem segredo', async () => {
  const res = await call('alice', 'POST', '/api/v1/auth/register', { body: { email: 'alice@test.dev', password: PASSWORD } });
  assert.equal(res.status, 201);
  assert.equal(res.data.user.email, 'alice@test.dev');
  assert.equal(res.data.user.passwordHash, undefined);
  assert.equal(res.data.user.salt, undefined);
});

test('senha fraca e email invalido sao rejeitados na borda', async () => {
  const res = await call('weak', 'POST', '/api/v1/auth/register', { body: { email: 'x@test.dev', password: '123' } });
  assert.equal(res.status, 400);
  assert.equal(res.data.error.code, 'WEAK_PASSWORD');
  const res2 = await call('weak', 'POST', '/api/v1/auth/register', { body: { email: 'nao-email', password: PASSWORD } });
  assert.equal(res2.status, 400);
});

test('erro nao expoe stack trace nem caminho de arquivo', async () => {
  const res = await call('anon', 'POST', '/api/v1/auth/login', { rawBody: '{invalido' });
  assert.equal(res.status, 400);
  assert.ok(!JSON.stringify(res.data).includes('/src/'));
  assert.equal(res.data.error.stack, undefined);
});

test('Content-Type obrigatorio', async () => {
  const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: 'email=a',
  });
  assert.equal(res.status, 415);
});

test('payload acima do limite e barrado', async () => {
  const huge = JSON.stringify({ email: 'a@b.dev', password: 'x'.repeat(200 * 1024) });
  const res = await call('big', 'POST', '/api/v1/auth/register', { rawBody: huge });
  assert.equal(res.status, 413);
});

test('Host nao autorizado e rejeitado (Host Header Injection)', async () => {
  // fetch (undici) nao permite sobrescrever Host; usamos o modulo http nativo.
  const status = await new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port: server.address().port, path: '/api/v1/health', method: 'GET', headers: { Host: 'evil.example.com' } },
      (res) => {
        res.resume();
        resolve(res.statusCode);
      },
    );
    req.on('error', reject);
    req.end();
  });
  assert.equal(status, 403);
});

test('CRUD completo de tarefas autenticado', async () => {
  await login('u1', 'u1@test.dev');
  const created = await call('u1', 'POST', '/api/v1/todos', { body: { title: 'escrever relatorio', priority: 'high' } });
  assert.equal(created.status, 201);
  const id = created.data.todo.id;

  const list = await call('u1', 'GET', '/api/v1/todos?status=open');
  assert.equal(list.data.total, 1);

  const patched = await call('u1', 'PATCH', `/api/v1/todos/${id}`, { body: { done: true } });
  assert.equal(patched.data.todo.done, true);
  assert.ok(patched.data.todo.completedAt);

  const removed = await call('u1', 'DELETE', `/api/v1/todos/${id}`);
  assert.equal(removed.status, 204);
  const after = await call('u1', 'GET', '/api/v1/todos?status=all');
  assert.equal(after.data.total, 0);
});

test('IDOR via API: segundo usuario nao le nem altera tarefa alheia', async () => {
  await login('u2', 'u2@test.dev');
  const other = await call('u2', 'POST', '/api/v1/todos', { body: { title: 'segredo do u2' } });
  const otherId = other.data.todo.id;

  await login('u3', 'u3@test.dev');
  const read = await call('u3', 'PATCH', `/api/v1/todos/${otherId}`, { body: { title: 'invadido' } });
  assert.equal(read.status, 404);

  const del = await call('u3', 'DELETE', `/api/v1/todos/${otherId}`);
  assert.equal(del.status, 404);

  const list = await call('u3', 'GET', '/api/v1/todos?status=all');
  assert.equal(list.data.total, 0);
});

test('CSRF: escrita sem token e bloqueada', async () => {
  await login('u4', 'u4@test.dev');
  const semToken = await call('u4', 'POST', '/api/v1/todos', { body: { title: 'x' }, csrf: false });
  assert.equal(semToken.status, 403);

  client('u4').csrf = 'token-invalido';
  const tokenErrado = await call('u4', 'POST', '/api/v1/todos', { body: { title: 'x' } });
  assert.equal(tokenErrado.status, 403);
  client('u4').csrf = (await call('u4', 'GET', '/api/v1/session')).data.csrfToken;
});

test('CSRF: Origin nao autorizado e bloqueado mesmo com token valido', async () => {
  await login('u5', 'u5@test.dev');
  const res = await call('u5', 'POST', '/api/v1/todos', {
    body: { title: 'x' },
    headers: { Origin: 'https://evil.example' },
  });
  assert.equal(res.status, 403);
});

test('anônimo nao acessa recursos protegidos', async () => {
  assert.equal((await call('anon', 'GET', '/api/v1/todos')).status, 401);
  assert.equal((await call('anon', 'POST', '/api/v1/todos', { body: { title: 'x' } })).status, 401);
});

test('logout invalida a sessao', async () => {
  await login('u6', 'u6@test.dev');
  const created = await call('u6', 'POST', '/api/v1/todos', { body: { title: 'antes do logout' } });
  assert.equal(created.status, 201);
  const out = await call('u6', 'POST', '/api/v1/auth/logout');
  assert.equal(out.status, 204);
  assert.equal((await call('u6', 'GET', '/api/v1/todos')).status, 401);
});

test('credenciais invalidas nao revelam se o usuario existe', async () => {
  const inexistente = await call('anon', 'POST', '/api/v1/auth/login', { body: { email: 'naoexiste@test.dev', password: PASSWORD } });
  const existente = await call('anon', 'POST', '/api/v1/auth/login', { body: { email: 'u1@test.dev', password: 'senha-errada-1234' } });
  assert.equal(inexistente.status, 401);
  assert.equal(existente.status, 401);
  assert.deepEqual(inexistente.data, existente.data);
});

test('idempotencia evita criacao duplicada com a mesma chave', async () => {
  await login('u7', 'u7@test.dev');
  const headers = { 'Idempotency-Key': 'chave-fixa-123456' };
  const a = await call('u7', 'POST', '/api/v1/todos', { body: { title: 'uma vez' }, headers });
  const b = await call('u7', 'POST', '/api/v1/todos', { body: { title: 'uma vez' }, headers });
  assert.equal(a.data.todo.id, b.data.todo.id);
  assert.equal(b.headers.get('idempotency-replayed'), 'true');
  const list = await call('u7', 'GET', '/api/v1/todos?status=all');
  assert.equal(list.data.total, 1);
});

test('path traversal em asset nao serve arquivos do sistema', async () => {
  const rawGet = (path) => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: server.address().port, path, method: 'GET' }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });

  const encoded = await rawGet('/%2e%2e%2f%2e%2e%2fetc%2fpasswd');
  assert.ok([400, 404].includes(encoded.status), `esperado 400/404, veio ${encoded.status}`);
  assert.ok(!encoded.body.includes('root:'));

  const traversal = await rawGet('/assets/../../../../etc/passwd');
  assert.ok([400, 403, 404].includes(traversal.status), `esperado 400/403/404, veio ${traversal.status}`);
  assert.ok(!traversal.body.includes('root:'));

  // Extensao nao allowlisted nunca e' servida (allowlist de tipos).
  const others = await rawGet('/package.json');
  assert.ok([400, 404].includes(others.status));
  assert.ok(!others.body.includes('devDependencies'));
});

test('metodo nao permitido retorna 404 sem executar handler', async () => {
  const res = await call('anon', 'PUT', '/api/v1/health');
  assert.equal(res.status, 404);
});

test('Transfer-Encoding rejeitado', async () => {
  const res = await fetch(`${baseUrl}/api/v1/todos`, {
    method: 'POST',
    headers: { 'Transfer-Encoding': 'chunked', 'Content-Type': 'application/json' },
    body: '{"title":"x"}',
  }).catch(() => null);
  assert.ok(res === null || res.status === 400);
});