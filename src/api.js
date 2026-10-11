'use strict';

const config = require('./config');
const logger = require('./logger');
const {
  AppError, errors, readJsonBody, consumeRateLimit, originAllowed,
} = require('./security');
const auth = require('./auth');
const store = require('./store');
const {
  registerSchema, loginSchema, todoCreateSchema, todoPatchSchema, todoListSchema, parseTodoId,
} = require('./validation');

const { toPublicUser, toPublicTodo } = store;

const verifyCsrf = auth.verifyCsrf;

const API_PREFIX = '/api/v1';
const WRITE_METHODS = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);

/* ------------------------------------------------------------------ *
 * Idempotencia de escritas (chave no header Idempotency-Key)
 * ------------------------------------------------------------------ */
const idempotency = new Map();
const IDEMPOTENCY_TTL_MS = 10 * 60 * 1000;

function rememberIdempotent(key, value) {
  idempotency.set(key, { value, expiresAt: Date.now() + IDEMPOTENCY_TTL_MS });
  if (idempotency.size > 5000) {
    for (const [k, v] of idempotency) if (v.expiresAt < Date.now()) idempotency.delete(k);
  }
}

function lookupIdempotent(key) {
  const hit = idempotency.get(key);
  if (!hit) return undefined;
  if (hit.expiresAt < Date.now()) {
    idempotency.delete(key);
    return undefined;
  }
  return hit.value;
}

/* ------------------------------------------------------------------ *
 * Infra de resposta
 * ------------------------------------------------------------------ */

function sendJson(res, status, payload, headers = {}) {
  const noContent = status === 204 || status === 304;
  const body = noContent ? null : Buffer.from(`${JSON.stringify(payload)}\n`, 'utf8');
  res.statusCode = status;
  if (body) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Length', String(body.length));
  } else {
    res.removeHeader('Content-Length');
    res.setHeader('Content-Length', '0');
  }
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.end(body ?? undefined);
}

function sendError(res, err, req) {
  const isApp = err instanceof AppError;
  const status = isApp ? err.status : 500;
  const code = isApp ? err.code : 'INTERNAL_ERROR';
  const message = isApp ? err.message : 'Erro interno.';
  if (!isApp) {
    logger.error('unhandled_error', {
      requestId: req.id,
      method: req.method,
      path: req.url,
      errName: err.name,
      errMessage: err.message,
      stack: config.isProduction ? undefined : err.stack,
    });
  }
  sendJson(res, status, { error: { code, message, ...(isApp && err.details ? { details: err.details } : {}) } }, {
    'Cache-Control': 'no-store',
    ...(status === 429 ? { 'Retry-After': '60' } : {}),
  });
}

function clientIp(req) {
  if (config.trustProxyHttps && typeof req.headers['x-forwarded-for'] === 'string') {
    return req.headers['x-forwarded-for'].split(',')[0].trim();
  }
  return req.socket?.remoteAddress ?? 'unknown';
}

function enforceRateLimit(req, res, bucket, max) {
  const result = consumeRateLimit(`${bucket}:${clientIp(req)}`, max);
  res.setHeader('X-RateLimit-Limit', String(result.limit));
  res.setHeader('X-RateLimit-Remaining', String(result.remaining));
  res.setHeader('X-RateLimit-Reset', String(Math.ceil(result.resetAt / 1000)));
  if (!result.allowed) {
    res.setHeader('Retry-After', String(result.retryAfterSeconds));
    logger.warn('rate_limit_exceeded', { requestId: req.id, bucket, path: req.url });
    throw errors.tooManyRequests('Limite de requisicoes excedido. Tente novamente em instantes.');
  }
}

/* ------------------------------------------------------------------ *
 * Handlers
 * ------------------------------------------------------------------ */

const handlers = {
  'GET /health': async (req, res) => {
    // Endpoint publico e' deliberadamente minimo: sem versao, sem deps, sem dados.
    sendJson(res, 200, { status: 'ok' });
  },

  'GET /session': async (req, res, ctx) => {
    if (!ctx.auth) {
      sendJson(res, 200, { authenticated: false });
      return;
    }
    sendJson(res, 200, {
      authenticated: true,
      user: toPublicUser(ctx.auth.user),
      csrfToken: ctx.auth.csrfToken,
    });
  },

  'POST /auth/register': async (req, res, ctx) => {
    enforceRateLimit(req, res, 'auth', config.rateLimit.authMaxRequests);
    const { email, password } = registerSchema.parse(await readJsonBody(req));
    if (ctx.store.countUsers() === 0 && !config.isProduction) {
      logger.info('bootstrap_first_user', {});
    }
    if (ctx.store.findUserByEmail(email)) {
      throw errors.conflict('Ja existe uma conta com este e-mail.');
    }
    const hashed = await auth.hashPassword(password);
    const user = ctx.store.createUser({ email, ...hashed });
    const { token } = ctx.store.createSession({
      userId: user.id,
      ip: clientIp(req),
      userAgent: req.headers['user-agent'],
    });
    auth.setSessionCookie(res, token);
    logger.info('user_registered', { requestId: req.id, userId: logger.anonymizeIdentifier(user.id) });
    sendJson(res, 201, { user: toPublicUser(user) });
  },

  'POST /auth/login': async (req, res, ctx) => {
    const body = await readJsonBody(req);
    const { email, password } = loginSchema.parse(body);
    enforceRateLimit(req, res, 'auth', config.rateLimit.authMaxRequests);
    enforceRateLimit(req, res, `acct:${logger.anonymizeIdentifier(email)}`, config.rateLimit.authMaxRequests * 3);
    const user = await auth.authenticate(ctx.store, { email, password });

    // Rotacao de sessao: novo id a cada login (anti fixacao de sessao).
    if (ctx.auth) ctx.store.deleteSession(ctx.auth.token);
    const { token } = ctx.store.createSession({
      userId: user.id,
      ip: clientIp(req),
      userAgent: req.headers['user-agent'],
    });
    auth.setSessionCookie(res, token);
    logger.info('login_success', { requestId: req.id, userId: logger.anonymizeIdentifier(user.id) });
    sendJson(res, 200, { user: toPublicUser(user) });
  },

  'POST /auth/logout': async (req, res, ctx) => {
    verifyCsrf(req, ctx);
    if (ctx.auth) ctx.store.deleteSession(ctx.auth.token);
    auth.clearSessionCookie(res);
    sendJson(res, 204, {});
  },

  'GET /todos': async (req, res, ctx) => {
    auth.requireAuth(ctx);
    const params = todoListSchema.parse(ctx.query);
    const result = ctx.store.listTodos({ ownerId: ctx.auth.user.id, ...params });
    sendJson(res, 200, {
      items: result.items.map(toPublicTodo),
      total: result.total,
      limit: result.limit,
      offset: result.offset,
    });
  },

  'POST /todos': async (req, res, ctx) => {
    auth.requireAuth(ctx);
    verifyCsrf(req, ctx);
    enforceRateLimit(req, res, 'write', config.rateLimit.writeMaxRequests);

    const idemKey = req.headers['idempotency-key'];
    if (idemKey !== undefined) {
      if (typeof idemKey !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(idemKey)) {
        throw errors.badRequest('Header Idempotency-Key invalido.');
      }
      const cacheKey = `${ctx.auth.user.id}:${idemKey}`;
      const cached = lookupIdempotent(cacheKey);
      if (cached) {
        sendJson(res, cached.status, cached.payload, { 'Idempotency-Replayed': 'true' });
        return;
      }
    }

    const payload = todoCreateSchema.parse(await readJsonBody(req));
    const todo = ctx.store.createTodo({ ownerId: ctx.auth.user.id, ...payload });
    logger.info('todo_created', { requestId: req.id, todoId: todo.id, priority: todo.priority });
    const response = { todo: toPublicTodo(todo) };
    if (idemKey !== undefined) rememberIdempotent(`${ctx.auth.user.id}:${idemKey}`, { status: 201, payload: response });
    sendJson(res, 201, response);
  },

  'PATCH /todos/:id': async (req, res, ctx) => {
    auth.requireAuth(ctx);
    verifyCsrf(req, ctx);
    enforceRateLimit(req, res, 'write', config.rateLimit.writeMaxRequests);
    const todoId = parseTodoId(ctx.params.id);
    const patch = todoPatchSchema.parse(await readJsonBody(req));
    const updated = ctx.store.updateTodoForOwner({ ownerId: ctx.auth.user.id, todoId, patch });
    if (!updated) throw errors.notFound('Tarefa nao encontrada.');
    sendJson(res, 200, { todo: toPublicTodo(updated) });
  },

  'DELETE /todos/:id': async (req, res, ctx) => {
    auth.requireAuth(ctx);
    verifyCsrf(req, ctx);
    enforceRateLimit(req, res, 'write', config.rateLimit.writeMaxRequests);
    const todoId = parseTodoId(ctx.params.id);
    const removed = ctx.store.deleteTodoForOwner({ ownerId: ctx.auth.user.id, todoId });
    if (!removed) throw errors.notFound('Tarefa nao encontrada.');
    logger.info('todo_deleted', { requestId: req.id, todoId });
    sendJson(res, 204, {});
  },
};

/* ------------------------------------------------------------------ *
 * Roteador
 * ------------------------------------------------------------------ */

const ROUTES = [
  ['GET', /^\/health$/, 'GET /health'],
  ['GET', /^\/session$/, 'GET /session'],
  ['POST', /^\/auth\/register$/, 'POST /auth/register'],
  ['POST', /^\/auth\/login$/, 'POST /auth/login'],
  ['POST', /^\/auth\/logout$/, 'POST /auth/logout'],
  ['GET', /^\/todos$/, 'GET /todos'],
  ['POST', /^\/todos$/, 'POST /todos'],
  ['PATCH', /^\/todos\/([^/]+)$/, 'PATCH /todos/:id'],
  ['DELETE', /^\/todos\/([^/]+)$/, 'DELETE /todos/:id'],
];

function matchRoute(method, pathname) {
  for (const [routeMethod, pattern, key] of ROUTES) {
    if (routeMethod !== method) continue;
    const match = pattern.exec(pathname);
    if (match) {
      return { key, params: match.slice(1).map(decodeURIComponentSafely) };
    }
  }
  return null;
}

function decodeURIComponentSafely(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

async function handleApi(req, res, ctx) {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname.startsWith(API_PREFIX)
    ? url.pathname.slice(API_PREFIX.length)
    : url.pathname;
  if (pathname === '' || pathname === '/') throw errors.notFound('Endpoint nao encontrado.');

  const route = matchRoute(req.method, pathname);
  if (!route) throw errors.notFound('Endpoint nao encontrado.');

  // Host allowlist e checado antes de qualquer trabalho (Host Header Injection).
  enforceRateLimit(req, res, 'global', config.rateLimit.maxRequests);

  if (WRITE_METHODS.has(req.method) && !originAllowed(req)) {
    // Sem Origin (cliente nao-navegador) o token CSRF ainda e' obrigatorio.
    logger.warn('cross_origin_write_blocked', { requestId: req.id, origin: req.headers.origin ?? null });
  }

  // Rotas com parametro nomeado: params sao posicionais no regex, expor por nome.
  ctx.params = { id: route.params[0] };
  ctx.query = Object.fromEntries(url.searchParams.entries());
  const handler = handlers[route.key];
  await handler(req, res, ctx);
}

module.exports = { handleApi, sendError, sendJson, clientIp, API_PREFIX, originAllowed, idempotency };