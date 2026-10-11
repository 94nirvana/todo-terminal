'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const config = require('./src/config');
const logger = require('./src/logger');
const { AppError, applySecurityHeaders, hostAllowed, errors, validateRequestFraming } = require('./src/security');
const { resolveSession, clearSessionCookie } = require('./src/auth');
const { JsonStore } = require('./src/store');
const { handleApi, sendError, sendJson } = require('./src/api');
const { serveStatic } = require('./src/static');

const store = new JsonStore();

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const server = http.createServer(async (req, res) => {
  const startedAt = process.hrtime.bigint();
  req.id = crypto.randomUUID();

  let ctx = { store, auth: null };
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch {
    applySecurityHeaders(req, res);
    sendError(res, errors.badRequest('URL invalida.'), req);
    return;
  }

  // Bloqueio de path traversal e de URLs com credencial/hostile chars, antes do roteamento.
  const rawPath = url.pathname;
  const suspicious = rawPath.includes('..')
    || rawPath.includes('//')
    || rawPath.includes('\\')
    || /%2f|%5c/i.test(rawPath);
  const isApi = rawPath.startsWith('/api/');

  applySecurityHeaders(req, res, { authenticated: false });

  try {
    if (!hostAllowed(req)) {
      logger.warn('host_not_allowed', { requestId: req.id, host: req.headers.host ?? null });
      throw errors.forbidden('Host nao autorizado.');
    }
    if (suspicious && isApi) {
      logger.warn('suspicious_path', { requestId: req.id, path: rawPath });
      throw errors.badRequest('Path invalido.');
    }

    ctx.auth = resolveSession(req, store);
    if (ctx.auth) {
      applySecurityHeaders(req, res, { authenticated: true });
      store.touchSession(ctx.auth.token, ctx.auth.session);
    } else if (req.headers.cookie) {
      // Cookie invalido/expirado: limpa imediatamente (higiene de sessao).
      clearSessionCookie(res);
    }

    if (isApi) {
      if (req.method === 'OPTIONS') {
        sendJson(res, 204, {});
        return;
      }
      validateRequestFraming(req);
      await handleApi(req, res, ctx);
      return;
    }

    if (!SAFE_METHODS.has(req.method)) {
      throw errors.notFound('Recurso nao encontrado.');
    }

    // Sem SPA fallback: a aplicacao nao tem rotas client-side.
    // 404 explicito reduz superficie de ataque e evita "abrir" qualquer path.
    const served = await serveStatic(req, res, rawPath);
    if (!served) {
      sendError(res, errors.notFound('Recurso nao encontrado.'), req);
    }
  } catch (err) {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    sendError(res, err, req);
  } finally {
    const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    // Log de acesso sem PII: caminho, status, duracao e correlacao.
    logger.info('http_request', {
      requestId: req.id,
      method: req.method,
      path: (rawPath || '/').slice(0, 120),
      status: res.statusCode,
      durationMs: Math.round(durationMs * 100) / 100,
      userId: ctx.auth ? logger.anonymizeIdentifier(ctx.auth.user.id) : undefined,
    });
  }
});

// Timeouts explicitos: evita conexoes ociosasoccupando slots (slow-loris).
server.headersTimeout = 10_000;
server.requestTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 100;
server.maxRequestsPerSocket = 1000;

server.on('clientError', (err, socket) => {
  logger.warn('client_error', { errCode: err.code ?? 'UNKNOWN' });
  if (socket.writable && !socket.destroyed) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
});

function shutdown(signal) {
  logger.info('shutdown_started', { signal });
  const purged = store.purgeExpiredSessions();
  logger.info('shutdown_sessions_purged', { count: purged });
  server.close(() => {
    logger.info('shutdown_complete', {});
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => {
  logger.error('unhandled_rejection', { reason: String(reason).slice(0, 200) });
});
process.on('uncaughtException', (err) => {
  logger.error('uncaught_exception', { errMessage: err.message, stack: err.stack });
  shutdown('uncaughtException');
});

if (require.main === module) {
  server.listen(config.port, config.host, () => {
    logger.info('server_listening', {
      host: config.host,
      port: config.port,
      env: config.env,
      trustedOrigins: config.trustedOrigins,
    });
  });
}

module.exports = { server, store };