'use strict';

const crypto = require('node:crypto');
const config = require('./config');

/* ------------------------------------------------------------------ *
 * Erros de aplicacao (contrato estavel, sem stack trace ao cliente)
 * ------------------------------------------------------------------ */

class AppError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.expose = true;
  }
}

const errors = {
  badRequest: (msg = 'Requisicao invalida.', code = 'BAD_REQUEST', details) => new AppError(400, code, msg, details),
  unauthorized: (msg = 'Autenticacao necessaria.') => new AppError(401, 'UNAUTHORIZED', msg),
  forbidden: (msg = 'Acesso negado.') => new AppError(403, 'FORBIDDEN', msg),
  notFound: (msg = 'Recurso nao encontrado.') => new AppError(404, 'NOT_FOUND', msg),
  conflict: (msg = 'Conflito de estado.') => new AppError(409, 'CONFLICT', msg),
  payloadTooLarge: (msg = 'Payload excede o limite permitido.') => new AppError(413, 'PAYLOAD_TOO_LARGE', msg),
  unsupportedMedia: (msg = 'Content-Type nao suportado.') => new AppError(415, 'UNSUPPORTED_MEDIA_TYPE', msg),
  tooManyRequests: (msg = 'Limite de requisicoes excedido.') => new AppError(429, 'RATE_LIMITED', msg),
};

/* ------------------------------------------------------------------ *
 * Cabecalhos de seguranca
 * ------------------------------------------------------------------ */

const STATIC_SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy': config.security.csp,
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'X-Permitted-Cross-Domain-Policies': 'none',
});

function isSecureRequest(req) {
  if (config.trustProxyHttps && typeof req.headers['x-forwarded-proto'] === 'string') {
    return req.headers['x-forwarded-proto'].split(',')[0].trim() === 'https';
  }
  return Boolean(req.socket && req.socket.encrypted);
}

/**
 * Aplica headers. Em respostas autenticadas usa-se 'no-store' para
 * evitar cache poisoning e vazamento de dados via cache compartilhado.
 */
function applySecurityHeaders(req, res, { authenticated = false } = {}) {
  for (const [name, value] of Object.entries(STATIC_SECURITY_HEADERS)) {
    res.setHeader(name, value);
  }
  if (isSecureRequest(req)) {
    res.setHeader('Strict-Transport-Security', config.security.hsts);
  }
  res.setHeader('X-Request-Id', req.id);
  res.setHeader('Cache-Control', authenticated ? 'no-store, no-cache, must-revalidate, private' : 'no-store');
  res.setHeader('Pragma', 'no-cache');
  // Nao anunciar stack (X-Powered-By e' padrao do Node; nunca permitir override).
  res.removeHeader('X-Powered-By');
}

/* ------------------------------------------------------------------ *
 * Host / Origin allowlist (Host Header Injection, CSRF cross-origin)
 * ------------------------------------------------------------------ */

function hostAllowed(req) {
  const raw = String(req.headers.host || '').toLowerCase().trim();
  if (!raw || raw.length > 255) return false;
  // Remove porta (ou colchetes de IPv6) antes da comparacao com a allowlist.
  let hostname = raw;
  if (hostname.startsWith('[')) {
    const end = hostname.indexOf(']');
    hostname = end === -1 ? hostname : hostname.slice(1, end);
  } else {
    const colon = hostname.indexOf(':');
    if (colon !== -1) hostname = hostname.slice(0, colon);
  }
  if (!/^[a-z0-9.:_-]+$/u.test(hostname)) return false;
  return config.trustedHosts.some((allowed) => hostname === allowed || hostname.endsWith(`.${allowed}`));
}

function originAllowed(req) {
  const origin = req.headers.origin;
  if (origin === undefined) return null; // clientes sem Origin (ex.: curl) -> decisão do chamador
  const normalized = String(origin).replace(/\/+$/, '');
  return config.trustedOrigins.includes(normalized);
}

/* ------------------------------------------------------------------ *
 * Rate limiting (janela deslizante aproximada, em memoria)
 * ------------------------------------------------------------------ */

const buckets = new Map();

function pruneBuckets(now) {
  if (buckets.size <= config.rateLimit.maxTrackedKeys) return;
  const cutoff = now - config.rateLimit.windowMs * 2;
  for (const [key, bucket] of buckets) {
    if (bucket.resetAt < cutoff) buckets.delete(key);
  }
}

/**
 * Retorna { allowed, remaining, limit, resetAt }.
 * Deliberadamente falho-fechado: se o mapa crescer alem do teto, o oldest e' descartado.
 */
function consumeRateLimit(key, max) {
  const now = Date.now();
  pruneBuckets(now);
  let bucket = buckets.get(key);
  if (!bucket) {
    bucket = { count: 0, resetAt: now + config.rateLimit.windowMs };
    buckets.set(key, bucket);
  }
  if (bucket.resetAt <= now) {
    bucket.count = 0;
    bucket.resetAt = now + config.rateLimit.windowMs;
  }
  bucket.count += 1;
  const remaining = Math.max(0, max - bucket.count);
  return {
    allowed: bucket.count <= max,
    remaining,
    limit: max,
    resetAt: bucket.resetAt,
    retryAfterSeconds: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)),
  };
}

function clearRateLimits() {
  buckets.clear();
}

/* ------------------------------------------------------------------ *
 * Leitura de corpo com limite rigido (anti-DoS / slow-loris de memoria)
 * ------------------------------------------------------------------ */

function readJsonBody(req, maxBytes = config.limits.maxBodyBytes) {
  return new Promise((resolve, reject) => {
    const contentType = String(req.headers['content-type'] || '');
    const mediaType = contentType.split(';')[0].trim().toLowerCase();
    if (mediaType !== 'application/json') {
      return reject(errors.unsupportedMedia('Requer Content-Type: application/json'));
    }
    const declared = Number.parseInt(req.headers['content-length'] || '', 10);
    if (Number.isFinite(declared) && declared > maxBytes) {
      return reject(errors.payloadTooLarge(`Limite de payload: ${maxBytes} bytes.`));
    }
    const chunks = [];
    let size = 0;
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', fail);
      req.pause();
      reject(err);
    };
    function onData(chunk) {
      size += chunk.length;
      if (size > maxBytes) return fail(errors.payloadTooLarge(`Limite de payload: ${maxBytes} bytes.`));
      chunks.push(chunk);
    }
    function onEnd() {
      if (settled) return;
      settled = true;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (raw.trim() === '') return resolve({});
      let parsed;
      try {
        parsed = JSON.parse(raw);
      } catch {
        return reject(errors.badRequest('JSON invalido.'));
      }
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return reject(errors.badRequest('Corpo deve ser um objeto JSON.'));
      }
      resolve(parsed);
    }
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', fail);
  });
}

/* ------------------------------------------------------------------ *
 * Cookies e CSRF
 * ------------------------------------------------------------------ */

function parseCookies(header) {
  const out = new Map();
  if (typeof header !== 'string' || header.length > 8192) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) continue;
    try {
      out.set(name, decodeURIComponent(value));
    } catch {
      out.set(name, value);
    }
  }
  return out;
}

function serializeSessionCookie(token, { clear = false } = {}) {
  const parts = [
    `${config.session.cookieName}=${clear ? '' : token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${clear ? 0 : Math.floor(config.session.absoluteTimeoutMs / 1000)}`,
  ];
  // Secure e' obrigatorio em producao com TLS; fora dele a cookie nao seria emitida.
  if (config.isProduction || config.trustProxyHttps) parts.push('Secure');
  return parts.join('; ');
}

function timingSafeEqualStrings(a, b) {
  const bufA = Buffer.from(String(a), 'utf8');
  const bufB = Buffer.from(String(b), 'utf8');
  if (bufA.length !== bufB.length) {
    // Ainda assim executa comparacao para nao vazar comprimento por tempo.
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/** Requests de escrita sem Content-Length/Transfer-Encoding sao rejeitados. */
function validateRequestFraming(req) {
  if (req.headers['transfer-encoding'] !== undefined) {
    throw errors.badRequest('Transfer-Encoding nao suportado.');
  }
  const cl = req.headers['content-length'];
  if (cl !== undefined && !/^\d{1,12}$/.test(cl)) {
    throw errors.badRequest('Content-Length invalido.');
  }
}

module.exports = {
  AppError,
  errors,
  applySecurityHeaders,
  hostAllowed,
  originAllowed,
  consumeRateLimit,
  clearRateLimits,
  readJsonBody,
  parseCookies,
  serializeSessionCookie,
  timingSafeEqualStrings,
  validateRequestFraming,
  STATIC_SECURITY_HEADERS,
};