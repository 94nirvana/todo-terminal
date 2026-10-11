'use strict';

/**
 * Configuracao unica da aplicacao.
 * Regra AppSec: nenhuma variavel de ambiente e' assumida como confiavel;
 * toda entrada de ambiente passa por allowlist + validacao + valor padrao seguro.
 */

const path = require('node:path');

function str(name, fallback, allowed) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = String(raw);
  if (allowed && !allowed.includes(value)) {
    throw new Error(`Config invalida: ${name} deve ser um de [${allowed.join(', ')}]`);
  }
  return value;
}

function int(name, fallback, min, max) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`Config invalida: ${name} deve ser inteiro entre ${min} e ${max}`);
  }
  return value;
}

function bool(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  throw new Error(`Config invalida: ${name} deve ser "true" ou "false"`);
}

const rootDir = path.resolve(__dirname, '..');

const env = str('NODE_ENV', 'development', ['development', 'test', 'production']);
const isProduction = env === 'production';

const config = {
  env,
  isProduction,
  host: str('HOST', '127.0.0.1'),
  port: int('PORT', 3000, 0, 65535),

  // Origens autorizadas para URLs absolutas, CORS, Origin/Referer e Host.
  // Allowlist -> evita Host Header Injection e CSRF cross-origin.
  trustedOrigins: str('TRUSTED_ORIGINS', 'http://127.0.0.1:3000,http://localhost:3000')
    .split(',')
    .map((o) => o.trim().replace(/\/+$/, ''))
    .filter(Boolean),

  trustedHosts: str('TRUSTED_HOSTS', '127.0.0.1,localhost')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean),

  // HSTS e cookie Secure so' com TLS terminado antes da app (reverse proxy).
  trustProxyHttps: bool('TRUST_PROXY_HTTPS', false),

  paths: {
    root: rootDir,
    public: path.join(rootDir, 'public'),
    data: path.join(rootDir, 'data'),
    users: path.join(rootDir, 'data', 'users.json'),
    todos: path.join(rootDir, 'data', 'todos.json'),
    sessions: path.join(rootDir, 'data', 'sessions.json'),
  },

  limits: {
    maxBodyBytes: int('MAX_BODY_BYTES', 16 * 1024, 1024, 1024 * 1024),
    maxTitleLength: 120,
    maxDescriptionLength: 1000,
    maxTodoPageSize: 100,
    defaultTodoPageSize: 50,
    maxUsers: int('MAX_USERS', 100, 1, 10000),
    minPasswordLength: 12,
    maxPasswordLength: 200,
  },

  session: {
    cookieName: 'todo_sid',
    csrfHeader: 'x-csrf-token',
    idleTimeoutMs: int('SESSION_IDLE_MINUTES', 30, 1, 1440) * 60 * 1000,
    absoluteTimeoutMs: int('SESSION_ABSOLUTE_HOURS', 12, 1, 720) * 60 * 60 * 1000,
    renewThresholdMs: 5 * 60 * 1000,
  },

  rateLimit: {
    windowMs: int('RATE_LIMIT_WINDOW_MS', 60 * 1000, 1000, 3600 * 1000),
    maxRequests: int('RATE_LIMIT_MAX', 120, 1, 100000),
    authMaxRequests: int('RATE_LIMIT_AUTH_MAX', 10, 1, 1000),
    writeMaxRequests: int('RATE_LIMIT_WRITE_MAX', 60, 1, 10000),
    maxTrackedKeys: int('RATE_LIMIT_MAX_KEYS', 20000, 100, 1000000),
  },

  scrypt: {
    N: int('SCRYPT_N', 16384, 2 ** 14, 2 ** 20),
    r: 8,
    p: 1,
    keylen: 64,
    maxmem: 64 * 1024 * 1024,
  },

  security: {
    // CSP estrita: sem 'unsafe-inline' e sem 'unsafe-eval' (ADR-002).
    csp: [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "manifest-src 'none'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
      "sandbox allow-scripts allow-forms allow-same-origin",
    ].join('; '),
    hsts: 'max-age=63072000; includeSubDomains; preload',
  },

  logLevel: str('LOG_LEVEL', isProduction ? 'info' : 'debug', ['debug', 'info', 'warn', 'error', 'silent']),
};

module.exports = config;