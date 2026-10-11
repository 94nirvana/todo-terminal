'use strict';

const config = require('./config');

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };
const threshold = LEVELS[config.logLevel] ?? LEVELS.info;

/**
 * Log estruturado (JSON Lines) com correlacao por requestId.
 * Regra AppSec: nunca logar senha, token, cookie, csrf ou PII (e-mail).
 */

const SECRET_KEYS = new Set([
  'password', 'senha', 'passwordhash', 'currentpassword', 'newpassword',
  'token', 'accesstoken', 'refreshtoken', 'authorization', 'cookie',
  'csrf', 'csrftoken', 'sessionid', 'secret',
]);

function scrub(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (depth > 4) return '[deep]';
  if (typeof value === 'string') return value.length > 512 ? `${value.slice(0, 512)}…[trunc]` : value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => scrub(v, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEYS.has(k.toLowerCase()) ? '[redacted]' : scrub(v, depth + 1);
    }
    return out;
  }
  return '[unserializable]';
}

/** E-mail nunca vai para log; apenas prefixo de dominio nao-PII opcional (desligado). */
function anonymizeIdentifier(value) {
  if (typeof value !== 'string' || value.length === 0) return 'anonymous';
  return `id:${value.slice(0, 8)}`;
}

function write(level, message, fields = {}) {
  if (LEVELS[level] < threshold) return;
  const record = {
    ts: new Date().toISOString(),
    level,
    msg: message,
    ...scrub(fields),
  };
  let line;
  try {
    line = JSON.stringify(record);
  } catch {
    line = JSON.stringify({ ts: record.ts, level, msg: message, note: 'unserializable-fields' });
  }
  if (level === 'error' || level === 'warn') process.stderr.write(`${line}\n`);
  else process.stdout.write(`${line}\n`);
}

module.exports = {
  debug: (msg, fields) => write('debug', msg, fields),
  info: (msg, fields) => write('info', msg, fields),
  warn: (msg, fields) => write('warn', msg, fields),
  error: (msg, fields) => write('error', msg, fields),
  anonymizeIdentifier,
};