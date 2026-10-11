'use strict';

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const config = require('./config');
const { errors, parseCookies, serializeSessionCookie, timingSafeEqualStrings } = require('./security');

const scryptAsync = promisify(crypto.scrypt);

/**
 * Hash de senha: scrypt (Argon2id/bcrypt exigiriam dependencia nativa ou
 * binaria). Parametros armazenados por usuario para permitir rotacao futura.
 */
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = await scryptAsync(password.normalize('NFC'), salt, config.scrypt.keylen, {
    N: config.scrypt.N,
    r: config.scrypt.r,
    p: config.scrypt.p,
    maxmem: config.scrypt.maxmem,
  });
  return {
    salt: salt.toString('base64'),
    passwordHash: derived.toString('base64'),
    params: { N: config.scrypt.N, r: config.scrypt.r, p: config.scrypt.p, keylen: config.scrypt.keylen },
  };
}

async function verifyPassword(password, user) {
  const salt = Buffer.from(user.salt, 'base64');
  const expected = Buffer.from(user.passwordHash, 'base64');
  let derived;
  try {
    derived = await scryptAsync(password.normalize('NFC'), salt, expected.length, {
      N: user.scrypt.N,
      r: user.scrypt.r,
      p: user.scrypt.p,
      maxmem: config.scrypt.maxmem,
    });
  } catch {
    return false;
  }
  return crypto.timingSafeEqual(derived, expected);
}

/**
 * Verificacao de credencial com tempo constante em relacao a existencia do usuario.
 * Para usuario inexistente, executa um hash descartavel (dummy) para nao criar
 * oraculo de enumeracao por tempo de resposta.
 */
const DUMMY_HASH = { salt: 'AAAAAAAAAAAAAAAAAAAAAA==', passwordHash: 'A'.repeat(86), scrypt: { N: config.scrypt.N, r: config.scrypt.r, p: config.scrypt.p } };

async function authenticate(store, { email, password }) {
  const user = store.findUserByEmail(email);
  if (!user) {
    await verifyPassword(password, DUMMY_HASH);
    throw errors.unauthorized('Credenciais invalidas.');
  }
  const ok = await verifyPassword(password, user);
  if (!ok) throw errors.unauthorized('Credenciais invalidas.');
  return user;
}

function readSessionToken(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies.get(config.session.cookieName);
  return token && typeof token === 'string' ? token : null;
}

/** Resolucao do contexto autenticado (deny-by-default). */
function resolveSession(req, store) {
  const token = readSessionToken(req);
  if (!token) return null;
  const entry = store.getSession(token);
  if (!entry) return null;
  const user = store.findUserById(entry.session.userId);
  if (!user) {
    store.deleteSession(token);
    return null;
  }
  return { token, session: entry.session, user, csrfToken: entry.session.csrfToken };
}

function requireAuth(ctx) {
  if (!ctx.auth) throw errors.unauthorized();
  return ctx.auth;
}

/**
 * Protecao CSRF: token por sessao (header) + verificacao de Origin.
 * Cookie SameSite=Strict e' defesa adicional, nao unica.
 */
function verifyCsrf(req, ctx, { required = true } = {}) {
  if (!required) return;
  const origin = req.headers.origin;
  if (typeof origin === 'string' && origin !== 'null') {
    const allowed = config.trustedOrigins.map((o) => o.toLowerCase());
    if (!allowed.includes(origin.replace(/\/+$/, '').toLowerCase())) {
      throw errors.forbidden('Origem nao autorizada.');
    }
  } else {
    const secFetchSite = req.headers['sec-fetch-site'];
    // Navegadores sempre enviam Sec-Fetch-Site em mutacoes; ausencia em cliente
    // nao-navegador e' permitida porque o token CSRF ainda e' exigido.
    if (typeof secFetchSite === 'string' && ['cross-site', 'same-site'].includes(secFetchSite)) {
      throw errors.forbidden('Origem nao autorizada.');
    }
  }
  const header = req.headers[config.session.csrfHeader];
  if (typeof header !== 'string' || !header) {
    throw errors.forbidden('Token CSRF ausente.');
  }
  if (!ctx.auth || !timingSafeEqualStrings(header, ctx.auth.csrfToken)) {
    throw errors.forbidden('Token CSRF invalido.');
  }
}

/** Rotacao de id de sessao apos evento de privilegio (login). */
function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', serializeSessionCookie(token));
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', serializeSessionCookie('', { clear: true }));
}

module.exports = {
  hashPassword,
  verifyPassword,
  authenticate,
  resolveSession,
  requireAuth,
  verifyCsrf,
  setSessionCookie,
  clearSessionCookie,
  readSessionToken,
};