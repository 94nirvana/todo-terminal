'use strict';

const config = require('./config');
const { errors } = require('./security');

/**
 * Validacao por ALLOWLIST: campos desconhecidos sao rejeitados (anti mass-assignment),
 * tipos sao checados e strings sao normalizadas (NFC + remocao de controles).
 */

const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u;
const EMAIL_RE = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/u;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function assertPlainObject(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw errors.badRequest(`Campo "${field}" deve ser objeto JSON.`);
  }
  return value;
}

function rejectUnknownFields(body, allowed, prefix = '') {
  for (const key of Object.keys(body)) {
    if (!allowed.includes(key)) {
      throw errors.badRequest(
        `Campo desconhecido: "${prefix}${key}".`,
        'UNKNOWN_FIELD',
        { allowed },
      );
    }
  }
}

/** Remove controles Unicode, normaliza NFC e limita comprimento em caracteres (nao bytes). */
function cleanText(value, { field, min = 1, max, required = true }) {
  if (value === undefined || value === null) {
    if (required) throw errors.badRequest(`Campo "${field}" e' obrigatorio.`);
    return undefined;
  }
  if (typeof value !== 'string') throw errors.badRequest(`Campo "${field}" deve ser string.`);
  const normalized = value.normalize('NFC').replace(CONTROL_CHARS, '').trim();
  if (normalized === '') {
    if (required) throw errors.badRequest(`Campo "${field}" nao pode ser vazio.`);
    return undefined;
  }
  const length = [...normalized].length;
  if (length < min) throw errors.badRequest(`Campo "${field}" deve ter ao menos ${min} caracteres.`);
  if (max !== undefined && length > max) {
    throw errors.badRequest(`Campo "${field}" deve ter no maximo ${max} caracteres.`, 'FIELD_TOO_LONG');
  }
  return normalized;
}

function validateEmail(value) {
  // Normalizado para minusculas: garante unicidade e correspondencia no login.
  const email = cleanText(value, { field: 'email', min: 3, max: 254 }).toLowerCase();
  if (!EMAIL_RE.test(email)) throw errors.badRequest('E-mail invalido.');
  return email;
}

function validatePassword(value, { field = 'password' } = {}) {
  if (typeof value !== 'string') throw errors.badRequest(`Campo "${field}" deve ser string.`);
  // Senha nao e' trimmed: espacos fazem parte do segredo.
  if (value.length < config.limits.minPasswordLength) {
    throw errors.badRequest(
      `Campo "${field}" deve ter ao menos ${config.limits.minPasswordLength} caracteres.`,
      'WEAK_PASSWORD',
    );
  }
  if (value.length > config.limits.maxPasswordLength) {
    throw errors.badRequest(`Campo "${field}" excede o tamanho maximo permitido.`, 'FIELD_TOO_LONG');
  }
  if (/^\s+$/u.test(value)) throw errors.badRequest('Senha nao pode ser apenas espacos.', 'WEAK_PASSWORD');
  return value;
}

/* ---------------------- Schemas por endpoint ---------------------- */

const registerSchema = {
  fields: ['email', 'password'],
  parse(body) {
    assertPlainObject(body, 'body');
    rejectUnknownFields(body, this.fields);
    return { email: validateEmail(body.email), password: validatePassword(body.password) };
  },
};

const loginSchema = {
  fields: ['email', 'password'],
  parse(body) {
    assertPlainObject(body, 'body');
    rejectUnknownFields(body, this.fields);
    // Nao aplicamos politica de senha forte no login (mensagem uniforme -> sem oraculo de enumeracao).
    if (typeof body.email !== 'string' || typeof body.password !== 'string') {
      throw errors.badRequest('Campos "email" e "password" sao obrigatorios.');
    }
    const email = body.email.normalize('NFC').trim().toLowerCase();
    if (email.length > 254 || body.password.length > config.limits.maxPasswordLength) {
      throw errors.badRequest('Credenciais invalidas.');
    }
    return { email, password: body.password };
  },
};

const PRIORITIES = new Set(['low', 'normal', 'high']);

const todoCreateSchema = {
  fields: ['title', 'description', 'priority'],
  parse(body) {
    assertPlainObject(body, 'body');
    rejectUnknownFields(body, this.fields);
    const priority = body.priority === undefined ? 'normal' : cleanText(body.priority, { field: 'priority', max: 10 });
    if (!PRIORITIES.has(priority)) {
      throw errors.badRequest('Campo "priority" deve ser low, normal ou high.');
    }
    return {
      title: cleanText(body.title, { field: 'title', min: 1, max: config.limits.maxTitleLength }),
      description: cleanText(body.description, {
        field: 'description',
        max: config.limits.maxDescriptionLength,
        required: false,
      }),
      priority,
    };
  },
};

const todoPatchSchema = {
  fields: ['title', 'description', 'priority', 'done'],
  parse(body) {
    assertPlainObject(body, 'body');
    rejectUnknownFields(body, this.fields);
    const patch = {};
    if (body.title !== undefined) {
      patch.title = cleanText(body.title, { field: 'title', min: 1, max: config.limits.maxTitleLength });
    }
    if (body.description !== undefined) {
      patch.description = body.description === null
        ? null
        : cleanText(body.description, {
          field: 'description',
          max: config.limits.maxDescriptionLength,
          required: false,
        }) ?? null;
    }
    if (body.priority !== undefined) {
      const priority = cleanText(body.priority, { field: 'priority', max: 10 });
      if (!PRIORITIES.has(priority)) {
        throw errors.badRequest('Campo "priority" deve ser low, normal ou high.');
      }
      patch.priority = priority;
    }
    if (body.done !== undefined) {
      if (typeof body.done !== 'boolean') throw errors.badRequest('Campo "done" deve ser boolean.');
      patch.done = body.done;
    }
    if (Object.keys(patch).length === 0) {
      throw errors.badRequest('Nenhum campo alteravel informado.');
    }
    return patch;
  },
};

const QUERY_STATUS = new Set(['all', 'open', 'done']);

const todoListSchema = {
  parse(query) {
    const status = query.status === undefined ? 'open' : String(query.status);
    if (!QUERY_STATUS.has(status)) {
      throw errors.badRequest('Query "status" deve ser all, open ou done.');
    }
    const rawLimit = query.limit === undefined ? String(config.limits.defaultTodoPageSize) : String(query.limit);
    if (!/^\d{1,3}$/.test(rawLimit)) throw errors.badRequest('Query "limit" deve ser inteiro positivo.');
    const limit = Number.parseInt(rawLimit, 10);
    if (limit < 1 || limit > config.limits.maxTodoPageSize) {
      throw errors.badRequest(`Query "limit" deve estar entre 1 e ${config.limits.maxTodoPageSize}.`);
    }
    const rawOffset = query.offset === undefined ? '0' : String(query.offset);
    if (!/^\d{1,9}$/.test(rawOffset)) throw errors.badRequest('Query "offset" deve ser inteiro nao negativo.');
    const offset = Number.parseInt(rawOffset, 10);
    if (offset > 1_000_000) throw errors.badRequest('Query "offset" excede o maximo permitido.');
    return { status, limit, offset };
  },
};

function parseTodoId(rawId) {
  if (typeof rawId !== 'string' || !UUID_RE.test(rawId)) {
    // Resposta 404 (nao 400) para evitar oraculo de formato de id.
    throw errors.notFound('Recurso nao encontrado.');
  }
  return rawId.toLowerCase();
}

module.exports = {
  registerSchema,
  loginSchema,
  todoCreateSchema,
  todoPatchSchema,
  todoListSchema,
  parseTodoId,
  validateEmail,
  validatePassword,
  cleanText,
  PRIORITIES,
  UUID_RE,
};