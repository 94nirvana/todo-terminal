'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const config = require('./config');
const { errors } = require('./security');

/**
 * Persistencia em arquivo JSON com escrita atomica (tmp + rename + fsync).
 *
 * Decisao (ADR-003): monólito modular com armazenamento local em arquivo.
 * Complexidade++, throughput++, operacao--. Valido enquanto o volume for
 * pequeno (limite de MAX_USERS). Migrar para SQLite/Postgres e' o caminho
 * de evolucao, com o dominio isolado em src/domain por tras desta fronteira.
 */

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

function emptyCollection() {
  return { version: 1, items: {} };
}

function readCollection(file, fallback) {
  try {
    const raw = fs.readFileSync(file, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== 'object' || typeof parsed.items !== 'object') {
      return structuredClone(fallback);
    }
    return parsed;
  } catch (err) {
    if (err.code === 'ENOENT') return structuredClone(fallback);
    // Arquivo corrompido: nao sobrescreve silenciosamente dados existentes.
    throw new Error(`Falha ao ler ${path.basename(file)}: ${err.code || 'EUNKNOWN'}`);
  }
}

function writeCollectionAtomic(file, data) {
  ensureDir(path.dirname(file));
  const tmp = `${file}.${process.pid}.tmp`;
  const payload = `${JSON.stringify(data, null, 2)}\n`;
  const fd = fs.openSync(tmp, 'w', 0o600);
  try {
    fs.writeFileSync(fd, payload, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, file);
}

/** Hash de token em hexadecimal (tokens nunca sao persistidos em claro). */
function hashToken(token) {
  return crypto.createHash('sha256').update(String(token), 'utf8').digest('hex');
}

class JsonStore {
  constructor() {
    ensureDir(config.paths.data);
    this.users = readCollection(config.paths.users, emptyCollection());
    this.todos = readCollection(config.paths.todos, emptyCollection());
    this.sessions = readCollection(config.paths.sessions, emptyCollection());
  }

  persistUsers() { writeCollectionAtomic(config.paths.users, this.users); }
  persistTodos() { writeCollectionAtomic(config.paths.todos, this.todos); }
  persistSessions() { writeCollectionAtomic(config.paths.sessions, this.sessions); }

  /* ------------------------- Usuarios ------------------------- */

  countUsers() {
    return Object.keys(this.users.items).length;
  }

  findUserByEmail(email) {
    return this.users.items[hashToken(email)] ?? null;
  }

  findUserById(id) {
    for (const user of Object.values(this.users.items)) {
      if (user.id === id) return user;
    }
    return null;
  }

  createUser({ email, passwordHash, salt, params }) {
    if (this.countUsers() >= config.limits.maxUsers) {
      throw errors.conflict('Limite de usuarios atingido.');
    }
    const id = crypto.randomUUID();
    const user = {
      id,
      email,
      passwordHash,
      salt,
      scrypt: params,
      createdAt: new Date().toISOString(),
    };
    this.users.items[hashToken(email)] = user;
    this.persistUsers();
    return user;
  }

  /* ------------------------- Sessoes ------------------------- */

  createSession({ userId, ip, userAgent }) {
    const token = crypto.randomBytes(32).toString('base64url');
    const csrfToken = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    this.sessions.items[hashToken(token)] = {
      userId,
      csrfToken,
      createdAt: now,
      lastSeenAt: now,
      ipHash: hashToken(String(ip || '')),
      userAgent: String(userAgent || '').slice(0, 120),
    };
    this.persistSessions();
    return { token, csrfToken };
  }

  getSession(token) {
    if (!token || typeof token !== 'string' || token.length > 128) return null;
    const session = this.sessions.items[hashToken(token)];
    if (!session) return null;
    const now = Date.now();
    if (now - session.createdAt > config.session.absoluteTimeoutMs || now - session.lastSeenAt > config.session.idleTimeoutMs) {
      this.deleteSession(token);
      return null;
    }
    return { session, token };
  }

  touchSession(token, session) {
    session.lastSeenAt = Date.now();
    this.persistSessions();
  }

  deleteSession(token) {
    if (!token) return;
    delete this.sessions.items[hashToken(token)];
    this.persistSessions();
  }

  /** Invalidacao por mudanca de privilegio/senha (ADR-001). */
  deleteSessionsForUser(userId) {
    let removed = 0;
    for (const [key, session] of Object.entries(this.sessions.items)) {
      if (session.userId === userId) {
        delete this.sessions.items[key];
        removed += 1;
      }
    }
    if (removed > 0) this.persistSessions();
    return removed;
  }

  purgeExpiredSessions() {
    const now = Date.now();
    let removed = 0;
    for (const [key, session] of Object.entries(this.sessions.items)) {
      const expired = now - session.createdAt > config.session.absoluteTimeoutMs
        || now - session.lastSeenAt > config.session.idleTimeoutMs;
      if (expired) {
        delete this.sessions.items[key];
        removed += 1;
      }
    }
    if (removed > 0) this.persistSessions();
    return removed;
  }

  /* ------------------------- Todos ------------------------- */

  listTodos({ ownerId, status, limit, offset }) {
    const all = Object.values(this.todos.items).filter((todo) => todo.ownerId === ownerId);
    const filtered = status === 'all' ? all : all.filter((todo) => (status === 'done' ? todo.done : !todo.done));
    filtered.sort((a, b) => {
      if (a.done !== b.done) return a.done ? 1 : -1;
      if (a.priority !== b.priority) return priorityRank(b.priority) - priorityRank(a.priority);
      return a.createdAt < b.createdAt ? 1 : -1;
    });
    return {
      items: filtered.slice(offset, offset + limit),
      total: filtered.length,
      limit,
      offset,
    };
  }

  /** Autorizacao avaliada no recurso: todo sem ownerId correspondente => 404. */
  findTodoForOwner({ ownerId, todoId }) {
    const todo = this.todos.items[todoId];
    if (!todo || todo.ownerId !== ownerId) return null;
    return todo;
  }

  createTodo({ ownerId, title, description, priority }) {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const todo = {
      id,
      ownerId,
      title,
      description: description ?? null,
      priority,
      done: false,
      createdAt: now,
      updatedAt: now,
      completedAt: null,
    };
    this.todos.items[id] = todo;
    this.persistTodos();
    return todo;
  }

  updateTodoForOwner({ ownerId, todoId, patch }) {
    const todo = this.findTodoForOwner({ ownerId, todoId });
    if (!todo) return null;
    const next = { ...todo, ...patch };
    next.updatedAt = new Date().toISOString();
    if (patch.done !== undefined && patch.done !== todo.done) {
      next.completedAt = patch.done ? next.updatedAt : null;
    }
    this.todos.items[todoId] = next;
    this.persistTodos();
    return next;
  }

  deleteTodoForOwner({ ownerId, todoId }) {
    const todo = this.findTodoForOwner({ ownerId, todoId });
    if (!todo) return null;
    delete this.todos.items[todoId];
    this.persistTodos();
    return todo;
  }

  deleteTodosForUser(ownerId) {
    let removed = 0;
    for (const [key, todo] of Object.entries(this.todos.items)) {
      if (todo.ownerId === ownerId) {
        delete this.todos.items[key];
        removed += 1;
      }
    }
    if (removed > 0) this.persistTodos();
    return removed;
  }
}

function priorityRank(priority) {
  return priority === 'high' ? 2 : priority === 'normal' ? 1 : 0;
}

/** View publica: nunca expoe campos internos (principio de menor exposicao). */
function toPublicUser(user) {
  return { id: user.id, email: user.email, createdAt: user.createdAt };
}

function toPublicTodo(todo) {
  return {
    id: todo.id,
    title: todo.title,
    description: todo.description,
    priority: todo.priority,
    done: todo.done,
    createdAt: todo.createdAt,
    updatedAt: todo.updatedAt,
    completedAt: todo.completedAt,
  };
}

module.exports = { JsonStore, toPublicUser, toPublicTodo, hashToken };