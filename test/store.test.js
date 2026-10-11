'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

// Ambiente de teste isolado: diretório de dados proprio, portas/origens dedicated.
const TEST_ROOT = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'todo-terminal-test-'));
process.env.NODE_ENV = 'test';
process.env.DATA_DIR = TEST_ROOT;
process.env.LOG_LEVEL = 'silent';
process.env.TRUSTED_ORIGINS = 'http://127.0.0.1:3111';
process.env.TRUSTED_HOSTS = '127.0.0.1';
process.env.RATE_LIMIT_MAX = '10000';
process.env.RATE_LIMIT_AUTH_MAX = '1000';
process.env.RATE_LIMIT_WRITE_MAX = '1000';
process.env.SESSION_IDLE_MINUTES = '30';

// pointing data dir to temp
const config = require('../src/config');
for (const key of ['users', 'todos', 'sessions']) config.paths[key] = path.join(TEST_ROOT, `${key}.json`);
config.paths.data = TEST_ROOT;

const { JsonStore } = require('../src/store');
const auth = require('../src/auth');
const crypto = require('node:crypto');

function newStore() {
  fs.rmSync(path.join(TEST_ROOT, 'store.marker'), { force: true });
  return new JsonStore();
}

async function seed(store, email, password) {
  const hashed = await auth.hashPassword(password);
  return store.createUser({ email, ...hashed });
}

test('hash de senha: scrypt com salt unico, nunca reversivel', async () => {
  const a = await auth.hashPassword('senha-super-segura-123');
  const b = await auth.hashPassword('senha-super-segura-123');
  assert.notEqual(a.salt, b.salt);
  assert.notEqual(a.passwordHash, b.passwordHash);
  assert.ok(!a.passwordHash.includes('senha-super-segura-123'));
});

test('verificacao de senha aceita correta e rejeita incorreta', async () => {
  const store = newStore();
  const user = await seed(store, 'user@test.dev', 'senha-super-segura-123');
  const found = await auth.authenticate(store, { email: 'user@test.dev', password: 'senha-super-segura-123' });
  assert.equal(found.id, user.id);
  await assert.rejects(() => auth.authenticate(store, { email: 'user@test.dev', password: 'errada-123' }));
});

test('sessao: token opaco, hash persistido, expiracao por ociosidade', async () => {
  const store = newStore();
  const user = await seed(store, 'sess@test.dev', 'senha-super-segura-123');
  const { token } = store.createSession({ userId: user.id, ip: '127.0.0.1', userAgent: 'test' });

  // Token em claro nunca e' persistido
  const raw = fs.readFileSync(config.paths.sessions, 'utf8');
  assert.ok(!raw.includes(token));

  assert.ok(store.getSession(token));

  // Forca expiracao ociosa
  const sessionEntry = store.getSession(token).session;
  sessionEntry.lastSeenAt = Date.now() - config.session.idleTimeoutMs - 1000;
  store.persistSessions();
  assert.equal(store.getSession(token), null);
});

test('IDOR: usuario B nao acessa/edita/deleta tarefa de A', async () => {
  const store = newStore();
  const alice = await seed(store, 'alice@test.dev', 'senha-super-segura-123');
  const bob = await seed(store, 'bob@test.dev', 'senha-super-segura-123');
  const todo = store.createTodo({ ownerId: alice.id, title: 'privado da alice', priority: 'high' });

  assert.equal(store.findTodoForOwner({ ownerId: bob.id, todoId: todo.id }), null);
  assert.equal(store.updateTodoForOwner({ ownerId: bob.id, todoId: todo.id, patch: { title: 'hack' } }), null);
  assert.equal(store.deleteTodoForOwner({ ownerId: bob.id, todoId: todo.id }), null);
  assert.equal(store.findTodoForOwner({ ownerId: alice.id, todoId: todo.id }).title, 'privado da alice');
});

test('listagem isola por owner', async () => {
  const store = newStore();
  const alice = await seed(store, 'alice2@test.dev', 'senha-super-segura-123');
  const bob = await seed(store, 'bob2@test.dev', 'senha-super-segura-123');
  store.createTodo({ ownerId: alice.id, title: 'a1', priority: 'normal' });
  store.createTodo({ ownerId: bob.id, title: 'b1', priority: 'normal' });

  const aliceList = store.listTodos({ ownerId: alice.id, status: 'all', limit: 10, offset: 0 });
  assert.equal(aliceList.total, 1);
  assert.equal(aliceList.items[0].title, 'a1');
});

test('persistencia atômica (tmp + rename) e leitura pos-escrita', async () => {
  const store = newStore();
  const user = await seed(store, 'persist@test.dev', 'senha-super-segura-123');
  const todo = store.createTodo({ ownerId: user.id, title: 'duravel', priority: 'normal' });
  const reopened = new JsonStore();
  assert.equal(reopened.findTodoForOwner({ ownerId: user.id, todoId: todo.id }).title, 'duravel');
});

test('corrupcao de arquivo nao e sobrescrita silenciosamente', () => {
  const store = newStore();
  fs.writeFileSync(config.paths.todos, '{isto nao e json', 'utf8');
  assert.throws(() => new JsonStore());
});

test.after(() => {
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
});