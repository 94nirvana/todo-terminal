'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { validateEmail, validatePassword, registerSchema, todoCreateSchema, todoPatchSchema, todoListSchema, parseTodoId } = require('../src/validation');
const { errors } = require('../src/security');

function expectAppError(fn, code) {
  assert.throws(fn, (err) => {
    assert.equal(err.name, 'AppError');
    assert.equal(err.status >= 400 && err.status < 500, true);
    if (code) assert.equal(err.code, code);
    return true;
  });
}

test('rejeita campos desconhecidos (anti mass-assignment)', () => {
  expectAppError(() => registerSchema.parse({ email: 'a@b.com', password: 'x'.repeat(12), role: 'admin' }), 'UNKNOWN_FIELD');
  expectAppError(() => todoCreateSchema.parse({ title: 'x', isAdmin: true }), 'UNKNOWN_FIELD');
});

test('valida e-mail', () => {
  assert.equal(validateEmail('  User@Example.COM '), 'user@example.com');
  for (const bad of ['no-at-sign', 'a@b', 'a@@b.com', 'a b@c.com', '']) {
    assert.throws(() => validateEmail(bad));
  }
});

test('politica de senha minima', () => {
  assert.equal(validatePassword('x'.repeat(12)), 'x'.repeat(12));
  assert.throws(() => validatePassword('curta'), /12/);
  assert.throws(() => validatePassword('x'.repeat(500)), /maximo|maximo permitido/);
  assert.throws(() => validatePassword('   '));
});

test('normaliza texto e remove caracteres de controle', () => {
  const parsed = todoCreateSchema.parse({ title: '  comprar\u0007 café  ' });
  assert.equal(parsed.title, 'comprar café');
  assert.equal(parsed.priority, 'normal');
  assert.throws(() => todoCreateSchema.parse({ title: 'x'.repeat(121) }));
  assert.throws(() => todoCreateSchema.parse({ title: '' }));
  assert.throws(() => todoCreateSchema.parse({ priority: 'urgent', title: 'ok' }));
});

test('patch exige ao menos um campo e tipos estritos', () => {
  assert.deepEqual(todoPatchSchema.parse({ done: true }), { done: true });
  expectAppError(() => todoPatchSchema.parse({}), 'BAD_REQUEST');
  expectAppError(() => todoPatchSchema.parse({ done: 'true' }));
  expectAppError(() => todoPatchSchema.parse({ title: null }));
});

test('paginacao e filtros sao limitados (anti-DoS e vazamento)', () => {
  assert.deepEqual(todoListSchema.parse({}), { status: 'open', limit: 50, offset: 0 });
  assert.throws(() => todoListSchema.parse({ limit: '1000' }));
  assert.throws(() => todoListSchema.parse({ limit: '-1' }));
  assert.throws(() => todoListSchema.parse({ limit: '1; DROP TABLE' }));
  assert.throws(() => todoListSchema.parse({ status: 'deleted' }));
  assert.throws(() => todoListSchema.parse({ offset: '99999999' }));
});

test('id invalido devolve 404 (sem oraculo de formato)', () => {
  expectAppError(() => parseTodoId('../../etc/passwd'), 'NOT_FOUND');
  expectAppError(() => parseTodoId("' OR 1=1 --"), 'NOT_FOUND');
  const id = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';
  assert.equal(parseTodoId(id), id);
});