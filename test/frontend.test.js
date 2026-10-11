'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const publicDir = path.join(__dirname, '..', 'public');
const read = (file) => fs.readFileSync(path.join(publicDir, file), 'utf8');
/** Remove comentarios: o guardrail analisa codigo executavel, nao documentacao. */
const readCode = (file) => read(file)
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/(^|\s)\/\/.*$/gm, '$1');

/**
 * Guardrails de AppSec no cliente.
 * Falham se uma regressao reintroduzir XSS ou CSP permissiva.
 */

test('cliente nao usa APIs que executam HTML/JS dinamico', () => {
  const source = readCode('app.js');
  const forbidden = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function(', 'setTimeout("', 'setInterval("'];
  for (const api of forbidden) {
    assert.ok(!source.includes(api), `app.js deve nao usar ${api}`);
  }
});

test('index.html nao possui script ou style inline (CSP sem unsafe-inline)', () => {
  const html = read('index.html');
  const inlineScripts = html.match(/<script(?![^>]*\bsrc=)[^>]*>/gi) ?? [];
  assert.equal(inlineScripts.length, 0, 'nao deve haver <script> inline');
  assert.ok(!/<style[\s>]/i.test(html), 'nao deve haver <style> inline');
  assert.ok(!/\son[a-z]+=/i.test(html), 'nao deve haver handler de evento inline');
});

test('cliente nao persiste credenciais em storage do navegador', () => {
  const source = readCode('app.js');
  assert.ok(!source.includes('localStorage'));
  assert.ok(!source.includes('sessionStorage'));
  assert.ok(!source.includes('document.cookie'));
});

test('cliente envia credenciais apenas same-origin e sem redirecionamento', () => {
  const source = read('app.js');
  assert.ok(source.includes("credentials: 'same-origin'"));
  assert.ok(source.includes("redirect: 'error'"));
});

test('CSP nao permite origem externa alguma', () => {
  const config = require('../src/config');
  assert.ok(!config.security.csp.includes('unsafe-inline'));
  assert.ok(!config.security.csp.includes('unsafe-eval'));
  assert.ok(!config.security.csp.includes('https://'));
  assert.ok(!config.security.csp.includes('http://'), 'somente origens locais');
  assert.equal(config.security.csp.includes("img-src 'self' data:"), true);
});