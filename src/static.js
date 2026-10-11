'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const config = require('./config');

/**
 * Servidor de arquivos estaticos com allowlist de extensoes e resolucao
 * canonica contra raiz fixa (anti path traversal / null byte / symlink escape).
 */

const CONTENT_TYPES = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.webmanifest': 'application/manifest+json',
});

const publicRoot = fs.realpathSync(config.paths.public);

function resolveStaticPath(urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch {
    return null;
  }
  if (decoded.includes('\0')) return null;
  if (decoded === '/' || decoded === '') decoded = '/index.html';
  if (decoded.endsWith('/')) decoded += 'index.html';

  const candidate = path.resolve(publicRoot, `.${path.posix.normalize(decoded)}`);
  // Barriga canonica: o caminho resolvido precisa continuar dentro da raiz publica.
  if (candidate !== publicRoot && !candidate.startsWith(publicRoot + path.sep)) return null;
  const ext = path.extname(candidate).toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(CONTENT_TYPES, ext)) return null;
  return candidate;
}

async function serveStatic(req, res, urlPath) {
  const filePath = resolveStaticPath(urlPath);
  if (!filePath) return false;

  let stat;
  let realPath;
  try {
    // realpath evita servir conteudo via symlink apontando para fora da raiz.
    realPath = await fsp.realpath(filePath);
    if (realPath !== publicRoot && !realPath.startsWith(publicRoot + path.sep)) return false;
    stat = await fsp.stat(realPath);
    if (!stat.isFile()) return false;
  } catch {
    return false;
  }

  const etag = `"${crypto.createHash('sha256').update(`${stat.size}-${stat.mtimeMs}`).digest('base64url')}"`;
  res.setHeader('Content-Type', CONTENT_TYPES[path.extname(realPath).toLowerCase()]);
  res.setHeader('ETag', etag);
  res.setHeader('Last-Modified', new Date(stat.mtimeMs).toUTCString());
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Content-Length', String(stat.size));

  if (req.headers['if-none-match'] === etag) {
    res.statusCode = 304;
    res.end();
    return true;
  }
  if (req.method === 'HEAD') {
    res.end();
    return true;
  }

  res.statusCode = 200;
  await new Promise((resolve) => {
    const stream = fs.createReadStream(realPath);
    stream.on('error', () => {
      res.destroy();
      resolve();
    });
    stream.on('end', resolve);
    stream.pipe(res);
  });
  return true;
}

module.exports = { serveStatic, resolveStaticPath, CONTENT_TYPES };