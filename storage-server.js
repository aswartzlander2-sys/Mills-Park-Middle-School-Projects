// Secure IDrive E2 storage proxy for Mills Park Tech Assistance.
// Keep all credentials in environment variables — never in browser code.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ENDPOINT = process.env.IDRIVE_E2_ENDPOINT || 's3.us-southeast-1.idrivee2.com';
const REGION = process.env.IDRIVE_E2_REGION || 'us-southeast-1';
const BUCKET = process.env.IDRIVE_E2_BUCKET || 'mpms-tech';
const ACCESS_KEY = process.env.IDRIVE_E2_ACCESS_KEY;
const SECRET_KEY = process.env.IDRIVE_E2_SECRET_KEY;
const INITIAL_USER = 'aswartzlander';
const INITIAL_USER_SALT = 'mpms-e2-admin-v1';
const INITIAL_USER_HASH = '7e347bcaf1805e599de33fda7eb6e2ed70f6530c310503a379691aaf8274099c';

if (!ACCESS_KEY || !SECRET_KEY) {
  console.warn('IDrive E2 credentials are not configured. Set IDRIVE_E2_ACCESS_KEY and IDRIVE_E2_SECRET_KEY before starting the server.');
}

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const hmac = (key, value, encoding) => crypto.createHmac('sha256', key).update(value).digest(encoding);
const enc = value => encodeURIComponent(value).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
const amzDate = date => date.toISOString().replace(/[:-]/g, '').replace(/\.\d{3}Z$/, 'Z');

async function e2Request(method, key, body = Buffer.alloc(0), contentType = 'application/octet-stream') {
  if (!ACCESS_KEY || !SECRET_KEY) throw new Error('Storage proxy has no IDrive E2 credentials.');
  const now = new Date();
  const timestamp = amzDate(now);
  const date = timestamp.slice(0, 8);
  const canonicalUri = '/' + BUCKET + (key ? '/' + key.split('/').map(enc).join('/') : '');
  const payloadHash = sha256(body);
  const headers = {
    host: ENDPOINT,
    'content-type': contentType,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': timestamp,
  };
  const signedHeaders = Object.keys(headers).sort().join(';');
  const canonicalHeaders = Object.keys(headers).sort().map(k => `${k}:${headers[k]}\n`).join('');
  const scope = `${date}/${REGION}/s3/aws4_request`;
  const canonicalRequest = `${method}\n${canonicalUri}\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const stringToSign = `AWS4-HMAC-SHA256\n${timestamp}\n${scope}\n${sha256(canonicalRequest)}`;
  const kDate = hmac('AWS4' + SECRET_KEY, date);
  const kRegion = hmac(kDate, REGION);
  const kService = hmac(kRegion, 's3');
  const signingKey = hmac(kService, 'aws4_request');
  const signature = hmac(signingKey, stringToSign, 'hex');
  const authorization = `AWS4-HMAC-SHA256 Credential=${ACCESS_KEY}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  const response = await fetch(`https://${ENDPOINT}${canonicalUri}`, { method, headers: { ...headers, authorization }, body: ['GET', 'HEAD'].includes(method) ? undefined : body });
  if (!response.ok) throw new Error(`IDrive E2 returned ${response.status}: ${await response.text()}`);
  return response;
}

// Authentication records and case assets are stored in the IDrive E2 bucket, never on the public web host.
async function readUser(username) { try { const response = await e2Request('GET', `users/${username}.json`); return JSON.parse(await response.text()); } catch (error) { return null; } }
async function ensureInitialUser() { const existing = await readUser(INITIAL_USER); if (existing) return existing; const record = { username: INITIAL_USER, passwordHash: INITIAL_USER_HASH, salt: INITIAL_USER_SALT, role: 'responder', createdAt: new Date().toISOString() }; await e2Request('PUT', `users/${INITIAL_USER}.json`, Buffer.from(JSON.stringify(record)), 'application/json'); return record; }
function passwordHash(password, salt) { return crypto.pbkdf2Sync(String(password), salt, 210000, 32, 'sha256').toString('hex'); }

function send(res, status, data) {
  res.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': 'same-origin' });
  res.end(JSON.stringify(data));
}
function safeFileName(value) { return String(value || '').replace(/[^a-zA-Z0-9._ -]/g, '_'); }

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'access-control-allow-origin': 'same-origin', 'access-control-allow-methods': 'GET,POST,OPTIONS' }); return res.end(); }
  if (req.method === 'GET' && req.url === '/') {
    const file = path.join(__dirname, 'mills-park-tech-assistance.html');
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); return fs.createReadStream(file).pipe(res);
  }
  if (req.method === 'POST' && req.url === '/api/auth/login') {
    try { const chunks = []; for await (const chunk of req) chunks.push(chunk); const payload = JSON.parse(Buffer.concat(chunks).toString('utf8')); const username = safeFileName(payload.username); const user = username === INITIAL_USER ? await ensureInitialUser() : await readUser(username); const attempt = user ? passwordHash(payload.password || '', user.salt) : ''; const valid = user && crypto.timingSafeEqual(Buffer.from(attempt, 'hex'), Buffer.from(user.passwordHash, 'hex')); return valid ? send(res, 200, { ok: true, username: user.username, role: user.role }) : send(res, 401, { ok: false, error: 'Invalid username or password.' }); } catch (error) { return send(res, 500, { ok: false, error: error.message }); }
  }
  if (req.method === 'GET' && req.url === '/api/storage/status') return send(res, 200, { configured: Boolean(ACCESS_KEY && SECRET_KEY), bucket: BUCKET, endpoint: ENDPOINT, region: REGION });
  if (req.method === 'POST' && req.url === '/api/storage/upload') {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const caseId = safeFileName(payload.caseId);
      const filename = safeFileName(payload.filename);
      if (!caseId || !filename || !payload.base64) return send(res, 400, { error: 'caseId, filename, and base64 are required.' });
      const body = Buffer.from(payload.base64, 'base64');
      if (body.length > 32 * 1024 * 1024) return send(res, 413, { error: 'Case file exceeds the 32 MB limit.' });
      // Store case resources in the private IDrive E2 bucket under their case prefix.
      const key = `cases/${caseId}/${filename}`;
      await e2Request('PUT', key, body, payload.contentType || 'application/octet-stream');
      return send(res, 200, { ok: true, key });
    } catch (error) { return send(res, 500, { error: error.message }); }
  }
  send(res, 404, { error: 'Not found' });
});
server.listen(PORT, '0.0.0.0', () => console.log(`Mills Park storage proxy listening on http://0.0.0.0:${PORT}`));
