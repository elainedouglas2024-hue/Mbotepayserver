'use strict';

/*
 * MbotePay payment server
 *
 * Required environment:
 *   MBOTEPAY_API_KEY          API key from MbotePay Developer settings
 * Optional webhook setup:
 *   MBOTEPAY_WEBHOOK_SECRET   Secret provided when creating the API key
 *   PUBLIC_BASE_URL           Public HTTPS URL of this server
 *   PAYOUTS_ENABLED           Set to "true" to enable the payout route
 *   PAYOUT_SERVER_TOKEN       Server-only token; also signs admin sessions
 *   PAYOUT_ADMIN_USERNAME     Admin username for the withdrawal page
 *   PAYOUT_ADMIN_PASSWORD     Strong password for the withdrawal page
 * Optional configuration:
 *   PORT                      Defaults to 3000
 *   MBOTEPAY_API_BASE         Defaults to https://app.mbotepay.com/api/v1
 *   FRONTEND_ORIGINS          Comma-separated origins; unset means any origin
 *   WEBHOOK_TOLERANCE_SECONDS Defaults to 300 seconds
 *
 * Never put the MbotePay API key or PAYOUT_SERVER_TOKEN in frontend code.
 * Admin payout sessions are signed with PAYOUT_SERVER_TOKEN and require the
 * exact FRONTEND_ORIGINS value. CORS alone is not authentication.
 */

require('dotenv').config();

const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const API_BASE = (process.env.MBOTEPAY_API_BASE || 'https://app.mbotepay.com/api/v1')
  .replace(/\/+$/, '');
const API_KEY = process.env.MBOTEPAY_API_KEY;
const WEBHOOK_SECRET = process.env.MBOTEPAY_WEBHOOK_SECRET;
const PAYOUTS_ENABLED = process.env.PAYOUTS_ENABLED === 'true';
const PAYOUT_SERVER_TOKEN = process.env.PAYOUT_SERVER_TOKEN || '';
const PAYOUT_ADMIN_USERNAME = process.env.PAYOUT_ADMIN_USERNAME || '';
const PAYOUT_ADMIN_PASSWORD = process.env.PAYOUT_ADMIN_PASSWORD || '';
const WEBHOOK_TOLERANCE_SECONDS = Number(process.env.WEBHOOK_TOLERANCE_SECONDS) || 300;

// MbotePay-supported country, currency, and operator combinations.
const NETWORKS = {
  COD: { currencies: ['CDF', 'USD'], operators: ['VODACOM_MPESA_COD', 'AIRTEL_COD', 'ORANGE_COD'] },
  BEN: { currencies: ['XOF'], operators: ['MTN_MOMO_BEN', 'MOOV_BEN'] },
  CIV: { currencies: ['XOF'], operators: ['MTN_MOMO_CIV', 'ORANGE_CIV'] },
  CMR: { currencies: ['XAF'], operators: ['MTN_MOMO_CMR'] },
  COG: { currencies: ['XAF'], operators: ['AIRTEL_COG', 'MTN_MOMO_COG'] },
  GAB: { currencies: ['XAF'], operators: ['AIRTEL_GAB'] },
  SEN: { currencies: ['XOF'], operators: ['ORANGE_SEN', 'FREE_SEN'] },
  KEN: { currencies: ['KES'], operators: ['MPESA_KEN'] },
  RWA: { currencies: ['RWF'], operators: ['AIRTEL_RWA', 'MTN_MOMO_RWA'] },
  UGA: { currencies: ['UGX'], operators: ['AIRTEL_OAPI_UGA', 'MTN_MOMO_UGA'] },
  ZMB: { currencies: ['ZMW'], operators: ['AIRTEL_OAPI_ZMB', 'MTN_MOMO_ZMB', 'ZAMTEL_ZMB'] },
  SLE: { currencies: ['SLE'], operators: ['ORANGE_SLE'] },
};

const configuredOrigins = (process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.disable('x-powered-by');
app.use(cors({
  origin(origin, callback) {
    // Requests without an Origin header include server-to-server calls.
    if (!origin || configuredOrigins.length === 0 || configuredOrigins.includes('*') ||
        configuredOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Idempotency-Key'],
  maxAge: 600,
}));

// Small in-memory limiter. Use an external store if running multiple instances.
const requestCounts = new Map();
function rateLimit(req, res, next) {
  const now = Date.now();
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const current = requestCounts.get(key);
  const windowMs = 60_000;
  const maxRequests = 60;

  if (!current || now - current.startedAt >= windowMs) {
    requestCounts.set(key, { startedAt: now, count: 1 });
    return next();
  }
  current.count += 1;
  if (current.count > maxRequests) {
    res.set('Retry-After', String(Math.ceil((windowMs - (now - current.startedAt)) / 1000)));
    return sendError(res, 429, 'rate_limited', 'Too many requests. Try again shortly.');
  }
  return next();
}
setInterval(() => {
  const cutoff = Date.now() - 60_000;
  for (const [key, value] of requestCounts) {
    if (value.startedAt < cutoff) requestCounts.delete(key);
  }
  const loginCutoff = Date.now() - 15 * 60_000;
  for (const [key, value] of adminLoginAttempts) {
    if (value.startedAt < loginCutoff) adminLoginAttempts.delete(key);
  }
}, 60_000).unref();

app.get('/health', (_req, res) => res.json({ ok: true }));

// Keep the webhook body raw so its signature is checked against the exact bytes received.
app.post('/webhooks/mbotepay', express.raw({ type: 'application/json', limit: '256kb' }), (req, res) => {
  if (!WEBHOOK_SECRET) {
    return sendError(res, 503, 'webhook_not_configured', 'Webhook verification is not configured.');
  }
  if (!Buffer.isBuffer(req.body)) {
    return sendError(res, 400, 'invalid_webhook_body', 'Expected an application/json webhook body.');
  }

  const signatureHeader = req.get('X-MbotePay-Signature') || '';
  const parts = Object.fromEntries(
    signatureHeader.split(',').map((part) => {
      const separator = part.indexOf('=');
      return separator < 0 ? ['', ''] : [part.slice(0, separator).trim(), part.slice(separator + 1).trim()];
    }),
  );
  const timestamp = parts.t;
  const suppliedHex = parts.v1;
  if (!/^\d+$/.test(timestamp || '') || !/^[a-fA-F0-9]{64}$/.test(suppliedHex || '')) {
    return sendError(res, 400, 'invalid_webhook_signature', 'Webhook signature is missing or malformed.');
  }
  const ageSeconds = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (ageSeconds > WEBHOOK_TOLERANCE_SECONDS) {
    return sendError(res, 400, 'expired_webhook_signature', 'Webhook signature timestamp is outside the allowed window.');
  }

  const expected = crypto.createHmac('sha256', WEBHOOK_SECRET)
    .update(`${timestamp}.`)
    .update(req.body)
    .digest();
  const supplied = Buffer.from(suppliedHex, 'hex');
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    return sendError(res, 400, 'invalid_webhook_signature', 'Webhook signature verification failed.');
  }

  let event;
  try {
    event = JSON.parse(req.body.toString('utf8'));
  } catch {
    return sendError(res, 400, 'invalid_webhook_body', 'Webhook body is not valid JSON.');
  }

  if (typeof event.id !== 'string' || !event.id) {
    return sendError(res, 400, 'invalid_webhook_event', 'Webhook event is missing a transaction id.');
  }

  // Cache verified callbacks so the frontend can retrieve the latest receipt/status.
  webhookEvents.set(event.id, event);
  if (webhookEvents.size > 1000) {
    webhookEvents.delete(webhookEvents.keys().next().value);
  }
  return res.sendStatus(200);
});

app.use(express.json({ limit: '32kb' }));
app.use('/api/v1', rateLimit);

app.get('/api/auth/me', requirePayoutFrontendOrigin, (req, res) => {
  const session = readAdminSession(req);
  res.json({
    enabled: isAdminPayoutConfigured(),
    authenticated: Boolean(session),
    username: session ? session.username : null,
  });
});
app.post('/api/auth/login', requirePayoutFrontendOrigin, limitAdminLogin, loginAdmin);
app.post('/api/auth/logout', requirePayoutFrontendOrigin, (_req, res) => {
  res.set('Set-Cookie', adminCookie('', 0));
  res.json({ authenticated: false });
});

app.post('/api/v1/payin', (req, res) => createPayment(req, res, 'payin'));
app.post('/api/v1/payout', requirePayoutAccess, (req, res) => createPayment(req, res, 'payout'));
app.get('/api/v1/transactions/:id', (req, res) => getTransaction(req, res));

const webhookEvents = new Map();

function isAdminPayoutConfigured() {
  return PAYOUTS_ENABLED && Boolean(
    PAYOUT_SERVER_TOKEN.length >= 32 && PAYOUT_ADMIN_USERNAME &&
    PAYOUT_ADMIN_PASSWORD.length >= 12,
  );
}

function requirePayoutFrontendOrigin(req, res, next) {
  const origin = req.get('Origin') || '';
  const allowed = origin && configuredOrigins.length > 0 &&
    !configuredOrigins.includes('*') && configuredOrigins.includes(origin);
  if (!allowed) {
    return sendError(
      res,
      403,
      'payout_origin_not_allowed',
      'Set FRONTEND_ORIGINS to the exact static-site origin before using admin payouts.',
    );
  }
  return next();
}

function constantTimeEqual(value, expectedValue) {
  const valueBuffer = Buffer.from(String(value));
  const expectedBuffer = Buffer.from(String(expectedValue));
  return valueBuffer.length === expectedBuffer.length &&
    crypto.timingSafeEqual(valueBuffer, expectedBuffer);
}

const adminLoginAttempts = new Map();
function limitAdminLogin(req, res, next) {
  const now = Date.now();
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const current = adminLoginAttempts.get(key);
  const windowMs = 15 * 60_000;
  const maxAttempts = 5;
  if (!current || now - current.startedAt >= windowMs) {
    adminLoginAttempts.set(key, { startedAt: now, count: 1 });
    return next();
  }
  if (current.count >= maxAttempts) {
    res.set('Retry-After', String(Math.ceil((windowMs - (now - current.startedAt)) / 1000)));
    return sendError(res, 429, 'login_rate_limited', 'Too many sign-in attempts. Try again later.');
  }
  current.count += 1;
  return next();
}

function adminCookie(value, maxAgeSeconds) {
  return `mbotepay_admin=${value}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${maxAgeSeconds}`;
}

function adminSessionSigningKey() {
  return crypto.createHmac('sha256', PAYOUT_SERVER_TOKEN)
    .update(PAYOUT_ADMIN_PASSWORD)
    .digest();
}

function createAdminSession(username) {
  const expiresAt = Date.now() + 8 * 60 * 60 * 1000;
  const payload = Buffer.from(JSON.stringify({
    username,
    expiresAt,
    nonce: crypto.randomUUID(),
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', adminSessionSigningKey())
    .update(payload)
    .digest('base64url');
  return { token: `${payload}.${signature}`, maxAge: 8 * 60 * 60 };
}

function getCookie(req, cookieName) {
  const cookieHeader = req.headers.cookie || '';
  for (const part of cookieHeader.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === cookieName) {
      return part.slice(separator + 1).trim();
    }
  }
  return '';
}

function readAdminSession(req) {
  if (!PAYOUT_SERVER_TOKEN || !PAYOUT_ADMIN_USERNAME) return null;
  const token = getCookie(req, 'mbotepay_admin');
  const separator = token.lastIndexOf('.');
  if (separator < 1) return null;
  const payload = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  const expectedSignature = crypto.createHmac('sha256', adminSessionSigningKey())
    .update(payload)
    .digest('base64url');
  if (!constantTimeEqual(signature, expectedSignature)) return null;

  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (session.username !== PAYOUT_ADMIN_USERNAME || !Number.isFinite(session.expiresAt) ||
        session.expiresAt <= Date.now()) {
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

function loginAdmin(req, res) {
  if (!isAdminPayoutConfigured()) {
    return sendError(res, 503, 'payout_admin_not_configured', 'Admin payout access is not configured on the server.');
  }
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return sendError(res, 401, 'invalid_admin_credentials', 'Username or password is incorrect.');
  }
  const usernameMatches = constantTimeEqual(username, PAYOUT_ADMIN_USERNAME);
  const passwordMatches = constantTimeEqual(password, PAYOUT_ADMIN_PASSWORD);
  if (!usernameMatches || !passwordMatches) {
    return sendError(res, 401, 'invalid_admin_credentials', 'Username or password is incorrect.');
  }

  adminLoginAttempts.delete(req.ip || req.socket.remoteAddress || 'unknown');
  const session = createAdminSession(PAYOUT_ADMIN_USERNAME);
  res.set('Set-Cookie', adminCookie(session.token, session.maxAge));
  return res.json({ authenticated: true, username: PAYOUT_ADMIN_USERNAME });
}

function requirePayoutAccess(req, res, next) {
  if (!PAYOUTS_ENABLED) {
    return sendError(res, 403, 'payouts_disabled', 'Payouts are disabled on this server.');
  }
  if (PAYOUT_SERVER_TOKEN.length < 32) {
    return sendError(res, 503, 'payout_auth_not_configured', 'Set a payout server token with at least 32 characters.');
  }
  const suppliedToken = req.get('X-Payout-Token') || '';
  if (suppliedToken && constantTimeEqual(suppliedToken, PAYOUT_SERVER_TOKEN)) {
    return next();
  }
  if (!requirePayoutFrontendOriginForRequest(req)) {
    return sendError(res, 403, 'payout_origin_not_allowed', 'Payouts require the configured static-site origin.');
  }
  if (!readAdminSession(req)) {
    return sendError(res, 401, 'payout_unauthorized', 'Sign in as the payout admin before submitting a withdrawal.');
  }
  return next();
}

function requirePayoutFrontendOriginForRequest(req) {
  const origin = req.get('Origin') || '';
  return Boolean(origin && configuredOrigins.length > 0 &&
    !configuredOrigins.includes('*') && configuredOrigins.includes(origin));
}

async function createPayment(req, res, operation) {
  if (!API_KEY) {
    return sendError(res, 503, 'payment_server_not_configured', 'MbotePay API key is not configured on the server.');
  }

  const { amount, currency, country, operator, phone, reference } = req.body || {};
  if (typeof amount !== 'number' || !Number.isFinite(amount) ||
      amount <= 0 || amount > Number.MAX_SAFE_INTEGER) {
    return sendError(res, 400, 'invalid_amount', 'amount must be a positive number expressed in the main currency unit.');
  }
  if (typeof currency !== 'string' || typeof country !== 'string' || typeof operator !== 'string') {
    return sendError(res, 400, 'missing_payment_fields', 'currency, country, and operator are required.');
  }
  const countryCode = country.toUpperCase();
  const currencyCode = currency.toUpperCase();
  const network = NETWORKS[countryCode];
  if (!network) {
    return sendError(res, 400, 'unsupported_country', 'The selected country is not supported by MbotePay.');
  }
  if (!network.currencies.includes(currencyCode)) {
    return sendError(res, 400, 'unsupported_currency', 'The selected currency is not supported for this country.');
  }
  if (!network.operators.includes(operator.toUpperCase())) {
    return sendError(res, 400, 'unsupported_operator', 'The selected operator is not supported for this country.');
  }
  if (typeof phone !== 'string' || !/^\d{8,15}$/.test(phone)) {
    return sendError(res, 400, 'invalid_phone', 'phone must be an international number without a plus sign.');
  }
  if (reference !== undefined && (typeof reference !== 'string' || reference.length > 200)) {
    return sendError(res, 400, 'invalid_reference', 'reference must be a string of at most 200 characters.');
  }

  const idempotencyKey = req.get('Idempotency-Key') ||
    (typeof req.body.idempotencyKey === 'string' ? req.body.idempotencyKey : '');
  if (!idempotencyKey || idempotencyKey.length > 200) {
    return sendError(res, 400, 'missing_idempotency_key', 'Send a unique Idempotency-Key header for each payment operation.');
  }

  const payload = {
    amount,
    currency: currencyCode,
    country: countryCode,
    operator: operator.toUpperCase(),
    phone,
  };
  if (reference !== undefined) payload.reference = reference;

  // Only send a callback URL when this server can verify the callback.
  const publicBase = (process.env.PUBLIC_BASE_URL || '').replace(/\/+$/, '');
  if (publicBase && WEBHOOK_SECRET) {
    try {
      if (new URL(publicBase).protocol === 'https:') {
        payload.callback_url = `${publicBase}/webhooks/mbotepay`;
      }
    } catch {
      // Omit an invalid callback URL; status can still be checked through the API.
    }
  }

  return forwardToMbotePay({
    req,
    res,
    path: `/${operation}`,
    method: 'POST',
    body: payload,
    idempotencyKey,
  });
}

async function getTransaction(req, res) {
  if (!API_KEY) {
    return sendError(res, 503, 'payment_server_not_configured', 'MbotePay API key is not configured on the server.');
  }
  const transactionId = req.params.id;
  if (!transactionId || transactionId.length > 200 || /[/?#]/.test(transactionId)) {
    return sendError(res, 400, 'invalid_transaction_id', 'A valid transaction id is required.');
  }

  const cachedEvent = webhookEvents.get(transactionId);
  if (cachedEvent) return res.json(cachedEvent);

  return forwardToMbotePay({
    req,
    res,
    path: `/transactions/${encodeURIComponent(transactionId)}`,
    method: 'GET',
  });
}

async function forwardToMbotePay({ req, res, path, method, body, idempotencyKey }) {
  const headers = { Authorization: `Bearer ${API_KEY}` };
  if (body) headers['Content-Type'] = 'application/json';
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;

  try {
    const response = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(20_000),
    });
    const responseBody = await response.text();
    const contentType = response.headers.get('content-type') || 'application/json';
    // Forward MbotePay's status and response body unchanged so the frontend can
    // display the provider's exact error or use its transaction receipt.
    res.status(response.status);
    res.set('Content-Type', contentType);
    return res.send(responseBody);
  } catch {
    return sendError(
      res,
      502,
      'mbotepay_unavailable',
      'Could not reach MbotePay. If retrying, reuse the same Idempotency-Key.',
    );
  }
}

function sendError(res, status, code, message) {
  return res.status(status).json({ error: { code, message } });
}

app.use((err, _req, res, _next) => {
  if (res.headersSent) return;
  const status = err.status === 413 ? 413 : 400;
  const code = status === 413 ? 'request_too_large' : 'invalid_request';
  const message = status === 413 ? 'Request body is too large.' : 'Request body must be valid JSON.';
  return sendError(res, status, code, message);
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`MbotePay payment server listening on port ${PORT}`);
    if (!API_KEY) console.warn('MBOTEPAY_API_KEY is not configured; payment requests will return 503.');
    if (!WEBHOOK_SECRET || !process.env.PUBLIC_BASE_URL) {
      console.warn('Webhook callbacks are disabled until MBOTEPAY_WEBHOOK_SECRET and PUBLIC_BASE_URL are configured.');
    }
  });
}

module.exports = app;
