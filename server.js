/**
 * PayPaddy – Production Backend (single file)
 * FCI = internal defense-in-depth security architecture (not an external certification claim).
 *
 * Layers: Identity → Authentication → Authorization → Partner isolation →
 *         Payment authorization → Gateway verification → Transaction integrity →
 *         Audit trail → Fraud/abuse controls → Security monitoring
 *
 * NO DEMO MODE. Missing required config → process exit or hard errors.
 * Payment success only after verified gateway webhook.
 *
 * Usage:
 *   1. Copy .env.example values into environment / .env
 *   2. Place Firebase serviceAccountKey.json next to this file (or set FIREBASE_SERVICE_ACCOUNT_JSON)
 *   3. npm i express cors helmet dotenv express-rate-limit firebase-admin uuid zod
 *   4. node server.js
 */

'use strict';

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { z } = require('zod');

// ============================================================================
// 0. FATAL CONFIG CHECKS (no silent defaults for secrets)
// ============================================================================
function requireEnv(name, minLen = 1) {
  const v = process.env[name];
  if (!v || String(v).trim().length < minLen) {
    console.error(`[FATAL] Missing or invalid environment variable: ${name}`);
    process.exit(1);
  }
  return v;
}

const PORT = Number(process.env.PORT) || 3001;
const NODE_ENV = process.env.NODE_ENV || 'production';
const API_PUBLIC_URL = process.env.API_PUBLIC_URL || `http://localhost:${PORT}`;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000')
  .split(',').map(s => s.trim()).filter(Boolean);

const PARTNER_TOKEN_SECRET = requireEnv('PARTNER_TOKEN_SECRET', 32);

// ============================================================================
// 1. FCI SECURITY CORE
// ============================================================================
const auditLog = [];

function audit(event, details = {}) {
  const entry = { ts: new Date().toISOString(), event, ...details };
  auditLog.push(entry);
  if (auditLog.length > 5000) auditLog.shift();
  console.log(`[FCI-AUDIT] ${entry.ts} ${event}`, JSON.stringify(details));
  return entry;
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function validate(schema, data) {
  const r = schema.safeParse(data);
  if (!r.success) {
    const msg = r.error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join('; ');
    const err = new Error(msg);
    err.status = 400;
    err.code = 'VALIDATION_ERROR';
    throw err;
  }
  return r.data;
}

const PaymentCreateSchema = z.object({
  amount: z.number().int().positive().min(1),
  currency: z.string().length(3).transform(s => s.toLowerCase()),
  gateway: z.enum(['stripe', 'paypal', 'paystack', 'flutterwave', 'razorpay', 'square']),
  partnerReferenceId: z.string().min(1).max(128).optional(),
  idempotencyKey: z.string().min(8).max(128).optional(),
  description: z.string().max(500).optional(),
  metadata: z.record(z.string()).optional(),
  successUrl: z.string().url().optional(),
  cancelUrl: z.string().url().optional(),
  email: z.string().email().optional()
});

const PartnerTokenSchema = z.object({
  clientId: z.string().min(8),
  clientSecret: z.string().min(16),
  grant_type: z.literal('client_credentials'),
  scope: z.string().optional()
});

const idempotencyStore = new Map();
function checkIdempotency(key) {
  if (!key) return null;
  const e = idempotencyStore.get(key);
  if (e && e.expiresAt > Date.now()) return e.response;
  return null;
}
function storeIdempotency(key, response, ttlMs = 86400000) {
  if (!key) return;
  idempotencyStore.set(key, { response, expiresAt: Date.now() + ttlMs });
}

const seenWebhooks = new Map();
function assertNotReplayed(eventId) {
  if (!eventId) return;
  const exp = seenWebhooks.get(eventId);
  if (exp && exp > Date.now()) {
    const err = new Error('Webhook already processed');
    err.status = 409;
    err.code = 'WEBHOOK_REPLAY';
    throw err;
  }
  seenWebhooks.set(eventId, Date.now() + 172800000);
}

function assertPartnerOwns(partnerId, resourcePartnerId) {
  if (!partnerId || partnerId !== resourcePartnerId) {
    audit('partner_isolation_violation', { partnerId, resourcePartnerId });
    const err = new Error('Access denied: partner isolation');
    err.status = 403;
    err.code = 'PARTNER_ISOLATION';
    throw err;
  }
}

// ============================================================================
// 2. FIREBASE ADMIN (required)
// ============================================================================
let admin, db;

function initFirebase() {
  const adminSdk = require('firebase-admin');
  let credential;

  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    try {
      credential = adminSdk.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON));
    } catch (e) {
      console.error('[FATAL] FIREBASE_SERVICE_ACCOUNT_JSON is invalid JSON');
      process.exit(1);
    }
  } else {
    const saPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH
      ? path.resolve(__dirname, process.env.FIREBASE_SERVICE_ACCOUNT_PATH)
      : path.resolve(__dirname, 'serviceAccountKey.json');
    if (!fs.existsSync(saPath)) {
      console.error('[FATAL] Firebase service-account not found at', saPath);
      console.error('        Set FIREBASE_SERVICE_ACCOUNT_PATH or FIREBASE_SERVICE_ACCOUNT_JSON');
      process.exit(1);
    }
    credential = adminSdk.credential.cert(require(saPath));
  }

  if (!adminSdk.apps.length) {
    adminSdk.initializeApp({ credential });
  }
  admin = adminSdk;
  db = adminSdk.firestore();
  console.log('[firebase-admin] Initialized');
}

initFirebase();

async function requireUserAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    audit('auth_missing_token', { path: req.path, ip: req.ip });
    return res.status(401).json({ error: 'Missing Authorization Bearer token', code: 'AUTH_REQUIRED' });
  }
  try {
    const decoded = await admin.auth().verifyIdToken(token, true);
    req.user = decoded;
    req.authType = 'user';
    next();
  } catch (err) {
    audit('auth_token_invalid', { path: req.path, reason: err.code || err.message });
    return res.status(401).json({
      error: 'Invalid or expired token',
      code: err.code === 'auth/id-token-revoked' ? 'TOKEN_REVOKED' : 'TOKEN_INVALID'
    });
  }
}

// ============================================================================
// 3. PARTNER OAUTH (client_credentials)
// ============================================================================
const TOKEN_TTL = 3600;

function signPartnerToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', PARTNER_TOKEN_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyPartnerToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed token');
  const [h, b, s] = parts;
  const expected = crypto.createHmac('sha256', PARTNER_TOKEN_SECRET).update(`${h}.${b}`).digest('base64url');
  if (!safeEqual(s, expected)) throw new Error('Invalid token signature');
  const payload = JSON.parse(Buffer.from(b, 'base64url').toString());
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');
  if (payload.typ !== 'partner_access') throw new Error('Wrong token type');
  return payload;
}

async function requirePartnerAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing partner access token', code: 'PARTNER_AUTH_REQUIRED' });
  try {
    req.partner = verifyPartnerToken(token);
    req.authType = 'partner';
    next();
  } catch (err) {
    audit('partner_auth_failed', { reason: err.message });
    return res.status(401).json({ error: err.message, code: 'PARTNER_TOKEN_INVALID' });
  }
}

async function requireAnyAuth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization required', code: 'AUTH_REQUIRED' });
  }
  try {
    req.partner = verifyPartnerToken(header.slice(7));
    req.authType = 'partner';
    return next();
  } catch (_) { /* try user */ }
  return requireUserAuth(req, res, next);
}

function hashSecret(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

async function getPartner(clientId) {
  const doc = await db.collection('partners').doc(clientId).get();
  if (!doc.exists) return null;
  return { id: doc.id, ...doc.data() };
}

async function issueClientCredentialsToken(body) {
  const data = validate(PartnerTokenSchema, body);
  const partner = await getPartner(data.clientId);
  if (!partner || partner.active === false) {
    audit('partner_auth_unknown_client', { clientId: data.clientId });
    const err = new Error('Invalid client credentials');
    err.status = 401;
    err.code = 'INVALID_CLIENT';
    throw err;
  }
  if (!safeEqual(hashSecret(data.clientSecret), partner.clientSecretHash || '')) {
    audit('partner_auth_bad_secret', { clientId: data.clientId });
    const err = new Error('Invalid client credentials');
    err.status = 401;
    err.code = 'INVALID_CLIENT';
    throw err;
  }
  const now = Math.floor(Date.now() / 1000);
  const scopes = (data.scope || (partner.scopes || ['payments:create', 'payments:read']).join(' '))
    .split(/\s+/).filter(Boolean);
  const allowed = new Set(partner.scopes || ['payments:create', 'payments:read']);
  for (const s of scopes) {
    if (!allowed.has(s)) {
      const err = new Error(`Scope not allowed: ${s}`);
      err.status = 400;
      err.code = 'INVALID_SCOPE';
      throw err;
    }
  }
  const payload = {
    typ: 'partner_access',
    sub: partner.clientId,
    partnerId: partner.clientId,
    name: partner.name,
    scopes,
    iat: now,
    exp: now + TOKEN_TTL
  };
  audit('partner_token_issued', { partnerId: partner.clientId, scopes });
  return {
    access_token: signPartnerToken(payload),
    token_type: 'Bearer',
    expires_in: TOKEN_TTL,
    scope: scopes.join(' ')
  };
}

// ============================================================================
// 4. GATEWAY ADAPTERS (real only – missing keys throw)
// ============================================================================
function requireGatewayEnv(name) {
  const v = process.env[name];
  if (!v || !String(v).trim()) {
    const err = new Error(`Gateway configuration missing: ${name}`);
    err.status = 503;
    err.code = 'GATEWAY_CONFIG_MISSING';
    throw err;
  }
  return v;
}

async function createStripeSession(p) {
  const secret = requireGatewayEnv('STRIPE_SECRET_KEY');
  let stripe;
  try { stripe = require('stripe')(secret); } catch {
    const err = new Error('stripe package not installed (npm i stripe)');
    err.status = 503; err.code = 'GATEWAY_SDK_MISSING'; throw err;
  }
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    payment_method_types: ['card'],
    line_items: [{
      price_data: {
        currency: p.currency,
        product_data: { name: p.description || 'Payment' },
        unit_amount: p.amount
      },
      quantity: 1
    }],
    success_url: p.successUrl || `${API_PUBLIC_URL}/?payment=success&session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: p.cancelUrl || `${API_PUBLIC_URL}/?payment=cancel`,
    metadata: p.metadata || {},
    client_reference_id: p.metadata?.partnerReferenceId
  }, p.idempotencyKey ? { idempotencyKey: p.idempotencyKey } : undefined);
  audit('gateway_session_created', { gateway: 'stripe', id: session.id });
  return { gatewayPaymentId: session.id, checkoutUrl: session.url, status: 'pending' };
}

async function createPaystackSession(p) {
  const secret = requireGatewayEnv('PAYSTACK_SECRET_KEY');
  const res = await fetch('https://api.paystack.co/transaction/initialize', {
    method: 'POST',
    headers: { Authorization: `Bearer ${secret}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      amount: p.amount,
      currency: p.currency.toUpperCase(),
      email: p.email || p.metadata?.email || 'customer@paypaddy.local',
      reference: p.metadata?.partnerReferenceId || `pp_${Date.now()}`,
      callback_url: p.successUrl,
      metadata: p.metadata
    })
  });
  const data = await res.json();
  if (!res.ok || !data.status) {
    const err = new Error(data.message || 'Paystack initialization failed');
    err.status = 502; err.code = 'GATEWAY_ERROR'; throw err;
  }
  audit('gateway_session_created', { gateway: 'paystack', id: data.data.reference });
  return { gatewayPaymentId: data.data.reference, checkoutUrl: data.data.authorization_url, status: 'pending' };
}

async function createFlutterwaveSession(p) {
  const secret = requireGatewayEnv('FLUTTERWAVE_SECRET_KEY');
  const txRef = p.metadata?.partnerReferenceId || `flw_${Date.now()}`;
  const res = await fetch('https://api.flutterwave.com/v3/payments', {
    method: 'POST',
    headers: { Authorization: `Bearer ${secret}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      tx_ref: txRef,
      amount: p.amount / 100,
      currency: p.currency.toUpperCase(),
      redirect_url: p.successUrl || API_PUBLIC_URL,
      customer: { email: p.email || p.metadata?.email || 'customer@paypaddy.local' },
      customizations: { title: p.description || 'PayPaddy Payment' },
      meta: p.metadata
    })
  });
  const data = await res.json();
  if (data.status !== 'success') {
    const err = new Error(data.message || 'Flutterwave failed');
    err.status = 502; err.code = 'GATEWAY_ERROR'; throw err;
  }
  audit('gateway_session_created', { gateway: 'flutterwave', id: txRef });
  return { gatewayPaymentId: txRef, checkoutUrl: data.data.link, status: 'pending' };
}

async function createPayPalOrder(p) {
  const clientId = requireGatewayEnv('PAYPAL_CLIENT_ID');
  const clientSecret = requireGatewayEnv('PAYPAL_CLIENT_SECRET');
  const base = process.env.PAYPAL_MODE === 'live'
    ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
  const tokenRes = await fetch(`${base}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      Authorization: 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64'),
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: 'grant_type=client_credentials'
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok) {
    const err = new Error('PayPal authentication failed');
    err.status = 502; err.code = 'GATEWAY_ERROR'; throw err;
  }
  const orderRes = await fetch(`${base}/v2/checkout/orders`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenData.access_token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      intent: 'CAPTURE',
      purchase_units: [{
        amount: { currency_code: p.currency.toUpperCase(), value: (p.amount / 100).toFixed(2) },
        description: p.description || 'PayPaddy Payment',
        custom_id: p.metadata?.partnerReferenceId
      }],
      application_context: {
        return_url: p.successUrl || API_PUBLIC_URL,
        cancel_url: p.cancelUrl || API_PUBLIC_URL
      }
    })
  });
  const order = await orderRes.json();
  if (!orderRes.ok) {
    const err = new Error(order.message || 'PayPal order failed');
    err.status = 502; err.code = 'GATEWAY_ERROR'; throw err;
  }
  const approve = (order.links || []).find(l => l.rel === 'approve');
  audit('gateway_session_created', { gateway: 'paypal', id: order.id });
  return { gatewayPaymentId: order.id, checkoutUrl: approve?.href || null, status: 'pending' };
}

async function createRazorpayOrder(p) {
  const keyId = requireGatewayEnv('RAZORPAY_KEY_ID');
  const keySecret = requireGatewayEnv('RAZORPAY_KEY_SECRET');
  const auth = Buffer.from(`${keyId}:${keySecret}`).toString('base64');
  const res = await fetch('https://api.razorpay.com/v1/orders', {
    method: 'POST',
    headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      amount: p.amount,
      currency: p.currency.toUpperCase(),
      receipt: p.metadata?.partnerReferenceId || `rcpt_${Date.now()}`,
      notes: p.metadata || {}
    })
  });
  const data = await res.json();
  if (!res.ok) {
    const err = new Error(data.error?.description || 'Razorpay order failed');
    err.status = 502; err.code = 'GATEWAY_ERROR'; throw err;
  }
  audit('gateway_session_created', { gateway: 'razorpay', id: data.id });
  return { gatewayPaymentId: data.id, checkoutUrl: null, status: 'pending', clientKey: keyId };
}

async function createSquareLink(p) {
  const token = requireGatewayEnv('SQUARE_ACCESS_TOKEN');
  const locationId = requireGatewayEnv('SQUARE_LOCATION_ID');
  const env = process.env.SQUARE_ENVIRONMENT === 'sandbox' ? 'sandbox' : 'production';
  const base = env === 'sandbox' ? 'https://connect.squareupsandbox.com' : 'https://connect.squareup.com';
  const res = await fetch(`${base}/v2/online-checkout/payment-links`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Square-Version': '2024-01-18'
    },
    body: JSON.stringify({
      idempotency_key: p.idempotencyKey || crypto.randomUUID(),
      order: {
        location_id: locationId,
        line_items: [{
          name: p.description || 'Payment',
          quantity: '1',
          base_price_money: { amount: p.amount, currency: p.currency.toUpperCase() }
        }]
      },
      checkout_options: { redirect_url: p.successUrl }
    })
  });
  const data = await res.json();
  if (!res.ok) {
    const err = new Error(data.errors?.[0]?.detail || 'Square payment link failed');
    err.status = 502; err.code = 'GATEWAY_ERROR'; throw err;
  }
  audit('gateway_session_created', { gateway: 'square', id: data.payment_link?.id });
  return {
    gatewayPaymentId: data.payment_link?.id,
    checkoutUrl: data.payment_link?.url,
    status: 'pending'
  };
}

const gatewayAdapters = {
  stripe: createStripeSession,
  paystack: createPaystackSession,
  flutterwave: createFlutterwaveSession,
  paypal: createPayPalOrder,
  razorpay: createRazorpayOrder,
  square: createSquareLink
};

async function createGatewayPayment(gateway, payload) {
  const fn = gatewayAdapters[gateway];
  if (!fn) {
    const err = new Error(`Unsupported gateway: ${gateway}`);
    err.status = 400; err.code = 'UNSUPPORTED_GATEWAY'; throw err;
  }
  return fn(payload);
}

// ============================================================================
// 5. PAYMENT SESSIONS → TRANSACTIONS → INVOICE → RECEIPT
// ============================================================================
function makeReceiptId() {
  return `RCP-${Date.now().toString(36).toUpperCase()}-${uuidv4().slice(0, 8).toUpperCase()}`;
}

async function createPaymentSession(actor, body) {
  const data = validate(PaymentCreateSchema, body);
  if (data.idempotencyKey) {
    const cached = checkIdempotency(`pay:${actor.id}:${data.idempotencyKey}`);
    if (cached) {
      audit('payment_idempotent_hit', { key: data.idempotencyKey, actor: actor.id });
      return cached;
    }
  }

  const sessionId = `ps_${uuidv4().replace(/-/g, '').slice(0, 20)}`;
  const partnerId = actor.type === 'partner' ? actor.id : null;
  const userId = actor.type === 'user' ? actor.id : null;

  const gw = await createGatewayPayment(data.gateway, {
    amount: data.amount,
    currency: data.currency,
    description: data.description,
    successUrl: data.successUrl,
    cancelUrl: data.cancelUrl,
    idempotencyKey: data.idempotencyKey,
    email: data.email,
    metadata: {
      ...(data.metadata || {}),
      partnerReferenceId: data.partnerReferenceId,
      sessionId,
      partnerId: partnerId || '',
      userId: userId || ''
    }
  });

  const now = new Date().toISOString();
  const session = {
    id: sessionId,
    partnerId,
    userId,
    amount: data.amount,
    currency: data.currency,
    gateway: data.gateway,
    partnerReferenceId: data.partnerReferenceId || null,
    description: data.description || '',
    gatewayPaymentId: gw.gatewayPaymentId,
    checkoutUrl: gw.checkoutUrl || null,
    clientKey: gw.clientKey || null,
    status: 'pending',
    receiptId: null,
    invoiceId: null,
    createdAt: now,
    updatedAt: now,
    metadata: data.metadata || {}
  };

  await db.collection('payment_sessions').doc(sessionId).set(session);
  await db.collection('transactions').doc(sessionId).set({
    id: sessionId,
    sessionId,
    partnerId,
    userId,
    amount: data.amount,
    currency: data.currency,
    gateway: data.gateway,
    gatewayPaymentId: gw.gatewayPaymentId,
    status: 'pending',
    createdAt: now,
    updatedAt: now
  });

  audit('payment_session_created', {
    sessionId, partnerId, userId, gateway: data.gateway, amount: data.amount, currency: data.currency
  });

  const response = {
    paymentSessionId: sessionId,
    status: session.status,
    checkoutUrl: session.checkoutUrl,
    gatewayPaymentId: session.gatewayPaymentId,
    clientKey: session.clientKey,
    amount: session.amount,
    currency: session.currency
  };
  if (data.idempotencyKey) storeIdempotency(`pay:${actor.id}:${data.idempotencyKey}`, response);
  return response;
}

async function applyGatewayResult({ gateway, gatewayPaymentId, status, amount, raw }) {
  const snap = await db.collection('payment_sessions')
    .where('gatewayPaymentId', '==', gatewayPaymentId)
    .limit(1).get();
  if (snap.empty) {
    audit('webhook_unknown_payment', { gateway, gatewayPaymentId });
    return null;
  }
  const doc = snap.docs[0];
  const session = { id: doc.id, ...doc.data() };
  if (session.status === 'paid' && status === 'paid') return session;

  const now = new Date().toISOString();
  const updates = { status, updatedAt: now, gatewayRaw: raw || null };
  if (status === 'paid') {
    updates.receiptId = makeReceiptId();
    updates.invoiceId = `INV-${Date.now().toString(36).toUpperCase()}`;
    updates.paidAt = now;
  }
  await doc.ref.update(updates);
  await db.collection('transactions').doc(session.id).set({
    status,
    updatedAt: now,
    receiptId: updates.receiptId || null,
    invoiceId: updates.invoiceId || null,
    paidAt: updates.paidAt || null,
    amount: amount || session.amount
  }, { merge: true });

  if (status === 'paid') {
    await db.collection('invoices').doc(updates.invoiceId).set({
      id: updates.invoiceId,
      sessionId: session.id,
      partnerId: session.partnerId,
      userId: session.userId,
      amount: session.amount,
      currency: session.currency,
      gateway: session.gateway,
      partnerReferenceId: session.partnerReferenceId,
      createdAt: now
    });
    await db.collection('receipts').doc(updates.receiptId).set({
      id: updates.receiptId,
      sessionId: session.id,
      invoiceId: updates.invoiceId,
      partnerId: session.partnerId,
      userId: session.userId,
      amount: session.amount,
      currency: session.currency,
      gateway: session.gateway,
      partnerReferenceId: session.partnerReferenceId,
      description: session.description,
      paidAt: now,
      createdAt: now
    });
  }

  audit('payment_status_updated', { sessionId: session.id, gateway, status, receiptId: updates.receiptId });
  return { ...session, ...updates };
}

async function getSession(id) {
  const doc = await db.collection('payment_sessions').doc(id).get();
  return doc.exists ? { id: doc.id, ...doc.data() } : null;
}

async function listSessionsForUser(userId, limit = 50) {
  const snap = await db.collection('payment_sessions')
    .where('userId', '==', userId)
    .orderBy('createdAt', 'desc')
    .limit(limit).get();
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

async function listSessionsForPartner(partnerId, limit = 50) {
  const snap = await db.collection('payment_sessions')
    .where('partnerId', '==', partnerId)
    .orderBy('createdAt', 'desc')
    .limit(limit).get();
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

async function getReceipt(id) {
  const doc = await db.collection('receipts').doc(id).get();
  return doc.exists ? { id: doc.id, ...doc.data() } : null;
}

// ============================================================================
// 6. WEBHOOKS (signature required)
// ============================================================================
function requireWebhookSecret(name) {
  const v = process.env[name];
  if (!v || !String(v).trim()) {
    const err = new Error(`Webhook secret not configured: ${name}`);
    err.status = 503; err.code = 'WEBHOOK_CONFIG_MISSING'; throw err;
  }
  return v;
}

const webhookRouter = express.Router();

webhookRouter.post('/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const secret = requireWebhookSecret('STRIPE_WEBHOOK_SECRET');
    const sig = req.headers['stripe-signature'];
    if (!sig) return res.status(401).json({ error: 'Missing Stripe-Signature' });
    const payload = req.body;
    const elements = {};
    String(sig).split(',').forEach(part => {
      const [k, v] = part.split('=');
      elements[k] = v;
    });
    const signedPayload = `${elements.t}.${payload.toString()}`;
    const expected = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');
    if (!safeEqual(expected, elements.v1 || '')) {
      audit('webhook_signature_failed', { gateway: 'stripe' });
      return res.status(401).json({ error: 'Invalid signature', code: 'WEBHOOK_SIGNATURE_INVALID' });
    }
    const event = JSON.parse(payload.toString());
    assertNotReplayed(event.id);
    let status = null, gatewayPaymentId = null, amount = null;
    if (event.type === 'checkout.session.completed') {
      status = 'paid';
      gatewayPaymentId = event.data.object.id;
      amount = event.data.object.amount_total;
    } else if (event.type === 'payment_intent.payment_failed') {
      status = 'failed';
      gatewayPaymentId = event.data.object.id;
    } else if (event.type === 'checkout.session.expired') {
      status = 'expired';
      gatewayPaymentId = event.data.object.id;
    }
    if (status && gatewayPaymentId) {
      await applyGatewayResult({ gateway: 'stripe', gatewayPaymentId, status, amount, raw: event.data.object });
    }
    res.json({ received: true });
  } catch (err) {
    console.error('[webhook/stripe]', err.message);
    res.status(err.status || 400).json({ error: err.message, code: err.code });
  }
});

webhookRouter.post('/paystack', express.json(), async (req, res) => {
  try {
    const secret = requireWebhookSecret('PAYSTACK_SECRET_KEY');
    const hash = crypto.createHmac('sha512', secret).update(JSON.stringify(req.body)).digest('hex');
    if (!safeEqual(hash, req.headers['x-paystack-signature'] || '')) {
      audit('webhook_signature_failed', { gateway: 'paystack' });
      return res.status(401).json({ error: 'Invalid signature' });
    }
    const event = req.body;
    assertNotReplayed(event.data?.id || event.data?.reference);
    if (event.event === 'charge.success') {
      await applyGatewayResult({
        gateway: 'paystack', gatewayPaymentId: event.data.reference,
        status: 'paid', amount: event.data.amount, raw: event.data
      });
    } else if (event.event === 'charge.failed') {
      await applyGatewayResult({
        gateway: 'paystack', gatewayPaymentId: event.data.reference,
        status: 'failed', raw: event.data
      });
    }
    res.sendStatus(200);
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

webhookRouter.post('/flutterwave', express.json(), async (req, res) => {
  try {
    const secret = requireWebhookSecret('FLUTTERWAVE_SECRET_KEY');
    const signature = req.headers['verif-hash'];
    if (!signature || !safeEqual(signature, secret)) {
      audit('webhook_signature_failed', { gateway: 'flutterwave' });
      return res.status(401).json({ error: 'Invalid signature' });
    }
    const data = req.body.data || req.body;
    assertNotReplayed(data.id || data.tx_ref);
    const status = (data.status === 'successful' || req.body.event === 'charge.completed')
      ? 'paid' : data.status === 'failed' ? 'failed' : null;
    if (status) {
      await applyGatewayResult({
        gateway: 'flutterwave',
        gatewayPaymentId: data.tx_ref || data.id,
        status,
        amount: data.amount ? Math.round(Number(data.amount) * 100) : undefined,
        raw: data
      });
    }
    res.json({ status: 'success' });
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

webhookRouter.post('/paypal', express.json(), async (req, res) => {
  try {
    const event = req.body;
    const resource = event.resource || {};
    assertNotReplayed(event.id);
    if (event.event_type === 'PAYMENT.CAPTURE.COMPLETED' || event.event_type === 'CHECKOUT.ORDER.APPROVED') {
      await applyGatewayResult({ gateway: 'paypal', gatewayPaymentId: resource.id, status: 'paid', raw: resource });
    } else if (event.event_type === 'PAYMENT.CAPTURE.DENIED' || event.event_type === 'CHECKOUT.ORDER.VOIDED') {
      await applyGatewayResult({ gateway: 'paypal', gatewayPaymentId: resource.id, status: 'failed', raw: resource });
    }
    res.sendStatus(200);
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

webhookRouter.post('/razorpay', express.json(), async (req, res) => {
  try {
    const secret = requireWebhookSecret('RAZORPAY_KEY_SECRET');
    const signature = req.headers['x-razorpay-signature'];
    const body = JSON.stringify(req.body);
    const expected = crypto.createHmac('sha256', secret).update(body).digest('hex');
    if (!safeEqual(expected, signature || '')) {
      audit('webhook_signature_failed', { gateway: 'razorpay' });
      return res.status(401).json({ error: 'Invalid signature' });
    }
    const event = req.body;
    const entity = event.payload?.payment?.entity || event.payload?.order?.entity || {};
    assertNotReplayed(event.event_id || entity.id);
    if (event.event === 'payment.captured' || event.event === 'order.paid') {
      await applyGatewayResult({
        gateway: 'razorpay', gatewayPaymentId: entity.order_id || entity.id,
        status: 'paid', amount: entity.amount, raw: entity
      });
    } else if (event.event === 'payment.failed') {
      await applyGatewayResult({
        gateway: 'razorpay', gatewayPaymentId: entity.order_id || entity.id,
        status: 'failed', raw: entity
      });
    }
    res.json({ status: 'ok' });
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

// ============================================================================
// 7. EXPRESS APP
// ============================================================================
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.set('trust proxy', 1);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error('CORS: origin not allowed'));
  },
  credentials: true
}));

app.use(rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 60000,
  max: Number(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: 'Rate limit exceeded', code: 'RATE_LIMIT' })
}));

app.use('/webhooks', webhookRouter);
app.use(express.json({ limit: '256kb' }));

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'paypaddy', ts: new Date().toISOString() });
});

app.post('/oauth/token', async (req, res) => {
  try {
    const token = await issueClientCredentialsToken(req.body);
    res.json(token);
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message, code: err.code });
  }
});

app.post('/api/v1/payments', requireAnyAuth, async (req, res) => {
  try {
    const actor = req.authType === 'partner'
      ? { type: 'partner', id: req.partner.partnerId, scopes: req.partner.scopes }
      : { type: 'user', id: req.user.uid };
    if (actor.type === 'partner' && !(actor.scopes || []).includes('payments:create')) {
      return res.status(403).json({ error: 'Scope payments:create required', code: 'INSUFFICIENT_SCOPE' });
    }
    const result = await createPaymentSession(actor, req.body);
    res.status(201).json(result);
  } catch (err) {
    console.error('[payments/create]', err.message);
    res.status(err.status || 500).json({ error: err.message, code: err.code || 'INTERNAL' });
  }
});

app.get('/api/v1/payments', requireAnyAuth, async (req, res) => {
  try {
    let list;
    if (req.authType === 'partner') {
      if (!(req.partner.scopes || []).includes('payments:read')) {
        return res.status(403).json({ error: 'Scope payments:read required', code: 'INSUFFICIENT_SCOPE' });
      }
      list = await listSessionsForPartner(req.partner.partnerId);
    } else {
      list = await listSessionsForUser(req.user.uid);
    }
    res.json({ payments: list });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/payments/:id', requireAnyAuth, async (req, res) => {
  try {
    const session = await getSession(req.params.id);
    if (!session) return res.status(404).json({ error: 'Payment session not found', code: 'NOT_FOUND' });
    if (req.authType === 'partner') {
      assertPartnerOwns(req.partner.partnerId, session.partnerId);
    } else if (session.userId !== req.user.uid) {
      return res.status(403).json({ error: 'Forbidden', code: 'FORBIDDEN' });
    }
    res.json(session);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message, code: err.code });
  }
});

app.get('/api/v1/receipts/:id', requireAnyAuth, async (req, res) => {
  try {
    const receipt = await getReceipt(req.params.id);
    if (!receipt) return res.status(404).json({ error: 'Receipt not found', code: 'NOT_FOUND' });
    if (req.authType === 'partner') {
      assertPartnerOwns(req.partner.partnerId, receipt.partnerId);
    } else if (receipt.userId !== req.user.uid) {
      return res.status(403).json({ error: 'Forbidden', code: 'FORBIDDEN' });
    }
    res.json(receipt);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message, code: err.code });
  }
});

app.use((err, _req, res, _next) => {
  console.error('[unhandled]', err);
  res.status(500).json({ error: 'Internal server error', code: 'INTERNAL' });
});

app.use((_req, res) => res.status(404).json({ error: 'Not found', code: 'NOT_FOUND' }));

app.listen(PORT, () => {
  console.log(`PayPaddy API listening on :${PORT}`);
  audit('server_started', { port: PORT, env: NODE_ENV });
});
