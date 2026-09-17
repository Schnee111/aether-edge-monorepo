import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8799;
const RP_NAME = 'Aeter Auth Gate';
// Central RP ID is aeter.my.id
const RP_IDS = ['aeter.my.id', 'shorekeeper.my.id', 'tethys.web.id', 'localhost'];
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || (process.env.NODE_ENV === 'test' ? 'test-password' : '');
if (!MASTER_PASSWORD && process.env.NODE_ENV !== 'test') {
  throw new Error('[auth-gate] FATAL: MASTER_PASSWORD environment variable must be set (no hardcoded fallback allowed)');
}

const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV === 'test' ? 'test-secret-32-chars-long-security' : '');
if (!JWT_SECRET && process.env.NODE_ENV !== 'test') {
  throw new Error('[auth-gate] FATAL: JWT_SECRET environment variable must be set (no hardcoded fallback allowed)');
}

export const ALLOWED_DOMAINS = [
  'aeter.my.id',
  'shorekeeper.my.id',
  'tethys.web.id',
  'schnee.web.id',
  'localhost',
  '127.0.0.1'
];

export function isAllowedHost(host) {
  if (!host || typeof host !== 'string') return false;
  const clean = host.split(':')[0].toLowerCase();
  return ALLOWED_DOMAINS.some(d => clean === d || clean.endsWith('.' + d));
}

const DATA_FILE = path.join(__dirname, 'data.json');

// Constant-time password verification to prevent timing attacks
export function verifyMasterPassword(providedPassword, expectedPassword = MASTER_PASSWORD) {
  if (typeof providedPassword !== 'string' || typeof expectedPassword !== 'string') return false;
  const providedBuffer = Buffer.from(providedPassword);
  const masterBuffer = Buffer.from(expectedPassword);
  if (providedBuffer.length !== masterBuffer.length) {
    crypto.timingSafeEqual(masterBuffer, masterBuffer);
    return false;
  }
  return crypto.timingSafeEqual(providedBuffer, masterBuffer);
}

// In-memory brute-force protection (Per-IP failure tracking)
export const failedAttempts = new Map(); // ip -> { count, lockedUntil }

export function checkBruteForce(ip) {
  const record = failedAttempts.get(ip);
  if (!record) return { allowed: true };
  if (record.lockedUntil && Date.now() < record.lockedUntil) {
    const remainingSec = Math.ceil((record.lockedUntil - Date.now()) / 1000);
    return { allowed: false, remainingSec };
  }
  if (record.lockedUntil && Date.now() >= record.lockedUntil) {
    failedAttempts.delete(ip);
    return { allowed: true };
  }
  return { allowed: true };
}

export function recordFailedAttempt(ip) {
  const now = Date.now();
  const record = failedAttempts.get(ip) || { count: 0, firstAttempt: now };
  record.count += 1;
  if (record.count >= 5) {
    record.lockedUntil = now + 15 * 60 * 1000; // 15-minute lockout
  }
  failedAttempts.set(ip, record);
}

export function resetFailedAttempt(ip) {
  failedAttempts.delete(ip);
}

export function getClientIp(req) {
  // Trust X-Real-IP set by Nginx, fallback to socket remote address
  return (req.headers && req.headers['x-real-ip']) || (req.socket && req.socket.remoteAddress) || 'unknown';
}

export let state = {
  passkeys: [], // array of { id, publicKey, counter, transports, createdAt, deviceName }
  challenges: {} // challenge session map: { challengeId: challengeStr }
};

if (fs.existsSync(DATA_FILE)) {
  try {
    state = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (!state.challenges) state.challenges = {};
    if (!state.passkeys) state.passkeys = [];
  } catch (e) {
    console.error('Failed to parse data file:', e);
  }
}

export function saveData() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(state, null, 2));
}

export function pruneExpiredChallenges(challengesObj, now = Date.now()) {
  let count = 0;
  for (const [cid, data] of Object.entries(challengesObj || {})) {
    if (data.exp && data.exp < now) {
      delete challengesObj[cid];
      count++;
    }
  }
  return count;
}

// Background cleanup of expired challenges every 5 minutes
setInterval(() => {
  const pruned = pruneExpiredChallenges(state.challenges);
  if (pruned > 0) saveData();
}, 5 * 60 * 1000).unref();

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    try {
      const u = new URL(origin);
      if (isAllowedHost(u.hostname)) return callback(null, true);
    } catch (e) {}
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

// Helper to determine RP_ID from hostname
function getRpId(req) {
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0];
  for (const id of RP_IDS) {
    if (host.endsWith(id)) return id;
  }
  return 'aeter.my.id';
}

function getOrigin(req) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'aeter.my.id';
  return `${proto}://${host}`;
}

// Token generation and verification (HMAC signature)
export function createSessionToken(secret = JWT_SECRET) {
  const payload = {
    auth: true,
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days
  };
  const str = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(str).digest('base64url');
  return `${str}.${sig}`;
}

export function verifySessionToken(token, secret = JWT_SECRET) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return false;
  const [str, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', secret).update(str).digest('base64url');
  if (sig !== expectedSig) return false;
  try {
    const payload = JSON.parse(Buffer.from(str, 'base64url').toString('utf8'));
    if (payload.exp && payload.exp > Date.now()) return true;
  } catch (e) {
    return false;
  }
  return false;
}

// Nginx auth_request endpoint
app.get('/api/auth/verify', (req, res) => {
  const token = req.cookies.aeter_auth || req.headers['x-aeter-auth'];
  if (verifySessionToken(token)) {
    return res.status(200).send('OK');
  }
  return res.status(401).send('Unauthorized');
});

// SSO Callback for external domains (e.g., shorekeeper.my.id/auth/callback?token=...&return_to=...)
app.get('/auth/callback', (req, res) => {
  const { token, return_to } = req.query;
  if (!token || !verifySessionToken(token)) {
    return res.status(400).send('Invalid or expired SSO token');
  }

  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0];
  const isLocal = host.includes('localhost') || host.includes('127.0.0.1');

  // Set cookie for the specific host domain
  res.cookie('aeter_auth', token, {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: !isLocal,
    sameSite: 'lax'
  });

  // If host is 9router, also issue 9router internal auth_token (30 days validity)
  if (host.includes('9router')) {
    const nineRouterSecret = process.env.NINEROUTER_JWT_SECRET || '9router-secret-key-random-12345';
    const b64url = (b) => b.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const nowSec = Math.floor(Date.now() / 1000);
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = {
      authenticated: true,
      iat: nowSec,
      exp: nowSec + 30 * 24 * 3600
    };
    const parts = [
      b64url(Buffer.from(JSON.stringify(header))),
      b64url(Buffer.from(JSON.stringify(payload)))
    ];
    const sig = crypto.createHmac('sha256', nineRouterSecret).update(parts.join('.')).digest();
    parts.push(b64url(sig));
    const nineToken = parts.join('.');

    res.cookie('auth_token', nineToken, {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: !isLocal,
      sameSite: 'lax',
      path: '/'
    });
  }

  // Validate return_to against domain allowlist
  let dest = '/';
  if (return_to && typeof return_to === 'string') {
    try {
      const u = new URL(return_to, `https://${host}`);
      if (isAllowedHost(u.hostname)) {
        dest = return_to;
      }
    } catch (e) {
      dest = '/';
    }
  }
  res.redirect(dest);
});

// Direct Password Login
app.post('/api/auth/login-password', (req, res) => {
  const clientIp = getClientIp(req);
  
  const bruteCheck = checkBruteForce(clientIp);
  if (!bruteCheck.allowed) {
    return res.status(429).json({
      success: false,
      message: `Too many failed attempts. Locked for ${bruteCheck.remainingSec}s`
    });
  }

  const { password } = req.body;
  if (verifyMasterPassword(password)) {
    resetFailedAttempt(clientIp);
    const token = createSessionToken();
    const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0];
    const isLocal = host.includes('localhost') || host.includes('127.0.0.1');
    const domain = isLocal ? undefined : (host.endsWith('aeter.my.id') ? '.aeter.my.id' : undefined);

    res.cookie('aeter_auth', token, {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: !isLocal,
      sameSite: 'lax',
      domain: domain
    });

    return res.json({ success: true, token });
  }

  recordFailedAttempt(clientIp);
  return res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// Passkey: Registration Options
app.post('/api/auth/register-options', async (req, res) => {
  const clientIp = getClientIp(req);
  const bruteCheck = checkBruteForce(clientIp);
  if (!bruteCheck.allowed) {
    return res.status(429).json({
      success: false,
      message: `Too many failed attempts. Locked for ${bruteCheck.remainingSec}s`
    });
  }

  const { password, deviceName } = req.body;
  if (!verifyMasterPassword(password)) {
    recordFailedAttempt(clientIp);
    return res.status(401).json({ success: false, message: 'Invalid verification password' });
  }
  resetFailedAttempt(clientIp);

  const rpID = getRpId(req);
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rpID,
    userID: new TextEncoder().encode('schnee-user-id'),
    userName: 'Schnee',
    userDisplayName: 'Schnee',
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred'
    }
  });

  const challengeId = crypto.randomUUID();
  state.challenges[challengeId] = { challenge: options.challenge, exp: Date.now() + 120000, deviceName };

  res.json({ success: true, options, challengeId });
});

// Passkey: Registration Verify
app.post('/api/auth/register-verify', async (req, res) => {
  const { response, challengeId } = req.body;
  const stored = state.challenges[challengeId];
  if (!stored || stored.exp < Date.now()) {
    return res.status(400).json({ success: false, message: 'Challenge expired' });
  }
  delete state.challenges[challengeId];

  const rpID = getRpId(req);
  const origin = getOrigin(req);

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: stored.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;
      state.passkeys.push({
        id: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64'),
        counter: credential.counter,
        transports: response.response.transports || [],
        deviceName: stored.deviceName || 'Passkey Device',
        createdAt: new Date().toISOString()
      });
      saveData();

      const token = createSessionToken();
      const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0];
      const isLocal = host.includes('localhost') || host.includes('127.0.0.1');
      const domain = isLocal ? undefined : (host.endsWith('aeter.my.id') ? '.aeter.my.id' : undefined);

      res.cookie('aeter_auth', token, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: !isLocal,
        sameSite: 'lax',
        domain: domain
      });

      return res.json({ success: true, message: 'Passkey successfully registered', token });
    }
  } catch (e) {
    console.error('Registration verification error:', e);
    return res.status(400).json({ success: false, message: e.message });
  }
  return res.status(400).json({ success: false, message: 'Passkey verification failed' });
});

// Passkey: Auth Options
app.post('/api/auth/auth-options', async (req, res) => {
  const rpID = getRpId(req);
  const options = await generateAuthenticationOptions({
    rpID: rpID,
    userVerification: 'preferred',
    allowCredentials: state.passkeys.map(pk => ({
      id: pk.id,
      transports: pk.transports
    }))
  });

  const challengeId = crypto.randomUUID();
  state.challenges[challengeId] = { challenge: options.challenge, exp: Date.now() + 120000 };

  res.json({ success: true, options, challengeId, hasPasskeys: state.passkeys.length > 0 });
});

// Passkey: Auth Verify
app.post('/api/auth/auth-verify', async (req, res) => {
  const { response, challengeId } = req.body;
  const stored = state.challenges[challengeId];
  if (!stored || stored.exp < Date.now()) {
    return res.status(400).json({ success: false, message: 'Challenge expired' });
  }
  delete state.challenges[challengeId];

  const passkey = state.passkeys.find(pk => pk.id === response.id);
  if (!passkey) {
    return res.status(400).json({ success: false, message: 'Passkey unrecognized' });
  }

  const rpID = getRpId(req);
  const origin = getOrigin(req);

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: stored.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: passkey.id,
        publicKey: Buffer.from(passkey.publicKey, 'base64'),
        counter: passkey.counter
      }
    });

    if (verification.verified) {
      passkey.counter = verification.authenticationInfo.newCounter;
      saveData();

      const token = createSessionToken();
      const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0];
      const isLocal = host.includes('localhost') || host.includes('127.0.0.1');
      const domain = isLocal ? undefined : (host.endsWith('aeter.my.id') ? '.aeter.my.id' : undefined);

      res.cookie('aeter_auth', token, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: !isLocal,
        sameSite: 'lax',
        domain: domain
      });

      return res.json({ success: true, token });
    }
  } catch (e) {
    console.error('Auth verification error:', e);
    return res.status(400).json({ success: false, message: e.message });
  }
  return res.status(400).json({ success: false, message: 'Biometric verification failed' });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0];
  const domain = host.endsWith('aeter.my.id') ? '.aeter.my.id' : undefined;
  res.clearCookie('aeter_auth', { domain });
  res.json({ success: true });
});

// Serve the Clean Portal UI
app.use(express.static(path.join(__dirname, 'public')));

app.get('{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`[auth-gate] Running on port ${PORT} (RP: ${RP_IDS.join(', ')})`);
  });
}

export { app };
