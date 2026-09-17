import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import {
  verifyMasterPassword,
  createSessionToken,
  verifySessionToken,
  isAllowedHost,
  checkBruteForce,
  recordFailedAttempt,
  resetFailedAttempt,
  failedAttempts,
  getClientIp,
  pruneExpiredChallenges
} from './server.js';

test('verifyMasterPassword validates correctly in constant time', () => {
  const secret = 'super-secret-password-123';
  assert.equal(verifyMasterPassword('super-secret-password-123', secret), true);
  assert.equal(verifyMasterPassword('wrong-password', secret), false);
  assert.equal(verifyMasterPassword('', secret), false);
  assert.equal(verifyMasterPassword(123, secret), false);
});

test('createSessionToken & verifySessionToken HMAC integrity', () => {
  const secretKey = 'test-secret-key-32-bytes-minimum-size';
  const token = createSessionToken(secretKey);
  assert.equal(verifySessionToken(token, secretKey), true);

  // Wrong secret fails verification (cannot forge)
  assert.equal(verifySessionToken(token, 'attacker-known-secret-key-wrong'), false);

  // Tampered payload fails
  const [str, sig] = token.split('.');
  const tamperedPayload = Buffer.from(JSON.stringify({ auth: true, exp: Date.now() + 99999999 })).toString('base64url');
  assert.equal(verifySessionToken(`${tamperedPayload}.${sig}`, secretKey), false);

  // Expired token fails
  const expiredPayload = Buffer.from(JSON.stringify({ auth: true, exp: Date.now() - 1000 })).toString('base64url');
  const expiredSig = crypto.createHmac('sha256', secretKey).update(expiredPayload).digest('base64url');
  assert.equal(verifySessionToken(`${expiredPayload}.${expiredSig}`, secretKey), false);
});

test('getClientIp prioritizes X-Real-IP over client-manipulated X-Forwarded-For', () => {
  const mockReq = {
    headers: {
      'x-real-ip': '203.0.113.195',
      'x-forwarded-for': '1.1.1.1, 10.0.0.1'
    },
    socket: { remoteAddress: '127.0.0.1' }
  };
  assert.equal(getClientIp(mockReq), '203.0.113.195');

  const fallbackReq = {
    headers: {},
    socket: { remoteAddress: '198.51.100.44' }
  };
  assert.equal(getClientIp(fallbackReq), '198.51.100.44');
});

test('checkBruteForce locks IP after 5 failed attempts', () => {
  const testIp = '192.0.2.100';
  resetFailedAttempt(testIp);
  assert.equal(checkBruteForce(testIp).allowed, true);

  for (let i = 0; i < 4; i++) {
    recordFailedAttempt(testIp);
    assert.equal(checkBruteForce(testIp).allowed, true);
  }

  // 5th attempt locks IP
  recordFailedAttempt(testIp);
  const check = checkBruteForce(testIp);
  assert.equal(check.allowed, false);
  assert.ok(check.remainingSec > 0);

  resetFailedAttempt(testIp);
  assert.equal(checkBruteForce(testIp).allowed, true);
});

test('isAllowedHost permits only recognized sister domains', () => {
  assert.equal(isAllowedHost('aeter.my.id'), true);
  assert.equal(isAllowedHost('auth.aeter.my.id'), true);
  assert.equal(isAllowedHost('shorekeeper.my.id'), true);
  assert.equal(isAllowedHost('jarvis.shorekeeper.my.id'), true);
  assert.equal(isAllowedHost('tethys.web.id'), true);
  assert.equal(isAllowedHost('schnee.web.id'), true);
  assert.equal(isAllowedHost('localhost'), true);
  assert.equal(isAllowedHost('127.0.0.1'), true);

  // Untrusted hosts rejected
  assert.equal(isAllowedHost('evil.com'), false);
  assert.equal(isAllowedHost('attacker.aeter.my.id.evil.com'), false);
  assert.equal(isAllowedHost('notshorekeeper.my.id.com'), false);
  assert.equal(isAllowedHost(''), false);
});

test('pruneExpiredChallenges deletes only expired challenges', () => {
  const now = 1000000;
  const mockChallenges = {
    c1: { challenge: 'abc', exp: now - 1000 },
    c2: { challenge: 'def', exp: now + 5000 },
    c3: { challenge: 'ghi', exp: now - 50 }
  };

  const pruned = pruneExpiredChallenges(mockChallenges, now);
  assert.equal(pruned, 2);
  assert.equal(mockChallenges.c1, undefined);
  assert.equal(mockChallenges.c3, undefined);
  assert.ok(mockChallenges.c2);
});
