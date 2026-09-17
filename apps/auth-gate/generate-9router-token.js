import crypto from 'crypto';

export function generate9RouterToken() {
  function base64url(buf) {
    return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  }

  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    authenticated: true,
    iat: now,
    exp: now + 30 * 24 * 3600 // 30 days
  };

  const secret = "9router-secret-key-random-12345";

  const tokenParts = [
    base64url(Buffer.from(JSON.stringify(header))),
    base64url(Buffer.from(JSON.stringify(payload)))
  ];
  const sig = crypto.createHmac('sha256', secret).update(tokenParts.join('.')).digest();
  tokenParts.push(base64url(sig));

  return tokenParts.join('.');
}
