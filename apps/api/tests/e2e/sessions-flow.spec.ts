import { test, expect } from '@playwright/test';
import {
  extractTokenFromEmail,
  waitForOutboxDelivery,
} from './helpers/email-outbox.js';

test.describe('Automated Session Management API (List Sessions -> Revoke Specific -> Revoke All)', () => {
  test.setTimeout(90_000);

  const origin = 'http://localhost:5173';
  const testEmail = `sessions-user-${Date.now()}@example.com`;
  const testPassword = 'SessionPassword123!';


  test('Session lifecycle and revocation management', async ({ request }) => {
    // 1. Signup user & verify email (token read from outbox â€” provider-agnostic)
    const signupRes = await request.post('/api/v1/auth/signup', {
      data: { email: testEmail, password: testPassword, firstName: 'Session', lastName: 'User' },
      headers: { Origin: origin },
    });
    const verifyEmail = await waitForOutboxDelivery(testEmail, 'Verify your email');
    const verifyToken = extractTokenFromEmail(verifyEmail);
    const verifyRes = await request.post('/api/v1/auth/verify-email', {
      data: { token: verifyToken },
      headers: { Origin: origin },
    });
    expect(verifyRes.status()).toBe(200);

    // 2. Login
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email: testEmail, password: testPassword },
      headers: { Origin: origin },
    });
    expect(loginRes.status()).toBe(200);

    // 3. List active sessions
    const sessionsRes = await request.get('/api/v1/auth/sessions', {
      headers: { Origin: origin },
    });
    expect(sessionsRes.status()).toBe(200);
    const body = await sessionsRes.json();
    expect(body.sessions).toBeInstanceOf(Array);
    expect(body.sessions.length).toBeGreaterThan(0);

    // 4. Attempt revoking an invalid non-existent session ID -> 404 NOT_FOUND
    const invalidRevoke = await request.delete('/api/v1/auth/sessions/sess_nonexistent999999999999', {
      headers: { Origin: origin },
    });
    expect(invalidRevoke.status()).toBe(404);

    // 5. Test Revoke All sessions endpoint
    const revokeAllRes = await request.post('/api/v1/auth/sessions/revoke-all', {
      headers: { Origin: origin },
    });
    expect(revokeAllRes.status()).toBe(204);

    // 6. Verify profile endpoint returns 401 after revoke all
    const mePostRevoke = await request.get('/api/v1/auth/me', {
      headers: { Origin: origin },
    });
    expect(mePostRevoke.status()).toBe(401);
  });
});
