import { test, expect } from '@playwright/test';
import {
  extractTokenFromEmail,
  waitForOutboxDelivery,
} from './helpers/email-outbox.js';

test.describe('Automated API Identity Flow (Signup -> Verify -> Login -> Session -> Logout)', () => {
  test.setTimeout(90_000);

  const origin = 'http://localhost:5173';
  const testEmail = `e2e-user-${Date.now()}@example.com`;
  const testPassword = 'SecurePassword123!';


  test('Complete Authentication & Identity Lifecycle', async ({ request }) => {
    // 1. Signup user (starts as PENDING_VERIFICATION)
    const signupRes = await request.post('/api/v1/auth/signup', {
      data: {
        email: testEmail,
        password: testPassword,
        firstName: 'Sentinel',
        lastName: 'Tester',
      },
      headers: { Origin: origin },
    });
    expect(signupRes.status()).toBe(201);
    const signupBody = await signupRes.json();
    expect(signupBody.user).toBeDefined();
    expect(signupBody.user.email).toBe(testEmail);
    expect(signupBody.user.status).toBe('PENDING_VERIFICATION');

    // Extract verification token from the email outbox (works in console AND smtp mode)
    const verifyEmail = await waitForOutboxDelivery(testEmail, 'Verify your email');
    const verifyToken = extractTokenFromEmail(verifyEmail);
    const verifyRes = await request.post('/api/v1/auth/verify-email', {
      data: { token: verifyToken },
      headers: { Origin: origin },
    });
    expect(verifyRes.status()).toBe(200);

    // 2. Login (Strict assertion: MUST return HTTP 200 for activated account)
    const loginRes = await request.post('/api/v1/auth/login', {
      data: {
        email: testEmail,
        password: testPassword,
      },
      headers: { Origin: origin },
    });
    
    expect(loginRes.status()).toBe(200);

    const loginBody = await loginRes.json();
    expect(loginBody.user).toBeDefined();
    expect(loginBody.user.email).toBe(testEmail);

    // 3. GET /auth/me profile verification
    const meRes = await request.get('/api/v1/auth/me', {
      headers: { Origin: origin },
    });
    expect(meRes.status()).toBe(200);
    const meBody = await meRes.json();
    expect(meBody.user?.email).toBe(testEmail);

    // 4. Logout
    const logoutRes = await request.post('/api/v1/auth/logout', {
      headers: { Origin: origin },
    });
    expect(logoutRes.status()).toBe(204);

    // 5. GET /auth/me post logout should be 401
    const meAfterLogout = await request.get('/api/v1/auth/me', {
      headers: { Origin: origin },
    });
    expect(meAfterLogout.status()).toBe(401);
  });
});
