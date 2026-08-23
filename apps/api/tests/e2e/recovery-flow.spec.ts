import { test, expect } from '@playwright/test';
import {
  countOutboxRows,
  extractTokenFromEmail,
  findOutboxRow,
  waitForOutboxRow,
} from './helpers/email-outbox.js';

test.describe('Password Recovery Flow (Forgot Password -> Email -> Token -> Reset -> Login)', () => {
  test.setTimeout(120_000);

  const origin = 'http://localhost:5173';
  const testEmail = `recovery-user-${Date.now()}@example.com`;
  const initialPassword = 'InitialPassword123!';
  const newPassword = 'UpdatedPassword456!';


  test('Complete recovery flow with real email delivery', async ({ request }) => {
    // 1. Signup user
    const signupRes = await request.post('/api/v1/auth/signup', {
      data: {
        email: testEmail,
        password: initialPassword,
        firstName: 'Recovery',
        lastName: 'Tester',
      },
      headers: { Origin: origin },
    });
    expect(signupRes.status()).toBe(201);

    // 2. Verify email by extracting the token from the transactional email outbox
    const verifyEmail = await waitForOutboxRow(testEmail, 'Verify your email');
    const verifyToken = extractTokenFromEmail(verifyEmail);
    const verifyRes = await request.post('/api/v1/auth/verify-email', {
      data: { token: verifyToken },
      headers: { Origin: origin },
    });
    expect(verifyRes.status()).toBe(200);

    // 3. Request forgot password email
    const forgotRes = await request.post('/api/v1/auth/forgot-password', {
      data: { email: testEmail },
      headers: { Origin: origin },
    });
    expect(forgotRes.status()).toBe(200);

    // 4. SECURITY: response must never leak the reset token; it lives in email only
    const forgotBody = await forgotRes.json();
    const forgotBodyString = JSON.stringify(forgotBody);
    expect(forgotBodyString).not.toContain('token');
    expect(forgotBodyString).not.toContain('reset');

    // 5. Read queued email from database outbox securely without real external email sending
    const resetEmail = await waitForOutboxRow(testEmail, 'Reset your password');
    expect(resetEmail.recipient).toBe(testEmail);

    const resetToken = extractTokenFromEmail(resetEmail);
    expect(resetToken).not.toBeNull();

    // 6. Reset password using the emailed token
    const resetRes = await request.post('/api/v1/auth/reset-password', {
      data: { token: resetToken, newPassword },
      headers: { Origin: origin },
    });
    expect(resetRes.status()).toBe(200);

    // 7. SECURITY: reset token is single-use â€” replay must fail
    const replayRes = await request.post('/api/v1/auth/reset-password', {
      data: { token: resetToken, newPassword },
      headers: { Origin: origin },
    });
    expect(replayRes.status()).toBe(400);
    const replayBody = await replayRes.json();
    expect(replayBody.error?.code).toBe('TOKEN_INVALID');

    // 8. Verify login with OLD password fails (401)
    const oldLoginRes = await request.post('/api/v1/auth/login', {
      data: { email: testEmail, password: initialPassword },
      headers: { Origin: origin },
    });
    expect(oldLoginRes.status()).toBe(401);

    // 9. Verify login with NEW password succeeds (200)
    const newLoginRes = await request.post('/api/v1/auth/login', {
      data: { email: testEmail, password: newPassword },
      headers: { Origin: origin },
    });
    expect(newLoginRes.status()).toBe(200);
  });

  test('SECURITY: unknown email returns 200, queues nothing, leaks nothing', async ({ request }) => {
    const unknownEmail = `unknown-${Date.now()}@example.com`;

    const res = await request.post('/api/v1/auth/forgot-password', {
      data: { email: unknownEmail },
      headers: { Origin: origin },
    });
    // Anti-enumeration: identical status to the known-email case
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(JSON.stringify(body)).not.toContain('token');

    // No email may be queued for a non-existent account
    const rows = await countOutboxRows(unknownEmail, 'Reset your password');
    expect(rows).toBe(0);

    // And no existing row may have been touched either (idempotent no-op)
    const anyRow = await findOutboxRow(unknownEmail, 'Reset your password');
    expect(anyRow).toBeNull();
  });

  test('SECURITY: forgot-password is rate limited per email (5/hour -> 429)', async ({ request }) => {
    const burstEmail = `burst-${Date.now()}@example.com`;

    const statuses: number[] = [];
    for (let i = 0; i < 6; i += 1) {
      const res = await request.post('/api/v1/auth/forgot-password', {
        data: { email: burstEmail },
        headers: { Origin: origin },
      });
      statuses.push(res.status());
    }

    const allowed = statuses.filter((s) => s === 200);
    const limited = statuses.filter((s) => s === 429);
    expect(allowed).toHaveLength(5);
    expect(limited).toHaveLength(1);
    // The 6th request must be the one that hit the limit
    expect(statuses[5]).toBe(429);
  });
});