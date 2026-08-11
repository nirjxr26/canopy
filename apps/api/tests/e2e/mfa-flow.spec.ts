import { test, expect } from '@playwright/test';
import { generateTotpCode } from '../../src/infrastructure/crypto/totp.js';

test.describe('Automated API MFA Lifecycle (Enroll -> Confirm -> Login Challenge -> Disable)', () => {
  const origin = 'http://localhost:5173';
  const email = `mfa-user-${Date.now()}@example.com`;
  const password = 'MfaSecurePassword123!';

  test('MFA Setup & Challenge verification via API contract', async ({ request }) => {
    // 1. Signup user
    const signupRes = await request.post('/api/v1/auth/signup', {
      data: { email, password, firstName: 'MFA', lastName: 'User' },
      headers: { Origin: origin },
    });
    expect(signupRes.status()).toBe(201);
    const signupBody = await signupRes.json();

    // Verify email token to activate account
    if (signupBody.devEmailLink) {
      const token = new URL(signupBody.devEmailLink).searchParams.get('token');
      if (token) {
        await request.post('/api/v1/auth/verify-email', {
          data: { token },
          headers: { Origin: origin },
        });
      }
    }

    // 2. Login to get authenticated session
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email, password },
      headers: { Origin: origin },
    });
    expect(loginRes.status()).toBe(200);

    // 3. Step 1 of MFA Enrollment: POST /api/v1/auth/enroll -> returns { secret, otpauthUrl }
    const enrollRes = await request.post('/api/v1/auth/enroll', {
      headers: { Origin: origin },
    });
    expect(enrollRes.status()).toBe(200);
    const enrollBody = await enrollRes.json();
    expect(enrollBody.secret).toBeDefined();
    expect(enrollBody.otpauthUrl).toBeDefined();

    // 4. Step 2 of MFA Enrollment: POST /api/v1/auth/confirm -> returns { recoveryCodes }
    const secret = enrollBody.secret;
    const confirmCode = generateTotpCode(secret);

    const confirmRes = await request.post('/api/v1/auth/confirm', {
      data: { secret, code: confirmCode },
      headers: { Origin: origin },
    });
    expect(confirmRes.status()).toBe(200);
    const confirmBody = await confirmRes.json();
    expect(confirmBody.recoveryCodes).toBeInstanceOf(Array);
    expect(confirmBody.recoveryCodes.length).toBe(10);

    // 5. Logout & Re-login -> Should return 200 with { mfaRequired: true, mfaToken }
    await request.post('/api/v1/auth/logout', { headers: { Origin: origin } });

    const mfaLoginRes = await request.post('/api/v1/auth/login', {
      data: { email, password },
      headers: { Origin: origin },
    });
    expect(mfaLoginRes.status()).toBe(200);
    const mfaLoginBody = await mfaLoginRes.json();
    expect(mfaLoginBody.mfaRequired).toBe(true);
    expect(mfaLoginBody.mfaToken).toBeDefined();

    // 6. Complete MFA Challenge: POST /api/v1/auth/verify with { mfaToken, code }
    const challengeCode = generateTotpCode(secret);
    const challengeRes = await request.post('/api/v1/auth/verify', {
      data: {
        mfaToken: mfaLoginBody.mfaToken,
        code: challengeCode,
      },
      headers: { Origin: origin },
    });
    expect(challengeRes.status()).toBe(200);
    const challengeBody = await challengeRes.json();
    expect(challengeBody.user).toBeDefined();

    // 7. Disable MFA: POST /api/v1/auth/disable with { code } -> returns 204
    const disableCode = generateTotpCode(secret);
    const disableRes = await request.post('/api/v1/auth/disable', {
      data: { code: disableCode },
      headers: { Origin: origin },
    });
    expect(disableRes.status()).toBe(204);
  });
});
