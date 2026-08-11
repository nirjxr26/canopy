import { test, expect } from '@playwright/test';

test.describe('Automated API Password Recovery Flow (Forgot Password -> Token -> Reset Password -> Login)', () => {
  const origin = 'http://localhost:5173';
  const testEmail = `recovery-user-${Date.now()}@example.com`;
  const initialPassword = 'InitialPassword123!';
  const newPassword = 'UpdatedPassword456!';

  test('Complete Password Recovery Flow via API', async ({ request }) => {
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
    const signupBody = await signupRes.json();
    
    // Verify email to make account ACTIVE
    const signupDevLink = signupBody.devEmailLink;
    if (signupDevLink) {
      const url = new URL(signupDevLink);
      const token = url.searchParams.get('token');
      if (token) {
        await request.post('/api/v1/auth/verify-email', {
          data: { token },
          headers: { Origin: origin },
        });
      }
    }

    // 2. Request forgot password email
    const forgotRes = await request.post('/api/v1/auth/forgot-password', {
      data: { email: testEmail },
      headers: { Origin: origin },
    });
    expect(forgotRes.status()).toBe(200);
    const forgotBody = await forgotRes.json();
    expect(forgotBody.devEmailLink).toBeDefined();

    // 3. Reset password using token from devEmailLink
    const resetUrl = new URL(forgotBody.devEmailLink);
    const resetToken = resetUrl.searchParams.get('token');
    expect(resetToken).not.toBeNull();

    if (resetToken) {
      const resetRes = await request.post('/api/v1/auth/reset-password', {
        data: { token: resetToken, newPassword },
        headers: { Origin: origin },
      });
      expect(resetRes.status()).toBe(200);

      // 4. Verify login with OLD password fails (401)
      const oldLoginRes = await request.post('/api/v1/auth/login', {
        data: { email: testEmail, password: initialPassword },
        headers: { Origin: origin },
      });
      expect(oldLoginRes.status()).toBe(401);

      // 5. Verify login with NEW password succeeds (200)
      const newLoginRes = await request.post('/api/v1/auth/login', {
        data: { email: testEmail, password: newPassword },
        headers: { Origin: origin },
      });
      expect(newLoginRes.status()).toBe(200);
    }
  });
});
