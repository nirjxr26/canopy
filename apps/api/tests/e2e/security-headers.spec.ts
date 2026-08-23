import { test, expect } from '@playwright/test';

test.describe('Automated API Security & Origin Validation', () => {
  const disallowedOrigin = 'http://malicious-attacker.com';

  test('CSRF Defense: state-changing POST request with unauthorized Origin returns 403 INVALID_ORIGIN', async ({ request }) => {
    const response = await request.post('/api/v1/auth/login', {
      data: {
        email: 'test-user@example.com',
        password: 'Password12345!',
      },
      headers: {
        Origin: disallowedOrigin,
      },
    });

    expect(response.status()).toBe(403);
    const body = await response.json();
    expect(body.error).toBeDefined();
    expect(body.error.code).toBe('INVALID_ORIGIN');
  });

  test('Security Response Structure: verified on health check endpoint', async ({ request }) => {
    const response = await request.get('/healthz');
    expect(response.status()).toBe(200);

    const headers = response.headers();
    expect(headers['x-request-id']).toBeDefined();

    // §6.10: security headers on every response.
    expect(headers['strict-transport-security']).toContain('max-age=63072000');
    expect(headers['strict-transport-security']).toContain('includeSubDomains');
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['content-security-policy']).toContain("default-src 'self'");
    expect(headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
  });
});
