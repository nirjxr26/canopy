import { afterEach, describe, expect, it, vi } from "vitest";
import type { NextFunction, Request, Response } from "express";
import * as jose from "jose";

import { requireSession, verifyJwt } from "./index.js";

const ISSUER = "test-issuer";
const AUDIENCE = "test-audience";
const VALID_CLAIMS = {
  sub: "user-123",
  email: "user@example.com",
  email_verified: true,
  status: "ACTIVE",
  jti: "jti-123",
};

type MockResponse = Response & { statusCode: number; body: unknown };
type MockNext = NextFunction & ReturnType<typeof vi.fn>;

interface ResLike {
  statusCode: number;
  body: unknown;
  status(code: number): ResLike;
  json(obj: unknown): ResLike;
}

function mockExpress(): { req: Request; res: MockResponse; next: MockNext } {
  const rawRes: ResLike = {
    statusCode: 0,
    body: null,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(obj: unknown) {
      this.body = obj;
      return this;
    },
  };
  const res = rawRes as unknown as MockResponse;
  const req = { headers: {} } as unknown as Request;
  const next: MockNext = vi.fn() as unknown as MockNext;
  return { req, res, next };
}

async function makeKeyPair(): Promise<{ spki: string; pkcs8: string }> {
  const { publicKey, privateKey } = await jose.generateKeyPair("RS256", { extractable: true });
  const [spki, pkcs8] = await Promise.all([jose.exportSPKI(publicKey), jose.exportPKCS8(privateKey)]);
  return { spki, pkcs8 };
}

async function signToken(pkcs8: string, claims: Record<string, unknown>): Promise<string> {
  return new jose.SignJWT(claims)
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("2h")
    .sign(await jose.importPKCS8(pkcs8, "RS256"));
}

describe("verifyJwt", () => {
  it("accepts a token signed with a valid key", async () => {
    const { spki, pkcs8 } = await makeKeyPair();
    const token = await signToken(pkcs8, VALID_CLAIMS);
    const middleware = verifyJwt({ publicKey: spki, issuer: ISSUER, audience: AUDIENCE });
    const { req, res, next } = mockExpress();
    req.headers.authorization = `Bearer ${token}`;
    await middleware(req, res, next);
    expect(res.statusCode).toBe(0);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.auth).toEqual({
      userId: "user-123",
      email: "user@example.com",
      emailVerified: true,
      status: "ACTIVE",
    });
  });

  it("rejects a token signed with a different key with a generic message and logs jose details", async () => {
    const { spki } = await makeKeyPair();
    const otherKeys = await makeKeyPair();
    const token = await signToken(otherKeys.pkcs8, VALID_CLAIMS);
    const logger = { error: vi.fn() };
    const middleware = verifyJwt({ publicKey: spki, issuer: ISSUER, audience: AUDIENCE, logger });
    const { req, res, next } = mockExpress();
    req.headers.authorization = `Bearer ${token}`;
    await middleware(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({ error: { code: "UNAUTHENTICATED", message: "Invalid access token" } });
    expect(next).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalledWith("JWT verification failed", expect.any(Object));
    const meta = logger.error.mock.calls[0]?.[1] as Record<string, unknown> | undefined;
    const errInfo = meta?.err as { message?: string } | undefined;
    expect(errInfo?.message).toContain("signature");
  });

  it("rejects a token with a tampered signature without leaking jose details when no logger is configured", async () => {
    const { spki, pkcs8 } = await makeKeyPair();
    const validToken = await signToken(pkcs8, VALID_CLAIMS);
    const tampered = `${validToken.slice(0, -4)}XXXX`;
    const middleware = verifyJwt({ publicKey: spki, issuer: ISSUER, audience: AUDIENCE });
    const { req, res, next } = mockExpress();
    req.headers.authorization = `Bearer ${tampered}`;
    await middleware(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({ error: { code: "UNAUTHENTICATED", message: "Invalid access token" } });
  });

  it("rejects a token missing the email claim", async () => {
    const { spki, pkcs8 } = await makeKeyPair();
    const claims: Record<string, unknown> = { ...VALID_CLAIMS };
    delete claims.email;
    const token = await signToken(pkcs8, claims);
    const middleware = verifyJwt({ publicKey: spki, issuer: ISSUER, audience: AUDIENCE });
    const { req, res, next } = mockExpress();
    req.headers.authorization = `Bearer ${token}`;
    await middleware(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({ error: { code: "UNAUTHENTICATED", message: "Invalid access token" } });
    expect(req.auth).toBeUndefined();
  });

  it("rejects a token with a non-boolean email_verified claim", async () => {
    const { spki, pkcs8 } = await makeKeyPair();
    const token = await signToken(pkcs8, { ...VALID_CLAIMS, email_verified: "true" });
    const middleware = verifyJwt({ publicKey: spki, issuer: ISSUER, audience: AUDIENCE });
    const { req, res, next } = mockExpress();
    req.headers.authorization = `Bearer ${token}`;
    await middleware(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({ error: { code: "UNAUTHENTICATED", message: "Invalid access token" } });
  });

  it("rejects a token with an unknown status claim", async () => {
    const { spki, pkcs8 } = await makeKeyPair();
    const token = await signToken(pkcs8, { ...VALID_CLAIMS, status: "BANNED" });
    const middleware = verifyJwt({ publicKey: spki, issuer: ISSUER, audience: AUDIENCE });
    const { req, res, next } = mockExpress();
    req.headers.authorization = `Bearer ${token}`;
    await middleware(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({ error: { code: "UNAUTHENTICATED", message: "Invalid access token" } });
  });
});

describe("requireSession", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("propagates status and existing fields from the introspection response", async () => {
    const fetchMock = vi.fn(async (_url: string, options?: RequestInit) => {
      expect(options?.signal).toBeInstanceOf(AbortSignal);
      return {
        ok: true,
        json: async () => ({
          valid: true,
          userId: "u1",
          email: "a@b.com",
          emailVerified: true,
          status: "LOCKED",
          expiresAt: "2026-01-01T00:00:00.000Z",
        }),
      };
    });
    vi.stubGlobal("fetch", fetchMock);
    const middleware = requireSession({ apiBaseUrl: "https://auth.example.com", serviceApiKey: "k" });
    const { req, res, next } = mockExpress();
    req.headers.cookie = "__Host-ap_session=secret";
    await middleware(req, res, next);
    expect(res.statusCode).toBe(0);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.auth).toEqual({
      userId: "u1",
      email: "a@b.com",
      emailVerified: true,
      status: "LOCKED",
      expiresAt: "2026-01-01T00:00:00.000Z",
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://auth.example.com/api/v1/auth/introspect",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "X-Service-Key": "k",
        }),
        body: JSON.stringify({ sessionSecret: "secret" }),
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it("defaults to ACTIVE status when the introspection response omits status", async () => {
    const fetchMock = vi.fn(async (_url: string, _options?: RequestInit) => ({
      ok: true,
      json: async () => ({ valid: true, userId: "u1", email: "a@b.com", emailVerified: false }),
    }));
    vi.stubGlobal("fetch", fetchMock);
    const middleware = requireSession({ apiBaseUrl: "https://auth.example.com", serviceApiKey: "k" });
    const { req, res, next } = mockExpress();
    req.headers.cookie = "__Host-ap_session=secret";
    await middleware(req, res, next);
    expect(req.auth?.status).toBe("ACTIVE");
    expect(req.auth?.emailVerified).toBe(false);
  });

  it("throws synchronously for non-loopback http or non-http apiBaseUrl values", () => {
    expect(() => requireSession({ apiBaseUrl: "http://evil.example", serviceApiKey: "k" })).toThrow(
      "apiBaseUrl must use https, or http only for loopback hosts",
    );
    expect(() => requireSession({ apiBaseUrl: "ftp://auth.example.com", serviceApiKey: "k" })).toThrow(
      "apiBaseUrl must use https, or http only for loopback hosts",
    );
  });

  it("accepts loopback http and https apiBaseUrl values", () => {
    expect(() => requireSession({ apiBaseUrl: "http://localhost:3000", serviceApiKey: "k" })).not.toThrow();
    expect(() => requireSession({ apiBaseUrl: "http://127.0.0.1:3000", serviceApiKey: "k" })).not.toThrow();
    expect(() => requireSession({ apiBaseUrl: "http://[::1]:3000", serviceApiKey: "k" })).not.toThrow();
    expect(() => requireSession({ apiBaseUrl: "https://auth.example.com", serviceApiKey: "k" })).not.toThrow();
  });

  it("aborts introspection when the request exceeds requestTimeoutMs", async () => {
    const fetchMock = vi.fn(async (_url: string, options?: RequestInit) => {
      const signal = options?.signal;
      expect(signal).toBeInstanceOf(AbortSignal);
      const abortSignal = signal as AbortSignal;
      await new Promise<void>((resolve) => {
        abortSignal.addEventListener("abort", () => resolve(), { once: true });
        if (abortSignal.aborted) {
          resolve();
        }
      });
      throw abortSignal.reason;
    });
    vi.stubGlobal("fetch", fetchMock);
    const middleware = requireSession({
      apiBaseUrl: "http://localhost:3000",
      serviceApiKey: "k",
      requestTimeoutMs: 1,
    });
    const { req, res, next } = mockExpress();
    req.headers.cookie = "__Host-ap_session=secret";
    await middleware(req, res, next);
    expect(res.statusCode).toBe(0);
    expect(next).toHaveBeenCalledTimes(1);
    const err = next.mock.calls[0]?.[0] as Error | undefined;
    expect(err?.name).toBe("TimeoutError");
    expect(req.auth).toBeUndefined();
  });
});
