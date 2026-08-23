import { createPublicKey } from "node:crypto";
import type { Config } from "../../infrastructure/config/config.js";
import * as jose from "jose";

const JWK_PRIVATE_PARAMS = ["d", "p", "q", "dp", "dq", "qi", "oth"] as const;

// Public JWK shape only; used to derive a public key from the private JWK.
interface RsaPublicJwk {
  kty: string;
  n?: string;
  e?: string;
}

export interface JwksDocument {
  keys: Record<string, unknown>[];
}

export interface JwtPayload {
  sub: string;
  email: string;
  email_verified: boolean;
  status: string;
  iss: string;
  aud: string;
  jti: string;
  iat: number;
  exp: number;
}

type SignerConfig = Pick<
  Config,
  "jwtAccessTtlSeconds" | "jwtIssuer" | "jwtAudience" | "jwtKid" | "jwtPrivateKey"
>;

export interface JwtSigner {
  /** Validates the configured private key; rejects with a specific error. */
  validateKey(): Promise<void>;
  mintJwt(payload: Omit<JwtPayload, "iat" | "exp">): Promise<string>;
  buildJwks(): Promise<JwksDocument>;
}

/**
 * Per-config signer (spec §5.1 #12): each instance owns its key cache, so
 * swapping JWT_PRIVATE_KEY and constructing a new signer is the rotation
 * kill-switch — and one instance's failure can never poison another's.
 */
export function createJwtSigner(config: SignerConfig): JwtSigner {
  let keyPromise: Promise<jose.CryptoKey | jose.KeyObject> | undefined;
  let jwksCache: Promise<JwksDocument> | undefined;

  function keyFor(): Promise<jose.CryptoKey | jose.KeyObject> {
    if (!config.jwtPrivateKey) {
      return Promise.reject(new Error("JWT private key not configured"));
    }
    keyPromise ??= jose.importPKCS8(config.jwtPrivateKey, "RS256", { extractable: true }).catch((err) => {
      keyPromise = undefined; // never cache a failed import (no poisoned cache)
      throw err;
    });
    return keyPromise;
  }

  return {
    async validateKey() {
      await keyFor();
    },

    async mintJwt(payload) {
      const iat = Math.floor(Date.now() / 1000);
      const exp = iat + config.jwtAccessTtlSeconds;
      const key = await keyFor();
      return new jose.SignJWT({ ...payload })
        .setProtectedHeader({ alg: "RS256", kid: config.jwtKid ?? "", typ: "at+jwt" })
        .setIssuedAt(iat)
        .setExpirationTime(exp)
        .sign(key);
    },

    async buildJwks() {
      // The JWKS document is fully derived from the key — cache it per signer.
      jwksCache ??= (async () => {
        const key = await keyFor();
        const privateJwk = await jose.exportJWK(key);
        const publicKey = createPublicKey({ key: privateJwk as RsaPublicJwk, format: "jwk" });
        const jwk = await jose.exportJWK(publicKey);
        for (const param of JWK_PRIVATE_PARAMS) {
          if (param in jwk) {
            throw new Error(`JWKS export must never contain the private parameter "${param}"`);
          }
        }
        return {
          keys: [
            {
              ...jwk,
              kid: config.jwtKid ?? "",
              alg: "RS256",
              use: "sig",
            },
          ],
        } satisfies JwksDocument;
      })();
      try {
        return await jwksCache;
      } catch (err) {
        jwksCache = undefined; // allow retry after a transient failure
        throw err;
      }
    },
  };
}
