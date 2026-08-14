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

export async function makeJwtKey(config: Pick<Config, "jwtPrivateKey" | "jwtKid">): Promise<jose.CryptoKey | jose.KeyObject> {
  if (!config.jwtPrivateKey) {
    throw new Error("JWT private key not configured");
  }
  return jose.importPKCS8(config.jwtPrivateKey, "RS256", { extractable: true });
}

export async function mintJwt(
  payload: Omit<JwtPayload, "iat" | "exp">,
  config: Pick<Config, "jwtAccessTtlSeconds" | "jwtIssuer" | "jwtAudience" | "jwtKid" | "jwtPrivateKey">,
): Promise<string> {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + config.jwtAccessTtlSeconds;
  const key = await makeJwtKey(config);

  return new jose.SignJWT({ ...payload })
    .setProtectedHeader({ alg: "RS256", kid: config.jwtKid ?? "" })
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(key);
}

export async function buildJwks(config: Pick<Config, "jwtPrivateKey" | "jwtKid">): Promise<JwksDocument> {
  const key = await makeJwtKey(config);
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
  };
}