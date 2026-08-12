import type { Config } from "../../infrastructure/config/config.js";
import * as jose from "jose";

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
  return jose.importPKCS8(config.jwtPrivateKey, "RS256");
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

export async function exportJwk(config: Pick<Config, "jwtPrivateKey" | "jwtKid">): Promise<Record<string, unknown>> {
  const key = await makeJwtKey(config);
  const jwk = await jose.exportJWK(key);
  return {
    ...jwk,
    kid: config.jwtKid ?? "",
    alg: "RS256",
    use: "sig",
  };
}