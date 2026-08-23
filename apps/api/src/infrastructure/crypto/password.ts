import {
  argon2id,
  hash as argon2Hash,
  needsRehash as argon2NeedsRehash,
  verify as argon2Verify,
  type HashOptions,
} from "argon2";

export interface Argon2Params {
  memoryCostKiB: number;
  timeCost: number;
  parallelism: number;
  hashLength: number;
}

export interface PasswordHasher {
  hash(plain: string): Promise<string>;
  verify(hash: string, plain: string): Promise<boolean>;
  needsRehash(hash: string): boolean;
  rehashIfNeeded(hash: string, plain: string): Promise<string | null>;
  dummyHash(): Promise<string>;
}

export function createPasswordHasher(params: Argon2Params): PasswordHasher {
  if (params.memoryCostKiB < 8 * params.parallelism) {
    throw new RangeError("argon2 memoryCost must be at least 8 * parallelism");
  }

  const hashOptions: HashOptions = {
    type: argon2id,
    memoryCost: params.memoryCostKiB,
    timeCost: params.timeCost,
    parallelism: params.parallelism,
    hashLength: params.hashLength,
  };

  const hash = (plain: string) => argon2Hash(plain, hashOptions);

  async function verify(hashValue: string, plain: string): Promise<boolean> {
    if (typeof hashValue !== "string" || !hashValue.startsWith("$argon2id$")) {
      return false;
    }
    try {
      return await argon2Verify(hashValue, plain);
    } catch {
      return false;
    }
  }

  function needsRehash(hashValue: string): boolean {
    if (typeof hashValue !== "string" || !hashValue.startsWith("$argon2id$")) {
      return true;
    }
    try {
      return argon2NeedsRehash(hashValue, hashOptions);
    } catch {
      return true;
    }
  }

  async function rehashIfNeeded(hashValue: string, plain: string): Promise<string | null> {
    if (!needsRehash(hashValue)) {
      return null;
    }
    return hash(plain);
  }

  let dummyHashPromise: Promise<string> | undefined;

  function dummyHash(): Promise<string> {
    const existing = dummyHashPromise;
    if (existing !== undefined) {
      return existing;
    }
    const computed = argon2Hash("auuth-dummy-password", hashOptions);
    dummyHashPromise = computed;
    return computed;
  }

  return { hash, verify, needsRehash, rehashIfNeeded, dummyHash };
}
