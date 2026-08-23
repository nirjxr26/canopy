import { createHash, randomBytes } from "node:crypto";
import type { Config } from "../../infrastructure/config/config.js";
import { createId } from "../../infrastructure/crypto/ulid.js";
import type { UserRecord } from "../identity/user-repository.js";
import type { SessionRecord, SessionRepository } from "./session-repository.js";

export const SESSION_TOKEN_BYTES = 32;
export const TOUCH_THROTTLE_MS = 60_000;

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function sessionCookieName(cookieSecure: boolean): string {
  return cookieSecure ? "__Host-ap_session" : "ap_session";
}

export interface AuthenticatedContext {
  session: SessionRecord;
  user: UserRecord;
}

export interface SessionListItem extends SessionRecord {
  isCurrent: boolean;
}

export interface SessionService {
  createSession(input: {
    userId: string;
    ipAddress?: string;
    userAgent?: string;
    now?: number;
  }): Promise<{ token: string; session: SessionRecord }>;
  authenticate(
    token: string | undefined,
    options?: { now?: number; touch?: boolean },
  ): Promise<AuthenticatedContext | null>;
  revoke(id: string, userId: string): Promise<boolean>;
  revokeAll(userId: string): Promise<number>;
  revokeAllExcept(userId: string, keepId: string): Promise<number>;
  listByUser(userId: string, currentSessionId: string): Promise<SessionListItem[]>;
  findBySecret(secret: string, now?: number): Promise<SessionRecord | null>;
}

export function createSessionService(
  sessions: SessionRepository,
  getUsers: { getById(id: string): Promise<UserRecord | null> },
  config: Pick<Config, "sessionExpiryDays" | "sessionIdleHours" | "maxActiveSessions">,
): SessionService {
  // Single source of truth for session validity, shared by the cookie path
  // (authenticate) and the service path (introspect via findBySecret).
  function isLive(session: SessionRecord, now: number): boolean {
    if (session.revokedAt !== null || session.expiresAt.getTime() <= now) {
      return false;
    }
    const lastUsedMs = (session.lastUsedAt ?? session.createdAt).getTime();
    return now - lastUsedMs <= config.sessionIdleHours * 3_600_000;
  }

  return {
    async createSession({ userId, ipAddress, userAgent, now }) {
      const issuedAt = now ?? Date.now();
      const token = randomBytes(SESSION_TOKEN_BYTES).toString("base64url");
      const session = await sessions.insert({
        id: createId("sess", issuedAt),
        userId,
        tokenHash: sha256(token),
        expiresAt: new Date(issuedAt + config.sessionExpiryDays * 24 * 60 * 60 * 1000),
        ipAddress,
        userAgent,
      });
      await sessions.pruneExcess(userId, config.maxActiveSessions);
      return { token, session };
    },

    async authenticate(token, options = {}) {
      const { now = Date.now(), touch = true } = options;
      if (!token) {
        return null;
      }
      const session = await sessions.findByHash(sha256(token));
      if (session === null || !isLive(session, now)) {
        return null;
      }
      const user = await getUsers.getById(session.userId);
      if (user?.status !== "ACTIVE") {
        return null;
      }
      if (touch && now - session.lastUsedAt.getTime() >= TOUCH_THROTTLE_MS) {
        await sessions.touch(session.id, new Date(now));
      }
      return { session, user };
    },

    async revoke(id, userId) {
      return sessions.revoke(id, userId);
    },

    async revokeAll(userId) {
      return sessions.revokeAll(userId);
    },

    async revokeAllExcept(userId, keepId) {
      return sessions.revokeAllExcept(userId, keepId);
    },

    async listByUser(userId, currentSessionId) {
      const now = Date.now();
      const rows = await sessions.listByUser(userId);
      return rows
        .filter((session) => session.revokedAt === null && session.expiresAt.getTime() > now)
        .map((session) => ({
          ...session,
          isCurrent: session.id === currentSessionId,
        }));
    },

    async findBySecret(secret, now = Date.now()) {
      if (!secret) return null;
      const session = await sessions.findByHash(sha256(secret));
      if (session === null || !isLive(session, now)) {
        return null;
      }
      return session;
    },
  };
}
