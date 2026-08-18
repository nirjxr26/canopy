import { Redis } from "ioredis";

export const TEST_REDIS_URL = process.env.TEST_REDIS_URL ?? "redis://localhost:6379";

export async function probeRedis(url: string = TEST_REDIS_URL): Promise<boolean> {
  const client = new Redis(url, { lazyConnect: true, maxRetriesPerRequest: 1 });
  try {
    await Promise.race([
      client.ping(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("redis probe timeout")), 2000),
      ),
    ]);
    return true;
  } catch {
    return false;
  } finally {
    client.disconnect();
  }
}
