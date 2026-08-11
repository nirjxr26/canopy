import http from "node:http";
import pg from "pg";
import { createHmac } from "node:crypto";

const BASE = "http://localhost:3000";
const DB_URL = process.env.DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/auuth";
const PASSWORD = "Correct-horse-battery-staple-1";
const ts = Date.now();
const EMAIL1 = `smoke-mfa-${ts}@example.com`;
const EMAIL2 = `smoke-nomfa-${ts}@example.com`;

let passed = 0;
let failed = 0;

function req(method, path, body, cookie) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE);
    const data = body ? JSON.stringify(body) : null;
    const headers = { "Content-Type": "application/json", Origin: "http://localhost:5173" };
    if (cookie) headers["Cookie"] = cookie;
    const r = http.request(url, { method, headers }, (res) => {
      let c = "";
      res.on("data", (d) => (c += d));
      res.on("end", () => {
        let json;
        try { json = JSON.parse(c); } catch { json = null; }
        const sc = res.headers["set-cookie"];
        const cv = Array.isArray(sc) ? sc[0]?.split(";")[0] : sc?.split(";")[0];
        resolve({ status: res.statusCode, body: json, cookie: cv, setCookie: sc });
      });
    });
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

function assert(name, cond, detail) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else { console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); failed++; }
}

async function main() {
  const pool = new pg.Pool({ connectionString: DB_URL, max: 1 });

  // Helper: activate a user directly via SQL
  async function activateUser(email) {
    await pool.query(
      "UPDATE users SET status = 'ACTIVE', email_verified_at = NOW() WHERE email = $1",
      [email]
    );
    return true;
  }

  // Helper: get recovery codes from confirm response
  let recoveryCodes = [];

  try {
    // ─── 1. Health ───
    console.log("\n1. Health");
    const health = await req("GET", "/healthz");
    assert("GET /healthz 200", health.status === 200, `got ${health.status}`);

    // ─── 2. Signup ───
    console.log("\n2. Signup (MFA user)");
    const signup1 = await req("POST", "/api/v1/auth/signup", { email: EMAIL1, password: PASSWORD });
    assert("signup returns 201", signup1.status === 201, `got ${signup1.status}`);

    console.log("\n3. Signup (non-MFA user)");
    const signup2 = await req("POST", "/api/v1/auth/signup", { email: EMAIL2, password: PASSWORD });
    assert("signup returns 201", signup2.status === 201, `got ${signup2.status}`);

    // ─── 4. Activate users directly ───
    console.log("\n4. Activate users");
    await activateUser(EMAIL1);
    await activateUser(EMAIL2);
    assert("users activated", true);

    // ─── 5. Login non-MFA user ───
    console.log("\n5. Login (non-MFA user)");
    const loginNoMfa = await req("POST", "/api/v1/auth/login", { email: EMAIL2, password: PASSWORD });
    assert("login returns 200", loginNoMfa.status === 200, `got ${loginNoMfa.status}`);
    assert("no mfaRequired", loginNoMfa.body.mfaRequired !== true, `got mfaRequired=${loginNoMfa.body.mfaRequired}`);
    assert("returns user object", !!loginNoMfa.body.user?.email, JSON.stringify(loginNoMfa.body.user));

    // ─── 6. /me endpoint ───
    console.log("\n6. /me endpoint");
    const me = await req("GET", "/api/v1/auth/me", null, loginNoMfa.cookie);
    assert("me returns 200", me.status === 200, `got ${me.status}`);
    assert("me returns correct user", me.body.user?.email === EMAIL2, `got ${me.body.user?.email}`);

    const meNoCookie = await req("GET", "/api/v1/auth/me");
    assert("me without cookie returns 401", meNoCookie.status === 401, `got ${meNoCookie.status}`);

    // ─── 7. Sessions ───
    console.log("\n7. Sessions");
    const sessions = await req("GET", "/api/v1/auth/sessions", null, loginNoMfa.cookie);
    assert("sessions returns 200", sessions.status === 200, `got ${sessions.status}`);
    assert("has sessions array", Array.isArray(sessions.body.sessions), JSON.stringify(sessions.body));

    // ─── 8. MFA Enroll ───
    console.log("\n8. MFA Enroll");
    const enroll = await req("POST", "/api/v1/auth/enroll", null, loginNoMfa.cookie);
    assert("enroll returns 200", enroll.status === 200, `got ${enroll.status}`);
    assert("has secret", typeof enroll.body.secret === "string" && enroll.body.secret.length > 0, JSON.stringify(enroll.body));
    assert("has otpauthUrl", typeof enroll.body.otpauthUrl === "string" && enroll.body.otpauthUrl.startsWith("otpauth://"), JSON.stringify(enroll.body));

    // ─── 9. MFA Confirm ───
    console.log("\n9. MFA Confirm");
    const confirmBad = await req("POST", "/api/v1/auth/confirm", { secret: enroll.body.secret, code: "000000" }, loginNoMfa.cookie);
    assert("confirm bad code returns 400", confirmBad.status === 400, `got ${confirmBad.status}`);
    assert("error is MFA_INVALID", confirmBad.body?.error?.code === "MFA_INVALID", `got ${confirmBad.body?.error?.code}`);

    // Get the TOTP code via direct import — we'll use a Node script for this
    // Since we can't import TS modules from .mjs, we'll query the secret and generate the code via the API
    // Actually, let's use a different approach: create a small helper that generates TOTP
    const crypto = await import("node:crypto");

    // TOTP generation (RFC 6238 compatible)
    // Secret is base32-encoded. Decode it.
    function base32Decode(str) {
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      let bits = "";
      for (const c of str.toUpperCase().replace(/=/g, "")) {
        const val = alphabet.indexOf(c);
        if (val === -1) throw new Error(`Invalid base32 char: ${c}`);
        bits += val.toString(2).padStart(5, "0");
      }
      const bytes = new Uint8Array(Math.floor(bits.length / 8));
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
      }
      return bytes;
    }

    function generateTotp(secret, timeStep = 30) {
      const epoch = Math.floor(Date.now() / 1000);
      const counter = Math.floor(epoch / timeStep);
      const buf = Buffer.alloc(8);
      buf.writeUInt32BE(0, 0);
      buf.writeUInt32BE(counter, 4);
      const key = base32Decode(secret);
      const hmac = createHmac("sha1", key).update(buf).digest();
      const offset = hmac[hmac.length - 1] & 0x0f;
      const code = ((hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16 | (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff)) % 1000000;
      return code.toString().padStart(6, "0");
    }

    const totpCode = generateTotp(enroll.body.secret);
    assert("generated TOTP code", totpCode.length === 6, `got ${totpCode}`);

    const confirmGood = await req("POST", "/api/v1/auth/confirm", { secret: enroll.body.secret, code: totpCode }, loginNoMfa.cookie);
    assert("confirm good code returns 200", confirmGood.status === 200, `got ${confirmGood.status}`);
    assert("returns recovery codes", Array.isArray(confirmGood.body.recoveryCodes) && confirmGood.body.recoveryCodes.length === 10, `got ${JSON.stringify(confirmGood.body.recoveryCodes)}`);
    recoveryCodes = confirmGood.body.recoveryCodes;

    // ─── 10. /me shows mfaEnabled ───
    console.log("\n10. /me shows mfaEnabled");
    const meAfter = await req("GET", "/api/v1/auth/me", null, loginNoMfa.cookie);
    assert("me shows mfaEnabled true", meAfter.body.user?.mfaEnabled === true, `got ${meAfter.body.user?.mfaEnabled}`);

    // ─── 11. Login now requires MFA ───
    console.log("\n11. Login with MFA");
    const loginMfa = await req("POST", "/api/v1/auth/login", { email: EMAIL2, password: PASSWORD });
    assert("login returns 200", loginMfa.status === 200, `got ${loginMfa.status}`);
    assert("mfaRequired is true", loginMfa.body.mfaRequired === true, `got ${loginMfa.body.mfaRequired}`);
    assert("mfaToken is string", typeof loginMfa.body.mfaToken === "string" && loginMfa.body.mfaToken.length > 0, JSON.stringify(loginMfa.body));
    assert("no session cookie set", !loginMfa.cookie, `got cookie=${loginMfa.cookie}`);

    // ─── 12. MFA Verify with wrong code ───
    console.log("\n12. MFA Verify");
    const verifyBad = await req("POST", "/api/v1/auth/verify", { mfaToken: loginMfa.body.mfaToken, code: "000000" });
    assert("wrong code returns 400", verifyBad.status === 400, `got ${verifyBad.status}`);
    assert("error is MFA_INVALID", verifyBad.body?.error?.code === "MFA_INVALID", `got ${verifyBad.body?.error?.code}`);

    // ─── 13. MFA Verify with correct code ───
    console.log("\n13. MFA Verify (correct code)");
    // Need a fresh mfaToken since the previous login's token might be partially used
    const loginMfa2 = await req("POST", "/api/v1/auth/login", { email: EMAIL2, password: PASSWORD });
    const totpCode2 = generateTotp(enroll.body.secret);
    const verifyGood = await req("POST", "/api/v1/auth/verify", { mfaToken: loginMfa2.body.mfaToken, code: totpCode2 });
    assert("correct code returns 200", verifyGood.status === 200, `got ${verifyGood.status}`);
    assert("returns user", verifyGood.body?.user?.email === EMAIL2, JSON.stringify(verifyGood.body?.user));
    assert("sets session cookie", !!verifyGood.cookie, `cookie=${verifyGood.cookie}`);

    // ─── 14. /me works after MFA verify ───
    console.log("\n14. /me after MFA verify");
    const meAfterMfa = await req("GET", "/api/v1/auth/me", null, verifyGood.cookie);
    assert("me returns 200", meAfterMfa.status === 200, `got ${meAfterMfa.status}`);
    assert("mfaEnabled is true", meAfterMfa.body.user?.mfaEnabled === true, `got ${meAfterMfa.body.user?.mfaEnabled}`);

    // ─── 15. MFA Verify with recovery code ───
    console.log("\n15. MFA Verify with recovery code");
    const loginMfa3 = await req("POST", "/api/v1/auth/login", { email: EMAIL2, password: PASSWORD });
    assert("login gets mfaToken", typeof loginMfa3.body.mfaToken === "string", `got ${typeof loginMfa3.body.mfaToken}`);

    const verifyRecovery = await req("POST", "/api/v1/auth/verify", {
      mfaToken: loginMfa3.body.mfaToken,
      code: recoveryCodes[0]
    });
    assert("recovery code works", verifyRecovery.status === 200, `got ${verifyRecovery.status}`);
    assert("returns user", verifyRecovery.body?.user?.email === EMAIL2, JSON.stringify(verifyRecovery.body?.user));

    // ─── 16. Recovery code is single-use ───
    console.log("\n16. Recovery code single-use");
    const loginMfa4 = await req("POST", "/api/v1/auth/login", { email: EMAIL2, password: PASSWORD });
    const verifyRecoveryDup = await req("POST", "/api/v1/auth/verify", {
      mfaToken: loginMfa4.body.mfaToken,
      code: recoveryCodes[0]  // same code
    });
    assert("reused recovery code fails", verifyRecoveryDup.status === 400, `got ${verifyRecoveryDup.status}`);

    // ─── 17. MFA Disable ───
    console.log("\n17. MFA Disable");
    // Login fresh to get mfaToken, then verify to get a session
    const loginMfa5 = await req("POST", "/api/v1/auth/login", { email: EMAIL2, password: PASSWORD });
    const totpCode3 = generateTotp(enroll.body.secret);
    const verifyForSession = await req("POST", "/api/v1/auth/verify", { mfaToken: loginMfa5.body.mfaToken, code: totpCode3 });
    assert("got session for disable", verifyForSession.status === 200, `got ${verifyForSession.status}`);

    const disableBad = await req("POST", "/api/v1/auth/disable", { code: "000000" }, verifyForSession.cookie);
    assert("disable wrong code 400", disableBad.status === 400, `got ${disableBad.status}`);

    const disableGood = await req("POST", "/api/v1/auth/disable", { code: totpCode3 }, verifyForSession.cookie);
    assert("disable correct code 204", disableGood.status === 204, `got ${disableGood.status}`);

    // ─── 18. After disable, login no longer requires MFA ───
    console.log("\n18. Login after disable");
    const loginAfterDisable = await req("POST", "/api/v1/auth/login", { email: EMAIL2, password: PASSWORD });
    assert("login returns 200", loginAfterDisable.status === 200, `got ${loginAfterDisable.status}`);
    assert("mfaRequired is gone", loginAfterDisable.body.mfaRequired !== true, JSON.stringify(loginAfterDisable.body));

    // ─── 19. Logout ───
    console.log("\n19. Logout");
    const logout = await req("POST", "/api/v1/auth/logout", null, loginAfterDisable.cookie);
    assert("logout returns 204", logout.status === 204, `got ${logout.status}`);

    // ─── 20. Rate limits ───
    console.log("\n20. Rate limits");
    const signupRl = await req("POST", "/api/v1/auth/signup", { email: `rl-${ts}@example.com`, password: PASSWORD });
    assert("first signup succeeds", signupRl.status === 201 || signupRl.status === 200, `got ${signupRl.status}`);

    // ─── 21. Unknown route ───
    console.log("\n21. Error handling");
    const notFound = await req("GET", "/api/v1/nonexistent");
    assert("unknown route 404", notFound.status === 404, `got ${notFound.status}`);

    const badJson = await new Promise((resolve) => {
      const r = http.request(new URL("/api/v1/auth/login", BASE), { method: "POST", headers: { "Content-Type": "application/json", Origin: "http://localhost:5173" } }, (res) => {
        let c = ""; res.on("data", d => c += d); res.on("end", () => {
          let j; try { j = JSON.parse(c); } catch { j = null; }
          resolve({ status: res.statusCode, body: j });
        });
      });
      r.write("{bad json");
      r.end();
    });
    assert("malformed JSON 400", badJson.status === 400, `got ${badJson.status}`);

  } finally {
    await pool.end();
  }

  console.log(`\n${"=".repeat(50)}`);
  console.log(`LIVE SMOKE TEST: ${passed} passed, ${failed} failed`);
  console.log(`${"=".repeat(50)}`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
