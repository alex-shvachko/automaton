import { createHash, generateKeyPairSync, sign } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const context = vi.hoisted(() => ({ dir: "", open: (_url: string) => {} }));
vi.mock("../identity/wallet.js", () => ({ getAutomatonDir: () => context.dir }));
vi.mock("node:child_process", () => ({ spawn: (_command: string, args: string[]) => { context.open(args[args.length - 1]); return { on: () => {}, unref: () => {} }; } }));
import { getChatGPTAccessToken, loginChatGPT, validateIdToken } from "../inference/chatgpt-auth.js";

beforeEach(() => { context.dir = fs.mkdtempSync(path.join(os.tmpdir(), "automaton-auth-test-")); });
afterEach(() => { vi.unstubAllGlobals(); fs.rmSync(context.dir, { recursive: true, force: true }); });

describe("ChatGPT authentication", () => {
  it("completes PKCE login and persists only validated credentials", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = { ...publicKey.export({ format: "jwk" }), kid: "test", alg: "RS256" };
    const realFetch = globalThis.fetch;
    let authUrl: URL;
    context.open = (url) => {
      authUrl = new URL(url);
      const callback = new URL(authUrl.searchParams.get("redirect_uri")!);
      callback.searchParams.set("state", authUrl.searchParams.get("state")!);
      callback.searchParams.set("code", "code");
      callback.searchParams.set("client_id", "oaiapp_test");
      void realFetch(callback);
    };
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.endsWith("jwks.json")) return Response.json({ keys: [jwk] });
      const body = init!.body as URLSearchParams;
      expect(body.get("client_id")).toBe("oaiapp_test");
      expect(createHash("sha256").update(body.get("code_verifier")!).digest("base64url")).toBe(authUrl.searchParams.get("code_challenge"));
      const encode = (v: object) => Buffer.from(JSON.stringify(v)).toString("base64url");
      const header = encode({ alg: "RS256", kid: "test" });
      const payload = encode({ iss: "https://auth.openai.com", aud: "oaiapp_test", sub: "user", nonce: authUrl.searchParams.get("nonce"), iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 });
      const data = `${header}.${payload}`;
      return Response.json({ id_token: `${data}.${sign("RSA-SHA256", Buffer.from(data), privateKey).toString("base64url")}`, access_token: "access", refresh_token: "refresh", expires_in: 3600, scope: "chatgpt.tokens.use.direct" });
    }));
    await loginChatGPT();
    const saved = JSON.parse(fs.readFileSync(path.join(context.dir, "chatgpt-auth.json"), "utf8"));
    expect(saved).toMatchObject({ clientId: "oaiapp_test", subject: "user", accessToken: "access", refreshToken: "refresh" });
    expect(authUrl!.searchParams.get("client_id")).toBe("dynamic_agent_client");
  });

  it("verifies the signature, audience, expiry, and nonce of the ID token", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = { ...publicKey.export({ format: "jwk" }), kid: "test", alg: "RS256" };
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => Response.json({ keys: [jwk] })));
    const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const header = encode({ alg: "RS256", kid: "test" });
    const makeToken = (claims: object) => {
      const payload = encode(claims);
      const data = `${header}.${payload}`;
      return `${data}.${sign("RSA-SHA256", Buffer.from(data), privateKey).toString("base64url")}`;
    };
    const claims = { iss: "https://auth.openai.com", aud: "client", sub: "user", nonce: "nonce", iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60 };
    await expect(validateIdToken(makeToken(claims), "client", "nonce")).resolves.toMatchObject({ sub: "user" });
    await expect(validateIdToken(makeToken(claims), "client", "wrong")).rejects.toThrow("claims");
    await expect(validateIdToken(makeToken({ ...claims, exp: 1 }), "client", "nonce")).rejects.toThrow("claims");
    await expect(validateIdToken(makeToken(claims), "other", "nonce")).rejects.toThrow("claims");
    await expect(validateIdToken(makeToken(claims).replace(/.$/, "!"), "client", "nonce")).rejects.toThrow("signature");
  });

  it("serializes simultaneous refreshes and saves the rotated refresh token", async () => {
    const file = path.join(context.dir, "chatgpt-auth.json");
    fs.writeFileSync(file, JSON.stringify({ clientId: "client", accessToken: "old", refreshToken: "old-refresh", expiresAt: 0, scope: "chatgpt.tokens.use.direct" }));
    const fetchMock = vi.fn().mockResolvedValue(Response.json({ access_token: "new", refresh_token: "new-refresh", expires_in: 3600 }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await Promise.all([getChatGPTAccessToken(), getChatGPTAccessToken()])).toEqual(["new", "new"]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(JSON.parse(fs.readFileSync(file, "utf8")).refreshToken).toBe("new-refresh");
    expect(fs.existsSync(`${file}.lock`)).toBe(false);
  });
});
