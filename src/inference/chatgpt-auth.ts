import { createHash, createPublicKey, randomBytes, randomUUID, verify, type JsonWebKey } from "node:crypto";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { getAutomatonDir } from "../identity/wallet.js";

const issuer = "https://auth.openai.com";
const resource = "https://api.openai.com/v1";
const tokenEndpoint = `${issuer}/api/accounts/oauth/token`;
const credentialPath = () => path.join(getAutomatonDir(), "chatgpt-auth.json");
const hostPath = () => path.join(getAutomatonDir(), "chatgpt-host.json");

interface Credentials {
  clientId: string; hostId: string; subject: string; email?: string;
  idToken: string; accessToken: string; refreshToken: string; expiresAt: number; scope: string;
}

function savePrivate(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${randomUUID()}.tmp`;
  try {
    fs.writeFileSync(temporary, JSON.stringify(value), { mode: 0o600, flag: "wx" });
    fs.renameSync(temporary, file);
  } finally {
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
  }
}

function readCredentials(): Credentials | undefined {
  if (!fs.existsSync(credentialPath())) return undefined;
  return JSON.parse(fs.readFileSync(credentialPath(), "utf8")) as Credentials;
}

async function tokenRequest(params: Record<string, string>): Promise<any> {
  const response = await fetch(tokenEndpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(params), signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`ChatGPT authentication failed (${response.status}). Please sign in again.`);
  return response.json();
}

export async function validateIdToken(token: string, clientId: string, nonce: string): Promise<{ sub: string; email?: string }> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid ID token");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
  const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  if (header.alg !== "RS256" || typeof header.kid !== "string") throw new Error("Unsupported ID token signature");
  const response = await fetch(`${issuer}/.well-known/jwks.json`, { signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error("Could not retrieve OpenAI signing keys");
  const jwks = await response.json() as { keys: Array<JsonWebKey & { kid?: string; alg?: string }> };
  const key = jwks.keys.find(k => k.kid === header.kid && k.kty === "RSA" && (!k.alg || k.alg === "RS256"));
  if (!key || !verify("RSA-SHA256", Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey({ key, format: "jwk" }), Buffer.from(parts[2], "base64url"))) throw new Error("Invalid ID token signature");
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== issuer || !audiences.includes(clientId) || (audiences.length > 1 && claims.azp !== clientId) || claims.nonce !== nonce || typeof claims.exp !== "number" || claims.exp <= Date.now() / 1000 || typeof claims.iat !== "number" || claims.iat > Date.now() / 1000 + 5 || typeof claims.sub !== "string" || !claims.sub) throw new Error("Invalid ID token claims");
  return claims;
}

export async function loginChatGPT(): Promise<void> {
  const previous = readCredentials();
  let hostId: string;
  if (fs.existsSync(hostPath())) hostId = JSON.parse(fs.readFileSync(hostPath(), "utf8")).hostId;
  else { hostId = `urn:uuid:${randomUUID()}`; savePrivate(hostPath(), { hostId }); }
  const state = randomBytes(32).toString("base64url");
  const nonce = randomBytes(32).toString("base64url");
  const verifier = randomBytes(64).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  let resolveCallback!: (url: URL) => void;
  const callback = new Promise<URL>(resolve => { resolveCallback = resolve; });
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (url.pathname !== "/auth/callback" || url.searchParams.get("state") !== state) { res.writeHead(400).end("Invalid callback"); return; }
    res.writeHead(200, { "Content-Type": "text/plain" }).end("You may close this window and return to Automaton.");
    resolveCallback(url);
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Unable to start callback listener");
  const redirect = `http://127.0.0.1:${address.port}/auth/callback`;
  const params = new URLSearchParams({ client_id: previous?.clientId ?? "dynamic_agent_client", ext_agent_host_id: hostId, response_type: "code", redirect_uri: redirect, scope: "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct", resource, state, nonce, code_challenge_method: "S256", code_challenge: challenge });
  if (previous) params.set("id_token_hint", previous.idToken);
  else params.set("agent_name_hint", "Automaton");
  const url = `${issuer}/api/accounts/authorize?${params}`;
  console.log("Continue with ChatGPT: opening your browser. If it does not open, run this command again on a machine with a browser.");
  const opener = process.platform === "win32" ? "rundll32" : process.platform === "darwin" ? "open" : "xdg-open";
  const child = spawn(opener, process.platform === "win32" ? ["url.dll,FileProtocolHandler", url] : [url], { stdio: "ignore", detached: true });
  child.on("error", () => console.error("Could not open browser.")); child.unref();
  let result: URL;
  try { result = await Promise.race([callback, new Promise<never>((_, reject) => setTimeout(() => reject(new Error("ChatGPT sign-in timed out")), 300_000).unref())]); }
  finally { server.close(); }
  if (result.searchParams.has("error")) throw new Error(`ChatGPT sign-in failed: ${result.searchParams.get("error")}`);
  const clientId = result.searchParams.get("client_id") || previous?.clientId;
  const code = result.searchParams.get("code");
  if (!clientId || clientId === "dynamic_agent_client" || !code || (previous && clientId !== previous.clientId)) throw new Error("Incomplete or mismatched ChatGPT registration");
  const tokens = await tokenRequest({ grant_type: "authorization_code", client_id: clientId, code, code_verifier: verifier, redirect_uri: redirect, resource });
  if (typeof tokens.id_token !== "string" || typeof tokens.access_token !== "string" || typeof tokens.refresh_token !== "string" || typeof tokens.expires_in !== "number" || typeof tokens.scope !== "string" || !tokens.scope.split(" ").includes("chatgpt.tokens.use.direct")) throw new Error("ChatGPT plan usage was not authorized");
  const identity = await validateIdToken(tokens.id_token, clientId, nonce);
  if (previous && previous.subject !== identity.sub) throw new Error("ChatGPT account does not match the existing registration");
  savePrivate(credentialPath(), { clientId, hostId, subject: identity.sub, email: identity.email, idToken: tokens.id_token, accessToken: tokens.access_token, refreshToken: tokens.refresh_token, expiresAt: Date.now() + tokens.expires_in * 1000, scope: tokens.scope });
  console.log(`ChatGPT connected${identity.email ? `: ${identity.email}` : ""}.`);
}

let refreshing: Promise<string> | undefined;
export async function getChatGPTAccessToken(): Promise<string> {
  if (refreshing) return refreshing;
  const credentials = readCredentials();
  if (!credentials) throw new Error("Run automaton --chatgpt-login first");
  if (credentials.expiresAt > Date.now() + 60_000) return credentials.accessToken;
  refreshing = (async () => {
    const lock = `${credentialPath()}.lock`;
    let handle: number | undefined;
    for (let attempt = 0; attempt < 120; attempt++) {
      try { handle = fs.openSync(lock, "wx", 0o600); break; }
      catch (error: any) {
        if (error.code !== "EEXIST") throw error;
        try { if (Date.now() - fs.statSync(lock).mtimeMs > 120_000) fs.unlinkSync(lock); }
        catch (statError: any) { if (statError.code !== "ENOENT") throw statError; }
        await new Promise(resolve => setTimeout(resolve, 250));
      }
    }
    if (handle === undefined) throw new Error("Timed out waiting for ChatGPT token refresh");
    try {
      const current = readCredentials();
      if (!current) throw new Error("ChatGPT credentials are missing");
      if (current.expiresAt > Date.now() + 60_000) return current.accessToken;
      const tokens = await tokenRequest({ grant_type: "refresh_token", client_id: current.clientId, refresh_token: current.refreshToken, resource });
      if (typeof tokens.access_token !== "string" || typeof tokens.refresh_token !== "string" || typeof tokens.expires_in !== "number") throw new Error("Invalid ChatGPT refresh response");
      const scope = tokens.scope ?? current.scope;
      if (!scope.split(" ").includes("chatgpt.tokens.use.direct")) throw new Error("ChatGPT plan permission was revoked");
      savePrivate(credentialPath(), { ...current, accessToken: tokens.access_token, refreshToken: tokens.refresh_token, expiresAt: Date.now() + tokens.expires_in * 1000, scope });
      return tokens.access_token;
    } finally { fs.closeSync(handle); fs.unlinkSync(lock); }
  })();
  try { return await refreshing; } finally { refreshing = undefined; }
}

export async function getChatGPTModel(): Promise<string> {
  const token = await getChatGPTAccessToken();
  const response = await fetch(`${resource}/models`, { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`Could not list ChatGPT models (${response.status})`);
  const data = await response.json() as { models?: Array<{ slug?: string; visibility?: string }> };
  const models = data.models?.filter(model => model.visibility === "list" && typeof model.slug === "string") ?? [];
  const model = models.find(entry => entry.slug?.startsWith("gpt-")) ?? models[0];
  if (!model?.slug) throw new Error("No ChatGPT models are available for this account");
  return model.slug;
}
