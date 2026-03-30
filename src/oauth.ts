import { randomBytes, createHash } from "node:crypto";
import { execSync } from "node:child_process";
import {
  CLIENT_ID,
  TOKEN_URL,
  AUTHORIZE_URL,
  REDIRECT_URI,
  SCOPES,
  USER_AGENT,
} from "./constants.js";

export interface OAuthTokens {
  access: string;
  refresh: string;
  expires: number;
}

function base64url(buf: Buffer): string {
  return buf.toString("base64url").replace(/=+$/, "");
}

function sleep(ms: number): void {
  execSync(`sleep ${(ms / 1000).toFixed(3)}`, { timeout: 60000 });
}

function getRetryDelayMs(status: number, body: string, attempt: number): number {
  try {
    const parsed = JSON.parse(body) as {
      retry_after?: number | string;
      error?: { retry_after?: number | string };
    };
    const retryAfter = parsed.retry_after ?? parsed.error?.retry_after;
    const retrySeconds = Number(retryAfter);

    if (Number.isFinite(retrySeconds) && retrySeconds >= 0) {
      return retrySeconds * 1000;
    }
  } catch {}

  return status === 529
    ? Math.min(2000 * 2 ** attempt, 8000)
    : 1000 * Math.pow(2, attempt) + Math.random() * 1000;
}

/**
 * curl-based token exchange to avoid Bun/runtime fetch injecting
 * forbidden headers (Origin, Referer, Sec-Fetch-*) that trigger 429s.
 */
function curlPost(
  body: Record<string, string>,
  retries = 3,
): { status: number; body: string } {
  const payload = JSON.stringify(body);
  const escaped = payload.replace(/'/g, "'\\''");
  let lastStatus = 529;
  let lastBody = '{"error":{"type":"overloaded_error","message":"Overloaded"}}';

  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const result = execSync(
        `curl -s -w '\\n__HTTP_STATUS__%{http_code}' ` +
          `-X POST '${TOKEN_URL}' ` +
          `-H 'Content-Type: application/json' ` +
          `-H 'User-Agent: ${USER_AGENT}' ` +
          `-d '${escaped}'`,
        { timeout: 30000, encoding: "utf8" },
      );

      const parts = result.split("\n__HTTP_STATUS__");
      const status = parseInt(parts[parts.length - 1], 10);
      const responseBody = parts.slice(0, -1).join("\n__HTTP_STATUS__");
      lastStatus = status;
      lastBody = responseBody;

      if ((status !== 429 && status !== 529) || attempt === retries - 1) {
        return { status, body: responseBody };
      }

    } catch (err) {
      if (attempt === retries - 1) throw err;
    }
    sleep(getRetryDelayMs(lastStatus, lastBody, attempt));
  }

  return {
    status: lastStatus,
    body: lastBody,
  };
}

function parseTokenResponse(status: number, body: string, label: string): OAuthTokens {
  if (status !== 200) {
    throw new Error(`${label} failed (${status}): ${body}`);
  }
  const data = JSON.parse(body) as {
    access_token: string;
    refresh_token: string;
    expires_in: number;
  };
  return {
    access: data.access_token,
    refresh: data.refresh_token,
    expires: Date.now() + data.expires_in * 1000,
  };
}

export function createAuthorizationRequest(
  redirectUri?: string,
): { url: string; verifier: string } {
  const verifier = base64url(randomBytes(64));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  const state = base64url(randomBytes(16));

  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: redirectUri || REDIRECT_URI,
    scope: SCOPES,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
  });

  return { url: `${AUTHORIZE_URL}?${params}`, verifier };
}

export function parseAuthCode(raw: string): string {
  let code = raw.trim();

  if (code.includes("#")) {
    code = code.split("#")[0];
  }

  if (code.includes("?")) {
    try {
      const url = new URL(code);
      code = url.searchParams.get("code") || code;
    } catch {
      const match = code.match(/[?&]code=([^&#]+)/);
      if (match) code = match[1];
    }
  }

  return code.trim();
}

export function exchangeCodeForTokens(
  code: string,
  verifier: string,
  redirectUri?: string,
): OAuthTokens {
  const { status, body } = curlPost({
    grant_type: "authorization_code",
    code,
    code_verifier: verifier,
    client_id: CLIENT_ID,
    redirect_uri: redirectUri || REDIRECT_URI,
  });
  return parseTokenResponse(status, body, "Token exchange");
}

export function refreshTokens(refreshToken: string): OAuthTokens {
  const { status, body } = curlPost({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: CLIENT_ID,
  });
  return parseTokenResponse(status, body, "Token refresh");
}
