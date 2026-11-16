import { createHash, timingSafeEqual } from "node:crypto";

export const MIN_ACCESS_KEY_LENGTH = 32;

export type CookieResolution =
  { ok: true; cookie: string } | { ok: false; status: 401 | 500; message: string };

function digest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

export function resolveRequestCookie(
  token: string | null,
  env: NodeJS.ProcessEnv = process.env,
): CookieResolution {
  const serverCookie = env.WANDERLOG_COOKIE?.trim();

  if (!serverCookie) {
    if (!token) {
      return {
        ok: false,
        status: 401,
        message:
          "Missing Authorization header. Set Bearer token to your Wanderlog connect.sid cookie value.",
      };
    }
    return { ok: true, cookie: token };
  }

  const accessKey = env.MCP_ACCESS_KEY?.trim() ?? "";
  if (accessKey.length < MIN_ACCESS_KEY_LENGTH) {
    return {
      ok: false,
      status: 500,
      message: `Server misconfigured: MCP_ACCESS_KEY must be set to at least ${MIN_ACCESS_KEY_LENGTH} characters when WANDERLOG_COOKIE is set.`,
    };
  }

  if (!token || !timingSafeEqual(digest(token), digest(accessKey))) {
    return {
      ok: false,
      status: 401,
      message: "Missing or invalid access key. Send Authorization: Bearer <MCP_ACCESS_KEY>.",
    };
  }

  return { ok: true, cookie: serverCookie };
}
