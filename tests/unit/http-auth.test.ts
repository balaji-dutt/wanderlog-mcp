import { describe, expect, it } from "vitest";
import { MIN_ACCESS_KEY_LENGTH, resolveRequestCookie } from "../../src/http-auth.ts";

const SERVER_COOKIE = "s%3Aserver-side-session.signature";
const ACCESS_KEY = "a".repeat(64);

function serverEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return { WANDERLOG_COOKIE: SERVER_COOKIE, MCP_ACCESS_KEY: ACCESS_KEY, ...overrides };
}

describe("resolveRequestCookie without WANDERLOG_COOKIE", () => {
  it("uses the request token as the caller's cookie", () => {
    expect(resolveRequestCookie("s%3Acaller-cookie", {})).toEqual({
      ok: true,
      cookie: "s%3Acaller-cookie",
    });
  });

  it("rejects a request with no token", () => {
    expect(resolveRequestCookie(null, {})).toMatchObject({ ok: false, status: 401 });
  });

  it("treats a blank WANDERLOG_COOKIE as unset", () => {
    expect(resolveRequestCookie("s%3Acaller-cookie", { WANDERLOG_COOKIE: "  " })).toEqual({
      ok: true,
      cookie: "s%3Acaller-cookie",
    });
  });
});

describe("resolveRequestCookie with WANDERLOG_COOKIE", () => {
  it("returns the server cookie when the access key matches", () => {
    expect(resolveRequestCookie(ACCESS_KEY, serverEnv())).toEqual({
      ok: true,
      cookie: SERVER_COOKIE,
    });
  });

  it("rejects a request with no token", () => {
    expect(resolveRequestCookie(null, serverEnv())).toMatchObject({ ok: false, status: 401 });
  });

  it("rejects a wrong key of the same length", () => {
    expect(resolveRequestCookie("b".repeat(64), serverEnv())).toMatchObject({
      ok: false,
      status: 401,
    });
  });

  it("rejects a wrong key of a different length", () => {
    expect(resolveRequestCookie(ACCESS_KEY.slice(1), serverEnv())).toMatchObject({
      ok: false,
      status: 401,
    });
  });

  it("does not accept the server cookie itself as the access key", () => {
    expect(resolveRequestCookie(SERVER_COOKIE, serverEnv())).toMatchObject({
      ok: false,
      status: 401,
    });
  });

  it("reports misconfiguration when MCP_ACCESS_KEY is missing", () => {
    expect(
      resolveRequestCookie(ACCESS_KEY, serverEnv({ MCP_ACCESS_KEY: undefined })),
    ).toMatchObject({ ok: false, status: 500 });
  });

  it("reports misconfiguration when MCP_ACCESS_KEY is too short", () => {
    const shortKey = "k".repeat(MIN_ACCESS_KEY_LENGTH - 1);
    expect(resolveRequestCookie(shortKey, serverEnv({ MCP_ACCESS_KEY: shortKey }))).toMatchObject({
      ok: false,
      status: 500,
    });
  });

  it("never echoes the cookie or the access key in error messages", () => {
    const results = [
      resolveRequestCookie(null, serverEnv()),
      resolveRequestCookie("wrong", serverEnv()),
      resolveRequestCookie(ACCESS_KEY, serverEnv({ MCP_ACCESS_KEY: "short" })),
    ];
    for (const result of results) {
      expect(result.ok).toBe(false);
      if (result.ok) continue;
      expect(result.message).not.toContain(SERVER_COOKIE);
      expect(result.message).not.toContain(ACCESS_KEY);
      expect(result.message).not.toContain("short");
    }
  });
});
