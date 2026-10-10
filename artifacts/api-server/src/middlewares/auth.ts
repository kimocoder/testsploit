import crypto from "crypto";
import type { Request, Response, NextFunction, RequestHandler } from "express";

const COOKIE_NAME = "kmon_auth";
const COOKIE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

function getSecret(): string {
  const s = process.env["SESSION_SECRET"];
  if (!s) throw new Error("SESSION_SECRET is required for auth cookie signing");
  return s;
}

function getPassword(): string {
  const p = process.env["APP_PASSWORD"];
  if (!p) throw new Error("APP_PASSWORD is required for login");
  return p;
}

function sign(payload: string): string {
  return crypto.createHmac("sha256", getSecret()).update(payload).digest("hex");
}

function makeToken(): string {
  const issuedAt = Date.now().toString();
  const sig = sign(issuedAt);
  return `${issuedAt}.${sig}`;
}

function verifyToken(raw: string | undefined): boolean {
  if (!raw || typeof raw !== "string") return false;
  const dot = raw.indexOf(".");
  if (dot <= 0) return false;
  const issuedAt = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  if (!/^\d+$/.test(issuedAt)) return false;
  const expected = sign(issuedAt);
  if (sig.length !== expected.length) return false;
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  } catch { return false; }
  const age = Date.now() - Number(issuedAt);
  return age >= 0 && age < COOKIE_MAX_AGE_MS;
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  try { return crypto.timingSafeEqual(ab, bb); } catch { return false; }
}

export function checkPassword(password: unknown): boolean {
  if (typeof password !== "string") return false;
  return constantTimeEqual(password, getPassword());
}

export function setAuthCookie(res: Response): void {
  const isProd = process.env["NODE_ENV"] === "production" && process.env["COOKIE_SECURE"] !== "0";
  res.cookie(COOKIE_NAME, makeToken(), {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    maxAge: COOKIE_MAX_AGE_MS,
    path: "/",
  });
}

export function clearAuthCookie(res: Response): void {
  res.clearCookie(COOKIE_NAME, { path: "/" });
}

export function isAuthenticated(req: Request): boolean {
  const cookies = (req as Request & { cookies?: Record<string, string> }).cookies;
  return verifyToken(cookies?.[COOKIE_NAME]);
}

/**
 * Express middleware that 401s any request without a valid auth cookie.
 * Intended to be mounted *after* /api/auth/* routes (which must stay public).
 */
export const requireAuth: RequestHandler = (req, res, next) => {
  if (isAuthenticated(req)) { next(); return; }
  res.status(401).json({ error: "unauthorized" });
};
