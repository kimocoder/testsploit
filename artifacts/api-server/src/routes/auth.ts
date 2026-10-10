import { Router, type IRouter } from "express";
import {
  checkPassword,
  setAuthCookie,
  clearAuthCookie,
  isAuthenticated,
} from "../middlewares/auth";

const router: IRouter = Router();

// Naive in-memory rate limit: 10 failed attempts per IP per 15 min.
const FAIL_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILS = 10;
const fails = new Map<string, { count: number; firstAt: number }>();

function tooManyFails(ip: string): boolean {
  const e = fails.get(ip);
  if (!e) return false;
  if (Date.now() - e.firstAt > FAIL_WINDOW_MS) { fails.delete(ip); return false; }
  return e.count >= MAX_FAILS;
}

function recordFail(ip: string): void {
  const e = fails.get(ip);
  if (!e || Date.now() - e.firstAt > FAIL_WINDOW_MS) {
    fails.set(ip, { count: 1, firstAt: Date.now() });
  } else {
    e.count += 1;
  }
}

router.get("/status", (req, res) => {
  res.json({ authenticated: isAuthenticated(req) });
});

router.post("/login", (req, res) => {
  const ip = req.ip ?? "unknown";
  if (tooManyFails(ip)) {
    res.status(429).json({ error: "too_many_attempts" });
    return;
  }
  const password = (req.body as { password?: unknown } | undefined)?.password;
  if (!checkPassword(password)) {
    recordFail(ip);
    res.status(401).json({ error: "invalid_password" });
    return;
  }
  fails.delete(ip);
  setAuthCookie(res);
  res.json({ authenticated: true });
});

router.post("/logout", (_req, res) => {
  clearAuthCookie(res);
  res.json({ authenticated: false });
});

export default router;
