import { Router, type IRouter } from "express";
import healthRouter from "./health";
import { buildMonitorRouter } from "./monitor";
import { buildEnvScanRouter } from "./env-scan";
import { buildDiscoverRouter } from "./discover";
import { buildFleetRouter } from "./fleet";
import authRouter from "./auth";
import { requireAuth } from "../middlewares/auth";

const router: IRouter = Router();

// Public: health check + auth endpoints (login/logout/status).
router.use(healthRouter);
router.use("/auth", authRouter);

// Everything below requires a valid auth cookie.
router.use(requireAuth);
router.use("/monitor", buildMonitorRouter());
router.use("/env-scan", buildEnvScanRouter());
router.use("/discover", buildDiscoverRouter());
router.use("/fleet", buildFleetRouter());

export default router;
