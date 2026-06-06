import makeWASocket, {
  useMultiFileAuthState,
  DisconnectReason,
  type WASocket,
} from "@whiskeysockets/baileys";
import express, { type Request, type Response, type NextFunction } from "express";
import PQueue from "p-queue";
import { LRUCache } from "lru-cache";
import { timingSafeEqual } from "crypto";
import QRCode from "qrcode";
import pino from "pino";

// ─── Logger ────────────────────────────────────────────────────────────────
const log = pino({ level: "info" });

// ─── Env ───────────────────────────────────────────────────────────────────
const AUTH_DIR = process.env.BAILEYS_AUTH_DIR;
const BAILEYS_BEARER = process.env.BAILEYS_BEARER;
const ADMIN_BEARER = process.env.ADMIN_BEARER;
const PORT = parseInt(process.env.PORT ?? "8080", 10);

if (!AUTH_DIR || !BAILEYS_BEARER || !ADMIN_BEARER) {
  log.error("Missing required env vars: BAILEYS_AUTH_DIR, BAILEYS_BEARER, ADMIN_BEARER");
  process.exit(1);
}

// ─── State ─────────────────────────────────────────────────────────────────
let sock: WASocket | null = null;
let latestQR: string | null = null;
let isLoggedOut = false;

// ─── Idempotency cache (clientMsgId → wa message id, TTL 10 min) ──────────
const idempotencyCache = new LRUCache<string, string>({
  max: 5000,
  ttl: 10 * 60 * 1000,
});

// ─── Rate limiting ─────────────────────────────────────────────────────────
const otpLastSent = new LRUCache<string, number>({ max: 10000, ttl: 60 * 60 * 1000 });
const otpHourlyCount = new LRUCache<string, number>({ max: 10000, ttl: 60 * 60 * 1000 });

// Global: 1 send / 350ms via p-queue
const queue = new PQueue({ concurrency: 1, interval: 350, intervalCap: 1 });

// ─── Validation ────────────────────────────────────────────────────────────
const JID_DM_RE = /^\d{6,15}@s\.whatsapp\.net$/;
const JID_GROUP_RE = /^\d{6,20}@g\.us$/;

function validJid(jid: unknown, groupOnly = false): jid is string {
  if (typeof jid !== "string") return false;
  if (groupOnly) return JID_GROUP_RE.test(jid);
  return JID_DM_RE.test(jid) || JID_GROUP_RE.test(jid);
}

function validText(text: unknown): text is string {
  return typeof text === "string" && text.trim().length > 0 && text.length <= 4000;
}

// ─── Bearer auth helpers ────────────────────────────────────────────────────
function checkBearer(token: string | undefined, expected: string): boolean {
  if (!token) return false;
  try {
    // Pad both to same length to keep timingSafeEqual happy
    const maxLen = Math.max(token.length, expected.length);
    const a = Buffer.alloc(maxLen);
    const b = Buffer.alloc(maxLen);
    a.write(token);
    b.write(expected);
    return timingSafeEqual(a, b) && token.length === expected.length;
  } catch {
    return false;
  }
}

function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const token = req.headers.authorization?.replace(/^Bearer\s+/, "");
  if (!checkBearer(token, BAILEYS_BEARER!)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  next();
}

function adminMiddleware(req: Request, res: Response, next: NextFunction): void {
  const token = req.headers.authorization?.replace(/^Bearer\s+/, "");
  if (!checkBearer(token, ADMIN_BEARER!)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  next();
}

// ─── WhatsApp socket lifecycle ─────────────────────────────────────────────
async function connect(): Promise<void> {
  const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR!);

  sock = makeWASocket({
    auth: state,
    printQRInTerminal: false,
    logger: pino({ level: "silent" }) as any,
    browser: ["Hamduk Drive", "Chrome", "120.0.0"],
    connectTimeoutMs: 60_000,
    retryRequestDelayMs: 2000,
  });

  sock.ev.on("creds.update", saveCreds);

  // QR and connection state both come through connection.update
  sock.ev.on("connection.update", ({ connection, lastDisconnect, qr }) => {
    if (qr) {
      latestQR = qr;
      log.info({ op: "qr_generated" }, "New QR ready — visit GET /qr");
    }

    if (connection === "open") {
      latestQR = null;
      log.info({ op: "connected", jid: sock?.user?.id }, "WhatsApp connected");
    }

    if (connection === "close") {
      const code = (lastDisconnect?.error as any)?.output?.statusCode;
      log.warn({ op: "disconnected", code }, "Connection closed");

      if (code === DisconnectReason.loggedOut) {
        isLoggedOut = true;
        log.error({ op: "logged_out" }, "Logged out — re-pair via GET /qr after POST /session/logout");
        return;
      }

      // Reconnect for everything else
      setTimeout(() => connect(), 3000);
    }
  });
}

// ─── OTP rate-limit check ──────────────────────────────────────────────────
function checkOtpRateLimit(jid: string): { ok: boolean; retryAfter?: number } {
  const now = Date.now();
  const last = otpLastSent.get(jid);
  if (last !== undefined) {
    const elapsed = now - last;
    if (elapsed < 60_000) {
      return { ok: false, retryAfter: Math.ceil((60_000 - elapsed) / 1000) };
    }
  }
  const hourly = otpHourlyCount.get(jid) ?? 0;
  if (hourly >= 5) {
    return { ok: false, retryAfter: 3600 };
  }
  return { ok: true };
}

function recordOtpSent(jid: string): void {
  otpLastSent.set(jid, Date.now());
  const count = otpHourlyCount.get(jid) ?? 0;
  otpHourlyCount.set(jid, count + 1);
}

// ─── Express app ───────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: "16kb" }));
app.disable("x-powered-by");

// ── Health (open) ─────────────────────────────────────────────────────────
app.get("/health", (_req, res) => {
  const connected = !!sock?.user;
  if (!connected || isLoggedOut) {
    res.status(503).json({ ok: false, connected: false, jid: null });
    return;
  }
  res.json({ ok: true, connected, jid: sock!.user!.id });
});

// ── QR (admin) ────────────────────────────────────────────────────────────
app.get("/qr", adminMiddleware, async (_req, res) => {
  if (sock?.user) {
    res.status(409).json({ error: "already_paired" });
    return;
  }
  if (!latestQR) {
    res.status(404).json({ error: "no_qr_available" });
    return;
  }
  try {
    const png = await QRCode.toBuffer(latestQR, { type: "png", width: 300 });
    res.set("Content-Type", "image/png").send(png);
  } catch {
    res.status(500).json({ error: "qr_render_failed" });
  }
});

// ── Session logout (admin) ────────────────────────────────────────────────
app.post("/session/logout", adminMiddleware, async (_req, res) => {
  try {
    await sock?.logout();
  } catch {
    // ignore — socket may be closed
  }
  isLoggedOut = false;
  await connect();
  log.info({ op: "logout" }, "Session logged out, reconnecting for re-pair");
  res.json({ ok: true });
});

// ── POST /message/send ────────────────────────────────────────────────────
app.post("/message/send", authMiddleware, async (req, res) => {
  const { jid, text } = req.body ?? {};
  const clientMsgId = req.headers["clientmsgid"] as string | undefined;

  if (!validJid(jid) || !validText(text)) {
    res.status(400).json({ error: "bad_input" });
    return;
  }

  if (clientMsgId) {
    const cached = idempotencyCache.get(clientMsgId);
    if (cached) {
      log.info({ op: "send_deduped", jid, clientMsgId });
      res.json({ id: cached });
      return;
    }
  }

  if (!sock?.user) {
    res.status(503).json({ error: "not_connected" });
    return;
  }

  try {
    const m = await queue.add(() => sock!.sendMessage(jid, { text }));
    const id = m?.key.id ?? null;
    if (clientMsgId && id) idempotencyCache.set(clientMsgId, id);
    log.info({ op: "send", jid, status: "ok" });
    res.json({ id });
  } catch (e: any) {
    log.error({ op: "send", jid, err: e?.message, status: "error" });
    res.status(502).json({ error: e?.message ?? "send_failed" });
  }
});

// ── POST /otp/send ────────────────────────────────────────────────────────
app.post("/otp/send", authMiddleware, async (req, res) => {
  const { jid, text } = req.body ?? {};
  const clientMsgId = req.headers["clientmsgid"] as string | undefined;

  // OTPs only to DM JIDs, not groups
  if (!validJid(jid) || !JID_DM_RE.test(jid as string) || !validText(text)) {
    res.status(400).json({ error: "bad_input" });
    return;
  }

  if (clientMsgId) {
    const cached = idempotencyCache.get(clientMsgId);
    if (cached) {
      res.json({ id: cached });
      return;
    }
  }

  const rateCheck = checkOtpRateLimit(jid as string);
  if (!rateCheck.ok) {
    res.set("Retry-After", String(rateCheck.retryAfter)).status(429).json({
      error: "rate_limited",
      retryAfter: rateCheck.retryAfter,
    });
    return;
  }

  if (!sock?.user) {
    res.status(503).json({ error: "not_connected" });
    return;
  }

  try {
    const m = await queue.add(() => sock!.sendMessage(jid as string, { text }));
    const id = m?.key.id ?? null;
    recordOtpSent(jid as string);
    if (clientMsgId && id) idempotencyCache.set(clientMsgId, id);
    // Never log OTP text — it's a secret
    log.info({ op: "otp_send", jid, status: "ok" });
    res.json({ id });
  } catch (e: any) {
    log.error({ op: "otp_send", jid, err: e?.message, status: "error" });
    res.status(502).json({ error: e?.message ?? "send_failed" });
  }
});

// ── POST /group/broadcast ─────────────────────────────────────────────────
app.post("/group/broadcast", authMiddleware, async (req, res) => {
  const { jid, text } = req.body ?? {};
  const clientMsgId = req.headers["clientmsgid"] as string | undefined;

  if (!validJid(jid, true) || !validText(text)) {
    res.status(400).json({ error: "bad_input" });
    return;
  }

  if (clientMsgId) {
    const cached = idempotencyCache.get(clientMsgId);
    if (cached) {
      res.json({ id: cached });
      return;
    }
  }

  if (!sock?.user) {
    res.status(503).json({ error: "not_connected" });
    return;
  }

  // Confirm bot is a group member
  try {
    await sock.groupMetadata(jid as string);
  } catch {
    log.warn({ op: "group_broadcast", jid, status: "not_member" });
    res.status(404).json({ error: "group_not_found_or_not_member" });
    return;
  }

  try {
    const m = await queue.add(() => sock!.sendMessage(jid as string, { text }));
    const id = m?.key.id ?? null;
    if (clientMsgId && id) idempotencyCache.set(clientMsgId, id);
    log.info({ op: "group_broadcast", jid, status: "ok" });
    res.json({ id });
  } catch (e: any) {
    log.error({ op: "group_broadcast", jid, err: e?.message, status: "error" });
    res.status(502).json({ error: e?.message ?? "send_failed" });
  }
});

// ── 404 fallback ──────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: "not_found" }));

// ─── Boot ──────────────────────────────────────────────────────────────────
await connect();
app.listen(PORT, "0.0.0.0", () => {
  log.info({ op: "startup", port: PORT }, `Baileys service listening on :${PORT}`);
});
