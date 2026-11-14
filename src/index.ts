import { createServer, IncomingMessage, ServerResponse } from "node:http";
import {
  createHash,
  randomBytes,
  randomUUID,
  scrypt as scryptCallback,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";
import { MongoClient, Collection, Db } from "mongodb";

const port = Number(process.env.PORT ?? process.env.DB_API_PORT ?? 5000);
const host = process.env.HOST ?? "0.0.0.0";
const scrypt = promisify(scryptCallback);

let client: MongoClient | null = null;
let data: Collection;
let users: Collection;
let sessions: Collection;
let passwordResets: Collection;
let dbPromise: Promise<void> | null = null;

const loginAttempts = new Map<string, number[]>();
const passwordResetAttempts = new Map<string, number[]>();

const collectionKeys = new Set([
  "notices",
  "events",
  "gallery",
  "slides",
  "leaders",
  "alumni",
  "parents",
  "achievements",
  "quick",
  "results",
]);

function isAllowedOrigin(origin?: string): boolean {
  if (!origin) return true;

  const configured = [
    process.env.ADMIN_PUBLIC_URL,
    ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",") : []),
  ]
    .filter(Boolean)
    .map((o) => o!.trim().toLowerCase());

  if (configured.some((allowed) => allowed === origin.toLowerCase())) {
    return true;
  }

  try {
    const url = new URL(origin);
    return (
      (url.hostname === "localhost" || url.hostname === "127.0.0.1") &&
      url.protocol === "http:"
    );
  } catch {
    return false;
  }
}

function getClientIp(request: IncomingMessage): string {
  const forwarded = request.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }
  return request.socket.remoteAddress ?? "unknown";
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function getCookies(request: IncomingMessage): Record<string, string> {
  try {
    return Object.fromEntries(
      (request.headers.cookie ?? "")
        .split(";")
        .map((cookie) => cookie.trim().split("="))
        .filter(([name, value]) => name && value)
        .map(([name, ...value]) => {
          try {
            return [name, decodeURIComponent(value.join("="))];
          } catch {
            return [name, value.join("=")];
          }
        }),
    );
  } catch {
    return {};
  }
}

function sendSessionCookie(
  response: ServerResponse,
  token: string,
  expiresAt: Date,
): void {
  const maxAge = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
  response.setHeader(
    "set-cookie",
    `alokdia_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/api; Max-Age=${maxAge}${process.env.NODE_ENV === "production" ? "; Secure" : ""}`,
  );
}

async function getSession(request: IncomingMessage) {
  const token = getCookies(request).alokdia_session;
  if (!token) return null;
  const session = await sessions.findOne({
    _id: hashToken(token) as any,
    expiresAt: { $gt: new Date() },
  });
  if (!session) return null;
  const user = await users.findOne({ _id: session.userId, status: "active" });
  return user ? { session, user } : null;
}

async function requireAdmin(
  request: IncomingMessage,
  response: ServerResponse,
  origin?: string,
) {
  const auth = await getSession(request);
  if (!auth) {
    send(response, 401, { error: "Please sign in to continue." }, origin);
    return null;
  }
  return auth;
}

function publicUser(user: any) {
  return {
    id: user._id,
    username: user.username,
    role: user.role,
    status: user.status,
  };
}

async function createPasswordHash(password: string) {
  const salt = randomBytes(16);
  const hash = (await scrypt(password, salt, 64)) as Buffer;
  return {
    salt: salt.toString("hex"),
    passwordHash: Buffer.from(hash).toString("hex"),
  };
}

async function verifyPassword(password: string, user: any): Promise<boolean> {
  const hash = (await scrypt(
    password,
    Buffer.from(user.passwordSalt, "hex"),
    64,
  )) as Buffer;
  return timingSafeEqual(Buffer.from(hash), Buffer.from(user.passwordHash, "hex"));
}

async function readSessionBody(request: IncomingMessage): Promise<any> {
  const body = await readJson(request);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw Object.assign(new Error("Expected an object"), { status: 400 });
  }
  return body;
}

function validUsername(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9._-]{3,32}$/.test(value);
}

function validPassword(value: unknown): value is string {
  return typeof value === "string" && value.length >= 8 && value.length <= 256;
}

function allowRateLimitedAttempt(
  store: Map<string, number[]>,
  key: string,
  limit: number,
  windowMs: number,
): boolean {
  const now = Date.now();
  const attempts = (store.get(key) ?? []).filter((at) => now - at < windowMs);
  if (attempts.length >= limit) {
    store.set(key, attempts);
    return false;
  }
  attempts.push(now);
  store.set(key, attempts);
  return true;
}

async function sendPasswordResetEmail(token: string): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.RESET_EMAIL_FROM;
  const superAdminEmail = process.env.SUPER_ADMIN_EMAIL?.trim();
  const publicUrl = process.env.ADMIN_PUBLIC_URL;

  if (!apiKey || !from || !superAdminEmail || !publicUrl) {
    throw Object.assign(
      new Error("Super Admin email recovery is not configured on the server."),
      { status: 503 },
    );
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(superAdminEmail)) {
    throw Object.assign(
      new Error("The configured Super Admin email address is invalid."),
      { status: 503 },
    );
  }

  let resetUrl: URL;
  try {
    resetUrl = new URL("/admin", publicUrl);
    if (
      !["http:", "https:"].includes(resetUrl.protocol) ||
      resetUrl.username ||
      resetUrl.password
    ) {
      throw new Error("Invalid URL");
    }
  } catch {
    throw Object.assign(
      new Error("The configured admin website URL is invalid."),
      { status: 503 },
    );
  }
  resetUrl.searchParams.set("resetToken", token);
  resetUrl.hash = "";

  const emailResponse = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [superAdminEmail],
      subject: "Super Admin password reset",
      text: `A password reset was requested for the Alokdia High School Super Admin account. Open this one-time link within 30 minutes:\n\n${resetUrl}\n\nIf you did not request this, ignore this email.`,
      html: `<p>A password reset was requested for the Alokdia High School Super Admin account.</p><p><a href="${resetUrl}">Reset Super Admin password</a></p><p>This one-time link expires in 30 minutes. If you did not request this, ignore this email.</p>`,
    }),
  });

  if (!emailResponse.ok) {
    console.error(`Password reset email delivery failed (${emailResponse.status}).`);
    throw Object.assign(new Error("Could not send the password reset email."), {
      status: 502,
    });
  }
}

async function handleRegistration({
  request,
  response,
  origin,
}: {
  request: IncomingMessage;
  response: ServerResponse;
  origin?: string;
}): Promise<void> {
  const body = await readSessionBody(request);
  const username = typeof body.username === "string" ? body.username.trim() : "";
  if (!validUsername(username) || !validPassword(body.password)) {
    send(
      response,
      400,
      {
        error:
          "Username must be 3-32 letters/numbers/._- and password must be at least 8 characters.",
      },
      origin,
    );
    return;
  }

  const usernameNormalized = username.toLowerCase();
  if (await users.findOne({ usernameNormalized })) {
    send(response, 409, { error: "That username is already in use." }, origin);
    return;
  }

  try {
    const { salt, passwordHash } = await createPasswordHash(body.password);
    await users.insertOne({
      _id: randomUUID() as any,
      username,
      usernameNormalized,
      passwordSalt: salt,
      passwordHash,
      role: "admin",
      status: "pending",
      createdAt: new Date(),
    });
  } catch (error: any) {
    if (error?.code === 11000) {
      send(response, 409, { error: "That username is already in use." }, origin);
      return;
    }
    throw error;
  }

  send(
    response,
    201,
    { message: "Registration received. Wait for Super Admin approval." },
    origin,
  );
}

async function ensureSuperAdmin(): Promise<void> {
  const existing = await users.findOne({ role: "superadmin" });
  if (existing) return;

  const superAdminUsername = process.env.SUPER_ADMIN_USERNAME?.trim();
  const superAdminPassword = process.env.SUPER_ADMIN_PASSWORD;

  if (!validUsername(superAdminUsername) || !validPassword(superAdminPassword)) {
    throw new Error(
      "Set SUPER_ADMIN_USERNAME (3-32 letters/numbers/._-) and SUPER_ADMIN_PASSWORD (8+ characters) in .env to create the first Super Admin.",
    );
  }

  const { salt, passwordHash } = await createPasswordHash(superAdminPassword);
  await users.insertOne({
    _id: randomUUID() as any,
    username: superAdminUsername,
    usernameNormalized: superAdminUsername.toLowerCase(),
    passwordSalt: salt,
    passwordHash,
    role: "superadmin",
    status: "active",
    createdAt: new Date(),
  });
  console.log("Initial Super Admin account created from environment settings.");
}

function send(
  response: ServerResponse,
  status: number,
  payload: unknown,
  origin?: string,
): void {
  const headers: Record<string, string> = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  };
  if (origin && isAllowedOrigin(origin)) {
    headers["access-control-allow-origin"] = origin;
    headers["access-control-allow-methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS";
    headers["access-control-allow-headers"] = "content-type, authorization, cookie";
    headers["access-control-allow-credentials"] = "true";
    headers.vary = "Origin";
  }
  response.writeHead(status, headers);
  response.end(JSON.stringify(payload));
}

async function readJson(request: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    const bufferChunk = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += bufferChunk.length;
    if (bytes > 16 * 1024 * 1024) {
      throw Object.assign(new Error("Request body is too large"), { status: 413 });
    }
    chunks.push(bufferChunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw Object.assign(new Error("Request body must be valid JSON"), {
      status: 400,
    });
  }
}

function isValidItems(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.every(
      (item) => item && typeof item === "object" && Number.isSafeInteger(item.id),
    ) &&
    new Set(value.map((item) => item.id)).size === value.length
  );
}

export async function initDb(): Promise<void> {
  if (client) return;
  if (dbPromise) return dbPromise;

  dbPromise = (async () => {
    const mongoUri = process.env.MONGODB_URI;
    if (!mongoUri) {
      throw new Error("Set MONGODB_URI in .env to your MongoDB connection string.");
    }

    try {
      client = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 10000 });
    } catch {
      throw new Error(
        "MONGODB_URI is not a valid MongoDB connection string. Check its scheme and percent-encode special characters in credentials.",
      );
    }

    await client.connect();
    const database: Db = client.db(process.env.MONGODB_DB || undefined);
    data = database.collection("alokdia_data");
    users = database.collection("admin_users");
    sessions = database.collection("admin_sessions");
    passwordResets = database.collection("admin_password_resets");

    await users.createIndex({ usernameNormalized: 1 }, { unique: true });
    await sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    await passwordResets.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    await ensureSuperAdmin();
  })();

  return dbPromise;
}

export async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const origin = request.headers.origin;
  if (origin && !isAllowedOrigin(origin)) {
    send(response, 403, { error: "Origin is not allowed" });
    return;
  }
  if (request.method === "OPTIONS") {
    send(response, 204, {}, origin);
    return;
  }

  const url = new URL(request.url ?? "/", `http://${host}:${port}`);
  const parts = url.pathname.split("/").filter(Boolean);

  try {
    await initDb();

    if (
      request.method === "GET" &&
      (url.pathname === "/" ||
        url.pathname === "/api" ||
        url.pathname === "/api/health")
    ) {
      send(response, 200, { ok: true, message: "API is running" }, origin);
      return;
    }

    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      const auth = await getSession(request);
      send(response, 200, { user: auth ? publicUser(auth.user) : null }, origin);
      return;
    }

    if (url.pathname === "/api/auth/login" && request.method === "POST") {
      const ip = getClientIp(request);
      const attempts = loginAttempts.get(ip) ?? [];
      const recentAttempts = attempts.filter((at) => Date.now() - at < 60_000);
      if (recentAttempts.length >= 10) {
        send(
          response,
          429,
          { error: "Too many sign-in attempts. Try again in one minute." },
          origin,
        );
        return;
      }
      const body = await readSessionBody(request);
      if (typeof body.username !== "string" || typeof body.password !== "string") {
        send(response, 400, { error: "Username and password are required." }, origin);
        return;
      }
      const user = await users.findOne({
        usernameNormalized: body.username.trim().toLowerCase(),
      });
      if (!user || !(await verifyPassword(body.password, user))) {
        recentAttempts.push(Date.now());
        loginAttempts.set(ip, recentAttempts);
        send(response, 401, { error: "Incorrect username or password." }, origin);
        return;
      }
      if (user.status !== "active") {
        send(
          response,
          403,
          { error: "This account is awaiting Super Admin approval." },
          origin,
        );
        return;
      }
      loginAttempts.delete(ip);
      const token = randomBytes(32).toString("base64url");
      const expiresAt = new Date(
        Date.now() + (body.remember === true ? 30 : 1) * 24 * 60 * 60 * 1000,
      );
      await sessions.insertOne({
        _id: hashToken(token) as any,
        userId: user._id,
        expiresAt,
        createdAt: new Date(),
      });
      sendSessionCookie(response, token, expiresAt);
      send(response, 200, { user: publicUser(user) }, origin);
      return;
    }

    if (url.pathname === "/api/auth/forgot-password" && request.method === "POST") {
      const ip = getClientIp(request);
      if (!allowRateLimitedAttempt(passwordResetAttempts, `ip:${ip}`, 3, 15 * 60_000)) {
        send(response, 429, { error: "Too many reset requests. Try again later." }, origin);
        return;
      }

      const user = await users.findOne({ role: "superadmin", status: "active" });
      if (user) {
        if (
          !allowRateLimitedAttempt(passwordResetAttempts, `user:${user._id}`, 1, 5 * 60_000)
        ) {
          send(
            response,
            200,
            {
              message:
                "If email recovery is configured, a reset link will be sent to the Super Admin email.",
            },
            origin,
          );
          return;
        }

        const token = randomBytes(32).toString("base64url");
        const tokenHash = hashToken(token);
        await passwordResets.deleteMany({ userId: user._id });
        await passwordResets.insertOne({
          _id: tokenHash as any,
          userId: user._id,
          expiresAt: new Date(Date.now() + 30 * 60_000),
          createdAt: new Date(),
        });
        await sendPasswordResetEmail(token);
      }

      send(
        response,
        200,
        {
          message:
            "If email recovery is configured, a reset link will be sent to the Super Admin email.",
        },
        origin,
      );
      return;
    }

    if (url.pathname === "/api/auth/reset-password" && request.method === "POST") {
      const ip = getClientIp(request);
      if (!allowRateLimitedAttempt(passwordResetAttempts, `reset-ip:${ip}`, 10, 15 * 60_000)) {
        send(response, 429, { error: "Too many reset attempts. Try again later." }, origin);
        return;
      }
      const body = await readSessionBody(request);
      if (typeof body.token !== "string" || !validPassword(body.password)) {
        send(
          response,
          400,
          { error: "A valid reset link and a password of at least 8 characters are required." },
          origin,
        );
        return;
      }
      const reset = await passwordResets.findOneAndDelete({
        _id: hashToken(body.token) as any,
        expiresAt: { $gt: new Date() },
      });
      if (!reset) {
        send(
          response,
          400,
          { error: "This password reset link is invalid or has expired." },
          origin,
        );
        return;
      }
      const user = await users.findOne({
        _id: reset.userId,
        role: "superadmin",
        status: "active",
      });
      if (!user) {
        send(
          response,
          400,
          { error: "This password reset link is invalid or has expired." },
          origin,
        );
        return;
      }
      const { salt, passwordHash } = await createPasswordHash(body.password);
      const update = await users.updateOne(
        { _id: user._id, role: "superadmin", status: "active" },
        { $set: { passwordSalt: salt, passwordHash, updatedAt: new Date() } },
      );
      if (update.matchedCount === 0) {
        send(
          response,
          400,
          { error: "This password reset link is invalid or has expired." },
          origin,
        );
        return;
      }
      await passwordResets.deleteMany({ userId: user._id });
      await sessions.deleteMany({ userId: user._id });
      send(
        response,
        200,
        { message: "Super Admin password has been reset. Sign in with the new password." },
        origin,
      );
      return;
    }

    if (url.pathname === "/api/auth/logout" && request.method === "POST") {
      const token = getCookies(request).alokdia_session;
      if (token) await sessions.deleteOne({ _id: hashToken(token) as any });
      sendSessionCookie(response, "", new Date());
      send(response, 200, { ok: true }, origin);
      return;
    }

    if (url.pathname === "/api/auth/register" && request.method === "POST") {
      await handleRegistration({ request, response, origin });
      return;
    }

    if (url.pathname === "/api/auth/change-username" && request.method === "POST") {
      const auth = await requireAdmin(request, response, origin);
      if (!auth) return;
      const body = await readSessionBody(request);
      const username = typeof body.username === "string" ? body.username.trim() : "";
      if (!validUsername(username) || typeof body.currentPassword !== "string") {
        send(response, 400, { error: "Username must be 3-32 letters/numbers/._-." }, origin);
        return;
      }
      if (!(await verifyPassword(body.currentPassword, auth.user))) {
        send(response, 401, { error: "Current password is incorrect." }, origin);
        return;
      }
      try {
        await users.updateOne(
          { _id: auth.user._id },
          {
            $set: {
              username,
              usernameNormalized: username.toLowerCase(),
              updatedAt: new Date(),
            },
          },
        );
      } catch (error: any) {
        if (error?.code === 11000) {
          send(response, 409, { error: "That username is already in use." }, origin);
          return;
        }
        throw error;
      }
      send(response, 200, { user: { ...publicUser(auth.user), username } }, origin);
      return;
    }

    if (url.pathname === "/api/auth/change-password" && request.method === "POST") {
      const auth = await requireAdmin(request, response, origin);
      if (!auth) return;
      const body = await readSessionBody(request);
      if (typeof body.currentPassword !== "string" || !validPassword(body.password)) {
        send(response, 400, { error: "New password must be at least 8 characters." }, origin);
        return;
      }
      if (!(await verifyPassword(body.currentPassword, auth.user))) {
        send(response, 401, { error: "Current password is incorrect." }, origin);
        return;
      }
      const { salt, passwordHash } = await createPasswordHash(body.password);
      await users.updateOne(
        { _id: auth.user._id },
        { $set: { passwordSalt: salt, passwordHash, updatedAt: new Date() } },
      );
      await sessions.deleteMany({ userId: auth.user._id, _id: { $ne: auth.session._id } });
      send(response, 200, { ok: true }, origin);
      return;
    }

    if (url.pathname === "/api/upload" && request.method === "POST") {
      const auth = await requireAdmin(request, response, origin);
      if (!auth) return;
      const body = await readSessionBody(request);
      if (
        typeof body.image !== "string" ||
        body.image.length > 8 * 1024 * 1024 ||
        !/^data:image\/(jpeg|jpg|png|webp);base64,[A-Za-z0-9+/=\s]+$/.test(body.image)
      ) {
        send(
          response,
          400,
          { error: "The image must be a JPEG, JPG, PNG, or WebP smaller than 6 MB." },
          origin,
        );
        return;
      }
      const apiKey = process.env.IMGBB_API_KEY;
      if (!apiKey) {
        send(response, 503, { error: "Image upload is not configured on the server." }, origin);
        return;
      }
      const form = new FormData();
      form.set("image", body.image.slice(body.image.indexOf(",") + 1));
      const uploadResponse = await fetch(
        `https://api.imgbb.com/1/upload?key=${encodeURIComponent(apiKey)}`,
        { method: "POST", body: form },
      );
      const uploadResult: any = await uploadResponse.json();
      if (
        !uploadResponse.ok ||
        !uploadResult.success ||
        typeof uploadResult.data?.url !== "string"
      ) {
        send(
          response,
          502,
          {
            error: uploadResult.error?.message ?? `ImgBB upload failed (${uploadResponse.status}).`,
          },
          origin,
        );
        return;
      }
      send(response, 200, { url: uploadResult.data.url }, origin);
      return;
    }

    if (url.pathname.startsWith("/api/admin/")) {
      const auth = await requireAdmin(request, response, origin);
      if (!auth) return;
      if (auth.user.role !== "superadmin") {
        send(response, 403, { error: "Super Admin access is required." }, origin);
        return;
      }
      if (url.pathname === "/api/admin/seed-defaults" && request.method === "POST") {
        const body = await readSessionBody(request);
        if (
          !body.collections ||
          typeof body.collections !== "object" ||
          Array.isArray(body.collections) ||
          !body.school ||
          typeof body.school !== "object" ||
          Array.isArray(body.school)
        ) {
          send(
            response,
            400,
            { error: "Default collections and school settings are required." },
            origin,
          );
          return;
        }

        const entries = Object.entries(body.collections);
        if (
          entries.some(([key, items]) => !collectionKeys.has(key) || !isValidItems(items)) ||
          entries.length !== collectionKeys.size
        ) {
          send(response, 400, { error: "Default collections are invalid or incomplete." }, origin);
          return;
        }

        for (const [key, items] of entries) {
          await data.updateOne(
            { _id: key as any },
            { $setOnInsert: { _id: key as any, items, updatedAt: new Date() } },
            { upsert: true },
          );
        }
        await data.updateOne(
          { _id: "school" as any },
          { $setOnInsert: { _id: "school" as any, data: body.school, updatedAt: new Date() } },
          { upsert: true },
        );
        send(response, 200, { ok: true }, origin);
        return;
      }
      if (url.pathname === "/api/admin/users" && request.method === "GET") {
        const accountList = await users
          .find({}, { projection: { username: 1, role: 1, status: 1, createdAt: 1 } })
          .sort({ createdAt: 1 })
          .toArray();
        send(response, 200, { users: accountList.map(publicUser) }, origin);
        return;
      }
      const approvalMatch = url.pathname.match(/^\/api\/admin\/users\/([0-9a-f-]+)\/approve$/i);
      if (approvalMatch && request.method === "POST") {
        const result = await users.updateOne(
          { _id: approvalMatch[1] as any, role: "admin", status: "pending" },
          { $set: { status: "active", approvedBy: auth.user._id, approvedAt: new Date() } },
        );
        if (result.matchedCount === 0) {
          send(response, 404, { error: "Pending account not found." }, origin);
          return;
        }
        send(response, 200, { ok: true }, origin);
        return;
      }
      const deleteMatch = url.pathname.match(/^\/api\/admin\/users\/([0-9a-f-]+)$/i);
      if (deleteMatch && request.method === "DELETE") {
        const result = await users.deleteOne({ _id: deleteMatch[1] as any, role: "admin" });
        if (result.deletedCount === 0) {
          send(response, 404, { error: "Admin account not found." }, origin);
          return;
        }
        await sessions.deleteMany({ userId: deleteMatch[1] });
        send(response, 200, { ok: true }, origin);
        return;
      }
      send(response, 404, { error: "Not found" }, origin);
      return;
    }

    if (parts[0] === "api" && parts[1] === "collections" && parts.length === 3) {
      const collection = parts[2];
      if (!collectionKeys.has(collection)) {
        send(response, 404, { error: "Unknown collection" }, origin);
        return;
      }

      if (request.method === "GET") {
        const record = await data.findOne({ _id: collection as any });
        send(response, 200, { items: record?.items ?? null }, origin);
        return;
      }

      if (request.method === "PUT") {
        const auth = await requireAdmin(request, response, origin);
        if (!auth) return;
        const body = await readJson(request);
        if (!isValidItems(body)) {
          send(response, 400, { error: "Expected items with unique integer ids" }, origin);
          return;
        }
        await data.replaceOne(
          { _id: collection as any },
          { _id: collection as any, items: body, updatedAt: new Date() },
          { upsert: true },
        );
        send(response, 200, { ok: true }, origin);
        return;
      }

      if (request.method === "DELETE") {
        const auth = await requireAdmin(request, response, origin);
        if (!auth) return;
        await data.deleteOne({ _id: collection as any });
        send(response, 200, { ok: true }, origin);
        return;
      }
    }

    if (url.pathname === "/api/school") {
      if (request.method === "GET") {
        const record = await data.findOne({ _id: "school" as any });
        send(response, 200, { school: record?.data ?? null }, origin);
        return;
      }

      if (request.method === "PUT") {
        const auth = await requireAdmin(request, response, origin);
        if (!auth) return;
        const body = await readJson(request);
        if (!body || typeof body !== "object" || Array.isArray(body)) {
          send(response, 400, { error: "Expected a school settings object" }, origin);
          return;
        }
        await data.replaceOne(
          { _id: "school" as any },
          { _id: "school" as any, data: body, updatedAt: new Date() },
          { upsert: true },
        );
        send(response, 200, { ok: true }, origin);
        return;
      }

      if (request.method === "DELETE") {
        const auth = await requireAdmin(request, response, origin);
        if (!auth) return;
        await data.deleteOne({ _id: "school" as any });
        send(response, 200, { ok: true }, origin);
        return;
      }
    }

    send(response, 404, { error: "Not found" }, origin);
  } catch (error: any) {
    const mongoUri = process.env.MONGODB_URI;
    const message = error instanceof Error ? error.message : "Database request failed";
    const safeMessage = mongoUri ? message.replaceAll(mongoUri, "[redacted MongoDB URI]") : message;
    console.error("MongoDB API error:", safeMessage);
    send(response, error.status ?? 500, { error: safeMessage }, origin);
  }
}

export default handleRequest;

const server = createServer(handleRequest);

async function start() {
  await initDb();
  server.listen(port, host, () => {
    console.log("MongoDB database API connected.");
    console.log(`API is running on http://${host}:${port}`);
  });
}

function close() {
  server.close(async () => {
    await client?.close();
    process.exit(0);
  });
}

process.on("SIGINT", close);
process.on("SIGTERM", close);

if (!process.env.VERCEL) {
  start().catch((error) => {
    const mongoUri = process.env.MONGODB_URI;
    const message = error instanceof Error ? error.message : "Unknown startup error";
    const safeMessage = mongoUri ? message.replaceAll(mongoUri, "[redacted MongoDB URI]") : message;
    console.error(`Could not start MongoDB database API: ${safeMessage}`);
    client?.close();
    process.exitCode = 1;
  });
}
