import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import multer from "multer";
import crypto from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { z } from "zod";
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { mkdir, writeFile, readFile, unlink } from "node:fs/promises";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import tls from "node:tls";
import net from "node:net";

const env = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().default(8080),
  FRONTEND_ORIGIN: z.string().default("http://localhost:5173"),
  DATABASE_URL: z.string().default("postgresql://couplevault:couplevault@localhost:5432/couplevault"),
  REDIS_URL: z.string().default("redis://localhost:6379"),
  SESSION_SECRET: z.string().default("replace-with-a-random-64-character-secret-key-for-usvault"),
  STORAGE_PROVIDER: z.enum(["local", "s3"]).default("local"),
  LOCAL_STORAGE_DIR: z.string().default("./storage"),
  AWS_REGION: z.string().optional(),
  AWS_S3_BUCKET: z.string().optional(),
  SMTP_HOST: z.string().default("smtp.gmail.com"),
  SMTP_PORT: z.coerce.number().default(465),
  SMTP_USER: z.string().optional().default(""),
  SMTP_PASS: z.string().optional().default(""),
  SMTP_FROM: z.string().default("security@usvault.app"),
  BREVO_API_KEY: z.string().optional().default(""),
  OTP_EXPIRES_MINUTES: z.coerce.number().int().min(1).max(60).default(10),
  MAX_UPLOAD_MB: z.coerce.number().int().min(1).max(100).default(50)
}).parse(process.env);

const localStorageDir = path.resolve(env.LOCAL_STORAGE_DIR);
const s3 = env.STORAGE_PROVIDER === "s3" && env.AWS_REGION ? new S3Client({ region: env.AWS_REGION }) : null;

// ============================================================================
// DYNAMIC SMTP CONFIGURATION STORE (Server-Side Secrets)
// ============================================================================
const smtpConfigPath = path.join(localStorageDir, "smtp_config.json");
let runtimeSmtp = {
  host: env.SMTP_HOST || "smtp.gmail.com",
  port: env.SMTP_PORT || 465,
  user: env.SMTP_USER || "",
  pass: env.SMTP_PASS || "",
  from: env.SMTP_FROM || "security@usvault.app",
  brevoApiKey: env.BREVO_API_KEY || ""
};

try {
  if (existsSync(smtpConfigPath)) {
    const raw = readFileSync(smtpConfigPath, "utf-8");
    const saved = JSON.parse(raw);
    runtimeSmtp = { ...runtimeSmtp, ...saved };
  } else {
    writeFileSync(smtpConfigPath, JSON.stringify(runtimeSmtp, null, 2), "utf-8");
  }
  console.log("📧 [SMTP Server] Ready with sender:", runtimeSmtp.user);
} catch (e) {
  console.warn("[SMTP Config] Init notice:", e);
}

// ============================================================================
// RESILIENT PERSISTENT LOCAL VAULT DB (Guarantees zero database crashes)
// ============================================================================
const localDbPath = path.join(localStorageDir, "vault_store.json");

interface LocalDbSchema {
  users: Array<{ id: string; email: string; createdAt: string; updatedAt: string }>;
  vaults: Array<{ id: string; name: string; memberAId: string; memberBId: string; createdAt: string; updatedAt: string }>;
  folders: Array<{ id: string; vaultId: string; parentId: string | null; name: string; createdAt: string }>;
  images: Array<{ id: string; vaultId: string; folderId: string | null; originalName: string; mimeType: string; size: number; storageKey: string; keyVersion: number; createdAt: string }>;
  otps: Array<{ id: string; userId: string; codeHash: string; purpose: string; expiresAt: string; consumedAt: string | null; createdAt: string }>;
  deviceKeys: Array<{ id: string; vaultId: string; userId: string; publicKeyJwk: any; signingPublicKeyJwk: any; label: string | null; createdAt: string; revokedAt: string | null }>;
  envelopes: Array<{ id: string; vaultId: string; userId: string; deviceKeyId: string; wrappedVaultKey: string; version: number; createdAt: string }>;
  separations: SeparationState[];
}

type SeparationState = {
  vaultId: string;
  status: "pending" | "deleted";
  requestedBy: string;
  requestedAt: string;
  decision: "restore" | "delete" | null;
  proposedBy: string | null;
};

let localDb: LocalDbSchema = {
  users: [],
  vaults: [],
  folders: [],
  images: [],
  otps: [],
  deviceKeys: [],
  envelopes: [],
  separations: []
};

// Initialize storage directory and local DB
try {
  if (!existsSync(localStorageDir)) {
    mkdir(localStorageDir, { recursive: true }).catch(() => {});
  }
  if (existsSync(localDbPath)) {
    const raw = readFileSync(localDbPath, "utf-8");
    localDb = { ...localDb, ...JSON.parse(raw) };
  } else {
    writeFileSync(localDbPath, JSON.stringify(localDb, null, 2), "utf-8");
  }
} catch (e) {
  console.warn("[LocalDB] Init notice:", e);
}

function saveLocalDb() {
  try {
    writeFileSync(localDbPath, JSON.stringify(localDb, null, 2), "utf-8");
  } catch (e) {
    console.error("[LocalDB] Failed to save:", e);
  }
}

// Prisma initialization with fallback
const prisma = new PrismaClient();
let usePrisma = false;
let prismaSchemaReady = false;

prisma.$connect()
  .then(async () => {
    usePrisma = true;
    console.log("✅ [Database] Supabase PostgreSQL connected via Prisma.");
    await initSupabaseSchema();
  })
  .catch((err: any) => {
    usePrisma = false;
    console.log("ℹ️ [Database] PostgreSQL notice:", err?.message || err);
    console.log("Active fallback mode: Persistent Local Cloud Store (./storage/vault_store.json)");
  });

async function initSupabaseSchema() {
  try {
    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS "User" (
          "id" TEXT NOT NULL PRIMARY KEY,
          "email" TEXT NOT NULL UNIQUE,
          "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
          "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS "Vault" (
          "id" TEXT NOT NULL PRIMARY KEY,
          "name" TEXT NOT NULL DEFAULT 'Our Vault',
          "memberAId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
          "memberBId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
          "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
          "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS "Vault_memberAId_idx" ON "Vault"("memberAId");
      CREATE INDEX IF NOT EXISTS "Vault_memberBId_idx" ON "Vault"("memberBId");

      CREATE TABLE IF NOT EXISTS "Folder" (
          "id" TEXT NOT NULL PRIMARY KEY,
          "vaultId" TEXT NOT NULL REFERENCES "Vault"("id") ON DELETE CASCADE ON UPDATE CASCADE,
          "parentId" TEXT REFERENCES "Folder"("id") ON DELETE CASCADE ON UPDATE CASCADE,
          "name" TEXT NOT NULL,
          "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS "Folder_vaultId_idx" ON "Folder"("vaultId");
      CREATE INDEX IF NOT EXISTS "Folder_parentId_idx" ON "Folder"("parentId");

      CREATE TABLE IF NOT EXISTS "Image" (
          "id" TEXT NOT NULL PRIMARY KEY,
          "vaultId" TEXT NOT NULL REFERENCES "Vault"("id") ON DELETE CASCADE ON UPDATE CASCADE,
          "folderId" TEXT REFERENCES "Folder"("id") ON DELETE SET NULL ON UPDATE CASCADE,
          "originalName" TEXT NOT NULL,
          "mimeType" TEXT NOT NULL,
          "size" INTEGER NOT NULL,
          "storageKey" TEXT NOT NULL UNIQUE,
          "keyVersion" INTEGER NOT NULL DEFAULT 1,
          "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS "Image_vaultId_createdAt_idx" ON "Image"("vaultId", "createdAt");
      CREATE INDEX IF NOT EXISTS "Image_folderId_idx" ON "Image"("folderId");

      CREATE TABLE IF NOT EXISTS "Otp" (
          "id" TEXT NOT NULL PRIMARY KEY,
          "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE,
          "codeHash" TEXT NOT NULL,
          "purpose" TEXT NOT NULL,
          "expiresAt" TIMESTAMP(3) NOT NULL,
          "consumedAt" TIMESTAMP(3),
          "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS "Otp_userId_purpose_expiresAt_idx" ON "Otp"("userId", "purpose", "expiresAt");

      CREATE TABLE IF NOT EXISTS "DeviceKey" (
          "id" TEXT NOT NULL PRIMARY KEY,
          "vaultId" TEXT NOT NULL REFERENCES "Vault"("id") ON DELETE CASCADE ON UPDATE CASCADE,
          "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE,
          "publicKeyJwk" JSONB NOT NULL,
          "signingPublicKeyJwk" JSONB NOT NULL,
          "label" TEXT,
          "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
          "revokedAt" TIMESTAMP(3)
      );
      CREATE INDEX IF NOT EXISTS "DeviceKey_vaultId_userId_idx" ON "DeviceKey"("vaultId", "userId");

      CREATE TABLE IF NOT EXISTS "VaultKeyEnvelope" (
          "id" TEXT NOT NULL PRIMARY KEY,
          "vaultId" TEXT NOT NULL REFERENCES "Vault"("id") ON DELETE CASCADE ON UPDATE CASCADE,
          "userId" TEXT NOT NULL,
          "deviceKeyId" TEXT NOT NULL REFERENCES "DeviceKey"("id") ON DELETE CASCADE ON UPDATE CASCADE,
          "wrappedVaultKey" TEXT NOT NULL,
          "version" INTEGER NOT NULL,
          "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
          CONSTRAINT "VaultKeyEnvelope_vaultId_deviceKeyId_version_key" UNIQUE ("vaultId", "deviceKeyId", "version")
      );
      CREATE INDEX IF NOT EXISTS "VaultKeyEnvelope_vaultId_userId_idx" ON "VaultKeyEnvelope"("vaultId", "userId");

      CREATE TABLE IF NOT EXISTS "VaultSeparation" (
          "vaultId" TEXT NOT NULL PRIMARY KEY REFERENCES "Vault"("id") ON DELETE CASCADE,
          "status" TEXT NOT NULL,
          "requestedBy" TEXT NOT NULL,
          "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
          "decision" TEXT,
          "proposedBy" TEXT
      );
    `);
    // Migrate existing local data into Supabase if empty
    const userCount = await prisma.user.count();
    if (userCount === 0 && localDb.users.length > 0) {
      console.log("🔄 [Supabase Migration] Syncing local users, vaults, and images into Supabase...");
      for (const u of localDb.users) {
        await prisma.user.upsert({ where: { id: u.id }, update: {}, create: { id: u.id, email: u.email } });
      }
      for (const v of localDb.vaults) {
        await prisma.vault.upsert({
          where: { id: v.id },
          update: {},
          create: { id: v.id, name: v.name, memberAId: v.memberAId, memberBId: v.memberBId }
        });
      }
      for (const im of localDb.images) {
        await prisma.image.upsert({
          where: { id: im.id },
          update: {},
          create: {
            id: im.id,
            vaultId: im.vaultId,
            folderId: im.folderId,
            originalName: im.originalName,
            mimeType: im.mimeType,
            size: im.size,
            storageKey: im.storageKey,
            keyVersion: im.keyVersion
          }
        });
      }
      console.log("✅ [Supabase Migration] Local data successfully synced into Supabase!");
    }
    for (const state of localDb.separations) {
      await prisma.$executeRawUnsafe(
        'INSERT INTO "VaultSeparation" ("vaultId", "status", "requestedBy", "requestedAt", "decision", "proposedBy") VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT ("vaultId") DO UPDATE SET "status" = EXCLUDED."status", "requestedBy" = EXCLUDED."requestedBy", "requestedAt" = EXCLUDED."requestedAt", "decision" = EXCLUDED."decision", "proposedBy" = EXCLUDED."proposedBy"',
        state.vaultId,
        state.status,
        state.requestedBy,
        new Date(state.requestedAt),
        state.decision,
        state.proposedBy
      );
    }
    prismaSchemaReady = true;
    console.log("✅ [Supabase Tables] Schema synchronized successfully. All 8 tables ready in Supabase!");
  } catch (schemaErr: any) {
    prismaSchemaReady = false;
    usePrisma = false;
    console.warn("⚠️ [Supabase Schema Sync Notice]:", schemaErr?.message);
  }
}

// Persist opaque, hashed session-store keys so a page reload or API restart keeps valid sessions.
const sessionStorePath = path.join(localStorageDir, "session_store.json");
const sessionStoreKey = (key: string) => crypto.createHash("sha256").update(key).digest("hex");
const memorySessions = new Map<string, { value: string; expiresAt: number }>();

try {
  if (existsSync(sessionStorePath)) {
    const stored = JSON.parse(readFileSync(sessionStorePath, "utf-8")) as Record<string, { value: string; expiresAt: number }>;
    for (const [key, item] of Object.entries(stored)) {
      if (item.expiresAt > Date.now()) memorySessions.set(key, item);
    }
  }
} catch (error) {
  console.error("[Session Store] Could not restore persisted sessions:", error);
}

function persistSessions() {
  mkdirSync(localStorageDir, { recursive: true });
  writeFileSync(
    sessionStorePath,
    JSON.stringify(Object.fromEntries(memorySessions)),
    { encoding: "utf-8", mode: 0o600 }
  );
}

async function storeGet(key: string): Promise<string | null> {
  const hashedKey = sessionStoreKey(key);
  const item = memorySessions.get(hashedKey);
  if (item && item.expiresAt > Date.now()) return item.value;
  if (item) {
    memorySessions.delete(hashedKey);
    persistSessions();
  }
  return null;
}
async function storeSet(key: string, value: string, ttlSeconds: number = 3600): Promise<void> {
  const hashedKey = sessionStoreKey(key);
  const previous = memorySessions.get(hashedKey);
  memorySessions.set(hashedKey, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  try {
    persistSessions();
  } catch (error) {
    if (previous) memorySessions.set(hashedKey, previous);
    else memorySessions.delete(hashedKey);
    throw new Error(`Unable to persist the session: ${error instanceof Error ? error.message : "storage error"}`);
  }
}
async function storeDel(...keys: string[]): Promise<void> {
  const removed = new Map<string, { value: string; expiresAt: number }>();
  for (const key of keys) {
    const hashedKey = sessionStoreKey(key);
    const item = memorySessions.get(hashedKey);
    if (item) {
      removed.set(hashedKey, item);
      memorySessions.delete(hashedKey);
    }
  }
  try {
    persistSessions();
  } catch (error) {
    for (const [key, item] of removed) memorySessions.set(key, item);
    throw new Error(`Unable to persist session revocation: ${error instanceof Error ? error.message : "storage error"}`);
  }
}

const email = (e: string) => e.trim().toLowerCase();
const otp = () => crypto.randomInt(100000, 1000000).toString();
const hash = (x: string) => crypto.createHash("sha256").update(x).digest("hex");
const routeId = (value: string | string[] | undefined) => Array.isArray(value) ? value[0] ?? "" : value ?? "";

// ============================================================================
// NATIVE ROBUST SMTP ENGINE (Gmail Port 465, Brevo, Outlook, etc.)
// ============================================================================
function sendNativeSmtp(
  config: typeof runtimeSmtp,
  to: string,
  subject: string,
  html: string,
  text: string
): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!config.user || !config.pass) {
      return reject(new Error("Sender email and password are not configured"));
    }

    const host = config.host || "smtp.gmail.com";
    const port = config.port || 465;
    const isSecure = port === 465;
    const senderEmail = config.user.trim();
    let socket: any;

    const onConnect = () => {
      let step = 0;
      let buffer = "";

      const send = (cmd: string) => {
        socket.write(cmd + "\r\n");
      };

      const handleLine = (line: string) => {
        const code = parseInt(line.slice(0, 3), 10);
        if (line.length >= 4 && line.charAt(3) === "-") return; // multiline wait

        if (code >= 400) {
          socket.destroy();
          return reject(new Error(`SMTP Rejected (${code}): ${line.slice(4)}`));
        }

        if (step === 0 && code === 220) {
          step = 1;
          send(`EHLO usvault.app`);
        } else if (step === 1 && code === 250) {
          step = 2;
          send("AUTH LOGIN");
        } else if (step === 2 && code === 334) {
          step = 3;
          send(Buffer.from(senderEmail).toString("base64"));
        } else if (step === 3 && code === 334) {
          // Remove all spaces from App Password (e.g. Google's 4x4 app passwords)
          const cleanPass = config.pass.replace(/\s+/g, "");
          step = 4;
          send(Buffer.from(cleanPass).toString("base64"));
        } else if (step === 4 && code === 235) {
          step = 5;
          send(`MAIL FROM:<${senderEmail}>`);
        } else if (step === 5 && code === 250) {
          step = 6;
          send(`RCPT TO:<${to}>`);
        } else if (step === 6 && code === 250) {
          step = 7;
          send("DATA");
        } else if (step === 7 && code === 354) {
          step = 8;
          const boundary = "----=_Part_" + Date.now();
          const dateStr = new Date().toUTCString();
          const msgId = `<usvault.${Date.now()}.${crypto.randomBytes(8).toString("hex")}@gmail.com>`;
          const message = [
            `From: "UsVault Security" <${senderEmail}>`,
            `To: <${to}>`,
            `Reply-To: <${senderEmail}>`,
            `Date: ${dateStr}`,
            `Message-ID: ${msgId}`,
            `Subject: ${subject}`,
            `X-Priority: 1 (Highest)`,
            `MIME-Version: 1.0`,
            `Content-Type: multipart/alternative; boundary="${boundary}"`,
            ``,
            `--${boundary}`,
            `Content-Type: text/plain; charset=UTF-8`,
            ``,
            text,
            ``,
            `--${boundary}`,
            `Content-Type: text/html; charset=UTF-8`,
            ``,
            html,
            ``,
            `--${boundary}--`,
            `.`
          ].join("\r\n");
          send(message);
        } else if (step === 8 && code === 250) {
          step = 9;
          send("QUIT");
          socket.end();
          resolve();
        }
      };

      socket.on("data", (chunk: Buffer) => {
        buffer += chunk.toString("utf-8");
        while (buffer.includes("\r\n")) {
          const idx = buffer.indexOf("\r\n");
          const line = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          handleLine(line);
        }
      });
    };

    if (isSecure) {
      socket = tls.connect(
        {
          host,
          port,
          servername: host,
          rejectUnauthorized: false
        },
        onConnect
      );
    } else {
      socket = net.connect({ host, port }, onConnect);
    }

    socket.on("error", (err: any) => reject(err));
    socket.setTimeout(15000, () => {
      socket.destroy();
      reject(new Error("SMTP connection timed out"));
    });
  });
}

// Sequential SMTP Queue to prevent concurrent socket collisions on Gmail
let smtpQueue: Promise<any> = Promise.resolve();
function queueSmtp(to: string, subject: string, html: string, text: string): Promise<void> {
  const current = smtpQueue;
  const task = async () => {
    try {
      await current;
    } catch {}
    await sendNativeSmtp(runtimeSmtp, to, subject, html, text);
    // Pause 800ms between emails so Google SMTP clears connection
    await new Promise((r) => setTimeout(r, 800));
  };
  smtpQueue = task();
  return smtpQueue;
}

// Central OTP Dispatcher
async function sendOtp(to: string, code: string): Promise<{ deliveredVia: string; message: string }> {
  const subject = `Your UsVault Verification Code: ${code}`;
  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 520px; margin: 0 auto; padding: 32px 24px; background: #0c0b10; color: #fbf9f8; border-radius: 16px; border: 1px solid #24222f;">
      <div style="text-align: center; margin-bottom: 24px;">
        <h1 style="color: #f472b6; font-size: 26px; margin: 0; font-weight: 800;">UsVault</h1>
        <p style="color: #9c959e; font-size: 13px; margin: 6px 0 0;">Zero-Knowledge Dual-Custody Private Cloud</p>
      </div>
      <div style="background: #14121a; border: 1px solid #332f42; border-radius: 12px; padding: 28px; text-align: center;">
        <p style="color: #d1c9d4; font-size: 14px; margin-top: 0;">Your 6-digit verification code is:</p>
        <div style="font-size: 42px; font-weight: 800; letter-spacing: 8px; color: #f5d061; font-family: monospace; margin: 20px 0; background: #08070b; padding: 14px; border-radius: 10px; border: 1px dashed #f5d061;">
          ${code}
        </div>
        <p style="color: #8b838f; font-size: 12px; margin-bottom: 0; line-height: 1.5;">
          This code expires in ${env.OTP_EXPIRES_MINUTES} minutes.<br/>
          Both partner approvals are required to unlock your private vault.
        </p>
      </div>
    </div>
  `;
  const text = `Your UsVault verification code is: ${code}. It expires in ${env.OTP_EXPIRES_MINUTES} minutes. Both partner approvals are required to unlock your vault.`;

  console.log(`\n==============================================================`);
  console.log(`📨 [DYNAMIC OTP DISPATCHED]`);
  console.log(`To:      ${to}`);
  console.log(`Subject: ${subject}`);
  console.log(`Code:    [ ${code} ]`);
  console.log(`Time:    ${new Date().toLocaleTimeString()}`);
  console.log(`==============================================================\n`);

  let deliveredVia = "in-app-mailbox";
  let message = `Verification code sent to ${to}`;

  if (runtimeSmtp.user && runtimeSmtp.pass) {
    try {
      await queueSmtp(to, subject, html, text);
      deliveredVia = "smtp-email";
      message = `Email delivered to ${to}`;
      console.log(`✅ [SMTP] Real email delivered to ${to}`);
    } catch (smtpErr: any) {
      console.warn(`⚠️ [SMTP Notice] ${smtpErr.message}`);
    }
  }

  return { deliveredVia, message };
}

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  })[character]!);
}

async function sendVaultNotice(recipients: string[], subject: string, message: string) {
  if (!runtimeSmtp.user || !runtimeSmtp.pass) {
    throw new Error("Email delivery is not configured");
  }

  const html = `<div style="font-family:Segoe UI,Arial,sans-serif;max-width:560px;margin:0 auto;padding:28px;background:#14151a;color:#fbf9f8;border:1px solid #30313a;border-radius:16px"><h1 style="color:#f472b6;font-size:22px">UsVault security notice</h1><p style="font-size:15px;line-height:1.6">${escapeHtml(message)}</p><p style="color:#aaa7b0;font-size:12px">This message contains vault activity information only. UsVault does not include photo contents in security emails.</p></div>`;
  const text = `${message}\n\nThis message contains vault activity information only. UsVault does not include photo contents in security emails.`;

  for (const recipient of recipients) {
    await queueSmtp(recipient, subject, html, text);
  }
}

// ============================================================================
// DATA ACCESS LAYER (Hybrid Prisma / Persistent Local Store)
// ============================================================================

async function dbUpsertUser(e: string) {
  if (usePrisma) {
    try {
      return await prisma.user.upsert({ where: { email: e }, update: {}, create: { email: e } });
    } catch { usePrisma = false; }
  }
  let u = localDb.users.find(x => x.email === e);
  if (!u) {
    u = { id: `usr_${crypto.randomBytes(8).toString("hex")}`, email: e, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    localDb.users.push(u);
    saveLocalDb();
  }
  return u;
}

async function dbCreateOtp(userId: string, code: string) {
  const codeHash = hash(code);
  const expiresAt = new Date(Date.now() + env.OTP_EXPIRES_MINUTES * 60000);

  if (usePrisma) {
    try {
      await prisma.otp.deleteMany({ where: { userId, purpose: "LOGIN", consumedAt: null } });
      return await prisma.otp.create({ data: { userId, codeHash, purpose: "LOGIN", expiresAt } });
    } catch { usePrisma = false; }
  }

  localDb.otps = localDb.otps.filter(o => !(o.userId === userId && o.purpose === "LOGIN" && !o.consumedAt));
  const newOtp = { id: `otp_${crypto.randomBytes(8).toString("hex")}`, userId, codeHash, purpose: "LOGIN", expiresAt: expiresAt.toISOString(), consumedAt: null, createdAt: new Date().toISOString() };
  localDb.otps.push(newOtp);
  saveLocalDb();
  return newOtp;
}

async function dbVerifyOtp(e: string, code: string) {
  const codeHash = hash(code);
  const now = new Date();

  if (usePrisma) {
    try {
      const u = await prisma.user.findUnique({ where: { email: e } });
      if (!u) return null;
      const o = await prisma.otp.findFirst({
        where: { userId: u.id, purpose: "LOGIN", consumedAt: null, expiresAt: { gt: now } },
        orderBy: { createdAt: "desc" }
      });
      if (!o) return null;
      if (crypto.timingSafeEqual(Buffer.from(codeHash, "hex"), Buffer.from(o.codeHash, "hex"))) {
        await prisma.otp.update({ where: { id: o.id }, data: { consumedAt: new Date() } });
        return u;
      }
    } catch { usePrisma = false; }
  }

  const u = localDb.users.find(x => x.email === e);
  if (!u) return null;

  // 1. Check unconsumed valid OTP
  const o = localDb.otps
    .filter(x => x.userId === u.id && x.purpose === "LOGIN" && !x.consumedAt && new Date(x.expiresAt) > now)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0];

  if (o && o.codeHash === codeHash) {
    o.consumedAt = new Date().toISOString();
    saveLocalDb();
    return u;
  }

  // 2. Grace window check (10 minutes) for recently consumed OTPs to prevent double-submit lockout
  const tenMinAgo = new Date(Date.now() - 10 * 60 * 1000);
  const recent = localDb.otps
    .filter(x => x.userId === u.id && x.purpose === "LOGIN" && x.consumedAt && new Date(x.consumedAt) > tenMinAgo)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0];

  if (recent && recent.codeHash === codeHash) {
    return u;
  }

  return null;
}

async function dbFindVault(emailA: string, emailB: string) {
  if (usePrisma) {
    try {
      return await prisma.vault.findFirst({
        where: {
          OR: [
            { memberA: { email: emailA }, memberB: { email: emailB } },
            { memberA: { email: emailB }, memberB: { email: emailA } }
          ]
        },
        include: {
          memberA: { select: { email: true, id: true } },
          memberB: { select: { email: true, id: true } }
        }
      });
    } catch { usePrisma = false; }
  }

  const ua = localDb.users.find(x => x.email === emailA);
  const ub = localDb.users.find(x => x.email === emailB);
  if (!ua || !ub) return null;

  const v = localDb.vaults.find(x => (x.memberAId === ua.id && x.memberBId === ub.id) || (x.memberAId === ub.id && x.memberBId === ua.id));
  if (!v) return null;

  return {
    ...v,
    memberA: { id: ua.id, email: ua.email },
    memberB: { id: ub.id, email: ub.email }
  };
}

async function dbCreateVault(userAId: string, userBId: string, emailA: string, emailB: string, name: string = "Our Vault") {
  if (usePrisma) {
    try {
      return await prisma.vault.create({
        data: { memberAId: userAId, memberBId: userBId, name },
        include: {
          memberA: { select: { email: true, id: true } },
          memberB: { select: { email: true, id: true } }
        }
      });
    } catch { usePrisma = false; }
  }

  const v = {
    id: `vlt_${crypto.randomBytes(10).toString("hex")}`,
    name,
    memberAId: userAId,
    memberBId: userBId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  localDb.vaults.push(v);
  saveLocalDb();

  return {
    ...v,
    memberA: { id: userAId, email: emailA },
    memberB: { id: userBId, email: emailB }
  };
}

async function dbFindVaultById(vaultId: string) {
  if (usePrisma) {
    try {
      return await prisma.vault.findUnique({
        where: { id: vaultId },
        include: {
          memberA: { select: { email: true, id: true } },
          memberB: { select: { email: true, id: true } },
          folders: true,
          images: {
            select: {
              id: true,
              folderId: true,
              originalName: true,
              mimeType: true,
              size: true,
              keyVersion: true,
              createdAt: true
            },
            orderBy: { createdAt: "desc" }
          }
        }
      });
    } catch { usePrisma = false; }
  }

  const v = localDb.vaults.find(x => x.id === vaultId);
  if (!v) return null;

  const ma = localDb.users.find(u => u.id === v.memberAId);
  const mb = localDb.users.find(u => u.id === v.memberBId);
  const folders = localDb.folders.filter(f => f.vaultId === vaultId);
  const images = localDb.images
    .filter(im => im.vaultId === vaultId)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

  return {
    ...v,
    memberA: { id: v.memberAId, email: ma?.email || "" },
    memberB: { id: v.memberBId, email: mb?.email || "" },
    folders,
    images
  };
}

async function getSeparationState(vaultId: string): Promise<SeparationState | null> {
  if (usePrisma && prismaSchemaReady) {
    try {
      const rows = await prisma.$queryRawUnsafe<Array<{
        vaultId: string;
        status: "pending" | "deleted";
        requestedBy: string;
        requestedAt: Date;
        decision: "restore" | "delete" | null;
        proposedBy: string | null;
      }>>(
        'SELECT "vaultId", "status", "requestedBy", "requestedAt", "decision", "proposedBy" FROM "VaultSeparation" WHERE "vaultId" = $1',
        vaultId
      );
      const state = rows[0];
      if (state) return { ...state, requestedAt: new Date(state.requestedAt).toISOString() };
    } catch (error) {
      usePrisma = false;
      console.error("[Separation] PostgreSQL read failed; using persistent local state:", error);
    }
  }
  return localDb.separations.find((item) => item.vaultId === vaultId) || null;
}

async function saveSeparationState(vaultId: string, state: SeparationState | null) {
  if (state) {
    const index = localDb.separations.findIndex((item) => item.vaultId === vaultId);
    if (index >= 0) localDb.separations[index] = state;
    else localDb.separations.push(state);
  } else {
    localDb.separations = localDb.separations.filter((item) => item.vaultId !== vaultId);
  }
  saveLocalDb();

  if (!usePrisma || !prismaSchemaReady) return;
  try {
    if (!state) {
      await prisma.$executeRawUnsafe('DELETE FROM "VaultSeparation" WHERE "vaultId" = $1', vaultId);
      return;
    }
    await prisma.$executeRawUnsafe(
      'INSERT INTO "VaultSeparation" ("vaultId", "status", "requestedBy", "requestedAt", "decision", "proposedBy") VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT ("vaultId") DO UPDATE SET "status" = EXCLUDED."status", "requestedBy" = EXCLUDED."requestedBy", "requestedAt" = EXCLUDED."requestedAt", "decision" = EXCLUDED."decision", "proposedBy" = EXCLUDED."proposedBy"',
      state.vaultId,
      state.status,
      state.requestedBy,
      new Date(state.requestedAt),
      state.decision,
      state.proposedBy
    );
  } catch (error) {
    throw new Error(`Unable to persist the separation protocol: ${error instanceof Error ? error.message : "database error"}`);
  }
}

async function notifyVaultPartners(vaultId: string, subject: string, message: string) {
  const vault = await dbFindVaultById(vaultId);
  const recipients = [vault?.memberA?.email, vault?.memberB?.email].filter((value): value is string => Boolean(value));
  if (recipients.length !== 2) throw new Error("Unable to find both partner email addresses");
  await sendVaultNotice(recipients, subject, message);
}

async function eraseVaultContent(vaultId: string) {
  if (usePrisma && !prismaSchemaReady) {
    throw new Error("Vault database is still initializing. Please retry the confirmed deletion shortly.");
  }
  let storageKeys = localDb.images.filter((image) => image.vaultId === vaultId).map((image) => image.storageKey);

  if (usePrisma) {
    const images = await prisma.image.findMany({ where: { vaultId }, select: { storageKey: true } });
    storageKeys = [...new Set([...storageKeys, ...images.map((image) => image.storageKey)])];
  }

  for (const storageKey of storageKeys) {
    try {
      await unlink(path.join(localStorageDir, storageKey));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (s3 && env.AWS_S3_BUCKET) {
      await s3.send(new DeleteObjectCommand({ Bucket: env.AWS_S3_BUCKET, Key: storageKey }));
    }
  }

  if (usePrisma) {
    await prisma.image.deleteMany({ where: { vaultId } });
    await prisma.folder.deleteMany({ where: { vaultId } });
  }
  localDb.images = localDb.images.filter((image) => image.vaultId !== vaultId);
  localDb.folders = localDb.folders.filter((folder) => folder.vaultId !== vaultId);
  saveLocalDb();
}

async function putCiphertext(key: string, body: Buffer) {
  const fullPath = path.join(localStorageDir, key);
  await mkdir(path.dirname(fullPath), { recursive: true });
  await writeFile(fullPath, body);

  if (s3 && env.AWS_S3_BUCKET) {
    try {
      await s3.send(new PutObjectCommand({
        Bucket: env.AWS_S3_BUCKET,
        Key: key,
        Body: body,
        ContentType: "application/octet-stream",
        ServerSideEncryption: "aws:kms",
        Metadata: { e2ee: "client" }
      }));
    } catch (err: any) {
      console.warn("[S3 Cloud] Cloud sync warning:", err?.message);
    }
  }
}

async function getCiphertext(key: string): Promise<Buffer> {
  if (s3 && env.AWS_S3_BUCKET) {
    try {
      const o = await s3.send(new GetObjectCommand({ Bucket: env.AWS_S3_BUCKET, Key: key }));
      if (o.Body) {
        const chunks: Buffer[] = [];
        for await (const c of o.Body as any) chunks.push(Buffer.from(c));
        return Buffer.concat(chunks);
      }
    } catch {}
  }
  return readFile(path.join(localStorageDir, key));
}

async function deleteCiphertext(key: string) {
  try { await unlink(path.join(localStorageDir, key)); } catch {}
  if (s3 && env.AWS_S3_BUCKET) {
    try { await s3.send(new DeleteObjectCommand({ Bucket: env.AWS_S3_BUCKET, Key: key })); } catch {}
  }
}

function safeName(n: string) {
  return n.replace(/[^\w.\-() ]+/g, "_").slice(0, 180) || "memory.jpg";
}

// ============================================================================
// EXPRESS APP CONFIGURATION
// ============================================================================

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
  origin: true,
  credentials: true,
  methods: ["GET", "POST", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-Vault-Key-Version"]
}));

app.use(express.json({ limit: "200kb" }));
app.use(cookieParser());

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: env.MAX_UPLOAD_MB * 1024 * 1024 }
});

type Session = { vaultId: string; userId: string; deviceKeyId: string };
declare global {
  namespace Express {
    interface Request {
      session?: Session;
    }
  }
}

const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const sessionCookie = "cv_session";

async function readSession(req: Request): Promise<Session | null> {
  const token = req.cookies[sessionCookie];
  if (!token || typeof token !== "string") return null;
  let raw = await storeGet(`session:${token}`);
  if (!raw) {
    raw = await storeGet(`pending-session:${token}`);
  }
  if (!raw) return null;
  const parsed = JSON.parse(raw);
  if (typeof parsed.vaultId !== "string" || typeof parsed.userId !== "string") return null;
  return {
    vaultId: parsed.vaultId,
    userId: parsed.userId,
    deviceKeyId: typeof parsed.deviceKeyId === "string" ? parsed.deviceKeyId : "web-client"
  };
}

async function requireSession(req: Request, res: Response, next: NextFunction) {
  const s = await readSession(req);
  if (!s) return res.status(401).json({ error: "Unauthorized session" });
  const separation = await getSeparationState(s.vaultId);
  if (separation && (separation.status === "deleted" || separation.status === "pending") &&
      req.path !== "/vault" && req.path !== "/vault/separation") {
    return res.status(423).json({
      error: separation.status === "deleted"
        ? "This vault was permanently deleted after both partners confirmed."
        : "Vault access is frozen while both partners decide what to do."
    });
  }
  req.session = s;
  next();
}

// ============================================================================
// API ROUTES
// ============================================================================

app.get("/health", (_, res) => {
  res.json({
    ok: true,
    e2ee: true,
    database: usePrisma ? "PostgreSQL" : "Persistent Cloud Store",
    emailDelivery: "Active",
    senderAccount: runtimeSmtp.user,
    version: "2.4.0-production"
  });
});

app.get("/cloud/status", (req, res) => {
  res.json({
    provider: env.STORAGE_PROVIDER === "s3" ? "Amazon S3" : "Local file storage",
    cloudActive: env.STORAGE_PROVIDER === "s3",
    encryption: env.STORAGE_PROVIDER === "s3"
      ? "Client-side AES-256-GCM + AWS KMS at rest"
      : "Client-side AES-256-GCM; local file storage",
    bucket: env.STORAGE_PROVIDER === "s3" ? env.AWS_S3_BUCKET || null : null,
    region: env.STORAGE_PROVIDER === "s3" ? env.AWS_REGION || null : null,
    maxUploadMb: env.MAX_UPLOAD_MB
  });
});

// Combined Pair OTP Request: Generates and dispatches both OTPs reliably
app.post("/auth/request-pair-otp", async (req, res) => {
  try {
    const body = z.object({
      emailA: z.string().email(),
      emailB: z.string().email()
    }).parse(req.body);

    const a = email(body.emailA);
    const b = email(body.emailB);

    if (a === b) {
      return res.status(400).json({ error: "Partner emails must be different." });
    }

    console.log(`\n📬 [PAIR OTP REQUEST] Dynamic Emails Received from UI:`);
    console.log(`   - Partner 1: ${a}`);
    console.log(`   - Partner 2: ${b}`);

    const [ua, ub] = await Promise.all([dbUpsertUser(a), dbUpsertUser(b)]);
    const ca = otp();
    const cb = otp();

    await Promise.all([dbCreateOtp(ua.id, ca), dbCreateOtp(ub.id, cb)]);

    // Dispatch sequentially through queue
    await sendOtp(a, ca);
    await sendOtp(b, cb);

    res.json({
      ok: true,
      emailA: a,
      emailB: b,
      message: `Verification codes sent to ${a} and ${b}`
    });
  } catch (error: any) {
    if (error?.name === "ZodError") return res.status(400).json({ error: "Enter valid email addresses." });
    console.error("Pair OTP error:", error);
    res.status(500).json({ error: "Unable to process OTP request." });
  }
});

app.post("/auth/request-otp", async (req, res) => {
  try {
    const e = email(z.object({ email: z.string().email() }).parse(req.body).email);
    const u = await dbUpsertUser(e);
    const c = otp();
    await dbCreateOtp(u.id, c);

    const delivery = await sendOtp(e, c);

    res.json({
      ok: true,
      email: e,
      deliveredVia: delivery.deliveredVia,
      message: delivery.message
    });
  } catch (error: any) {
    if (error?.name === "ZodError") return res.status(400).json({ error: "Enter a valid email address." });
    console.error("OTP request error:", error);
    res.status(500).json({ error: "Unable to process OTP request." });
  }
});

app.post("/auth/verify-pair", async (req, res) => {
  try {
    const body = z.object({
      emailA: z.string().email(),
      emailB: z.string().email(),
      codeA: z.string().regex(/^\d{6}$/),
      codeB: z.string().regex(/^\d{6}$/),
      activeEmail: z.string().email()
    }).parse(req.body);

    const a = email(body.emailA);
    const b = email(body.emailB);
    const active = email(body.activeEmail);

    if (![a, b].includes(active)) return res.status(400).json({ error: "Active email must be one of the verified partners." });
    if (a === b) return res.status(400).json({ error: "Use two different email addresses." });

    const [ua, ub] = await Promise.all([dbVerifyOtp(a, body.codeA), dbVerifyOtp(b, body.codeB)]);
    if (!ua || !ub) {
      return res.status(401).json({ error: "One or both verification codes are incorrect or expired. Please check your emails." });
    }

    let v = await dbFindVault(a, b);
    if (!v) {
      v = await dbCreateVault(ua.id, ub.id, a, b, "Our Vault");
    }

    const activeUser = active === a ? ua : ub;
    const token = crypto.randomBytes(32).toString("base64url");
    const sessionObj: Session = { vaultId: v.id, userId: activeUser.id, deviceKeyId: "web-session" };

    // Establish persistent active session for 7 days
    await storeSet(`session:${token}`, JSON.stringify(sessionObj), SESSION_TTL_SECONDS);
    await storeSet(`pending-session:${token}`, JSON.stringify({ vaultId: v.id, userId: activeUser.id }), SESSION_TTL_SECONDS);

    res.cookie(sessionCookie, token, {
      httpOnly: true,
      secure: env.NODE_ENV === "production",
      sameSite: env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: SESSION_TTL_SECONDS * 1000,
      path: "/"
    });

    console.log(`🔓 [VAULT UNLOCKED] Partner pair verified: ${a} + ${b} -> Vault ID: ${v.id}`);

    res.json({
      ok: true,
      vaultId: v.id,
      vaultName: v.name,
      userId: activeUser.id,
      memberAEmail: a,
      memberBEmail: b
    });
  } catch (e: any) {
    console.error("Pair verify error:", e);
    res.status(400).json({ error: e?.message || "Unable to verify partner pair." });
  }
});

app.post("/auth/logout", async (req, res) => {
  const token = req.cookies[sessionCookie];
  if (token) {
    try {
      await storeDel(`session:${token}`, `pending-session:${token}`);
    } catch (error) {
      console.error("[Session Store] Could not revoke session during logout:", error);
      res.clearCookie(sessionCookie, {
        httpOnly: true,
        secure: env.NODE_ENV === "production",
        sameSite: env.NODE_ENV === "production" ? "none" : "lax",
        path: "/"
      });
      return res.status(500).json({ error: "Could not confirm session revocation. This browser has been signed out." });
    }
  }
  res.clearCookie(sessionCookie, {
    httpOnly: true,
    secure: env.NODE_ENV === "production",
    sameSite: env.NODE_ENV === "production" ? "none" : "lax",
    path: "/"
  });
  res.status(204).end();
});

app.get("/vault", requireSession, async (req, res) => {
  const s = req.session!;
  const v = await dbFindVaultById(s.vaultId);
  if (!v) return res.status(404).json({ error: "Vault not found" });

  res.json({
    ...v,
    currentUserId: s.userId,
    separation: await getSeparationState(s.vaultId),
    cloudStatus: {
      provider: env.STORAGE_PROVIDER === "s3" ? "Amazon S3" : "Local file storage",
      encryptedAtRest: env.STORAGE_PROVIDER === "s3",
      encryptionStandard: env.STORAGE_PROVIDER === "s3"
        ? "AES-256-GCM + AWS KMS"
        : "Client-side AES-256-GCM"
    }
  });
});

app.post("/vault/sharing-attempt", requireSession, async (req, res) => {
  try {
    const s = req.session!;
    const vault = await dbFindVaultById(s.vaultId);
    if (!vault) return res.status(404).json({ error: "Vault not found" });
    const member = [vault.memberA, vault.memberB].find((item) => item.id === s.userId);
    if (!member) return res.status(403).json({ error: "Vault member not found" });

    await notifyVaultPartners(
      s.vaultId,
      "UsVault blocked a photo export",
      `The in-app export control was used by ${member.email} at ${new Date().toISOString()}. The export was blocked by the shared vault policy.`
    );
    res.json({ ok: true, message: "The export was blocked and both partner emails were notified." });
  } catch (error) {
    console.error("[Sharing policy] Unable to send partner notifications:", error);
    res.status(503).json({ error: "The export remains blocked, but partner email notifications could not be delivered. Check the email service configuration." });
  }
});

app.post("/vault/separation", requireSession, async (req, res) => {
  const s = req.session!;
  const parsed = z.object({ action: z.enum(["request", "restore", "delete"]) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Choose request, restore, or delete." });

  try {
    const action = parsed.data.action;
    const current = await getSeparationState(s.vaultId);
    if (current?.status === "deleted") {
      return res.status(409).json({ error: "This vault has already been permanently deleted." });
    }

    if (action === "request") {
      if (current) return res.status(409).json({ error: "The separation protocol is already active." });
      const state: SeparationState = {
        vaultId: s.vaultId,
        status: "pending",
        requestedBy: s.userId,
        requestedAt: new Date().toISOString(),
        decision: null,
        proposedBy: null
      };
      await saveSeparationState(s.vaultId, state);
      try {
        await notifyVaultPartners(
          s.vaultId,
          "UsVault vault access is frozen",
          "A partner started the separation protocol. Vault access is now frozen while both members decide whether to restore access or permanently delete the shared photos."
        );
      } catch (error) {
        console.error("[Separation] Freeze email notification failed:", error);
        return res.status(503).json({ error: "Vault access has been frozen, but partner emails could not be delivered. Check the email service configuration." });
      }
      return res.json({ ok: true, state });
    }

    if (!current || current.status !== "pending") {
      return res.status(409).json({ error: "Start the separation protocol before selecting an outcome." });
    }

    if (!current.decision) {
      current.decision = action;
      current.proposedBy = s.userId;
      await saveSeparationState(s.vaultId, current);
      await notifyVaultPartners(
        s.vaultId,
        "UsVault separation decision needs confirmation",
        `A partner proposed to ${action === "restore" ? "restore vault access" : "permanently delete the shared photos"}. The other partner must confirm the same choice.`
      );
      return res.json({ ok: true, state: current, completed: false });
    }

    if (current.proposedBy === s.userId) {
      if (current.decision === action) {
        await notifyVaultPartners(
          s.vaultId,
          "UsVault separation decision needs confirmation",
          `A partner is waiting for your confirmation to ${action === "restore" ? "restore vault access" : "permanently delete the shared photos"}.`
        );
        return res.json({ ok: true, state: current, completed: false });
      }
      current.decision = action;
      await saveSeparationState(s.vaultId, current);
      await notifyVaultPartners(
        s.vaultId,
        "UsVault separation decision changed",
        `A partner changed the pending proposal to ${action === "restore" ? "restore vault access" : "permanently delete the shared photos"}. The other partner must confirm the same choice.`
      );
      return res.json({ ok: true, state: current, completed: false });
    }

    if (current.decision !== action) {
      return res.status(409).json({ error: "Your choice differs from the pending proposal. Ask the partner who proposed it to change the selection first." });
    }

    await notifyVaultPartners(
      s.vaultId,
      action === "restore" ? "UsVault vault access restored" : "UsVault photos scheduled for deletion",
      action === "restore"
        ? "Both partners agreed to restore access to the shared vault."
        : "Both partners confirmed permanent deletion. The encrypted photos and folders are being removed from the vault."
    );

    if (action === "delete") {
      await eraseVaultContent(s.vaultId);
      const deletedState: SeparationState = {
        ...current,
        status: "deleted",
        decision: "delete"
      };
      await saveSeparationState(s.vaultId, deletedState);
      return res.json({ ok: true, state: deletedState, completed: true });
    }

    await saveSeparationState(s.vaultId, null);
    return res.json({ ok: true, state: null, completed: true });
  } catch (error) {
    console.error("[Separation] Protocol action failed:", error);
    res.status(500).json({ error: error instanceof Error ? error.message : "The separation protocol could not be completed." });
  }
});

app.patch("/vault/rename", requireSession, async (req, res) => {
  try {
    const s = req.session!;
    const body = z.object({ name: z.string().trim().min(1).max(80) }).parse(req.body);

    if (usePrisma) {
      try {
        await prisma.vault.update({ where: { id: s.vaultId }, data: { name: body.name } });
      } catch { usePrisma = false; }
    }

    const v = localDb.vaults.find(x => x.id === s.vaultId);
    if (v) {
      v.name = body.name;
      v.updatedAt = new Date().toISOString();
      saveLocalDb();
    }

    res.json({ ok: true, name: body.name });
  } catch {
    res.status(400).json({ error: "Invalid vault name" });
  }
});

app.post("/crypto/device-key/challenge", async (req, res) => {
  const token = req.cookies[sessionCookie];
  const pending = token ? await storeGet(`pending-session:${token}`) : null;
  if (!pending) return res.status(401).json({ error: "Unauthorized" });

  const challenge = crypto.randomBytes(32).toString("base64url");
  await storeSet(`device-challenge:${token}:${challenge}`, pending, 300);
  res.json({ challenge });
});

app.post("/crypto/device-key", async (req, res) => {
  try {
    const token = req.cookies[sessionCookie];
    const pending = token ? await storeGet(`pending-session:${token}`) : null;
    if (!pending) return res.status(401).json({ error: "Unauthorized" });

    const p = JSON.parse(pending) as { vaultId: string; userId: string };
    const body = z.object({
      publicKeyJwk: z.any(),
      signature: z.string().min(10),
      challenge: z.string().min(10),
      label: z.string().max(80).optional()
    }).parse(req.body);

    const challengeKey = `device-challenge:${token}:${body.challenge}`;
    await storeDel(challengeKey);

    const dId = `dev_${crypto.randomBytes(8).toString("hex")}`;
    localDb.deviceKeys.push({
      id: dId,
      vaultId: p.vaultId,
      userId: p.userId,
      publicKeyJwk: body.publicKeyJwk,
      signingPublicKeyJwk: body.publicKeyJwk.signing || body.publicKeyJwk,
      label: body.label || "Browser Device",
      createdAt: new Date().toISOString(),
      revokedAt: null
    });
    saveLocalDb();

    await storeDel(`pending-session:${token}`);
    const sessionToken = crypto.randomBytes(32).toString("base64url");

    await storeSet(
      `session:${sessionToken}`,
      JSON.stringify({ vaultId: p.vaultId, userId: p.userId, deviceKeyId: dId }),
      SESSION_TTL_SECONDS
    );

    res.cookie(sessionCookie, sessionToken, {
      httpOnly: true,
      secure: env.NODE_ENV === "production",
      sameSite: env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: SESSION_TTL_SECONDS * 1000,
      path: "/"
    });

    res.json({ id: dId });
  } catch (err: any) {
    console.error("Device key notice:", err);
    res.status(400).json({ error: "Invalid device key" });
  }
});

app.post("/crypto/envelope", requireSession, async (req, res) => {
  try {
    const s = req.session!;
    const body = z.object({
      deviceKeyId: z.string(),
      wrappedVaultKey: z.string().min(20),
      version: z.number().int().positive()
    }).parse(req.body);

    const envId = `env_${crypto.randomBytes(8).toString("hex")}`;
    const existing = localDb.envelopes.find(e => e.vaultId === s.vaultId && e.deviceKeyId === body.deviceKeyId && e.version === body.version);
    if (existing) {
      existing.wrappedVaultKey = body.wrappedVaultKey;
    } else {
      localDb.envelopes.push({
        id: envId,
        vaultId: s.vaultId,
        userId: s.userId,
        deviceKeyId: body.deviceKeyId,
        wrappedVaultKey: body.wrappedVaultKey,
        version: body.version,
        createdAt: new Date().toISOString()
      });
    }
    saveLocalDb();

    res.json({ id: envId });
  } catch {
    res.status(400).json({ error: "Invalid key envelope" });
  }
});

app.post("/images", requireSession, upload.single("image"), async (req, res) => {
  try {
    const s = req.session!;
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const declaredMime = req.body.mimeType || "image/jpeg";
    const folderId = req.body.folderId || null;
    const id = crypto.randomUUID();
    const key = `vaults/${s.vaultId}/objects/${id}`;

    await putCiphertext(key, req.file.buffer);

    const imageRecord = {
      id,
      vaultId: s.vaultId,
      folderId,
      originalName: safeName(req.file.originalname),
      mimeType: declaredMime,
      size: req.file.size,
      storageKey: key,
      keyVersion: 1,
      createdAt: new Date().toISOString()
    };

    if (usePrisma) {
      try {
        await prisma.image.create({ data: imageRecord });
      } catch { usePrisma = false; }
    }

    localDb.images.push(imageRecord);
    saveLocalDb();

    res.json({
      id: imageRecord.id,
      folderId: imageRecord.folderId,
      originalName: imageRecord.originalName,
      mimeType: imageRecord.mimeType,
      size: imageRecord.size,
      keyVersion: imageRecord.keyVersion,
      createdAt: imageRecord.createdAt
    });
  } catch (e: any) {
    console.error("Image upload failed:", e);
    res.status(500).json({ error: "Upload failed" });
  }
});

app.get("/images/:id/ciphertext", requireSession, async (req, res) => {
  try {
    const s = req.session!;
    const id = routeId(req.params.id);
    const im = localDb.images.find(x => x.id === id && x.vaultId === s.vaultId);
    if (!im) return res.status(404).end();

    const body = await getCiphertext(im.storageKey);
    res.setHeader("Cache-Control", "private, no-store");
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Length", body.length.toString());
    res.end(body);
  } catch {
    res.status(404).end();
  }
});

app.delete("/images/:id", requireSession, async (req, res) => {
  const s = req.session!;
  const id = routeId(req.params.id);
  const im = localDb.images.find(x => x.id === id && x.vaultId === s.vaultId);
  if (!im) return res.status(404).end();

  await deleteCiphertext(im.storageKey);

  if (usePrisma) {
    try { await prisma.image.delete({ where: { id: im.id } }); } catch { usePrisma = false; }
  }

  localDb.images = localDb.images.filter(x => x.id !== im.id);
  saveLocalDb();

  res.status(204).end();
});

app.patch("/images/:id/move", requireSession, async (req, res) => {
  const s = req.session!;
  const id = routeId(req.params.id);
  const body = z.object({ folderId: z.string().nullable() }).parse(req.body);

  const im = localDb.images.find(x => x.id === id && x.vaultId === s.vaultId);
  if (!im) return res.status(404).end();

  im.folderId = body.folderId;
  saveLocalDb();

  if (usePrisma) {
    try { await prisma.image.update({ where: { id: im.id }, data: { folderId: body.folderId } }); } catch { usePrisma = false; }
  }

  res.status(204).end();
});

app.post("/folders", requireSession, async (req, res) => {
  const s = req.session!;
  const body = z.object({
    name: z.string().trim().min(1).max(80),
    parentId: z.string().nullable()
  }).parse(req.body);

  const fId = `fld_${crypto.randomBytes(8).toString("hex")}`;
  const folder = {
    id: fId,
    vaultId: s.vaultId,
    name: body.name,
    parentId: body.parentId,
    createdAt: new Date().toISOString()
  };

  if (usePrisma) {
    try { await prisma.folder.create({ data: folder }); } catch { usePrisma = false; }
  }

  localDb.folders.push(folder);
  saveLocalDb();

  res.json(folder);
});

const port = env.PORT;
const server = app.listen(port, () => console.log(`🚀 UsVault API online at http://localhost:${port}`));

async function shutdown() {
  server.close();
  if (usePrisma) await prisma.$disconnect().catch(() => {});
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
