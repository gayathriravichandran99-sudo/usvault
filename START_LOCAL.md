# UsVault MVP — local start

## Requirements
- Docker Desktop
- Node.js 20+

## 1. Start PostgreSQL + Redis

```bash
docker compose up -d
```

## 2. Start API (Terminal 1)

```bash
cd backend
copy .env.example .env
npm install
npx prisma generate
npx prisma migrate deploy
npm run dev
```

On macOS/Linux replace `copy` with `cp`.

The development OTP is printed in the API terminal.

## 3. Start web app (Terminal 2)

```bash
cd frontend
copy .env.example .env.local
npm install
npm run dev
```

Open the Vite URL shown in the terminal (normally http://localhost:5173).

## What this MVP demonstrates
- Two partner email addresses
- Two OTPs required to open a vault
- Browser/device key pair generation
- Browser-side AES-256-GCM photo encryption
- Server/storage receives ciphertext, not plaintext photo bytes
- Per-device encrypted vault-key envelopes
- Encrypted photo preview in the browser
- On-device smart photo categories; photos are not sent to an AI service
- Blocked in-app exports with email notices to both partners
- A separation protocol that freezes access and requires both partners to choose restore or deletion
- Folders and moving photos
- Delete and logout
- Opaque, seven-day sessions persisted locally across page refreshes and API restarts
- Local ciphertext storage, with an S3 production adapter

## Important MVP limitations
This is a runnable **web MVP**, not the final production mobile release. The separation flow is a mutual freeze/restore/delete process, not cryptographic key revocation; it cannot recall files already copied or captured outside the app. The current key is derived partly from partner email addresses, which are not secret. The MVP also lacks recovery codes, complete vault-key rotation/revocation, an encrypted metadata manifest, per-item keys/secretstream chunking, encrypted share links, mobile clients, an independent audit, and production infrastructure.

Do not use this MVP to store highly sensitive real-world material until those gaps are implemented and independently reviewed.
