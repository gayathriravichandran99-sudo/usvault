# UsVault — hardened E2EE production foundation

## Get the current project running locally

The `Failed to fetch` message appears when the frontend at `http://localhost:5173` cannot reach the API. This project now supports a real local development mode so you do **not** need AWS just to test the app.

Start PostgreSQL and Redis:

```bash
docker compose up -d
```

Start the API:

```bash
cd backend
cp .env.example .env
npm install
npx prisma generate
npx prisma migrate deploy
npm run dev
```

If this is a brand-new database and migrations have not been applied, `migrate deploy` will create the schema from the checked-in migrations.

Then start the frontend in another terminal:

```bash
cd frontend
cp .env.example .env.local
npm install
npm run dev
```

For local login, OTPs are sent by Resend. Local uploads are stored under `backend/storage/`. They are still **client-encrypted ciphertext**; the local storage provider is only for development.

For production, switch `STORAGE_PROVIDER=s3`, configure Resend, then use managed PostgreSQL/Redis and a private S3 bucket. See `CLOUD_SETUP.md`.

## The trust promise

**Your photos are encrypted before they leave your device. UsVault's servers store ciphertext, not photo plaintext.**

Our architecture is designed so the service does not possess the plaintext vault key needed to decrypt your photos. That is the core of the UsVault privacy model.

## Security model

- Photos are encrypted in the browser with AES-256-GCM before upload.
- The API receives only ciphertext.
- S3 stores ciphertext only and is private; S3 also uses AWS KMS server-side encryption as a second at-rest layer.
- The vault AES key is never sent to the API in plaintext.
- Each browser/device creates a 3072-bit RSA-OAEP key pair using Web Crypto.
- The private key stays in IndexedDB and is non-exportable.
- The vault key is wrapped separately for each registered device using RSA-OAEP.
- The server stores only the public device keys and encrypted vault-key envelopes.
- Both partner OTPs are required before a session is issued.
- OTPs are stored as hashes and expire.
- Redis rate limits OTP and pair-login attempts.
- Auth is an HttpOnly, Secure, SameSite cookie in production.
- Every vault/object operation is scoped to the authenticated vault.

## What we will and will not claim

We should **not** publish “100% secure” or “unhackable” as a factual guarantee. No internet-connected service can honestly guarantee that.

The stronger, accurate claim is: **“Designed so UsVault cannot decrypt your photos.”** Photos are encrypted in your browser before upload, and the server stores ciphertext.

There is one important web-E2EE limitation: a compromised browser, malicious extension, compromised device, XSS vulnerability, or compromised frontend deployment could potentially access plaintext before encryption or after decryption. That is why production frontend integrity, CSP, dependency controls, secure CI/CD, monitoring and an independent security review are part of the security boundary.

## Production services

1. PostgreSQL (Neon, Supabase, AWS RDS, etc.)
2. Redis (Upstash, ElastiCache, etc.)
3. Private S3 bucket
4. AWS KMS key used by S3 for server-side encryption
5. Amazon SES for OTP delivery
6. HTTPS frontend + API

## AWS S3 requirements

- Block all public access.
- Disable public ACLs.
- Use bucket encryption with AWS KMS.
- Enable versioning if you want recovery from accidental deletion.
- Add lifecycle rules and backups according to your retention policy.
- Give the API IAM role only `PutObject`, `GetObject`, and `DeleteObject` on the vault prefix; do not give it broad admin permissions.

## KMS requirements

The API does not need KMS decrypt permission for the photo encryption itself because photo E2EE happens in the browser. KMS protects the S3 ciphertext at rest. Prefer an IAM role and short-lived AWS credentials instead of long-lived access keys.

## Database

Run migrations in deployment:

```bash
cd backend
npm ci
npx prisma generate
npx prisma migrate deploy
npm run build
npm start
```

Create the first migration locally with `npx prisma migrate dev --name init` after setting `DATABASE_URL`.

## Frontend

```bash
cd frontend
npm ci
npm run build
```

Set `VITE_API_URL` to the HTTPS API origin.

## Before accepting real users

- Put the API behind a WAF/reverse proxy.
- Add CSP with nonces/hashes appropriate to the final frontend build; remove unsafe inline allowances.
- Add malware/content scanning if you decide to support more file types.
- Add account/vault recovery and a documented lost-device flow.
- Add encrypted vault-key backup/recovery that never exposes the plaintext key to the server.
- Add audit logging that never logs photo content or encryption keys.
- Configure database PITR/backups and S3 versioning.
- Add monitoring, alerting, dependency scanning, secret rotation, and incident response.
- Add Terms, Privacy Policy, data deletion/export, and retention controls.
- Test multi-device key rotation and revoked-device handling.
- Run an independent penetration test before launch.


See `SECURITY.md` for the security baseline and pre-launch checklist.

## Security-hardening changes in this revision

- Opaque random Redis-backed sessions instead of JWTs in browser cookies.
- Session is bound to a registered, non-revoked browser device.
- One-time device registration challenges.
- State-changing requests require the configured frontend Origin.
- Stronger production HTTP security headers/CSP baseline.
- OTP verification rate limiting in addition to OTP-send rate limiting.
- Device limit and device revocation support.
- Removed server-side image file-type inspection because E2EE ciphertext is intentionally opaque; the client-declared MIME type is restricted to supported image types. This is not equivalent to plaintext malware scanning.
- Removed unused legacy per-image server encryption fields.
- Graceful shutdown for DB/Redis.
- Production deployment and security-header checklists.

## Do not claim “100% secure”

Use this wording on the website instead:

> **Designed so UsVault cannot decrypt your photos.** Photos are encrypted in your browser before they leave your device. Our servers store encrypted data, not photo plaintext.

Avoid “unhackable”, “100% secure”, or similar absolute guarantees. The web application still depends on the security of the user's device/browser and the integrity of the frontend code delivered to it.
