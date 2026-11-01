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

OTP and vault-security emails use the backend's configured SMTP sender. Configure the `SMTP_*` settings in `backend/.env` or the server-side SMTP settings before expecting emails; without a working sender, OTPs are only logged in the API terminal and export/separation notices cannot be delivered. End users enter only their own email addresses.

Local uploads are stored under `backend/storage/`. The provider stores browser-encrypted photo bytes, but does not add AWS KMS encryption at rest. For production, switch `STORAGE_PROVIDER=s3`, configure SMTP delivery, and use managed database/storage services. See `CLOUD_SETUP.md`.

## Current privacy model

Photo bytes are encrypted in the browser with AES-256-GCM before upload, and the API stores ciphertext. **This MVP does not yet provide a strong, independently verified end-to-end encryption guarantee.** Its current vault key is derived from both partners' email addresses and the vault ID; those values are not secret, and the current application must not claim that UsVault is technically unable to derive the key.

## Security model

- Photos are encrypted in the browser with AES-256-GCM before upload.
- The API receives only ciphertext.
- When configured, private S3 stores ciphertext and can use AWS KMS server-side encryption as an additional at-rest layer.
- The browser derives the vault key from the two email addresses and vault ID; this is a known MVP limitation, not secure key custody.
- Both partner email verification codes are required before a session is issued.
- OTPs are stored as hashes and expire.
- Auth uses an HttpOnly cookie; photo and folder operations are scoped to the authenticated vault.
- Smart categories are inferred in the browser. The classifier model may be downloaded from Google on first use; photos are not sent to an AI service for categorization.
- In-app export controls are blocked and export attempts trigger email notices to both partners. This does not prevent screenshots, browser inspection, or copies outside the app.
- The separation protocol freezes vault operations and requires both partners to agree on restoring access or permanently deleting stored photos. It cannot revoke plaintext or keys already copied from a browser.

## What we will and will not claim

We should **not** publish “100% secure” or “unhackable” as a factual guarantee. No internet-connected service can honestly guarantee that.

The accurate current claim is: **“Photos are encrypted in your browser before upload, but this MVP's key derivation is not strong enough to guarantee that the service cannot decrypt them.”**

There is one important web-E2EE limitation: a compromised browser, malicious extension, compromised device, XSS vulnerability, or compromised frontend deployment could potentially access plaintext before encryption or after decryption. That is why production frontend integrity, CSP, dependency controls, secure CI/CD, monitoring and an independent security review are part of the security boundary.

## Production services

1. PostgreSQL (Neon, Supabase, AWS RDS, etc.)
2. Redis (Upstash, ElastiCache, etc.)
3. Private S3 bucket
4. AWS KMS key used by S3 for server-side encryption
5. A configured SMTP provider for OTP and security notices
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

## Current implementation caveats

- Local-development sessions are persisted in `backend/storage/session_store.json` with hashed lookup keys and a seven-day expiry, so refreshing the page or restarting the API does not sign users out. Redis-backed sessions and API rate limiting are not wired into the current server; use a shared durable session store for multi-instance production deployments.
- The current HTTP configuration disables Helmet's Content Security Policy. A production CSP and origin restrictions still need implementation and testing.
- Device-key and vault-key-envelope helpers exist, but the current vault key is derived from partner email addresses rather than securely rotated and wrapped for each device.
- Local storage does not add AWS KMS encryption. Configure S3 and KMS separately for that additional at-rest layer.

## Do not claim “100% secure”

For the current MVP, describe the protection accurately:

> Photos are encrypted in your browser before upload. This early-access MVP derives its vault key partly from partner email addresses and is not suitable for highly sensitive files.

Avoid “unhackable”, “100% secure”, or claims that UsVault cannot decrypt photos until strong key management is implemented and independently reviewed. The web application also depends on the security of the user's device/browser and the integrity of the frontend code delivered to it.
