# Couple Vault cloud setup

## 1. Get the local application working first

From the project root:

```bash
docker compose up -d
cd backend
cp .env.example .env
npm install
npx prisma generate
npx prisma migrate dev --name init
npm run dev
```

Then, in a second terminal:

```bash
cd frontend
cp .env.example .env.local
npm install
npm run dev
```

Open `http://localhost:5173`.

The backend sends OTP codes through Resend. Set `RESEND_API_KEY` and `RESEND_FROM_EMAIL` in `backend/.env`.

## 2. Cloud architecture

Use this production layout:

```text
Browser
  |
 HTTPS
  v
Frontend CDN/hosting
  |
 HTTPS + secure cookie
  v
API service
  |------ PostgreSQL (TLS)
  |------ Redis (TLS)
  |------ S3 private bucket (ciphertext only)
  |------ Resend (OTP email)
  \------ CloudWatch / audit logs

Browser encrypts photo -> API -> S3
Browser decrypts photo <- API <- S3

The API never receives the plaintext photo or plaintext vault key.
```

## 3. S3

Run `infra/aws/s3-bootstrap.sh` from an AWS-authenticated environment:

```bash
export AWS_REGION=ap-south-1
export BUCKET_NAME=couple-vault-private-UNIQUE-NAME
./infra/aws/s3-bootstrap.sh
```

AWS recommends S3 Block Public Access, disabling ACLs with Bucket Owner Enforced, least-privilege policies, IAM roles rather than long-lived access keys, and encryption at rest. See AWS's current S3 security guidance.

After creating the bucket, attach `infra/aws/backend-s3-kms-policy.json` to the backend runtime role after replacing the bucket name and KMS ARN.

## 4. PostgreSQL

Use Amazon RDS PostgreSQL, Neon, or another managed PostgreSQL provider. Production requirements:

- TLS required
- encryption at rest
- automated backups
- point-in-time recovery
- no public database access if using AWS VPC
- separate production credentials
- least-privilege database user

Set `DATABASE_URL` to the provider's TLS connection string.

## 5. Redis

Use Amazon ElastiCache/MemoryDB or a managed Redis provider such as Upstash. Production requirements:

- TLS
- authentication
- private networking where supported
- no public unauthenticated Redis endpoint

Set `REDIS_URL` to the TLS URL.

## 6. Resend

Create a Resend API key and verify the sender email or domain. Resend's testing sender can only deliver to the Resend account email; verify a domain to send to arbitrary recipient emails. Set:

```env
RESEND_API_KEY=re_...
RESEND_FROM_EMAIL=security@yourdomain.com
```

## 7. Backend environment

Production example:

```env
NODE_ENV=production
PORT=8080
FRONTEND_ORIGIN=https://app.yourdomain.com
DATABASE_URL=postgresql://...
REDIS_URL=rediss://...
SESSION_SECRET=<random-secret-from-secret-manager>
STORAGE_PROVIDER=s3
AWS_REGION=ap-south-1
AWS_S3_BUCKET=couple-vault-private-production
RESEND_API_KEY=re_...
RESEND_FROM_EMAIL=security@yourdomain.com
OTP_EXPIRES_MINUTES=10
MAX_UPLOAD_MB=50
```

Store these in AWS Secrets Manager/SSM or your deployment platform's secret store. Do not commit `.env`.

## 8. Database deployment

In CI/CD:

```bash
npm ci
npx prisma generate
npx prisma migrate deploy
npm run build
npm start
```

Do not use `prisma db push` against production.

## 9. Frontend deployment

Set:

```env
VITE_API_URL=https://api.yourdomain.com
```

The frontend receives no AWS credentials. Only the API accesses S3.

## 10. What you create yourself

You need to create:

1. AWS account with MFA on the root/admin identity.
2. S3 bucket + KMS key.
3. Backend IAM role.
4. PostgreSQL database.
5. Redis instance.
6. SES verified domain/email.
7. API hosting (ECS/Fargate, App Runner, Render, Railway, etc.).
8. Frontend hosting/CDN.
9. DNS records for `app.yourdomain.com` and `api.yourdomain.com`.
10. HTTPS certificates.
11. Secret storage.
12. Monitoring and alerts.

Never give the browser an AWS access key, S3 secret, KMS key, database password, or Redis password.
