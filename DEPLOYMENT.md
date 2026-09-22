# Production deployment baseline

## Frontend

Build the Vite application and serve the generated `dist/` directory from a trusted HTTPS origin. Do not expose the Vite development server to the internet.

Recommended edge controls:

- TLS 1.2+ only; redirect HTTP to HTTPS.
- HSTS with includeSubDomains after verifying every subdomain is HTTPS.
- Content-Security-Policy appropriate to the final deployment.
- `frame-ancestors 'none'` and `X-Content-Type-Options: nosniff`.
- `Referrer-Policy: no-referrer`.
- `Permissions-Policy` disabling browser capabilities the app does not use.
- Cache JS/CSS assets immutably by content hash; do not cache authenticated API responses.
- Do not deploy source maps publicly unless you have consciously accepted the information disclosure.

## API

Place the API behind an HTTPS load balancer/WAF. Allow traffic only from the frontend origin at the CORS layer, and keep the API private from direct database/Redis access.

The application also checks the `Origin` header on state-changing requests. Do not disable that protection when adding a reverse proxy.

## Render quick start

The repository includes `render.yaml` for the API. Create managed PostgreSQL and Redis resources with TLS, then create a Render Blueprint from this repository. Enter the generated values for `DATABASE_URL`, `REDIS_URL`, `AWS_REGION`, `AWS_S3_BUCKET`, `RESEND_API_KEY`, and `RESEND_FROM_EMAIL`.

After the API deploys, copy its HTTPS URL into the GitHub repository variable `VITE_API_URL`. The Pages workflow will then build the frontend with the correct API origin.

## AWS

S3:

- Block Public Access: ON.
- Object Ownership: Bucket owner enforced.
- ACLs: disabled.
- Default encryption: SSE-KMS with a dedicated KMS key.
- Versioning: ON if your retention policy requires recovery.
- Lifecycle rules: define explicitly.
- Bucket policy: deny non-TLS access and deny public access.
- API IAM role: least privilege to the specific bucket/prefix.

KMS:

- Separate application encryption key from unrelated workloads.
- Restrict key administration and usage to separate roles.
- Enable CloudTrail logging for key usage.

## Database and Redis

- PostgreSQL must require TLS and use private networking where practical.
- Enable point-in-time recovery and regularly test restore.
- Redis must use TLS/authentication and private networking.
- Never put OTP values, session tokens, private keys, vault keys or decrypted photo content in logs.

## CI/CD

At minimum:

1. `npm ci` from committed lockfiles.
2. TypeScript build.
3. Prisma migration validation.
4. Dependency vulnerability scanning.
5. SAST and secret scanning.
6. Unit/integration/security tests.
7. Build once and deploy the exact artifact that was tested.
8. Protect production deployment credentials with short-lived identity where supported.
9. Require review for production changes.

## Security review

Before accepting real users, commission an independent penetration test and review the E2EE threat model. In particular, test XSS, malicious frontend deployment, stolen sessions, device registration, device revocation, OTP abuse, CSRF, IDOR, S3 access, backup access, dependency/supply-chain attacks and lost-device scenarios.
