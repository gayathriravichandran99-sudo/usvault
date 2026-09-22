# Couple Vault Security Baseline

## Product security promise

Couple Vault is designed so the service backend receives encrypted photo data rather than photo plaintext. Photo encryption is performed in the user's browser using Web Crypto AES-256-GCM. Vault keys are wrapped to device public keys; the server does not receive the vault key in plaintext.

This is a security design, not a promise that no endpoint, browser, device, dependency, identity provider, or deployment can ever be compromised. A malicious or compromised client-side JavaScript bundle can defeat browser E2EE, and a device that already holds a vault key can decrypt content it has access to.

## Implemented hardening in this build

- Browser-side AES-256-GCM photo encryption.
- RSA-OAEP 3072-bit per-device key wrapping.
- Non-exportable private Web Crypto keys in IndexedDB.
- ECDSA proof-of-possession for device registration.
- One-time Redis-backed device challenges.
- Opaque random server sessions stored in Redis instead of self-contained JWT sessions.
- HttpOnly + Secure + SameSite cookies in production.
- Same-origin protection for state-changing API requests.
- Strict CORS allow-list.
- Helmet security headers, CSP, HSTS in production, no-referrer policy and frame denial.
- Redis-backed OTP/login rate limits.
- Maximum upload size and binary file-signature validation.
- Private S3 storage with KMS server-side encryption.
- Device limit and device revocation flag.
- Session is bound to a non-revoked device.
- Graceful shutdown for API, database and Redis connections.
- No photo plaintext, vault keys or private keys in server logs.

## Important revocation property

Revoking a device blocks its future authenticated API access. It cannot remotely erase a vault key that was already cached on that device. To cryptographically invalidate a previously trusted device, the vault key must be rotated and the stored ciphertext re-encrypted under the new key. That operation should be implemented as a deliberate, authenticated recovery/key-rotation workflow before launch.

## Required before public launch

1. Independent application security review and penetration test.
2. Threat model covering malicious server, stolen session, compromised browser extension, XSS, supply-chain attack, compromised CDN, malicious partner, lost device, and database/S3 compromise.
3. Strict production frontend CSP and deployment integrity controls; do not ship a debug/dev bundle.
4. Immutable/pinned production builds, dependency lockfiles, automated dependency/SAST scanning and signed CI/CD artifacts where practical.
5. WAF/rate limiting at the edge, DDoS protection and monitoring.
6. AWS S3 Block Public Access, Object Ownership enforced, least-privilege IAM, KMS key policy, CloudTrail and alerting.
7. PostgreSQL encryption, private networking where practical, PITR backups and tested restore procedures.
8. Redis TLS, authentication, private networking and eviction/availability monitoring.
9. Encrypted key recovery and full vault-key rotation before offering account recovery.
10. Device management UI, recovery codes, session/device revocation, and incident-response procedures.
11. Audit events that contain no photo content, plaintext keys, OTPs or sensitive metadata.
12. Privacy policy, retention/deletion/export policy and clear explanation of the E2EE trust model.

## Web-E2EE limitation

The server cannot decrypt ciphertext with the cryptographic material described above. However, the server or a compromised deployment pipeline could theoretically serve malicious JavaScript to a browser and attempt to steal plaintext or newly generated keys. This is why frontend integrity, CSP, dependency control, secure CI/CD, independent review and transparent releases are part of the security boundary.
