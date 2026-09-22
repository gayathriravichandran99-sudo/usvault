# UsVault MVP scope

## Included
- Pair login: two emails + two OTPs
- Device registration with ECDSA proof of possession
- Browser-held non-exportable device private keys (IndexedDB)
- Browser-side AES-256-GCM encryption before upload
- Encrypted vault-key envelopes using RSA-OAEP 3072
- Ciphertext-only photo object storage
- Encrypted preview/decryption in browser
- Download after local decryption
- Folder creation and photo movement
- Delete, logout, session expiry
- Redis rate limiting and opaque sessions
- Local storage for development + S3 adapter for deployment

## Deliberately not represented as complete
- Recovery code / social recovery
- Complete cryptographic key rotation and revocation
- Encrypted metadata manifest
- Per-item data keys / secretstream chunking
- Ownership + dual-consent deletion state machine
- Vault separation/breakup flow
- E2EE share links
- Mobile Flutter/Rust/Go implementation
- Independent security audit / pentest
- Production WAF, backups/PITR, monitoring, CI/CD and legal launch package
