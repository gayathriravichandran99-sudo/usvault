# UsVault MVP scope

## Included
- Pair login: two emails + two OTPs
- Device registration with ECDSA proof of possession
- Browser-held non-exportable device private keys (IndexedDB)
- Browser-side AES-256-GCM encryption before upload
- Device-key and RSA-OAEP envelope helpers (not yet used for current vault-key derivation)
- Ciphertext-only photo object storage
- Encrypted preview/decryption in browser
- On-device photo categories, stored only in the local browser
- In-app export blocked with email notice to both partners
- Separation protocol: freeze access; require both partners to confirm restore or deletion
- Folder creation and photo movement
- Delete, logout, session expiry
- Opaque, seven-day sessions persisted locally for development (Redis-backed sessions and API rate limiting are not wired in this server)
- Local storage for development + S3 adapter for deployment

## Deliberately not represented as complete
- Recovery code / social recovery
- Complete cryptographic key rotation and revocation
- Encrypted metadata manifest
- Per-item data keys / secretstream chunking
- Ownership + dual-consent deletion state machine
- Cryptographic separation and key revocation; the current flow cannot recall plaintext already copied or captured
- E2EE share links
- Mobile Flutter/Rust/Go implementation
- Independent security audit / pentest
- Production WAF, backups/PITR, monitoring, CI/CD and legal launch package
