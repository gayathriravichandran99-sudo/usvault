-- Security/E2EE schema hardening. Safe on a fresh install and on the previous E2EE schema.
ALTER TABLE "Image" DROP COLUMN IF EXISTS "encryptedKey";
ALTER TABLE "Image" DROP COLUMN IF EXISTS "iv";
ALTER TABLE "Image" DROP COLUMN IF EXISTS "authTag";
ALTER TABLE "Image" ADD COLUMN IF NOT EXISTS "keyVersion" INTEGER NOT NULL DEFAULT 1;
ALTER TABLE "DeviceKey" ADD COLUMN IF NOT EXISTS "revokedAt" TIMESTAMP(3);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='VaultKeyEnvelope' AND column_name='ciphertextJwe'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='VaultKeyEnvelope' AND column_name='wrappedVaultKey'
  ) THEN
    ALTER TABLE "VaultKeyEnvelope" RENAME COLUMN "ciphertextJwe" TO "wrappedVaultKey";
  END IF;
END $$;
