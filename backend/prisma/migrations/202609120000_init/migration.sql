CREATE TABLE "User" (
  "id" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

CREATE TABLE "Vault" (
  "id" TEXT NOT NULL,
  "name" TEXT NOT NULL DEFAULT 'Our Vault',
  "memberAId" TEXT NOT NULL,
  "memberBId" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "Vault_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "Vault_memberAId_idx" ON "Vault"("memberAId");
CREATE INDEX "Vault_memberBId_idx" ON "Vault"("memberBId");

CREATE TABLE "Folder" (
  "id" TEXT NOT NULL,
  "vaultId" TEXT NOT NULL,
  "parentId" TEXT,
  "name" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "Folder_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "Folder_vaultId_idx" ON "Folder"("vaultId");
CREATE INDEX "Folder_parentId_idx" ON "Folder"("parentId");

CREATE TABLE "Image" (
  "id" TEXT NOT NULL,
  "vaultId" TEXT NOT NULL,
  "folderId" TEXT,
  "originalName" TEXT NOT NULL,
  "mimeType" TEXT NOT NULL,
  "size" INTEGER NOT NULL,
  "storageKey" TEXT NOT NULL,
  "keyVersion" INTEGER NOT NULL DEFAULT 1,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "Image_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "Image_storageKey_key" ON "Image"("storageKey");
CREATE INDEX "Image_vaultId_createdAt_idx" ON "Image"("vaultId","createdAt");
CREATE INDEX "Image_folderId_idx" ON "Image"("folderId");

CREATE TABLE "Otp" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "codeHash" TEXT NOT NULL,
  "purpose" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "consumedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "Otp_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "Otp_userId_purpose_expiresAt_idx" ON "Otp"("userId","purpose","expiresAt");

CREATE TABLE "DeviceKey" (
  "id" TEXT NOT NULL,
  "vaultId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "publicKeyJwk" JSONB NOT NULL,
  "signingPublicKeyJwk" JSONB NOT NULL,
  "label" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "revokedAt" TIMESTAMP(3),
  CONSTRAINT "DeviceKey_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "DeviceKey_vaultId_userId_idx" ON "DeviceKey"("vaultId","userId");

CREATE TABLE "VaultKeyEnvelope" (
  "id" TEXT NOT NULL,
  "vaultId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "deviceKeyId" TEXT NOT NULL,
  "wrappedVaultKey" TEXT NOT NULL,
  "version" INTEGER NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "VaultKeyEnvelope_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "VaultKeyEnvelope_vaultId_deviceKeyId_version_key" ON "VaultKeyEnvelope"("vaultId","deviceKeyId","version");
CREATE INDEX "VaultKeyEnvelope_vaultId_userId_idx" ON "VaultKeyEnvelope"("vaultId","userId");

ALTER TABLE "Vault" ADD CONSTRAINT "Vault_memberAId_fkey" FOREIGN KEY ("memberAId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "Vault" ADD CONSTRAINT "Vault_memberBId_fkey" FOREIGN KEY ("memberBId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "Folder" ADD CONSTRAINT "Folder_vaultId_fkey" FOREIGN KEY ("vaultId") REFERENCES "Vault"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Folder" ADD CONSTRAINT "Folder_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "Folder"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Image" ADD CONSTRAINT "Image_vaultId_fkey" FOREIGN KEY ("vaultId") REFERENCES "Vault"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Image" ADD CONSTRAINT "Image_folderId_fkey" FOREIGN KEY ("folderId") REFERENCES "Folder"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "Otp" ADD CONSTRAINT "Otp_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "DeviceKey" ADD CONSTRAINT "DeviceKey_vaultId_fkey" FOREIGN KEY ("vaultId") REFERENCES "Vault"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "DeviceKey" ADD CONSTRAINT "DeviceKey_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "VaultKeyEnvelope" ADD CONSTRAINT "VaultKeyEnvelope_vaultId_fkey" FOREIGN KEY ("vaultId") REFERENCES "Vault"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "VaultKeyEnvelope" ADD CONSTRAINT "VaultKeyEnvelope_deviceKeyId_fkey" FOREIGN KEY ("deviceKeyId") REFERENCES "DeviceKey"("id") ON DELETE CASCADE ON UPDATE CASCADE;
