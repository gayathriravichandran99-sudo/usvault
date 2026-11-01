const DB = "couple-vault-keys";
const STORE = "keys";

function db(): Promise<IDBDatabase> {
  return new Promise((ok, no) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => ok(r.result);
    r.onerror = () => no(r.error);
  });
}

async function put(id: string, v: any): Promise<void> {
  try {
    const d = await db();
    return new Promise((ok, no) => {
      const t = d.transaction(STORE, "readwrite");
      t.objectStore(STORE).put(v, id);
      t.oncomplete = () => ok();
      t.onerror = () => no(t.error);
    });
  } catch {}
}

async function get<T = any>(id: string): Promise<T | null> {
  try {
    const d = await db();
    return new Promise((ok, no) => {
      const r = d.transaction(STORE).objectStore(STORE).get(id);
      r.onsuccess = () => ok(r.result ?? null);
      r.onerror = () => no(r.error);
    });
  } catch {
    return null;
  }
}

// Safe base64 encode without stack overflow
export function b64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  const len = bytes.byteLength;
  const chunk = 0x8000;
  for (let i = 0; i < len; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + chunk, len)) as any);
  }
  return btoa(binary);
}

// Safe base64 decode
export function unb64(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function createDevice() {
  const enc = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    false,
    ["encrypt", "decrypt"]
  );
  const sign = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"]
  );
  return { enc, sign };
}

export async function saveDevice(id: string, p: any) {
  await put("enc:" + id, p.enc.privateKey);
  await put("sign:" + id, p.sign.privateKey);
}

export async function privateKey(id: string) {
  const enc = await get<CryptoKey>("enc:" + id);
  const sign = await get<CryptoKey>("sign:" + id);
  return enc && sign ? { enc, sign } : null;
}

export async function exportPublic(p: any) {
  return {
    encryption: await crypto.subtle.exportKey("jwk", p.enc.publicKey),
    signing: await crypto.subtle.exportKey("jwk", p.sign.publicKey)
  };
}

export async function signChallenge(k: CryptoKey, challenge: string) {
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k, new TextEncoder().encode(challenge));
  return b64(sig);
}

export async function saveVaultKey(vaultId: string, key: CryptoKey) {
  await put("vault-key:" + vaultId, key);
}

export async function vaultKey(vaultId: string): Promise<CryptoKey | null> {
  return get<CryptoKey>("vault-key:" + vaultId);
}

export async function clearVaultKey(vaultId: string) {
  try {
    const d = await db();
    return new Promise<void>((ok, no) => {
      const t = d.transaction(STORE, "readwrite");
      t.objectStore(STORE).delete("vault-key:" + vaultId);
      t.oncomplete = () => ok();
      t.onerror = () => no(t.error);
    });
  } catch {}
}

export async function makeVaultKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

/**
 * Deterministically derives the Vault Master Key using PBKDF2 (100,000 rounds)
 * from the two partner emails and vaultId.
 * Guarantees that ANY approved session on ANY device can decrypt the images immediately!
 */
export async function deriveVaultKey(vaultId: string, emailA: string, emailB: string): Promise<CryptoKey> {
  const sorted = [emailA.trim().toLowerCase(), emailB.trim().toLowerCase()].sort().join("::");
  const enc = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(`usvault-master:${sorted}:${vaultId}`),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const salt = await crypto.subtle.digest("SHA-256", enc.encode(`usvault-salt:${vaultId}:${sorted}`));
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function wrapVaultKey(vaultKey: CryptoKey, publicJwk: any) {
  const pub = await crypto.subtle.importKey("jwk", publicJwk.encryption, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  const raw = await crypto.subtle.exportKey("raw", vaultKey);
  return b64(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, raw));
}

export async function unwrapVaultKey(ciphertext: string, priv: CryptoKey) {
  const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, unb64(ciphertext) as any);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
}

export async function encryptFile(file: File, key: CryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const buffer = await file.arrayBuffer();
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, buffer);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), 12);
  return new Blob([out], { type: "application/octet-stream" });
}

export async function decryptBlob(blob: Blob, key: CryptoKey, mime: string): Promise<Blob> {
  const x = new Uint8Array(await blob.arrayBuffer());
  const iv = x.slice(0, 12);
  const ciphertext = x.slice(12);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new Blob([plain], { type: mime });
}
