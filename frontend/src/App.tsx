import { useEffect, useRef, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Heart,
  Upload,
  FolderPlus,
  ShieldAlert,
  Trash2,
  LogOut,
  Lock,
  ShieldCheck,
  RefreshCw,
  Mail,
  CheckCircle2,
  AlertCircle,
  Eye,
  Sparkles,
  Cloud,
  Shield,
  Users,
  Search,
  ZoomIn,
  ZoomOut,
  X,
  Edit3,
  HardDrive,
  Folder as FolderIcon
} from "lucide-react";
import { api, ApiError } from "./api";
import * as C from "./crypto";
import { classifyPhoto } from "./classifyPhoto";

type Img = {
  id: string;
  folderId: string | null;
  originalName: string;
  mimeType: string;
  size: number;
  keyVersion: number;
  createdAt: string;
};

type Folder = {
  id: string;
  parentId: string | null;
  name: string;
};

type VaultData = {
  id: string;
  name: string;
  currentUserId: string;
  memberA: { id: string; email: string };
  memberB: { id: string; email: string };
  folders: Folder[];
  images: Img[];
  separation: {
    status: "pending" | "deleted";
    requestedBy: string;
    requestedAt: string;
    decision: "restore" | "delete" | null;
    proposedBy: string | null;
  } | null;
  cloudStatus?: {
    provider: string;
    encryptedAtRest: boolean;
    encryptionStandard: string;
  };
};

const DEVICE_ID_KEY = "cv-device-id";
const PRIVACY_CONSENT_KEY = "usvault-privacy-consent-v1";
const PRIVACY_CONSENT_VALUE = "accepted";
const getDeviceId = () => localStorage.getItem(DEVICE_ID_KEY) || "";
const setDeviceId = (x: string) => localStorage.setItem(DEVICE_ID_KEY, x);

export default function App() {
  // Vault & Auth States
  const [vault, setVault] = useState<VaultData | null>(null);
  const [privacyAccepted, setPrivacyAccepted] = useState(() => {
    try {
      return localStorage.getItem(PRIVACY_CONSENT_KEY) === PRIVACY_CONSENT_VALUE;
    } catch {
      return false;
    }
  });
  const [sessionStatus, setSessionStatus] = useState<"checking" | "ready" | "error">(
    () => privacyAccepted ? "checking" : "ready"
  );
  const [showPrivacyNotice, setShowPrivacyNotice] = useState(false);
  const [privacyAcknowledged, setPrivacyAcknowledged] = useState(false);
  const [privacyError, setPrivacyError] = useState("");
  const [emailA, setEmailA] = useState("");
  const [emailB, setEmailB] = useState("");
  const [codeA, setCodeA] = useState(["", "", "", "", "", ""]);
  const [codeB, setCodeB] = useState(["", "", "", "", "", ""]);
  const [activePartner, setActivePartner] = useState<"a" | "b">("a");
  const [authStep, setAuthStep] = useState<"emails" | "codes">("emails");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [deliveryStatus, setDeliveryStatus] = useState<string | null>(null);

  // Gallery & Decrypted Object URLs State
  const [decryptedMap, setDecryptedMap] = useState<Record<string, string>>({});
  const [decryptingIds, setDecryptingIds] = useState<Set<string>>(new Set());
  const [currentFolder, setCurrentFolder] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [categories, setCategories] = useState<Record<string, string>>({});
  const [activeCategory, setActiveCategory] = useState("All photos");
  const [categoryError, setCategoryError] = useState("");
  const [policyNotice, setPolicyNotice] = useState("");

  // Modals & Lightbox
  const [activeImage, setActiveImage] = useState<Img | null>(null);
  const [zoomScale, setZoomScale] = useState(1);
  const [showSecurityModal, setShowSecurityModal] = useState(false);
  const [showNewFolderModal, setShowNewFolderModal] = useState(false);
  const [newFolderName, setNewFolderName] = useState("");
  const [uploadProgress, setUploadProgress] = useState<string | null>(null);
  const categoriesRef = useRef<Record<string, string>>({});
  const categorizingIds = useRef(new Set<string>());

  // Cryptographic Key Reference
  const vaultKeyRef = useRef<CryptoKey | null>(null);

  function rememberCategories(vaultId: string, next: Record<string, string>) {
    categoriesRef.current = next;
    setCategories(next);
    try {
      localStorage.setItem(`usvault-categories:${vaultId}`, JSON.stringify(next));
    } catch (error) {
      console.warn("[Local categorization] Could not save category labels:", error);
      setCategoryError("Photo categories could not be saved in this browser. You can still use them until this page is refreshed.");
    }
  }

  // Clean up object URLs on unmount to avoid memory leaks
  useEffect(() => {
    return () => {
      Object.values(decryptedMap).forEach((url) => {
        try { URL.revokeObjectURL(url); } catch {}
      });
    };
  }, []);

  async function categorizeImage(vaultId: string, imageId: string, image: Blob) {
    if (categoriesRef.current[imageId] || categorizingIds.current.has(imageId)) return;
    categorizingIds.current.add(imageId);
    try {
      const category = await classifyPhoto(image);
      const next = { ...categoriesRef.current, [imageId]: category };
      setCategoryError("");
      rememberCategories(vaultId, next);
    } catch (error) {
      console.warn(`[Local categorization] Could not classify image ${imageId}:`, error);
      setCategoryError("On-device photo recognition could not run. The photo is still encrypted and saved; its category is unavailable.");
    } finally {
      categorizingIds.current.delete(imageId);
    }
  }

  // Decrypt individual image given the AES-256-GCM vault key
  const decryptImage = useCallback(async (img: Img, key: CryptoKey, vaultId: string) => {
    if (decryptedMap[img.id]) return decryptedMap[img.id];
    setDecryptingIds((prev) => new Set(prev).add(img.id));
    try {
      const blob = await api.ciphertextBlob(img.id);
      const plainBlob = await C.decryptBlob(blob, key, img.mimeType);
      const url = URL.createObjectURL(plainBlob);
      setDecryptedMap((prev) => ({ ...prev, [img.id]: url }));
      void categorizeImage(vaultId, img.id, plainBlob);
      return url;
    } catch (err) {
      console.warn(`[E2EE Decrypt Warning] Could not decrypt image ${img.id}:`, err);
      return null;
    } finally {
      setDecryptingIds((prev) => {
        const next = new Set(prev);
        next.delete(img.id);
        return next;
      });
    }
  }, [decryptedMap]);

  // Decrypt all images in the vault
  const decryptAllImages = useCallback(async (images: Img[], key: CryptoKey, vaultId: string) => {
    for (const img of images) {
      if (!decryptedMap[img.id]) {
        decryptImage(img, key, vaultId);
      }
    }
  }, [decryptedMap, decryptImage]);

  // Bootstrap vault authentication and deterministic key derivation
  async function bootstrap(v: VaultData) {
    if (v.separation?.status === "pending" || v.separation?.status === "deleted") {
      if (v.separation.status === "deleted") {
        localStorage.removeItem(`usvault-categories:${v.id}`);
        categoriesRef.current = {};
        setCategories({});
      }
      await C.clearVaultKey(v.id);
      vaultKeyRef.current = null;
      Object.values(decryptedMap).forEach((url) => URL.revokeObjectURL(url));
      setDecryptedMap({});
      setVault(v);
      return;
    }

    try {
      const savedCategories = JSON.parse(localStorage.getItem(`usvault-categories:${v.id}`) || "{}") as Record<string, string>;
      categoriesRef.current = savedCategories;
      setCategories(savedCategories);
    } catch (error) {
      console.warn("[Local categorization] Could not load saved categories:", error);
      categoriesRef.current = {};
      setCategories({});
    }

    let did = getDeviceId();
    let priv = did ? await C.privateKey(did) : null;

    if (!priv) {
      try {
        const kp = await C.createDevice();
        const pub = await C.exportPublic(kp);
        const ch = await api.deviceChallenge();
        const sig = await C.signChallenge(kp.sign.privateKey, ch.challenge);
        const r = await api.registerDevice({ publicKeyJwk: pub, signature: sig, challenge: ch.challenge, label: "Browser Client" });
        did = r.id;
        setDeviceId(did);
        await C.saveDevice(did, kp);
      } catch (e) {
        console.warn("[Device Registration Notice]", e);
      }
    }

    // 1. Try local cached vault key
    let vk = await C.vaultKey(v.id);

    // 2. Deterministic derivation: derive using PBKDF2 (100,000 rounds) from (emailA, emailB, vaultId)
    // Guarantees that anytime you log in with the same email pair, the same AES-256-GCM vault key
    // is derived and all saved images decrypt and show up!
    if (!vk && v.memberA?.email && v.memberB?.email) {
      try {
        vk = await C.deriveVaultKey(v.id, v.memberA.email, v.memberB.email);
        await C.saveVaultKey(v.id, vk);
      } catch (err) {
        console.warn("[Key Derivation Notice]", err);
      }
    }

    if (vk) {
      vaultKeyRef.current = vk;
      setVault(v);
      decryptAllImages(v.images, vk, v.id);
    } else {
      setVault(v);
    }
  }

  // Load vault state
  async function loadVault() {
    if (!vault) setSessionStatus("checking");
    try {
      const v = await api.vault();
      await bootstrap(v);
      setError("");
      setSessionStatus("ready");
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        setVault(null);
        setError("");
        setSessionStatus("ready");
        return;
      }

      const message = error instanceof Error ? error.message : "Unable to load the shared vault.";
      setError(message);
      if (!vault) setSessionStatus("error");
    }
  }

  useEffect(() => {
    if (privacyAccepted) loadVault();
  }, []);

  function handlePrivacyNoticeAction() {
    if (privacyAccepted) {
      setShowPrivacyNotice(false);
      return;
    }

    try {
      localStorage.setItem(PRIVACY_CONSENT_KEY, PRIVACY_CONSENT_VALUE);
      setPrivacyAccepted(true);
      setSessionStatus("checking");
      setPrivacyError("");
      void loadVault();
    } catch {
      setPrivacyError("Your browser blocked local storage. Enable site storage to save your acknowledgement and continue.");
    }
  }

  // Request dual OTP verification codes sent to both partner emails
  async function handleRequestCodes() {
    setError("");
    const a = emailA.trim().toLowerCase();
    const b = emailB.trim().toLowerCase();
    if (!a || !b) {
      setError("Please enter email addresses for both partners.");
      return;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(a) || !emailRegex.test(b)) {
      setError("Please enter valid email formats for both partners.");
      return;
    }
    if (a === b) {
      setError("Partner emails must be different.");
      return;
    }

    setBusy(true);
    try {
      // Use atomic pair request which queues both emails sequentially to prevent socket collisions
      await api.requestPairOtp(a, b);
      setDeliveryStatus(`Verification codes were sent to ${a} and ${b}. Please check both inboxes.`);
      setEmailA(a);
      setEmailB(b);
      setAuthStep("codes");
    } catch (e: any) {
      setError(e.message || "Unable to send verification codes to the specified emails.");
    } finally {
      setBusy(false);
    }
  }

  // Verify Pair & Unlock Vault
  async function handleVerifyAndUnlock() {
    setError("");
    const fullCodeA = codeA.join("");
    const fullCodeB = codeB.join("");

    if (fullCodeA.length !== 6 || fullCodeB.length !== 6) {
      setError("Both partners must enter their complete 6-digit verification code.");
      return;
    }

    setBusy(true);
    try {
      await api.verifyPair({
        emailA,
        emailB,
        codeA: fullCodeA,
        codeB: fullCodeB,
        activeEmail: activePartner === "a" ? emailA : emailB
      });
      const v = await api.vault();
      await bootstrap(v);
    } catch (e: any) {
      console.error("Verification/Unlock error:", e);
      setError(e.message || "Invalid or expired verification codes. Please check your emails.");
    } finally {
      setBusy(false);
    }
  }

  // Upload private photo with live client-side AES-256-GCM encryption
  async function handleUploadFiles(files: FileList | null) {
    const vaultKey = vaultKeyRef.current;
    if (!files || !files.length || !vaultKey || !vault) return;
    setBusy(true);
    setError("");

    try {
      for (const file of Array.from(files)) {
        let category = "Uncategorized";
        setUploadProgress(`Recognizing photo category on this device…`);
        try {
          category = await classifyPhoto(file);
          setCategoryError("");
        } catch (error) {
          console.warn("[Local categorization] Could not classify uploaded photo:", error);
          setCategoryError("On-device photo recognition could not run. The photo will still be encrypted and saved without a category.");
        }

        setUploadProgress(`Encrypting ${file.name} with 256-bit AES-GCM on this device…`);
        const encryptedBlob = await C.encryptFile(file, vaultKey);

        setUploadProgress(`Storing ciphertext securely in Cloud Vault…`);
        const uploadedImg = await api.upload(encryptedBlob, file.name, file.type, currentFolder);
        const nextCategories = { ...categoriesRef.current, [uploadedImg.id]: category };
        rememberCategories(vault.id, nextCategories);

        // Immediately decrypt and display in UI
        const plainBlob = await C.decryptBlob(encryptedBlob, vaultKey, file.type);
        const url = URL.createObjectURL(plainBlob);
        setDecryptedMap((prev) => ({ ...prev, [uploadedImg.id]: url }));
      }
      setUploadProgress(null);
      await loadVault();
    } catch (e: any) {
      setError(e.message || "Failed to encrypt or upload image.");
    } finally {
      setBusy(false);
      setUploadProgress(null);
    }
  }

  async function handleBlockedExport() {
    try {
      const result = await api.reportSharingAttempt();
      setPolicyNotice(result.message);
    } catch (error) {
      setError(error instanceof Error ? error.message : "The export was blocked, but partner notifications failed.");
    }
  }

  async function handleSeparation(action: "request" | "restore" | "delete") {
    const promptText = action === "request"
      ? "Freeze both partners' vault access now? Both will receive an email and must agree on restoring access or permanently deleting the shared photos."
      : action === "delete"
        ? "Propose permanent deletion of every encrypted photo and folder? The other partner must confirm before anything is removed."
        : "Propose restoring shared vault access? The other partner must confirm before access is restored.";
    if (!confirm(promptText)) return;

    setBusy(true);
    setError("");
    setPolicyNotice("");
    try {
      await api.separation(action);
      await loadVault();
    } catch (error) {
      setError(error instanceof Error ? error.message : "The separation protocol could not be completed.");
      await loadVault();
    } finally {
      setBusy(false);
    }
  }

  // Delete image
  async function handleDeleteImage(id: string) {
    if (confirm("Permanently delete this encrypted memory from Cloud Vault?")) {
      try {
        await api.remove(id);
        const nextCategories = { ...categoriesRef.current };
        delete nextCategories[id];
        if (vault) rememberCategories(vault.id, nextCategories);
        setDecryptedMap((prev) => {
          const next = { ...prev };
          if (next[id]) {
            URL.revokeObjectURL(next[id]);
            delete next[id];
          }
          return next;
        });
        if (activeImage?.id === id) setActiveImage(null);
        await loadVault();
      } catch (e: any) {
        setError(e.message || "Failed to delete photo.");
      }
    }
  }

  // Create folder
  async function handleCreateFolder() {
    if (!newFolderName.trim()) return;
    try {
      await api.createFolder(newFolderName.trim(), currentFolder);
      setNewFolderName("");
      setShowNewFolderModal(false);
      await loadVault();
    } catch (e: any) {
      setError(e.message || "Failed to create folder.");
    }
  }

  // Rename vault
  async function handleRenameVault() {
    const currentName = vault?.name || "Our Vault";
    const newName = prompt("Rename your private vault:", currentName);
    if (newName && newName.trim() && newName !== currentName) {
      try {
        await api.renameVault(newName.trim());
        await loadVault();
      } catch (e: any) {
        setError(e.message || "Failed to rename vault.");
      }
    }
  }

  // Logout and wipe session keys
  async function handleLogout() {
    let logoutError = "";
    try {
      await api.logout();
    } catch (error) {
      logoutError = error instanceof Error
        ? `Signed out locally, but server logout failed: ${error.message}`
        : "Signed out locally, but server logout failed.";
    }

    if (vault?.id) {
      try {
        await C.clearVaultKey(vault.id);
      } catch (error) {
        logoutError = logoutError
          ? `${logoutError} The cached vault key could not be cleared.`
          : error instanceof Error
            ? `Signed out, but the cached vault key could not be cleared: ${error.message}`
            : "Signed out, but the cached vault key could not be cleared.";
      }
    }
    Object.values(decryptedMap).forEach((url) => {
      try { URL.revokeObjectURL(url); } catch {}
    });
    setDecryptedMap({});
    vaultKeyRef.current = null;
    setVault(null);
    setSessionStatus("ready");
    setAuthStep("emails");
    setCodeA(["", "", "", "", "", ""]);
    setCodeB(["", "", "", "", "", ""]);
    setDeliveryStatus(null);
    setError(logoutError);
  }

  // ---------------- AUTHENTICATION VIEW ----------------
  if (!vault) {
    if (sessionStatus === "checking") {
      return (
        <main className="auth-wrapper">
          <section className="auth-card" role="status" aria-live="polite">
            <div className="brand-row">
              <div className="brand">
                <div className="brand-logo-icon"><Heart size={18} fill="currentColor" /></div>
                <span>UsVault</span>
              </div>
              <div className="security-badge"><Lock size={13} /> Restoring secure session</div>
            </div>
            <h1 className="auth-title">Opening your vault…</h1>
            <p className="auth-subtitle">Checking your secure session. This may take a moment.</p>
          </section>
        </main>
      );
    }

    if (sessionStatus === "error") {
      return (
        <main className="auth-wrapper">
          <section className="auth-card" role="alert">
            <div className="brand-row">
              <div className="brand">
                <div className="brand-logo-icon"><Heart size={18} fill="currentColor" /></div>
                <span>UsVault</span>
              </div>
              <div className="security-badge"><AlertCircle size={13} /> Connection problem</div>
            </div>
            <h1 className="auth-title">Your vault could not be restored</h1>
            <p className="auth-subtitle">{error || "Check your connection and try again. Your session has not been signed out."}</p>
            <button className="btn-primary" onClick={() => void loadVault()}>
              <RefreshCw size={16} /> Retry
            </button>
          </section>
        </main>
      );
    }

    return (
      <div className="auth-wrapper">
        <motion.div
          className="auth-card"
          initial={{ opacity: 0, scale: 0.96, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          transition={{ duration: 0.4 }}
        >
          <div className="brand-row">
            <div className="brand">
              <div className="brand-logo-icon">
                <Heart size={18} fill="currentColor" />
              </div>
              <span>UsVault</span>
            </div>
            <div className="security-badge">
              <ShieldCheck size={13} /> Two-person verification
            </div>
          </div>

          <h1 className="auth-title">A private space for two</h1>
          <p className="auth-subtitle">
            A private place for two people to keep shared memories. Both partners verify their email before opening the same vault.
          </p>

          {authStep === "emails" ? (
            <div>
              <div className="partner-chamber">
                {/* Partner 1 Email Box */}
                <div className="partner-box">
                  <div className="partner-header">
                    <span className="partner-tag">
                      <Users size={14} /> Partner one
                    </span>
                  </div>
                  <div className="input-group">
                    <Mail size={16} className="input-icon" />
                    <input
                      className="input-field"
                      type="email"
                      autoComplete="email"
                      aria-label="Partner one's email address"
                      placeholder="name@example.com"
                      value={emailA}
                      onChange={(e) => setEmailA(e.target.value)}
                    />
                  </div>
                </div>

                {/* Central Interlock Line */}
                <div className="interlock-bridge">
                  <div className="interlock-line" />
                  <div className="interlock-icon">
                    <Lock size={13} />
                  </div>
                  <div className="interlock-line" />
                </div>

                {/* Partner 2 Email Box */}
                <div className="partner-box">
                  <div className="partner-header">
                    <span className="partner-tag">
                      <Users size={14} /> Partner two
                    </span>
                  </div>
                  <div className="input-group">
                    <Mail size={16} className="input-icon" />
                    <input
                      className="input-field"
                      type="email"
                      autoComplete="email"
                      aria-label="Partner two's email address"
                      placeholder="name@example.com"
                      value={emailB}
                      onChange={(e) => setEmailB(e.target.value)}
                    />
                  </div>
                </div>
              </div>

              <button className="btn-primary" disabled={busy} onClick={handleRequestCodes}>
                <Mail size={16} />
                {busy ? "Sending verification codes…" : "Send verification codes"}
              </button>
            </div>
          ) : (
            <div>
              {/* Delivery notification banner */}
              {deliveryStatus && (
                <div
                  style={{
                    background: "rgba(16, 185, 129, 0.12)",
                    border: "1px solid rgba(16, 185, 129, 0.3)",
                    borderRadius: "12px",
                    padding: "12px 16px",
                    marginBottom: "20px",
                    fontSize: "13px",
                    color: "#6ee7b7",
                    display: "flex",
                    alignItems: "center",
                    gap: "8px"
                  }}
                >
                  <CheckCircle2 size={16} />
                  <span>{deliveryStatus}</span>
                </div>
              )}

              {/* Active User Toggle */}
              <div className="active-partner-toggle">
                <button
                  className={`toggle-btn ${activePartner === "a" ? "active" : ""}`}
                  onClick={() => setActivePartner("a")}
                >
                  <Users size={14} /> Partner one ({emailA.split("@")[0]})
                </button>
                <button
                  className={`toggle-btn ${activePartner === "b" ? "active" : ""}`}
                  onClick={() => setActivePartner("b")}
                >
                  <Users size={14} /> Partner two ({emailB.split("@")[0]})
                </button>
              </div>

              <div className="partner-chamber">
                {/* Partner 1 OTP Digits */}
                <div className="partner-box">
                  <div className="partner-header">
                    <span className="partner-tag">Partner one verification code</span>
                  </div>
                  <div className="otp-container">
                    {codeA.map((digit, idx) => (
                      <input
                        key={`a-${idx}`}
                        id={`otp-a-${idx}`}
                        className="otp-digit"
                        aria-label={`Partner one verification code digit ${idx + 1}`}
                        maxLength={1}
                        inputMode="numeric"
                        value={digit}
                        onChange={(e) => {
                          const val = e.target.value.replace(/\D/g, "");
                          const next = [...codeA];
                          next[idx] = val;
                          setCodeA(next);
                          if (val && idx < 5) {
                            document.getElementById(`otp-a-${idx + 1}`)?.focus();
                          }
                        }}
                        onKeyDown={(e) => {
                          if (e.key === "Backspace" && !codeA[idx] && idx > 0) {
                            document.getElementById(`otp-a-${idx - 1}`)?.focus();
                          }
                        }}
                        onPaste={(e) => {
                          e.preventDefault();
                          const pasted = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
                          if (pasted.length === 6) {
                            setCodeA(pasted.split(""));
                          }
                        }}
                      />
                    ))}
                  </div>
                </div>

                {/* Partner 2 OTP Digits */}
                <div className="partner-box">
                  <div className="partner-header">
                    <span className="partner-tag">Partner two verification code</span>
                  </div>
                  <div className="otp-container">
                    {codeB.map((digit, idx) => (
                      <input
                        key={`b-${idx}`}
                        id={`otp-b-${idx}`}
                        className="otp-digit"
                        aria-label={`Partner two verification code digit ${idx + 1}`}
                        maxLength={1}
                        inputMode="numeric"
                        value={digit}
                        onChange={(e) => {
                          const val = e.target.value.replace(/\D/g, "");
                          const next = [...codeB];
                          next[idx] = val;
                          setCodeB(next);
                          if (val && idx < 5) {
                            document.getElementById(`otp-b-${idx + 1}`)?.focus();
                          }
                        }}
                        onKeyDown={(e) => {
                          if (e.key === "Backspace" && !codeB[idx] && idx > 0) {
                            document.getElementById(`otp-b-${idx - 1}`)?.focus();
                          }
                        }}
                        onPaste={(e) => {
                          e.preventDefault();
                          const pasted = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
                          if (pasted.length === 6) {
                            setCodeB(pasted.split(""));
                          }
                        }}
                      />
                    ))}
                  </div>
                </div>
              </div>

              <button className="btn-primary" disabled={busy} onClick={handleVerifyAndUnlock}>
                <Lock size={16} />
                {busy ? "Verifying both codes…" : "Verify both codes and open vault"}
              </button>

              <button className="btn-ghost" onClick={() => setAuthStep("emails")}>
                Edit email addresses
              </button>

              <div className="auth-resend">
                <button
                  onClick={handleRequestCodes}
                >
                  Didn't receive a code? Resend both
                </button>
              </div>
            </div>
          )}

          {error && (
            <div className="error-banner">
              <AlertCircle size={18} />
              <span>{error}</span>
            </div>
          )}

          <div className="auth-privacy-footer">
            <span>We use your email addresses for verification and vault access.</span>
            <button type="button" className="text-button" onClick={() => setShowPrivacyNotice(true)}>
              Privacy notice
            </button>
          </div>
        </motion.div>

        {(!privacyAccepted || showPrivacyNotice) && (
          <div className="privacy-overlay" role="dialog" aria-modal="true" aria-labelledby="privacy-title">
            <section className="privacy-dialog">
              <div className="privacy-heading">
                <div className="privacy-icon"><ShieldCheck size={20} /></div>
                <div>
                  <div className="privacy-eyebrow">Privacy &amp; data use</div>
                  <h2 id="privacy-title">Before you continue</h2>
                </div>
              </div>

              <div className="privacy-copy">
                <p>
                  UsVault uses both partners' email addresses for vault access and one-time verification codes. It also processes account,
                  vault, session, and device details needed to operate the app. Configured hosting, database, storage, and email providers may
                  process this information on the service's behalf.
                </p>
                <p>
                  Photo files are encrypted in your browser before upload. File names, file types, sizes, folder details, and timestamps may
                  still be visible to the service; the uploaded file contents are stored as encrypted data.
                </p>
                <p>
                  Smart photo categories are detected on this device. The first use may download an image-recognition model from Google, but
                  your photo is not sent to an AI service for classification. In-app exports are blocked and export attempts notify both partners.
                </p>
                <p className="privacy-warning">
                  <strong>Important:</strong> This is an early-access MVP, not an independently audited security product. Its current
                  encryption key is derived partly from partner email addresses, which are not secret. Photos displayed in a browser can still
                  be captured or copied outside the app. Do not store highly sensitive files here.
                </p>
                <p className="privacy-disclaimer">
                  Your acknowledgement is saved in this browser only. This short notice summarizes the MVP and is not a substitute for a complete, legally reviewed privacy policy.
                </p>
              </div>

              {!privacyAccepted && (
                <label className="privacy-checkbox">
                  <input
                    type="checkbox"
                    checked={privacyAcknowledged}
                    onChange={(event) => setPrivacyAcknowledged(event.target.checked)}
                  />
                  <span>I have read and understand this privacy notice.</span>
                </label>
              )}

              {privacyError && <p className="privacy-error" role="alert">{privacyError}</p>}

              <div className="privacy-actions">
                <button
                  type="button"
                  className="btn-primary"
                  disabled={!privacyAccepted && !privacyAcknowledged}
                  onClick={handlePrivacyNoticeAction}
                >
                  {privacyAccepted ? "Close notice" : "Agree and continue"}
                </button>
              </div>
              {!privacyAccepted && <p className="privacy-exit-note">If you do not agree, please close this page.</p>}
            </section>
          </div>
        )}
      </div>
    );
  }

  if (vault.separation?.status === "pending" || vault.separation?.status === "deleted") {
    const separation = vault.separation;
    const isDeleted = separation.status === "deleted";
    const isProposer = separation.proposedBy === vault.currentUserId;
    const pendingDecision = separation.decision;

    return (
      <main className="separation-page">
        <header className="separation-brand">
          <div className="brand">
            <div className="brand-logo-icon"><Heart size={18} fill="currentColor" /></div>
            <span>UsVault</span>
          </div>
          <button className="btn-ghost separation-logout" onClick={handleLogout}>
            <LogOut size={15} /> Sign out
          </button>
        </header>

        <section className="separation-card" aria-labelledby="separation-title">
          <div className="separation-icon"><ShieldAlert size={24} /></div>
          <p className="vault-eyebrow">Shared vault protocol</p>
          <h1 id="separation-title">{isDeleted ? "Vault data deleted" : "Vault access is frozen"}</h1>
          <p className="separation-copy">
            {isDeleted
              ? "Both members confirmed permanent deletion. Photos and folders have been removed from the shared vault."
              : "A partner started a separation review. Uploads and photo access are paused while both members agree on the next step."}
          </p>

          {!isDeleted && (
            <div className="separation-details">
              <p>Started {new Date(separation.requestedAt).toLocaleString()}</p>
              <p>
                {pendingDecision
                  ? `Pending decision: ${pendingDecision === "restore" ? "restore access" : "permanently delete photos"}.`
                  : "No outcome has been proposed yet."}
              </p>
              {pendingDecision && (
                <p>
                  {isProposer
                    ? "Your proposal is waiting for the other partner to confirm."
                    : "Choose the same outcome below to confirm your partner's proposal."}
                </p>
              )}
              <p>Photos already downloaded, copied, or captured outside UsVault cannot be recalled.</p>
            </div>
          )}

          {!isDeleted && (!pendingDecision || isProposer) && (
            <div className="separation-actions">
              <button className="btn-primary" disabled={busy} onClick={() => handleSeparation("restore")}>
                Restore access
              </button>
              <button className="btn-danger" disabled={busy} onClick={() => handleSeparation("delete")}>
                Propose permanent deletion
              </button>
              {pendingDecision && <p className="separation-hint">You can change your proposal; your partner must confirm the same outcome.</p>}
            </div>
          )}

          {!isDeleted && pendingDecision && !isProposer && (
            <div className="separation-actions">
              <button className="btn-primary" disabled={busy} onClick={() => handleSeparation(pendingDecision)}>
                Confirm {pendingDecision === "restore" ? "restore access" : "permanent deletion"}
              </button>
              <p className="separation-hint">Only the same choice from both partners will take effect.</p>
            </div>
          )}

          {error && <div className="error-banner" role="alert"><AlertCircle size={18} /><span>{error}</span></div>}
        </section>
      </main>
    );
  }

  // ---------------- AUTHENTICATED VAULT DASHBOARD ----------------
  const folders = vault.folders || [];
  const availableCategories = ["All photos", ...new Set(Object.values(categories))];
  const filteredImages = (vault.images || [])
    .filter((img) => (currentFolder ? img.folderId === currentFolder : true))
    .filter((img) => activeCategory === "All photos" || categories[img.id] === activeCategory)
    .filter((img) => searchQuery
      ? `${img.originalName} ${categories[img.id] || ""}`.toLowerCase().includes(searchQuery.toLowerCase())
      : true);

  const totalBytes = (vault.images || []).reduce((acc, curr) => acc + curr.size, 0);
  const formattedStorage =
    totalBytes > 1024 * 1024
      ? `${(totalBytes / (1024 * 1024)).toFixed(1)} MB`
      : `${Math.round(totalBytes / 1024)} KB`;

  return (
    <div className="app-container">
      {/* Top Navigation Bar */}
      <header className="app-navbar">
        <div className="nav-left">
          <div className="brand">
            <div className="brand-logo-icon">
              <Heart size={18} fill="currentColor" />
            </div>
            <span>UsVault</span>
          </div>

          <div className="nav-badges">
            <div className="security-badge">
              <ShieldCheck size={13} /> Browser-encrypted photos
            </div>
            <div className="cloud-pill">
              <Cloud size={13} /> {vault.cloudStatus?.provider || "Vault storage"}
            </div>
            <div className="partners-pill">
              <Users size={13} />
              <span>
                {vault.memberA?.email.split("@")[0]} & {vault.memberB?.email.split("@")[0]}
              </span>
            </div>
          </div>
        </div>

        <div className="nav-actions">
          <button
            className="nav-icon-btn"
            title="Cloud & Cryptographic Security Info"
            onClick={() => setShowSecurityModal(true)}
          >
            <Shield size={17} />
          </button>
          <button className="nav-icon-btn" title="Refresh Vault" onClick={loadVault}>
            <RefreshCw size={17} />
          </button>
          <button className="nav-icon-btn" title="Lock & Logout" onClick={handleLogout}>
            <LogOut size={17} />
          </button>
        </div>
      </header>

      {/* Vault Hero & Actions */}
      <section className="vault-hero">
        <div className="vault-title-group">
          <div className="vault-eyebrow">
            <Lock size={12} /> Browser-encrypted shared vault
          </div>
          <h2 className="vault-heading">
            <span>{vault.name}</span>
            <button className="vault-rename-btn" title="Rename Vault" onClick={handleRenameVault}>
              <Edit3 size={18} />
            </button>
          </h2>
          <p className="vault-desc">
            A shared space for two verified members. Photos are encrypted before upload; smart categories are generated on this device.
          </p>
        </div>

        <div className="hero-actions">
          <label className="btn-upload">
            <Upload size={17} />
            <span>{busy ? "Encrypting…" : "Upload Private Photo"}</span>
            <input
              hidden
              type="file"
              accept="image/*"
              multiple
              onChange={(e) => {
                void handleUploadFiles(e.currentTarget.files);
                e.currentTarget.value = "";
              }}
            />
          </label>

          <button className="btn-folder" onClick={() => setShowNewFolderModal(true)}>
            <FolderPlus size={17} />
            <span>New Folder</span>
          </button>
        </div>
      </section>

      {/* Upload Progress Banner */}
      {uploadProgress && (
        <div className="status-banner">
          <Sparkles size={16} />
          <span>{uploadProgress}</span>
        </div>
      )}
      {categoryError && <div className="notice-banner" role="status">{categoryError}</div>}
      {policyNotice && <div className="success-banner" role="status">{policyNotice}</div>}
      {error && <div className="error-banner dashboard-error" role="alert"><AlertCircle size={18} /><span>{error}</span></div>}

      {/* Security & Cloud Metrics Ribbon */}
      <section className="stats-ribbon">
        <div className="stat-card">
          <div className="stat-icon">
            <Heart size={20} />
          </div>
          <div>
            <div className="stat-label">Shared photos</div>
            <div className="stat-value">{vault.images?.length || 0} memories</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon cyan">
            <HardDrive size={20} />
          </div>
          <div>
            <div className="stat-label">Encrypted storage</div>
            <div className="stat-value">{formattedStorage}</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon emerald">
            <ShieldCheck size={20} />
          </div>
          <div>
            <div className="stat-label">Photo encryption</div>
            <div className="stat-value">AES-256-GCM</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon gold">
            <Users size={20} />
          </div>
          <div>
            <div className="stat-label">Shared access</div>
            <div className="stat-value">2-of-2 Verified</div>
          </div>
        </div>
      </section>

      {/* Folder Navigation & Search */}
      <section className="filter-bar">
        <div className="folder-pills">
          <button
            className={`folder-pill ${currentFolder === null ? "active" : ""}`}
            onClick={() => setCurrentFolder(null)}
          >
            <FolderIcon size={14} /> All Memories ({vault.images?.length || 0})
          </button>
          {folders.map((f) => (
            <button
              key={f.id}
              className={`folder-pill ${currentFolder === f.id ? "active" : ""}`}
              onClick={() => setCurrentFolder(f.id)}
            >
              <FolderIcon size={14} /> {f.name}
            </button>
          ))}
        </div>

        <div className="search-box">
          <Search size={16} className="search-icon" />
          <input
            className="search-input"
            type="text"
            placeholder="Search photos or categories…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </section>

      <section className="category-bar" aria-label="Smart photo categories">
        <div className="category-heading">
          <div>
            <h3>Smart categories</h3>
            <p>Suggested privately on this device. You can filter by the detected scene.</p>
          </div>
          <Sparkles size={18} />
        </div>
        <div className="folder-pills">
          {availableCategories.map((category) => (
            <button
              key={category}
              className={`folder-pill ${activeCategory === category ? "active" : ""}`}
              onClick={() => setActiveCategory(category)}
            >
              {category === "All photos" ? `All photos (${vault.images.length})` : category}
            </button>
          ))}
        </div>
      </section>

      {/* Decrypted Photo Gallery Grid */}
      {filteredImages.length > 0 ? (
        <section className="photo-grid">
          {filteredImages.map((img) => {
            const decryptedUrl = decryptedMap[img.id];
            const isDecrypting = decryptingIds.has(img.id);

            return (
              <motion.article
                layout
                key={img.id}
                className="photo-card"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.25 }}
              >
                <div
                  className="photo-thumb-container"
                  onClick={() => {
                    if (decryptedUrl) {
                      setActiveImage(img);
                      setZoomScale(1);
                    }
                  }}
                >
                  {decryptedUrl ? (
                    <img className="photo-img" src={decryptedUrl} alt={img.originalName} />
                  ) : isDecrypting ? (
                    <div className="shimmer-skeleton">
                      <Lock size={20} />
                      <span>Decrypting on device…</span>
                    </div>
                  ) : (
                    <div
                      className="shimmer-skeleton"
                      onClick={() => vaultKeyRef.current && decryptImage(img, vaultKeyRef.current, vault.id)}
                    >
                      <Lock size={20} />
                      <span>Click to Decrypt</span>
                    </div>
                  )}

                  {/* Hover Quick Actions */}
                  {decryptedUrl && (
                    <div className="card-overlay-actions" onClick={(e) => e.stopPropagation()}>
                      <button
                        className="quick-action-btn"
                        title="View Fullscreen"
                        onClick={() => {
                          setActiveImage(img);
                          setZoomScale(1);
                        }}
                      >
                        <Eye size={15} />
                      </button>
                      <button
                        className="quick-action-btn"
                        title="Export blocked; notify both partners"
                        aria-label="Attempt blocked export and notify both partners"
                        onClick={() => handleBlockedExport()}
                      >
                        <ShieldAlert size={15} />
                      </button>
                      <button
                        className="quick-action-btn delete"
                        title="Delete from Vault"
                        onClick={() => handleDeleteImage(img.id)}
                      >
                        <Trash2 size={15} />
                      </button>
                    </div>
                  )}
                </div>

                <div className="photo-footer">
                  <div className="photo-name-meta">
                    <div className="photo-name" title={img.originalName}>
                      {img.originalName}
                    </div>
                    <div className="photo-meta">
                      <span className="mime-tag">{img.mimeType.split("/")[1] || "IMG"}</span>
                      {categories[img.id] && <span className="category-tag">{categories[img.id]}</span>}
                      <span>•</span>
                      <span>
                        {img.size > 1024 * 1024
                          ? `${(img.size / (1024 * 1024)).toFixed(1)} MB`
                          : `${Math.round(img.size / 1024)} KB`}
                      </span>
                    </div>
                  </div>
                </div>
              </motion.article>
            );
          })}
        </section>
      ) : (
        <div className="empty-gallery">
          <div className="empty-icon">
            <Heart size={30} fill="currentColor" />
          </div>
          <h3>{vault.images.length ? "No photos match these filters" : "Your shared vault is ready"}</h3>
          <p>
            {vault.images.length
              ? "Try another folder, category, or search term."
              : "Add a memory to encrypt it in this browser. Smart categories are detected locally and are not sent to UsVault."}
          </p>
          <label className="btn-upload" style={{ marginTop: "10px" }}>
            <Upload size={17} />
            <span>Upload First Memory</span>
            <input
              hidden
              type="file"
              accept="image/*"
              multiple
              onChange={(e) => {
                void handleUploadFiles(e.currentTarget.files);
                e.currentTarget.value = "";
              }}
            />
          </label>
        </div>
      )}

      {/* FULLSCREEN LIGHTBOX & CRYPTOGRAPHIC INSPECTOR */}
      <AnimatePresence>
        {activeImage && (
          <motion.div
            className="lightbox-backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <div className="lightbox-topbar">
              <div className="lightbox-title">
                <ShieldCheck size={18} color="var(--accent-emerald)" />
                <span>{activeImage.originalName}</span>
                <span className="security-badge" style={{ fontSize: "10px" }}>
                  Client Decrypted
                </span>
              </div>

              <div className="lightbox-actions">
                <button
                  className="nav-icon-btn"
                  title="Zoom In"
                  onClick={() => setZoomScale((s) => Math.min(s + 0.25, 3))}
                >
                  <ZoomIn size={16} />
                </button>
                <button
                  className="nav-icon-btn"
                  title="Zoom Out"
                  onClick={() => setZoomScale((s) => Math.max(s - 0.25, 0.5))}
                >
                  <ZoomOut size={16} />
                </button>
                <button
                  className="nav-icon-btn"
                  title="Export blocked; notify both partners"
                  aria-label="Attempt blocked export and notify both partners"
                  onClick={handleBlockedExport}
                >
                  <ShieldAlert size={16} />
                </button>
                <button
                  className="nav-icon-btn"
                  title="Close Lightbox"
                  onClick={() => setActiveImage(null)}
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            <div className="lightbox-body">
              <div className="lightbox-stage" onClick={() => setActiveImage(null)}>
                {decryptedMap[activeImage.id] ? (
                  <img
                    className="lightbox-img"
                    src={decryptedMap[activeImage.id]}
                    alt={activeImage.originalName}
                    style={{ transform: `scale(${zoomScale})` }}
                    onClick={(e) => e.stopPropagation()}
                  />
                ) : (
                  <div className="shimmer-skeleton" style={{ width: "300px", height: "300px" }}>
                    <Lock size={30} />
                    <span>Decrypting…</span>
                  </div>
                )}
              </div>

              {/* Cryptographic Inspector Drawer */}
              <aside className="crypto-inspector">
                <div>
                  <div className="inspector-section-title">
                    <Shield size={14} /> Cryptographic Proof
                  </div>
                  <div className="inspector-field">
                    <div className="field-label">Encryption Algorithm</div>
                    <div className="field-value">AES-256-GCM (Authenticated)</div>
                  </div>
                  <div className="inspector-field">
                    <div className="field-label">Initialization Vector (IV)</div>
                    <div className="field-value">96-bit Random Nonce</div>
                  </div>
                  <div className="inspector-field">
                    <div className="field-label">Ciphertext Size</div>
                    <div className="field-value">{activeImage.size} bytes</div>
                  </div>
                  <div className="inspector-field">
                    <div className="field-label">Additional storage encryption</div>
                    <div className="field-value">
                      {vault.cloudStatus?.encryptedAtRest ? "AWS KMS at rest" : "Not configured; photo contents are browser-encrypted"}
                    </div>
                  </div>
                </div>

                <div>
                  <div className="inspector-section-title">
                    <Users size={14} /> Dual-Custody Verification
                  </div>
                  <div className="inspector-field">
                    <div className="field-label">Partner A Approved</div>
                    <div className="field-value">{vault.memberA?.email}</div>
                  </div>
                  <div className="inspector-field">
                    <div className="field-label">Partner B Approved</div>
                    <div className="field-value">{vault.memberB?.email}</div>
                  </div>
                  <div className="inspector-field">
                    <div className="field-label">Vault ID</div>
                    <div className="field-value">{vault.id}</div>
                  </div>
                </div>
              </aside>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <section className="policy-panel">
        <div className="policy-panel-copy">
          <div className="inspector-section-title"><ShieldCheck size={15} /> Shared privacy controls</div>
          <h3>Keep this space between the two of you</h3>
          <p>
            UsVault has no public share links. In-app photo exports are blocked; selecting the export control notifies both partners by email.
            This cannot prevent screenshots, browser inspection, or copies made outside the app.
          </p>
        </div>
        <button className="btn-danger" disabled={busy} onClick={() => handleSeparation("request")}>
          <Lock size={15} /> Start separation protocol
        </button>
      </section>

      {/* New Folder Modal */}
      {showNewFolderModal && (
        <div className="modal-overlay" onClick={() => setShowNewFolderModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 style={{ fontSize: "18px" }}>Create New Folder</h3>
              <button className="nav-icon-btn" onClick={() => setShowNewFolderModal(false)}>
                <X size={16} />
              </button>
            </div>
            <div className="input-group" style={{ marginBottom: "20px" }}>
              <FolderIcon size={16} className="input-icon" />
              <input
                className="input-field"
                type="text"
                placeholder="Folder name (e.g. Vacation 2026, Anniversary)"
                value={newFolderName}
                onChange={(e) => setNewFolderName(e.target.value)}
                autoFocus
                onKeyDown={(e) => e.key === "Enter" && handleCreateFolder()}
              />
            </div>
            <button className="btn-primary" onClick={handleCreateFolder}>
              Create Folder
            </button>
          </div>
        </div>
      )}

      {/* Cloud & Security Modal */}
      {showSecurityModal && (
        <div className="modal-overlay" onClick={() => setShowSecurityModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <ShieldCheck size={20} color="var(--accent-emerald)" />
                <h3 style={{ fontSize: "18px" }}>Cloud & Security Architecture</h3>
              </div>
              <button className="nav-icon-btn" onClick={() => setShowSecurityModal(false)}>
                <X size={16} />
              </button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "12px", marginBottom: "20px" }}>
              <div className="inspector-field">
                <div className="field-label">File encryption</div>
                <div className="field-value">
                  Photo contents are encrypted in your browser before upload. File names and related metadata may remain visible to the service.
                </div>
              </div>
              <div className="inspector-field">
                <div className="field-label">Cloud Storage Engine</div>
                <div className="field-value">
                  {vault.cloudStatus?.provider || "Local file storage"} (browser-encrypted photo contents)
                </div>
              </div>
              <div className="inspector-field">
                <div className="field-label">Dual-Party Custody System</div>
                <div className="field-value">
                  Both partner email addresses must approve with their OTP to access this vault.
                </div>
              </div>
              <div className="inspector-field">
                <div className="field-label">Deterministic Key Custody</div>
                <div className="field-value">
                  The current MVP derives the vault key partly from both partner email addresses. Email addresses are not secret, and a browser can capture displayed photos, so this is not suitable for highly sensitive files.
                </div>
              </div>
              <div className="inspector-field">
                <div className="field-label">Photo categories</div>
                <div className="field-value">
                  Image recognition runs in this browser. The photo itself is not uploaded to an AI provider; category labels stay on this device.
                </div>
              </div>
            </div>

            <button className="btn-primary" onClick={() => setShowSecurityModal(false)}>
              Got it
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
