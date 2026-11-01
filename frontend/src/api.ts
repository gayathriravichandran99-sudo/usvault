const API = (import.meta.env.VITE_API_URL || "http://localhost:8080").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = "ApiError";
  }
}

async function request(path: string, init?: RequestInit) {
  const r = await fetch(`${API}${path}`, {
    ...init,
    credentials: "include"
  });
  const d = r.status === 204 ? null : await r.json().catch(() => null);
  if (!r.ok) {
    throw new ApiError(d?.error || d?.message || `Request failed with status ${r.status}`, r.status);
  }
  return d;
}

export const api = {
  requestOtp: (email: string) =>
    request("/auth/request-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email })
    }),

  requestPairOtp: (emailA: string, emailB: string) =>
    request("/auth/request-pair-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ emailA, emailB })
    }),

  verifyPair: (body: {
    emailA: string;
    emailB: string;
    codeA: string;
    codeB: string;
    activeEmail: string;
  }) =>
    request("/auth/verify-pair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }),

  logout: () => request("/auth/logout", { method: "POST" }),

  vault: () => request("/vault"),

  renameVault: (name: string) =>
    request("/vault/rename", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name })
    }),

  cloudStatus: () => request("/cloud/status"),

  reportSharingAttempt: () =>
    request("/vault/sharing-attempt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    }),

  separation: (action: "request" | "restore" | "delete") =>
    request("/vault/separation", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action })
    }),

  deviceChallenge: () => request("/crypto/device-key/challenge", { method: "POST" }),

  registerDevice: (body: any) =>
    request("/crypto/device-key", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }),

  saveEnvelope: (deviceKeyId: string, wrappedVaultKey: string, version: number) =>
    request("/crypto/envelope", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ deviceKeyId, wrappedVaultKey, version })
    }),

  upload: (blob: Blob, name: string, mime: string, folderId: string | null) => {
    const fd = new FormData();
    fd.append("image", new File([blob], name, { type: "application/octet-stream" }));
    fd.append("mimeType", mime);
    if (folderId) fd.append("folderId", folderId);
    return request("/images", { method: "POST", body: fd });
  },

  ciphertextBlob: async (id: string): Promise<Blob> => {
    const r = await fetch(`${API}/images/${id}/ciphertext`, {
      credentials: "include"
    });
    if (!r.ok) throw new Error("Unable to fetch encrypted photo from cloud vault");
    return await r.blob();
  },

  move: (id: string, folderId: string | null) =>
    request(`/images/${id}/move`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ folderId })
    }),

  remove: (id: string) => request(`/images/${id}`, { method: "DELETE" }),

  createFolder: (name: string, parentId: string | null) =>
    request("/folders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, parentId })
    })
};
