// CipherChat E2EE — Web Crypto API (RSA-OAEP + AES-GCM)

const DB_NAME = "cipherchat-keys";
const STORE = "keystore";
const DB_VERSION = 1;

// ── IndexedDB helpers ──────────────────────────────────────────────────────
async function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function savePrivateKey(username: string, key: CryptoKey): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    const req = tx.objectStore(STORE).put(key, `${username}:private`);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function loadPrivateKey(username: string): Promise<CryptoKey | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(`${username}:private`);
    req.onsuccess = () => resolve((req.result as CryptoKey) ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function savePublicKey(username: string, key: CryptoKey): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    const req = tx.objectStore(STORE).put(key, `${username}:public`);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function loadPublicKey(username: string): Promise<CryptoKey | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(`${username}:public`);
    req.onsuccess = () => resolve((req.result as CryptoKey) ?? null);
    req.onerror = () => reject(req.error);
  });
}

// ── Base64 helpers ─────────────────────────────────────────────────────────
export function bufToB64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

export function b64ToBuf(b64: string): ArrayBuffer {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer as ArrayBuffer;
}

// ── RSA key management ─────────────────────────────────────────────────────
const RSA_PARAMS: RsaHashedKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(RSA_PARAMS, true, ["encrypt", "decrypt"]);
}

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const buf = await crypto.subtle.exportKey("spki", key);
  return bufToB64(buf);
}

export async function importPublicKey(b64: string): Promise<CryptoKey> {
  const buf = b64ToBuf(b64);
  return crypto.subtle.importKey(
    "spki",
    buf,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"],
  );
}

export async function getOrCreateKeyPair(
  username: string,
): Promise<CryptoKeyPair> {
  const existingPrivate = await loadPrivateKey(username);
  const existingPublic = await loadPublicKey(username);
  if (existingPrivate && existingPublic) {
    return { privateKey: existingPrivate, publicKey: existingPublic };
  }
  const pair = await generateKeyPair();
  await savePrivateKey(username, pair.privateKey);
  await savePublicKey(username, pair.publicKey);
  return pair;
}

// ── Message encryption (AES-GCM + RSA-OAEP wrapped key) ───────────────────
interface EncryptedEnvelope {
  ciphertext: string; // AES-GCM encrypted plaintext (base64)
  iv: string; // 12-byte IV (base64)
  senderKey: string; // AES key encrypted for sender (base64)
  recipientKey: string; // AES key encrypted for recipient (base64)
}

export async function encryptMessage(
  plaintext: string,
  senderPublicKey: CryptoKey,
  recipientPublicKey: CryptoKey,
): Promise<string> {
  // 1. Generate ephemeral AES-GCM key
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );

  // 2. Encrypt plaintext
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    enc.encode(plaintext),
  );

  // 3. Export raw AES key and wrap for both parties
  const rawAes = await crypto.subtle.exportKey("raw", aesKey);
  const [senderWrapped, recipientWrapped] = await Promise.all([
    crypto.subtle.encrypt({ name: "RSA-OAEP" }, senderPublicKey, rawAes),
    crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientPublicKey, rawAes),
  ]);

  const envelope: EncryptedEnvelope = {
    ciphertext: bufToB64(cipherBuf),
    iv: bufToB64(iv.buffer as ArrayBuffer),
    senderKey: bufToB64(senderWrapped),
    recipientKey: bufToB64(recipientWrapped),
  };
  return JSON.stringify(envelope);
}

export async function decryptMessage(
  encryptedJson: string,
  privateKey: CryptoKey,
  isSender: boolean,
): Promise<string | null> {
  try {
    const envelope: EncryptedEnvelope = JSON.parse(encryptedJson);
    // Verify it looks like an envelope
    if (
      !envelope.ciphertext ||
      !envelope.iv ||
      !envelope.senderKey ||
      !envelope.recipientKey
    ) {
      return null;
    }

    const wrappedKey = isSender ? envelope.senderKey : envelope.recipientKey;

    // Unwrap AES key
    const rawAes = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      b64ToBuf(wrappedKey),
    );

    // Import AES key
    const aesKey = await crypto.subtle.importKey(
      "raw",
      rawAes,
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );

    // Decrypt ciphertext
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(b64ToBuf(envelope.iv)) },
      aesKey,
      b64ToBuf(envelope.ciphertext),
    );

    return new TextDecoder().decode(plainBuf);
  } catch {
    return null;
  }
}

// ── Image / bytes encryption (AES-GCM + RSA-OAEP wrapped key) ─────────────

export interface EncryptedBytesResult {
  encryptedData: ArrayBuffer; // AES-GCM encrypted bytes
  iv: string; // 12-byte IV (base64)
  senderKey: string; // AES key encrypted for sender (base64)
  recipientKey: string; // AES key encrypted for recipient (base64)
}

export async function encryptBytes(
  data: ArrayBuffer,
  senderPublicKey: CryptoKey,
  recipientPublicKey: CryptoKey,
): Promise<EncryptedBytesResult> {
  // 1. Generate ephemeral AES-GCM key
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );

  // 2. Encrypt raw bytes
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    data,
  );

  // 3. Export raw AES key and wrap for both parties
  const rawAes = await crypto.subtle.exportKey("raw", aesKey);
  const [senderWrapped, recipientWrapped] = await Promise.all([
    crypto.subtle.encrypt({ name: "RSA-OAEP" }, senderPublicKey, rawAes),
    crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientPublicKey, rawAes),
  ]);

  return {
    encryptedData,
    iv: bufToB64(iv.buffer as ArrayBuffer),
    senderKey: bufToB64(senderWrapped),
    recipientKey: bufToB64(recipientWrapped),
  };
}

export async function decryptBytes(
  encryptedData: ArrayBuffer,
  iv: string,
  wrappedKey: string,
  privateKey: CryptoKey,
): Promise<ArrayBuffer | null> {
  try {
    // Unwrap AES key
    const rawAes = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      b64ToBuf(wrappedKey),
    );

    // Import AES key
    const aesKey = await crypto.subtle.importKey(
      "raw",
      rawAes,
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );

    // Decrypt bytes
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(b64ToBuf(iv)) },
      aesKey,
      encryptedData,
    );

    return plainBuf;
  } catch {
    return null;
  }
}
