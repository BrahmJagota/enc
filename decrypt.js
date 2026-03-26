/**
 * SERVER A — Encryption Module
 * 
 * Strategy: RSA-OAEP Hybrid Encryption
 * 
 *  1. Generate a random 256-bit AES-GCM symmetric key (per-message)
 *  2. Encrypt the plaintext with AES-GCM  → ciphertext + iv + authTag
 *  3. Encrypt the AES key with RSA-OAEP   → encryptedKey
 *  4. Bundle { encryptedKey, iv, ciphertext } → send to Server B
 *
 * Why hybrid?
 *  - RSA can only encrypt ~245 bytes (2048-bit key). Real payloads are larger.
 *  - AES-GCM is fast, authenticated (tamper-proof), and handles arbitrary sizes.
 *  - Only the tiny AES key crosses RSA — standard TLS/PGP uses the same pattern.
 *
 * Server A only ever needs the PUBLIC key. Keep it in an env var or a key vault.
 */

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Load / import the RSA public key
// ---------------------------------------------------------------------------

/**
 * Import a PEM-encoded RSA public key into a KeyObject.
 *
 * @param {string} pemPublicKey  - PEM string (-----BEGIN PUBLIC KEY-----)
 * @returns {crypto.KeyObject}
 */
function loadPublicKey(pemPublicKey) {
  return crypto.createPublicKey({
    key: pemPublicKey,
    format: "pem",
    type: "spki",       // SubjectPublicKeyInfo — standard PEM format from openssl
  });
}

// ---------------------------------------------------------------------------
// Core: encrypt
// ---------------------------------------------------------------------------

/**
 * Encrypt an arbitrary plaintext string using RSA-OAEP + AES-256-GCM.
 *
 * @param {string} plaintext     - UTF-8 text to encrypt
 * @param {string} pemPublicKey  - Server A's copy of the RSA public key (PEM)
 * @returns {{ encryptedKey: string, iv: string, ciphertext: string, authTag: string }}
 *          All values are base64-encoded strings — safe to send over HTTP/JSON.
 *
 * @throws {Error} If key import or any crypto operation fails.
 */
function encryptText(plaintext, pemPublicKey) {
  if (typeof plaintext !== "string" || plaintext.length === 0) {
    throw new TypeError("plaintext must be a non-empty string");
  }
  if (typeof pemPublicKey !== "string") {
    throw new TypeError("pemPublicKey must be a PEM string");
  }

  // 1. Generate a fresh random 256-bit AES key for this message only
  //    (per-message keys mean a compromised key leaks exactly one message)
  const aesKey = crypto.randomBytes(32);           // 256 bits
  const iv     = crypto.randomBytes(12);           // 96-bit IV — GCM standard

  // 2. Encrypt plaintext with AES-256-GCM
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  const encryptedBuffer = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();             // 16-byte GCM authentication tag

  // 3. Wrap the AES key with RSA-OAEP (SHA-256 hash)
  //    The AES key is only 32 bytes — well within RSA-2048's ~245-byte limit.
  const publicKey = loadPublicKey(pemPublicKey);
  const encryptedKey = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey
  );

  // 4. Return all components as base64 strings
  return {
    encryptedKey: encryptedKey.toString("base64"),   // RSA-wrapped AES key
    iv:           iv.toString("base64"),             // AES-GCM initialisation vector
    ciphertext:   encryptedBuffer.toString("base64"),// Encrypted message body
    authTag:      authTag.toString("base64"),        // GCM authentication tag
  };
}

// ---------------------------------------------------------------------------
// Optional: seal the bundle as a single opaque string for transport
// ---------------------------------------------------------------------------

/**
 * Convenience wrapper: returns a single base64-encoded JSON envelope
 * instead of four separate fields.
 *
 * @param {string} plaintext
 * @param {string} pemPublicKey
 * @returns {string}  base64(JSON({ encryptedKey, iv, ciphertext, authTag }))
 */
function encryptToEnvelope(plaintext, pemPublicKey) {
  const parts = encryptText(plaintext, pemPublicKey);
  return Buffer.from(JSON.stringify(parts)).toString("base64");
}

// ---------------------------------------------------------------------------
// Exports (CommonJS — swap to `export` if using ESM)
// ---------------------------------------------------------------------------

module.exports = { loadPublicKey, encryptText, encryptToEnvelope };

// ---------------------------------------------------------------------------
// Quick self-test  (run: node serverA_encrypt.js)
// ---------------------------------------------------------------------------

if (require.main === module) {
  // Generate a throwaway key pair just to demo the encryption side
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const plaintext = "Hello from Server A — this is a secret message 🔐";

  console.log("─────────────────────────────────────────────────");
  console.log("SERVER A — ENCRYPTION DEMO");
  console.log("─────────────────────────────────────────────────");
  console.log("Plaintext :", plaintext);

  const payload = encryptText(plaintext, publicKey);
  console.log("\nEncrypted payload (send this to Server B):");
  console.log(JSON.stringify(payload, null, 2));

  // Print envelope form too
  const envelope = encryptToEnvelope(plaintext, publicKey);
  console.log("\nEnvelope (single base64 string):");
  console.log(envelope);

  // ── Quickly verify with the private key (inline, for demo only) ──────────
  //    In production, Server A NEVER has the private key.
  const aesKey  = crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    Buffer.from(payload.encryptedKey, "base64")
  );
  const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, Buffer.from(payload.iv, "base64"));
  decipher.setAuthTag(Buffer.from(payload.authTag, "base64"));
  const decrypted = decipher.update(Buffer.from(payload.ciphertext, "base64")) + decipher.final("utf8");
  console.log("\n✅  Round-trip verification:", decrypted === plaintext ? "PASSED" : "FAILED");
  console.log("Decrypted:", decrypted);
}