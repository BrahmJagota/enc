/**
 * KEY GENERATION UTILITY
 * 
 * Run ONCE on a secure machine to generate your RSA-2048 key pair.
 * 
 *   node generate_keys.js
 *
 * Output:
 *   public_key.pem   → deploy to Server A  (encrypt only)
 *   private_key.pem  → deploy to Server B  (decrypt only) — KEEP SECRET
 *
 * In production, prefer storing keys in:
 *   - AWS KMS / GCP KMS / Azure Key Vault
 *   - HashiCorp Vault
 *   - An HSM (Hardware Security Module)
 *   - Kubernetes secrets (encrypted at rest)
 */

const crypto = require("crypto");
const fs     = require("fs");
const path   = require("path");

const KEY_SIZE     = 2048;          // minimum for production; use 4096 for long-lived keys
const PUBLIC_FILE  = path.join(__dirname, "public_key.pem");
const PRIVATE_FILE = path.join(__dirname, "private_key.pem");

console.log(`Generating RSA-${KEY_SIZE} key pair…`);

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: KEY_SIZE,
  publicKeyEncoding:  { type: "spki",  format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

fs.writeFileSync(PUBLIC_FILE,  publicKey,  { mode: 0o644 }); // world-readable  (Server A)
fs.writeFileSync(PRIVATE_FILE, privateKey, { mode: 0o600 }); // owner-read only (Server B)

console.log("✅  public_key.pem  → copy to Server A");
console.log("✅  private_key.pem → copy to Server B  ⚠️  NEVER share or commit this file");