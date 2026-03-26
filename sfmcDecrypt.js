/**
 * SERVER B — SFMC PII Decryption Module
 * File: serverB_sfmc_decrypt.js
 *
 * Decrypts ciphertext produced by SFMC's EncryptSymmetric("aes256", ...)
 *
 * ─── How SFMC's EncryptSymmetric works internally ────────────────────────
 *  Algorithm : AES-256-CBC
 *  Key derive: PBKDF2-SHA1(password=key, salt=salt, iterations=1000, keylen=32)
 *  IV        : SFMC prepends the 16-byte IV to the ciphertext before Base64
 *              so the wire format is:  Base64( IV[16] + Ciphertext[N] )
 *  Padding   : PKCS#7
 * ─────────────────────────────────────────────────────────────────────────
 *
 * You need from SFMC Symmetric Key Management:
 *   PII_AES_KEY  → the "Key Value" field (plain text password / passphrase)
 *   PII_AES_SALT → the "Salt Value" field (plain text)
 *
 * Store these in environment variables — NEVER hard-code them.
 */

const crypto  = require("crypto");
const express = require("express");   // optional — only if exposing as HTTP endpoint

// ---------------------------------------------------------------------------
// Config — load from environment variables
// ---------------------------------------------------------------------------

const SFMC_KEY  = process.env.SFMC_PII_KEY;   // "Key Value"  from SFMC Key Management
const SFMC_SALT = process.env.SFMC_PII_SALT;  // "Salt Value" from SFMC Key Management

if (!SFMC_KEY || !SFMC_SALT) {
  throw new Error(
    "Missing env vars: SFMC_PII_KEY and SFMC_PII_SALT must be set before starting Server B"
  );
}

// ---------------------------------------------------------------------------
// Key derivation — mirrors SFMC's internal PBKDF2 call
// ---------------------------------------------------------------------------

/**
 * Derive the 32-byte AES key the same way SFMC does.
 *
 * @param {string} keyPassword   - "Key Value" from SFMC Symmetric Key Management
 * @param {string} saltString    - "Salt Value" from SFMC Symmetric Key Management
 * @returns {Buffer}  32-byte derived key
 */
function deriveKey(keyPassword, saltString) {
  return crypto.pbkdf2Sync(
    Buffer.from(keyPassword, "utf8"),
    Buffer.from(saltString,  "utf8"),
    1000,          // iterations — SFMC default
    32,            // 256 bits
    "sha1"         // SFMC uses SHA-1 for PBKDF2
  );
}

// Pre-derive once at startup (key/salt don't change per-request)
const DERIVED_KEY = deriveKey(SFMC_KEY, SFMC_SALT);

// ---------------------------------------------------------------------------
// Core: decrypt a single SFMC-encrypted PII field
// ---------------------------------------------------------------------------

/**
 * Decrypt a Base64 ciphertext produced by SFMC's EncryptSymmetric("aes256").
 *
 * Wire format coming from SFMC:
 *   Base64( IV[16 bytes] || AES-CBC-Ciphertext )
 *
 * @param {string} base64Ciphertext - value straight from SFMC / Data Extension
 * @returns {string}  Original plaintext (UTF-8)
 *
 * @throws {Error} on bad padding, wrong key, or malformed input
 */
function decryptSFMCField(base64Ciphertext) {
  if (!base64Ciphertext || typeof base64Ciphertext !== "string") {
    throw new TypeError("base64Ciphertext must be a non-empty string");
  }

  // 1. Base64-decode the full blob
  const blob = Buffer.from(base64Ciphertext, "base64");

  if (blob.length < 17) {
    throw new Error("Ciphertext too short — must be at least 17 bytes (16 IV + 1 cipher byte)");
  }

  // 2. Split IV (first 16 bytes) from actual ciphertext
  const iv         = blob.subarray(0, 16);
  const ciphertext = blob.subarray(16);

  // 3. AES-256-CBC decrypt with PKCS#7 padding (Node's default)
  const decipher = crypto.createDecipheriv("aes-256-cbc", DERIVED_KEY, iv);
  // autopadding: true is the Node default — handles PKCS#7 removal

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),            // throws if padding is invalid (wrong key)
  ]).toString("utf8");

  return plaintext;
}

// ---------------------------------------------------------------------------
// Decrypt a full PII payload object (as POSTed from AMPscript)
// ---------------------------------------------------------------------------

/**
 * Decrypt all encrypted fields in a PII payload from SFMC.
 *
 * @param {{ subscriberKey, encEmail, encPhone, encFirstName, encLastName }} payload
 * @returns {{ subscriberKey, email, phone, firstName, lastName }}
 */
function decryptPIIPayload(payload) {
  const { subscriberKey, encEmail, encPhone, encFirstName, encLastName } = payload;

  return {
    subscriberKey,
    email     : decryptSFMCField(encEmail),
    phone     : decryptSFMCField(encPhone),
    firstName : decryptSFMCField(encFirstName),
    lastName  : decryptSFMCField(encLastName),
  };
}

// ---------------------------------------------------------------------------
// Optional Express endpoint — receives the POST from AMPscript HTTPPost2
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());

// Simple API key middleware — replace with proper auth (JWT / mTLS) in prod
app.use((req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  if (apiKey !== process.env.SERVER_B_API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
});

/**
 * POST /decrypt-pii
 * Body: { subscriberKey, encEmail, encPhone, encFirstName, encLastName }
 */
app.post("/decrypt-pii", (req, res) => {
  try {
    const decrypted = decryptPIIPayload(req.body);

    // ── Use decrypted PII here — write to CRM, trigger fulfillment, etc. ──
    // NEVER log decrypted.email / decrypted.phone in production logs
    console.log(`Decrypted PII for subscriberKey: ${decrypted.subscriberKey}`);

    // Return only a confirmation — don't echo PII back unless necessary
    res.json({ success: true, subscriberKey: decrypted.subscriberKey });
  } catch (err) {
    console.error("Decryption error:", err.message);
    res.status(400).json({ error: "Decryption failed", detail: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server B (SFMC PII decryptor) listening on port ${PORT}`)
);

// ---------------------------------------------------------------------------
// Exports for unit testing / use as a module
// ---------------------------------------------------------------------------

module.exports = { decryptSFMCField, decryptPIIPayload, deriveKey };

// ---------------------------------------------------------------------------
// Self-test  (run: SFMC_PII_KEY=mykey SFMC_PII_SALT=mysalt node serverB_sfmc_decrypt.js test)
// ---------------------------------------------------------------------------

if (process.argv[2] === "test") {
  console.log("─────────────────────────────────────────────────");
  console.log("SERVER B — SFMC AES DECRYPTION SELF-TEST");
  console.log("─────────────────────────────────────────────────");

  // Simulate what SFMC EncryptSymmetric produces
  function simulateSFMCEncrypt(plaintext) {
    const iv      = crypto.randomBytes(16);
    const cipher  = crypto.createCipheriv("aes-256-cbc", DERIVED_KEY, iv);
    const enc     = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return Buffer.concat([iv, enc]).toString("base64"); // IV prepended — SFMC format
  }

  const testCases = [
    { field: "email",     value: "john.doe@example.com" },
    { field: "phone",     value: "+1-555-867-5309"      },
    { field: "firstName", value: "John"                 },
    { field: "lastName",  value: "Doe"                  },
  ];

  let allPassed = true;
  for (const { field, value } of testCases) {
    const encrypted = simulateSFMCEncrypt(value);
    const decrypted = decryptSFMCField(encrypted);
    const passed    = decrypted === value;
    allPassed       = allPassed && passed;
    console.log(`${passed ? "✅" : "❌"}  ${field}: "${value}" → decrypt → "${decrypted}"`);
  }

  console.log("\n" + (allPassed ? "✅  ALL TESTS PASSED" : "❌  SOME TESTS FAILED"));
  process.exit(allPassed ? 0 : 1);
}