/**
 * Encryption/Decryption Utility using Web Crypto API (PBKDF2 + AES-GCM)
 */

const SALT_LEN = 16;
const IV_LEN = 12;
const ITERATIONS = 100000;
const HASH_ALGO = 'SHA-256';

/**
 * Generate a CryptoKey from a password and salt.
 * @param {string} password 
 * @param {Uint8Array} salt 
 * @returns {Promise<CryptoKey>}
 */
async function getKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: ITERATIONS,
      hash: HASH_ALGO
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts logic using AES-GCM given a password.
 * Returns a JSON string containing iv, salt, and ciphertext (all hex encoded).
 * @param {string} text 
 * @param {string} password 
 * @returns {Promise<string>}
 */
async function encryptData(text, password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await getKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    enc.encode(text)
  );

  // Helper to convert buffer to hex string
  const buf2hex = (buffer) => {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  };

  return JSON.stringify({
    salt: buf2hex(salt),
    iv: buf2hex(iv),
    data: buf2hex(encrypted)
  });
}

/**
 * Decrypts data given the JSON string (from encryptData) and password.
 * @param {string} encryptedJson 
 * @param {string} password 
 * @returns {Promise<string>}
 */
async function decryptData(encryptedJson, password) {
  const dataObj = JSON.parse(encryptedJson);

  const hex2buf = (hex) => {
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  };

  const salt = hex2buf(dataObj.salt);
  const iv = hex2buf(dataObj.iv);
  const encryptedData = hex2buf(dataObj.data);

  const key = await getKey(password, salt);

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      encryptedData
    );
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    throw new Error('Decryption failed. Wrong password?');
  }
}

// Export functions for use in modules (though we might just include this file directly if not using modules)
// For chrome extension context without bundlers, we might need to attach to global scope or use ES modules if configured.
// We'll attach to a global object `LicenseCrypto` for simplicity in non-module contexts.
// Expose to global scope
(typeof window !== 'undefined' ? window : self).LicenseCrypto = {
  encryptData,
  decryptData
};

// --- B2B / PUBLIC KEY CRYPTO ---

const B2B_ALGO_KEY = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

/**
 * Generate a new RSA KeyPair for Sharing.
 */
async function generateKeyPair() {
  return await crypto.subtle.generateKey(
    B2B_ALGO_KEY,
    true,
    ["encrypt", "decrypt"]
  );
}

/**
 * Export Public Key as JWK (or SPKI Base64 if backend prefers).
 * We'll use SPKI Base64 for simplicity in DB storage.
 */
async function exportPublicKey(key) {
  const exported = await crypto.subtle.exportKey("spki", key);
  return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

/**
 * Wrap (Encrypt) a Symmetric Key with a Public Key.
 * Used when sharing a license with another user.
 */
async function wrapKeyForUser(symmetricKey, publicKeySpkiBase64) {
  // Import User's Public Key
  const binaryDer = Uint8Array.from(atob(publicKeySpkiBase64), c => c.charCodeAt(0));
  const pubKey = await crypto.subtle.importKey(
    "spki",
    binaryDer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );

  // Export Symmetric Key to raw bytes
  const rawKey = await crypto.subtle.exportKey("raw", symmetricKey);

  // Encrypt raw key with RSA
  const encrypted = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    pubKey,
    rawKey
  );

  // Helper to convert buffer to hex string
  const buf2hex = (buffer) => {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  };

  return buf2hex(encrypted);
}

/**
 * Unwrap (Decrypt) a Symmetric Key using my Private Key.
 */
async function unwrapKey(encryptedKeyHex, privateKey) {
  const hex2buf = (hex) => {
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  };

  const encryptedBytes = hex2buf(encryptedKeyHex);

  const decryptedRaw = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encryptedBytes
  );

  // Import as AES-GCM Key
  return await crypto.subtle.importKey(
    "raw",
    decryptedRaw,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

// Add to global
// Add to global
const globalScope = self;
globalScope.LicenseCrypto.generateKeyPair = generateKeyPair;
globalScope.LicenseCrypto.exportPublicKey = exportPublicKey;
globalScope.LicenseCrypto.wrapKeyForUser = wrapKeyForUser;
globalScope.LicenseCrypto.unwrapKey = unwrapKey;
