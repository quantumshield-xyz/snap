// QuantumShield PQC Snap — ML-DSA-65 Hybrid Signatures for MetaMask
//
// This Snap adds post-quantum cryptography support to MetaMask:
//   - ML-DSA-65 (FIPS 204) key pair generation
//   - Hybrid signing (ECDSA + ML-DSA-65)
//   - Session key management
//   - PQC key export/import
//
// Signature versions:
//   0x01 = Hybrid (ECDSA + ML-DSA-65) — 3,375 bytes
//   0x02 = PQC-only (ML-DSA-65) — 3,310 bytes
//   0x03 = Session Key (ECDSA only) — 66 bytes
//   0x04 = Hybrid (ECDSA + ML-DSA-87) — 4,693 bytes (Level 5)
//   0xFF = ECDSA-only (fallback) — 66 bytes

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const VERSION_HYBRID = 0x01;
const VERSION_PQC_ONLY = 0x02;
const VERSION_SESSION_KEY = 0x03;
const VERSION_ECDSA_MLDSA87 = 0x04;
const VERSION_ECDSA_ONLY = 0xff;

const MLDSA_PUBKEY_SIZE = 1952;
const MLDSA_PRIVKEY_SIZE = 4032;
const MLDSA_SIG_SIZE = 3309;

/**
 * Get or initialize PQC state from Snap storage
 */
async function getState() {
  const state = await snap.request({
    method: 'snap_manageState',
    params: { operation: 'get' },
  });
  return state || { keys: {}, sessionKeys: {} };
}

/**
 * Save state to Snap storage
 */
async function saveState(state) {
  await snap.request({
    method: 'snap_manageState',
    params: { operation: 'update', newState: state },
  });
}

/**
 * Convert Uint8Array to hex string
 */
function toHex(bytes) {
  return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert hex string to Uint8Array
 */
function fromHex(hex) {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Generate ML-DSA-65 key pair
 */
function generatePQCKeyPair() {
  const { publicKey, secretKey } = ml_dsa65.keygen();
  if (publicKey.length !== MLDSA_PUBKEY_SIZE) {
    throw new Error(`Invalid pubkey size: ${publicKey.length}`);
  }
  if (secretKey.length !== MLDSA_PRIVKEY_SIZE) {
    throw new Error(`Invalid privkey size: ${secretKey.length}`);
  }
  return { publicKey, secretKey };
}

/**
 * Sign message with ML-DSA-65
 */
function signPQC(secretKey, message) {
  const sig = ml_dsa65.sign(message, secretKey);
  if (sig.length !== MLDSA_SIG_SIZE) {
    throw new Error(`Invalid sig size: ${sig.length}`);
  }
  return sig;
}

/**
 * Verify ML-DSA-65 signature
 */
function verifyPQC(publicKey, message, signature) {
  return ml_dsa65.verify(signature, message, publicKey);
}

/**
 * Handle incoming RPC requests from dApps
 */
export const onRpcRequest = async ({ origin, request }) => {
  const { method, params } = request;

  switch (method) {
    // =========================================
    // Key Management
    // =========================================
    case 'qs_generateKeyPair': {
      const confirm = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Generate PQC Key Pair'),
            text(`**${origin}** wants to generate a new ML-DSA-65 key pair.`),
            text('This will create a post-quantum secure key pair (NIST FIPS 204, Security Level 3).'),
            divider(),
            text('**Public Key:** 1,952 bytes'),
            text('**Private Key:** 4,032 bytes (stored securely in Snap)'),
          ]),
        },
      });

      if (!confirm) {
        throw new Error('User rejected key generation');
      }

      const { publicKey, secretKey } = generatePQCKeyPair();
      const pubHex = toHex(publicKey);
      const state = await getState();
      const keyId = `key_${Date.now()}`;

      state.keys[keyId] = {
        publicKey: pubHex,
        secretKey: toHex(secretKey),
        createdAt: Date.now(),
        label: params?.label || 'Default',
      };
      await saveState(state);

      await snap.request({
        method: 'snap_notify',
        params: {
          type: 'inApp',
          message: `PQC key pair generated (${keyId})`,
        },
      });

      return {
        keyId,
        publicKey: pubHex,
        publicKeySize: MLDSA_PUBKEY_SIZE,
        algorithm: 'ML-DSA-65',
        standard: 'NIST FIPS 204',
        securityLevel: 3,
      };
    }

    case 'qs_listKeys': {
      const state = await getState();
      return Object.entries(state.keys).map(([id, key]) => ({
        keyId: id,
        publicKey: key.publicKey.slice(0, 20) + '...',
        publicKeyFull: key.publicKey,
        label: key.label,
        createdAt: key.createdAt,
      }));
    }

    case 'qs_getPublicKey': {
      const { keyId } = params;
      const state = await getState();
      const key = state.keys[keyId];
      if (!key) throw new Error(`Key not found: ${keyId}`);
      return {
        publicKey: key.publicKey,
        size: MLDSA_PUBKEY_SIZE,
      };
    }

    case 'qs_deleteKey': {
      const { keyId } = params;
      const confirm = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Delete PQC Key'),
            text(`Delete key **${keyId}**?`),
            text('This action cannot be undone. The private key will be permanently removed.'),
          ]),
        },
      });
      if (!confirm) throw new Error('User rejected key deletion');

      const state = await getState();
      delete state.keys[keyId];
      await saveState(state);
      return { deleted: keyId };
    }

    // =========================================
    // Signing
    // =========================================
    case 'qs_signHybrid': {
      // Hybrid signature: version(1) + ecdsaSig(65) + mldsaSig(3309)
      const { keyId, messageHash, ecdsaSignature } = params;
      const state = await getState();
      const key = state.keys[keyId];
      if (!key) throw new Error(`Key not found: ${keyId}`);

      const confirm = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Hybrid PQC Signature'),
            text(`**${origin}** requests a hybrid signature.`),
            text(`Hash: ${messageHash.slice(0, 18)}...`),
            text(`Key: ${keyId}`),
            divider(),
            text('This will create an ECDSA + ML-DSA-65 hybrid signature (3,375 bytes).'),
          ]),
        },
      });
      if (!confirm) throw new Error('User rejected signing');

      const msgBytes = fromHex(messageHash);
      const secretKey = fromHex(key.secretKey);
      const mldsaSig = signPQC(secretKey, msgBytes);
      const ecdsaBytes = fromHex(ecdsaSignature);

      // Assemble: version(1) + ecdsa(65) + mldsa(3309)
      const result = new Uint8Array(1 + ecdsaBytes.length + mldsaSig.length);
      result[0] = VERSION_HYBRID;
      result.set(ecdsaBytes, 1);
      result.set(mldsaSig, 1 + ecdsaBytes.length);

      return {
        signature: toHex(result),
        version: VERSION_HYBRID,
        size: result.length,
        mode: 'hybrid',
      };
    }

    case 'qs_signPQCOnly': {
      // PQC-only signature: version(1) + mldsaSig(3309)
      const { keyId, messageHash } = params;
      const state = await getState();
      const key = state.keys[keyId];
      if (!key) throw new Error(`Key not found: ${keyId}`);

      const confirm = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('PQC-Only Signature'),
            text(`**${origin}** requests a PQC-only signature.`),
            text(`Hash: ${messageHash.slice(0, 18)}...`),
            divider(),
            text('ML-DSA-65 only (no ECDSA). Use when ECDSA is compromised.'),
          ]),
        },
      });
      if (!confirm) throw new Error('User rejected signing');

      const msgBytes = fromHex(messageHash);
      const secretKey = fromHex(key.secretKey);
      const mldsaSig = signPQC(secretKey, msgBytes);

      const result = new Uint8Array(1 + mldsaSig.length);
      result[0] = VERSION_PQC_ONLY;
      result.set(mldsaSig, 1);

      return {
        signature: toHex(result),
        version: VERSION_PQC_ONLY,
        size: result.length,
        mode: 'pqc-only',
      };
    }

    // =========================================
    // Verification
    // =========================================
    case 'qs_verify': {
      const { keyId, messageHash, signature } = params;
      const state = await getState();
      const key = state.keys[keyId];
      if (!key) throw new Error(`Key not found: ${keyId}`);

      const sigBytes = fromHex(signature);
      const msgBytes = fromHex(messageHash);
      const publicKey = fromHex(key.publicKey);
      const version = sigBytes[0];

      let mldsaSig;
      if (version === VERSION_HYBRID) {
        mldsaSig = sigBytes.slice(66); // skip version(1) + ecdsa(65)
      } else if (version === VERSION_PQC_ONLY) {
        mldsaSig = sigBytes.slice(1); // skip version(1)
      } else {
        return { valid: false, reason: 'No PQC component in signature' };
      }

      const valid = verifyPQC(publicKey, msgBytes, mldsaSig);
      return { valid, version, mode: version === VERSION_HYBRID ? 'hybrid' : 'pqc-only' };
    }

    // =========================================
    // Info
    // =========================================
    case 'qs_getInfo': {
      const state = await getState();
      return {
        name: 'QuantumShield PQC Snap',
        version: '0.1.0',
        algorithm: 'ML-DSA-65',
        standard: 'NIST FIPS 204',
        securityLevel: 3,
        publicKeySize: MLDSA_PUBKEY_SIZE,
        privateKeySize: MLDSA_PRIVKEY_SIZE,
        signatureSize: MLDSA_SIG_SIZE,
        hybridSignatureSize: 1 + 65 + MLDSA_SIG_SIZE,
        keyCount: Object.keys(state.keys).length,
        chainId: 42069,
        supportedVersions: {
          '0x01': 'Hybrid (ECDSA + ML-DSA-65)',
          '0x02': 'PQC-only (ML-DSA-65)',
          '0x03': 'Session Key (ECDSA)',
          '0x04': 'Hybrid (ECDSA + ML-DSA-87) — Level 5',
          '0xFF': 'ECDSA-only (fallback)',
        },
      };
    }

    case 'qs_exportPublicKey': {
      const { keyId } = params;
      const state = await getState();
      const key = state.keys[keyId];
      if (!key) throw new Error(`Key not found: ${keyId}`);
      return {
        publicKey: key.publicKey,
        format: 'hex',
        algorithm: 'ML-DSA-65',
        size: MLDSA_PUBKEY_SIZE,
      };
    }

    // =========================================
    // Secret Key Export / Key Pair Import
    // =========================================
    case 'qs_exportSecretKey': {
      // Exports the ML-DSA secret key for backup purposes
      // Requires explicit user confirmation via snap_dialog
      const { keyId } = params;
      const state = await getState();
      const key = state.keys[keyId];
      if (!key) throw new Error(`Key not found: ${keyId}`);

      const confirm = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Export Secret Key'),
            text(`**${origin}** wants to export the secret key for **${keyId}**.`),
            divider(),
            text('**WARNING:** This will expose your ML-DSA-65 private key (4,032 bytes).'),
            text('Only proceed if you are backing up your keys to a secure location.'),
            text('Anyone with this key can sign transactions on your behalf.'),
          ]),
        },
      });

      if (!confirm) {
        throw new Error('User rejected secret key export');
      }

      return {
        keyId,
        secretKey: key.secretKey,
        publicKey: key.publicKey,
        algorithm: 'ML-DSA-65',
        secretKeySize: MLDSA_PRIVKEY_SIZE,
        publicKeySize: MLDSA_PUBKEY_SIZE,
      };
    }

    case 'qs_importKeyPair': {
      // Imports an ML-DSA key pair (public + secret key) into Snap storage
      // Validates sizes and performs sign+verify integrity check
      const { publicKey: pubHex, secretKey: secHex, label } = params;
      if (!pubHex || !secHex) {
        throw new Error('publicKey and secretKey are required');
      }

      const pubBytes = fromHex(pubHex);
      const secBytes = fromHex(secHex);

      if (pubBytes.length !== MLDSA_PUBKEY_SIZE) {
        throw new Error(`Invalid public key size: expected ${MLDSA_PUBKEY_SIZE}, got ${pubBytes.length}`);
      }
      if (secBytes.length !== MLDSA_PRIVKEY_SIZE) {
        throw new Error(`Invalid secret key size: expected ${MLDSA_PRIVKEY_SIZE}, got ${secBytes.length}`);
      }

      // Integrity check: sign a test message and verify
      const testMsg = new Uint8Array(32);
      testMsg[0] = 0x51; // 'Q' for QuantumShield
      testMsg[1] = 0x53; // 'S'
      const testSig = ml_dsa65.sign(testMsg, secBytes);
      if (!ml_dsa65.verify(testSig, testMsg, pubBytes)) {
        throw new Error('Key pair integrity check failed: sign+verify mismatch');
      }

      const confirm = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Import PQC Key Pair'),
            text(`**${origin}** wants to import an ML-DSA-65 key pair.`),
            text(`Public key: ${pubHex.slice(0, 20)}...`),
            divider(),
            text('The key pair has been verified (sign+verify check passed).'),
            text('This will store the private key securely in the Snap.'),
          ]),
        },
      });

      if (!confirm) {
        throw new Error('User rejected key pair import');
      }

      const state = await getState();
      const keyId = `key_${Date.now()}`;
      const normalizedPub = pubHex.startsWith('0x') ? pubHex : '0x' + pubHex;
      const normalizedSec = secHex.startsWith('0x') ? secHex : '0x' + secHex;

      state.keys[keyId] = {
        publicKey: normalizedPub,
        secretKey: normalizedSec,
        createdAt: Date.now(),
        label: label || 'Imported',
      };
      await saveState(state);

      await snap.request({
        method: 'snap_notify',
        params: {
          type: 'inApp',
          message: `PQC key pair imported (${keyId})`,
        },
      });

      return {
        keyId,
        publicKey: normalizedPub,
        publicKeySize: MLDSA_PUBKEY_SIZE,
        algorithm: 'ML-DSA-65',
        standard: 'NIST FIPS 204',
        securityLevel: 3,
        imported: true,
      };
    }

    default:
      throw new Error(`Method not supported: ${method}`);
  }
};

// Snap UI helpers (MetaMask Snaps UI components)
function panel(children) {
  return { type: 'panel', children };
}
function heading(value) {
  return { type: 'heading', value };
}
function text(value) {
  return { type: 'text', value };
}
function divider() {
  return { type: 'divider' };
}
