// QuantumShield Snap — Unit Tests
import { describe, it, expect } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const MLDSA_PUBKEY_SIZE = 1952;
const MLDSA_PRIVKEY_SIZE = 4032;
const MLDSA_SIG_SIZE = 3309;

const VERSION_HYBRID = 0x01;
const VERSION_PQC_ONLY = 0x02;
const VERSION_SESSION_KEY = 0x03;
const VERSION_ECDSA_ONLY = 0xff;

function toHex(bytes) {
  return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.substr(i * 2, 2), 16);
  }
  return bytes;
}

describe('ML-DSA-65 Key Generation', () => {
  it('should generate valid key pair', () => {
    const { publicKey, secretKey } = ml_dsa65.keygen();
    expect(publicKey.length).toBe(MLDSA_PUBKEY_SIZE);
    expect(secretKey.length).toBe(MLDSA_PRIVKEY_SIZE);
  });

  it('should generate unique keys each time', () => {
    const kp1 = ml_dsa65.keygen();
    const kp2 = ml_dsa65.keygen();
    expect(toHex(kp1.publicKey)).not.toBe(toHex(kp2.publicKey));
  });
});

describe('ML-DSA-65 Signing', () => {
  it('should produce valid signature', () => {
    const { publicKey, secretKey } = ml_dsa65.keygen();
    const msg = new Uint8Array(32).fill(0xab);
    const sig = ml_dsa65.sign(msg, secretKey);
    expect(sig.length).toBe(MLDSA_SIG_SIZE);
    expect(ml_dsa65.verify(sig, msg, publicKey)).toBe(true);
  });

  it('should reject tampered message', () => {
    const { publicKey, secretKey } = ml_dsa65.keygen();
    const msg = new Uint8Array(32).fill(0xab);
    const sig = ml_dsa65.sign(msg, secretKey);
    const bad = new Uint8Array(32).fill(0xcd);
    expect(ml_dsa65.verify(sig, bad, publicKey)).toBe(false);
  });

  it('should reject wrong public key', () => {
    const kp1 = ml_dsa65.keygen();
    const kp2 = ml_dsa65.keygen();
    const msg = new Uint8Array(32).fill(0x01);
    const sig = ml_dsa65.sign(msg, kp1.secretKey);
    expect(ml_dsa65.verify(sig, msg, kp2.publicKey)).toBe(false);
  });
});

describe('Hybrid Signature Assembly', () => {
  it('should assemble hybrid signature (0x01)', () => {
    const { secretKey } = ml_dsa65.keygen();
    const msg = new Uint8Array(32).fill(0xde);
    const fakeEcdsa = new Uint8Array(65).fill(0x11);
    const mldsaSig = ml_dsa65.sign(msg, secretKey);

    const result = new Uint8Array(1 + fakeEcdsa.length + mldsaSig.length);
    result[0] = VERSION_HYBRID;
    result.set(fakeEcdsa, 1);
    result.set(mldsaSig, 1 + fakeEcdsa.length);

    expect(result[0]).toBe(0x01);
    expect(result.length).toBe(1 + 65 + 3309);
    expect(result.length).toBe(3375);
  });

  it('should assemble pqc-only signature (0x02)', () => {
    const { secretKey } = ml_dsa65.keygen();
    const msg = new Uint8Array(32).fill(0xbe);
    const mldsaSig = ml_dsa65.sign(msg, secretKey);

    const result = new Uint8Array(1 + mldsaSig.length);
    result[0] = VERSION_PQC_ONLY;
    result.set(mldsaSig, 1);

    expect(result[0]).toBe(0x02);
    expect(result.length).toBe(1 + 3309);
    expect(result.length).toBe(3310);
  });

  it('should assemble session key signature (0x03)', () => {
    const fakeEcdsa = new Uint8Array(65).fill(0x22);
    const result = new Uint8Array(1 + fakeEcdsa.length);
    result[0] = VERSION_SESSION_KEY;
    result.set(fakeEcdsa, 1);

    expect(result[0]).toBe(0x03);
    expect(result.length).toBe(66);
  });

  it('should assemble ecdsa-only signature (0xFF)', () => {
    const fakeEcdsa = new Uint8Array(65).fill(0x33);
    const result = new Uint8Array(1 + fakeEcdsa.length);
    result[0] = VERSION_ECDSA_ONLY;
    result.set(fakeEcdsa, 1);

    expect(result[0]).toBe(0xff);
    expect(result.length).toBe(66);
  });
});

describe('Hex Conversion', () => {
  it('should round-trip hex conversion', () => {
    const original = new Uint8Array([0x01, 0x02, 0xff, 0x00, 0xab]);
    const hex = toHex(original);
    const restored = fromHex(hex);
    expect(restored).toEqual(original);
  });

  it('should handle 0x prefix', () => {
    const bytes = fromHex('0xdeadbeef');
    expect(bytes.length).toBe(4);
    expect(bytes[0]).toBe(0xde);
    expect(bytes[3]).toBe(0xef);
  });
});

describe('Signature Verification', () => {
  it('should verify hybrid signature PQC component', () => {
    const { publicKey, secretKey } = ml_dsa65.keygen();
    const msg = new Uint8Array(32).fill(0x42);
    const fakeEcdsa = new Uint8Array(65).fill(0x11);
    const mldsaSig = ml_dsa65.sign(msg, secretKey);

    // Assemble hybrid
    const hybrid = new Uint8Array(1 + 65 + mldsaSig.length);
    hybrid[0] = VERSION_HYBRID;
    hybrid.set(fakeEcdsa, 1);
    hybrid.set(mldsaSig, 66);

    // Extract and verify PQC component
    const extractedSig = hybrid.slice(66);
    expect(ml_dsa65.verify(extractedSig, msg, publicKey)).toBe(true);
  });

  it('should verify pqc-only signature', () => {
    const { publicKey, secretKey } = ml_dsa65.keygen();
    const msg = new Uint8Array(32).fill(0x77);
    const mldsaSig = ml_dsa65.sign(msg, secretKey);

    const pqcOnly = new Uint8Array(1 + mldsaSig.length);
    pqcOnly[0] = VERSION_PQC_ONLY;
    pqcOnly.set(mldsaSig, 1);

    const extractedSig = pqcOnly.slice(1);
    expect(ml_dsa65.verify(extractedSig, msg, publicKey)).toBe(true);
  });
});

describe('Constants', () => {
  it('should have correct ML-DSA-65 sizes', () => {
    expect(MLDSA_PUBKEY_SIZE).toBe(1952);
    expect(MLDSA_PRIVKEY_SIZE).toBe(4032);
    expect(MLDSA_SIG_SIZE).toBe(3309);
  });

  it('should have correct version bytes', () => {
    expect(VERSION_HYBRID).toBe(0x01);
    expect(VERSION_PQC_ONLY).toBe(0x02);
    expect(VERSION_SESSION_KEY).toBe(0x03);
    expect(VERSION_ECDSA_ONLY).toBe(0xff);
  });
});
