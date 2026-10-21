// sigcrypto.js
// ------------------------------------------------------------------
//
// The RFC 9421 signature algorithms (Section 3.3), mapped onto WebCrypto.

import { pemToKeyData } from "./pem.js";

const RSA_GEN = { modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) };

const ALGORITHMS = {
  "rsa-pss-sha512": {
    family: "rsa",
    importParams: { name: "RSA-PSS", hash: "SHA-512" },
    signParams: { name: "RSA-PSS", saltLength: 64 },
    genParams: { name: "RSA-PSS", hash: "SHA-512", ...RSA_GEN },
  },
  "rsa-v1_5-sha256": {
    family: "rsa",
    importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    signParams: { name: "RSASSA-PKCS1-v1_5" },
    genParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", ...RSA_GEN },
  },
  "hmac-sha256": {
    family: "hmac",
    importParams: { name: "HMAC", hash: "SHA-256" },
    signParams: { name: "HMAC" },
  },
  "ecdsa-p256-sha256": {
    family: "ec-p256",
    importParams: { name: "ECDSA", namedCurve: "P-256" },
    signParams: { name: "ECDSA", hash: "SHA-256" },
    genParams: { name: "ECDSA", namedCurve: "P-256" },
  },
  "ecdsa-p384-sha384": {
    family: "ec-p384",
    importParams: { name: "ECDSA", namedCurve: "P-384" },
    signParams: { name: "ECDSA", hash: "SHA-384" },
    genParams: { name: "ECDSA", namedCurve: "P-384" },
  },
  ed25519: {
    family: "ed25519",
    importParams: { name: "Ed25519" },
    signParams: { name: "Ed25519" },
    genParams: { name: "Ed25519" },
  },
};

const ALGORITHM_NAMES = Object.keys(ALGORITHMS);

function algorithm(name) {
  const alg = ALGORITHMS[name];
  if (!alg) {
    throw new Error(`unsupported algorithm: ${name}`);
  }
  return alg;
}

const keyFamily = (algName) => algorithm(algName).family;

function importPemKey(algName, pem, usage /* "sign" | "verify" */) {
  const { format, der } = pemToKeyData(pem);
  const expected = usage == "sign" ? "pkcs8" : "spki";
  if (format != expected) {
    throw new Error(`expected a ${usage == "sign" ? "private" : "public"} key`);
  }
  return crypto.subtle.importKey(format, der, algorithm(algName).importParams, false, [usage]);
}

function importHmacKey(keyBytes) {
  return crypto.subtle.importKey("raw", keyBytes, ALGORITHMS["hmac-sha256"].importParams, false, [
    "sign",
    "verify",
  ]);
}

async function sign(algName, key, base) {
  const signature = await crypto.subtle.sign(algorithm(algName).signParams, key, new TextEncoder().encode(base));
  return new Uint8Array(signature);
}

function verify(algName, key, base, signatureBytes) {
  return crypto.subtle.verify(algorithm(algName).signParams, key, signatureBytes, new TextEncoder().encode(base));
}

function pem(label, der) {
  const b64 = btoa(Array.from(new Uint8Array(der), (b) => String.fromCharCode(b)).join(""));
  return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g).join("\n")}\n-----END ${label}-----`;
}

// Generates a keypair for an asymmetric algorithm; returns PEM strings.
async function generateKeyPair(algName) {
  const { genParams } = algorithm(algName);
  if (!genParams) {
    throw new Error(`${algName} does not use a keypair`);
  }
  const keyPair = await crypto.subtle.generateKey(genParams, true, ["sign", "verify"]);
  return {
    publicKey: pem("PUBLIC KEY", await crypto.subtle.exportKey("spki", keyPair.publicKey)),
    privateKey: pem("PRIVATE KEY", await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)),
  };
}

export { ALGORITHM_NAMES, keyFamily, importPemKey, importHmacKey, sign, verify, generateKeyPair };
