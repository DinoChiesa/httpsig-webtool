// pem.js
// ------------------------------------------------------------------
//
// PEM to DER for WebCrypto importKey, which accepts only PKCS#8 private keys
// and SubjectPublicKeyInfo (SPKI) public keys with standard algorithm
// identifiers. Other common encodings are rewrapped:
//
//   BEGIN RSA PRIVATE KEY (PKCS#1)  -> PKCS#8 with rsaEncryption
//   BEGIN RSA PUBLIC KEY  (PKCS#1)  -> SPKI with rsaEncryption
//   BEGIN EC PRIVATE KEY  (SEC1)    -> PKCS#8 with id-ecPublicKey + curve
//   PKCS#8 / SPKI tagged id-RSASSA-PSS -> same key, tagged rsaEncryption
//
// For reference, PKCS#8 is:
//   PrivateKeyInfo ::= SEQUENCE {
//     version              INTEGER 0,
//     privateKeyAlgorithm  AlgorithmIdentifier,
//     privateKey           OCTET STRING
//   }
// and SPKI is:
//   SubjectPublicKeyInfo ::= SEQUENCE {
//     algorithm         AlgorithmIdentifier,
//     subjectPublicKey  BIT STRING
//   }

import { bytesFromBase64 } from "./encoding.js";

const TAG = { INTEGER: 0x02, BIT_STRING: 0x03, OCTET_STRING: 0x04, OID: 0x06, SEQUENCE: 0x30 };

const OID_RSA_ENCRYPTION = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_RSASSA_PSS = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_EC_PUBLIC_KEY = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const DER_NULL = [0x05, 0x00];
const DER_INTEGER_0 = [TAG.INTEGER, 0x01, 0x00];

function derLength(length) {
  if (length < 0x80) {
    return [length];
  }
  const bytes = [];
  for (let n = length; n > 0; n = Math.floor(n / 256)) {
    bytes.unshift(n & 0xff);
  }
  return [0x80 | bytes.length, ...bytes];
}

const derElement = (tag, content) => [tag, ...derLength(content.length), ...content];

// Reads one DER element at pos: returns its tag and the bounds of its content.
function readElement(bytes, pos) {
  const tag = bytes[pos];
  let length = bytes[pos + 1],
    headerLength = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i++) {
      length = length * 256 + bytes[pos + 2 + i];
    }
    headerLength += count;
  }
  const start = pos + headerLength;
  if (start + length > bytes.length) {
    throw new Error("malformed key: truncated DER");
  }
  return { tag, start, end: start + length };
}

function childElements(bytes, parent) {
  const children = [];
  for (let pos = parent.start; pos < parent.end; ) {
    const child = readElement(bytes, pos);
    children.push(child);
    pos = child.end;
  }
  return children;
}

const contentOf = (bytes, element) => Array.from(bytes.slice(element.start, element.end));
const wholeElement = (bytes, element, pos) => Array.from(bytes.slice(pos, element.end));
const sameBytes = (a, b) => a.length == b.length && a.every((v, i) => v == b[i]);

const rsaAlgorithmId = () => derElement(TAG.SEQUENCE, [...OID_RSA_ENCRYPTION, ...DER_NULL]);

const pkcs8 = (algorithmId, privateKey) =>
  derElement(TAG.SEQUENCE, [
    ...DER_INTEGER_0,
    ...algorithmId,
    ...derElement(TAG.OCTET_STRING, privateKey),
  ]);

const spki = (algorithmId, publicKey) =>
  derElement(TAG.SEQUENCE, [...algorithmId, ...derElement(TAG.BIT_STRING, [0x00, ...publicKey])]);

function sec1ToPkcs8(der) {
  // ECPrivateKey ::= SEQUENCE { version, privateKey, [0] parameters, [1] publicKey }
  const outer = readElement(der, 0);
  const curveParam = childElements(der, outer).find((e) => e.tag == 0xa0);
  if (!curveParam) {
    throw new Error("EC private key does not name its curve");
  }
  const curveOidElement = readElement(der, curveParam.start);
  const curveOid = wholeElement(der, curveOidElement, curveParam.start);
  const algorithmId = derElement(TAG.SEQUENCE, [...OID_EC_PUBLIC_KEY, ...curveOid]);
  return pkcs8(algorithmId, Array.from(der));
}

// The algorithm OID of a PKCS#8 or SPKI structure, as the full DER element.
function algorithmOid(der, algorithmIdElement) {
  const oidElement = readElement(der, algorithmIdElement.start);
  return wholeElement(der, oidElement, algorithmIdElement.start);
}

function retagRsaPssPkcs8(der) {
  const [, algorithmId, privateKey] = childElements(der, readElement(der, 0));
  if (!sameBytes(algorithmOid(der, algorithmId), OID_RSASSA_PSS)) {
    return der;
  }
  return new Uint8Array(pkcs8(rsaAlgorithmId(), contentOf(der, privateKey)));
}

function retagRsaPssSpki(der) {
  const [algorithmId, publicKey] = childElements(der, readElement(der, 0));
  if (!sameBytes(algorithmOid(der, algorithmId), OID_RSASSA_PSS)) {
    return der;
  }
  // skip the BIT STRING's leading "unused bits" byte
  return new Uint8Array(spki(rsaAlgorithmId(), contentOf(der, publicKey).slice(1)));
}

function pemParts(pem) {
  const m = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(pem);
  if (!m) {
    throw new Error("expected a PEM-encoded key (-----BEGIN ... KEY-----)");
  }
  return { label: m[1], der: bytesFromBase64(m[2]) };
}

// Returns { format: "pkcs8" | "spki", der: ArrayBuffer } for importKey.
function pemToKeyData(pem) {
  const { label, der } = pemParts(pem);
  switch (label) {
    case "RSA PRIVATE KEY":
      return { format: "pkcs8", der: new Uint8Array(pkcs8(rsaAlgorithmId(), Array.from(der))).buffer };
    case "RSA PUBLIC KEY":
      return { format: "spki", der: new Uint8Array(spki(rsaAlgorithmId(), Array.from(der))).buffer };
    case "EC PRIVATE KEY":
      return { format: "pkcs8", der: new Uint8Array(sec1ToPkcs8(der)).buffer };
    case "PRIVATE KEY":
      return { format: "pkcs8", der: retagRsaPssPkcs8(der).buffer };
    case "PUBLIC KEY":
      return { format: "spki", der: retagRsaPssSpki(der).buffer };
  }
  throw new Error(`unsupported PEM type: ${label}`);
}

export { pemToKeyData };
