// pem.js
// ------------------------------------------------------------------
//
// PEM to DER for WebCrypto importKey. WebCrypto accepts PKCS#8 private keys
// but not PKCS#1 ("BEGIN RSA PRIVATE KEY"), so PKCS#1 keys get wrapped:
//
//   PrivateKeyInfo ::= SEQUENCE {
//     version              INTEGER 0,
//     privateKeyAlgorithm  SEQUENCE { OID rsaEncryption, NULL },
//     privateKey           OCTET STRING  -- the PKCS#1 DER, unchanged
//   }

import { bytesFromBase64 } from "./encoding.js";

const DER_INTEGER_0 = [0x02, 0x01, 0x00];
const DER_RSA_ALGORITHM_ID = [
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  0x05, 0x00,
];

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

function pkcs1ToPkcs8(pkcs1Der) {
  const octetString = derElement(0x04, Array.from(pkcs1Der));
  const sequence = derElement(0x30, [
    ...DER_INTEGER_0,
    ...DER_RSA_ALGORITHM_ID,
    ...octetString,
  ]);
  return new Uint8Array(sequence);
}

function pemBody(pem) {
  return pem
    .split("\n")
    .filter((line) => line.indexOf("-----") < 0)
    .join("");
}

// Returns an ArrayBuffer of DER, PKCS#8 for private keys, as-is otherwise.
function pemToDer(pem) {
  const der = bytesFromBase64(pemBody(pem));
  if (pem.indexOf("BEGIN RSA PRIVATE KEY") >= 0) {
    return pkcs1ToPkcs8(der).buffer;
  }
  return der.buffer;
}

export { pemToDer };
