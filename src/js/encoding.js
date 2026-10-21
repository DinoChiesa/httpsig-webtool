// encoding.js
// ------------------------------------------------------------------
//
// Conversions between strings and bytes, using only browser APIs.
// Encoding names match the options in the page's dropdowns.

const bytesFromBase64 = (b64) =>
  Uint8Array.from(atob(b64.replace(/\s+/g, "")), (c) => c.charCodeAt(0));

const base64FromBytes = (bytes) =>
  btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(""));

function bytesFromHex(hex) {
  const clean = hex.replace(/\s+/g, "");
  if (clean.length % 2 != 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error("invalid hex string");
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

const hexFromBytes = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function bytesFromText(text, encoding) {
  switch (encoding.toLowerCase()) {
    case "utf-8":
      return new TextEncoder().encode(text);
    case "base64":
      return bytesFromBase64(text);
    case "hex":
      return bytesFromHex(text);
  }
  throw new Error("unsupported encoding: " + encoding);
}

function textFromBytes(bytes, encoding) {
  switch (encoding.toLowerCase()) {
    case "utf-8":
      return new TextDecoder().decode(bytes);
    case "base64":
      return base64FromBytes(bytes);
    case "hex":
      return hexFromBytes(bytes);
  }
  throw new Error("unsupported encoding: " + encoding);
}

export { bytesFromText, textFromBytes, bytesFromBase64, base64FromBytes };
