// digest.js
// ------------------------------------------------------------------
//
// Content-Digest (RFC 9530): computing it from a message body, checking it,
// and setting the header in the message text.
//
//   Content-Digest: sha-512=:<base64 of SHA-512(body)>:

import { parseDictionary, serializeItem, sfBytes } from "./sfv.js";
import { base64FromBytes } from "./encoding.js";

const DIGEST_ALGORITHMS = { "sha-256": "SHA-256", "sha-512": "SHA-512" };
const DEFAULT_DIGEST_ALGORITHM = "sha-512";

async function digestBytes(algorithm, body) {
  const hash = await crypto.subtle.digest(DIGEST_ALGORITHMS[algorithm], new TextEncoder().encode(body));
  return new Uint8Array(hash);
}

async function contentDigestValue(body, algorithm = DEFAULT_DIGEST_ALGORITHM) {
  if (!DIGEST_ALGORITHMS[algorithm]) {
    throw new Error(`unsupported digest algorithm: ${algorithm}`);
  }
  return `${algorithm}=${serializeItem({ ...sfBytes(await digestBytes(algorithm, body)), params: [] })}`;
}

function parseDigestHeader(headerValue) {
  try {
    return parseDictionary(headerValue);
  } catch (_e) {
    return new Map();
  }
}

// The first supported algorithm named in an existing header, else the default.
function digestAlgorithmOf(headerValue) {
  return [...parseDigestHeader(headerValue || "").keys()].find((k) => DIGEST_ALGORITHMS[k]) || DEFAULT_DIGEST_ALGORITHM;
}

// Returns true or false when the header names a supported algorithm, else
// null. Per RFC 9530, one matching supported digest is enough.
async function contentDigestMatches(headerValue, body) {
  const members = [...parseDigestHeader(headerValue)].filter(
    ([k, v]) => DIGEST_ALGORITHMS[k] && v.type == "bytes",
  );
  if (members.length == 0) {
    return null;
  }
  for (const [algorithm, member] of members) {
    const expected = base64FromBytes(await digestBytes(algorithm, body));
    if (base64FromBytes(member.value) == expected) {
      return true;
    }
  }
  return false;
}

// Replaces (or adds) a header in the message text, keeping everything else.
function setHeader(messageText, name, value) {
  const lines = messageText.replace(/\r\n/g, "\n").split("\n");
  const first = lines.findIndex((l) => l.trim() != "");
  let blank = lines.findIndex((l, i) => i > first && l.trim() == "");
  if (blank < 0) {
    blank = lines.length;
  }
  const isNamed = (line) => line.toLowerCase().startsWith(name.toLowerCase() + ":");
  const start = lines.findIndex((l, i) => i > first && i < blank && isNamed(l));
  if (start < 0) {
    lines.splice(blank, 0, `${name}: ${value}`);
  } else {
    let end = start + 1;
    while (end < blank && /^[ \t]/.test(lines[end])) {
      end++; // folded continuation lines of the old value
    }
    const existingName = lines[start].slice(0, name.length);
    lines.splice(start, end - start, `${existingName}: ${value}`);
  }
  return lines.join("\n");
}

export { contentDigestValue, contentDigestMatches, digestAlgorithmOf, setHeader };
