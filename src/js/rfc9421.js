// rfc9421.js
// ------------------------------------------------------------------
//
// RFC 9421 HTTP Message Signatures: component values, the signature base,
// and the Signature-Input / Signature fields. No DOM access, so this can be
// tested outside the browser.

import {
  parseDictionary,
  parseItem,
  serializeItem,
  serializeInnerList,
  sfString,
  sfInteger,
  sfBytes,
} from "./sfv.js";

// Signature parameters, in the order they are serialized.
const SIGNATURE_PARAMS = ["created", "expires", "keyid", "alg", "nonce", "tag"];
const INTEGER_PARAMS = ["created", "expires"];

// Fields that carry signatures; never offered as covered components.
const SIGNATURE_FIELDS = ["signature", "signature-input"];

const REQUEST_DERIVED = [
  "@method",
  "@target-uri",
  "@authority",
  "@scheme",
  "@request-target",
  "@path",
  "@query",
];

// "application/x-www-form-urlencoded percent-encode set", without
// space-as-plus: everything but ASCII alphanumerics and *-._ is encoded.
function formPercentEncode(text) {
  return Array.from(new TextEncoder().encode(text), (b) => {
    const c = String.fromCharCode(b);
    return /[A-Za-z0-9*\-._]/.test(c) ? c : "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }).join("");
}

function queryParams(url) {
  return Array.from(new URLSearchParams(url.search), ([name, value]) => ({
    name: formPercentEncode(name),
    value: formPercentEncode(value),
  }));
}

const identifier = (name, params = []) => serializeItem({ ...sfString(name), params });

// The component identifiers available in a message, in display order.
function availableComponents(message) {
  const derived = message.isRequest
    ? [
        ...REQUEST_DERIVED.map((name) => identifier(name)),
        ...queryParams(message.url).map((p) => identifier("@query-param", [["name", sfString(p.name)]])),
      ]
    : [identifier("@status")];
  const fields = message.fields
    .filter((f) => !SIGNATURE_FIELDS.includes(f.name))
    .map((f) => identifier(f.name));
  return [...new Set([...derived, ...fields])];
}

// Checked by default: method, authority and path (or status), plus every
// header except Host, which RFC 9421 says to cover via @authority instead.
function isDefaultCovered(componentId) {
  const { value: name } = parseItem(componentId);
  if (name.startsWith("@")) {
    return ["@method", "@authority", "@path", "@status"].includes(name);
  }
  return name != "host";
}

function requireRequest(message, name) {
  if (!message.isRequest) {
    throw new Error(`${name} applies only to requests`);
  }
}

function derivedValue(name, params, message) {
  const paramNames = params.map(([k]) => k);
  const allowed = name == "@query-param" ? ["name"] : [];
  const unsupported = paramNames.filter((p) => !allowed.includes(p));
  if (unsupported.length) {
    throw new Error(`unsupported parameter ;${unsupported[0]} on ${name}`);
  }
  if (name == "@status") {
    if (message.isRequest) {
      throw new Error("@status applies only to responses");
    }
    return message.status;
  }
  requireRequest(message, name);
  const url = message.url;
  switch (name) {
    case "@method":
      return message.method;
    case "@target-uri":
      return url.href.replace(/#.*$/, "");
    case "@authority":
      return url.host;
    case "@scheme":
      return url.protocol.replace(/:$/, "").toLowerCase();
    case "@request-target":
      return message.target;
    case "@path":
      return url.pathname || "/";
    case "@query":
      return "?" + url.search.replace(/^\?/, "");
    case "@query-param": {
      const nameParam = params.find(([k]) => k == "name");
      if (!nameParam || nameParam[1].type != "string") {
        throw new Error('@query-param needs a ;name="..." parameter');
      }
      const matches = queryParams(url).filter((p) => p.name == nameParam[1].value);
      if (matches.length != 1) {
        throw new Error(
          matches.length == 0
            ? `query parameter "${nameParam[1].value}" is not in the message`
            : `query parameter "${nameParam[1].value}" occurs more than once`,
        );
      }
      return matches[0].value;
    }
  }
  throw new Error(`unknown derived component: ${name}`);
}

function fieldValue(name, params, message) {
  if (params.length) {
    // sf, key, bs, req, tr
    throw new Error(`component parameter ;${params[0][0]} on "${name}" is not supported by this tool`);
  }
  if (name != name.toLowerCase()) {
    throw new Error(`field names must be lowercase: "${name}"`);
  }
  const field = message.fields.find((f) => f.name == name);
  if (!field) {
    throw new Error(`the header "${name}" is not in the message`);
  }
  return field.values.map((v) => v.trim()).join(", ");
}

function componentValue(item, message) {
  if (item.type != "string") {
    throw new Error("component identifiers must be strings");
  }
  return item.value.startsWith("@")
    ? derivedValue(item.value, item.params || [], message)
    : fieldValue(item.value, item.params || [], message);
}

// params: { created, expires, keyid, alg, nonce, tag }; absent/empty ones are skipped.
function buildSignatureParams(componentIds, params) {
  const items = componentIds.map((id) => parseItem(id));
  const sfParams = SIGNATURE_PARAMS.filter((k) => params[k] !== undefined && params[k] !== "").map((k) => [
    k,
    INTEGER_PARAMS.includes(k) ? sfInteger(Number(params[k])) : sfString(String(params[k])),
  ]);
  return { type: "innerlist", value: items, params: sfParams };
}

function signatureBase(message, signatureParams) {
  const seen = new Set();
  const lines = signatureParams.value.map((item) => {
    const id = serializeItem(item);
    if (seen.has(id)) {
      throw new Error(`component ${id} is listed more than once`);
    }
    seen.add(id);
    return `${id}: ${componentValue(item, message)}`;
  });
  lines.push(`"@signature-params": ${serializeInnerList(signatureParams)}`);
  const base = lines.join("\n");
  if (/[^\x00-\x7f]/.test(base)) {
    throw new Error("the signature base contains non-ASCII characters");
  }
  return base;
}

function signatureFields(label, signatureParams, signatureBytes) {
  return {
    signatureInput: `${label}=${serializeInnerList(signatureParams)}`,
    signature: `${label}=${serializeItem({ ...sfBytes(signatureBytes), params: [] })}`,
  };
}

const stripFieldName = (text, name) =>
  text
    .trim()
    .replace(new RegExp(`^${name}\\s*:\\s*`, "i"), "")
    .replace(/\s*\n\s*/g, " ");

// Reads pasted Signature-Input and Signature values (with or without the
// field name) and returns the signature for `label`, or the first label
// present in both.
function parseSignatureFields(signatureInputText, signatureText, label) {
  const inputs = parseDictionary(stripFieldName(signatureInputText, "Signature-Input")),
    signatures = parseDictionary(stripFieldName(signatureText, "Signature"));
  const chosen = label && inputs.has(label) ? label : [...inputs.keys()].find((k) => signatures.has(k));
  if (!chosen) {
    throw new Error("no signature label appears in both Signature-Input and Signature");
  }
  if (!signatures.has(chosen)) {
    throw new Error(`the Signature field has no entry for label "${chosen}"`);
  }
  const signatureParams = inputs.get(chosen),
    signature = signatures.get(chosen);
  if (signatureParams.type != "innerlist") {
    throw new Error(`Signature-Input "${chosen}" is not an inner list`);
  }
  if (signature.type != "bytes") {
    throw new Error(`Signature "${chosen}" is not a byte sequence`);
  }
  const params = Object.fromEntries(signatureParams.params.map(([k, v]) => [k, v.value]));
  return { label: chosen, signatureParams, params, signatureBytes: signature.value };
}

export {
  availableComponents,
  isDefaultCovered,
  buildSignatureParams,
  signatureBase,
  signatureFields,
  parseSignatureFields,
  componentValue,
};
