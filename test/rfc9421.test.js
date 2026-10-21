// Tests for the RFC 9421 implementation, using the RFC's Appendix B vectors.
// Run with: npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseMessage } from "../src/js/message.js";
import {
  availableComponents,
  isDefaultCovered,
  buildSignatureParams,
  signatureBase,
  signatureFields,
  parseSignatureFields,
} from "../src/js/rfc9421.js";
import { importPemKey, importHmacKey, sign, verify, generateKeyPair } from "../src/js/sigcrypto.js";
import { bytesFromBase64, base64FromBytes } from "../src/js/encoding.js";
import { keys, testRequest, testResponse, cases } from "./rfc9421-vectors.js";

const VECTORS = {
  "B.2.1": { message: testRequest, alg: "rsa-pss-sha512", publicKey: keys.rsaPssPublic },
  "B.2.2": { message: testRequest, alg: "rsa-pss-sha512", publicKey: keys.rsaPssPublic },
  "B.2.3": { message: testRequest, alg: "rsa-pss-sha512", publicKey: keys.rsaPssPublic },
  "B.2.4": { message: testResponse, alg: "ecdsa-p256-sha256", publicKey: keys.eccP256Public },
  "B.2.5": { message: testRequest, alg: "hmac-sha256" },
  "B.2.6": { message: testRequest, alg: "ed25519", publicKey: keys.ed25519Public },
};

const hmacKey = () => importHmacKey(bytesFromBase64(keys.sharedSecret));

// Rebuild the signature base from the message plus the parameters in the
// RFC's Signature-Input, as a verifier would.
function rebuild(id) {
  const { message, alg } = VECTORS[id];
  const c = cases[id];
  const parsed = parseSignatureFields(c.signatureInput, c.signature);
  const msg = parseMessage(message);
  return { alg, msg, parsed, base: signatureBase(msg, parsed.signatureParams) };
}

for (const id of Object.keys(VECTORS)) {
  test(`${id}: signature base matches the RFC`, () => {
    assert.equal(rebuild(id).base, cases[id].base);
  });

  test(`${id}: the RFC signature verifies`, async () => {
    const { alg, parsed, base } = rebuild(id);
    const key = alg == "hmac-sha256" ? await hmacKey() : await importPemKey(alg, VECTORS[id].publicKey, "verify");
    assert.equal(await verify(alg, key, base, parsed.signatureBytes), true);
  });

  test(`${id}: Signature-Input re-serializes identically`, () => {
    const { parsed } = rebuild(id);
    const fields = signatureFields(parsed.label, parsed.signatureParams, parsed.signatureBytes);
    assert.equal(fields.signatureInput, cases[id].signatureInput);
    assert.equal(fields.signature, cases[id].signature);
  });
}

test("B.2.2: building the parameters from scratch gives the RFC base", () => {
  const msg = parseMessage(testRequest);
  const params = buildSignatureParams(['"@authority"', '"content-digest"', '"@query-param";name="Pet"'], {
    created: 1618884473,
    keyid: "test-key-rsa-pss",
    tag: "header-example",
  });
  assert.equal(signatureBase(msg, params), cases["B.2.2"].base);
});

test("B.2.5: hmac-sha256 signature matches the RFC exactly", async () => {
  const { base } = rebuild("B.2.5");
  const signature = await sign("hmac-sha256", await hmacKey(), base);
  assert.equal(`sig-b25=:${base64FromBytes(signature)}:`, cases["B.2.5"].signature);
});

test("B.2.6: ed25519 signature matches the RFC exactly", async () => {
  const { base } = rebuild("B.2.6");
  const key = await importPemKey("ed25519", keys.ed25519Private, "sign");
  const signature = await sign("ed25519", key, base);
  assert.equal(`sig-b26=:${base64FromBytes(signature)}:`, cases["B.2.6"].signature);
});

test("test-key-rsa-pss private key (PKCS#8 tagged RSASSA-PSS) signs verifiably", async () => {
  const { base } = rebuild("B.2.3");
  const signature = await sign("rsa-pss-sha512", await importPemKey("rsa-pss-sha512", keys.rsaPssPrivate, "sign"), base);
  const publicKey = await importPemKey("rsa-pss-sha512", keys.rsaPssPublic, "verify");
  assert.equal(await verify("rsa-pss-sha512", publicKey, base, signature), true);
});

test("rsa-v1_5-sha256 with test-key-rsa (PKCS#1 private and public keys)", async () => {
  const { base } = rebuild("B.2.3");
  const signature = await sign("rsa-v1_5-sha256", await importPemKey("rsa-v1_5-sha256", keys.rsaPrivate, "sign"), base);
  const publicKey = await importPemKey("rsa-v1_5-sha256", keys.rsaPublic, "verify");
  assert.equal(await verify("rsa-v1_5-sha256", publicKey, base, signature), true);
});

test("ecdsa-p256-sha256 with test-key-ecc-p256 (SEC1 private key)", async () => {
  const { base } = rebuild("B.2.4");
  const signature = await sign("ecdsa-p256-sha256", await importPemKey("ecdsa-p256-sha256", keys.eccP256Private, "sign"), base);
  assert.equal(signature.length, 64);
  const publicKey = await importPemKey("ecdsa-p256-sha256", keys.eccP256Public, "verify");
  assert.equal(await verify("ecdsa-p256-sha256", publicKey, base, signature), true);
});

for (const alg of ["rsa-pss-sha512", "rsa-v1_5-sha256", "ecdsa-p256-sha256", "ecdsa-p384-sha384", "ed25519"]) {
  test(`${alg}: generated keypair signs and verifies; tampering fails`, async () => {
    const { publicKey, privateKey } = await generateKeyPair(alg);
    const { base } = rebuild("B.2.3");
    const signature = await sign(alg, await importPemKey(alg, privateKey, "sign"), base);
    const verifyKey = await importPemKey(alg, publicKey, "verify");
    assert.equal(await verify(alg, verifyKey, base, signature), true);
    assert.equal(await verify(alg, verifyKey, base + " ", signature), false);
  });
}

test("query parameters are decoded and re-encoded (RFC 9421 section 2.2.8)", () => {
  const msg = parseMessage(
    "GET /parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something HTTP/1.1\nHost: www.example.com",
  );
  const params = buildSignatureParams(
    ['"@query-param";name="var"', '"@query-param";name="bar"', '"@query-param";name="fa%C3%A7ade%22%3A%20"'],
    {},
  );
  assert.equal(
    signatureBase(msg, params),
    [
      '"@query-param";name="var": this%20is%20a%20big%0Amultiline%20value',
      '"@query-param";name="bar": with%20plus%20whitespace',
      '"@query-param";name="fa%C3%A7ade%22%3A%20": something',
      '"@signature-params": ("@query-param";name="var" "@query-param";name="bar" "@query-param";name="fa%C3%A7ade%22%3A%20")',
    ].join("\n"),
  );
});

test("derived components for an absolute-form request", () => {
  const msg = parseMessage("GET HTTPS://WWW.Example.com:443/a%20b?x=1 \nAccept: */*");
  const ids = ['"@method"', '"@target-uri"', '"@authority"', '"@scheme"', '"@request-target"', '"@path"', '"@query"'];
  const lines = signatureBase(msg, buildSignatureParams(ids, {})).split("\n");
  assert.deepEqual(lines.slice(0, 7), [
    '"@method": GET',
    '"@target-uri": https://www.example.com/a%20b?x=1',
    '"@authority": www.example.com',
    '"@scheme": https',
    '"@request-target": HTTPS://WWW.Example.com:443/a%20b?x=1',
    '"@path": /a%20b',
    '"@query": ?x=1',
  ]);
});

test("repeated and folded header fields are combined (RFC 9421 section 2.1)", () => {
  const msg = parseMessage(
    "GET /\nHost: www.example.com\nX-Obs-Fold-Header: Obsolete\n    line folding.\nCache-Control: max-age=60\nCache-Control:    must-revalidate\nX-Empty-Header: ",
  );
  const base = signatureBase(msg, buildSignatureParams(['"x-obs-fold-header"', '"cache-control"', '"x-empty-header"'], {}));
  assert.deepEqual(base.split("\n").slice(0, 3), [
    '"x-obs-fold-header": Obsolete line folding.',
    '"cache-control": max-age=60, must-revalidate',
    '"x-empty-header": ',
  ]);
});

test("available components and defaults", () => {
  const msg = parseMessage(testRequest);
  const ids = availableComponents(msg);
  assert.deepEqual(ids, [
    '"@method"',
    '"@target-uri"',
    '"@authority"',
    '"@scheme"',
    '"@request-target"',
    '"@path"',
    '"@query"',
    '"@query-param";name="param"',
    '"@query-param";name="Pet"',
    '"host"',
    '"date"',
    '"content-type"',
    '"content-digest"',
    '"content-length"',
  ]);
  assert.deepEqual(
    ids.filter(isDefaultCovered),
    ['"@method"', '"@authority"', '"@path"', '"date"', '"content-type"', '"content-digest"', '"content-length"'],
  );
  assert.deepEqual(availableComponents(parseMessage(testResponse)).slice(0, 2), ['"@status"', '"date"']);
});

test("errors: missing header, unsupported parameter, duplicate component, label mismatch", () => {
  const msg = parseMessage(testRequest);
  assert.throws(() => signatureBase(msg, buildSignatureParams(['"x-missing"'], {})), /not in the message/);
  assert.throws(() => signatureBase(msg, buildSignatureParams(['"date";sf'], {})), /not supported/);
  assert.throws(() => signatureBase(msg, buildSignatureParams(['"date"', '"date"'], {})), /more than once/);
  assert.throws(() => parseSignatureFields("a=()", "b=:AAAA:"), /no signature label/);
});

test("pasted fields may include the field names and line breaks", () => {
  const c = cases["B.2.5"];
  const parsed = parseSignatureFields(`Signature-Input: ${c.signatureInput}`, `Signature:\n  ${c.signature}`);
  assert.equal(parsed.label, "sig-b25");
  assert.equal(parsed.params.keyid, "test-shared-secret");
});
