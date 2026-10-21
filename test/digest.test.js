// Tests for Content-Digest (RFC 9530) support.
// Run with: npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseMessage } from "../src/js/message.js";
import { contentDigestValue, contentDigestMatches, digestAlgorithmOf, setHeader } from "../src/js/digest.js";
import { testRequest, testResponse } from "./rfc9421-vectors.js";

const headerValue = (message, name) => message.fields.find((f) => f.name == name).values[0];

test("the RFC 9421 test request and response bodies produce their Content-Digest headers", async () => {
  for (const text of [testRequest, testResponse]) {
    const msg = parseMessage(text);
    assert.equal(await contentDigestValue(msg.body, "sha-512"), headerValue(msg, "content-digest"));
    assert.equal(await contentDigestMatches(headerValue(msg, "content-digest"), msg.body), true);
  }
});

test("trailing newlines are not part of the body", () => {
  assert.equal(parseMessage(testRequest + "\n\n").body, '{"hello": "world"}');
  assert.equal(parseMessage("GET /\nHost: a.example").body, undefined);
  assert.equal(parseMessage("GET /\nHost: a.example\n").body, "");
});

test("a changed body no longer matches; sha-256 works too", async () => {
  const msg = parseMessage(testRequest);
  assert.equal(await contentDigestMatches(headerValue(msg, "content-digest"), '{"hello": "there"}'), false);
  // RFC 9530 section 2 example
  assert.equal(
    await contentDigestValue('{"hello": "world"}', "sha-256"),
    "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
  );
});

test("headers with no supported algorithm give null", async () => {
  assert.equal(await contentDigestMatches("md5=:AAAA:", "x"), null);
  assert.equal(await contentDigestMatches("not a dictionary(", "x"), null);
});

test("digestAlgorithmOf keeps the header's algorithm", () => {
  assert.equal(digestAlgorithmOf("sha-256=:AAAA:"), "sha-256");
  assert.equal(digestAlgorithmOf("md5=:AAAA:, sha-512=:AAAA:"), "sha-512");
  assert.equal(digestAlgorithmOf(undefined), "sha-512");
});

test("setHeader replaces an existing header, keeping its name and position", () => {
  const out = setHeader("POST /x\nHost: a\ncontent-digest: old\n  folded\nX-Other: 1\n\nbody", "Content-Digest", "new");
  assert.equal(out, "POST /x\nHost: a\ncontent-digest: new\nX-Other: 1\n\nbody");
});

test("setHeader adds the header at the end of the headers", () => {
  assert.equal(setHeader("POST /x\nHost: a\n\nbody", "Content-Digest", "v"), "POST /x\nHost: a\nContent-Digest: v\n\nbody");
  assert.equal(setHeader("POST /x\nHost: a", "Content-Digest", "v"), "POST /x\nHost: a\nContent-Digest: v");
});
