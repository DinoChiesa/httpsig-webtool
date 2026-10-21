// sfv.js
// ------------------------------------------------------------------
//
// The subset of HTTP Structured Field Values (RFC 8941) that RFC 9421 needs:
// parsing Dictionaries (Signature-Input, Signature) and strict serialization
// of Items, Inner Lists and Parameters.
//
// Bare items are represented as { type, value }, with type one of
// "integer", "decimal", "string", "token", "bytes" (value is a Uint8Array),
// or "boolean". An Inner List is { type: "innerlist", value: [ items ] }.
// Items and Inner Lists carry params: an array of [key, bareItem] pairs.

import { bytesFromBase64, base64FromBytes } from "./encoding.js";

const sfString = (value) => ({ type: "string", value });
const sfInteger = (value) => ({ type: "integer", value });
const sfBoolean = (value) => ({ type: "boolean", value });
const sfBytes = (value) => ({ type: "bytes", value });

class Parser {
  constructor(input) {
    this.input = input;
    this.pos = 0;
  }

  fail(message) {
    throw new Error(`${message} at position ${this.pos}`);
  }

  peek() {
    return this.input.charAt(this.pos);
  }

  atEnd() {
    return this.pos >= this.input.length;
  }

  skip(chars) {
    while (!this.atEnd() && chars.includes(this.peek())) {
      this.pos++;
    }
  }

  expect(c) {
    if (this.peek() != c) {
      this.fail(`expected '${c}'`);
    }
    this.pos++;
  }

  parseKey() {
    const m = /^[a-z*][a-z0-9_\-.*]*/.exec(this.input.slice(this.pos));
    if (!m) {
      this.fail("invalid key");
    }
    this.pos += m[0].length;
    return m[0];
  }

  parseBareItem() {
    const c = this.peek();
    if (c == "-" || /[0-9]/.test(c)) return this.parseNumber();
    if (c == '"') return this.parseString();
    if (c == ":") return this.parseBytes();
    if (c == "?") return this.parseBoolean();
    if (c == "*" || /[A-Za-z]/.test(c)) return this.parseToken();
    this.fail("unexpected character");
  }

  parseNumber() {
    const m = /^-?[0-9]{1,15}(\.[0-9]{1,3})?/.exec(this.input.slice(this.pos));
    if (!m) {
      this.fail("invalid number");
    }
    this.pos += m[0].length;
    return m[1]
      ? { type: "decimal", value: Number(m[0]) }
      : sfInteger(Number(m[0]));
  }

  parseString() {
    this.expect('"');
    let out = "";
    while (!this.atEnd()) {
      const c = this.input.charAt(this.pos++);
      if (c == "\\") {
        const next = this.input.charAt(this.pos++);
        if (next != '"' && next != "\\") {
          this.fail("invalid escape in string");
        }
        out += next;
      } else if (c == '"') {
        return sfString(out);
      } else if (c < " " || c > "~") {
        this.fail("invalid character in string");
      } else {
        out += c;
      }
    }
    this.fail("unterminated string");
  }

  parseToken() {
    const m = /^[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*/.exec(this.input.slice(this.pos));
    this.pos += m[0].length;
    return { type: "token", value: m[0] };
  }

  parseBytes() {
    this.expect(":");
    const end = this.input.indexOf(":", this.pos);
    if (end < 0) {
      this.fail("unterminated byte sequence");
    }
    const b64 = this.input.slice(this.pos, end);
    if (/[^A-Za-z0-9+/=]/.test(b64)) {
      this.fail("invalid byte sequence");
    }
    this.pos = end + 1;
    return sfBytes(bytesFromBase64(b64));
  }

  parseBoolean() {
    this.expect("?");
    const c = this.input.charAt(this.pos++);
    if (c != "0" && c != "1") {
      this.fail("invalid boolean");
    }
    return sfBoolean(c == "1");
  }

  parseParams() {
    const params = [];
    while (this.peek() == ";") {
      this.pos++;
      this.skip(" ");
      const key = this.parseKey();
      let value = sfBoolean(true);
      if (this.peek() == "=") {
        this.pos++;
        value = this.parseBareItem();
      }
      const existing = params.findIndex(([k]) => k == key);
      if (existing >= 0) {
        params.splice(existing, 1);
      }
      params.push([key, value]);
    }
    return params;
  }

  parseInnerList() {
    this.expect("(");
    const items = [];
    for (;;) {
      this.skip(" ");
      if (this.peek() == ")") {
        this.pos++;
        return { type: "innerlist", value: items, params: this.parseParams() };
      }
      const item = this.parseBareItem();
      item.params = this.parseParams();
      items.push(item);
      if (this.peek() != " " && this.peek() != ")") {
        this.fail("expected space or ')' in inner list");
      }
    }
  }

  parseItemOrInnerList() {
    if (this.peek() == "(") {
      return this.parseInnerList();
    }
    const item = this.parseBareItem();
    item.params = this.parseParams();
    return item;
  }
}

// Returns a Map from member key to Item or Inner List, in order.
function parseDictionary(input) {
  const parser = new Parser(input.trim());
  const members = new Map();
  while (!parser.atEnd()) {
    const key = parser.parseKey();
    let member;
    if (parser.peek() == "=") {
      parser.pos++;
      member = parser.parseItemOrInnerList();
    } else {
      member = sfBoolean(true);
      member.params = parser.parseParams();
    }
    members.delete(key);
    members.set(key, member);
    parser.skip(" \t");
    if (parser.atEnd()) {
      break;
    }
    parser.expect(",");
    parser.skip(" \t");
    if (parser.atEnd()) {
      parser.fail("trailing comma");
    }
  }
  return members;
}

// Parses a single Item, e.g. a component identifier like "@query-param";name="x".
function parseItem(input) {
  const parser = new Parser(input.trim());
  const item = parser.parseBareItem();
  item.params = parser.parseParams();
  if (!parser.atEnd()) {
    parser.fail("unexpected trailing characters");
  }
  return item;
}

function serializeString(value) {
  if (/[^\x20-\x7e]/.test(value)) {
    throw new Error("strings must be printable ASCII: " + JSON.stringify(value));
  }
  return '"' + value.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}

function serializeBareItem(item) {
  switch (item.type) {
    case "integer":
      return String(item.value);
    case "decimal":
      return Number.isInteger(item.value) ? item.value.toFixed(1) : String(item.value);
    case "string":
      return serializeString(item.value);
    case "token":
      return item.value;
    case "bytes":
      return ":" + base64FromBytes(item.value) + ":";
    case "boolean":
      return item.value ? "?1" : "?0";
  }
  throw new Error("cannot serialize item of type " + item.type);
}

function serializeParams(params = []) {
  return params
    .map(([key, value]) =>
      value.type == "boolean" && value.value ? `;${key}` : `;${key}=${serializeBareItem(value)}`,
    )
    .join("");
}

const serializeItem = (item) => serializeBareItem(item) + serializeParams(item.params);

const serializeInnerList = (list) =>
  "(" + list.value.map(serializeItem).join(" ") + ")" + serializeParams(list.params);

const serializeMember = (member) =>
  member.type == "innerlist" ? serializeInnerList(member) : serializeItem(member);

export {
  parseDictionary,
  parseItem,
  serializeItem,
  serializeInnerList,
  serializeMember,
  serializeString,
  sfString,
  sfInteger,
  sfBoolean,
  sfBytes,
};
