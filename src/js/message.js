// message.js
// ------------------------------------------------------------------
//
// Parses the HTTP message typed into the page:
//
//   POST https://example.com/foo?param=Value     (absolute form)
//   POST /foo?param=Value HTTP/1.1               (origin form; uses Host)
//   HTTP/1.1 200 OK                              (a response)
//   Header-Name: value
//   ...
//   <blank line, then an optional body>

const DEFAULT_SCHEME = "https";

function parseRequestLine(line) {
  const m = /^([A-Za-z]+)\s+(\S+)(?:\s+HTTP\/[0-9.]+)?$/.exec(line);
  if (!m) {
    throw new Error(`cannot parse the first line as a request or status line: ${line}`);
  }
  return { method: m[1], target: m[2] };
}

function parseFields(lines) {
  const fields = []; // [{ name (lowercase), values: [...] }] in first-appearance order
  let previous = null;
  for (const line of lines) {
    if (/^[ \t]/.test(line) && previous) {
      // obsolete line folding: continue the previous value
      previous.values[previous.values.length - 1] += " " + line.trim();
      continue;
    }
    const m = /^([!#$%&'*+\-.^_`|~0-9A-Za-z]+):(.*)$/.exec(line);
    if (!m) {
      throw new Error(`cannot parse header line: ${line}`);
    }
    const name = m[1].toLowerCase(),
      value = m[2].trim();
    previous = fields.find((f) => f.name == name);
    if (previous) {
      previous.values.push(value);
    } else {
      previous = { name, values: [value] };
      fields.push(previous);
    }
  }
  return fields;
}

function resolveTarget(target, fields) {
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(target)) {
    return { url: new URL(target), form: "absolute" };
  }
  if (target.startsWith("/")) {
    const host = fields.find((f) => f.name == "host");
    if (!host) {
      throw new Error("an origin-form request line (e.g. GET /path) needs a Host header");
    }
    return { url: new URL(`${DEFAULT_SCHEME}://${host.values[0]}${target}`), form: "origin" };
  }
  throw new Error(`unsupported request target: ${target}`);
}

// The body is the text after the first blank line, with trailing newlines
// removed; it is undefined when there is no blank line.
function bodyOf(lines, blank) {
  return blank < 0 ? undefined : lines.slice(blank + 1).join("\n").replace(/\n+$/, "");
}

// Returns a message object:
//   { isRequest, method, target, url, targetForm, status, fields, body }
function parseMessage(text) {
  const allLines = text.replace(/\r\n/g, "\n").split("\n");
  const firstContent = allLines.findIndex((l) => l.trim() != "");
  if (firstContent < 0) {
    throw new Error("the message is empty");
  }
  const lines = allLines.slice(firstContent);
  const blank = lines.findIndex((l, i) => i > 0 && l.trim() == "");
  const headerLines = lines.slice(1, blank < 0 ? lines.length : blank);
  const firstLine = lines[0].trim();
  const fields = parseFields(headerLines);
  const body = bodyOf(lines, blank);

  const status = /^HTTP\/[0-9.]+\s+([0-9]{3})\b/.exec(firstLine);
  if (status) {
    return { isRequest: false, status: status[1], fields, body };
  }
  const { method, target } = parseRequestLine(firstLine);
  const { url, form } = resolveTarget(target, fields);
  return { isRequest: true, method, target, url, targetForm: form, fields, body };
}

export { parseMessage };
