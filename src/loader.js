/**
 * Config discovery and normalisation.
 *
 * Every supported format is flattened into the same `Target` shape so rules
 * never need to know whether they are looking at a UTCP manual, an MCP
 * server config or an OpenAPI document.
 */

import { readFileSync, statSync, readdirSync } from 'node:fs';
import { join, relative, resolve, extname } from 'node:path';

/**
 * @typedef {Object} AuthInfo
 * @property {string} type          e.g. api_key, oauth2, basic
 * @property {string} [location]    header | query | cookie
 * @property {string} [varName]     header/query parameter name
 * @property {string} [secret]      the value as written in the file
 * @property {string} [secretField] which field the secret came from
 * @property {string} [pointer]     JSON location of the secret in the file
 */

/**
 * @typedef {Object} Target
 * @property {string} pointer       JSON pointer-ish location inside the document
 * @property {string} [toolName]
 * @property {string} url           URL or URL template
 * @property {string} [transport]
 * @property {AuthInfo|null} auth
 * @property {AuthInfo[]} [auths]    every credential found on this target
 * @property {string} [authPointer]  where the credential actually lives
 * @property {string[]} ignored     rule ids suppressed at this node
 */

/**
 * @typedef {Object} Document
 * @property {string} file
 * @property {'utcp'|'mcp'|'openapi'|'unknown'} kind
 * @property {Target[]} targets
 * @property {string[]} notes
 * @property {any} [data]           the parsed document, for document-level rules
 */

const CONFIG_EXTENSIONS = new Set(['.json', '.jsonc']);

/**
 * Advance past whitespace and comments.
 *
 * Needed for trailing-comma detection: `"a": 1, // note\n}` has its comma
 * followed by a comment, not by `}`. Skipping only whitespace misses it, and
 * that exact shape is common in hand-written configs.
 *
 * @param {string} text
 * @param {number} start
 * @returns {number}
 */
function skipTrivia(text, start) {
  const n = text.length;
  let j = start;
  while (j < n) {
    const c = text[j];
    if (/\s/.test(c)) {
      j += 1;
      continue;
    }
    if (c === '/' && text[j + 1] === '/') {
      j += 2;
      while (j < n && text[j] !== '\n') j += 1;
      continue;
    }
    if (c === '/' && text[j + 1] === '*') {
      j += 2;
      while (j < n && !(text[j] === '*' && text[j + 1] === '/')) j += 1;
      j += 2;
      continue;
    }
    break;
  }
  return j;
}

/**
 * Strip JSONC syntax (comments and trailing commas) so a config written for a
 * human can still be parsed.
 *
 * This matters more than it looks. `tsconfig.json`, `jsconfig.json`, VS Code
 * settings and a good share of hand-written MCP configs are JSONC. A linter
 * that reports "invalid JSON" on all of them is a linter people uninstall.
 *
 * The scan is a small state machine rather than a regex because `https://…`
 * inside a string value must survive untouched.
 *
 * @param {string} text
 * @returns {string}
 */
export function stripJsonc(text) {
  let out = '';
  let i = 0;
  const n = text.length;
  let inString = false;
  let inLine = false;
  let inBlock = false;

  while (i < n) {
    const ch = text[i];
    const next = text[i + 1];

    if (inLine) {
      if (ch === '\n') {
        inLine = false;
        out += ch;
      }
      i += 1;
      continue;
    }

    if (inBlock) {
      if (ch === '*' && next === '/') {
        inBlock = false;
        i += 2;
        continue;
      }
      i += 1;
      continue;
    }

    if (inString) {
      out += ch;
      if (ch === '\\') {
        out += next ?? '';
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i += 1;
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
      i += 1;
      continue;
    }

    if (ch === '/' && next === '/') {
      inLine = true;
      i += 2;
      continue;
    }

    if (ch === '/' && next === '*') {
      inBlock = true;
      i += 2;
      continue;
    }

    if (ch === ',') {
      const j = skipTrivia(text, i + 1);
      if (text[j] === '}' || text[j] === ']') {
        i += 1; // drop the trailing comma
        continue;
      }
    }

    out += ch;
    i += 1;
  }

  return out;
}

/**
 * Read and parse a JSON (or JSONC) document.
 * @param {string} file
 * @returns {{ ok: true, data: any, jsonc?: boolean } | { ok: false, error: string }}
 */
export function readJson(file) {
  let raw;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (err) {
    return { ok: false, error: `cannot read: ${err.message}` };
  }
  // Strip a UTF-8 BOM; some editors add one and JSON.parse rejects it.
  if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
  if (raw.trim() === '') {
    return { ok: false, error: 'file is empty' };
  }
  try {
    return { ok: true, data: JSON.parse(raw) };
  } catch (strictErr) {
    const cleaned = stripJsonc(raw);
    if (cleaned !== raw) {
      try {
        return { ok: true, data: JSON.parse(cleaned), jsonc: true };
      } catch {
        /* fall through to the original, more informative error */
      }
    }
    return { ok: false, error: `invalid JSON: ${strictErr.message}` };
  }
}

/**
 * Collect rule ids suppressed on a node.
 *
 * Accepts both `["R1"]` and `[{ rule: "R1", reason: "..." }]`. A bare string
 * may also carry an inline reason after a colon (`"R1: dev fixture"`).
 *
 * @param {any} node
 * @returns {string[]}
 */
function suppressedAt(node) {
  if (!node || typeof node !== 'object') return [];
  const raw = node._utcpLintIgnore ?? node['x-utcp-lint-ignore'];
  if (!raw) return [];
  const list = Array.isArray(raw) ? raw : [raw];
  const out = [];
  for (const item of list) {
    if (typeof item === 'string') {
      out.push(item.split(':')[0].trim());
    } else if (item && typeof item === 'object' && typeof item.rule === 'string') {
      out.push(item.rule.trim());
    }
  }
  return out;
}

/**
 * Normalise the many auth shapes UTCP and MCP use into one object.
 * @param {any} auth
 * @returns {AuthInfo|null}
 */
function normalizeAuth(auth) {
  if (!auth || typeof auth !== 'object') return null;

  const type = String(auth.auth_type ?? auth.type ?? 'unknown');

  if (type === 'api_key' || type === 'apikey') {
    const secretField = auth.api_key !== undefined ? 'api_key' : 'value';
    return {
      type,
      location: auth.location,
      varName: auth.var_name ?? auth.name,
      secret: auth.api_key ?? auth.value,
      secretField,
    };
  }

  if (type === 'oauth2') {
    // client_secret is the credential that must never be inlined.
    return {
      type,
      location: auth.location,
      varName: auth.var_name,
      secret: auth.client_secret,
      secretField: 'client_secret',
    };
  }

  if (type === 'basic') {
    return {
      type,
      location: 'header',
      varName: 'Authorization',
      secret: auth.password ?? auth.token,
      secretField: auth.password !== undefined ? 'password' : 'token',
    };
  }

  // Unknown auth type: still surface whatever looks like a secret so R3 can
  // judge it rather than silently passing.
  const guess = auth.api_key ?? auth.token ?? auth.secret ?? auth.password;
  return {
    type,
    location: auth.location,
    varName: auth.var_name ?? auth.name,
    secret: guess,
    secretField: guess === undefined ? undefined : 'value',
  };
}

/**
 * Pull the URL out of any call-template / transport shape.
 * @param {any} node
 * @returns {string|null}
 */
function pickUrl(node) {
  if (!node || typeof node !== 'object') return null;
  const candidates = [node.url, node.baseUrl, node.base_url, node.endpoint, node.server_url];
  for (const c of candidates) {
    if (typeof c === 'string' && c.trim() !== '') return c;
  }
  return null;
}

/**
 * Walk a UTCP manual.
 * @param {any} doc
 * @param {string} file
 * @returns {Document}
 */
function parseUtcp(doc, file) {
  const targets = [];
  const notes = [];
  const tools = Array.isArray(doc.tools) ? doc.tools : [];

  tools.forEach((tool, i) => {
    if (!tool || typeof tool !== 'object') return;
    // `tool_call_template` is the current field; `tool_transport` is the
    // pre-1.0 spelling that still appears in the wild.
    const template = tool.tool_call_template ?? tool.tool_transport ?? tool.transport;
    const url = pickUrl(template);
    const inherited = suppressedAt(tool);

    if (!url) {
      notes.push(`tools[${i}] has no URL (transport may be cli/text); skipped by URL rules`);
      return;
    }

    const toolAuth = normalizeAuth(template?.auth);
    targets.push({
      pointer: `tools[${i}].tool_call_template.url`,
      toolName: typeof tool.name === 'string' ? tool.name : `tools[${i}]`,
      url,
      transport: template?.call_template_type ?? template?.transport_type,
      auth: toolAuth,
      auths: toolAuth
        ? [{ ...toolAuth, pointer: `tools[${i}].tool_call_template.auth.${toolAuth.secretField}` }]
        : [],
      ignored: [...inherited, ...suppressedAt(template)],
    });
  });

  // A manual may also carry a manual-level auth block that every tool inherits.
  const manualAuth = normalizeAuth(doc.auth);
  if (manualAuth && targets.length > 0) {
    for (const t of targets) {
      if (!t.auth) {
        t.auth = manualAuth;
        t.auths = [{ ...manualAuth, pointer: 'auth' }];
      }
    }
  }

  // Client-side config: manual_call_templates[].
  const calls = Array.isArray(doc.manual_call_templates) ? doc.manual_call_templates : [];
  calls.forEach((entry, i) => {
    const url = pickUrl(entry);
    if (!url) return;
    targets.push({
      pointer: `manual_call_templates[${i}].url`,
      toolName: typeof entry.name === 'string' ? entry.name : `manual_call_templates[${i}]`,
      url,
      transport: entry.call_template_type,
      auth: normalizeAuth(entry.auth),
      ignored: [...suppressedAt(entry)],
    });
  });

  return { file, kind: 'utcp', targets, notes, data: doc };
}

/**
 * Walk an MCP client config (`mcpServers` map).
 * @param {any} doc
 * @param {string} file
 * @returns {Document}
 */
function parseMcp(doc, file) {
  const targets = [];
  const notes = [];
  const servers = doc.mcpServers ?? doc.servers ?? {};

  if (servers && typeof servers === 'object' && !Array.isArray(servers)) {
    for (const [name, server] of Object.entries(servers)) {
      if (!server || typeof server !== 'object') continue;
      const url = pickUrl(server);
      if (!url) {
        // stdio transport: command + args. No URL, but env vars may still
        // hold credentials; that is out of scope for R1/R3 in 0.1.0.
        notes.push(`mcpServers.${name} uses a local command transport; no URL to check`);
        continue;
      }
      const headers = server.headers && typeof server.headers === 'object' ? server.headers : {};
      const structured = normalizeAuth(server.auth);
      const auths = [];
      if (structured) {
        auths.push({ ...structured, pointer: `mcpServers.${name}.auth.${structured.secretField}` });
      }
      for (const h of headerAuths(headers)) {
        auths.push({ ...h, pointer: `mcpServers.${name}.headers.${h.varName}` });
      }
      targets.push({
        pointer: `mcpServers.${name}.url`,
        toolName: name,
        url,
        transport: server.type ?? server.transport ?? 'http',
        auth: auths[0] ?? null,
        auths,
        ignored: [...suppressedAt(server)],
      });
    }
  }

  return { file, kind: 'mcp', targets, notes, data: doc };
}

/**
 * Treat every credential-shaped header as auth material so R3 can judge it
 * even when there is no structured `auth` block. Returns all of them: a config
 * carrying both `Authorization` and `X-Api-Key` leaks both.
 * @param {Record<string, any>} headers
 * @returns {AuthInfo[]}
 */
function headerAuths(headers) {
  const out = [];
  for (const [name, value] of Object.entries(headers)) {
    if (typeof value !== 'string') continue;
    if (!/authorization|api[-_]?key|token|secret/i.test(name)) continue;
    out.push({ type: 'header', location: 'header', varName: name, secret: value, secretField: name });
  }
  return out;
}

/**
 * Walk an OpenAPI / Swagger document.
 * @param {any} doc
 * @param {string} file
 * @returns {Document}
 */
function parseOpenApi(doc, file) {
  const targets = [];
  const notes = [];
  const servers = Array.isArray(doc.servers) ? doc.servers : [];

  servers.forEach((server, i) => {
    const url = pickUrl(server);
    if (!url) return;
    targets.push({
      pointer: `servers[${i}].url`,
      toolName: typeof server.description === 'string' ? server.description : `servers[${i}]`,
      url,
      transport: 'http',
      auth: null,
      ignored: [...suppressedAt(server)],
    });
  });

  // Swagger 2.0 puts the base URL in three separate fields.
  if (typeof doc.host === 'string' && doc.host !== '') {
    const scheme = Array.isArray(doc.schemes) && doc.schemes.length > 0 ? doc.schemes[0] : 'https';
    const basePath = typeof doc.basePath === 'string' ? doc.basePath : '';
    targets.push({
      pointer: 'host',
      toolName: 'swagger host',
      url: `${scheme}://${doc.host}${basePath}`,
      transport: 'http',
      auth: null,
      ignored: [...suppressedAt(doc)],
    });
  }

  if (targets.length === 0) notes.push('no servers[] and no host; nothing to check');

  return { file, kind: 'openapi', targets, notes, data: doc };
}

/**
 * Decide which parser applies, based on structural signals rather than the
 * filename — configs get renamed constantly.
 * @param {any} doc
 * @returns {'utcp'|'mcp'|'openapi'|'unknown'}
 */
export function detectKind(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return 'unknown';
  if (typeof doc.utcp_version === 'string' || Array.isArray(doc.tools) || Array.isArray(doc.manual_call_templates)) {
    return 'utcp';
  }
  if (doc.mcpServers && typeof doc.mcpServers === 'object') return 'mcp';
  if (typeof doc.openapi === 'string' || typeof doc.swagger === 'string') return 'openapi';
  if (Array.isArray(doc.servers)) return 'openapi';
  return 'unknown';
}

/**
 * Load one document.
 * @param {string} file
 * @returns {Document}
 */
export function loadDocument(file) {
  const parsed = readJson(file);
  if (!parsed.ok) {
    return { file, kind: 'unknown', targets: [], notes: [], error: parsed.error };
  }
  const kind = detectKind(parsed.data);
  switch (kind) {
    case 'utcp':
      return parseUtcp(parsed.data, file);
    case 'mcp':
      return parseMcp(parsed.data, file);
    case 'openapi':
      return parseOpenApi(parsed.data, file);
    default:
      return {
        file,
        kind: 'unknown',
        targets: [],
        notes: ['unrecognised document shape; expected UTCP manual, MCP config or OpenAPI'],
        data: parsed.data,
      };
  }
}

/**
 * Expand the CLI inputs into a list of files.
 * @param {string[]} inputs
 * @param {string} cwd
 * @returns {string[]}
 */
export function expandInputs(inputs, cwd = process.cwd()) {
  const files = [];
  for (const input of inputs) {
    const abs = resolve(cwd, input);
    let st;
    try {
      st = statSync(abs);
    } catch {
      files.push(abs); // let the loader report the read error
      continue;
    }
    if (st.isDirectory()) {
      walk(abs, files);
    } else {
      files.push(abs);
    }
  }
  return [...new Set(files)];
}

/**
 * Depth-first walk collecting config-looking JSON files.
 * @param {string} dir
 * @param {string[]} out
 * @param {number} [depth]
 */
function walk(dir, out, depth = 0) {
  if (depth > 8) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, out, depth + 1);
    } else if (entry.isFile() && CONFIG_EXTENSIONS.has(extname(entry.name))) {
      out.push(full);
    }
  }
}

/**
 * Human-friendly relative path for output.
 * @param {string} file
 * @param {string} cwd
 * @returns {string}
 */
export function displayPath(file, cwd = process.cwd()) {
  const rel = relative(cwd, file);
  return rel === '' || rel.startsWith('..') ? file : rel;
}
