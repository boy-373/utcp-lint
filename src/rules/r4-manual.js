/**
 * R4 — The manual must be a manual the client can actually load.
 *
 * This rule exists because of a mistake we made ourselves. The first version of
 * the Mycel manual carried an `info` block — a natural thing to write, and the
 * shape every other API description format uses. `python-utcp` rejected the
 * whole document with:
 *
 *   TypeError: UtcpManual.__init__() got an unexpected keyword argument 'info'
 *
 * The manual had been published and served over HTTPS for an hour before
 * anyone tried to register it. Every URL check passed, because the URLs were
 * fine. The document was simply not a manual.
 *
 * `UtcpManual.model_fields` is exactly `utcp_version`, `manual_version`,
 * `tools`. Anything else is a hard failure at load time, and load time is when
 * the client is already running — in CI that is a green build that produces a
 * broken agent.
 *
 * A linter that only checks addresses will never catch this. It is not a
 * security bug; it is a schema bug, and it fails the same way a bad address
 * does: at the worst possible moment.
 */

export const id = 'R4';
export const title = 'Manual will not load in a UTCP client';
export const scope = 'document';

/**
 * The only fields `UtcpManual` accepts. Kept as an explicit list rather than
 * derived from a dependency: this package has no runtime dependencies, and
 * pinning the list makes a version bump a deliberate act.
 *
 * Source: `utcp.utcp_client.UtcpManual.model_fields` in python-utcp 1.2.0.
 */
const MANUAL_FIELDS = new Set(['utcp_version', 'manual_version', 'tools']);

/**
 * Field names that show up in hand-written manuals because every other spec
 * format has them. Naming them makes the message actionable instead of a bare
 * "unexpected field".
 */
const LIKELY_MISTAKES = {
  info: 'the OpenAPI `info` block has no equivalent in a UTCP manual — move the text into the tool descriptions',
  metadata: 'there is no `metadata` block; use `manual_version` for versioning',
  description: 'a manual has no top-level description — describe each tool instead',
  name: 'the manual has no `name` field; the name is set when the client registers it',
  version: 'the field is `manual_version`, not `version`',
  tools_list: 'the field is `tools`, not `tools_list`',
  auth: 'a manual-level `auth` block is not part of UtcpManual — put `auth` inside each tool\'s `tool_call_template`',
};

/**
 * Versions of the protocol this tool knows about. An unknown version is a
 * warning, not an error: a newer client may accept more than we know about.
 */
const KNOWN_PROTOCOL_VERSIONS = new Set(['1.0.0', '1.0', '1.1.0', '1.1', '1.2.0', '1.2']);

/**
 * @typedef {Object} Finding
 * @property {string} rule
 * @property {string} check
 * @property {'error'|'warning'|'info'} severity
 * @property {string} message
 * @property {string} [hint]
 * @property {string} [pointer]
 */

/**
 * Check one loaded document. Called once per file, not once per target,
 * because these problems belong to the document as a whole.
 *
 * @param {{ kind: string, data: any, file: string }} ctx
 * @returns {Finding[]}
 */
export function checkDocument(ctx) {
  /** @type {Finding[]} */
  const findings = [];
  if (ctx.kind !== 'utcp') return findings;

  const doc = ctx.data;
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return findings;

  // --- Fields UtcpManual does not define ------------------------------------

  for (const key of Object.keys(doc)) {
    if (MANUAL_FIELDS.has(key)) continue;
    if (key === '_utcpLintIgnore' || key === 'x-utcp-lint-ignore') continue;

    const known = LIKELY_MISTAKES[key];
    findings.push({
      rule: id,
      check: 'R4/unknown-field',
      severity: 'error',
      pointer: key,
      message: `"${key}" is not a field of UtcpManual. A UTCP client rejects the entire manual with a TypeError before reading any tool.`,
      hint: known
        ? `Likely cause: ${known}.`
        : `Remove it. UtcpManual accepts only utcp_version, manual_version and tools — anything else fails at registration, not at call time.`,
    });
  }

  // --- tools[] must exist and be non-empty ----------------------------------

  if (!Array.isArray(doc.tools)) {
    findings.push({
      rule: id,
      check: 'R4/no-tools',
      severity: 'error',
      pointer: 'tools',
      message: '`tools` is required and must be an array. Without it the client registers a manual that exposes nothing.',
      hint: 'Add at least one tool, or the manual has no reason to exist.',
    });
    return findings;
  }

  if (doc.tools.length === 0) {
    findings.push({
      rule: id,
      check: 'R4/empty-tools',
      severity: 'warning',
      pointer: 'tools',
      message: '`tools` is an empty array. The manual loads, and offers nothing.',
      hint: 'Either populate it or do not publish it — an empty manual still costs a round trip and a registration slot.',
    });
  }

  // --- Protocol version -----------------------------------------------------

  if (doc.utcp_version !== undefined && !KNOWN_PROTOCOL_VERSIONS.has(String(doc.utcp_version))) {
    findings.push({
      rule: id,
      check: 'R4/unknown-version',
      severity: 'warning',
      pointer: 'utcp_version',
      message: `utcp_version "${doc.utcp_version}" is not a version this tool knows (${[...KNOWN_PROTOCOL_VERSIONS].join(', ')}).`,
      hint: 'A client older than the manual will reject it. Pin the version to the one your consumers actually run.',
    });
  }

  // --- Per-tool structure ---------------------------------------------------

  const seen = new Map();

  doc.tools.forEach((tool, i) => {
    if (!tool || typeof tool !== 'object') {
      findings.push({
        rule: id,
        check: 'R4/tool-not-object',
        severity: 'error',
        pointer: `tools[${i}]`,
        message: `tools[${i}] is ${Array.isArray(tool) ? 'an array' : typeof tool}, not an object.`,
        hint: 'Every entry in tools[] must be a tool object.',
      });
      return;
    }

    if (typeof tool.name !== 'string' || tool.name.trim() === '') {
      findings.push({
        rule: id,
        check: 'R4/tool-no-name',
        severity: 'error',
        pointer: `tools[${i}].name`,
        message: `tools[${i}] has no name. Clients address tools by name; an unnamed tool cannot be called.`,
        hint: 'Give it a name, e.g. "search_web".',
      });
    } else {
      const key = tool.name.trim();
      if (seen.has(key)) {
        findings.push({
          rule: id,
          check: 'R4/duplicate-tool-name',
          severity: 'warning',
          pointer: `tools[${i}].name`,
          message: `Tool name "${key}" is already used by tools[${seen.get(key)}]. The later definition shadows or is dropped, depending on the client.`,
          hint: 'Tool names are the call address. Two tools with one name means one of them is unreachable.',
        });
      } else {
        seen.set(key, i);
      }
    }

    const template = tool.tool_call_template ?? tool.tool_transport ?? tool.transport;
    if (!template || typeof template !== 'object') {
      findings.push({
        rule: id,
        check: 'R4/tool-no-template',
        severity: 'error',
        pointer: `tools[${i}].tool_call_template`,
        message: `tools[${i}] ("${tool.name ?? 'unnamed'}") has no tool_call_template, so the client has no way to invoke it.`,
        hint: 'Add a tool_call_template with a call_template_type and (for HTTP) a url.',
      });
      return;
    }

    if (typeof template.call_template_type !== 'string' && typeof template.transport_type !== 'string') {
      findings.push({
        rule: id,
        check: 'R4/template-no-type',
        severity: 'error',
        pointer: `tools[${i}].tool_call_template.call_template_type`,
        message: `tools[${i}] ("${tool.name ?? 'unnamed'}") has a template with no call_template_type, so the client cannot tell which transport to use.`,
        hint: 'Set call_template_type to "http", "cli", "sse", "websocket" or another registered transport.',
      });
    }

    if (typeof tool.description !== 'string' || tool.description.trim() === '') {
      findings.push({
        rule: id,
        check: 'R4/tool-no-description',
        severity: 'warning',
        pointer: `tools[${i}].description`,
        message: `tools[${i}] ("${tool.name ?? 'unnamed'}") has no description. An agent picks tools by reading these, so an undescribed tool is a tool that never gets chosen.`,
        hint: 'Write what the tool does, what it costs and when to use it — that is the text the model actually reads.',
      });
    }
  });

  return findings;
}
