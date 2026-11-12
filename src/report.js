/**
 * Output formatting.
 *
 * Three shapes, because a lint tool lives in three places: a terminal, a CI
 * log, and a JSON pipeline. Each one gets a format that fits.
 */

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';

/**
 * Decide whether to emit ANSI codes.
 * @param {{ noColor?: boolean, stream?: NodeJS.WriteStream }} opts
 * @returns {boolean}
 */
function useColor(opts) {
  if (opts.noColor) return false;
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR) return true;
  return Boolean(opts.stream?.isTTY);
}

/**
 * Build a tiny colouring helper.
 * @param {boolean} enabled
 */
function paint(enabled) {
  return {
    bold: (s) => (enabled ? `${BOLD}${s}${RESET}` : s),
    dim: (s) => (enabled ? `${DIM}${s}${RESET}` : s),
    red: (s) => (enabled ? `${RED}${s}${RESET}` : s),
    yellow: (s) => (enabled ? `${YELLOW}${s}${RESET}` : s),
    green: (s) => (enabled ? `${GREEN}${s}${RESET}` : s),
    cyan: (s) => (enabled ? `${CYAN}${s}${RESET}` : s),
  };
}

/**
 * Group findings by file, preserving discovery order.
 * @param {Array<any>} findings
 * @returns {Map<string, Array<any>>}
 */
function byFile(findings) {
  const map = new Map();
  for (const f of findings) {
    if (!map.has(f.file)) map.set(f.file, []);
    map.get(f.file).push(f);
  }
  return map;
}

/**
 * Wrap text to a readable width, indenting continuation lines.
 * @param {string} text
 * @param {number} width
 * @param {string} indent
 * @returns {string}
 */
function wrap(text, width, indent) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = '';
  for (const word of words) {
    if (line === '') {
      line = word;
    } else if (line.length + 1 + word.length <= width) {
      line += ` ${word}`;
    } else {
      lines.push(line);
      line = word;
    }
  }
  if (line !== '') lines.push(line);
  return lines.join(`\n${indent}`);
}

/**
 * Render the human-readable report.
 * @param {import('./index.js').RunResult} result
 * @param {{ noColor?: boolean, stream?: NodeJS.WriteStream, version?: string, quiet?: boolean }} opts
 * @returns {string}
 */
export function pretty(result, opts = {}) {
  const c = paint(useColor(opts));
  const out = [];
  const errors = result.findings.filter((f) => f.severity === 'error');
  const warnings = result.findings.filter((f) => f.severity === 'warning');

  if (!opts.quiet) {
    for (const [file, items] of byFile(result.findings)) {
      out.push('');
      out.push(c.bold(file));
      for (const f of items) {
        const mark = f.severity === 'error' ? c.red('✗') : c.yellow('!');
        const where = c.dim(`${f.pointer}${f.toolName ? `  ${f.toolName}` : ''}`);
        out.push(`  ${mark} ${c.bold(f.rule)} ${where}`);
        out.push(`      ${wrap(f.message, 84, '      ')}`);
        if (f.url) out.push(`      ${c.dim('url:')} ${c.dim(truncate(f.url, 100))}`);
        if (f.hint) out.push(`      ${c.cyan('→')} ${wrap(f.hint, 84, '        ')}`);
      }
    }

    for (const note of result.notes) {
      out.push(c.dim(`  note: ${note}`));
    }

    for (const err of result.errors) {
      out.push('');
      out.push(`${c.red('✗')} ${c.bold(err.file)}`);
      out.push(`      ${wrap(err.error, 84, '      ')}`);
    }
  }

  const parts = [
    `${result.filesRead ?? result.filesScanned} file${(result.filesRead ?? result.filesScanned) === 1 ? '' : 's'} read`,
    `${result.filesScanned} config${result.filesScanned === 1 ? '' : 's'}`,
    `${result.targetsScanned} target${result.targetsScanned === 1 ? '' : 's'}`,
    errors.length > 0 ? c.red(`${errors.length} error${errors.length === 1 ? '' : 's'}`) : c.green('0 errors'),
    warnings.length > 0 ? c.yellow(`${warnings.length} warning${warnings.length === 1 ? '' : 's'}`) : '0 warnings',
  ];

  out.push('');
  out.push(`${c.bold('utcp-lint')} ${c.dim(opts.version ?? '')}`.trimEnd());
  out.push(parts.join(c.dim(' · ')));
  if (result.filesScanned === 0 && (result.filesRead ?? 0) > 0) {
    out.push(c.dim('  no UTCP manual, MCP config or OpenAPI document found in these files'));
  }
  if (result.errors.length > 0) {
    out.push(c.dim('  some files could not be read; see above'));
  }
  out.push('');

  return out.join('\n');
}

/**
 * Render machine-readable JSON.
 * @param {import('./index.js').RunResult} result
 * @param {{ version?: string }} opts
 * @returns {string}
 */
export function json(result, opts = {}) {
  const errors = result.findings.filter((f) => f.severity === 'error').length;
  const warnings = result.findings.filter((f) => f.severity === 'warning').length;
  return JSON.stringify(
    {
      tool: 'utcp-lint',
      version: opts.version ?? null,
      summary: {
        filesRead: result.filesRead ?? result.filesScanned,
        configs: result.filesScanned,
        targets: result.targetsScanned,
        errors,
        warnings,
        readErrors: result.errors.length,
      },
      findings: result.findings.map((f) => ({
        rule: f.rule,
        check: f.check,
        severity: f.severity,
        file: f.file,
        pointer: f.pointer,
        tool: f.toolName ?? null,
        url: f.url ?? null,
        message: f.message,
        hint: f.hint ?? null,
        reference: f.reference ?? null,
      })),
      readErrors: result.errors,
      notes: result.notes,
    },
    null,
    2,
  );
}

/**
 * Render GitHub Actions workflow commands so findings annotate the diff.
 * @param {import('./index.js').RunResult} result
 * @returns {string}
 */
export function github(result) {
  const lines = [];
  for (const f of result.findings) {
    const level = f.severity === 'error' ? 'error' : 'warning';
    const title = escapeProp(`${f.rule} ${f.check}`);
    const file = escapeProp(f.file);
    const message = escapeData(`${f.message}${f.hint ? ` ${f.hint}` : ''}`);
    lines.push(`::${level} file=${file},line=1,title=${title}::${message}`);
  }
  for (const err of result.errors) {
    lines.push(`::error file=${escapeProp(err.file)},line=1,title=utcp-lint::${escapeData(err.error)}`);
  }
  const errors = result.findings.filter((f) => f.severity === 'error').length;
  const warnings = result.findings.filter((f) => f.severity === 'warning').length;
  lines.push(`::notice::utcp-lint: ${result.filesScanned} files, ${result.targetsScanned} targets, ${errors} errors, ${warnings} warnings`);
  return lines.join('\n');
}

/**
 * @param {string} s
 * @returns {string}
 */
function escapeData(s) {
  return String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

/**
 * @param {string} s
 * @returns {string}
 */
function escapeProp(s) {
  return escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

/**
 * @param {string} s
 * @param {number} n
 * @returns {string}
 */
function truncate(s, n) {
  return s.length <= n ? s : `${s.slice(0, n - 1)}…`;
}

/**
 * Pick a renderer by name.
 * @param {string} name
 * @returns {(result: import('./index.js').RunResult, opts?: any) => string}
 */
export function renderer(name) {
  switch (name) {
    case 'json':
      return json;
    case 'github':
      return github;
    case 'pretty':
    default:
      return pretty;
  }
}
