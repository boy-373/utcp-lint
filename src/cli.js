/**
 * Command-line interface.
 *
 * No argument-parsing dependency: the flag set is small enough that a hand
 * rolled parser is fewer lines than the import would be, and it keeps the
 * package at zero runtime dependencies.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { run, RULES } from './index.js';
import { renderer } from './report.js';

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * Read the package version without importing package.json as a module.
 * @returns {string}
 */
function version() {
  try {
    const pkg = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8'));
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

const USAGE = `
utcp-lint — catch SSRF and credential leaks in agent protocol configs

Usage
  utcp-lint [options] [paths...]

  Paths may be files or directories. With no path, the current directory is
  scanned for .json configs (node_modules and .git are skipped).

Options
  -f, --format <name>   pretty | json | github        (default: pretty)
  -o, --only <rules>    run only these rules, e.g. --only R1
  -s, --skip <rules>    skip these rules, e.g. --skip R3
      --dns             resolve hostnames to catch DNS-rebinding shapes
      --timeout <ms>    per-lookup DNS timeout              (default: 2000)
      --strict          exit non-zero on warnings too
      --quiet           summary only
      --no-color        disable ANSI colour
  -v, --version         print version
  -h, --help            print this help

Exit codes
  0  no errors (warnings allowed unless --strict)
  1  at least one error
  2  the run itself failed (bad flags, unreadable input)

Rules
${RULES.map((r) => `  ${r.id}  ${r.title}`).join('\n')}
`.trim();

/**
 * Parse argv into options plus positional paths.
 * @param {string[]} argv
 * @returns {{ options: any, paths: string[], action: 'run'|'help'|'version' }}
 */
export function parseArgs(argv) {
  const options = { format: 'pretty', only: [], skip: [], dns: false, strict: false, quiet: false, noColor: false, timeoutMs: 2000 };
  const paths = [];
  let action = 'run';

  const next = (i, flag) => {
    if (i + 1 >= argv.length) {
      throw new Error(`${flag} requires a value`);
    }
    return argv[i + 1];
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '-h':
      case '--help':
        action = 'help';
        break;
      case '-v':
      case '--version':
        action = 'version';
        break;
      case '-f':
      case '--format': {
        const value = next(i, arg);
        if (!['pretty', 'json', 'github'].includes(value)) {
          throw new Error(`unknown format: ${value}`);
        }
        options.format = value;
        i += 1;
        break;
      }
      case '-o':
      case '--only': {
        const value = next(i, arg);
        options.only = splitRules(value);
        i += 1;
        break;
      }
      case '-s':
      case '--skip': {
        const value = next(i, arg);
        options.skip = splitRules(value);
        i += 1;
        break;
      }
      case '--dns':
        options.dns = true;
        break;
      case '--timeout': {
        const value = Number(next(i, arg));
        if (!Number.isFinite(value) || value <= 0) throw new Error('--timeout must be a positive number of milliseconds');
        options.timeoutMs = value;
        i += 1;
        break;
      }
      case '--strict':
        options.strict = true;
        break;
      case '--quiet':
        options.quiet = true;
        break;
      case '--no-color':
        options.noColor = true;
        break;
      default:
        if (arg.startsWith('-')) {
          throw new Error(`unknown option: ${arg}`);
        }
        paths.push(arg);
    }
  }

  return { options, paths, action };
}

/**
 * @param {string} value
 * @returns {string[]}
 */
function splitRules(value) {
  const known = new Set(RULES.map((r) => r.id));
  const list = value
    .split(',')
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
  for (const rule of list) {
    if (!known.has(rule)) {
      throw new Error(`unknown rule: ${rule} (known: ${[...known].join(', ')})`);
    }
  }
  return list;
}

/**
 * Entry point.
 * @param {string[]} argv
 * @returns {Promise<number>} exit code
 */
export async function main(argv) {
  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`utcp-lint: ${err.message}\n\n${USAGE}\n`);
    return 2;
  }

  if (parsed.action === 'help') {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (parsed.action === 'version') {
    process.stdout.write(`${version()}\n`);
    return 0;
  }

  const { options, paths } = parsed;

  let result;
  try {
    result = await run({
      inputs: paths,
      only: options.only,
      skip: options.skip,
      dns: options.dns,
      timeoutMs: options.timeoutMs,
    });
  } catch (err) {
    process.stderr.write(`utcp-lint: run failed: ${err.message}\n`);
    return 2;
  }

  const render = renderer(options.format);
  const output = render(result, {
    noColor: options.noColor,
    stream: process.stdout,
    version: version(),
    quiet: options.quiet,
  });
  process.stdout.write(`${output}\n`);

  const errors = result.findings.filter((f) => f.severity === 'error').length;
  const warnings = result.findings.filter((f) => f.severity === 'warning').length;

  if (result.errors.length > 0 && errors === 0) {
    return 2;
  }
  if (errors > 0) return 1;
  if (options.strict && warnings > 0) return 1;
  return 0;
}
