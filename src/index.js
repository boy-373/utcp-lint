/**
 * Rule registry and the run loop.
 */

import { resolve, basename } from 'node:path';
import { statSync } from 'node:fs';
import { resolve4, resolve6 } from 'node:dns/promises';
import * as r1 from './rules/r1-target.js';
import * as r2 from './rules/r2-redirect.js';
import * as r3 from './rules/r3-auth.js';
import * as r4 from './rules/r4-manual.js';
import { loadDocument, expandInputs, displayPath } from './loader.js';

/**
 * A broken JSON file only earns a report when its name says it is one of ours.
 * A stray tsconfig.json inside a scanned directory is noise, not a finding.
 */
const CONFIG_NAME_RE = /(utcp|mcp|openapi|swagger)/i;

/**
 * @param {string} file
 * @returns {boolean}
 */
function looksLikeConfigName(file) {
  return CONFIG_NAME_RE.test(basename(file));
}

/**
 * @typedef {Object} RuleModule
 * @property {string} id
 * @property {string} title
 * @property {'target'|'document'} [scope]  defaults to 'target'
 * @property {(target: any, opts?: any) => Promise<any[]>} [check]
 * @property {(ctx: {kind: string, data: any, file: string}) => any[]} [checkDocument]
 */

/** @type {RuleModule[]} */
export const RULES = [r1, r2, r3, r4];

/** @type {Map<string, RuleModule>} */
export const RULE_BY_ID = new Map(RULES.map((r) => [r.id, r]));

/**
 * @typedef {Object} Options
 * @property {string[]} [inputs]        files or directories
 * @property {string} [cwd]
 * @property {string[]} [only]          rule ids to run
 * @property {string[]} [skip]          rule ids to skip
 * @property {boolean} [dns]            resolve hostnames (network)
 * @property {number} [timeoutMs]       per-DNS-lookup timeout
 */

/**
 * @typedef {Object} RunResult
 * @property {Array<any>} findings
 * @property {Array<{file: string, error: string}>} errors
 * @property {number} filesScanned   documents a rule could run on
 * @property {number} filesRead      JSON documents parsed successfully
 * @property {number} targetsScanned
 * @property {string[]} notes
 */

/**
 * Resolve a hostname with a hard timeout so a hanging resolver cannot stall CI.
 * @param {string} host
 * @param {number} timeoutMs
 * @returns {Promise<string[]>}
 */
async function resolveHost(host, timeoutMs = 2000) {
  const work = (async () => {
    const out = [];
    try {
      out.push(...(await resolve4(host)));
    } catch {
      /* no A record */
    }
    try {
      out.push(...(await resolve6(host)));
    } catch {
      /* no AAAA record */
    }
    return out;
  })();

  const timeout = new Promise((_, reject) => {
    const t = setTimeout(() => reject(new Error('dns timeout')), timeoutMs);
    if (typeof t.unref === 'function') t.unref();
  });

  return Promise.race([work, timeout]);
}

/**
 * Scan everything the options point at.
 * @param {Options} options
 * @returns {Promise<RunResult>}
 */
export async function run(options = {}) {
  const cwd = options.cwd ?? process.cwd();
  const inputs = options.inputs && options.inputs.length > 0 ? options.inputs : ['.'];
  const only = options.only && options.only.length > 0 ? new Set(options.only) : null;
  const skip = new Set(options.skip ?? []);

  const selected = RULES.filter((r) => (!only || only.has(r.id)) && !skip.has(r.id));
  const active = selected.filter((r) => (r.scope ?? 'target') === 'target');
  const activeDocument = selected.filter((r) => r.scope === 'document');

  const files = expandInputs(inputs, cwd);
  /** @type {Array<any>} */
  const findings = [];
  /** @type {Array<{file: string, error: string}>} */
  const errors = [];
  /** @type {string[]} */
  const notes = [];
  let targetsScanned = 0;
  let filesScanned = 0;
  let filesRead = 0;

  // Files the user named on the command line always get their problems
  // reported. Files discovered by walking a directory do not.
  const explicit = new Set();
  for (const input of inputs) {
    const abs = resolve(cwd, input);
    try {
      if (statSync(abs).isFile()) explicit.add(abs);
    } catch {
      /* missing input is reported by the loader below */
    }
  }

  for (const file of files) {
    const doc = loadDocument(file);
    if (doc.error) {
      if (explicit.has(file) || looksLikeConfigName(file)) {
        errors.push({ file: displayPath(file, cwd), error: doc.error });
      }
      continue;
    }
    filesRead += 1;
    if (doc.kind === 'unknown') {
      // Parsed fine, just not a document we have rules for.
      continue;
    }
    filesScanned += 1;
    for (const note of doc.notes) {
      notes.push(`${displayPath(file, cwd)}: ${note}`);
    }

    // Document-level rules judge the file as a whole, so they run once,
    // before the per-target loop.
    for (const rule of activeDocument) {
      const docFindings = rule.checkDocument({
        kind: doc.kind,
        data: doc.data,
        file: displayPath(file, cwd),
      });
      for (const f of docFindings) {
        findings.push({
          ...f,
          file: displayPath(file, cwd),
          pointer: f.pointer ?? '',
          toolName: undefined,
          url: undefined,
        });
      }
    }

    for (const target of doc.targets) {
      targetsScanned += 1;
      for (const rule of active) {
        if (target.ignored.includes(rule.id)) continue;
        const ruleFindings = await rule.check(target, {
          resolveHost: options.dns ? (h) => resolveHost(h, options.timeoutMs ?? 2000) : undefined,
        });
        for (const f of ruleFindings) {
          findings.push({
            ...f,
            file: displayPath(file, cwd),
            pointer: f.pointer ?? target.pointer,
            toolName: target.toolName,
            url: target.url,
          });
        }
      }
    }
  }

  return { findings, errors, filesScanned, filesRead, targetsScanned, notes };
}

export { loadDocument, displayPath };
