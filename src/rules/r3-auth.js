/**
 * R3 — Credentials must not be written into the config file.
 *
 * This rule is our own judgement call; there is no CVE behind it. That is the
 * point: every scanner in this space checks whether a config *works*, and
 * none checks whether it is safe to commit. A live API key in a UTCP manual
 * gets copied into git history, CI logs, container images and issue reports
 * long before anything calls it.
 *
 * The reference implementations never look at this. `auth.api_key` is read at
 * call time and used; where the value came from is not their problem. From a
 * security review's point of view it is the whole problem.
 */

import { isPlaceholderSecret } from '../url.js';

export const id = 'R3';
export const title = 'Credential is hardcoded in the config';

/**
 * Shapes that are almost certainly a live credential rather than a sample.
 * Kept short on purpose — the rule fires on any non-placeholder value; these
 * only raise the message from "looks like a secret" to "this is a live key".
 */
const KNOWN_KEY_PATTERNS = [
  { re: /^sk-[A-Za-z0-9_\-]{16,}$/, label: 'OpenAI-style secret key' },
  { re: /^sk_live_[A-Za-z0-9]{16,}$/, label: 'Stripe live secret key' },
  { re: /^gh[pousr]_[A-Za-z0-9]{20,}$/, label: 'GitHub token' },
  { re: /^github_pat_[A-Za-z0-9_]{20,}$/, label: 'GitHub fine-grained token' },
  { re: /^AKIA[0-9A-Z]{16}$/, label: 'AWS access key id' },
  { re: /^ASIA[0-9A-Z]{16}$/, label: 'AWS temporary access key id' },
  { re: /^xox[baprs]-[A-Za-z0-9\-]{10,}$/, label: 'Slack token' },
  { re: /^AIza[0-9A-Za-z_\-]{35}$/, label: 'Google API key' },
  { re: /^LTAI[A-Za-z0-9]{12,}$/, label: 'Alibaba Cloud access key id' },
  { re: /^eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\./, label: 'JWT' },
];

/**
 * @typedef {Object} Finding
 * @property {string} rule
 * @property {string} check
 * @property {'error'|'warning'|'info'} severity
 * @property {string} message
 * @property {string} [hint]
 * @property {string} [pointer]  overrides the target pointer when the problem
 *                               is not the URL itself (e.g. a header value)
 */

/**
 * Mask a secret so reports can quote it without leaking it into CI logs.
 * @param {string} value
 * @returns {string}
 */
export function mask(value) {
  if (typeof value !== 'string') return '<non-string>';
  const v = value.trim();
  if (v.length <= 8) return '*'.repeat(v.length);
  return `${v.slice(0, 4)}${'*'.repeat(Math.min(v.length - 8, 24))}${v.slice(-4)}`;
}

/**
 * Run R3 against one normalised target. A target may carry several
 * credentials (a structured auth block plus one or more headers), and each
 * one is judged separately.
 * @param {import('../loader.js').Target} target
 * @returns {Promise<Finding[]>}
 */
export async function check(target) {
  /** @type {Finding[]} */
  const findings = [];
  const auths = target.auths ?? (target.auth ? [target.auth] : []);
  for (const auth of auths) {
    findings.push(...judge(auth));
  }
  return findings;
}

/**
 * Judge a single credential.
 * @param {import('../loader.js').AuthInfo} auth
 * @returns {Finding[]}
 */
function judge(auth) {
  /** @type {Finding[]} */
  const findings = [];
  const secret = auth.secret;

  // An auth block with no value at all is a different problem (a config that
  // cannot work), not a leak. Leave it alone.
  if (secret === undefined || secret === null || String(secret).trim() === '') {
    return findings;
  }

  if (isPlaceholderSecret(secret)) {
    // Correct shape: the value comes from the environment at runtime.
    return findings;
  }

  const pointer = auth.pointer;
  const text = String(secret);
  const known = KNOWN_KEY_PATTERNS.find((p) => p.re.test(text.trim()));

  if (known) {
    findings.push({
      rule: id,
      check: 'R3/live-key',
      severity: 'error',
      pointer,
      message: `A ${known.label} is written directly into the config: ${mask(text)}.`,
      hint: `Replace it with an environment reference, e.g. "\${${guessEnvName(auth)}}", and rotate the key — it is already in this file's history.`,
    });
    return findings;
  }

  findings.push({
    rule: id,
    check: 'R3/hardcoded-secret',
    severity: 'error',
    pointer,
    message: `The ${auth.type} credential is a literal value (${mask(text)}), not an environment reference.`,
    hint: `Use "\${${guessEnvName(auth)}}" so the value stays out of the repository, CI logs and container images.`,
  });

  // Query-string credentials leak through logs, proxies and Referer headers
  // even when they are environment-backed.
  if (auth.location === 'query') {
    findings.push({
      rule: id,
      check: 'R3/query-credential',
      severity: 'warning',
      pointer,
      message: `Credential is sent as a query parameter${auth.varName ? ` (${auth.varName})` : ''}, so it appears in server access logs, proxy logs and Referer headers.`,
      hint: 'Move it to a header (location: "header") where it is not part of the URL.',
    });
  }

  return findings;
}

/**
 * Derive a sensible environment variable name from the auth shape.
 * @param {import('../loader.js').AuthInfo} auth
 * @returns {string}
 */
function guessEnvName(auth) {
  if (auth.varName) {
    return String(auth.varName).toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_|_$/g, '');
  }
  if (auth.secretField) {
    return String(auth.secretField).toUpperCase().replace(/[^A-Z0-9]+/g, '_');
  }
  return 'API_KEY';
}
