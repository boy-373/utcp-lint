/**
 * R1 — Tool targets must be reachable only on the public internet.
 *
 * Background: python-utcp 1.1.15 ships a 650-line `_security.py` that checks
 * the *scheme* of every URL (HTTPS, or plain HTTP to loopback). It never
 * checks the *destination*. As a result all of these pass its check today:
 *
 *   https://169.254.169.254/latest/meta-data/iam/security-credentials/
 *   https://100.100.100.200/latest/meta-data/
 *   https://metadata.google.internal/computeMetadata/v1/
 *   https://10.0.0.5/internal-admin
 *   https://192.168.1.1/router
 *
 * The CVE history for this project is a sequence of trust-boundary fixes at
 * the protocol layer. The destination layer has never been covered. That is
 * what this rule exists for: catch it while the config is being written, not
 * when the agent is already running inside the network.
 */

import {
  classifyLiteralAddress,
  cloudMetadataService,
  isLoopbackHost,
  isLiteralAddress,
  NON_PUBLIC_LABELS,
} from '../net.js';
import { parseUrl, effectivePort, isHttpScheme } from '../url.js';

export const id = 'R1';
export const title = 'Tool target is not a public internet host';

/**
 * @typedef {Object} Finding
 * @property {string} rule
 * @property {string} check
 * @property {'error'|'warning'|'info'} severity
 * @property {string} message
 * @property {string} [hint]
 * @property {string} [reference]
 */

/**
 * Run R1 against one normalised target.
 *
 * @param {import('../loader.js').Target} target
 * @param {{ resolveHost?: (host: string) => Promise<string[]> }} [opts]
 * @returns {Promise<Finding[]>}
 */
export async function check(target, opts = {}) {
  /** @type {Finding[]} */
  const findings = [];
  const parts = parseUrl(target.url);

  if (!parts) {
    // Relative URL, or a transport that does not use a URL at all.
    return findings;
  }

  if (!isHttpScheme(parts.scheme)) {
    findings.push({
      rule: id,
      check: 'R1/scheme',
      severity: 'error',
      message: `Transport scheme "${parts.scheme}:" is not an HTTP transport. A UTCP HTTP client cannot call this, and some clients will hand it to a generic fetcher.`,
      hint: 'Use https:// (or http:// to localhost for local development).',
    });
    return findings;
  }

  if (parts.templated) {
    // The host is chosen at call time. Upstream's `ensure_loopback_was_declared`
    // catches the loopback case at runtime, but nothing catches it at review
    // time, which is where a reviewer would notice the design.
    findings.push({
      rule: id,
      check: 'R1/dynamic-host',
      severity: 'warning',
      message: `Host is a placeholder (${parts.host || 'unknown'}), so the real destination is decided by a tool argument at call time.`,
      hint: 'Write the host literally in the template and let arguments choose only the path. This is the same rule python-utcp enforces at runtime as `ensure_loopback_was_declared`.',
    });
    return findings;
  }

  // --- Destination layer: the part upstream does not check. -----------------

  const metadata = cloudMetadataService(parts.host);
  if (metadata) {
    findings.push({
      rule: id,
      check: 'R1/cloud-metadata',
      severity: 'error',
      message: `Target is a cloud instance metadata endpoint (${metadata}). An agent calling this can read the host's temporary credentials.`,
      hint: 'Remove the target, or point it at the public API hostname instead of the metadata address.',
      reference: 'https://www.utcp.io/next/protocols/http',
    });
    return findings;
  }

  const literal = classifyLiteralAddress(parts.host);
  if (literal && NON_PUBLIC_LABELS.has(literal.label)) {
    findings.push({
      rule: id,
      check: 'R1/private-address',
      severity: 'error',
      message: `Target ${literal.text} is a ${literal.label} address (${literal.cidr}). ${literal.note}`,
      hint: 'A tool that calls an internal address turns the agent into an SSRF pivot inside your network. Point it at a public hostname, or move the call behind an explicit gateway.',
    });
    return findings;
  }

  // Plain HTTP to anything that is not loopback: upstream rejects this at
  // runtime, but the config should never have been written that way.
  if (parts.scheme === 'http' && !isLoopbackHost(parts.host)) {
    findings.push({
      rule: id,
      check: 'R1/plaintext-transport',
      severity: 'error',
      message: `Plain HTTP to ${parts.host}:${effectivePort(parts)} sends every tool call and every credential in clear text.`,
      hint: 'Switch to https://. python-utcp rejects this at runtime, so the config would fail anyway — catch it here instead.',
    });
    return findings;
  }

  // --- DNS layer: a public-looking hostname that resolves inward. -----------

  if (opts.resolveHost && !isLiteralAddress(parts.host)) {
    let addresses = [];
    try {
      addresses = await opts.resolveHost(parts.host);
    } catch {
      addresses = [];
    }
    const inward = addresses
      .map((addr) => ({ addr, cls: classifyLiteralAddress(addr) }))
      .filter((entry) => entry.cls && NON_PUBLIC_LABELS.has(entry.cls.label));

    if (inward.length > 0) {
      findings.push({
        rule: id,
        check: 'R1/dns-resolves-inward',
        severity: 'warning',
        message: `${parts.host} resolves to ${inward.map((e) => `${e.addr} (${e.cls.label})`).join(', ')}. The hostname looks public but the traffic goes inside.`,
        hint: 'Either the hostname is misconfigured, or it is a DNS-rebinding shape. Upstream validates the hostname string only, so this passes its check.',
      });
    }
  }

  return findings;
}
