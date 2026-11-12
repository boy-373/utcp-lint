/**
 * R2 — The target that gets validated must be the target that gets called.
 *
 * Two CVEs in the UTCP reference implementations are the same bug wearing
 * different clothes: the URL that passed the check is not the URL that ends up
 * being fetched.
 *
 *   CVE-2026-45366 — @utcp/http before 1.1.2, CVSS 4.7
 *     `registerManual()` validated the discovery URL against an HTTPS /
 *     loopback allowlist, but `callTool()` reused the resolved
 *     `toolCallTemplate.url` without revalidating, and `OpenApiConverter`
 *     trusted whatever `servers[0].url` the spec declared. A spec hosted on a
 *     legitimate HTTPS endpoint could declare `servers: [{ url:
 *     "http://169.254.169.254" }]` and the converter happily built tools that
 *     pointed at the instance metadata service. The discovery-time guard was
 *     itself a `startsWith("http://localhost")` prefix test, so
 *     `http://localhost.evil.com` walked straight through it.
 *
 *   CVE-2026-101060 — python-utcp before 1.1.4, CVSS 8.4
 *     `HttpCommunicationProtocol.call_tool` validated the initial tool URL but
 *     followed HTTP redirects without revalidating the target. An endpoint
 *     under attacker control answers 302 to an internal address and the client
 *     returns the internal response body to the caller.
 *
 * Both are patched upstream. Both stay reachable through configuration: a
 * manual that points at a redirector, at a wildcard-DNS host, or at a hostname
 * that merely *begins with* a trusted label reintroduces the same gap no matter
 * which client version is installed. Pinning the version fixes the library;
 * only the config can fix the manual.
 */

import {
  classifyLiteralAddress,
  cloudMetadataService,
  isLoopbackHost,
  NON_PUBLIC_LABELS,
} from '../net.js';
import { parseUrl } from '../url.js';

export const id = 'R2';
export const title = 'Declared target is not the target that will be called';

/**
 * Hosts whose whole purpose is to send you somewhere else. A tool URL pointing
 * at one of these has no fixed destination, so no amount of review can tell you
 * where the agent's credentials will land.
 */
const URL_SHORTENERS = new Set([
  'bit.ly',
  'bitly.com',
  'tinyurl.com',
  't.co',
  'goo.gl',
  't.cn',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'rebrand.ly',
  'cutt.ly',
  'shorturl.at',
  'rb.gy',
  'tiny.cc',
  's.id',
  'v.gd',
]);

/**
 * Tunnel providers. The destination exists, but it is a temporary endpoint
 * whose owner changes by the hour. Not an error on its own — plenty of people
 * develop against a tunnel — but never something to ship.
 */
const TUNNEL_SUFFIXES = [
  'ngrok.io',
  'ngrok-free.app',
  'ngrok.app',
  'trycloudflare.com',
  'loca.lt',
  'localtunnel.me',
  'serveo.net',
  'bore.pub',
  'pagekite.me',
];

/**
 * Wildcard-DNS services: any IPv4 address can be encoded into the hostname and
 * the service resolves it for you. `169.254.169.254.nip.io` reaches the
 * instance metadata service while looking like an ordinary public hostname, and
 * every hostname-based allowlist in every client waves it through.
 */
const WILDCARD_DNS = [
  { suffix: 'nip.io', separator: /[.\-]/ },
  { suffix: 'sslip.io', separator: /[.\-]/ },
  { suffix: 'xip.io', separator: /[.\-]/ },
  { suffix: 'traefik.me', separator: /[.\-]/ },
];

/**
 * Hosts that resolve to loopback by design. Legitimate for local development,
 * which is why this is a warning rather than an error — but they are also the
 * cheapest way to smuggle `localhost` past a reviewer who only reads the
 * hostname.
 */
const LOOPBACK_ALIASES = new Set([
  'localtest.me',
  'lvh.me',
  'vcap.me',
  'lacolhost.com',
  'local.gd',
]);

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
 * Decode an IPv4 address hidden in a wildcard-DNS hostname.
 *
 * `169.254.169.254.nip.io` and `169-254-169-254.nip.io` are the same request.
 * Both forms are supported by every wildcard-DNS provider, and both defeat a
 * string comparison against the metadata address.
 *
 * @param {string} host
 * @returns {{ address: string, service: string } | null}
 */
export function decodeWildcardDns(host) {
  for (const { suffix, separator } of WILDCARD_DNS) {
    if (!host.endsWith(`.${suffix}`)) continue;
    const stem = host.slice(0, -(suffix.length + 1));
    const octets = stem.split(separator).filter((p) => p !== '');
    if (octets.length !== 4) continue;
    if (!octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255)) continue;
    return { address: octets.map(Number).join('.'), service: suffix };
  }
  return null;
}

/**
 * Does the hostname merely *start with* a loopback label?
 *
 * `localhost.evil.com` is a registrable domain owned by whoever registered
 * evil.com. It is not loopback, it never was, and it is exactly what the
 * prefix test in CVE-2026-45366 let through.
 *
 * @param {string} host
 * @returns {string | null} the trusted label it imitates
 */
function imitatesLoopback(host) {
  for (const label of ['localhost', '127.0.0.1', '0.0.0.0']) {
    if (host !== label && host.startsWith(`${label}.`)) return label;
  }
  return null;
}

/**
 * Run R2 against one normalised target.
 *
 * @param {import('../loader.js').Target} target
 * @returns {Promise<Finding[]>}
 */
export async function check(target) {
  /** @type {Finding[]} */
  const findings = [];
  const parts = parseUrl(target.url);

  // A relative URL (`/api/v1`, `{baseUrl}/tools`) has no origin at all. R1
  // skips those silently, which is the right call for it but leaves a hole
  // here: the destination is then decided by whatever base the client applies
  // at load time, and the spec author chose neither.
  if (!parts) {
    if (typeof target.url === 'string' && /^[./]/.test(target.url.trim())) {
      findings.push({
        rule: id,
        check: 'R2/relative-target',
        severity: 'warning',
        message: `Target "${target.url}" is a relative URL, so the real host is chosen by whatever base the client applies at load time.`,
        hint: 'Write the full origin into the template. A relative target cannot be reviewed, and it inherits whatever origin the loader happens to be configured with.',
      });
    }
    return findings;
  }

  if (parts.templated) {
    // R1 already warns that the destination is argument-controlled. Nothing
    // further can be said about the host without knowing the argument.
    return findings;
  }

  // --- CVE-2026-45366: the prefix test that trusted `localhost.evil.com` -----

  const imitated = imitatesLoopback(parts.host);
  if (imitated) {
    findings.push({
      rule: id,
      check: 'R2/loopback-prefix',
      severity: 'error',
      message: `${parts.host} starts with "${imitated}" but is not ${imitated} — it is an ordinary domain owned by whoever registered it.`,
      hint: 'A prefix check on the hostname string accepts this host. Either the config meant to call a real local service, or the hostname was chosen to look like one.',
      reference: 'https://nvd.nist.gov/vuln/detail/CVE-2026-45366',
    });
    return findings;
  }

  // --- Wildcard DNS: an IP address wearing a hostname ------------------------

  const decoded = decodeWildcardDns(parts.host);
  if (decoded) {
    const metadata = cloudMetadataService(decoded.address);
    const literal = classifyLiteralAddress(decoded.address);

    if (metadata) {
      findings.push({
        rule: id,
        check: 'R2/wildcard-dns-metadata',
        severity: 'error',
        message: `${parts.host} encodes ${decoded.address} through ${decoded.service} — that is the cloud instance metadata service (${metadata}).`,
        hint: 'This reaches IMDS while looking like an ordinary public hostname. Remove the target; there is no legitimate reason for a tool to read instance credentials.',
        reference: 'https://nvd.nist.gov/vuln/detail/CVE-2026-45366',
      });
      return findings;
    }

    if (literal && NON_PUBLIC_LABELS.has(literal.label)) {
      findings.push({
        rule: id,
        check: 'R2/wildcard-dns-private',
        severity: 'error',
        message: `${parts.host} encodes ${decoded.address} through ${decoded.service}, which is a ${literal.label} address (${literal.cidr}).`,
        hint: 'Wildcard DNS lets any address be written as a hostname, so a hostname allowlist cannot see it. Point the tool at a real public hostname instead.',
      });
      return findings;
    }

    findings.push({
      rule: id,
      check: 'R2/wildcard-dns',
      severity: 'warning',
      message: `${parts.host} resolves to ${decoded.address} via ${decoded.service}. The hostname is a wrapper around a hardcoded IP.`,
      hint: 'Write the address literally if the IP is intentional. A wildcard-DNS hostname hides the destination from every hostname-based review.',
    });
  }

  // --- CVE-2026-101060: the redirect that lands somewhere else --------------

  if (URL_SHORTENERS.has(parts.host)) {
    findings.push({
      rule: id,
      check: 'R2/shortener',
      severity: 'error',
      message: `${parts.host} is a URL shortener. The tool's real destination is whatever the short link points at today.`,
      hint: 'Resolve the link and write the final URL. A short link can be repointed at any time, including after review.',
      reference: 'https://nvd.nist.gov/vuln/detail/CVE-2026-101060',
    });
    return findings;
  }

  const tunnel = TUNNEL_SUFFIXES.find((s) => parts.host === s || parts.host.endsWith(`.${s}`));
  if (tunnel) {
    findings.push({
      rule: id,
      check: 'R2/tunnel',
      severity: 'warning',
      message: `${parts.host} is a ${tunnel} tunnel endpoint. The process answering it changes with whoever holds the tunnel today.`,
      hint: 'Fine for local development. Replace it with a stable hostname before this manual ships.',
    });
  }

  // These services answer for every subdomain, so `app.localtest.me` resolves
  // to 127.0.0.1 exactly the way the bare domain does.
  const loopbackAlias = [...LOOPBACK_ALIASES].find(
    (a) => parts.host === a || parts.host.endsWith(`.${a}`),
  );
  if (loopbackAlias) {
    findings.push({
      rule: id,
      check: 'R2/loopback-alias',
      severity: 'warning',
      message: `${parts.host} is a ${loopbackAlias} hostname, which resolves to 127.0.0.1 by design.`,
      hint: 'Correct for local development, and a common way to make a loopback call look like a public one. Confirm this manual is never deployed.',
    });
  }

  return findings;
}
