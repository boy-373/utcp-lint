/**
 * Address classification for lint rules.
 *
 * Everything here is pure and offline: no DNS, no sockets. Rules that need
 * resolution call `resolveHost` explicitly so the lint stays usable in CI
 * sandboxes with no network.
 */

/** @typedef {{ cidr: string, base: number, mask: number, bits: number, label: string, note: string }} V4Block */

/** @type {V4Block[]} */
const V4_BLOCKS = [
  block('0.0.0.0/8', 'this-network', 'Unroutable; on Linux a connect to 0.0.0.0 lands on localhost.'),
  block('10.0.0.0/8', 'private', 'RFC 1918 private range.'),
  block('100.64.0.0/10', 'cgnat', 'RFC 6598 carrier-grade NAT. Alibaba Cloud metadata (100.100.100.200) lives here.'),
  block('127.0.0.0/8', 'loopback', 'Loopback.'),
  block('169.254.0.0/16', 'link-local', 'RFC 3927 link-local. Every major cloud metadata endpoint lives here.'),
  block('172.16.0.0/12', 'private', 'RFC 1918 private range.'),
  block('192.0.0.0/24', 'ietf-protocol', 'IETF protocol assignments.'),
  block('192.0.2.0/24', 'documentation', 'TEST-NET-1.'),
  block('192.168.0.0/16', 'private', 'RFC 1918 private range.'),
  block('198.18.0.0/15', 'benchmark', 'RFC 2544 benchmarking range.'),
  block('198.51.100.0/24', 'documentation', 'TEST-NET-2.'),
  block('203.0.113.0/24', 'documentation', 'TEST-NET-3.'),
  block('224.0.0.0/4', 'multicast', 'Multicast; never a legitimate tool target.'),
  block('240.0.0.0/4', 'reserved', 'Reserved for future use.'),
];

/**
 * Hostnames that are, by convention, cloud instance metadata services.
 * These are the credential-theft targets an SSRF payload aims at.
 * @type {Map<string, string>}
 */
const CLOUD_METADATA_HOSTS = new Map([
  ['169.254.169.254', 'AWS / Azure / GCP / OpenStack instance metadata'],
  ['169.254.170.2', 'AWS ECS task metadata'],
  ['100.100.100.200', 'Alibaba Cloud metadata'],
  ['metadata.google.internal', 'GCP instance metadata'],
  ['metadata.goog', 'GCP instance metadata'],
  ['fd00:ec2::254', 'AWS instance metadata over IPv6'],
  ['instance-data', 'OpenStack instance metadata'],
]);

/**
 * Build a V4Block from a dotted-quad CIDR.
 * @param {string} cidr
 * @param {string} label
 * @param {string} note
 * @returns {V4Block}
 */
function block(cidr, label, note) {
  const [addr, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  const base = parseIpv4(addr);
  if (base === null) throw new Error(`bad CIDR base: ${cidr}`);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { cidr, base: (base & mask) >>> 0, mask, bits, label, note };
}

/**
 * Parse a single IPv4 component the way `inet_aton` does.
 * Accepts decimal, `0x` hex, and leading-zero octal.
 * @param {string} part
 * @returns {number|null}
 */
function parseIpv4Part(part) {
  if (part === '') return null;
  let value;
  if (/^0[xX][0-9a-fA-F]+$/.test(part)) {
    value = Number.parseInt(part.slice(2), 16);
  } else if (/^0[0-7]+$/.test(part)) {
    value = Number.parseInt(part, 8);
  } else if (/^\d+$/.test(part)) {
    value = Number.parseInt(part, 10);
  } else {
    return null;
  }
  return Number.isFinite(value) ? value : null;
}

/**
 * Parse every IPv4 spelling the OS resolver accepts into a uint32.
 *
 * `ipaddress` in Python rejects `127.1` and `2130706433`; the resolver does
 * not. A lint that only understands dotted quads is trivially bypassed.
 *
 * @param {string} host
 * @returns {number|null} unsigned 32-bit value, or null if not IPv4-ish
 */
export function parseIpv4(host) {
  if (typeof host !== 'string' || host === '') return null;
  const parts = host.split('.');
  if (parts.length === 0 || parts.length > 4) return null;
  const nums = parts.map(parseIpv4Part);
  if (nums.some((n) => n === null)) return null;
  if (nums.some((n) => n < 0)) return null;

  const [a, b, c, d] = nums;
  let value;
  switch (nums.length) {
    case 1:
      value = a;
      break;
    case 2:
      value = a * 256 ** 3 + b;
      break;
    case 3:
      value = a * 256 ** 3 + b * 256 ** 2 + c;
      break;
    default:
      value = a * 256 ** 3 + b * 256 ** 2 + c * 256 + d;
  }
  if (!Number.isFinite(value) || value < 0 || value > 0xffffffff) return null;
  return value >>> 0;
}

/**
 * Render a uint32 back to dotted quad (for messages).
 * @param {number} value
 * @returns {string}
 */
export function formatIpv4(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join('.');
}

/**
 * Classify an IPv4 uint32 against the special-purpose blocks.
 * @param {number} value
 * @returns {{ label: string, cidr: string, note: string }|null}
 */
export function classifyIpv4(value) {
  for (const b of V4_BLOCKS) {
    if (((value & b.mask) >>> 0) === b.base) {
      return { label: b.label, cidr: b.cidr, note: b.note };
    }
  }
  return null;
}

/**
 * Strip the brackets and any trailing dot a hostname may carry.
 * @param {string} host
 * @returns {string}
 */
function normalizeHost(host) {
  return String(host).trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

/**
 * Is this hostname literally the loopback interface?
 *
 * Matches the upstream `_is_loopback_host` contract: hostname-based, never
 * prefix-based, so `localhost.evil.com` is not loopback.
 *
 * @param {string} host
 * @returns {boolean}
 */
export function isLoopbackHost(host) {
  const h = normalizeHost(host);
  if (h === '') return false;
  if (h === 'localhost' || h === '::1' || h === '::') return true;
  const v4 = parseIpv4(h);
  if (v4 !== null) {
    return classifyIpv4(v4)?.label === 'loopback';
  }
  // IPv4-mapped IPv6, e.g. ::ffff:127.0.0.1
  const mapped = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) {
    const inner = parseIpv4(mapped[1]);
    return inner !== null && classifyIpv4(inner)?.label === 'loopback';
  }
  return false;
}

/**
 * Identify a cloud metadata endpoint by hostname or address.
 * @param {string} host
 * @returns {string|null} human description, or null
 */
export function cloudMetadataService(host) {
  const h = normalizeHost(host);
  if (CLOUD_METADATA_HOSTS.has(h)) return CLOUD_METADATA_HOSTS.get(h);
  // Normalize integer / octal spellings of the metadata address too.
  const v4 = parseIpv4(h);
  if (v4 !== null) {
    const dotted = formatIpv4(v4);
    if (CLOUD_METADATA_HOSTS.has(dotted)) return CLOUD_METADATA_HOSTS.get(dotted);
  }
  return null;
}

/**
 * Classify a host that is a literal IP address (any accepted spelling).
 * @param {string} host
 * @returns {{ kind: 'ipv4'|'ipv6', label: string, cidr: string, note: string, text: string }|null}
 */
export function classifyLiteralAddress(host) {
  const h = normalizeHost(host);
  if (h === '') return null;

  const v4 = parseIpv4(h);
  if (v4 !== null) {
    const cls = classifyIpv4(v4);
    if (!cls) return null;
    return { kind: 'ipv4', ...cls, text: formatIpv4(v4) };
  }

  // IPv6: only the ranges that matter for SSRF.
  const v6 = h.startsWith('::ffff:') ? h.slice(7) : h;
  const mappedV4 = parseIpv4(v6);
  if (mappedV4 !== null) {
    const cls = classifyIpv4(mappedV4);
    if (!cls) return null;
    return { kind: 'ipv6', ...cls, text: `::ffff:${formatIpv4(mappedV4)}` };
  }

  if (h === '::1') {
    return { kind: 'ipv6', label: 'loopback', cidr: '::1/128', note: 'IPv6 loopback.', text: '::1' };
  }
  if (h === '::') {
    return { kind: 'ipv6', label: 'this-network', cidr: '::/128', note: 'IPv6 unspecified.', text: '::' };
  }
  if (/^f[cd][0-9a-f]{2}:/.test(h)) {
    return { kind: 'ipv6', label: 'private', cidr: 'fc00::/7', note: 'IPv6 unique local address.', text: h };
  }
  if (/^fe[89ab][0-9a-f]:/.test(h)) {
    return { kind: 'ipv6', label: 'link-local', cidr: 'fe80::/10', note: 'IPv6 link-local.', text: h };
  }
  return null;
}

/**
 * Does this hostname look like a literal address at all?
 * Used to decide whether DNS resolution is worth attempting.
 * @param {string} host
 * @returns {boolean}
 */
export function isLiteralAddress(host) {
  const h = normalizeHost(host);
  if (h === '') return false;
  if (parseIpv4(h) !== null) return true;
  return h.includes(':');
}

/**
 * Labels that mean "this address is not a public internet host".
 * Loopback is separate because plain-HTTP-to-loopback is legitimate in dev.
 * @type {Set<string>}
 */
export const NON_PUBLIC_LABELS = new Set([
  'this-network',
  'private',
  'cgnat',
  'link-local',
  'ietf-protocol',
  'documentation',
  'benchmark',
  'multicast',
  'reserved',
]);

export { normalizeHost };
