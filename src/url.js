/**
 * Shared URL handling for rules.
 *
 * Config URLs are often templates (`https://api.example.com/users/{id}`), so
 * `new URL()` is not reliable here — a placeholder in the host or port throws.
 * This module extracts scheme and host the same way a browser would, then
 * leaves the rest of the string alone.
 */

const ORIGIN_RE = /^\s*([A-Za-z][A-Za-z0-9+.\-]*):\/\/([^/?#]*)/;

/**
 * @typedef {Object} UrlParts
 * @property {string} scheme
 * @property {string} authority     raw authority (may contain userinfo)
 * @property {string} host          hostname only, lowercased, no brackets
 * @property {string|null} port     port if present
 * @property {boolean} templated    true if the host contains a placeholder
 */

/**
 * Split a URL or URL template into the pieces rules need.
 * @param {string} raw
 * @returns {UrlParts|null} null when the string has no absolute origin
 */
export function parseUrl(raw) {
  if (typeof raw !== 'string') return null;
  const m = ORIGIN_RE.exec(raw);
  if (!m) return null;

  const scheme = m[1].toLowerCase();
  const authority = m[2];
  const hostPart = authority.includes('@') ? authority.slice(authority.lastIndexOf('@') + 1) : authority;

  let host;
  let port = null;

  if (hostPart.startsWith('[')) {
    // Bracketed IPv6, optionally with a port.
    const end = hostPart.indexOf(']');
    host = end === -1 ? hostPart.slice(1) : hostPart.slice(1, end);
    const after = end === -1 ? '' : hostPart.slice(end + 1);
    if (after.startsWith(':')) port = after.slice(1) || null;
  } else {
    const idx = hostPart.lastIndexOf(':');
    if (idx !== -1) {
      host = hostPart.slice(0, idx);
      port = hostPart.slice(idx + 1) || null;
    } else {
      host = hostPart;
    }
  }

  host = host.toLowerCase();
  const templated = host.includes('{') || host.includes('$') || (port !== null && /[{$]/.test(port));

  return { scheme, authority, host, port, templated };
}

/**
 * Effective port, filling in the scheme default.
 * @param {UrlParts} parts
 * @returns {number|null}
 */
export function effectivePort(parts) {
  if (parts.port !== null && /^\d+$/.test(parts.port)) return Number(parts.port);
  if (parts.port !== null) return null;
  if (parts.scheme === 'http' || parts.scheme === 'ws') return 80;
  if (parts.scheme === 'https' || parts.scheme === 'wss') return 443;
  return null;
}

/**
 * Is this a scheme a UTCP HTTP transport can actually use?
 * @param {string} scheme
 * @returns {boolean}
 */
export function isHttpScheme(scheme) {
  return scheme === 'http' || scheme === 'https';
}

/**
 * Does the secret look like an environment-variable reference rather than a
 * literal? `${VAR}`, `$VAR`, `{{ var }}` and empty strings all count.
 * @param {any} value
 * @returns {boolean}
 */
export function isPlaceholderSecret(value) {
  if (value === undefined || value === null) return true;
  if (typeof value !== 'string') return false;
  const v = value.trim();
  if (v === '') return true;
  if (v === '${' + v.slice(2)) return true;
  // ${VAR} possibly embedded in a larger string, e.g. "Bearer ${TOKEN}".
  if (/\$\{[^}]+\}/.test(v)) return true;
  // $VAR form.
  if (/^\$[A-Za-z_][A-Za-z0-9_]*$/.test(v)) return true;
  // Jinja / mustache style.
  if (/\{\{[^}]+\}\}/.test(v)) return true;
  // Common placeholder spellings that are not real secrets.
  if (/^(your[-_ ]?api[-_ ]?key|api[-_ ]?key|changeme|placeholder|xxx+|<[^>]+>)$/i.test(v)) return true;
  return false;
}
