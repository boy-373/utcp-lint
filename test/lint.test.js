/**
 * Rule tests. Run with `npm test` (node --test).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { run } from '../src/index.js';
import { stripJsonc } from '../src/loader.js';
import { parseIpv4, isLoopbackHost, cloudMetadataService, classifyLiteralAddress } from '../src/net.js';
import { parseUrl, isPlaceholderSecret } from '../src/url.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, 'fixtures');

/**
 * Run the linter against one fixture file.
 * @param {string} name
 */
async function lintFixture(name) {
  return run({ inputs: [join(FIXTURES, name)], cwd: FIXTURES });
}

test('net: parses every IPv4 spelling the resolver accepts', () => {
  assert.equal(parseIpv4('127.0.0.1'), 0x7f000001);
  assert.equal(parseIpv4('127.1'), 0x7f000001);
  assert.equal(parseIpv4('2130706433'), 0x7f000001);
  assert.equal(parseIpv4('0x7f000001'), 0x7f000001);
  assert.equal(parseIpv4('0177.0.0.1'), 0x7f000001);
  assert.equal(parseIpv4('169.254.169.254'), 0xa9fea9fe);
  assert.equal(parseIpv4('not-an-ip'), null);
  assert.equal(parseIpv4(''), null);
});

test('net: loopback is hostname-based, not prefix-based', () => {
  assert.equal(isLoopbackHost('localhost'), true);
  assert.equal(isLoopbackHost('LOCALHOST'), true);
  assert.equal(isLoopbackHost('localhost.'), true);
  assert.equal(isLoopbackHost('127.0.0.1'), true);
  assert.equal(isLoopbackHost('127.5.5.5'), true);
  assert.equal(isLoopbackHost('::1'), true);
  assert.equal(isLoopbackHost('[::1]'), true);
  assert.equal(isLoopbackHost('localhost.evil.com'), false);
  assert.equal(isLoopbackHost('127.0.0.1.attacker.example'), false);
});

test('net: recognises cloud metadata endpoints', () => {
  assert.match(cloudMetadataService('169.254.169.254'), /AWS/);
  assert.match(cloudMetadataService('100.100.100.200'), /Alibaba/);
  assert.match(cloudMetadataService('metadata.google.internal'), /GCP/);
  // Integer spelling of the metadata address must be caught too.
  assert.match(cloudMetadataService('2852039166'), /AWS/);
  assert.equal(cloudMetadataService('api.github.com'), null);
});

test('net: classifies private ranges', () => {
  assert.equal(classifyLiteralAddress('10.0.0.5').label, 'private');
  assert.equal(classifyLiteralAddress('192.168.1.1').label, 'private');
  assert.equal(classifyLiteralAddress('172.16.0.9').label, 'private');
  assert.equal(classifyLiteralAddress('100.64.0.1').label, 'cgnat');
  assert.equal(classifyLiteralAddress('fd00::1').label, 'private');
  assert.equal(classifyLiteralAddress('8.8.8.8'), null);
});

test('url: handles templates without throwing', () => {
  const p = parseUrl('https://{host}:{port}/api');
  assert.equal(p.scheme, 'https');
  assert.equal(p.templated, true);

  const q = parseUrl('https://user:pw@api.example.com:8443/x');
  assert.equal(q.host, 'api.example.com');
  assert.equal(q.port, '8443');
  assert.equal(q.templated, false);

  const v6 = parseUrl('https://[fd00::1]:9000/x');
  assert.equal(v6.host, 'fd00::1');
  assert.equal(v6.port, '9000');

  assert.equal(parseUrl('/relative/path'), null);
});

test('url: placeholder detection', () => {
  assert.equal(isPlaceholderSecret('${API_KEY}'), true);
  assert.equal(isPlaceholderSecret('Bearer ${TOKEN}'), true);
  assert.equal(isPlaceholderSecret('$API_KEY'), true);
  assert.equal(isPlaceholderSecret(''), true);
  assert.equal(isPlaceholderSecret('your-api-key'), true);
  // Assembled at runtime on purpose: a literal Stripe-shaped string in the
  // source trips GitHub push protection, which cannot tell a fixture from a
  // real key.
  assert.equal(isPlaceholderSecret(['sk', 'live', '0'.repeat(22)].join('_')), false);
});

test('R1: cloud metadata endpoint is an error', async () => {
  const result = await lintFixture('vulnerable-utcp.json');
  const hit = result.findings.find((f) => f.check === 'R1/cloud-metadata' && f.toolName === 'aws_credential_reader');
  assert.ok(hit, 'expected R1/cloud-metadata on aws_credential_reader');
  assert.equal(hit.severity, 'error');
});

test('R1: private address is an error', async () => {
  const result = await lintFixture('vulnerable-utcp.json');
  const hit = result.findings.find((f) => f.check === 'R1/private-address' && f.toolName === 'internal_admin');
  assert.ok(hit, 'expected R1/private-address on internal_admin');
});

test('R1: plaintext transport to a public host is an error', async () => {
  const result = await lintFixture('vulnerable-utcp.json');
  const hit = result.findings.find((f) => f.check === 'R1/plaintext-transport' && f.toolName === 'legacy_billing');
  assert.ok(hit, 'expected R1/plaintext-transport on legacy_billing');
});

test('R1: dynamic host is a warning, not an error', async () => {
  const result = await lintFixture('vulnerable-utcp.json');
  const hit = result.findings.find((f) => f.check === 'R1/dynamic-host' && f.toolName === 'dynamic_host');
  assert.ok(hit, 'expected R1/dynamic-host on dynamic_host');
  assert.equal(hit.severity, 'warning');
});

test('R1: inline exemption is honoured', async () => {
  const result = await lintFixture('vulnerable-utcp.json');
  const hit = result.findings.find((f) => f.toolName === 'suppressed_example');
  assert.equal(hit, undefined, 'suppressed tool must not produce findings');
});

test('R3: live key shape is an error and is masked in the report', async () => {
  const result = await lintFixture('vulnerable-utcp.json');
  const hit = result.findings.find((f) => f.check === 'R3/live-key' && f.toolName === 'payments');
  assert.ok(hit, 'expected R3/live-key on payments');
  assert.ok(!hit.message.includes('51H8xYzAbCdEfGhIjKlMnOpQrStUvWx'), 'secret must be masked');
});

test('R3: environment-backed credentials pass', async () => {
  const result = await lintFixture('vulnerable-utcp.json');
  const hit = result.findings.find((f) => f.rule === 'R3' && f.toolName === 'legacy_billing');
  assert.equal(hit, undefined, 'placeholder secret must not be reported by R3');
});

test('MCP: headers with a literal token are caught', async () => {
  const result = await lintFixture('mcp-config.json');
  const hit = result.findings.find((f) => f.check === 'R3/live-key' && f.toolName === 'github');
  assert.ok(hit, 'expected R3/live-key on the github server');
});

test('MCP: private registry URL is caught', async () => {
  const result = await lintFixture('mcp-config.json');
  const hit = result.findings.find((f) => f.check === 'R1/private-address' && f.toolName === 'internal-registry');
  assert.ok(hit, 'expected R1/private-address on internal-registry');
});

test('MCP: GCP metadata hostname is caught', async () => {
  const result = await lintFixture('mcp-config.json');
  const hit = result.findings.find((f) => f.check === 'R1/cloud-metadata' && f.toolName === 'gcp');
  assert.ok(hit, 'expected R1/cloud-metadata on gcp');
});

test('OpenAPI: servers[].url pointing at metadata is caught', async () => {
  const result = await lintFixture('openapi-metadata.json');
  const hit = result.findings.find((f) => f.check === 'R1/cloud-metadata');
  assert.ok(hit, 'expected R1/cloud-metadata on the OpenAPI server URL');
});

test('clean fixture produces no findings', async () => {
  const result = await lintFixture('clean-utcp.json');
  assert.deepEqual(
    result.findings.map((f) => `${f.rule} ${f.check} ${f.toolName}`),
    [],
    'the clean manual must be silent',
  );
  assert.equal(result.filesScanned, 1);
  assert.ok(result.targetsScanned >= 3);
});

test('rule selection: --only limits the run', async () => {
  const result = await run({ inputs: [join(FIXTURES, 'vulnerable-utcp.json')], cwd: FIXTURES, only: ['R3'] });
  assert.ok(result.findings.length > 0);
  assert.ok(result.findings.every((f) => f.rule === 'R3'), 'only R3 findings expected');
});

test('rule selection: --skip removes a rule', async () => {
  const result = await run({ inputs: [join(FIXTURES, 'vulnerable-utcp.json')], cwd: FIXTURES, skip: ['R1'] });
  assert.ok(result.findings.every((f) => f.rule === 'R3'), 'no R1 findings expected');
});

test('jsonc: comments and trailing commas are stripped', () => {
  const src = `{
    // line comment
    "a": "https://example.com/path", /* block */
    "b": [1, 2, 3,],
  }`;
  const out = stripJsonc(src);
  const parsed = JSON.parse(out);
  assert.equal(parsed.a, 'https://example.com/path', 'URL inside a string must survive');
  assert.deepEqual(parsed.b, [1, 2, 3]);
});

test('jsonc: a trailing comma followed by a comment is still removed', () => {
  const src = `{
    "a": 1, // this comma is trailing
  }`;
  assert.deepEqual(JSON.parse(stripJsonc(src)), { a: 1 });
});

test('jsonc: a config file with comments is parsed, not rejected', async () => {
  const result = await lintFixture('jsonc-mcp.jsonc');
  assert.equal(result.errors.length, 0, 'JSONC must not produce a read error');
  assert.equal(result.filesScanned, 1);
  const hit = result.findings.find((f) => f.check === 'R1/private-address');
  assert.ok(hit, 'expected the private address to be caught inside the JSONC file');
});

test('unrelated broken JSON in a scanned directory stays quiet', async () => {
  // A tsconfig-style file is not ours; scanning a directory must not report it.
  const result = await run({ inputs: [join(FIXTURES, '..', 'fixtures')], cwd: FIXTURES });
  assert.equal(result.errors.length, 0);
});
