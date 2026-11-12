#!/usr/bin/env node
/**
 * utcp-lint CLI entry point.
 */

import { main } from '../src/cli.js';

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    process.stderr.write(`utcp-lint: unexpected failure: ${err?.stack ?? err}\n`);
    process.exitCode = 2;
  });
