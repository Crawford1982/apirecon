#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const binPath = join(__dirname, '..', 'bin', 'apirecon.mjs');

const child = spawn(process.execPath, [binPath, '--mode', 'diff-replay', ...process.argv.slice(2)], {
  stdio: 'inherit',
});

child.on('exit', (code) => process.exit(code ?? 1));
