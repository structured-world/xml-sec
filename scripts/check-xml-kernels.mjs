import { spawn } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

const directories = ['crates/xml-sec-xml-input/src/', 'src/c14n/', 'src/parser_roxmltree/', 'src/parser_xmloxide/',
  'src/sxd_document/', 'src/sxd_xpath/', 'src/xml/dom/', 'src/xml_input/'];
const files = new Set(['src/document.rs', 'src/encoding.rs', 'src/xml.rs', 'src/hard_limits/xpath.rs',
  'vendor/sxd-xpath-no-unsafe/tests/integration.rs']);

export function physical(path) {
  try { return realpathSync(path); }
  catch { return resolve(path); }
}

export function ownsSource(root, filename) {
  const path = relative(physical(root), physical(resolve(root, filename))).split(sep).join('/');
  return !isAbsolute(path) && !path.startsWith('../')
    && (files.has(path) || directories.some(prefix => path.startsWith(prefix)));
}

export class DiagnosticGate {
  constructor(root, sourceOwner) {
    this.root = root;
    this.sourceOwner = sourceOwner;
    this.failures = [];
    this.seen = new Set();
    this.finished = false;
  }

  acceptLine(line) {
    try { this.accept(JSON.parse(line)); }
    catch (error) { this.failures.push(`Invalid Cargo JSON: ${error.message}`); }
  }

  accept(event) {
    if (!event || typeof event !== 'object' || typeof event.reason !== 'string') {
      throw new Error('Malformed Cargo event');
    }
    if (event.reason === 'build-finished') {
      this.finished = event.success === true;
      if (!this.finished) this.failures.push('Cargo reported an unsuccessful build');
      return;
    }
    if (event.reason !== 'compiler-message') return;
    const message = event.message;
    if (!message || !Array.isArray(message.spans)) throw new Error('Malformed compiler diagnostic');
    if (!['error', 'warning'].includes(message.level)) return;
    const spans = message.spans.filter(span => span.is_primary);
    const pending = [...spans];
    let owned;
    while (pending.length) {
      const span = pending.pop();
      if (this.sourceOwner(this.root, span.file_name)) { owned = span; break; }
      if (span.expansion?.span) pending.push(span.expansion.span);
    }
    // Compiler failures are terminal irrespective of scope. Warnings from
    // independently qualified subsystems do not become XML-kernel waivers.
    if (message.level !== 'error' && !owned) return;
    const location = owned || spans[0];
    const path = location ? physical(resolve(this.root, location.file_name)) : '';
    const key = JSON.stringify([path, location?.line_start, location?.column_start,
      message.level, message.code?.code, message.message]);
    if (this.seen.has(key)) return;
    this.seen.add(key);
    const label = location ? `${path}:${location.line_start}` : 'Cargo';
    this.failures.push(message.rendered || `${label}: ${message.message}`);
  }
}

export async function check(root, name, args, sourceOwner) {
  console.error(`Component pedantic: ${name}`);
  const gate = new DiagnosticGate(root, sourceOwner);
  const child = spawn('cargo', ['clippy', ...args, '--message-format=json', '--',
    '--force-warn', 'clippy::pedantic'], { cwd: root, stdio: ['ignore', 'pipe', 'inherit'] });
  const completed = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  for await (const line of createInterface({ input: child.stdout, crlfDelay: Infinity })) {
    gate.acceptLine(line);
  }
  const { code, signal } = await completed;
  for (const failure of gate.failures) console.error(failure);
  if (code !== 0 || signal || !gate.finished || gate.failures.length) {
    throw new Error(`${name}: ${gate.failures.length} diagnostics; cargo=${code}, signal=${signal}, finished=${gate.finished}`);
  }
}

async function main() {
  if (process.argv.length !== 2) throw new Error('Usage: node scripts/check-xml-kernels.mjs');
  const root = physical(resolve(import.meta.dirname, '..'));
  // These are the existing product entry graphs: full embedded/standalone,
  // default, isolated minimal core, and the separate alloc-only input crate.
  // Root no-default is not a root no_std claim. Force-warn bypasses allow/expect;
  // the diagnostic gate, not a warning baseline, enforces owned source files.
  for (const [name, args] of [
    ['workspace-all-features', ['--workspace', '--all-targets', '--all-features']],
    ['workspace-default', ['--workspace', '--all-targets']],
    ['core-minimal', ['-p', 'xml-sec', '--lib', '--no-default-features', '--features',
      'xmldsig,xmlenc,c14n,xml-backend-differential']],
    ['xml-input-alloc', ['-p', 'xml-sec-xml-input', '--lib', '--no-default-features']],
  ]) await check(root, name, args, ownsSource);
  console.log('XML-kernel pedantic: all entry graphs passed');
}

if (process.argv[1] && physical(process.argv[1]) === physical(fileURLToPath(import.meta.url))) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
