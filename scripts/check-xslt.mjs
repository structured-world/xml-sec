import { isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { check, physical } from './check-xml-kernels.mjs';

export function ownsSource(root, filename) {
  const path = relative(physical(root), physical(resolve(root, filename))).split(sep).join('/');
  return !isAbsolute(path) && !path.startsWith('../')
    && (path.startsWith('src/xslt/') || path.startsWith('crates/xml-sec-xslt/tests/')
      || path === 'benchmarks/xslt-latency.rs' || path === 'benchmarks/xslt-alloc.rs'
      || path === 'benches/support/xslt.rs');
}

export const graphs = [
  ['xslt-standalone', ['-p', 'xml-sec-xslt', '--all-targets', '--all-features']],
  ['xslt-embedded-default', ['-p', 'xml-sec', '--all-targets', '--features', 'xslt']],
  ['xslt-embedded-all', ['--workspace', '--all-targets', '--all-features']],
  ['xslt-embedded-minimal', ['-p', 'xml-sec', '--lib', '--no-default-features',
    '--features', 'xslt,xml-backend-differential']],
];

async function main() {
  if (process.argv.length !== 2) throw new Error('Usage: node scripts/check-xslt.mjs');
  const root = physical(resolve(import.meta.dirname, '..'));
  for (const [name, args] of graphs) await check(root, name, args, ownsSource);
  console.log('XSLT pedantic: all entry graphs passed');
}

if (process.argv[1] && physical(process.argv[1]) === physical(fileURLToPath(import.meta.url))) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
