import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export function checkReport(report, canonical = realpathSync) {
  if (report.type !== 'llvm.coverage.json.export' || !Array.isArray(report.data)
      || report.data.length !== 1 || !report.data[0].files?.length) {
    throw Error('Expected one nonempty LLVM coverage export');
  }
  const seen = new Set();
  for (const file of report.data[0].files) {
    const physical = canonical(file.filename);
    if (seen.has(physical)) throw Error(`Duplicate coverage source: ${file.filename}`);
    if (physical !== file.filename) throw Error(`Noncanonical coverage source: ${file.filename}`);
    seen.add(physical);
  }
  // LLVM owns executable-line and threshold semantics. This check validates
  // identity/shape only; it must not reconstruct a competing coverage metric.
  const lines = report.data[0].totals?.lines;
  if (!lines || !Number.isSafeInteger(lines.count) || lines.count <= 0
      || !Number.isSafeInteger(lines.covered) || lines.covered < 0
      || lines.covered > lines.count || !Number.isFinite(lines.percent)
      || lines.percent < 0 || lines.percent > 100) {
    throw Error('Invalid LLVM line totals');
  }
  return { sources: seen.size, ...lines };
}

// Symlinked entry paths must execute validation, not silently succeed on import.
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  if (process.argv.length !== 3) throw Error('Usage: check-coverage-report.mjs LLVM_JSON');
  console.log(JSON.stringify(checkReport(JSON.parse(readFileSync(process.argv[2], 'utf8')))));
}
