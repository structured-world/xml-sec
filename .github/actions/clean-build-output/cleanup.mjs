import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function clean(manifest, toolchain, run = spawnSync) {
  if (!manifest || !toolchain) throw new Error('Cleanup requires an explicit manifest and toolchain');
  const result = run('cargo', [`+${toolchain}`, 'clean', '--manifest-path', manifest], { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.signal || result.status !== 0) throw new Error(`Cargo cleanup failed: ${result.signal ?? result.status}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  clean(process.env.INPUT_MANIFEST, process.env.INPUT_TOOLCHAIN);
}
