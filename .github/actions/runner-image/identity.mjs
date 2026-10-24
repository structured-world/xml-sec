import { appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function identity(environment) {
  const image = environment.ImageOS;
  if (!image || !/^[a-zA-Z0-9_-]+$/.test(image)) {
    throw new Error('A hosted runner ImageOS is required for build caching');
  }
  return image;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  appendFileSync(process.env.GITHUB_OUTPUT, `identity=${identity(process.env)}\n`);
}
