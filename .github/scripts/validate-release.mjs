import { readFile } from 'node:fs/promises';

const tag = process.env.GITHUB_REF_NAME ?? process.argv[2];
if (!/^v\d+\.\d+\.\d+$/.test(tag ?? '')) {
  console.error(`Release tag must be an immutable vX.Y.Z tag; received ${tag ?? '<none>'}`);
  process.exit(1);
}

const version = tag.slice(1);
const files = ['package.json', 'server/package.json', 'module.manifest.json'];
const versions = await Promise.all(
  files.map(async (path) => [path, JSON.parse(await readFile(path, 'utf8')).version]),
);
const mismatches = versions.filter(([, fileVersion]) => fileVersion !== version);

if (mismatches.length > 0) {
  for (const [path, fileVersion] of mismatches) {
    console.error(`${path}: version ${fileVersion} does not match release tag ${tag}`);
  }
  process.exit(1);
}

console.log(`Validated release ${tag}`);
