import { readFile } from 'node:fs/promises';

const readJson = async (path) => JSON.parse(await readFile(path, 'utf8'));
const [frontendPackage, backendPackage, manifest] = await Promise.all([
  readJson('package.json'),
  readJson('server/package.json'),
  readJson('module.manifest.json'),
]);

const errors = [];
const requiredStrings = [
  'protocolVersion',
  'slug',
  'displayName',
  'version',
  'remoteScope',
  'exposedModule',
  'routeSlug',
];

for (const field of requiredStrings) {
  if (typeof manifest[field] !== 'string' || manifest[field].trim() === '') {
    errors.push(`module.manifest.json: ${field} must be a non-empty string`);
  }
}

if (!/^\d+\.\d+\.\d+$/.test(manifest.version ?? '')) {
  errors.push('module.manifest.json: version must be an immutable x.y.z release version');
}

for (const [name, version] of [
  ['package.json', frontendPackage.version],
  ['server/package.json', backendPackage.version],
]) {
  if (version !== manifest.version) {
    errors.push(`${name}: version ${version} does not match manifest version ${manifest.version}`);
  }
}

for (const serviceName of ['frontend', 'backend']) {
  const service = manifest.services?.[serviceName];
  if (!service || typeof service !== 'object') {
    errors.push(`module.manifest.json: services.${serviceName} is required`);
    continue;
  }
  if (!Number.isInteger(service.port) || service.port < 1 || service.port > 65535) {
    errors.push(`module.manifest.json: services.${serviceName}.port must be a valid port`);
  }
  if (typeof service.image !== 'string' || !service.image.endsWith(`:${manifest.version}`)) {
    errors.push(`module.manifest.json: services.${serviceName}.image must use tag ${manifest.version}`);
  }
}

if (!Array.isArray(manifest.permissions) || manifest.permissions.some((value) => typeof value !== 'string')) {
  errors.push('module.manifest.json: permissions must be an array of strings');
}

if (errors.length > 0) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log(`Validated Robin Tools manifest version ${manifest.version}`);
