import assert from 'node:assert/strict';
import test from 'node:test';
import {
  isPrivateOrLocalIp,
  publicProbeAddresses,
  resolvePublicAddresses,
  resolvePublicHttpsTarget,
} from './network-safety.js';

test('rejects non-public addresses', () => {
  for (const address of [
    '127.0.0.1',
    '10.0.0.1',
    '169.254.1.1',
    '::1',
    'fc00::1',
    '0.0.0.0',
    '203.0.113.10',
    '2001:db8::10',
  ]) {
    assert.equal(isPrivateOrLocalIp(address), true, address);
  }
});

test('retains only public addresses for network probes', () => {
  assert.deepEqual(
    publicProbeAddresses(['8.8.8.8', '10.0.0.2', '2606:4700:4700::1111', '8.8.8.8']),
    ['8.8.8.8', '2606:4700:4700::1111']
  );
});

test('rejects a hostname if any resolved address is not public', async () => {
  const lookup = async () => [
    { address: '8.8.8.8', family: 4 as const },
    { address: '127.0.0.1', family: 4 as const },
  ];

  await assert.rejects(resolvePublicAddresses('example.com', lookup), /public unicast/);
});

test('returns deduplicated public hostname addresses', async () => {
  const lookup = async () => [
    { address: '8.8.8.8', family: 4 as const },
    { address: '8.8.8.8', family: 4 as const },
  ];

  assert.deepEqual(await resolvePublicAddresses('example.com', lookup), ['8.8.8.8']);
});

test('validates every HTTPS target before a request or redirect is followed', async () => {
  const lookup = async () => [{ address: '8.8.8.8', family: 4 as const }];

  await assert.rejects(resolvePublicHttpsTarget('http://example.com/policy', lookup), /HTTPS/);
  await assert.rejects(
    resolvePublicHttpsTarget('https://user:pass@example.com/policy', lookup),
    /HTTPS/
  );
  await assert.rejects(
    resolvePublicHttpsTarget('https://example.com:8443/policy', lookup),
    /HTTPS/
  );
  await assert.rejects(
    resolvePublicHttpsTarget('https://redirect.example/policy', async () => [
      { address: '127.0.0.1', family: 4 as const },
    ]),
    /public unicast/
  );
  assert.equal(
    (await resolvePublicHttpsTarget('https://example.com/policy', lookup)).url.hostname,
    'example.com'
  );
});
