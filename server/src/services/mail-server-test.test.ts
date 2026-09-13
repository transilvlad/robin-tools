import assert from 'node:assert/strict';
import test from 'node:test';
import type net from 'node:net';
import type tls from 'node:tls';
import { probePort, runServerTest, type ToolSettings } from '../routes/robin-tools.js';

function socket() {
  return {
    write() {
      return true;
    },
    end() {},
    destroy() {},
  } as unknown as net.Socket;
}

function tlsSocket() {
  return {
    end() {},
    getPeerCertificate() {
      return { subject: { CN: 'mx.example.com' }, valid_to: 'Dec 31 23:59:59 2030 GMT' };
    },
  } as unknown as tls.TLSSocket;
}

function smtpDependencies(
  responses: Array<string | null>,
  tlsResult: tls.TLSSocket | Error = tlsSocket()
) {
  return {
    connect: async () => socket(),
    read: async () => responses.shift() ?? null,
    upgradeTls: async () => {
      if (tlsResult instanceof Error) throw tlsResult;
      return tlsResult;
    },
  };
}

test('reports every completed SMTP and STARTTLS phase on success', async () => {
  const result = await probePort(
    'mx.example.com',
    '8.8.8.8',
    25,
    1000,
    smtpDependencies([
      '220 mx.example.com ESMTP',
      '250-mx.example.com\n250 STARTTLS',
      '220 Ready to start TLS',
    ])
  );

  assert.equal(result.phase, 'complete');
  assert.equal(result.open, true);
  assert.equal(result.tlsVerified, true);
  assert.deepEqual(result.checksPerformed, [
    'connection',
    'banner',
    'EHLO',
    'STARTTLS availability',
    'STARTTLS command',
    'TLS handshake',
    'certificate verification',
  ]);
});

test('distinguishes connection timeout and refusal', async () => {
  for (const [code, kind] of [
    ['ETIMEDOUT', 'timeout'],
    ['ECONNREFUSED', 'refused'],
  ] as const) {
    const error = Object.assign(new Error(code), { code });
    const result = await probePort('mx.example.com', '8.8.8.8', 25, 1000, {
      connect: async () => {
        throw error;
      },
    });
    assert.equal(result.phase, 'connect');
    assert.equal(result.failureKind, kind);
    assert.match(result.nextStep ?? '', /Check|Start/);
  }
});

test('distinguishes malformed banner and unavailable STARTTLS', async () => {
  const malformed = await probePort(
    'mx.example.com',
    '8.8.8.8',
    25,
    1000,
    smtpDependencies(['not smtp'])
  );
  assert.equal(malformed.phase, 'banner');
  assert.equal(malformed.failureKind, 'protocol');
  assert.match(malformed.technicalDetail ?? '', /not smtp/);

  const noStartTls = await probePort(
    'mx.example.com',
    '8.8.8.8',
    25,
    1000,
    smtpDependencies(['220 mx.example.com ESMTP', '250 mx.example.com'])
  );
  assert.equal(noStartTls.phase, 'starttls');
  assert.equal(noStartTls.failureKind, 'starttls-unavailable');
  assert.match(noStartTls.nextStep ?? '', /Enable STARTTLS/);
});

test('distinguishes TLS handshake and certificate failures', async () => {
  const responses = ['220 mx.example.com ESMTP', '250 STARTTLS', '220 Go ahead'];
  const handshakeError = Object.assign(new Error('wrong version number'), { code: 'EPROTO' });
  const handshake = await probePort(
    'mx.example.com',
    '8.8.8.8',
    25,
    1000,
    smtpDependencies([...responses], handshakeError)
  );
  assert.equal(handshake.phase, 'tls-handshake');
  assert.equal(handshake.failureKind, 'tls-handshake');

  const certError = Object.assign(new Error('hostname mismatch'), {
    code: 'ERR_TLS_CERT_ALTNAME_INVALID',
  });
  const certificate = await probePort(
    'mx.example.com',
    '8.8.8.8',
    25,
    1000,
    smtpDependencies([...responses], certError)
  );
  assert.equal(certificate.phase, 'certificate');
  assert.equal(certificate.failureKind, 'certificate');
  assert.match(certificate.nextStep ?? '', /SAN/);
});

test('validates POP3 and IMAP greetings and negotiates their TLS upgrades', async () => {
  const pop3 = await probePort(
    'mx.example.com',
    '8.8.8.8',
    110,
    1000,
    smtpDependencies(['+OK POP3 ready', '+OK Begin TLS'])
  );
  assert.equal(pop3.phase, 'complete');
  assert.equal(pop3.tlsVerified, true);
  assert.deepEqual(pop3.checksPerformed, [
    'connection',
    'banner',
    'STARTTLS command',
    'TLS handshake',
    'certificate verification',
  ]);

  const imap = await probePort(
    'mx.example.com',
    '8.8.8.8',
    143,
    1000,
    smtpDependencies(['* OK IMAP ready', 'a001 OK Begin TLS'])
  );
  assert.equal(imap.phase, 'complete');
  assert.equal(imap.tlsVerified, true);

  const malformed = await probePort(
    'mx.example.com',
    '8.8.8.8',
    143,
    1000,
    smtpDependencies(['not imap'])
  );
  assert.equal(malformed.phase, 'banner');
  assert.equal(malformed.failureKind, 'protocol');

  const unavailable = await probePort(
    'mx.example.com',
    '8.8.8.8',
    110,
    1000,
    smtpDependencies(['+OK POP3 ready', '-ERR STLS unavailable'])
  );
  assert.equal(unavailable.phase, 'starttls');
  assert.equal(unavailable.failureKind, 'starttls-unavailable');
});

test('selects the lowest-priority MX host for probing', async () => {
  const settings: ToolSettings = {
    rblProviders: [],
    dblProviders: [],
    resolvers: [],
    confirmResolvers: [],
    timeoutMs: 1000,
    concurrency: 1,
    serverPorts: [25],
  };
  let probedHost = '';
  await runServerTest('example.com', settings, {
    resolveAddresses: async (host) => (host === 'primary.example.com' ? ['8.8.4.4'] : ['8.8.8.8']),
    resolveMx: async () => [
      { priority: 20, exchange: 'backup.example.com' },
      { priority: 10, exchange: 'primary.example.com' },
    ],
    probe: async (host, address, port) => {
      probedHost = host;
      return probePort(
        host,
        address,
        port,
        1000,
        smtpDependencies(['220 mx.example.com ESMTP', '250 STARTTLS', '220 Ready'])
      );
    },
    allowPrivateNetworkDiagnostics: false,
  });
  assert.equal(probedHost, 'primary.example.com');
});

test('reports DNS failure and does not claim later checks were performed', async () => {
  const settings: ToolSettings = {
    rblProviders: [],
    dblProviders: [],
    resolvers: [],
    confirmResolvers: [],
    timeoutMs: 1000,
    concurrency: 1,
    serverPorts: [25],
  };
  let probed = false;
  const dnsError = Object.assign(new Error('query timed out'), { code: 'ETIMEOUT' });
  const result = await runServerTest('mx.example.com', settings, {
    resolveAddresses: async () => {
      throw dnsError;
    },
    probe: async () => {
      probed = true;
      throw new Error('must not run');
    },
  });

  assert.equal(result.status, 'error');
  assert.match(result.summary, /no connection checks were performed/);
  assert.equal(result.findings[0]?.code, 'mail_server_dns_resolution');
  assert.equal(probed, false);
});
