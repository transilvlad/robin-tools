import dgram from 'node:dgram';
import dns from 'node:dns';
import net from 'node:net';

export const DNS_RR_TYPE = {
  DS: 43,
  DNSKEY: 48,
  TLSA: 52,
} as const;

type KnownDnsRrType = keyof typeof DNS_RR_TYPE;

type DnsServer = {
  host: string;
  port: number;
  socketType: 'udp4' | 'udp6';
};

type RawDnsRecord = {
  type: number;
  data: Buffer;
};

export async function resolveTlsaRecordStrings(name: string, timeoutMs = 5000): Promise<string[]> {
  const records = await resolveRawRecords(name, 'TLSA', timeoutMs);
  return records
    .filter((record) => record.data.length >= 4)
    .map((record) =>
      [
        record.data[0],
        record.data[1],
        record.data[2],
        record.data.subarray(3).toString('hex'),
      ].join(' ')
    );
}

export async function resolveDnssecRecordCounts(
  domain: string,
  timeoutMs = 5000
): Promise<{ ds: number; dnskey: number }> {
  const [ds, dnskey] = await Promise.all([
    resolveRawRecords(domain, 'DS', timeoutMs).catch((error: unknown) =>
      isRawDnsMiss(error) ? [] : Promise.reject(error)
    ),
    resolveRawRecords(domain, 'DNSKEY', timeoutMs).catch((error: unknown) =>
      isRawDnsMiss(error) ? [] : Promise.reject(error)
    ),
  ]);
  return { ds: ds.length, dnskey: dnskey.length };
}

function isRawDnsMiss(error: unknown): boolean {
  const code =
    typeof error === 'object' && error ? String((error as { code?: unknown }).code ?? '') : '';
  return ['ENODATA', 'ENOTFOUND', 'ENODOMAIN', 'NXDOMAIN'].includes(code);
}

async function resolveRawRecords(
  name: string,
  rrtype: KnownDnsRrType,
  timeoutMs: number
): Promise<RawDnsRecord[]> {
  const query = buildQuery(name, DNS_RR_TYPE[rrtype]);
  const servers = getDnsServers();
  let lastError: unknown = null;
  let sawEmptyResponse = false;

  for (const server of servers) {
    try {
      const records = await queryServer(server, query, timeoutMs, DNS_RR_TYPE[rrtype]);
      if (records.length > 0) {
        return records;
      }
      sawEmptyResponse = true;
    } catch (error) {
      if (isRawDnsMiss(error)) {
        return [];
      }
      lastError = error;
    }
  }

  if (sawEmptyResponse) {
    return [];
  }
  throw lastError instanceof Error ? lastError : new Error(`${rrtype} lookup failed`);
}

function getDnsServers(): DnsServer[] {
  const servers = dgramGetServers();
  return servers.map(parseDnsServer).filter((server): server is DnsServer => Boolean(server));
}

function dgramGetServers(): string[] {
  const servers = dns.getServers();
  const fallback = ['1.1.1.1', '8.8.8.8'];
  return [...new Set([...servers, ...fallback])];
}

function parseDnsServer(value: string): DnsServer | null {
  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(value);
  if (bracketed) {
    const host = bracketed[1];
    return net.isIP(host) === 6
      ? { host, port: parsePort(bracketed[2]), socketType: 'udp6' }
      : null;
  }

  const ipv4WithPort = /^(\d+\.\d+\.\d+\.\d+):(\d+)$/.exec(value);
  if (ipv4WithPort) {
    return { host: ipv4WithPort[1], port: parsePort(ipv4WithPort[2]), socketType: 'udp4' };
  }

  const family = net.isIP(value);
  if (family === 4) {
    return { host: value, port: 53, socketType: 'udp4' };
  }
  if (family === 6) {
    return { host: value, port: 53, socketType: 'udp6' };
  }
  return null;
}

function parsePort(value: string | undefined): number {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= 65535 ? parsed : 53;
}

async function queryServer(
  server: DnsServer,
  query: Buffer,
  timeoutMs: number,
  expectedType: number
): Promise<RawDnsRecord[]> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket(server.socketType);
    const timer = setTimeout(() => {
      socket.close();
      const error = new Error('DNS query timed out');
      (error as NodeJS.ErrnoException).code = 'ETIMEOUT';
      reject(error);
    }, timeoutMs);

    socket.once('error', (error) => {
      clearTimeout(timer);
      socket.close();
      reject(error);
    });

    socket.once('message', (message) => {
      clearTimeout(timer);
      socket.close();
      try {
        resolve(parseResponse(message, query.readUInt16BE(0), expectedType));
      } catch (error) {
        reject(error);
      }
    });

    socket.send(query, server.port, server.host, (error) => {
      if (error) {
        clearTimeout(timer);
        socket.close();
        reject(error);
      }
    });
  });
}

function buildQuery(name: string, rrtype: number): Buffer {
  const id = Math.floor(Math.random() * 0xffff);
  const question = Buffer.concat([encodeName(name), u16(rrtype), u16(1)]);
  const opt = Buffer.concat([Buffer.from([0]), u16(41), u16(1232), u32(0), u16(0)]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(1, 10);
  return Buffer.concat([header, question, opt]);
}

// Exported so tests can build crafted DNS response fixtures.
export function encodeName(name: string): Buffer {
  const labels = name.replace(/\.$/, '').split('.');
  return Buffer.concat([
    ...labels.map((label) => {
      const data = Buffer.from(label, 'ascii');
      return Buffer.concat([Buffer.from([data.length]), data]);
    }),
    Buffer.from([0]),
  ]);
}

// Exported for dedicated unit tests of the raw DNS packet parsing/decompression
// logic (crafted/malformed/truncated response handling); not used elsewhere.
export function parseResponse(
  message: Buffer,
  expectedId: number,
  expectedType: number
): RawDnsRecord[] {
  if (message.length < 12 || message.readUInt16BE(0) !== expectedId) {
    throw new Error('Invalid DNS response');
  }
  const flags = message.readUInt16BE(2);
  const rcode = flags & 0x000f;
  if (rcode === 3) {
    const error = new Error('DNS name not found');
    (error as NodeJS.ErrnoException).code = 'ENOTFOUND';
    throw error;
  }
  if (rcode !== 0) {
    const error = new Error(`DNS query failed with rcode ${rcode}`);
    (error as NodeJS.ErrnoException).code = `EDNSRCODE${rcode}`;
    throw error;
  }

  const questionCount = message.readUInt16BE(4);
  const answerCount = message.readUInt16BE(6);
  let offset = 12;
  for (let i = 0; i < questionCount; i += 1) {
    offset = readName(message, offset).offset + 4;
  }

  const records: RawDnsRecord[] = [];
  for (let i = 0; i < answerCount; i += 1) {
    offset = readName(message, offset).offset;
    if (offset + 10 > message.length) {
      throw new Error('Truncated DNS response');
    }
    const type = message.readUInt16BE(offset);
    const klass = message.readUInt16BE(offset + 2);
    const rdlength = message.readUInt16BE(offset + 8);
    offset += 10;
    if (offset + rdlength > message.length) {
      throw new Error('Truncated DNS record');
    }
    if (type === expectedType && klass === 1) {
      records.push({ type, data: message.subarray(offset, offset + rdlength) });
    }
    offset += rdlength;
  }
  return records;
}

// Exported for the same testing reason as parseResponse above.
export function readName(message: Buffer, start: number): { name: string; offset: number } {
  const labels: string[] = [];
  let offset = start;
  let consumedOffset = start;
  let jumped = false;

  for (let depth = 0; depth < 32; depth += 1) {
    if (offset >= message.length) {
      throw new Error('Truncated DNS name');
    }
    const length = message[offset];
    if ((length & 0xc0) === 0xc0) {
      if (offset + 1 >= message.length) {
        throw new Error('Truncated DNS pointer');
      }
      if (!jumped) {
        consumedOffset = offset + 2;
      }
      offset = ((length & 0x3f) << 8) | message[offset + 1];
      jumped = true;
      continue;
    }
    if (length === 0) {
      return { name: labels.join('.'), offset: jumped ? consumedOffset : offset + 1 };
    }
    offset += 1;
    if (offset + length > message.length) {
      throw new Error('Truncated DNS label');
    }
    labels.push(message.subarray(offset, offset + length).toString('ascii'));
    offset += length;
  }

  throw new Error('DNS name compression loop');
}

function u16(value: number): Buffer {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value, 0);
  return buffer;
}

function u32(value: number): Buffer {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value, 0);
  return buffer;
}
