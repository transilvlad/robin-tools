import dns from 'node:dns/promises';
import net from 'node:net';
import ipaddr from 'ipaddr.js';

type LookupAll = (
  hostname: string,
  options: { all: true; verbatim: true }
) => Promise<Array<{ address: string; family: number }>>;

export function isPrivateOrLocalIp(ip: string): boolean {
  try {
    const parsed = ipaddr.parse(ip);
    return parsed.range() !== 'unicast';
  } catch {
    return true;
  }
}

export function publicProbeAddresses(addresses: string[]): string[] {
  return [...new Set(addresses)].filter((address) => !isPrivateOrLocalIp(address));
}

export async function resolvePublicAddresses(
  hostname: string,
  lookup: LookupAll = dns.lookup
): Promise<string[]> {
  const addresses = net.isIP(hostname)
    ? [hostname]
    : (await lookup(hostname, { all: true, verbatim: true })).map((entry) => entry.address);

  if (addresses.length === 0 || addresses.some(isPrivateOrLocalIp)) {
    throw new Error('Target does not resolve exclusively to public unicast addresses');
  }

  return publicProbeAddresses(addresses);
}

export async function resolvePublicHttpsTarget(
  urlValue: string,
  lookup?: LookupAll
): Promise<{ url: URL; addresses: string[] }> {
  const url = new URL(urlValue);
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    (url.port && url.port !== '443')
  ) {
    throw new Error('Target must be an unauthenticated HTTPS URL on port 443');
  }

  return {
    url,
    addresses: await resolvePublicAddresses(url.hostname, lookup),
  };
}
