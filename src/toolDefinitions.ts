// Tool catalog and navigation metadata: which DNS/mail/transform tools
// exist, how they're grouped into pages/tabs, legacy id aliases used for
// local-storage migration, and their icons. Pure data with no React or DOM
// dependencies, split out of remote.tsx.

import type {
  ToolDefinition,
  ToolKey,
  ToolPage,
  TransformCategory,
  TransformFormat,
  TransformKey,
  UiIconName,
} from './types';

export const moduleDefinition = {
  name: 'robin-tools',
  title: 'Robin Tools',
  description: 'DNS, mail posture, and diagnostics tools for deliverability operators.',
  defaultPath: 'dns-lookup/a',
  remoteScope: 'robinTools',
  exposedModule: './RobinToolsApp',
  navigation: [
    {
      label: 'DNS Lookup',
      iconName: 'search',
      path: 'dns-lookup',
    },
    {
      label: 'Mail Posture',
      iconName: 'mail',
      path: 'mail-posture',
    },
    {
      label: 'Reputation',
      iconName: 'shield-check',
      path: 'reputation',
    },
    {
      label: 'Mail Tests',
      iconName: 'wrench',
      path: 'mail-tests',
    },
    {
      label: 'Transforms',
      iconName: 'file-code',
      path: 'transforms',
    },
  ],
} as const;

export const TOOL_DEFINITIONS: Record<ToolKey, ToolDefinition> = {
  a: {
    key: 'a',
    label: 'A',
    target: 'domain',
    description: 'IPv4 address records for a hostname or domain.',
  },
  aaaa: {
    key: 'aaaa',
    label: 'AAAA',
    target: 'domain',
    description: 'IPv6 address records for a hostname or domain.',
  },
  cname: {
    key: 'cname',
    label: 'CNAME',
    target: 'domain',
    description: 'Canonical hostname aliases for a hostname or domain.',
  },
  ns: {
    key: 'ns',
    label: 'NS',
    target: 'domain',
    description: 'Authoritative nameserver records for a domain.',
  },
  txt: {
    key: 'txt',
    label: 'TXT',
    target: 'domain',
    description: 'Published TXT records for a hostname or domain.',
  },
  ptr: {
    key: 'ptr',
    label: 'PTR',
    target: 'ip',
    description: 'Reverse DNS hostname records for an IP address.',
  },
  caa: {
    key: 'caa',
    label: 'CAA',
    target: 'domain',
    description: 'Certificate Authority Authorization records.',
  },
  soa: {
    key: 'soa',
    label: 'SOA',
    target: 'domain',
    description: 'Start of Authority nameserver and zone timing record.',
  },
  dnssec: {
    key: 'dnssec',
    label: 'DNSSEC',
    target: 'domain',
    description: 'DS delegation and DNSKEY publication evidence.',
  },
  mx: {
    key: 'mx',
    label: 'MX',
    target: 'domain',
    description: 'Mail exchanger records and host targets.',
  },
  spf: {
    key: 'spf',
    label: 'SPF',
    target: 'domain',
    description: 'Authorized sending sources and SPF syntax health.',
  },
  dmarc: {
    key: 'dmarc',
    label: 'DMARC',
    target: 'domain',
    description: 'Published DMARC policy and reporting posture.',
  },
  dkim: {
    key: 'dkim',
    label: 'DKIM',
    target: 'domain',
    description: 'Selector lookup and DKIM public key checks.',
  },
  'mta-sts': {
    key: 'mta-sts',
    label: 'MTA-STS',
    target: 'domain',
    description: 'TXT discovery and hosted MTA-STS policy.',
  },
  tlsrpt: {
    key: 'tlsrpt',
    label: 'TLS-RPT',
    target: 'domain',
    description: 'TLS reporting TXT publication.',
  },
  dane: {
    key: 'dane',
    label: 'DANE',
    target: 'domain',
    description: 'TLSA records discovered from MX hosts.',
  },
  bimi: {
    key: 'bimi',
    label: 'BIMI',
    target: 'domain',
    description: 'Default BIMI TXT publication.',
  },
  fcrdns: {
    key: 'fcrdns',
    label: 'FCrDNS',
    target: 'ip',
    description: 'PTR and forward-confirmed reverse DNS validation.',
  },
  srv: {
    key: 'srv',
    label: 'Mail SRV',
    target: 'domain',
    description: 'Standard mail service discovery records.',
  },
  rbl: {
    key: 'rbl',
    label: 'RBL',
    target: 'ip',
    description: 'IP reputation lookups against configured DNSBL/RBL providers.',
  },
  dbl: {
    key: 'dbl',
    label: 'DBL',
    target: 'domain',
    description: 'Domain and URI reputation lookups against configured DBL/SURBL providers.',
  },
  'message-analysis': {
    key: 'message-analysis',
    label: 'Message Analysis',
    target: 'raw',
    description: 'Analyze a domain, address, message headers, or a raw email.',
  },
  'mail-server-test': {
    key: 'mail-server-test',
    label: 'Mail Server Test',
    target: 'host',
    description: 'MX, SMTP, STARTTLS, TLS, and port diagnostics.',
  },
  'reputation-providers': {
    key: 'reputation-providers',
    label: 'Providers',
    target: 'raw',
    description: 'Manage Robin Tools reputation provider settings.',
  },
  'base64-encode': {
    key: 'base64-encode',
    label: 'Base64 Encode',
    target: 'raw',
    description: 'Encode UTF-8 text as Base64.',
  },
  'base64-decode': {
    key: 'base64-decode',
    label: 'Base64 Decode',
    target: 'raw',
    description: 'Decode Base64 UTF-8 text.',
  },
  'base64url-encode': {
    key: 'base64url-encode',
    label: 'Base64Url Encode',
    target: 'raw',
    description: 'Encode UTF-8 text as Base64URL.',
  },
  'base64url-decode': {
    key: 'base64url-decode',
    label: 'Base64Url Decode',
    target: 'raw',
    description: 'Decode Base64URL UTF-8 text.',
  },
  'url-encode': {
    key: 'url-encode',
    label: 'URL Encode',
    target: 'raw',
    description: 'Percent-encode text for a URL component.',
  },
  'url-decode': {
    key: 'url-decode',
    label: 'URL Decode',
    target: 'raw',
    description: 'Decode a percent-encoded URL component.',
  },
  md5: {
    key: 'md5',
    label: 'MD5 Hash',
    target: 'raw',
    description: 'Calculate an MD5 digest for interoperability.',
  },
  sha256: {
    key: 'sha256',
    label: 'SHA-256 Hash',
    target: 'raw',
    description: 'Calculate a SHA-256 digest.',
  },
  'saml-encode': {
    key: 'saml-encode',
    label: 'SAML Encode',
    target: 'raw',
    description: 'Encode XML for SAML HTTP-Redirect binding.',
  },
  'saml-decode': {
    key: 'saml-decode',
    label: 'SAML Decode',
    target: 'raw',
    description: 'Decode SAML HTTP-Redirect binding data.',
  },
  'pretty-json': {
    key: 'pretty-json',
    label: 'Pretty JSON',
    target: 'raw',
    description: 'Validate and format JSON.',
  },
  'quoted-printable-encode': {
    key: 'quoted-printable-encode',
    label: 'Quoted-Printable Encode',
    target: 'raw',
    description: 'Encode UTF-8 text as quoted-printable.',
  },
  'quoted-printable-decode': {
    key: 'quoted-printable-decode',
    label: 'Quoted-Printable Decode',
    target: 'raw',
    description: 'Decode quoted-printable UTF-8 text.',
  },
  'uu-encode': {
    key: 'uu-encode',
    label: 'UUEncode',
    target: 'raw',
    description: 'Encode UTF-8 text as UUEncode.',
  },
  'uu-decode': {
    key: 'uu-decode',
    label: 'UUDecode',
    target: 'raw',
    description: 'Decode UUEncode UTF-8 text.',
  },
  'utf16-decode': {
    key: 'utf16-decode',
    label: 'UTF-16 Decode',
    target: 'raw',
    description: 'Decode hexadecimal UTF-16 code units.',
  },
  'hex-decode': {
    key: 'hex-decode',
    label: 'Hex Decode',
    target: 'raw',
    description: 'Decode hexadecimal UTF-8 bytes.',
  },
  'jwt-decode': {
    key: 'jwt-decode',
    label: 'JWT Decode',
    target: 'raw',
    description: 'Decode a JWT without verifying its signature.',
  },
  'unix-time': {
    key: 'unix-time',
    label: 'Unix Time',
    target: 'raw',
    description: 'Convert Unix timestamps and ISO dates.',
  },
};

export const PAGE_TABS: Record<ToolPage, readonly ToolKey[]> = {
  'dns-lookup': ['a', 'aaaa', 'cname', 'ns', 'txt', 'ptr', 'caa', 'soa', 'dnssec'],
  'mail-posture': [
    'mx',
    'spf',
    'dmarc',
    'dkim',
    'mta-sts',
    'tlsrpt',
    'dane',
    'bimi',
    'fcrdns',
    'srv',
  ],
  reputation: ['rbl', 'dbl', 'reputation-providers'],
  'mail-tests': ['message-analysis', 'mail-server-test'],
  transforms: [
    'base64-encode',
    'base64-decode',
    'base64url-encode',
    'base64url-decode',
    'url-encode',
    'url-decode',
    'md5',
    'sha256',
    'saml-encode',
    'saml-decode',
    'pretty-json',
    'quoted-printable-encode',
    'quoted-printable-decode',
    'uu-encode',
    'uu-decode',
    'utf16-decode',
    'hex-decode',
    'jwt-decode',
    'unix-time',
  ],
};

export const TOOL_PAGE_BY_KEY = Object.fromEntries(
  Object.entries(PAGE_TABS).flatMap(([page, keys]) => keys.map((key) => [key, page]))
) as Record<ToolKey, ToolPage>;

export const DEFAULT_PAGE_TABS: Record<ToolPage, ToolKey> = {
  'dns-lookup': 'a',
  'mail-posture': 'spf',
  reputation: 'rbl',
  'mail-tests': 'message-analysis',
  transforms: 'base64-encode',
};

export const LEGACY_PAGE_NAMES: Partial<Record<ToolPage, readonly string[]>> = {
  'dns-lookup': ['dns-lookup', 'dns'],
  'mail-posture': ['mail-posture', 'email-dns'],
};

export const LEGACY_TOOL_IDS: Partial<Record<ToolKey, readonly string[]>> = {
  a: ['a', 'a-record', 'dns-a'],
  aaaa: ['aaaa', 'aaaa-record', 'dns-aaaa'],
  cname: ['cname', 'cname-record', 'dns-cname'],
  ns: ['ns', 'ns-record', 'dns-ns'],
  txt: ['txt', 'txt-record', 'dns-txt'],
  ptr: ['ptr', 'ptr-record', 'dns-ptr'],
  caa: ['caa', 'caa-record', 'dns-caa'],
  soa: ['soa', 'soa-record', 'dns-soa'],
  dnssec: ['dnssec', 'dnssec-check'],
  mx: ['mx', 'mx-record', 'email-dns-mx'],
  spf: ['spf', 'spf-record', 'email-dns-spf'],
  dmarc: ['dmarc', 'dmarc-record', 'email-dns-dmarc'],
  dkim: ['dkim', 'dkim-record', 'email-dns-dkim'],
  'mta-sts': ['mta-sts', 'mtasts'],
  tlsrpt: ['tlsrpt', 'tls-rpt'],
  dane: ['dane', 'tlsa'],
  bimi: ['bimi', 'bimi-record'],
  fcrdns: ['fcrdns', 'forward-confirmed-rdns'],
  srv: ['srv', 'mail-srv'],
};

// Transforms are presented as a compact set of formats grouped into
// categories, with a direction toggle instead of separate encode/decode tabs.
// The underlying operation keys (and URLs) are unchanged.
export const TRANSFORM_CATEGORIES: readonly TransformCategory[] = [
  { id: 'binary', label: 'Base64 & Binary', icon: 'binary' },
  { id: 'web', label: 'URL & Web', icon: 'link' },
  { id: 'hashes', label: 'Hashes', icon: 'hash' },
  { id: 'tokens', label: 'JSON & Tokens', icon: 'braces' },
];

export const TRANSFORM_FORMATS: readonly TransformFormat[] = [
  {
    id: 'base64',
    label: 'Base64',
    category: 'binary',
    encode: 'base64-encode',
    decode: 'base64-decode',
  },
  {
    id: 'base64url',
    label: 'Base64URL',
    category: 'binary',
    encode: 'base64url-encode',
    decode: 'base64url-decode',
  },
  { id: 'uu', label: 'UUEncode', category: 'binary', encode: 'uu-encode', decode: 'uu-decode' },
  { id: 'hex', label: 'Hex', category: 'binary', decode: 'hex-decode', note: 'Decode only' },
  { id: 'utf16', label: 'UTF-16', category: 'binary', decode: 'utf16-decode', note: 'Decode only' },
  { id: 'url', label: 'URL', category: 'web', encode: 'url-encode', decode: 'url-decode' },
  {
    id: 'quoted-printable',
    label: 'Quoted-Printable',
    category: 'web',
    encode: 'quoted-printable-encode',
    decode: 'quoted-printable-decode',
  },
  { id: 'saml', label: 'SAML', category: 'web', encode: 'saml-encode', decode: 'saml-decode' },
  { id: 'md5', label: 'MD5', category: 'hashes', encode: 'md5', note: 'One-way' },
  { id: 'sha256', label: 'SHA-256', category: 'hashes', encode: 'sha256', note: 'One-way' },
  {
    id: 'pretty-json',
    label: 'Pretty JSON',
    category: 'tokens',
    encode: 'pretty-json',
    note: 'Format',
  },
  { id: 'jwt', label: 'JWT', category: 'tokens', decode: 'jwt-decode', note: 'Decode only' },
  { id: 'unix-time', label: 'Unix Time', category: 'tokens', encode: 'unix-time', note: 'Convert' },
];

export function findTransformFormat(key: ToolKey): TransformFormat | undefined {
  return TRANSFORM_FORMATS.find((format) => format.encode === key || format.decode === key);
}

export function defaultTransformKey(format: TransformFormat): TransformKey {
  return (format.encode ?? format.decode) as TransformKey;
}

export function isTransformKey(toolKey: ToolKey): toolKey is TransformKey {
  return PAGE_TABS.transforms.includes(toolKey);
}

export const TOOL_TAB_ICONS: Record<ToolKey, UiIconName> = {
  a: 'globe',
  aaaa: 'globe',
  cname: 'link',
  ns: 'network',
  txt: 'file',
  ptr: 'network',
  caa: 'shield',
  soa: 'settings',
  dnssec: 'shield',
  mx: 'mail',
  spf: 'shield',
  dmarc: 'shield',
  dkim: 'key',
  'mta-sts': 'shield',
  tlsrpt: 'file',
  dane: 'key',
  bimi: 'mail',
  fcrdns: 'network',
  srv: 'server',
  rbl: 'shield',
  dbl: 'shield',
  'reputation-providers': 'settings',
  'message-analysis': 'mail',
  'mail-server-test': 'server',
  'base64-encode': 'binary',
  'base64-decode': 'binary',
  'base64url-encode': 'binary',
  'base64url-decode': 'binary',
  'url-encode': 'link',
  'url-decode': 'link',
  md5: 'hash',
  sha256: 'hash',
  'saml-encode': 'key',
  'saml-decode': 'key',
  'pretty-json': 'braces',
  'quoted-printable-encode': 'file',
  'quoted-printable-decode': 'file',
  'uu-encode': 'binary',
  'uu-decode': 'binary',
  'utf16-decode': 'binary',
  'hex-decode': 'binary',
  'jwt-decode': 'key',
  'unix-time': 'wrench',
};
