import dns from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import { Router, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import ipaddr from 'ipaddr.js';
import { config as runtimeConfig } from '../config.js';
import { query } from '../db/connection.js';
import { logger } from '../logger.js';
import { requireAuth } from '../middleware/auth.js';
import { requireAdmin, requireEditor, requireViewer } from '../middleware/rbac.js';
import {
  getDomainDnsRecords,
  ipMatchesSpf,
  resolveFcrdns,
  resolvePtrHost,
  withTimeout,
} from '../services/sender-enrichment.js';
import { publicProbeAddresses } from '../services/network-safety.js';
import { resolveDnssecRecordCounts } from '../services/dns-records.js';

const router = Router();
const ROUTER_RATE_LIMIT_WINDOW_MS = 60_000;
const ROUTER_RATE_LIMIT_MAX_REQUESTS = 300;

const routerRateLimiter = rateLimit({
  windowMs: ROUTER_RATE_LIMIT_WINDOW_MS,
  limit: ROUTER_RATE_LIMIT_MAX_REQUESTS,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many Robin Tools requests. Try again shortly.',
  },
});

router.use(routerRateLimiter, requireAuth);
router.use(requireViewer);

class ValidationError extends Error {}

function respondToCheckError(res: Response, error: unknown, fallbackMessage: string) {
  if (error instanceof ValidationError) {
    return res.status(400).json({
      success: false,
      error: error.message || fallbackMessage,
    });
  }

  logger.error(fallbackMessage, { detail: (error as Error).message });
  return res.status(500).json({
    success: false,
    error: fallbackMessage,
  });
}

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 120;
const requestBuckets = new Map<number, { count: number; resetAt: number }>();
const RATE_LIMITED_PATHS = new Set([
  '/reputation/rbl/run',
  '/reputation/dbl/run',
  '/mail-tests/message-analysis/run',
  '/mail-tests/mail-server-test/run',
  '/checks/run',
  '/domains/bulk-check',
  '/ips/bulk-check',
]);

router.use((req: Request, res: Response, next) => {
  if (!RATE_LIMITED_PATHS.has(req.path)) {
    next();
    return;
  }

  const adminId = req.moduleAdmin!.adminId;
  const now = Date.now();
  const current = requestBuckets.get(adminId);
  const bucket =
    !current || current.resetAt <= now
      ? { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS }
      : current;

  bucket.count += 1;
  requestBuckets.set(adminId, bucket);

  if (bucket.count > RATE_LIMIT_MAX_REQUESTS) {
    res.status(429).json({
      success: false,
      error: 'Too many Robin Tools requests. Try again shortly.',
    });
    return;
  }

  next();
});

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
const HISTORY_LIMIT = 8;

type DomainIssue = {
  severity: Severity;
  code: string;
  title: string;
  detail: string;
};

type ToolKind =
  | 'a'
  | 'aaaa'
  | 'cname'
  | 'ns'
  | 'txt'
  | 'ptr'
  | 'caa'
  | 'soa'
  | 'dnssec'
  | 'srv'
  | 'mx'
  | 'spf'
  | 'dmarc'
  | 'dkim'
  | 'mta-sts'
  | 'tlsrpt'
  | 'dane'
  | 'bimi'
  | 'fcrdns'
  | 'rbl'
  | 'dbl'
  | 'message-analysis'
  | 'mail-server-test';

type TargetType = 'domain' | 'ip' | 'email' | 'headers' | 'raw' | 'host';
type VerificationStatus = 'pass' | 'fail' | 'warning' | 'error';

type CheckRecord = {
  key: string;
  label: string;
  value: string | null;
  ok: boolean | null;
  explanation: string;
};

type CheckResult = {
  toolKind: ToolKind;
  targetType: TargetType;
  targetValue: string;
  selector: string | null;
  status: VerificationStatus;
  summary: string;
  checkedAt: string;
  records: CheckRecord[];
  findings: DomainIssue[];
  meta?: Record<string, unknown>;
};

type CheckHistoryEntry = {
  id: number;
  issueId: number | null;
  subjectValue: string | null;
  toolKind: ToolKind;
  targetType: TargetType;
  targetValue: string;
  selector: string | null;
  status: VerificationStatus;
  summary: string | null;
  result: CheckResult;
  createdAt: string;
};

type OptionalCheckConfig = {
  mtaSts: boolean;
  tlsRpt: boolean;
  dane: boolean;
  bimi: boolean;
};

type BlocklistProvider = {
  id: string;
  zone: string;
  label: string;
  enabled: boolean;
  notes?: string | null;
};

export type ToolSettings = {
  rblProviders: BlocklistProvider[];
  dblProviders: BlocklistProvider[];
  resolvers: string[];
  confirmResolvers: string[];
  timeoutMs: number;
  concurrency: number;
  serverPorts: number[];
};

type BlocklistHit = {
  provider: BlocklistProvider;
  queryName: string;
  listed: boolean;
  responses: string[];
  txt: string[];
  error: string | null;
  disputed: boolean;
};

type HeaderMap = Map<string, string[]>;

type ParsedMessageInput = {
  inputKind: 'domain' | 'email' | 'headers' | 'raw';
  value: string;
  domain: string | null;
  email: string | null;
  headers: HeaderMap;
  rawHeaders: string;
  domains: string[];
  ips: string[];
  dkimSelectors: Array<{ selector: string; domain: string; algorithm: string | null }>;
  urls: string[];
};

export type ProbePhase =
  'connect' | 'banner' | 'ehlo' | 'starttls' | 'tls-handshake' | 'certificate' | 'complete';
type ProbeFailureKind =
  | 'timeout'
  | 'refused'
  | 'network'
  | 'protocol'
  | 'starttls-unavailable'
  | 'tls-handshake'
  | 'certificate';

export type ServerPortResult = {
  port: number;
  open: boolean;
  protocol: 'smtp' | 'smtps' | 'pop3' | 'pop3s' | 'imap' | 'imaps' | 'tcp';
  banner: string | null;
  ehlo: string | null;
  startTls: boolean | null;
  tls: boolean;
  tlsVerified: boolean | null;
  certSubject: string | null;
  certValidTo: string | null;
  error: string | null;
  phase: ProbePhase;
  failureKind: ProbeFailureKind | null;
  reason: string | null;
  nextStep: string | null;
  technicalDetail: string | null;
  checksPerformed: string[];
};

type DomainBulkResult = {
  domain: string;
  checkedAt: string;
  checks: {
    mx: boolean;
    spf: boolean;
    dmarc: boolean;
    dkim: boolean | null;
    mtaSts?: boolean;
    tlsRpt?: boolean;
    dane?: boolean;
    bimi?: boolean;
  };
  records: {
    mxHosts: string[];
    spfRecord: string | null;
    dmarcRecord: string | null;
    dkimRecord: string | null;
    mtaStsRecord?: string | null;
    tlsRptRecord?: string | null;
    bimiRecord?: string | null;
    daneHosts?: string[];
  };
  issues: DomainIssue[];
};

type IpBulkResult = {
  sourceIp: string;
  ptrHost: string | null;
  fcrdnsHost: string | null;
  fcrdnsAligned: boolean;
  domains: string[];
  checkedAt: string;
  issues: DomainIssue[];
};

const SETTINGS_KEY = 'tool-settings';
const MAX_BLOCKLIST_TARGETS = 100;
const MAX_BLOCKLIST_PROVIDERS = 50;
const MAX_ANALYSIS_INPUT_CHARS = 200_000;
const DEFAULT_TOOL_SETTINGS: ToolSettings = {
  rblProviders: [
    {
      id: 'spamhaus-zen',
      zone: 'zen.spamhaus.org',
      label: 'Spamhaus ZEN',
      enabled: true,
      notes: 'Combined Spamhaus IP DNSBL example. Review query entitlement before production use.',
    },
    {
      id: 'spamcop',
      zone: 'bl.spamcop.net',
      label: 'SpamCop SCBL',
      enabled: true,
      notes: 'Time-based IP listing signal from SpamCop reports.',
    },
    {
      id: 'barracuda',
      zone: 'b.barracudacentral.org',
      label: 'Barracuda BRBL',
      enabled: true,
      notes: 'Barracuda IP reputation DNSBL example.',
    },
  ],
  dblProviders: [
    {
      id: 'spamhaus-dbl',
      zone: 'dbl.spamhaus.org',
      label: 'Spamhaus DBL',
      enabled: true,
      notes: 'Domain-only blocklist. Do not query IP addresses against this zone.',
    },
    {
      id: 'surbl-multi',
      zone: 'multi.surbl.org',
      label: 'SURBL Multi',
      enabled: true,
      notes: 'URI/domain reputation list for domains found in message content.',
    },
  ],
  resolvers: [],
  confirmResolvers: [],
  timeoutMs: 5000,
  concurrency: 8,
  serverPorts: [25, 465, 587, 110, 143, 993, 995],
};

function parseDomain(value: string): string | null {
  const normalized = value.trim().toLowerCase();
  if (!normalized || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(normalized)) {
    return null;
  }
  return normalized;
}

function parseHost(value: string): string | null {
  const normalized = value.trim().toLowerCase().replace(/\.$/, '');
  if (net.isIP(normalized) > 0) {
    return normalized;
  }
  return parseDomain(normalized);
}

function sanitizeProvider(value: unknown, fallback?: BlocklistProvider): BlocklistProvider | null {
  if (!value || typeof value !== 'object') {
    return fallback ?? null;
  }

  const input = value as Record<string, unknown>;
  const zone = typeof input.zone === 'string' ? parseDomain(input.zone) : null;
  if (!zone) {
    return fallback ?? null;
  }

  const label =
    typeof input.label === 'string' && input.label.trim()
      ? input.label.trim().slice(0, 80)
      : (fallback?.label ?? zone);
  const id =
    typeof input.id === 'string' && input.id.trim()
      ? input.id
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9._-]+/g, '-')
          .slice(0, 80)
      : zone.replace(/[^a-z0-9]+/g, '-');

  return {
    id,
    zone,
    label,
    enabled: parseBoolean(input.enabled, fallback?.enabled ?? true),
    notes:
      typeof input.notes === 'string' && input.notes.trim()
        ? input.notes.trim().slice(0, 240)
        : null,
  };
}

function sanitizeProviderList(value: unknown, fallback: BlocklistProvider[]): BlocklistProvider[] {
  if (!Array.isArray(value)) {
    return fallback;
  }

  const seen = new Set<string>();
  const providers = value
    .map((item) => sanitizeProvider(item))
    .filter((item): item is BlocklistProvider => Boolean(item))
    .filter((item) => {
      const key = item.zone.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, MAX_BLOCKLIST_PROVIDERS);

  return providers.length > 0 ? providers : fallback;
}

function sanitizeIpList(value: unknown, fallback: string[], allowEmpty = false): string[] {
  if (!Array.isArray(value)) {
    return fallback;
  }

  const ips = [
    ...new Set(value.map((item) => String(item).trim()).filter((item) => net.isIP(item) > 0)),
  ].slice(0, 8);

  return ips.length > 0 ? ips : allowEmpty ? [] : fallback;
}

function sanitizePortList(value: unknown, fallback: number[]): number[] {
  if (!Array.isArray(value)) {
    return fallback;
  }

  const ports = [
    ...new Set(
      value
        .map((item) => Number.parseInt(String(item), 10))
        .filter((item) => Number.isInteger(item) && item > 0 && item <= 65535)
    ),
  ].slice(0, 20);

  return ports.length > 0 ? ports : fallback;
}

function sanitizeSettings(value: unknown): ToolSettings {
  const input = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const timeoutMs = Number.parseInt(String(input.timeoutMs ?? ''), 10);
  const concurrency = Number.parseInt(String(input.concurrency ?? ''), 10);
  return {
    rblProviders: sanitizeProviderList(input.rblProviders, DEFAULT_TOOL_SETTINGS.rblProviders),
    dblProviders: sanitizeProviderList(input.dblProviders, DEFAULT_TOOL_SETTINGS.dblProviders),
    resolvers: sanitizeIpList(input.resolvers, DEFAULT_TOOL_SETTINGS.resolvers, true),
    confirmResolvers: Array.isArray(input.confirmResolvers)
      ? [
          ...new Set(
            input.confirmResolvers
              .map((item) => String(item).trim())
              .filter((item) => net.isIP(item) > 0)
          ),
        ].slice(0, 8)
      : DEFAULT_TOOL_SETTINGS.confirmResolvers,
    timeoutMs: Number.isInteger(timeoutMs)
      ? Math.min(Math.max(timeoutMs, 1000), 30_000)
      : DEFAULT_TOOL_SETTINGS.timeoutMs,
    concurrency: Number.isInteger(concurrency)
      ? Math.min(Math.max(concurrency, 1), 20)
      : DEFAULT_TOOL_SETTINGS.concurrency,
    serverPorts: sanitizePortList(input.serverPorts, DEFAULT_TOOL_SETTINGS.serverPorts),
  };
}

async function getToolSettings(): Promise<ToolSettings> {
  const result = await query<{ value_json: ToolSettings }>(
    `SELECT value_json
     FROM robin_tools_module.tool_settings
     WHERE key = $1`,
    [SETTINGS_KEY]
  );
  return sanitizeSettings(result.rows[0]?.value_json ?? DEFAULT_TOOL_SETTINGS);
}

async function saveToolSettings(settings: ToolSettings): Promise<ToolSettings> {
  const sanitized = sanitizeSettings(settings);
  await query(
    `INSERT INTO robin_tools_module.tool_settings (key, value_json, updated_at)
     VALUES ($1, $2::jsonb, CURRENT_TIMESTAMP)
     ON CONFLICT (key)
     DO UPDATE SET value_json = EXCLUDED.value_json, updated_at = CURRENT_TIMESTAMP`,
    [SETTINGS_KEY, JSON.stringify(sanitized)]
  );
  return sanitized;
}

function parseDomainArray(input: unknown): string[] {
  if (!Array.isArray(input)) {
    return [];
  }
  return [
    ...new Set(
      input
        .map((value) => parseDomain(String(value)))
        .filter((value): value is string => Boolean(value))
    ),
  ];
}

function parseIpArray(input: unknown): string[] {
  if (!Array.isArray(input)) {
    return [];
  }
  return [
    ...new Set(input.map((value) => String(value).trim()).filter((value) => net.isIP(value) > 0)),
  ];
}

function parseBoolean(value: unknown, fallback = false): boolean {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    return value === 'true' || value === '1';
  }
  return fallback;
}

function parsePage(value: unknown, fallback: number): number {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function severityWeight(severity: Severity | null): number {
  switch (severity) {
    case 'critical':
      return 5;
    case 'high':
      return 4;
    case 'medium':
      return 3;
    case 'low':
      return 2;
    case 'info':
      return 1;
    default:
      return 0;
  }
}

function parseSelector(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '');
  return normalized || null;
}

function parseToolKind(value: unknown): ToolKind | null {
  if (typeof value !== 'string') {
    return null;
  }

  const normalized = value.trim().toLowerCase() as ToolKind;
  return [
    'a',
    'aaaa',
    'cname',
    'ns',
    'txt',
    'ptr',
    'caa',
    'soa',
    'dnssec',
    'srv',
    'mx',
    'spf',
    'dmarc',
    'dkim',
    'mta-sts',
    'tlsrpt',
    'dane',
    'bimi',
    'fcrdns',
    'rbl',
    'dbl',
    'message-analysis',
    'mail-server-test',
  ].includes(normalized)
    ? normalized
    : null;
}

function parseTargetType(value: unknown): TargetType | null {
  return value === 'domain' ||
    value === 'ip' ||
    value === 'email' ||
    value === 'headers' ||
    value === 'raw' ||
    value === 'host'
    ? value
    : null;
}

function summarizeDmarcPolicy(record: string | null): string | null {
  if (!record) {
    return null;
  }

  const tags = new Map(
    record
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const [key, rawValue] = part.split('=');
        return [key?.trim().toLowerCase() ?? '', rawValue?.trim() ?? ''] as const;
      })
  );

  const policy = tags.get('p') || 'none';
  const rua = tags.get('rua');
  const pct = tags.get('pct');
  return `Policy ${policy}${pct ? `, pct=${pct}` : ''}${rua ? ', aggregate reporting configured' : ''}.`;
}

function explainSpfRecord(record: string | null, permerror: boolean): string {
  if (!record) {
    return 'No SPF record is currently published for this domain.';
  }
  if (permerror) {
    return 'The SPF record was found but expansion hit an error or an invalid condition.';
  }

  const mechanismCount = record
    .split(/\s+/)
    .filter(
      (part) =>
        part.includes(':') ||
        ['mx', 'a', 'include', 'redirect'].some((token) => part.includes(token))
    ).length;
  return `SPF is published and currently expands cleanly. ${mechanismCount > 0 ? `It contains ${mechanismCount} mechanism${mechanismCount === 1 ? '' : 's'} or modifiers.` : ''}`;
}

function explainDkimRecord(selector: string, record: string | null): string {
  if (!record) {
    return `No TXT record resolved at ${selector}._domainkey for the checked domain.`;
  }
  const keyType = /k=([^;]+)/i.exec(record)?.[1]?.trim() ?? 'rsa';
  const hasKey = /p=([^;]+)/i.test(record);
  return `DKIM selector ${selector} resolved${hasKey ? ` with a ${keyType.toUpperCase()} public key` : ''}.`;
}

function explainMxHosts(hosts: string[]): string {
  if (hosts.length === 0) {
    return 'No MX hosts resolved for this domain.';
  }
  return hosts.length === 1
    ? `One MX host is currently published for this domain.`
    : `${hosts.length} MX hosts are currently published for this domain.`;
}

function explainOptionalRecord(
  label: string,
  record: string | null,
  positiveExplanation: string
): string {
  if (!record) {
    return `${label} is not currently published.`;
  }
  return positiveExplanation;
}

function countResultRecords(result: CheckResult): number {
  return result.records.reduce((total, record) => {
    if (!record.value) return total;
    const lines = record.value.split('\n').filter((line) => line.trim().length > 0);
    return total + (lines.length || 1);
  }, 0);
}

// The persisted "summary" column drives the history list's collapsed label. A
// verdict-only sentence (e.g. "MX records are present.") is identical across
// every domain with the same outcome, making history entries indistinguishable
// from one another. Lead with the query (and selector, if any) plus a record
// count so each entry can be told apart at a glance without expanding it.
function buildCheckHistorySummary(result: CheckResult): string {
  const count = countResultRecords(result);
  const noun = count === 1 ? 'record' : 'records';
  const label = result.selector ? `${result.targetValue} · ${result.selector}` : result.targetValue;
  return `${label} (${count} ${noun})`;
}

async function listHistoryEntries(filters: {
  adminId: number;
  issueId?: number;
  subjectValue?: string;
  toolKind?: ToolKind;
  targetType?: TargetType;
  targetValue?: string;
  selector?: string | null;
  limit?: number;
}): Promise<CheckHistoryEntry[]> {
  const conditions: string[] = ['admin_id = $1'];
  const params: unknown[] = [filters.adminId];

  if (filters.issueId) {
    params.push(filters.issueId);
    conditions.push(`issue_id = $${params.length}`);
  }
  if (filters.subjectValue) {
    params.push(filters.subjectValue);
    conditions.push(`subject_value = $${params.length}`);
  }
  if (filters.toolKind) {
    params.push(filters.toolKind);
    conditions.push(`tool_kind = $${params.length}`);
  }
  if (filters.targetType) {
    params.push(filters.targetType);
    conditions.push(`target_type = $${params.length}`);
  }
  if (filters.targetValue) {
    params.push(filters.targetValue.toLowerCase());
    conditions.push(`target_value = $${params.length}`);
  }
  if (filters.selector !== undefined) {
    if (filters.selector === null) {
      conditions.push('selector IS NULL');
    } else {
      params.push(filters.selector);
      conditions.push(`selector = $${params.length}`);
    }
  }

  params.push(Math.min(filters.limit ?? 10, 50));

  const result = await query<{
    id: number;
    issue_id: number | null;
    subject_value: string | null;
    tool_kind: ToolKind;
    target_type: TargetType;
    target_value: string;
    selector: string | null;
    status: VerificationStatus;
    summary: string | null;
    result_json: CheckResult;
    created_at: string;
  }>(
    `SELECT
       id,
       issue_id,
       subject_value,
       tool_kind,
       target_type,
       target_value,
       selector,
       status,
       summary,
       result_json,
       created_at
     FROM robin_tools_module.check_history
     ${conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''}
     ORDER BY created_at DESC
     LIMIT $${params.length}`,
    params
  );

  return result.rows.map((row) => ({
    id: row.id,
    issueId: row.issue_id,
    subjectValue: row.subject_value,
    toolKind: row.tool_kind,
    targetType: row.target_type,
    targetValue: row.target_value,
    selector: row.selector,
    status: row.status,
    summary: row.summary,
    result: row.result_json,
    createdAt: row.created_at,
  }));
}

async function createHistoryEntry(input: {
  adminId: number;
  issueId?: number | null;
  subjectValue?: string | null;
  toolKind: ToolKind;
  targetType: TargetType;
  targetValue: string;
  selector?: string | null;
  result: CheckResult;
}): Promise<CheckHistoryEntry> {
  const result = await query<{
    id: number;
    issue_id: number | null;
    subject_value: string | null;
    tool_kind: ToolKind;
    target_type: TargetType;
    target_value: string;
    selector: string | null;
    status: VerificationStatus;
    summary: string | null;
    result_json: CheckResult;
    created_at: string;
  }>(
    `INSERT INTO robin_tools_module.check_history (
       admin_id,
       issue_id,
       subject_value,
       tool_kind,
       target_type,
       target_value,
       selector,
       status,
       summary,
       result_json
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
     RETURNING
       id,
       issue_id,
       subject_value,
       tool_kind,
       target_type,
       target_value,
       selector,
       status,
       summary,
       result_json,
       created_at`,
    [
      input.adminId,
      input.issueId ?? null,
      input.subjectValue ?? null,
      input.toolKind,
      input.targetType,
      input.targetValue,
      input.selector ?? null,
      input.result.status,
      buildCheckHistorySummary(input.result),
      JSON.stringify(input.result),
    ]
  );

  const row = result.rows[0];
  return {
    id: row.id,
    issueId: row.issue_id,
    subjectValue: row.subject_value,
    toolKind: row.tool_kind,
    targetType: row.target_type,
    targetValue: row.target_value,
    selector: row.selector,
    status: row.status,
    summary: row.summary,
    result: row.result_json,
    createdAt: row.created_at,
  };
}

async function deleteHistoryEntry(id: number, adminId: number): Promise<boolean> {
  const result = await query(
    'DELETE FROM robin_tools_module.check_history WHERE id = $1 AND admin_id = $2',
    [id, adminId]
  );
  return (result.rowCount ?? 0) > 0;
}

async function clearHistoryEntries(filters: {
  adminId: number;
  toolKind?: ToolKind;
}): Promise<number> {
  if (filters.toolKind) {
    const result = await query(
      'DELETE FROM robin_tools_module.check_history WHERE admin_id = $1 AND tool_kind = $2',
      [filters.adminId, filters.toolKind]
    );
    return result.rowCount ?? 0;
  }

  const result = await query('DELETE FROM robin_tools_module.check_history WHERE admin_id = $1', [
    filters.adminId,
  ]);
  return result.rowCount ?? 0;
}

function createResolver(servers: string[]): dns.Resolver {
  const resolver = new dns.Resolver();
  if (servers.length > 0) {
    resolver.setServers(servers);
  }
  return resolver;
}

function isDnsMiss(error: unknown): boolean {
  const code =
    typeof error === 'object' && error ? String((error as { code?: unknown }).code ?? '') : '';
  return ['ENODATA', 'ENOTFOUND', 'ENODOMAIN', 'NXDOMAIN', 'ETIMEOUT'].includes(code);
}

function isDnsxlErrorResponse(address: string): boolean {
  return /^127\.255\.255\./.test(address);
}

function reverseIpForRbl(ip: string): string {
  const parsed = ipaddr.parse(ip.replace(/^::ffff:/, ''));
  if (parsed.kind() === 'ipv4') {
    return parsed.toString().split('.').reverse().join('.');
  }

  return parsed
    .toByteArray()
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .split('')
    .reverse()
    .join('.');
}

function buildDblQueryName(domain: string, provider: BlocklistProvider): string {
  return `${domain.replace(/\.$/, '')}.${provider.zone}`;
}

function buildRblQueryName(ip: string, provider: BlocklistProvider): string {
  return `${reverseIpForRbl(ip)}.${provider.zone}`;
}

async function resolveARecords(
  queryName: string,
  resolver: dns.Resolver,
  timeoutMs: number
): Promise<{ addresses: string[]; error: string | null }> {
  try {
    const addresses = await withTimeout(resolver.resolve4(queryName), timeoutMs, `A ${queryName}`);
    return { addresses, error: null };
  } catch (error) {
    return {
      addresses: [],
      error: isDnsMiss(error) ? null : (error as Error).message || 'DNS lookup failed',
    };
  }
}

async function resolveTxtRecords(
  queryName: string,
  resolver: dns.Resolver,
  timeoutMs: number
): Promise<string[]> {
  try {
    const txt = await withTimeout(resolver.resolveTxt(queryName), timeoutMs, `TXT ${queryName}`);
    return txt.map((parts) => parts.join('')).filter(Boolean);
  } catch {
    return [];
  }
}

async function runDnsxlLookup(input: {
  queryName: string;
  provider: BlocklistProvider;
  settings: ToolSettings;
}): Promise<BlocklistHit> {
  const primaryResolver = createResolver(input.settings.resolvers);
  const primary = await resolveARecords(input.queryName, primaryResolver, input.settings.timeoutMs);
  const nonErrorResponses = primary.addresses.filter((address) => !isDnsxlErrorResponse(address));
  const errorResponses = primary.addresses.filter(isDnsxlErrorResponse);
  const txt =
    primary.addresses.length > 0
      ? await resolveTxtRecords(input.queryName, primaryResolver, input.settings.timeoutMs)
      : [];

  if (errorResponses.length > 0 && nonErrorResponses.length === 0) {
    return {
      provider: input.provider,
      queryName: input.queryName,
      listed: false,
      responses: errorResponses,
      txt,
      error: `Provider returned DNSxL error code ${errorResponses.join(', ')}`,
      disputed: false,
    };
  }

  if (nonErrorResponses.length > 0 && input.settings.confirmResolvers.length > 0) {
    const confirmResolver = createResolver(input.settings.confirmResolvers);
    const confirm = await resolveARecords(
      input.queryName,
      confirmResolver,
      input.settings.timeoutMs
    );
    const confirmed = confirm.addresses.filter((address) => !isDnsxlErrorResponse(address));
    if (confirmed.length === 0) {
      return {
        provider: input.provider,
        queryName: input.queryName,
        listed: false,
        responses: nonErrorResponses,
        txt,
        error: 'Primary resolver saw a listing, but confirm resolvers did not.',
        disputed: true,
      };
    }
  }

  return {
    provider: input.provider,
    queryName: input.queryName,
    listed: nonErrorResponses.length > 0,
    responses: nonErrorResponses,
    txt,
    error: primary.error,
    disputed: false,
  };
}

async function mapLimited<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T) => Promise<R>
): Promise<R[]> {
  const results: R[] = [];
  let nextIndex = 0;
  const workers = Array.from(
    { length: Math.min(Math.max(concurrency, 1), items.length) },
    async () => {
      while (nextIndex < items.length) {
        const index = nextIndex;
        nextIndex += 1;
        results[index] = await worker(items[index]);
      }
    }
  );
  await Promise.all(workers);
  return results;
}

function blocklistRecords(hits: BlocklistHit[]): CheckRecord[] {
  return hits.map((hit) => ({
    key: hit.provider.id,
    label: hit.provider.label,
    value: [
      `Query: ${hit.queryName}`,
      hit.responses.length > 0 ? `A: ${hit.responses.join(', ')}` : 'A: clear',
      hit.txt.length > 0 ? `TXT: ${hit.txt.join(' | ')}` : null,
      hit.error ? `Note: ${hit.error}` : null,
    ]
      .filter(Boolean)
      .join('\n'),
    ok: hit.error && !hit.disputed ? null : !hit.listed,
    explanation: hit.listed
      ? `${hit.provider.label} returned a listing response.`
      : hit.disputed
        ? 'The primary resolver result was not confirmed, so Robin Tools did not treat it as listed.'
        : hit.error
          ? hit.error
          : `${hit.provider.label} did not list this target.`,
  }));
}

async function runBlocklistCheck(input: {
  kind: 'rbl' | 'dbl';
  targets: string[];
  settings: ToolSettings;
}): Promise<CheckResult> {
  const providers = (
    input.kind === 'rbl' ? input.settings.rblProviders : input.settings.dblProviders
  )
    .filter((provider) => provider.enabled)
    .slice(0, MAX_BLOCKLIST_PROVIDERS);

  if (providers.length === 0) {
    throw new ValidationError(`No enabled ${input.kind.toUpperCase()} providers are configured`);
  }

  const targets = [...new Set(input.targets)]
    .map((target) => (input.kind === 'rbl' ? target.trim() : target.trim().toLowerCase()))
    .filter((target) =>
      input.kind === 'rbl' ? net.isIP(target) > 0 : Boolean(parseDomain(target))
    )
    .slice(0, MAX_BLOCKLIST_TARGETS);

  if (targets.length === 0) {
    throw new ValidationError(
      input.kind === 'rbl'
        ? 'At least one valid IP address is required'
        : 'At least one valid domain is required'
    );
  }

  const work = targets.flatMap((target) =>
    providers.map((provider) => ({
      target,
      provider,
      queryName:
        input.kind === 'rbl'
          ? buildRblQueryName(target, provider)
          : buildDblQueryName(target, provider),
    }))
  );
  const hits = await mapLimited(work, input.settings.concurrency, (item) =>
    runDnsxlLookup({
      queryName: item.queryName,
      provider: item.provider,
      settings: input.settings,
    })
  );
  const listedHits = hits.filter((hit) => hit.listed);
  const disputedHits = hits.filter((hit) => hit.disputed);
  const errorHits = hits.filter((hit) => hit.error && !hit.disputed);
  const status: VerificationStatus =
    listedHits.length > 0
      ? 'fail'
      : errorHits.length > 0 || disputedHits.length > 0
        ? 'warning'
        : 'pass';
  const targetValue = targets.length === 1 ? targets[0] : `${targets.length} targets`;

  return {
    toolKind: input.kind,
    targetType: input.kind === 'rbl' ? 'ip' : 'domain',
    targetValue,
    selector: null,
    status,
    summary:
      listedHits.length > 0
        ? `${listedHits.length} of ${hits.length} ${input.kind.toUpperCase()} lookups returned listing responses.`
        : disputedHits.length > 0
          ? `No confirmed listings; ${disputedHits.length} lookup${disputedHits.length === 1 ? '' : 's'} were disputed.`
          : `No ${input.kind.toUpperCase()} listings were found across ${hits.length} lookups.`,
    checkedAt: new Date().toISOString(),
    records: blocklistRecords(hits),
    findings: listedHits.map((hit) => ({
      severity: input.kind === 'rbl' ? 'high' : 'medium',
      code: `${input.kind}_listed`,
      title: `${hit.provider.label} listing`,
      detail: `${hit.queryName} returned ${hit.responses.join(', ')}${hit.txt.length ? ` (${hit.txt.join(' | ')})` : ''}.`,
    })),
    meta: {
      targets,
      providers: providers.map((provider) => ({
        id: provider.id,
        zone: provider.zone,
        label: provider.label,
      })),
      listed: listedHits.length,
      disputed: disputedHits.length,
      errors: errorHits.length,
    },
  };
}

function splitHeaders(raw: string): string {
  const normalized = raw.replace(/\r\n/g, '\n');
  const headerEnd = normalized.search(/\n\s*\n/);
  return (headerEnd >= 0 ? normalized.slice(0, headerEnd) : normalized).slice(
    0,
    MAX_ANALYSIS_INPUT_CHARS
  );
}

function isSafeHeaderName(name: string): boolean {
  if (!name || name === '__proto__' || name === 'constructor' || name === 'prototype') {
    return false;
  }
  for (let index = 0; index < name.length; index += 1) {
    const code = name.charCodeAt(index);
    const isTokenChar =
      (code >= 65 && code <= 90) ||
      (code >= 97 && code <= 122) ||
      (code >= 48 && code <= 57) ||
      "!#$%&'*+-.^_`|~".includes(name[index]);
    if (!isTokenChar) {
      return false;
    }
  }
  return true;
}

function parseHeaderMap(rawHeaders: string): HeaderMap {
  const headers: HeaderMap = new Map();
  let currentName: string | null = null;
  for (const line of rawHeaders.split('\n')) {
    if ((line.startsWith(' ') || line.startsWith('\t')) && currentName) {
      const values = headers.get(currentName) ?? [];
      values[values.length - 1] = `${values[values.length - 1]} ${line.trim()}`;
      continue;
    }
    const separator = line.indexOf(':');
    if (separator <= 0) {
      currentName = null;
      continue;
    }
    const name = line.slice(0, separator).trim().toLowerCase();
    if (!isSafeHeaderName(name)) {
      currentName = null;
      continue;
    }
    currentName = name;
    headers.set(currentName, [
      ...(headers.get(currentName) ?? []),
      line.slice(separator + 1).trim(),
    ]);
  }
  return headers;
}

function firstHeader(headers: HeaderMap, name: string): string | null {
  return headers.get(name.toLowerCase())?.[0] ?? null;
}

function isEmailLocalPartChar(value: string): boolean {
  const code = value.charCodeAt(0);
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    ".!#$%&'*+/=?^_`{|}~-".includes(value)
  );
}

function isValidEmailLocalPart(value: string): boolean {
  if (!value || value.startsWith('.') || value.endsWith('.') || value.includes('..')) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    if (!isEmailLocalPartChar(value[index])) {
      return false;
    }
  }
  return true;
}

function emailCandidateTokens(value: string): string[] {
  const tokens: string[] = [];
  let start: number | null = null;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    const isCandidateChar = isEmailLocalPartChar(char) || char === '@';
    if (isCandidateChar && start === null) {
      start = index;
    } else if (!isCandidateChar && start !== null) {
      tokens.push(value.slice(start, index));
      start = null;
    }
  }
  if (start !== null) {
    tokens.push(value.slice(start));
  }
  return tokens;
}

function extractEmails(value: string): string[] {
  const emails = new Set<string>();
  for (const token of emailCandidateTokens(value)) {
    const atIndex = token.indexOf('@');
    if (atIndex <= 0 || atIndex !== token.lastIndexOf('@')) {
      continue;
    }

    const local = token.slice(0, atIndex);
    const domain = parseDomain(token.slice(atIndex + 1));
    if (domain && isValidEmailLocalPart(local)) {
      emails.add(`${local.toLowerCase()}@${domain}`);
    }
  }
  return [...emails];
}

function domainFromEmailValue(value: string | null): string | null {
  if (!value) return null;
  const email = extractEmails(value)[0];
  if (!email) return null;
  return parseDomain(email.slice(email.lastIndexOf('@') + 1));
}

function extractUrls(value: string): string[] {
  return [...value.matchAll(/https?:\/\/[^\s<>"')]+/gi)].map((match) => match[0]).slice(0, 200);
}

function extractDomains(value: string): string[] {
  const domains = new Set<string>();
  for (const email of extractEmails(value)) {
    const domain = parseDomain(email.slice(email.lastIndexOf('@') + 1));
    if (domain) domains.add(domain);
  }
  for (const url of extractUrls(value)) {
    try {
      const domain = parseDomain(new URL(url).hostname);
      if (domain) domains.add(domain);
    } catch {
      // ignore malformed URLs from raw message text
    }
  }
  for (const match of value.matchAll(/\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi)) {
    const domain = parseDomain(match[0]);
    if (domain) domains.add(domain);
  }
  return [...domains].slice(0, 200);
}

function extractIps(value: string): string[] {
  const ips = new Set<string>();
  for (const match of value.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
    if (net.isIP(match[0]) > 0) ips.add(match[0]);
  }
  for (const match of value.matchAll(/\b(?:[a-f0-9]{0,4}:){2,}[a-f0-9]{0,4}\b/gi)) {
    if (net.isIP(match[0]) > 0) ips.add(match[0]);
  }
  return [...ips].slice(0, 200);
}

function parseDkimSignatures(
  headers: HeaderMap
): Array<{ selector: string; domain: string; algorithm: string | null }> {
  return (headers.get('dkim-signature') ?? [])
    .map((value) => {
      const tags = new Map(
        value.split(';').map((part) => {
          const [key, ...rest] = part.split('=');
          return [key.trim().toLowerCase(), rest.join('=').trim()] as const;
        })
      );
      return {
        selector: tags.get('s') ?? '',
        domain: tags.get('d') ?? '',
        algorithm: tags.get('a') ?? null,
      };
    })
    .filter((item) => parseDomain(item.domain) && item.selector);
}

function parseMessageInput(
  inputKind: ParsedMessageInput['inputKind'],
  value: string
): ParsedMessageInput {
  const trimmed = value.trim().slice(0, MAX_ANALYSIS_INPUT_CHARS);
  const rawHeaders = inputKind === 'domain' || inputKind === 'email' ? '' : splitHeaders(trimmed);
  const headers = rawHeaders ? parseHeaderMap(rawHeaders) : new Map<string, string[]>();
  const email =
    inputKind === 'email'
      ? (extractEmails(trimmed)[0] ?? null)
      : (extractEmails(firstHeader(headers, 'from') ?? '')[0] ?? null);
  const domain =
    inputKind === 'domain'
      ? parseDomain(trimmed)
      : inputKind === 'email'
        ? domainFromEmailValue(trimmed)
        : (domainFromEmailValue(firstHeader(headers, 'from')) ??
          domainFromEmailValue(firstHeader(headers, 'return-path')));
  const domains = new Set<string>();
  if (domain) domains.add(domain);
  for (const item of extractDomains(trimmed)) domains.add(item);
  for (const signature of parseDkimSignatures(headers)) {
    const signingDomain = parseDomain(signature.domain);
    if (signingDomain) domains.add(signingDomain);
  }
  return {
    inputKind,
    value: trimmed,
    domain,
    email,
    headers,
    rawHeaders,
    domains: [...domains],
    ips: extractIps(trimmed),
    dkimSelectors: parseDkimSignatures(headers),
    urls: extractUrls(trimmed),
  };
}

function messageHeaderFindings(parsed: ParsedMessageInput): DomainIssue[] {
  if (parsed.inputKind === 'domain' || parsed.inputKind === 'email') {
    return [];
  }

  const findings: DomainIssue[] = [];
  for (const header of ['from', 'date', 'message-id', 'subject']) {
    if (!firstHeader(parsed.headers, header)) {
      findings.push({
        severity: 'low',
        code: `missing_${header.replace(/-/g, '_')}`,
        title: `${header} header missing`,
        detail: `The submitted message headers do not include ${header}.`,
      });
    }
  }
  if (
    (parsed.headers.has('list-id') || parsed.headers.has('list-unsubscribe')) &&
    !firstHeader(parsed.headers, 'list-unsubscribe')
  ) {
    findings.push({
      severity: 'medium',
      code: 'list_unsubscribe_missing',
      title: 'List-Unsubscribe missing',
      detail: 'The message looks list-like but does not include List-Unsubscribe.',
    });
  }
  return findings;
}

function statusFromFindings(findings: DomainIssue[]): VerificationStatus {
  if (findings.some((finding) => finding.severity === 'critical' || finding.severity === 'high'))
    return 'fail';
  if (findings.length > 0) return 'warning';
  return 'pass';
}

async function runEmailAnalysis(
  inputKind: ParsedMessageInput['inputKind'],
  value: string,
  settings: ToolSettings
): Promise<CheckResult> {
  const parsed = parseMessageInput(inputKind, value);
  if (!parsed.domain && parsed.domains.length === 0 && parsed.ips.length === 0) {
    throw new ValidationError(
      'Provide a domain, email address, headers, or raw email with analyzable domains or IPs'
    );
  }

  const primaryDomain = parsed.domain ?? parsed.domains[0] ?? null;
  // Find a DKIM selector that matches the primary domain, or fall back to first
  const primaryDkimSelector =
    parsed.dkimSelectors.find((sig) => sig.domain === primaryDomain)?.selector ??
    parsed.dkimSelectors[0]?.selector ??
    null;
  const dnsResult = primaryDomain
    ? await runBulkDomainChecks([primaryDomain], primaryDkimSelector, {
        mtaSts: true,
        tlsRpt: true,
        dane: true,
        bimi: true,
      })
    : [];
  // Check all DKIM selectors against their respective domains
  const dkimResults = await Promise.all(
    parsed.dkimSelectors.map(async (sig) => {
      const record = await resolveDkimRecord(sig.domain, sig.selector);
      return { ...sig, record, resolved: Boolean(record) };
    })
  );
  const dblTargets = parsed.domains.slice(0, MAX_BLOCKLIST_TARGETS);
  const dblResult =
    dblTargets.length > 0
      ? await runBlocklistCheck({ kind: 'dbl', targets: dblTargets, settings }).catch(() => null)
      : null;
  const rblResult =
    parsed.ips.length > 0
      ? await runBlocklistCheck({ kind: 'rbl', targets: parsed.ips, settings }).catch(() => null)
      : null;
  // Filter out "dkim_missing" if no selectors expected OR if any DKIM selector resolved
  const anyDkimResolved = dkimResults.some((r) => r.resolved);
  const dnsIssues =
    inputKind === 'domain' || inputKind === 'email' || anyDkimResolved
      ? (dnsResult[0]?.issues ?? []).filter((issue) => issue.code !== 'dkim_missing')
      : (dnsResult[0]?.issues ?? []);
  const findings = [
    ...messageHeaderFindings(parsed),
    ...dnsIssues,
    ...(dblResult?.findings ?? []),
    ...(rblResult?.findings ?? []),
  ];

  return {
    toolKind: 'message-analysis',
    targetType: inputKind,
    targetValue:
      inputKind === 'raw' || inputKind === 'headers'
        ? `${inputKind} input`
        : value.trim().slice(0, 255),
    selector: parsed.dkimSelectors[0]?.selector ?? null,
    status: statusFromFindings(findings),
    summary:
      findings.length > 0
        ? `${findings.length} diagnostic finding${findings.length === 1 ? '' : 's'} found across parsed message evidence.`
        : 'No blocking or publishing issues were found in the parsed diagnostic evidence.',
    checkedAt: new Date().toISOString(),
    records: [
      {
        key: 'parsed-input',
        label: 'Parsed evidence',
        value: [
          parsed.domain ? `Primary domain: ${parsed.domain}` : null,
          parsed.email ? `Email: ${parsed.email}` : null,
          `Domains: ${parsed.domains.length ? parsed.domains.join(', ') : 'none'}`,
          `IPs: ${parsed.ips.length ? parsed.ips.join(', ') : 'none'}`,
          `DKIM selectors: ${parsed.dkimSelectors.length ? parsed.dkimSelectors.map((item) => `${item.selector}._domainkey.${item.domain}`).join(', ') : 'none'}`,
          `URLs: ${parsed.urls.length}`,
        ]
          .filter(Boolean)
          .join('\n'),
        ok: true,
        explanation:
          'Robin Tools extracted domains, IPs, and selectors from the submitted diagnostic input.',
      },
      ...(dnsResult[0]
        ? [
            {
              key: 'dns-posture',
              label: 'Primary domain DNS posture',
              value: Object.entries(dnsResult[0].checks)
                .map(
                  ([key, val]) =>
                    `${key.toUpperCase()}: ${val === true ? '✓' : val === false ? '✗' : '—'}`
                )
                .join('\n'),
              ok: dnsResult[0].issues.length === 0,
              explanation: `DNS posture checked for ${dnsResult[0].domain}.`,
            },
          ]
        : []),
      ...(dkimResults.length > 0
        ? [
            {
              key: 'dkim-selectors',
              label: 'DKIM selector verification',
              value: dkimResults
                .map(
                  (r) =>
                    `${r.selector}._domainkey.${r.domain}: ${r.resolved ? '✓ resolved' : '✗ not found'}`
                )
                .join('\n'),
              ok: dkimResults.every((r) => r.resolved),
              explanation: 'DKIM selectors from message headers were verified against DNS.',
            },
          ]
        : []),
      ...(dblResult
        ? [
            {
              key: 'dbl-summary',
              label: 'DBL summary',
              value: dblResult.summary,
              ok: dblResult.status === 'pass',
              explanation: 'Configured DBL providers were checked against parsed domains.',
            },
          ]
        : []),
      ...(rblResult
        ? [
            {
              key: 'rbl-summary',
              label: 'RBL summary',
              value: rblResult.summary,
              ok: rblResult.status === 'pass',
              explanation: 'Configured RBL providers were checked against parsed IP addresses.',
            },
          ]
        : []),
      {
        key: 'headers',
        label: 'Submitted headers',
        value: parsed.rawHeaders || null,
        ok: null,
        explanation: parsed.rawHeaders
          ? 'Headers were parsed with folded lines unfolded for analysis.'
          : 'No raw headers were submitted.',
      },
    ],
    findings,
    meta: {
      parsed,
      dns: dnsResult,
      dbl: dblResult,
      rbl: rblResult,
      dkim: dkimResults,
    },
  };
}

async function resolveProbeAddresses(host: string, timeoutMs: number): Promise<string[]> {
  if (net.isIP(host) > 0) {
    return [host];
  }
  const addresses = await withTimeout(dns.lookup(host, { all: true }), timeoutMs, `lookup ${host}`);
  return addresses.map((address) => address.address);
}

function protocolForPort(port: number): ServerPortResult['protocol'] {
  if (port === 25 || port === 587) return 'smtp';
  if (port === 465) return 'smtps';
  if (port === 110) return 'pop3';
  if (port === 995) return 'pop3s';
  if (port === 143) return 'imap';
  if (port === 993) return 'imaps';
  return 'tcp';
}

function socketConnect(address: string, port: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: address, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`Connection timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.setTimeout(timeoutMs);
      resolve(socket);
    });
    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function readSocket(socket: net.Socket, timeoutMs: number): Promise<string | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), timeoutMs);
    socket.once('data', (chunk) => {
      clearTimeout(timer);
      resolve(chunk.toString('utf8').trim());
    });
    socket.once('error', () => {
      clearTimeout(timer);
      resolve(null);
    });
  });
}

function connectTls(
  address: string,
  host: string,
  port: number,
  timeoutMs: number
): Promise<tls.TLSSocket> {
  return withTimeout(
    new Promise<tls.TLSSocket>((resolve, reject) => {
      const socket = tls.connect(
        {
          host: address,
          port,
          servername: net.isIP(host) ? undefined : host,
          rejectUnauthorized: true,
        },
        () => resolve(socket)
      );
      socket.once('error', reject);
    }),
    timeoutMs,
    `TLS ${host}:${port}`
  );
}

function upgradeTls(
  socket: net.Socket,
  host: string,
  port: number,
  timeoutMs: number
): Promise<tls.TLSSocket> {
  return withTimeout(
    new Promise<tls.TLSSocket>((resolve, reject) => {
      const wrapped = tls.connect(
        { socket, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: true },
        () => resolve(wrapped)
      );
      wrapped.once('error', reject);
    }),
    timeoutMs,
    `STARTTLS ${host}:${port}`
  );
}

function certSummary(socket: tls.TLSSocket): { subject: string | null; validTo: string | null } {
  const cert = socket.getPeerCertificate();
  if (!cert || Object.keys(cert).length === 0) {
    return { subject: null, validTo: null };
  }
  const subject = cert.subject
    ? Object.entries(cert.subject)
        .map(([key, item]) => `${key}=${String(item)}`)
        .join(', ')
    : null;
  return { subject, validTo: cert.valid_to ?? null };
}

function errorCode(error: unknown): string {
  return typeof error === 'object' && error && 'code' in error ? String(error.code) : '';
}

function safeErrorDetail(error: unknown): string {
  const code = errorCode(error);
  const message = error instanceof Error ? error.message : String(error);
  return [code, message]
    .filter(Boolean)
    .join(': ')
    .replace(/[\r\n]+/g, ' ')
    .slice(0, 300);
}

function tlsFailure(
  error: unknown
): Pick<ServerPortResult, 'phase' | 'failureKind' | 'reason' | 'nextStep' | 'technicalDetail'> {
  const code = typeof error === 'object' && error && 'code' in error ? String(error.code) : '';
  if (
    code === 'ECONNREFUSED' ||
    code === 'ETIMEDOUT' ||
    /timed out/i.test(safeErrorDetail(error))
  ) {
    return connectionFailure(error);
  }
  const technicalDetail = safeErrorDetail(error);
  if (code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
    return {
      phase: 'certificate',
      failureKind: 'certificate',
      reason: 'The certificate does not match the server hostname.',
      nextStep: 'Install a certificate whose SAN includes this hostname.',
      technicalDetail,
    };
  }
  if (code === 'CERT_HAS_EXPIRED') {
    return {
      phase: 'certificate',
      failureKind: 'certificate',
      reason: 'The TLS certificate has expired.',
      nextStep: 'Renew and deploy the certificate, including its complete chain.',
      technicalDetail,
    };
  }
  if (
    code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
    code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
    code.startsWith('UNABLE_TO_VERIFY') ||
    code === 'CERT_UNTRUSTED'
  ) {
    return {
      phase: 'certificate',
      failureKind: 'certificate',
      reason: 'The TLS certificate chain is not publicly trusted.',
      nextStep: 'Install a publicly trusted certificate and complete intermediate chain.',
      technicalDetail,
    };
  }
  return {
    phase: 'tls-handshake',
    failureKind: 'tls-handshake',
    reason: 'TLS negotiation failed before a verified session was established.',
    nextStep: 'Check protocol versions, ciphers, SNI, and the server TLS logs.',
    technicalDetail,
  };
}

function connectionFailure(
  error: unknown
): Pick<ServerPortResult, 'phase' | 'failureKind' | 'reason' | 'nextStep' | 'technicalDetail'> {
  const code = errorCode(error);
  const technicalDetail = safeErrorDetail(error);
  if (code === 'ETIMEDOUT' || /timed out/i.test(technicalDetail)) {
    return {
      phase: 'connect',
      failureKind: 'timeout',
      reason: 'The TCP connection timed out.',
      nextStep: 'Check firewall rules, routing, and whether the service is listening on this port.',
      technicalDetail,
    };
  }
  if (code === 'ECONNREFUSED') {
    return {
      phase: 'connect',
      failureKind: 'refused',
      reason: 'The host refused the TCP connection.',
      nextStep: 'Start the service or verify that the configured port is correct.',
      technicalDetail,
    };
  }
  return {
    phase: 'connect',
    failureKind: 'network',
    reason: 'The TCP connection failed.',
    nextStep: 'Check address routing, firewall policy, and server availability.',
    technicalDetail,
  };
}

type ProbeDependencies = {
  connect: typeof socketConnect;
  read: typeof readSocket;
  connectTls: typeof connectTls;
  upgradeTls: typeof upgradeTls;
};

export async function probePort(
  host: string,
  address: string,
  port: number,
  timeoutMs: number,
  overrides: Partial<ProbeDependencies> = {}
): Promise<ServerPortResult> {
  const dependencies: ProbeDependencies = {
    connect: socketConnect,
    read: readSocket,
    connectTls,
    upgradeTls,
    ...overrides,
  };
  const protocol = protocolForPort(port);
  const base: ServerPortResult = {
    port,
    protocol,
    open: false,
    banner: null,
    ehlo: null,
    startTls: null,
    tls: false,
    tlsVerified: null,
    certSubject: null,
    certValidTo: null,
    error: null,
    phase: 'connect',
    failureKind: null,
    reason: null,
    nextStep: null,
    technicalDetail: null,
    checksPerformed: [],
  };

  try {
    if (protocol === 'smtps' || protocol === 'imaps' || protocol === 'pop3s') {
      try {
        const socket = await dependencies.connectTls(address, host, port, timeoutMs);
        const cert = certSummary(socket);
        socket.end();
        return {
          ...base,
          open: true,
          tls: true,
          tlsVerified: true,
          certSubject: cert.subject,
          certValidTo: cert.validTo,
          phase: 'complete',
          checksPerformed: ['connection', 'TLS handshake', 'certificate verification'],
        };
      } catch (error) {
        const failure = tlsFailure(error);
        return {
          ...base,
          open: failure.phase !== 'connect',
          tlsVerified: failure.phase === 'connect' ? null : false,
          error: failure.reason,
          ...failure,
          checksPerformed:
            failure.phase === 'connect' ? ['connection'] : ['connection', 'TLS handshake'],
        };
      }
    }

    const socket = await dependencies.connect(address, port, timeoutMs);
    const checksPerformed = ['connection'];
    const banner = await dependencies.read(socket, Math.min(timeoutMs, 2000));
    checksPerformed.push('banner');
    let ehlo: string | null = null;
    let startTls: boolean | null = null;
    let tlsUsed = false;
    let certSubject: string | null = null;
    let certValidTo: string | null = null;

    if (protocol === 'smtp') {
      if (!banner || !/^220(?:[ -]|$)/.test(banner)) {
        socket.destroy();
        const reason = banner
          ? 'The server returned a malformed SMTP banner.'
          : 'The server did not return an SMTP banner before timeout.';
        return {
          ...base,
          open: true,
          banner,
          phase: 'banner',
          failureKind: banner ? 'protocol' : 'timeout',
          reason,
          error: reason,
          nextStep:
            'Verify the SMTP service banner and inspect the server logs for stalled or non-SMTP connections.',
          technicalDetail: banner ? `Received: ${banner.slice(0, 300)}` : null,
          checksPerformed,
        };
      }
      socket.write('EHLO robin-tools.local\r\n');
      ehlo = await dependencies.read(socket, Math.min(timeoutMs, 3000));
      checksPerformed.push('EHLO');
      if (!ehlo || !/^250(?:[ -]|$)/.test(ehlo)) {
        socket.write('HELO robin-tools.local\r\n');
        const helo = await dependencies.read(socket, Math.min(timeoutMs, 3000));
        checksPerformed.push('HELO fallback');
        if (!helo || !/^250(?:[ -]|$)/.test(helo)) {
          socket.destroy();
          const reason = 'The server did not accept EHLO or the HELO fallback.';
          return {
            ...base,
            open: true,
            banner,
            ehlo,
            phase: 'ehlo',
            failureKind: 'protocol',
            reason,
            error: reason,
            nextStep: 'Check SMTP command handling and confirm the endpoint is an SMTP service.',
            technicalDetail: `EHLO: ${(ehlo ?? 'no response').slice(0, 180)}; HELO: ${(helo ?? 'no response').slice(0, 180)}`,
            checksPerformed,
          };
        }
      }
      startTls = /STARTTLS/i.test(ehlo ?? '');
      checksPerformed.push('STARTTLS availability');
      if (!startTls) {
        socket.write('QUIT\r\n');
        socket.end();
        const reason = 'The SMTP service did not advertise STARTTLS.';
        return {
          ...base,
          open: true,
          banner,
          ehlo,
          startTls: false,
          phase: 'starttls',
          failureKind: 'starttls-unavailable',
          reason,
          error: reason,
          nextStep: 'Enable STARTTLS and advertise it in the EHLO response.',
          technicalDetail: `EHLO: ${(ehlo ?? 'no response').slice(0, 300)}`,
          checksPerformed,
        };
      }
      if (startTls) {
        socket.write('STARTTLS\r\n');
        const response = await dependencies.read(socket, Math.min(timeoutMs, 3000));
        checksPerformed.push('STARTTLS command');
        if (/^220/.test(response ?? '')) {
          try {
            const tlsSocket = await dependencies.upgradeTls(socket, host, port, timeoutMs);
            const cert = certSummary(tlsSocket);
            tlsUsed = true;
            certSubject = cert.subject;
            certValidTo = cert.validTo;
            tlsSocket.end();
            return {
              ...base,
              open: true,
              banner,
              ehlo,
              startTls,
              tls: tlsUsed,
              tlsVerified: true,
              certSubject,
              certValidTo,
              phase: 'complete',
              checksPerformed: [...checksPerformed, 'TLS handshake', 'certificate verification'],
            };
          } catch (error) {
            socket.destroy();
            const failure = tlsFailure(error);
            return {
              ...base,
              open: true,
              banner,
              ehlo,
              startTls,
              tlsVerified: false,
              error: failure.reason,
              ...failure,
              checksPerformed: [...checksPerformed, 'TLS handshake'],
            };
          }
        }
        socket.destroy();
        const reason = 'The server rejected the STARTTLS command.';
        return {
          ...base,
          open: true,
          banner,
          ehlo,
          startTls,
          phase: 'starttls',
          failureKind: 'protocol',
          reason,
          error: reason,
          nextStep:
            'Inspect SMTP TLS configuration and ensure STARTTLS returns a 220 ready response.',
          technicalDetail: `Received: ${(response ?? 'no response').slice(0, 300)}`,
          checksPerformed,
        };
      }
      socket.write('QUIT\r\n');
    } else if (protocol === 'pop3' || protocol === 'imap') {
      const validBanner =
        protocol === 'pop3'
          ? /^\+OK(?:[ \r\n]|$)/i.test(banner ?? '')
          : /^\*\s+OK(?:[ \r\n]|$)/i.test(banner ?? '');
      if (!validBanner) {
        socket.destroy();
        const reason = banner
          ? `The server returned a malformed ${protocol.toUpperCase()} greeting.`
          : `The server did not return a ${protocol.toUpperCase()} greeting before timeout.`;
        return {
          ...base,
          open: true,
          banner,
          phase: 'banner',
          failureKind: banner ? 'protocol' : 'timeout',
          reason,
          error: reason,
          nextStep: `Verify the ${protocol.toUpperCase()} service greeting and inspect its server logs.`,
          technicalDetail: banner ? `Received: ${banner.slice(0, 300)}` : null,
          checksPerformed,
        };
      }

      const command = protocol === 'pop3' ? 'STLS\r\n' : 'a001 STARTTLS\r\n';
      socket.write(command);
      const response = await dependencies.read(socket, Math.min(timeoutMs, 3000));
      checksPerformed.push('STARTTLS command');
      const accepted =
        protocol === 'pop3'
          ? /^\+OK(?:[ \r\n]|$)/i.test(response ?? '')
          : /^a001\s+OK(?:[ \r\n]|$)/i.test(response ?? '');
      startTls = accepted;
      if (!accepted) {
        socket.end();
        const reason = `The ${protocol.toUpperCase()} service did not accept its TLS upgrade command.`;
        return {
          ...base,
          open: true,
          banner,
          startTls: false,
          phase: 'starttls',
          failureKind: 'starttls-unavailable',
          reason,
          error: reason,
          nextStep: `Enable ${protocol === 'pop3' ? 'STLS' : 'STARTTLS'} on this service or use its implicit TLS port.`,
          technicalDetail: `Received: ${(response ?? 'no response').slice(0, 300)}`,
          checksPerformed,
        };
      }

      try {
        const tlsSocket = await dependencies.upgradeTls(socket, host, port, timeoutMs);
        const cert = certSummary(tlsSocket);
        tlsSocket.end();
        return {
          ...base,
          open: true,
          banner,
          startTls: true,
          tls: true,
          tlsVerified: true,
          certSubject: cert.subject,
          certValidTo: cert.validTo,
          phase: 'complete',
          checksPerformed: [...checksPerformed, 'TLS handshake', 'certificate verification'],
        };
      } catch (error) {
        socket.destroy();
        const failure = tlsFailure(error);
        return {
          ...base,
          open: true,
          banner,
          startTls: true,
          tlsVerified: false,
          error: failure.reason,
          ...failure,
          checksPerformed: [...checksPerformed, 'TLS handshake'],
        };
      }
    }
    socket.end();
    return {
      ...base,
      open: true,
      banner,
      ehlo,
      startTls,
      tls: tlsUsed,
      certSubject,
      certValidTo,
      phase: 'complete',
      checksPerformed,
    };
  } catch (error) {
    const failure = connectionFailure(error);
    return { ...base, error: failure.reason, ...failure };
  }
}

function portFindings(host: string, results: ServerPortResult[]): DomainIssue[] {
  const findings: DomainIssue[] = [];
  for (const result of results) {
    if (result.failureKind) {
      const severity: Severity = result.failureKind === 'starttls-unavailable' ? 'medium' : 'high';
      const detail = [
        `${host}:${result.port} failed during ${result.phase}: ${result.reason}`,
        result.nextStep ? `Next step: ${result.nextStep}` : null,
        result.technicalDetail ? `Technical detail: ${result.technicalDetail}` : null,
      ]
        .filter(Boolean)
        .join(' ');
      findings.push({
        severity,
        code: `mail_server_${result.phase.replace('-', '_')}_${result.failureKind.replace('-', '_')}_${result.port}`,
        title: `${result.protocol.toUpperCase()} ${result.port}: ${result.phase} failed`,
        detail,
      });
    }
    if (result.open && result.certValidTo) {
      const expiresAt = new Date(result.certValidTo);
      if (
        !Number.isNaN(expiresAt.getTime()) &&
        expiresAt.getTime() < Date.now() + 14 * 24 * 60 * 60_000
      ) {
        findings.push({
          severity: 'medium',
          code: `tls_certificate_expiring_${result.port}`,
          title: `TLS certificate expiry on ${result.port}`,
          detail: `${host}:${result.port} certificate expires at ${result.certValidTo}. Next step: renew and deploy the certificate before expiry.`,
        });
      }
    }
  }
  if (results.length === 0) {
    findings.push({
      severity: 'high',
      code: 'mail_server_no_ports',
      title: 'No ports were tested',
      detail: `No valid ports were selected for ${host}. Next step: provide at least one valid mail service port.`,
    });
  }
  return findings;
}

type ServerTestDependencies = {
  resolveAddresses: typeof resolveProbeAddresses;
  resolveMx: typeof dns.resolveMx;
  probe: typeof probePort;
  allowPrivateNetworkDiagnostics: boolean;
};

export async function runServerTest(
  host: string,
  settings: ToolSettings,
  overrides: Partial<ServerTestDependencies> = {}
): Promise<CheckResult> {
  const dependencies: ServerTestDependencies = {
    resolveAddresses: resolveProbeAddresses,
    resolveMx: dns.resolveMx,
    probe: probePort,
    allowPrivateNetworkDiagnostics: runtimeConfig.allowPrivateNetworkDiagnostics,
    ...overrides,
  };
  const target = parseHost(host);
  if (!target) {
    throw new ValidationError('A valid hostname, domain, or IP address is required');
  }

  let addresses: string[];
  try {
    addresses = await dependencies.resolveAddresses(target, settings.timeoutMs);
  } catch (error) {
    const detail = safeErrorDetail(error);
    return {
      toolKind: 'mail-server-test',
      targetType: net.isIP(target) ? 'ip' : 'host',
      targetValue: target,
      selector: null,
      status: 'error',
      summary: `DNS resolution failed for ${target}; no connection checks were performed.`,
      checkedAt: new Date().toISOString(),
      records: [
        {
          key: 'dns-resolution',
          label: 'DNS resolution',
          value: `Phase: DNS resolution\nHost: ${target}\nResult: failed${detail ? `\nTechnical detail: ${detail}` : ''}`,
          ok: false,
          explanation:
            'Verify the hostname, its A/AAAA records, and resolver availability before retrying.',
        },
      ],
      findings: [
        {
          severity: 'high',
          code: 'mail_server_dns_resolution',
          title: 'DNS resolution failed',
          detail: `${target} could not be resolved, so no ports were contacted. Next step: verify the hostname and its A/AAAA records.${detail ? ` Technical detail: ${detail}` : ''}`,
        },
      ],
      meta: { probeHost: target, phase: 'dns', checksPerformed: ['DNS resolution'] },
    };
  }
  const publicAddresses = publicProbeAddresses(addresses);
  if (
    !dependencies.allowPrivateNetworkDiagnostics &&
    (addresses.length === 0 || publicAddresses.length !== addresses.length)
  ) {
    return {
      toolKind: 'mail-server-test',
      targetType: net.isIP(target) ? 'ip' : 'host',
      targetValue: target,
      selector: null,
      status: 'error',
      summary:
        'Server probing was blocked because the target resolves to a private or local address.',
      checkedAt: new Date().toISOString(),
      records: [
        {
          key: 'addresses',
          label: 'Resolved addresses',
          value: `Phase: DNS safety validation\nHost: ${target}\nAddresses: ${addresses.join(', ') || 'none'}\nResult: blocked`,
          ok: false,
          explanation:
            'Correct public DNS, or enable private probes only in a trusted local lab deployment.',
        },
      ],
      findings: [
        {
          severity: 'high',
          code: 'private_probe_blocked',
          title: 'Private network probe blocked',
          detail:
            'Set ROBIN_TOOLS_ALLOW_PRIVATE_PROBES=true only in trusted local lab deployments.',
        },
      ],
      meta: {
        probeHost: target,
        addresses,
        phase: 'dns',
        checksPerformed: ['DNS resolution', 'address safety validation'],
      },
    };
  }

  let mxHosts: string[] = [];
  if (!net.isIP(target)) {
    try {
      mxHosts = (await dependencies.resolveMx(target))
        .sort(
          (left, right) =>
            left.priority - right.priority || left.exchange.localeCompare(right.exchange)
        )
        .map((item) => item.exchange.toLowerCase());
    } catch (error) {
      const code = errorCode(error);
      if (code !== 'ENODATA' && code !== 'ENOTFOUND') {
        const detail = safeErrorDetail(error);
        return {
          toolKind: 'mail-server-test',
          targetType: 'host',
          targetValue: target,
          selector: null,
          status: 'error',
          summary: `MX resolution failed for ${target}; no connection checks were performed.`,
          checkedAt: new Date().toISOString(),
          records: [
            {
              key: 'mx-resolution',
              label: 'MX resolution',
              value: `Phase: DNS resolution\nHost: ${target}\nResult: failed${detail ? `\nTechnical detail: ${detail}` : ''}`,
              ok: false,
              explanation: 'Check authoritative DNS and resolver availability, then retry.',
            },
          ],
          findings: [
            {
              severity: 'high',
              code: 'mail_server_mx_resolution',
              title: 'MX resolution failed',
              detail: `${target} resolved, but its MX lookup failed. No mail host was probed. Next step: check authoritative DNS and retry.${detail ? ` Technical detail: ${detail}` : ''}`,
            },
          ],
          meta: {
            probeHost: target,
            addresses,
            phase: 'dns',
            checksPerformed: ['DNS resolution', 'MX resolution'],
          },
        };
      }
    }
  }
  const probeHost = mxHosts[0] ?? target;
  let probeAddresses = addresses;
  if (probeHost !== target) {
    try {
      probeAddresses = await dependencies.resolveAddresses(probeHost, settings.timeoutMs);
    } catch (error) {
      const detail = safeErrorDetail(error);
      return {
        toolKind: 'mail-server-test',
        targetType: 'host',
        targetValue: target,
        selector: null,
        status: 'error',
        summary: `DNS resolution failed for MX host ${probeHost}; no connection checks were performed.`,
        checkedAt: new Date().toISOString(),
        records: [
          {
            key: 'mx-host-resolution',
            label: 'MX host resolution',
            value: `Phase: DNS resolution\nHost: ${probeHost}\nResult: failed${detail ? `\nTechnical detail: ${detail}` : ''}`,
            ok: false,
            explanation: 'Publish a valid A or AAAA record for the MX host, then retry.',
          },
        ],
        findings: [
          {
            severity: 'high',
            code: 'mail_server_mx_host_resolution',
            title: 'MX host DNS resolution failed',
            detail: `${probeHost} could not be resolved, so no ports were contacted. Next step: publish or repair its A/AAAA records.${detail ? ` Technical detail: ${detail}` : ''}`,
          },
        ],
        meta: {
          probeHost,
          addresses,
          mxHosts,
          phase: 'dns',
          checksPerformed: ['DNS resolution', 'MX resolution', 'MX host resolution'],
        },
      };
    }
  }
  const publicProbeAddressesForHost = publicProbeAddresses(probeAddresses);
  if (
    !dependencies.allowPrivateNetworkDiagnostics &&
    (probeAddresses.length === 0 || publicProbeAddressesForHost.length !== probeAddresses.length)
  ) {
    return {
      toolKind: 'mail-server-test',
      targetType: 'host',
      targetValue: target,
      selector: null,
      status: 'error',
      summary: `Server probing was blocked for MX host ${probeHost}; no connection checks were performed.`,
      checkedAt: new Date().toISOString(),
      records: [
        {
          key: 'mx-host-addresses',
          label: 'MX host addresses',
          value: probeAddresses.join('\n') || null,
          ok: false,
          explanation:
            'The MX host must resolve exclusively to public unicast addresses before network probing is allowed.',
        },
      ],
      findings: [
        {
          severity: 'high',
          code: 'mail_server_private_mx_probe_blocked',
          title: 'Private network probe blocked',
          detail: `${probeHost} resolves to a private, local, or unavailable address. No ports were contacted. Next step: correct public DNS, or enable private probes only in a trusted lab environment.`,
        },
      ],
      meta: {
        probeHost,
        addresses,
        mxHosts,
        probeAddresses,
        phase: 'dns',
        checksPerformed: ['DNS resolution', 'MX resolution', 'MX host resolution'],
      },
    };
  }
  const probeAddress = publicProbeAddressesForHost[0] ?? probeAddresses[0];
  const results = await mapLimited(
    settings.serverPorts,
    Math.min(settings.concurrency, 6),
    (port) => dependencies.probe(probeHost, probeAddress, port, settings.timeoutMs)
  );
  const findings = [
    ...(mxHosts.length === 0 && !net.isIP(target)
      ? [
          {
            severity: 'medium' as Severity,
            code: 'mx_missing',
            title: 'No MX records found',
            detail: `${target} has no MX records; probing ${probeHost} directly.`,
          },
        ]
      : []),
    ...portFindings(probeHost, results),
  ];

  return {
    toolKind: 'mail-server-test',
    targetType: net.isIP(target) ? 'ip' : 'host',
    targetValue: target,
    selector: null,
    status: statusFromFindings(findings),
    summary: `${probeHost} tested on ${results.length} port${results.length === 1 ? '' : 's'}; ${results.filter((result) => result.open).length} open.`,
    checkedAt: new Date().toISOString(),
    records: [
      {
        key: 'mx',
        label: 'MX routing',
        value: mxHosts.length ? mxHosts.join('\n') : null,
        ok: net.isIP(target) ? null : mxHosts.length > 0,
        explanation: mxHosts.length
          ? `Probing the first MX host: ${probeHost}.`
          : `No MX host was available; probing ${probeHost}.`,
      },
      ...results.map((result) => ({
        key: `port-${result.port}`,
        label: `${result.protocol.toUpperCase()} ${result.port}`,
        value: [
          result.open ? 'open' : 'closed',
          `Phase: ${result.phase}`,
          `Host: ${probeHost}`,
          `Port: ${result.port}`,
          result.checksPerformed.length
            ? `Checks performed: ${result.checksPerformed.join(', ')}`
            : null,
          result.banner ? `Banner: ${result.banner}` : null,
          result.ehlo ? `EHLO: ${result.ehlo}` : null,
          result.startTls !== null ? `STARTTLS: ${result.startTls ? 'yes' : 'no'}` : null,
          result.tls ? 'TLS: yes' : null,
          result.tlsVerified !== null ? `TLS verified: ${result.tlsVerified ? 'yes' : 'no'}` : null,
          result.certValidTo ? `Certificate valid to: ${result.certValidTo}` : null,
          result.certSubject ? `Certificate subject: ${result.certSubject}` : null,
          result.reason ? `Reason: ${result.reason}` : null,
          result.nextStep ? `Next step: ${result.nextStep}` : null,
          result.technicalDetail ? `Technical detail: ${result.technicalDetail}` : null,
        ]
          .filter(Boolean)
          .join('\n'),
        ok:
          result.tlsVerified === false
            ? false
            : result.port === 25
              ? result.open
              : result.open
                ? true
                : null,
        explanation:
          result.tlsVerified === false
            ? `${probeHost}:${result.port} accepted a connection but TLS certificate or hostname verification failed.`
            : result.open
              ? `${probeHost}:${result.port} accepted a connection.`
              : `${probeHost}:${result.port} did not accept a connection.`,
      })),
    ],
    findings,
    meta: { probeHost, probeAddress, addresses, mxHosts, ports: results },
  };
}

async function resolveDkimRecord(domain: string, selector: string): Promise<string | null> {
  try {
    const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
    return records.length > 0 ? records[0].join('') : null;
  } catch {
    return null;
  }
}

async function runDnsRecordCheck(
  toolKind: 'a' | 'aaaa' | 'cname' | 'ns' | 'txt' | 'ptr' | 'caa' | 'soa' | 'dnssec' | 'srv',
  targetValue: string
): Promise<CheckResult> {
  const lookup: { label: string; resolve: () => Promise<string[]> } = {
    a: {
      label: 'A records',
      resolve: () => dns.resolve4(targetValue),
    },
    aaaa: {
      label: 'AAAA records',
      resolve: () => dns.resolve6(targetValue),
    },
    cname: {
      label: 'CNAME records',
      resolve: () => dns.resolveCname(targetValue),
    },
    ns: {
      label: 'NS records',
      resolve: () => dns.resolveNs(targetValue),
    },
    txt: {
      label: 'TXT records',
      resolve: async () => (await dns.resolveTxt(targetValue)).map((parts) => parts.join('')),
    },
    ptr: {
      label: 'PTR records',
      resolve: () => dns.reverse(targetValue),
    },
    caa: {
      label: 'CAA records',
      resolve: async () =>
        (await dns.resolveCaa(targetValue)).map((record) =>
          [
            record.issue ? `issue ${record.issue}` : null,
            record.issuewild ? `issuewild ${record.issuewild}` : null,
            record.iodef ? `iodef ${record.iodef}` : null,
            record.contactemail ? `contactemail ${record.contactemail}` : null,
            record.contactphone ? `contactphone ${record.contactphone}` : null,
          ]
            .filter(Boolean)
            .join('; ')
        ),
    },
    soa: {
      label: 'SOA record',
      resolve: async () => {
        const record = await dns.resolveSoa(targetValue);
        return [
          `Primary nameserver: ${record.nsname}`,
          `Responsible mailbox: ${record.hostmaster}`,
          `Serial: ${record.serial}`,
          `Refresh: ${record.refresh}`,
          `Retry: ${record.retry}`,
          `Expire: ${record.expire}`,
          `Minimum TTL: ${record.minttl}`,
        ];
      },
    },
    dnssec: {
      label: 'DNSSEC delegation and keys',
      resolve: async () => {
        const { ds, dnskey } = await resolveDnssecRecordCounts(targetValue);
        return [`DS delegation records: ${ds}`, `DNSKEY records: ${dnskey}`];
      },
    },
    srv: {
      label: 'Mail service SRV records',
      resolve: async () => {
        const names = [
          '_submission._tcp',
          '_submissions._tcp',
          '_imap._tcp',
          '_imaps._tcp',
          '_pop3._tcp',
          '_pop3s._tcp',
          '_autodiscover._tcp',
        ];
        const records = await Promise.all(
          names.map(async (name) => {
            try {
              const values = await dns.resolveSrv(`${name}.${targetValue}`);
              return values.map(
                (value) => `${name}: ${value.priority} ${value.weight} ${value.port} ${value.name}`
              );
            } catch (error) {
              if (isDnsMiss(error)) return [];
              throw error;
            }
          })
        );
        return records.flat();
      },
    },
  }[toolKind];
  let records: string[];
  try {
    records = await lookup.resolve();
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== 'ENOTFOUND' && code !== 'ENODATA') {
      throw error;
    }
    records = [];
  }
  const found =
    toolKind === 'dnssec' ? records.some((record) => !record.endsWith(': 0')) : records.length > 0;
  const recordType = toolKind.toUpperCase();

  return {
    toolKind,
    targetType: toolKind === 'ptr' ? 'ip' : 'domain',
    targetValue,
    selector: null,
    status: found ? 'pass' : 'fail',
    summary: found
      ? `${records.length} ${recordType} record${records.length === 1 ? '' : 's'} found.`
      : `No ${recordType} records were found.`,
    checkedAt: new Date().toISOString(),
    records: [
      {
        key: toolKind,
        label: lookup.label,
        value: found ? records.join('\n') : null,
        ok: found,
        explanation: found
          ? `${lookup.label} resolved for ${targetValue}.`
          : `No ${lookup.label} resolved for ${targetValue}.`,
      },
    ],
    findings: found
      ? []
      : [
          {
            severity: 'medium',
            code: `${toolKind}_missing`,
            title: `${recordType} record missing`,
            detail: `${targetValue} does not currently resolve any ${recordType} records.`,
          },
        ],
  };
}

async function runToolCheck(input: {
  toolKind: ToolKind;
  targetType: TargetType;
  targetValue: string;
  selector?: string | null;
  focusIp?: string | null;
}): Promise<CheckResult> {
  if (input.targetType === 'domain' && !parseDomain(input.targetValue)) {
    throw new ValidationError('A valid domain is required');
  }
  if (input.targetType === 'ip' && net.isIP(input.targetValue) === 0) {
    throw new ValidationError('A valid IP address is required');
  }

  if (
    input.toolKind === 'a' ||
    input.toolKind === 'aaaa' ||
    input.toolKind === 'cname' ||
    input.toolKind === 'ns' ||
    input.toolKind === 'txt' ||
    input.toolKind === 'ptr' ||
    input.toolKind === 'caa' ||
    input.toolKind === 'soa' ||
    input.toolKind === 'dnssec' ||
    input.toolKind === 'srv'
  ) {
    const expectedTargetType = input.toolKind === 'ptr' ? 'ip' : 'domain';
    if (input.targetType !== expectedTargetType) {
      throw new ValidationError(
        `${input.toolKind.toUpperCase()} checks require a ${expectedTargetType === 'ip' ? 'valid IP address' : 'valid domain'}`
      );
    }
    return runDnsRecordCheck(input.toolKind, input.targetValue);
  }

  if (input.toolKind === 'rbl') {
    const settings = await getToolSettings();
    return runBlocklistCheck({ kind: 'rbl', targets: [input.targetValue], settings });
  }

  if (input.toolKind === 'dbl') {
    const settings = await getToolSettings();
    return runBlocklistCheck({ kind: 'dbl', targets: [input.targetValue], settings });
  }

  if (input.toolKind === 'mail-server-test') {
    const settings = await getToolSettings();
    return runServerTest(input.targetValue, settings);
  }

  if (input.toolKind === 'message-analysis') {
    const settings = await getToolSettings();
    const inputKind =
      input.targetType === 'domain' ||
      input.targetType === 'email' ||
      input.targetType === 'headers' ||
      input.targetType === 'raw'
        ? input.targetType
        : 'raw';
    return runEmailAnalysis(inputKind, input.targetValue, settings);
  }

  if (input.toolKind === 'fcrdns') {
    const [ptrHost, fcrdnsHost] = await Promise.all([
      resolvePtrHost(input.targetValue).catch(() => null),
      resolveFcrdns(input.targetValue).catch(() => null),
    ]);
    const findings: DomainIssue[] = [];
    if (!ptrHost) {
      findings.push({
        severity: 'medium',
        code: 'ptr_missing',
        title: 'PTR record missing',
        detail: `${input.targetValue} does not currently publish a PTR record.`,
      });
    }
    if (ptrHost && !fcrdnsHost) {
      findings.push({
        severity: 'medium',
        code: 'fcrdns_failed',
        title: 'FCrDNS failed',
        detail: 'The PTR hostname does not resolve back to the original IP address.',
      });
    }

    return {
      toolKind: 'fcrdns',
      targetType: 'ip',
      targetValue: input.targetValue,
      selector: null,
      status: ptrHost && fcrdnsHost ? 'pass' : ptrHost || fcrdnsHost ? 'warning' : 'fail',
      summary:
        ptrHost && fcrdnsHost
          ? 'PTR and forward-confirmed reverse DNS both passed.'
          : ptrHost
            ? 'PTR exists, but forward-confirmed reverse DNS failed.'
            : 'PTR record is missing.',
      checkedAt: new Date().toISOString(),
      records: [
        {
          key: 'ptr',
          label: 'PTR host',
          value: ptrHost,
          ok: Boolean(ptrHost),
          explanation: ptrHost
            ? 'Reverse DNS is published for this IP.'
            : 'No PTR host resolved for this IP.',
        },
        {
          key: 'fcrdns',
          label: 'FCrDNS host',
          value: fcrdnsHost,
          ok: Boolean(fcrdnsHost),
          explanation: fcrdnsHost
            ? 'The PTR hostname resolves back to this IP.'
            : 'The PTR hostname did not resolve back to this IP.',
        },
      ],
      findings,
    };
  }

  const domain = input.targetValue;
  const dnsSnapshot = await getDomainDnsRecords(domain);
  const checkedAt = dnsSnapshot.checkedAt.toISOString();

  switch (input.toolKind) {
    case 'mx': {
      const hasRealMx = dnsSnapshot.mxHosts.length > 0;
      const status: VerificationStatus = hasRealMx
        ? 'pass'
        : dnsSnapshot.hasNullMx
          ? 'warning'
          : 'fail';
      const summary = hasRealMx
        ? 'MX records are present.'
        : dnsSnapshot.hasNullMx
          ? 'This domain publishes a null MX (RFC 7505) and explicitly declines to receive email.'
          : 'No MX records were found.';
      return {
        toolKind: 'mx',
        targetType: 'domain',
        targetValue: domain,
        selector: null,
        status,
        summary,
        checkedAt,
        records: [
          {
            key: 'mx',
            label: 'MX hosts',
            value: hasRealMx
              ? dnsSnapshot.mxHosts.join('\n')
              : dnsSnapshot.hasNullMx
                ? '. (null MX — RFC 7505)'
                : null,
            ok: hasRealMx ? true : dnsSnapshot.hasNullMx ? null : false,
            explanation: hasRealMx
              ? explainMxHosts(dnsSnapshot.mxHosts)
              : dnsSnapshot.hasNullMx
                ? 'The domain publishes a null MX record (exchange "."), explicitly declaring that it accepts no email.'
                : explainMxHosts(dnsSnapshot.mxHosts),
          },
        ],
        findings:
          hasRealMx || dnsSnapshot.hasNullMx
            ? []
            : [
                {
                  severity: 'high',
                  code: 'mx_missing',
                  title: 'MX record missing',
                  detail: `${domain} has no MX records.`,
                },
              ],
      };
    }
    case 'spf': {
      const focusIpCovered = input.focusIp
        ? ipMatchesSpf(input.focusIp, dnsSnapshot.spfAuthorized)
        : null;
      const findings: DomainIssue[] = [];
      if (!dnsSnapshot.spfRecord) {
        findings.push({
          severity: 'high',
          code: 'spf_missing',
          title: 'SPF record missing',
          detail: 'Publish an SPF record for the domain.',
        });
      } else if (dnsSnapshot.spfPermerror) {
        findings.push({
          severity: 'critical',
          code: 'spf_permerror',
          title: 'SPF permerror',
          detail: 'The SPF record could not be expanded cleanly.',
        });
      } else if (input.focusIp && !focusIpCovered) {
        findings.push({
          severity: 'high',
          code: 'spf_missing_for_ip',
          title: 'Selected IP missing from SPF',
          detail: `${input.focusIp} is not currently covered by the live SPF record for ${domain}.`,
        });
      }

      const authorizedValue =
        [...(dnsSnapshot.spfAuthorized.ipv4 ?? []), ...(dnsSnapshot.spfAuthorized.ipv6 ?? [])].join(
          '\n'
        ) || null;
      return {
        toolKind: 'spf',
        targetType: 'domain',
        targetValue: domain,
        selector: null,
        status: !dnsSnapshot.spfRecord
          ? 'fail'
          : dnsSnapshot.spfPermerror || (input.focusIp ? !focusIpCovered : false)
            ? 'warning'
            : 'pass',
        summary: !dnsSnapshot.spfRecord
          ? 'No SPF record is currently published.'
          : input.focusIp
            ? focusIpCovered
              ? `SPF covers ${input.focusIp}.`
              : `SPF does not cover ${input.focusIp}.`
            : dnsSnapshot.spfPermerror
              ? 'SPF exists, but expansion failed.'
              : 'SPF is published and expands cleanly.',
        checkedAt,
        records: [
          {
            key: 'spf-record',
            label: 'SPF record',
            value: dnsSnapshot.spfRecord,
            ok: dnsSnapshot.spfRecord ? !dnsSnapshot.spfPermerror : false,
            explanation: explainSpfRecord(dnsSnapshot.spfRecord, dnsSnapshot.spfPermerror),
          },
          {
            key: 'spf-authorized',
            label: 'Authorized IP ranges',
            value: authorizedValue,
            ok: authorizedValue ? true : null,
            explanation: authorizedValue
              ? 'Expanded SPF include, ip4, and ip6 mechanisms currently authorize these ranges.'
              : 'No explicit authorized IP ranges could be expanded from the current SPF record.',
          },
          ...(input.focusIp
            ? [
                {
                  key: 'spf-focus-ip',
                  label: 'Selected IP coverage',
                  value: input.focusIp,
                  ok: focusIpCovered,
                  explanation: focusIpCovered
                    ? `${input.focusIp} is covered by the live SPF record.`
                    : `${input.focusIp} is not covered by the live SPF record.`,
                },
              ]
            : []),
        ],
        findings,
      };
    }
    case 'dmarc':
      return {
        toolKind: 'dmarc',
        targetType: 'domain',
        targetValue: domain,
        selector: null,
        status: dnsSnapshot.dmarcRecord ? 'pass' : 'fail',
        summary: dnsSnapshot.dmarcRecord ? 'DMARC is published.' : 'No DMARC record was found.',
        checkedAt,
        records: [
          {
            key: 'dmarc-record',
            label: 'DMARC record',
            value: dnsSnapshot.dmarcRecord,
            ok: Boolean(dnsSnapshot.dmarcRecord),
            explanation: dnsSnapshot.dmarcRecord
              ? (summarizeDmarcPolicy(dnsSnapshot.dmarcRecord) ?? 'DMARC is published.')
              : 'Publish a DMARC TXT record at _dmarc.',
          },
        ],
        findings: dnsSnapshot.dmarcRecord
          ? []
          : [
              {
                severity: 'medium',
                code: 'dmarc_missing',
                title: 'DMARC record missing',
                detail: 'Publish a DMARC policy and report destination.',
              },
            ],
      };
    case 'dkim': {
      const selector = input.selector ?? 'default';
      const record =
        dnsSnapshot.dkimRecords[selector] ?? (await resolveDkimRecord(domain, selector));
      return {
        toolKind: 'dkim',
        targetType: 'domain',
        targetValue: domain,
        selector,
        status: record ? 'pass' : 'fail',
        summary: record
          ? `DKIM selector ${selector} is published.`
          : `No DKIM record was found for selector ${selector}.`,
        checkedAt,
        records: [
          {
            key: 'dkim-record',
            label: `DKIM selector ${selector}`,
            value: record,
            ok: Boolean(record),
            explanation: explainDkimRecord(selector, record),
          },
        ],
        findings: record
          ? []
          : [
              {
                severity: 'medium',
                code: 'dkim_missing',
                title: 'DKIM selector missing',
                detail: `No DKIM TXT record was found for selector ${selector}.`,
              },
            ],
      };
    }
    case 'mta-sts':
      return {
        toolKind: 'mta-sts',
        targetType: 'domain',
        targetValue: domain,
        selector: null,
        status: dnsSnapshot.mtaStsDnsRecord || dnsSnapshot.mtaStsPolicyText ? 'pass' : 'fail',
        summary:
          dnsSnapshot.mtaStsDnsRecord || dnsSnapshot.mtaStsPolicyText
            ? 'MTA-STS is configured.'
            : 'No MTA-STS record or policy was found.',
        checkedAt,
        records: [
          {
            key: 'mta-sts-dns',
            label: 'MTA-STS DNS record',
            value: dnsSnapshot.mtaStsDnsRecord,
            ok: Boolean(dnsSnapshot.mtaStsDnsRecord),
            explanation: explainOptionalRecord(
              'MTA-STS TXT',
              dnsSnapshot.mtaStsDnsRecord,
              'The MTA-STS TXT record is published.'
            ),
          },
          {
            key: 'mta-sts-policy',
            label: 'MTA-STS policy',
            value: dnsSnapshot.mtaStsPolicyText,
            ok: Boolean(dnsSnapshot.mtaStsPolicyText),
            explanation: explainOptionalRecord(
              'MTA-STS policy',
              dnsSnapshot.mtaStsPolicyText,
              'The hosted MTA-STS policy was retrieved successfully.'
            ),
          },
        ],
        findings:
          dnsSnapshot.mtaStsDnsRecord || dnsSnapshot.mtaStsPolicyText
            ? []
            : [
                {
                  severity: 'medium',
                  code: 'mta_sts_missing',
                  title: 'MTA-STS missing',
                  detail: 'No MTA-STS TXT record or hosted policy was found.',
                },
              ],
      };
    case 'tlsrpt':
      return {
        toolKind: 'tlsrpt',
        targetType: 'domain',
        targetValue: domain,
        selector: null,
        status: dnsSnapshot.tlsRptRecord ? 'pass' : 'fail',
        summary: dnsSnapshot.tlsRptRecord
          ? 'TLS-RPT is published.'
          : 'No TLS-RPT record was found.',
        checkedAt,
        records: [
          {
            key: 'tlsrpt-record',
            label: 'TLS-RPT record',
            value: dnsSnapshot.tlsRptRecord,
            ok: Boolean(dnsSnapshot.tlsRptRecord),
            explanation: explainOptionalRecord(
              'TLS-RPT',
              dnsSnapshot.tlsRptRecord,
              'The TLS-RPT TXT record is published.'
            ),
          },
        ],
        findings: dnsSnapshot.tlsRptRecord
          ? []
          : [
              {
                severity: 'medium',
                code: 'tlsrpt_missing',
                title: 'TLS-RPT missing',
                detail: 'No TLS-RPT TXT record was found.',
              },
            ],
      };
    case 'dane': {
      const hosts = Object.keys(dnsSnapshot.daneRecords);
      return {
        toolKind: 'dane',
        targetType: 'domain',
        targetValue: domain,
        selector: null,
        status: hosts.length > 0 ? 'pass' : 'fail',
        summary:
          hosts.length > 0
            ? 'TLSA records were found for MX hosts.'
            : 'No TLSA records were found for current MX hosts.',
        checkedAt,
        records:
          hosts.length > 0
            ? hosts.map((host) => ({
                key: `dane-${host}`,
                label: `TLSA for ${host}`,
                value: dnsSnapshot.daneRecords[host].join('\n') || null,
                ok: dnsSnapshot.daneRecords[host].length > 0,
                explanation:
                  dnsSnapshot.daneRecords[host].length > 0
                    ? `TLSA records were found for ${host}.`
                    : `No TLSA records were found for ${host}.`,
              }))
            : [
                {
                  key: 'dane',
                  label: 'TLSA records',
                  value: null,
                  ok: false,
                  explanation: 'No TLSA records were found for the current MX hosts.',
                },
              ],
        findings:
          hosts.length > 0
            ? []
            : [
                {
                  severity: 'low',
                  code: 'dane_missing',
                  title: 'DANE missing',
                  detail: 'No TLSA records were found for the current MX hosts.',
                },
              ],
      };
    }
    case 'bimi':
      return {
        toolKind: 'bimi',
        targetType: 'domain',
        targetValue: domain,
        selector: null,
        status: dnsSnapshot.bimiRecord ? 'pass' : 'fail',
        summary: dnsSnapshot.bimiRecord
          ? 'BIMI is published.'
          : 'No default BIMI record was found.',
        checkedAt,
        records: [
          {
            key: 'bimi-record',
            label: 'BIMI record',
            value: dnsSnapshot.bimiRecord,
            ok: Boolean(dnsSnapshot.bimiRecord),
            explanation: explainOptionalRecord(
              'BIMI',
              dnsSnapshot.bimiRecord,
              'The default BIMI TXT record is published.'
            ),
          },
        ],
        findings: dnsSnapshot.bimiRecord
          ? []
          : [
              {
                severity: 'low',
                code: 'bimi_missing',
                title: 'BIMI missing',
                detail: 'No default BIMI record was found.',
              },
            ],
      };
  }

  throw new Error(`Unsupported tool kind: ${String(input.toolKind)}`);
}

function buildDomainIssues(
  domain: string,
  dnsSnapshot: Awaited<ReturnType<typeof getDomainDnsRecords>>,
  approvedSenders: Array<{ inCurrentSpf?: boolean; tlsFailureCount: number }>,
  dkimChecks: Array<{ selector: string; record: string | null }>
): DomainIssue[] {
  const issues: DomainIssue[] = [];

  if (dnsSnapshot.mxHosts.length === 0 && !dnsSnapshot.hasNullMx) {
    issues.push({
      severity: 'high',
      code: 'mx_missing',
      title: 'MX record missing',
      detail: `${domain} has no MX records.`,
    });
  }
  if (!dnsSnapshot.spfRecord) {
    issues.push({
      severity: 'high',
      code: 'spf_missing',
      title: 'SPF record missing',
      detail: 'Publish an SPF record for the domain.',
    });
  } else if (dnsSnapshot.spfPermerror) {
    issues.push({
      severity: 'critical',
      code: 'spf_permerror',
      title: 'SPF permerror',
      detail: 'The SPF record could not be expanded cleanly.',
    });
  }
  if (!dnsSnapshot.dmarcRecord) {
    issues.push({
      severity: 'medium',
      code: 'dmarc_missing',
      title: 'DMARC record missing',
      detail: 'Publish a DMARC policy and report destination.',
    });
  }
  if (dkimChecks.length === 0 || dkimChecks.every((entry) => !entry.record)) {
    issues.push({
      severity: 'medium',
      code: 'dkim_missing',
      title: 'No DKIM selectors resolved',
      detail: 'No DKIM selector records were found for observed or requested selectors.',
    });
  }

  const missingSpfIps = approvedSenders.filter((sender) => sender.inCurrentSpf === false);
  if (missingSpfIps.length > 0) {
    issues.push({
      severity: 'high',
      code: 'approved_ip_missing_from_spf',
      title: 'Approved senders missing from SPF',
      detail: `${missingSpfIps.length} approved sending IP${missingSpfIps.length === 1 ? '' : 's'} are not covered by the live SPF record.`,
    });
  }

  const tlsFailures = approvedSenders.filter((sender) => sender.tlsFailureCount > 0);
  if (tlsFailures.length > 0) {
    issues.push({
      severity: 'medium',
      code: 'tls_failures_present',
      title: 'TLS failures observed',
      detail: `${tlsFailures.length} approved sending IP${tlsFailures.length === 1 ? '' : 's'} show TLS failures in recent reporting.`,
    });
  }

  return issues.sort(
    (left, right) => severityWeight(right.severity) - severityWeight(left.severity)
  );
}

async function runBulkDomainChecks(
  domains: string[],
  selector: string | null,
  optionalChecks: OptionalCheckConfig
): Promise<DomainBulkResult[]> {
  return Promise.all(
    domains.map(async (domain) => {
      const dnsSnapshot = await getDomainDnsRecords(domain);
      const dkimRecord = selector ? await resolveDkimRecord(domain, selector) : null;
      const issues = buildDomainIssues(
        domain,
        dnsSnapshot,
        [],
        selector ? [{ selector, record: dkimRecord }] : []
      );

      return {
        domain,
        checkedAt: dnsSnapshot.checkedAt.toISOString(),
        checks: {
          mx: dnsSnapshot.mxHosts.length > 0,
          spf: Boolean(dnsSnapshot.spfRecord) && !dnsSnapshot.spfPermerror,
          dmarc: Boolean(dnsSnapshot.dmarcRecord),
          dkim: selector ? Boolean(dkimRecord) : null,
          ...(optionalChecks.mtaSts
            ? { mtaSts: Boolean(dnsSnapshot.mtaStsDnsRecord || dnsSnapshot.mtaStsPolicyText) }
            : {}),
          ...(optionalChecks.tlsRpt ? { tlsRpt: Boolean(dnsSnapshot.tlsRptRecord) } : {}),
          ...(optionalChecks.dane ? { dane: Object.keys(dnsSnapshot.daneRecords).length > 0 } : {}),
          ...(optionalChecks.bimi ? { bimi: Boolean(dnsSnapshot.bimiRecord) } : {}),
        },
        records: {
          mxHosts: dnsSnapshot.mxHosts,
          spfRecord: dnsSnapshot.spfRecord,
          dmarcRecord: dnsSnapshot.dmarcRecord,
          dkimRecord,
          ...(optionalChecks.mtaSts
            ? { mtaStsRecord: dnsSnapshot.mtaStsDnsRecord ?? dnsSnapshot.mtaStsPolicyText }
            : {}),
          ...(optionalChecks.tlsRpt ? { tlsRptRecord: dnsSnapshot.tlsRptRecord } : {}),
          ...(optionalChecks.bimi ? { bimiRecord: dnsSnapshot.bimiRecord } : {}),
          ...(optionalChecks.dane ? { daneHosts: Object.keys(dnsSnapshot.daneRecords) } : {}),
        },
        issues,
      };
    })
  );
}

async function runBulkIpChecks(ips: string[]): Promise<IpBulkResult[]> {
  return Promise.all(
    ips.map(async (sourceIp) => {
      const [ptrHost, fcrdnsHost] = await Promise.all([
        resolvePtrHost(sourceIp).catch(() => null),
        resolveFcrdns(sourceIp).catch(() => null),
      ]);

      const issues: DomainIssue[] = [];
      if (!ptrHost) {
        issues.push({
          severity: 'medium',
          code: 'ptr_missing',
          title: 'PTR record missing',
          detail: `${sourceIp} does not currently have a PTR record.`,
        });
      }
      if (ptrHost && !fcrdnsHost) {
        issues.push({
          severity: 'medium',
          code: 'fcrdns_failed',
          title: 'FCrDNS failed',
          detail: 'The PTR hostname does not resolve back to the source IP.',
        });
      }

      return {
        sourceIp,
        ptrHost,
        fcrdnsHost,
        fcrdnsAligned: Boolean(fcrdnsHost),
        domains: [],
        checkedAt: new Date().toISOString(),
        issues,
      };
    })
  );
}

router.get('/context', async (_req: Request, res: Response) => {
  try {
    res.json({
      success: true,
      data: {
        optionalChecks: {
          mtaSts: true,
          tlsRpt: true,
          dane: true,
          bimi: true,
        },
      },
    });
  } catch (error) {
    logger.error('Failed to load Robin Tools context', { detail: (error as Error).message });
    res.status(500).json({
      success: false,
      error: 'Failed to load Robin Tools context',
    });
  }
});

router.get('/settings', async (_req: Request, res: Response) => {
  try {
    const settings = await getToolSettings();
    return res.json({
      success: true,
      data: {
        settings,
        defaults: DEFAULT_TOOL_SETTINGS,
        privateNetworkDiagnosticsEnabled: runtimeConfig.allowPrivateNetworkDiagnostics,
      },
    });
  } catch (error) {
    logger.error('Failed to load Robin Tools settings', { detail: (error as Error).message });
    return res.status(500).json({
      success: false,
      error: 'Failed to load Robin Tools settings',
    });
  }
});

router.put('/settings', requireAdmin, async (req: Request, res: Response) => {
  try {
    const settings = await saveToolSettings(req.body?.settings ?? req.body);
    return res.json({
      success: true,
      data: {
        settings,
      },
    });
  } catch (error) {
    logger.error('Failed to save Robin Tools settings', { detail: (error as Error).message });
    return res.status(500).json({
      success: false,
      error: 'Failed to save Robin Tools settings',
    });
  }
});

router.post('/reputation/rbl/run', requireEditor, async (req: Request, res: Response) => {
  const rawTargets = Array.isArray(req.body?.targets) ? req.body.targets : [req.body?.target];
  const targets = parseIpArray(rawTargets);
  if (targets.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'At least one valid IP address is required',
    });
  }

  try {
    const settings = await getToolSettings();
    const result = await runBlocklistCheck({ kind: 'rbl', targets, settings });
    const historyEntry = await createHistoryEntry({
      adminId: req.moduleAdmin!.adminId,
      toolKind: 'rbl',
      targetType: 'ip',
      targetValue: targets.length === 1 ? targets[0] : `${targets.length} targets`,
      result,
    });
    return res.json({
      success: true,
      data: { result, historyEntry },
    });
  } catch (error) {
    return respondToCheckError(res, error, 'Failed to run RBL check');
  }
});

router.post('/reputation/dbl/run', requireEditor, async (req: Request, res: Response) => {
  const rawTargets = Array.isArray(req.body?.targets) ? req.body.targets : [req.body?.target];
  const extracted = typeof req.body?.text === 'string' ? extractDomains(req.body.text) : [];
  const targets = parseDomainArray([...rawTargets, ...extracted]);
  if (targets.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'At least one valid domain is required',
    });
  }

  try {
    const settings = await getToolSettings();
    const result = await runBlocklistCheck({ kind: 'dbl', targets, settings });
    const historyEntry = await createHistoryEntry({
      adminId: req.moduleAdmin!.adminId,
      toolKind: 'dbl',
      targetType: 'domain',
      targetValue: targets.length === 1 ? targets[0] : `${targets.length} targets`,
      result,
    });
    return res.json({
      success: true,
      data: { result, historyEntry },
    });
  } catch (error) {
    return respondToCheckError(res, error, 'Failed to run DBL check');
  }
});

router.post(
  '/mail-tests/message-analysis/run',
  requireEditor,
  async (req: Request, res: Response) => {
    const inputKind = ['domain', 'email', 'headers', 'raw'].includes(req.body?.inputKind)
      ? (req.body.inputKind as ParsedMessageInput['inputKind'])
      : 'raw';
    const value = typeof req.body?.value === 'string' ? req.body.value : '';
    if (!value.trim()) {
      return res.status(400).json({
        success: false,
        error: 'Message input is required',
      });
    }

    try {
      const settings = await getToolSettings();
      const result = await runEmailAnalysis(inputKind, value, settings);
      const historyEntry = await createHistoryEntry({
        adminId: req.moduleAdmin!.adminId,
        toolKind: 'message-analysis',
        targetType: inputKind,
        targetValue: result.targetValue,
        selector: result.selector,
        result,
      });
      return res.json({
        success: true,
        data: { result, historyEntry },
      });
    } catch (error) {
      return respondToCheckError(res, error, 'Failed to analyze message');
    }
  }
);

router.post(
  '/mail-tests/mail-server-test/run',
  requireEditor,
  async (req: Request, res: Response) => {
    const target = typeof req.body?.target === 'string' ? req.body.target.trim() : '';
    if (!target) {
      return res.status(400).json({
        success: false,
        error: 'A server, domain, or IP target is required',
      });
    }

    try {
      const settings = await getToolSettings();
      const requestedPorts = Array.isArray(req.body?.ports)
        ? sanitizePortList(req.body.ports, settings.serverPorts)
        : settings.serverPorts;
      const result = await runServerTest(target, { ...settings, serverPorts: requestedPorts });
      const historyEntry = await createHistoryEntry({
        adminId: req.moduleAdmin!.adminId,
        toolKind: 'mail-server-test',
        targetType: result.targetType,
        targetValue: result.targetValue,
        result,
      });
      return res.json({
        success: true,
        data: { result, historyEntry },
      });
    } catch (error) {
      return respondToCheckError(res, error, 'Failed to run server test');
    }
  }
);

router.get('/checks/recent', async (req: Request, res: Response) => {
  const toolKind = parseToolKind(req.query.toolKind);

  if (!toolKind) {
    return res.status(400).json({
      success: false,
      error: 'toolKind is required',
    });
  }

  try {
    const items = await listHistoryEntries({
      adminId: req.moduleAdmin!.adminId,
      toolKind,
      limit: Math.min(parsePage(req.query.limit, HISTORY_LIMIT), 25),
    });

    return res.json({
      success: true,
      data: {
        items,
      },
    });
  } catch (error) {
    logger.error('Failed to load recent checks', { detail: (error as Error).message });
    return res.status(500).json({
      success: false,
      error: 'Failed to load recent checks',
    });
  }
});

router.get('/checks/history', async (req: Request, res: Response) => {
  const toolKind = parseToolKind(req.query.toolKind);
  const targetType = parseTargetType(req.query.targetType);
  const targetValue = typeof req.query.targetValue === 'string' ? req.query.targetValue.trim() : '';
  const selector = parseSelector(req.query.selector);

  if (!toolKind || !targetType || !targetValue) {
    return res.status(400).json({
      success: false,
      error: 'toolKind, targetType, and targetValue are required',
    });
  }

  try {
    const items = await listHistoryEntries({
      adminId: req.moduleAdmin!.adminId,
      toolKind,
      targetType,
      targetValue,
      selector: selector ?? null,
      limit: Math.min(parsePage(req.query.limit, HISTORY_LIMIT), 25),
    });

    return res.json({
      success: true,
      data: {
        items,
      },
    });
  } catch (error) {
    logger.error('Failed to load check history', { detail: (error as Error).message });
    return res.status(500).json({
      success: false,
      error: 'Failed to load check history',
    });
  }
});

router.delete('/checks/history/:id', requireEditor, async (req: Request, res: Response) => {
  const id = Number.parseInt(String(req.params.id), 10);

  if (!Number.isFinite(id) || id <= 0) {
    return res.status(400).json({
      success: false,
      error: 'Invalid history entry ID',
    });
  }

  try {
    const deleted = await deleteHistoryEntry(id, req.moduleAdmin!.adminId);
    if (!deleted) {
      return res.status(404).json({
        success: false,
        error: 'History entry not found',
      });
    }

    return res.json({
      success: true,
      data: { deleted: true },
    });
  } catch (error) {
    logger.error('Failed to delete history entry', { detail: (error as Error).message });
    return res.status(500).json({
      success: false,
      error: 'Failed to delete history entry',
    });
  }
});

router.delete('/checks/history', requireEditor, async (req: Request, res: Response) => {
  const toolKind = parseToolKind(req.query.toolKind);

  try {
    const count = await clearHistoryEntries({
      adminId: req.moduleAdmin!.adminId,
      toolKind: toolKind ?? undefined,
    });

    return res.json({
      success: true,
      data: { deleted: count },
    });
  } catch (error) {
    logger.error('Failed to clear history', { detail: (error as Error).message });
    return res.status(500).json({
      success: false,
      error: 'Failed to clear history',
    });
  }
});

router.post('/checks/run', requireEditor, async (req: Request, res: Response) => {
  const toolKind = parseToolKind(req.body?.toolKind);
  const targetType = parseTargetType(req.body?.targetType);
  const targetValue =
    typeof req.body?.targetValue === 'string' ? req.body.targetValue.trim().toLowerCase() : '';
  const selector = parseSelector(req.body?.selector);
  const focusIp =
    typeof req.body?.focusIp === 'string' && net.isIP(req.body.focusIp) > 0
      ? req.body.focusIp
      : null;

  if (!toolKind || !targetType || !targetValue) {
    return res.status(400).json({
      success: false,
      error: 'toolKind, targetType, and targetValue are required',
    });
  }

  try {
    const result = await runToolCheck({
      toolKind,
      targetType,
      targetValue,
      selector,
      focusIp,
    });
    const historyEntry = await createHistoryEntry({
      adminId: req.moduleAdmin!.adminId,
      subjectValue: focusIp,
      toolKind,
      targetType,
      targetValue: result.targetValue,
      selector,
      result,
    });

    return res.json({
      success: true,
      data: {
        result,
        historyEntry,
      },
    });
  } catch (error) {
    return respondToCheckError(res, error, 'Failed to run check');
  }
});

const MAX_BULK_TARGETS = 100;

router.post('/domains/bulk-check', requireEditor, async (req: Request, res: Response) => {
  const domains = parseDomainArray(req.body?.domains);
  const selector =
    typeof req.body?.selector === 'string'
      ? req.body.selector
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9._-]+/g, '')
      : null;

  if (domains.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'At least one valid domain is required',
    });
  }

  if (domains.length > MAX_BULK_TARGETS) {
    return res.status(400).json({
      success: false,
      error: `At most ${MAX_BULK_TARGETS} domains per request`,
    });
  }

  try {
    const requested =
      req.body?.optionalChecks && typeof req.body.optionalChecks === 'object'
        ? (req.body.optionalChecks as Record<string, unknown>)
        : {};
    const optionalChecks: OptionalCheckConfig = {
      mtaSts: parseBoolean(requested.mtaSts, true),
      tlsRpt: parseBoolean(requested.tlsRpt, true),
      dane: parseBoolean(requested.dane, true),
      bimi: parseBoolean(requested.bimi, true),
    };

    const results = await runBulkDomainChecks(domains, selector, optionalChecks);
    return res.json({
      success: true,
      data: {
        results,
      },
    });
  } catch (error) {
    logger.error('Failed to run bulk domain checks', { detail: (error as Error).message });
    return res.status(500).json({
      success: false,
      error: 'Failed to run bulk domain checks',
    });
  }
});

router.post('/ips/bulk-check', requireEditor, async (req: Request, res: Response) => {
  const ips = parseIpArray(req.body?.ips);
  if (ips.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'At least one valid IP address is required',
    });
  }

  if (ips.length > MAX_BULK_TARGETS) {
    return res.status(400).json({
      success: false,
      error: `At most ${MAX_BULK_TARGETS} IP addresses per request`,
    });
  }

  try {
    const results = await runBulkIpChecks(ips);
    return res.json({
      success: true,
      data: {
        results,
      },
    });
  } catch (error) {
    logger.error('Failed to run bulk IP checks', { detail: (error as Error).message });
    return res.status(500).json({
      success: false,
      error: 'Failed to run bulk IP checks',
    });
  }
});

// Catch-all for anything that didn't match a route above. This must stay
// registered LAST so Express only reaches it when no earlier route matched.
router.use((_req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    error: 'Robin Tools endpoint not found',
  });
});

export default router;
