// Shared types for the Robin Tools module: tool identifiers, check results,
// history entries, settings, and transform metadata. Split out of remote.tsx
// so the UI, storage, and tool-definition modules can share one source of
// truth without pulling in React or DOM-facing code.

export type AdminRole = 'viewer' | 'editor' | 'admin';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type TransformKey =
  | 'base64-encode'
  | 'base64-decode'
  | 'base64url-encode'
  | 'base64url-decode'
  | 'url-encode'
  | 'url-decode'
  | 'md5'
  | 'sha256'
  | 'saml-encode'
  | 'saml-decode'
  | 'pretty-json'
  | 'quoted-printable-encode'
  | 'quoted-printable-decode'
  | 'uu-encode'
  | 'uu-decode'
  | 'utf16-decode'
  | 'hex-decode'
  | 'jwt-decode'
  | 'unix-time';
export type ToolKey =
  | 'a'
  | 'aaaa'
  | 'cname'
  | 'ns'
  | 'txt'
  | 'ptr'
  | 'caa'
  | 'soa'
  | 'dnssec'
  | 'mx'
  | 'spf'
  | 'dmarc'
  | 'dkim'
  | 'mta-sts'
  | 'tlsrpt'
  | 'dane'
  | 'bimi'
  | 'fcrdns'
  | 'srv'
  | 'rbl'
  | 'dbl'
  | 'message-analysis'
  | 'mail-server-test'
  | 'reputation-providers'
  | TransformKey;
export type ToolPage = 'dns-lookup' | 'mail-posture' | 'reputation' | 'mail-tests' | 'transforms';
export type VerificationStatus = 'pass' | 'fail' | 'warning' | 'error';

export interface ContextResponse {
  optionalChecks: {
    mtaSts: boolean;
    tlsRpt: boolean;
    dane: boolean;
    bimi: boolean;
  };
}

export interface DomainIssue {
  severity: Severity;
  code: string;
  title: string;
  detail: string;
}

export interface CheckRecord {
  key: string;
  label: string;
  value: string | null;
  ok: boolean | null;
  explanation: string;
}

export interface CheckResult {
  toolKind: ToolKey;
  targetType: 'domain' | 'ip' | 'email' | 'headers' | 'raw' | 'host';
  targetValue: string;
  selector: string | null;
  status: VerificationStatus;
  summary: string;
  checkedAt: string;
  records: CheckRecord[];
  findings: DomainIssue[];
  meta?: Record<string, unknown>;
}

export interface CheckHistoryEntry {
  id: number;
  issueId: number | null;
  subjectValue: string | null;
  toolKind: ToolKey;
  targetType: 'domain' | 'ip';
  targetValue: string;
  selector: string | null;
  status: VerificationStatus;
  summary: string | null;
  result: CheckResult;
  createdAt: string;
}

export interface BulkDomainResult {
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
}

export interface BulkIpResult {
  sourceIp: string;
  ptrHost: string | null;
  fcrdnsHost: string | null;
  fcrdnsAligned: boolean;
  domains: string[];
  checkedAt: string;
  issues: DomainIssue[];
}

export interface BlocklistProvider {
  id: string;
  zone: string;
  label: string;
  enabled: boolean;
  notes?: string | null;
}

export interface ToolSettings {
  rblProviders: BlocklistProvider[];
  dblProviders: BlocklistProvider[];
  resolvers: string[];
  confirmResolvers: string[];
  timeoutMs: number;
  concurrency: number;
  serverPorts: number[];
}

export interface HostedModuleProps {
  basePath?: string;
  routePath?: string;
  navigate?: (path: string) => void;
  styleRoot?: ShadowRoot | Document;
  currentAdmin?: {
    role: AdminRole;
  };
  /** API path prefix. Hosted mode proxies through the Robin Admin host; standalone mode talks to its own backend directly under `/api`. */
  apiBasePath?: string;
  /** True when running as a self-contained deployment with no host to proxy CSRF/session state through. */
  standalone?: boolean;
}

export interface ToolDefinition {
  key: ToolKey;
  label: string;
  target: 'domain' | 'ip' | 'email' | 'headers' | 'raw' | 'host';
  description: string;
}

export interface TransformFormat {
  id: string;
  label: string;
  category: TransformCategoryId;
  encode?: TransformKey;
  decode?: TransformKey;
  note?: string;
}

export type TransformCategoryId = 'binary' | 'web' | 'hashes' | 'tokens';

export interface TransformCategory {
  id: TransformCategoryId;
  label: string;
  icon: UiIconName;
}

export type UiIconName =
  | 'binary'
  | 'braces'
  | 'copy'
  | 'file'
  | 'globe'
  | 'hash'
  | 'key'
  | 'layers'
  | 'link'
  | 'mail'
  | 'network'
  | 'save'
  | 'search'
  | 'server'
  | 'settings'
  | 'shield'
  | 'swap'
  | 'trash'
  | 'upload'
  | 'wrench';
