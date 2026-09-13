// Small presentational building blocks shared by every tool page: icons,
// buttons/fields with built-in accessibility wiring, status/severity pills,
// card/empty-state shells, and the check-result renderer. Split out of
// remote.tsx; these components are stateless aside from generated element ids.

import { cloneElement, useId } from 'react';
import type { ButtonHTMLAttributes, ReactElement, ReactNode } from 'react';
import {
  ArrowLeftRight,
  Binary,
  Braces,
  Copy,
  FileText,
  Globe2,
  Hash,
  KeyRound,
  Layers3,
  Link,
  Mail,
  Network,
  Save,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Trash2,
  Upload,
  Wrench,
  type LucideIcon,
} from 'lucide-react';
import type { CheckResult, Severity, UiIconName, VerificationStatus } from './types';

const UI_ICONS: Record<UiIconName, LucideIcon> = {
  binary: Binary,
  braces: Braces,
  copy: Copy,
  file: FileText,
  globe: Globe2,
  hash: Hash,
  key: KeyRound,
  layers: Layers3,
  link: Link,
  mail: Mail,
  network: Network,
  save: Save,
  search: Search,
  server: Server,
  settings: Settings,
  shield: ShieldCheck,
  swap: ArrowLeftRight,
  trash: Trash2,
  upload: Upload,
  wrench: Wrench,
};

export function UiIcon({ name }: { name: UiIconName }) {
  const Icon = UI_ICONS[name];
  return (
    <Icon
      className="rt-icon"
      size={16}
      strokeWidth={2}
      color="currentColor"
      aria-hidden="true"
      focusable="false"
    />
  );
}

interface ActionButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  icon: UiIconName;
  disabledReason?: string;
}

export function ActionButton({
  icon,
  disabledReason,
  disabled,
  children,
  ...props
}: ActionButtonProps) {
  const hintId = useId();
  return (
    <>
      <button
        type="button"
        className="rt-action"
        disabled={disabled}
        aria-describedby={disabled && disabledReason ? hintId : undefined}
        {...props}
      >
        <UiIcon name={icon} />
        {children}
      </button>
      {disabled && disabledReason ? (
        <span id={hintId} className="rt-control-hint">
          {disabledReason}
        </span>
      ) : null}
    </>
  );
}

interface FieldProps {
  label: string;
  children: ReactElement<{ id?: string; 'aria-describedby'?: string }>;
  hint?: string;
}

export function Field({ label, children, hint }: FieldProps) {
  const inputId = useId();
  const hintId = useId();
  return (
    <div className="rt-field">
      <label className="rt-field-label" htmlFor={inputId}>
        {label}
      </label>
      {cloneElement(children, {
        id: inputId,
        'aria-describedby': hint ? hintId : children.props['aria-describedby'],
      })}
      {hint ? (
        <span id={hintId} className="rt-field-hint">
          {hint}
        </span>
      ) : null}
    </div>
  );
}

export function StatusPill({ status }: { status: VerificationStatus }) {
  const className = (() => {
    switch (status) {
      case 'pass':
        return 'rt-pill rt-pill-healthy';
      case 'warning':
        return 'rt-pill rt-pill-low';
      case 'fail':
        return 'rt-pill rt-pill-high';
      case 'error':
        return 'rt-pill rt-pill-critical';
    }
  })();

  const label: Record<VerificationStatus, string> = {
    pass: 'Pass',
    warning: 'Warning',
    fail: 'Fail',
    error: 'Error',
  };

  return <span className={className}>{label[status]}</span>;
}

export function SeverityPill({ severity }: { severity: Severity }) {
  const label: Record<Severity, string> = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Info',
  };

  return <span className={`rt-pill rt-pill-${severity}`}>{label[severity]}</span>;
}

export function DetailCard({
  title,
  meta,
  children,
}: {
  title: string;
  meta?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rt-card">
      <div className="rt-card-header">
        <h2>{title}</h2>
        {meta ? <div className="rt-card-meta">{meta}</div> : null}
      </div>
      {children}
    </section>
  );
}

export function EmptyState({ title, description }: { title: string; description: string }) {
  return (
    <section className="rt-empty-state" aria-label={title}>
      <strong>{title}</strong>
      <p>{description}</p>
    </section>
  );
}

function formatRecordValue(record: {
  key: string;
  label: string;
  value: string | null;
  ok: boolean | null;
}) {
  const value = record.value ?? 'No record found';

  // DNS posture - render as status list
  if (record.key === 'dns-posture') {
    const lines = value.split('\n');
    return (
      <ul className="rt-status-list">
        {lines.map((line, i) => {
          const [label, status] = line.split(': ');
          const isPass = status === '✓';
          const isFail = status === '✗';
          return (
            <li key={i} className="rt-status-item">
              <span className="rt-status-label">{label}</span>
              <span
                className={`rt-status-badge ${isPass ? 'rt-status-pass' : isFail ? 'rt-status-fail' : 'rt-status-na'}`}
              >
                {isPass ? 'Pass' : isFail ? 'Missing' : 'N/A'}
              </span>
            </li>
          );
        })}
      </ul>
    );
  }

  // DKIM selectors - render as status list
  if (record.key === 'dkim-selectors') {
    const lines = value.split('\n');
    return (
      <ul className="rt-status-list">
        {lines.map((line, i) => {
          const resolved = line.includes('✓ resolved');
          const selector = line.split(':')[0];
          return (
            <li key={i} className="rt-status-item">
              <code className="rt-selector-name">{selector}</code>
              <span className={`rt-status-badge ${resolved ? 'rt-status-pass' : 'rt-status-fail'}`}>
                {resolved ? 'Resolved' : 'Not found'}
              </span>
            </li>
          );
        })}
      </ul>
    );
  }

  // Parsed evidence - render as labeled list
  if (record.key === 'parsed-input') {
    const lines = value.split('\n');
    return (
      <dl className="rt-evidence-list">
        {lines.map((line, i) => {
          const colonIndex = line.indexOf(':');
          if (colonIndex > 0) {
            const label = line.slice(0, colonIndex);
            const content = line.slice(colonIndex + 1).trim();
            return (
              <div key={i} className="rt-evidence-item">
                <dt className="rt-evidence-label">{label}</dt>
                <dd className="rt-evidence-value">{content || 'none'}</dd>
              </div>
            );
          }
          return (
            <div key={i} className="rt-evidence-item">
              <dd className="rt-evidence-value">{line}</dd>
            </div>
          );
        })}
      </dl>
    );
  }

  // Default: code block
  return <code>{value}</code>;
}

export function renderResultBody(result: CheckResult) {
  return (
    <>
      <section className="rt-issue-list" aria-label="Findings">
        {result.findings.length > 0 ? (
          result.findings.map((finding) => (
            <article key={finding.code} className={`rt-issue rt-issue-${finding.severity}`}>
              <div className="rt-issue-head">
                <strong>{finding.title}</strong>
                <SeverityPill severity={finding.severity} />
              </div>
              <p>{finding.detail}</p>
            </article>
          ))
        ) : (
          <article className="rt-issue rt-issue-verified">
            <div className="rt-issue-head">
              <strong>{result.summary}</strong>
              <StatusPill status={result.status} />
            </div>
          </article>
        )}
      </section>

      <dl className="rt-record-grid">
        {result.records.map((record) => (
          <div key={`${result.toolKind}-${record.key}`} className="rt-record rt-record-span">
            <dt className="rt-record-title">{record.label}</dt>
            <dd className="rt-record-value">
              {formatRecordValue(record)}
              <p className="rt-record-explanation">{record.explanation}</p>
            </dd>
          </div>
        ))}
      </dl>
    </>
  );
}
