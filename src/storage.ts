// LocalStorage persistence: canonical per-tool input/history keys, legacy-key
// migration (older releases used different naming schemes), history merging,
// and last-selected-tab memory. Split out of remote.tsx; no React dependency.

import {
  DEFAULT_PAGE_TABS,
  LEGACY_PAGE_NAMES,
  LEGACY_TOOL_IDS,
  PAGE_TABS,
  TOOL_DEFINITIONS,
  TOOL_PAGE_BY_KEY,
} from './toolDefinitions';
import type { BlocklistProvider, CheckHistoryEntry, CheckResult, ToolKey, ToolPage } from './types';

export const HISTORY_LIMIT = 8;

const STORAGE_PREFIX = 'robin-tools';

export function storageGet(key: string): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function storageSet(key: string, value: string): boolean {
  if (typeof window === 'undefined') return false;
  try {
    window.localStorage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

export function canonicalInputKey(toolKey: ToolKey, field = 'input'): string {
  return `${STORAGE_PREFIX}:tool:${toolKey}:${field}`;
}

export function canonicalHistoryKey(toolKey: ToolKey): string {
  return `${STORAGE_PREFIX}:tool:${toolKey}:history`;
}

export function normalizeStoredToolKey(value: unknown): ToolKey | null {
  if (typeof value !== 'string') return null;
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[\s_/]+/g, '-');
  for (const key of Object.keys(TOOL_DEFINITIONS) as ToolKey[]) {
    if (key === normalized || LEGACY_TOOL_IDS[key]?.includes(normalized)) return key;
  }
  const simplified = normalized
    .replace(/^email-dns-/, '')
    .replace(/^dns-/, '')
    .replace(/-(?:record|lookup|check)$/, '');
  if (simplified === 'tls-rpt') return 'tlsrpt';
  if (simplified === 'mail-srv') return 'srv';
  if (TOOL_DEFINITIONS[simplified as ToolKey]) return simplified as ToolKey;
  return null;
}

function legacyStorageKeys(toolKey: ToolKey, suffix: 'input' | 'history' | 'selector'): string[] {
  const page = TOOL_PAGE_BY_KEY[toolKey];
  const pages = LEGACY_PAGE_NAMES[page] ?? [page];
  const ids = [
    ...new Set([
      toolKey,
      ...(LEGACY_TOOL_IDS[toolKey] ?? []),
      `${toolKey}-record`,
      `${toolKey}-lookup`,
      `${toolKey}-check`,
    ]),
  ];
  const keys = new Set<string>();
  for (const family of pages) {
    for (const id of ids) {
      keys.add(`${STORAGE_PREFIX}:${family}:${id}:${suffix}`);
      keys.add(`${STORAGE_PREFIX}-${family}-${id}-${suffix}`);
      keys.add(`${STORAGE_PREFIX}-${suffix}-${family}-${id}`);
    }
  }
  for (const id of ids) {
    keys.add(`${STORAGE_PREFIX}:${id}:${suffix}`);
    keys.add(`${STORAGE_PREFIX}-${id}-${suffix}`);
    keys.add(`${STORAGE_PREFIX}-${suffix}-${id}`);
  }
  return [...keys];
}

function readLegacyFamilyValue(
  toolKey: ToolKey,
  field: 'input' | 'history' | 'selector'
): unknown[] {
  const page = TOOL_PAGE_BY_KEY[toolKey];
  const ids = [
    ...new Set([
      toolKey,
      ...(LEGACY_TOOL_IDS[toolKey] ?? []),
      `${toolKey}-record`,
      `${toolKey}-lookup`,
      `${toolKey}-check`,
    ]),
  ];
  const values: unknown[] = [];
  for (const family of LEGACY_PAGE_NAMES[page] ?? [page]) {
    for (const key of [
      `${STORAGE_PREFIX}:${family}:${field}`,
      `${STORAGE_PREFIX}-${family}-${field}`,
      `${STORAGE_PREFIX}-${field}-${family}`,
    ]) {
      const raw = storageGet(key);
      if (!raw) continue;
      try {
        const parsed: unknown = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          if (field === 'history') values.push(parsed);
          continue;
        }
        if (!parsed || typeof parsed !== 'object') continue;
        const bucket = parsed as Record<string, unknown>;
        for (const [storedId, value] of Object.entries(bucket)) {
          if (ids.includes(storedId) || normalizeStoredToolKey(storedId) === toolKey)
            values.push(value);
        }
        const nested = bucket[field];
        if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
          for (const [storedId, value] of Object.entries(nested as Record<string, unknown>)) {
            if (ids.includes(storedId) || normalizeStoredToolKey(storedId) === toolKey)
              values.push(value);
          }
        }
      } catch {
        // A malformed legacy bucket must not prevent other valid keys from migrating.
      }
    }
  }
  return values;
}

export function migrateToolInput(toolKey: ToolKey, field: 'input' | 'selector' = 'input'): string {
  const canonicalKey = canonicalInputKey(toolKey, field);
  const current = storageGet(canonicalKey);
  if (current !== null) return current;

  const legacyField = field;
  const directValues = legacyStorageKeys(toolKey, legacyField)
    .map(storageGet)
    .filter((value): value is string => value !== null);
  const familyValues = readLegacyFamilyValue(toolKey, legacyField).filter(
    (value): value is string => typeof value === 'string'
  );
  const globalValue =
    field === 'selector'
      ? storageGet(`${STORAGE_PREFIX}-last-selector`)
      : storageGet(
          `${STORAGE_PREFIX}-last-${TOOL_DEFINITIONS[toolKey].target === 'ip' ? 'ip' : 'domain'}`
        );
  const migrated = [...directValues, ...familyValues, globalValue].find(
    (value): value is string => typeof value === 'string'
  );
  if (migrated !== undefined) storageSet(canonicalKey, migrated);
  return migrated ?? '';
}

function isHistoryEntry(value: unknown): value is CheckHistoryEntry {
  if (!value || typeof value !== 'object') return false;
  const entry = value as Partial<CheckHistoryEntry>;
  return (
    (typeof entry.id === 'number' || typeof entry.id === 'string') &&
    typeof entry.targetValue === 'string' &&
    typeof entry.status === 'string' &&
    Boolean(entry.result && typeof entry.result === 'object')
  );
}

function parseHistory(raw: string | null): CheckHistoryEntry[] | null {
  if (raw === null) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return null;
    return parsed.filter(isHistoryEntry).map((entry) => ({ ...entry, id: Number(entry.id) }));
  } catch {
    return null;
  }
}

export function mergeHistory(...groups: CheckHistoryEntry[][]): CheckHistoryEntry[] {
  const merged = new Map<string, CheckHistoryEntry>();
  for (const entry of groups.flat()) {
    const key = Number.isFinite(entry.id)
      ? `id:${entry.id}`
      : `${entry.toolKind}:${entry.targetValue}:${entry.selector ?? ''}:${entry.createdAt}`;
    if (!merged.has(key)) merged.set(key, entry);
  }
  return [...merged.values()]
    .sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt))
    .slice(0, HISTORY_LIMIT);
}

export function loadLocalHistory(toolKey: ToolKey): CheckHistoryEntry[] {
  const canonicalKey = canonicalHistoryKey(toolKey);
  const canonical = parseHistory(storageGet(canonicalKey));
  const canonicalEntries = (canonical ?? [])
    .filter((entry) => normalizeStoredToolKey(entry.toolKind) === toolKey)
    .map((entry) => ({
      ...entry,
      toolKind: toolKey,
      result: { ...entry.result, toolKind: toolKey },
    }));
  const markerKey = `${canonicalKey}:migrated`;
  if (storageGet(markerKey) === '1') return canonicalEntries;

  const legacy: CheckHistoryEntry[] = [];
  for (const key of legacyStorageKeys(toolKey, 'history')) {
    const entries = parseHistory(storageGet(key));
    if (entries)
      legacy.push(
        ...entries
          .filter((entry) => normalizeStoredToolKey(entry.toolKind) === toolKey)
          .map((entry) => ({
            ...entry,
            toolKind: toolKey,
            result: { ...entry.result, toolKind: toolKey },
          }))
      );
  }
  for (const value of readLegacyFamilyValue(toolKey, 'history')) {
    const entries = Array.isArray(value) ? value.filter(isHistoryEntry) : [];
    legacy.push(
      ...entries
        .filter((entry) => normalizeStoredToolKey(entry.toolKind) === toolKey)
        .map((entry) => ({
          ...entry,
          toolKind: toolKey,
          result: { ...entry.result, toolKind: toolKey },
        }))
    );
  }

  const merged = mergeHistory(canonicalEntries, legacy);
  if (
    (canonical !== null || legacy.length > 0) &&
    storageSet(canonicalKey, JSON.stringify(merged))
  ) {
    storageSet(markerKey, '1');
  }
  return merged;
}

export function saveLocalHistory(toolKey: ToolKey, entries: CheckHistoryEntry[]): void {
  storageSet(canonicalHistoryKey(toolKey), JSON.stringify(mergeHistory(entries)));
  storageSet(`${canonicalHistoryKey(toolKey)}:migrated`, '1');
}

export function historyMatchesTarget(
  entry: CheckHistoryEntry,
  targetType: CheckResult['targetType'],
  targetValue: string,
  selector = ''
): boolean {
  const normalize = (value: string) =>
    targetType === 'domain' ? value.trim().toLowerCase() : value.trim();
  return (
    entry.targetType === targetType &&
    normalize(entry.targetValue) === normalize(targetValue) &&
    (entry.selector ?? '').trim().toLowerCase() === selector.trim().toLowerCase()
  );
}

export function setLastTab(page: ToolPage, toolKey: ToolKey): void {
  storageSet(`${STORAGE_PREFIX}-last-tab-${page}`, toolKey);
}

export function getLastTab(page: ToolPage): ToolKey {
  const canonicalKey = `${STORAGE_PREFIX}-last-tab-${page}`;
  const candidates = [
    storageGet(canonicalKey),
    ...(LEGACY_PAGE_NAMES[page] ?? []).flatMap((family) => [
      storageGet(`${STORAGE_PREFIX}-last-tab-${family}`),
      storageGet(`${STORAGE_PREFIX}:${family}:last-tab`),
    ]),
  ];
  const saved = candidates
    .map(normalizeStoredToolKey)
    .find((key): key is ToolKey => Boolean(key && PAGE_TABS[page].includes(key)));
  if (saved) {
    storageSet(canonicalKey, saved);
    return saved;
  }
  return DEFAULT_PAGE_TABS[page];
}

export function providerLines(providers: BlocklistProvider[]): string {
  return providers
    .filter((provider) => provider.enabled)
    .map((provider) => provider.zone)
    .join('\n');
}

export function providersFromLines(
  lines: string,
  current: BlocklistProvider[]
): BlocklistProvider[] {
  const currentByZone = new Map(current.map((provider) => [provider.zone, provider]));
  return [
    ...new Set(
      lines
        .split(/\r?\n|,/)
        .map((line) => line.trim().toLowerCase())
        .filter(Boolean)
    ),
  ].map((zone) => ({
    id: currentByZone.get(zone)?.id ?? zone.replace(/[^a-z0-9]+/g, '-'),
    zone,
    label: currentByZone.get(zone)?.label ?? zone,
    enabled: true,
    notes: currentByZone.get(zone)?.notes ?? null,
  }));
}
