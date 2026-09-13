import { useCallback, useEffect, useRef, useState } from 'react';
import type { KeyboardEvent } from 'react';
import {
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  convertUnixTimestamp,
  decodeJwt,
  hexDecode,
  md5Hex,
  prettyJson,
  quotedPrintableDecode,
  quotedPrintableEncode,
  samlRedirectDecode,
  samlRedirectEncode,
  sha256Hex,
  urlDecode,
  urlEncode,
  utf16HexDecode,
  uuDecode,
  uuEncode,
} from './encoding';
import { moduleApiFetch } from './moduleApi';
import {
  ActionButton,
  DetailCard,
  EmptyState,
  Field,
  renderResultBody,
  StatusPill,
  UiIcon,
} from './components';
import {
  defaultTransformKey,
  findTransformFormat,
  isTransformKey,
  moduleDefinition,
  PAGE_TABS,
  TOOL_DEFINITIONS,
  TOOL_TAB_ICONS,
  TRANSFORM_CATEGORIES,
  TRANSFORM_FORMATS,
} from './toolDefinitions';
import {
  canonicalInputKey,
  getLastTab,
  historyMatchesTarget,
  HISTORY_LIMIT,
  loadLocalHistory,
  mergeHistory,
  migrateToolInput,
  normalizeStoredToolKey,
  providerLines,
  providersFromLines,
  saveLocalHistory,
  setLastTab,
  storageGet,
  storageSet,
} from './storage';
import {
  ensureModuleStyles,
  formatDate,
  getTabId,
  getToolKey,
  getToolPage,
  hasRole,
  joinModulePath,
} from './utils';
import type {
  BulkDomainResult,
  BulkIpResult,
  CheckHistoryEntry,
  CheckResult,
  ContextResponse,
  HostedModuleProps,
  ToolKey,
  ToolPage,
  ToolSettings,
} from './types';

export { ActionButton, Field, UiIcon } from './components';
export { getTabId } from './utils';
export { moduleDefinition, PAGE_TABS } from './toolDefinitions';
export function ModulePage({
  basePath = '/modules/robin-tools',
  routePath = '',
  navigate,
  styleRoot,
  currentAdmin,
  apiBasePath = '/api/modules/robin-tools',
  standalone = false,
}: HostedModuleProps = {}) {
  const fetchModuleJson = useCallback(
    <T,>(path: string, init?: RequestInit): Promise<T> => {
      return moduleApiFetch<T>(apiBasePath, path, init, { csrf: !standalone });
    },
    [apiBasePath, standalone]
  );
  const [context, setContext] = useState<ContextResponse | null>(null);
  const [toolDomainInput, setToolDomainInput] = useState('');
  const [toolIpInput, setToolIpInput] = useState('');
  const [toolSelectorInput, setToolSelectorInput] = useState('');
  const [toolResult, setToolResult] = useState<CheckResult | null>(null);
  const [toolHistory, setToolHistory] = useState<CheckHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [toolBulkText, setToolBulkText] = useState('');
  const [blocklistText, setBlocklistText] = useState('');
  const [analysisInputKind, setAnalysisInputKind] = useState<
    'domain' | 'email' | 'headers' | 'raw'
  >('domain');
  const [analysisInput, setAnalysisInput] = useState('');
  const [uploadFilename, setUploadFilename] = useState('');
  const [uploadStatus, setUploadStatus] = useState('');
  const [serverTarget, setServerTarget] = useState('');
  const [serverPorts, setServerPorts] = useState('25,465,587,110,143,993,995');
  const [settings, setSettings] = useState<ToolSettings | null>(null);
  const [rblProviderText, setRblProviderText] = useState('');
  const [dblProviderText, setDblProviderText] = useState('');
  const [resolversText, setResolversText] = useState('');
  const [toolBulkDomainResults, setToolBulkDomainResults] = useState<BulkDomainResult[]>([]);
  const [toolBulkIpResults, setToolBulkIpResults] = useState<BulkIpResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [transformInput, setTransformInput] = useState('');
  const [transformOutput, setTransformOutput] = useState('');
  const [copyStatus, setCopyStatus] = useState('');
  const [standalonePath] = useState('');
  const uploadInputRef = useRef<HTMLInputElement>(null);
  const uploadReaderRef = useRef<FileReader | null>(null);
  const uploadStatusTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [selectedTabs, setSelectedTabs] = useState<Record<ToolPage, ToolKey>>(() => ({
    'dns-lookup': getLastTab('dns-lookup'),
    'mail-posture': getLastTab('mail-posture'),
    reputation: getLastTab('reputation'),
    'mail-tests': getLastTab('mail-tests'),
    transforms: getLastTab('transforms'),
  }));

  const isHosted = Boolean(navigate);
  const effectivePath = isHosted ? routePath : standalonePath;
  const routedToolKey = getToolKey(effectivePath);
  const toolPage = getToolPage(effectivePath, routedToolKey);
  const toolKey =
    routedToolKey && PAGE_TABS[toolPage].includes(routedToolKey)
      ? routedToolKey
      : selectedTabs[toolPage];
  const toolDefinition = TOOL_DEFINITIONS[toolKey];
  const canEdit = !isHosted || hasRole(currentAdmin?.role, 'editor');
  const canAdmin = !isHosted || hasRole(currentAdmin?.role, 'admin');
  const activeFormat = isTransformKey(toolKey) ? findTransformFormat(toolKey) : undefined;
  const activePanelLabelId = activeFormat
    ? getTabId('format', activeFormat.id)
    : getTabId(toolPage, toolKey);

  useEffect(() => {
    ensureModuleStyles(styleRoot);
  }, [styleRoot]);

  useEffect(
    () => () => {
      if (uploadStatusTimerRef.current) clearTimeout(uploadStatusTimerRef.current);
      const reader = uploadReaderRef.current;
      if (reader?.readyState === 1) {
        reader.onloadstart = null;
        reader.onload = null;
        reader.onerror = null;
        reader.onabort = null;
        reader.onloadend = null;
        reader.abort();
      }
    },
    []
  );

  // Transforms run live: switching format or direction, or editing the
  // input, updates the result immediately (all local, no request).
  useEffect(() => {
    if (toolPage !== 'transforms' || !isTransformKey(toolKey)) return;
    if (!transformInput) {
      setTransformOutput('');
      setCopyStatus('');
      setError(null);
      return;
    }
    void runTransform();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runTransform closes over transform state that is intentionally re-derived from toolKey/transformInput
  }, [toolKey, transformInput]);

  useEffect(() => {
    const parts = (routePath ?? '').split('/').filter(Boolean);
    const familyRoot =
      parts.length === 1 &&
      (Boolean(PAGE_TABS[parts[0] as ToolPage]) || parts[0] === 'dns' || parts[0] === 'email-dns');
    if (navigate && (parts.length === 0 || familyRoot)) {
      const page = getToolPage(routePath, null);
      navigate(joinModulePath(basePath, `${page}/${selectedTabs[page]}`));
    }
  }, [basePath, navigate, routePath, selectedTabs]);

  useEffect(() => {
    if (!routedToolKey || !PAGE_TABS[toolPage].includes(routedToolKey)) {
      return;
    }
    setSelectedTabs((current) =>
      current[toolPage] === routedToolKey ? current : { ...current, [toolPage]: routedToolKey }
    );
    setLastTab(toolPage, routedToolKey);
  }, [routedToolKey, toolPage]);

  useEffect(() => {
    if (isTransformKey(toolKey) || toolKey === 'reputation-providers') return;
    if (
      toolKey === 'rbl' ||
      toolKey === 'dbl' ||
      toolKey === 'message-analysis' ||
      toolKey === 'mail-server-test'
    ) {
      setToolHistory([]);
      setToolResult(null);
      return;
    }
    const localHistory = loadLocalHistory(toolKey);
    const target = migrateToolInput(toolKey) || localHistory[0]?.targetValue || '';
    if (target) storageSet(canonicalInputKey(toolKey), target);
    if (toolDefinition.target === 'domain') setToolDomainInput(target);
    if (toolDefinition.target === 'ip') setToolIpInput(target);
    const selector = toolKey === 'dkim' ? migrateToolInput(toolKey, 'selector') : '';
    setToolSelectorInput(selector);
    const visibleHistory = target
      ? localHistory.filter((entry) =>
          historyMatchesTarget(entry, toolDefinition.target, target, selector)
        )
      : localHistory;
    setToolHistory(visibleHistory);
    setToolResult(visibleHistory[0]?.result ?? null);
  }, [toolDefinition.target, toolKey]);

  useEffect(() => {
    setToolBulkText(storageGet(canonicalInputKey(toolKey, 'bulk')) ?? '');
    if (toolKey === 'rbl' || toolKey === 'dbl') {
      setBlocklistText(storageGet(canonicalInputKey(toolKey)) ?? '');
    }
    if (toolKey === 'mail-server-test') {
      setServerTarget(storageGet(canonicalInputKey(toolKey)) ?? '');
      setServerPorts(
        storageGet(canonicalInputKey(toolKey, 'ports')) ?? '25,465,587,110,143,993,995'
      );
    }
    if (toolKey === 'message-analysis') {
      const storedMode = storageGet(canonicalInputKey(toolKey, 'mode'));
      const mode =
        storedMode === 'email' || storedMode === 'headers' || storedMode === 'raw'
          ? storedMode
          : 'domain';
      setAnalysisInputKind(mode);
      setAnalysisInput(
        mode === 'domain' || mode === 'email'
          ? (storageGet(canonicalInputKey(toolKey, mode)) ?? '')
          : ''
      );
    }
  }, [toolKey]);

  function updateBulkInput(value: string): void {
    setToolBulkText(value);
    storageSet(canonicalInputKey(toolKey, 'bulk'), value);
  }

  function updateBlocklistInput(value: string): void {
    setBlocklistText(value);
    storageSet(canonicalInputKey(toolKey), value);
  }

  function updateAnalysisMode(mode: typeof analysisInputKind): void {
    const activeReader = uploadReaderRef.current;
    if (activeReader?.readyState === 1) {
      activeReader.abort();
      uploadReaderRef.current = null;
    }
    if (analysisInputKind === 'domain' || analysisInputKind === 'email') {
      storageSet(canonicalInputKey('message-analysis', analysisInputKind), analysisInput);
    }
    storageSet(canonicalInputKey('message-analysis', 'mode'), mode);
    setAnalysisInputKind(mode);
    setAnalysisInput(
      mode === 'domain' || mode === 'email'
        ? (storageGet(canonicalInputKey('message-analysis', mode)) ?? '')
        : ''
    );
    setUploadFilename('');
    setUploadStatus('');
  }

  function updateAnalysisInput(value: string): void {
    setAnalysisInput(value);
    if (analysisInputKind === 'domain' || analysisInputKind === 'email') {
      storageSet(canonicalInputKey('message-analysis', analysisInputKind), value);
    }
  }

  function selectTab(nextToolKey: ToolKey): void {
    setSelectedTabs((current) => ({ ...current, [toolPage]: nextToolKey }));
    setLastTab(toolPage, nextToolKey);
    if (navigate) {
      navigate(joinModulePath(basePath, `${toolPage}/${nextToolKey}`));
    }
  }

  function updateToolTarget(value: string): void {
    if (toolDefinition.target === 'ip') {
      setToolIpInput(value);
    } else {
      setToolDomainInput(value);
    }
    storageSet(canonicalInputKey(toolKey), value);
  }

  function updateToolSelector(value: string): void {
    setToolSelectorInput(value);
    storageSet(canonicalInputKey(toolKey, 'selector'), value);
  }

  useEffect(() => {
    let cancelled = false;
    setError(null);
    setLoading(true);

    fetchModuleJson<ContextResponse>('/context')
      .then((nextContext) => {
        if (cancelled) return;
        setContext(nextContext);
      })
      .catch((err) => {
        if (!cancelled) {
          setError((err as Error).message || 'Failed to load Robin Tools');
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    fetchModuleJson<{ settings: ToolSettings }>('/settings')
      .then((payload) => {
        if (cancelled) return;
        setSettings(payload.settings);
        setRblProviderText(
          storageGet(canonicalInputKey('reputation-providers', 'rbl-providers')) ??
            providerLines(payload.settings.rblProviders)
        );
        setDblProviderText(
          storageGet(canonicalInputKey('reputation-providers', 'dbl-providers')) ??
            providerLines(payload.settings.dblProviders)
        );
        setResolversText(
          storageGet(canonicalInputKey('reputation-providers', 'resolvers')) ??
            payload.settings.resolvers.join('\n')
        );
        setServerPorts(
          storageGet(canonicalInputKey('mail-server-test', 'ports')) ??
            payload.settings.serverPorts.join(',')
        );
      })
      .catch(() => {
        // Settings are optional for existing DNS tools; surface errors only when saving or running.
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- run once on mount only
  }, []);

  useEffect(() => {
    if (isTransformKey(toolKey)) {
      setTransformInput(storageGet(canonicalInputKey(toolKey)) ?? '');
      setToolHistory([]);
      setToolResult(null);
      setHistoryLoading(false);
      return;
    }

    // Provider settings have no history.
    if (toolKey === 'reputation-providers') {
      setToolHistory([]);
      setToolResult(null);
      setHistoryLoading(false);
      return;
    }

    // Tools with multi-target or freeform input use simple recent history
    const useRecentOnly =
      toolKey === 'rbl' ||
      toolKey === 'dbl' ||
      toolKey === 'message-analysis' ||
      toolKey === 'mail-server-test';

    if (useRecentOnly) {
      const controller = new AbortController();
      setHistoryLoading(true);
      const params = new URLSearchParams({
        toolKind: toolKey,
        limit: String(HISTORY_LIMIT),
      });

      fetchModuleJson<{ items: CheckHistoryEntry[] }>(`/checks/recent?${params.toString()}`, {
        signal: controller.signal,
      })
        .then((payload) => {
          if (!controller.signal.aborted) {
            const merged = mergeHistory(payload.items, loadLocalHistory(toolKey));
            setToolHistory(merged);
            saveLocalHistory(toolKey, merged);
            // Don't auto-populate result for multi-target tools
          }
        })
        .catch(() => {
          // Silently ignore history load errors for these tools
        })
        .finally(() => {
          if (!controller.signal.aborted) {
            setHistoryLoading(false);
          }
        });

      return () => {
        controller.abort();
      };
    }

    // DNS tools: filter by target
    const targetType = toolDefinition.target;
    const targetValue =
      targetType === 'domain' ? toolDomainInput.trim().toLowerCase() : toolIpInput.trim();
    const selector = toolKey === 'dkim' ? toolSelectorInput.trim().toLowerCase() : '';

    if (!targetValue) {
      setToolHistory([]);
      setToolResult(null);
      setHistoryLoading(false);
      return;
    }

    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      setHistoryLoading(true);
      const params = new URLSearchParams({
        toolKind: toolKey,
        targetType,
        targetValue,
        limit: String(HISTORY_LIMIT),
      });
      if (toolKey === 'dkim' && selector) {
        params.set('selector', selector);
      }

      fetchModuleJson<{ items: CheckHistoryEntry[] }>(`/checks/history?${params.toString()}`, {
        signal: controller.signal,
      })
        .then((payload) => {
          if (!controller.signal.aborted) {
            const stored = loadLocalHistory(toolKey);
            const remote = payload.items.filter(
              (entry) => normalizeStoredToolKey(entry.toolKind) === toolKey
            );
            const visible = mergeHistory(
              remote,
              stored.filter((entry) =>
                historyMatchesTarget(entry, targetType, targetValue, selector)
              )
            );
            setToolHistory(visible);
            setToolResult(visible[0]?.result ?? null);
            saveLocalHistory(toolKey, mergeHistory(remote, stored));
          }
        })
        .catch((err) => {
          if (!controller.signal.aborted) {
            setError((err as Error).message || 'Failed to load check history');
          }
        })
        .finally(() => {
          if (!controller.signal.aborted) {
            setHistoryLoading(false);
          }
        });
    }, 300);

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- fetchModuleJson is stable per apiBasePath/standalone
  }, [toolDefinition.target, toolDomainInput, toolIpInput, toolKey, toolSelectorInput]);

  async function runTool() {
    if (!canEdit) {
      setError('Editor role required to run checks.');
      return;
    }

    const targetType = toolDefinition.target;
    const targetValue =
      targetType === 'domain' ? toolDomainInput.trim().toLowerCase() : toolIpInput.trim();
    const selector = toolKey === 'dkim' ? toolSelectorInput.trim().toLowerCase() : '';

    if (!targetValue) {
      setError(`Enter a ${targetType === 'domain' ? 'domain' : 'source IP'} to run this check.`);
      return;
    }

    setError(null);
    setLoadingDetail(true);
    try {
      const payload = await fetchModuleJson<{
        result: CheckResult;
        historyEntry: CheckHistoryEntry;
      }>('/checks/run', {
        method: 'POST',
        body: JSON.stringify({
          toolKind: toolKey,
          targetType,
          targetValue,
          selector: toolKey === 'dkim' ? selector || undefined : undefined,
        }),
      });

      setToolResult(payload.result);
      setToolHistory((current) => {
        const next = mergeHistory([payload.historyEntry], current);
        saveLocalHistory(toolKey, mergeHistory([payload.historyEntry], loadLocalHistory(toolKey)));
        return next;
      });

      if (targetType === 'domain') {
        setToolDomainInput(targetValue);
      } else {
        setToolIpInput(targetValue);
      }
      storageSet(canonicalInputKey(toolKey), targetValue);
      if (toolKey === 'dkim' && selector) {
        setToolSelectorInput(selector);
        storageSet(canonicalInputKey(toolKey, 'selector'), selector);
      }
    } catch (err) {
      setError((err as Error).message || 'Failed to run check');
    } finally {
      setLoadingDetail(false);
    }
  }

  async function runBulkTool() {
    if (!canEdit) {
      setError('Editor role required to run checks.');
      return;
    }

    const entries = toolBulkText
      .split(/\r?\n|,/)
      .map((entry) => entry.trim())
      .filter(Boolean);
    if (entries.length === 0) {
      setError('Enter one or more values for the bulk run.');
      return;
    }

    setError(null);
    setLoadingDetail(true);
    try {
      if (toolKey === 'fcrdns') {
        const response = await fetchModuleJson<{ results: BulkIpResult[] }>('/ips/bulk-check', {
          method: 'POST',
          body: JSON.stringify({ ips: entries }),
        });
        setToolBulkIpResults(response.results);
        setToolBulkDomainResults([]);
      } else {
        const response = await fetchModuleJson<{ results: BulkDomainResult[] }>(
          '/domains/bulk-check',
          {
            method: 'POST',
            body: JSON.stringify({
              domains: entries,
              selector: toolKey === 'dkim' ? toolSelectorInput.trim() || undefined : undefined,
              optionalChecks: context?.optionalChecks,
            }),
          }
        );
        setToolBulkDomainResults(response.results);
        setToolBulkIpResults([]);
      }
    } catch (err) {
      setError((err as Error).message || 'Failed to run bulk check');
    } finally {
      setLoadingDetail(false);
    }
  }

  async function runBlocklistTool() {
    if (!canEdit) {
      setError('Editor role required to run checks.');
      return;
    }

    const entries = blocklistText
      .split(/\r?\n|,/)
      .map((entry) => entry.trim())
      .filter(Boolean);
    if (entries.length === 0) {
      setError(`Enter one or more ${toolKey === 'rbl' ? 'IP addresses' : 'domains'} to check.`);
      return;
    }

    setError(null);
    setLoadingDetail(true);
    try {
      const path = toolKey === 'rbl' ? '/reputation/rbl/run' : '/reputation/dbl/run';
      const payload = await fetchModuleJson<{
        result: CheckResult;
        historyEntry: CheckHistoryEntry;
      }>(path, {
        method: 'POST',
        body: JSON.stringify({ targets: entries }),
      });
      setToolResult(payload.result);
      setToolHistory((current) => {
        const next = mergeHistory([payload.historyEntry], current);
        saveLocalHistory(toolKey, next);
        return next;
      });
    } catch (err) {
      setError((err as Error).message || `Failed to run ${toolDefinition.label} check`);
    } finally {
      setLoadingDetail(false);
    }
  }

  async function runAnalysisTool() {
    if (!canEdit) {
      setError('Editor role required to run mail tests.');
      return;
    }

    if (!analysisInput.trim()) {
      setError('Enter diagnostic input to analyze.');
      return;
    }

    setError(null);
    setLoadingDetail(true);
    try {
      const payload = await fetchModuleJson<{
        result: CheckResult;
        historyEntry: CheckHistoryEntry;
      }>('/mail-tests/message-analysis/run', {
        method: 'POST',
        body: JSON.stringify({ inputKind: analysisInputKind, value: analysisInput }),
      });
      setToolResult(payload.result);
      setToolHistory((current) => {
        const next = mergeHistory([payload.historyEntry], current);
        saveLocalHistory(toolKey, next);
        return next;
      });
    } catch (err) {
      setError((err as Error).message || 'Failed to analyze message');
    } finally {
      setLoadingDetail(false);
    }
  }

  async function runServerTool() {
    if (!canEdit) {
      setError('Editor role required to run mail tests.');
      return;
    }

    const target = serverTarget.trim();
    if (!target) {
      setError('Enter a domain, host, or IP to test.');
      return;
    }

    const ports = serverPorts
      .split(',')
      .map((port) => Number.parseInt(port.trim(), 10))
      .filter((port) => Number.isInteger(port));
    setError(null);
    setLoadingDetail(true);
    try {
      const payload = await fetchModuleJson<{
        result: CheckResult;
        historyEntry: CheckHistoryEntry;
      }>('/mail-tests/mail-server-test/run', {
        method: 'POST',
        body: JSON.stringify({ target, ports }),
      });
      setToolResult(payload.result);
      setToolHistory((current) => {
        const next = mergeHistory([payload.historyEntry], current);
        saveLocalHistory(toolKey, next);
        return next;
      });
    } catch (err) {
      setError((err as Error).message || 'Failed to run mail server test');
    } finally {
      setLoadingDetail(false);
    }
  }

  async function saveBlocklistSettings() {
    if (!canAdmin || !settings) {
      setError('Admin role required to update provider settings.');
      return;
    }

    const nextSettings: ToolSettings = {
      ...settings,
      rblProviders: providersFromLines(rblProviderText, settings.rblProviders),
      dblProviders: providersFromLines(dblProviderText, settings.dblProviders),
      resolvers: resolversText
        .split(/\r?\n|,/)
        .map((line) => line.trim())
        .filter(Boolean),
      serverPorts: serverPorts
        .split(',')
        .map((port) => Number.parseInt(port.trim(), 10))
        .filter((port) => Number.isInteger(port)),
    };

    setError(null);
    setLoadingDetail(true);
    try {
      const payload = await fetchModuleJson<{ settings: ToolSettings }>('/settings', {
        method: 'PUT',
        body: JSON.stringify({ settings: nextSettings }),
      });
      setSettings(payload.settings);
      setRblProviderText(providerLines(payload.settings.rblProviders));
      setDblProviderText(providerLines(payload.settings.dblProviders));
      setResolversText(payload.settings.resolvers.join('\n'));
      storageSet(
        canonicalInputKey('reputation-providers', 'rbl-providers'),
        providerLines(payload.settings.rblProviders)
      );
      storageSet(
        canonicalInputKey('reputation-providers', 'dbl-providers'),
        providerLines(payload.settings.dblProviders)
      );
      storageSet(
        canonicalInputKey('reputation-providers', 'resolvers'),
        payload.settings.resolvers.join('\n')
      );
      setServerPorts(payload.settings.serverPorts.join(','));
    } catch (err) {
      setError((err as Error).message || 'Failed to save provider settings');
    } finally {
      setLoadingDetail(false);
    }
  }

  async function deleteHistoryEntry(id: number) {
    if (!canEdit) {
      setError('Editor role required to delete history.');
      return;
    }

    if (!window.confirm('Delete this history entry? This cannot be undone.')) {
      return;
    }

    try {
      await fetchModuleJson(`/checks/history/${id}`, { method: 'DELETE' });
      setToolHistory((current) => {
        const next = current.filter((entry) => entry.id !== id);
        saveLocalHistory(
          toolKey,
          loadLocalHistory(toolKey).filter((entry) => entry.id !== id)
        );
        return next;
      });
      if (toolResult && toolHistory[0]?.id === id) {
        setToolResult(toolHistory[1]?.result ?? null);
      }
    } catch (err) {
      setError((err as Error).message || 'Failed to delete history entry');
    }
  }

  async function clearHistory() {
    if (!canEdit) {
      setError('Editor role required to clear history.');
      return;
    }

    if (!window.confirm('Clear all history for this tool? This cannot be undone.')) {
      return;
    }

    try {
      const params = new URLSearchParams({ toolKind: toolKey });
      await fetchModuleJson(`/checks/history?${params.toString()}`, { method: 'DELETE' });
      setToolHistory([]);
      setToolResult(null);
      saveLocalHistory(toolKey, []);
    } catch (err) {
      setError((err as Error).message || 'Failed to clear history');
    }
  }

  function renderHistory(entries: CheckHistoryEntry[], showClear = true) {
    if (historyLoading) {
      return <p className="rt-muted">Loading recent checks…</p>;
    }

    if (entries.length === 0) {
      return <p className="rt-muted">No recent checks for this target yet.</p>;
    }

    return (
      <>
        {showClear && canEdit && entries.length > 0 ? (
          <div className="rt-history-toolbar">
            <button
              type="button"
              className="rt-history-clear"
              onClick={() => void clearHistory()}
              title="Clear all history for this tool"
            >
              <UiIcon name="trash" />
              Clear all
            </button>
          </div>
        ) : null}
        <div className="rt-history-list">
          {entries.map((entry) => (
            <details key={entry.id} className="rt-history-item">
              <summary className="rt-history-summary">
                <span className="rt-history-main">
                  <strong>{entry.summary ?? entry.result.summary}</strong>
                  <small>
                    {formatDate(entry.createdAt)}
                    {entry.selector ? ` · ${entry.selector}` : ''}
                  </small>
                </span>
                <span className="rt-history-actions">
                  <StatusPill status={entry.status} />
                  <span className="rt-history-more">More</span>
                </span>
              </summary>
              <div className="rt-history-detail">
                {renderResultBody(entry.result)}
                {canEdit ? (
                  <button
                    type="button"
                    className="rt-history-delete"
                    onClick={() => void deleteHistoryEntry(entry.id)}
                  >
                    <UiIcon name="trash" />
                    Delete this entry
                  </button>
                ) : null}
              </div>
            </details>
          ))}
        </div>
      </>
    );
  }

  function renderBulkDomainTable() {
    if (toolBulkDomainResults.length === 0) return null;

    return (
      <DetailCard title={`Bulk ${toolDefinition.label} results`}>
        <div className="rt-table-scroll">
          <table className="rt-table">
            <thead>
              <tr>
                <th scope="col">Domain</th>
                <th scope="col">Status</th>
                <th scope="col">Issues</th>
              </tr>
            </thead>
            <tbody>
              {toolBulkDomainResults.map((result) => {
                let ok: boolean;
                switch (toolKey) {
                  case 'mx':
                    ok = result.checks.mx;
                    break;
                  case 'spf':
                    ok = result.checks.spf;
                    break;
                  case 'dmarc':
                    ok = result.checks.dmarc;
                    break;
                  case 'dkim':
                    ok = Boolean(result.checks.dkim);
                    break;
                  case 'mta-sts':
                    ok = Boolean(result.checks.mtaSts);
                    break;
                  case 'tlsrpt':
                    ok = Boolean(result.checks.tlsRpt);
                    break;
                  case 'dane':
                    ok = Boolean(result.checks.dane);
                    break;
                  case 'bimi':
                    ok = Boolean(result.checks.bimi);
                    break;
                  default:
                    ok = false;
                }

                return (
                  <tr key={result.domain}>
                    <th scope="row">{result.domain}</th>
                    <td>{ok ? 'Pass' : 'Needs work'}</td>
                    <td>{result.issues.length}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </DetailCard>
    );
  }

  function renderBulkIpTable() {
    if (toolBulkIpResults.length === 0) return null;

    return (
      <DetailCard title="Bulk FCrDNS results">
        <div className="rt-table-scroll">
          <table className="rt-table">
            <thead>
              <tr>
                <th scope="col">IP</th>
                <th scope="col">PTR</th>
                <th scope="col">Issues</th>
              </tr>
            </thead>
            <tbody>
              {toolBulkIpResults.map((result) => (
                <tr key={result.sourceIp}>
                  <th scope="row">{result.sourceIp}</th>
                  <td>{result.ptrHost ?? 'Missing'}</td>
                  <td>{result.issues.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </DetailCard>
    );
  }

  function renderDomainTool() {
    return (
      <div className="rt-workbench rt-workbench-tools">
        <aside className="rt-sidebar">
          <DetailCard title={toolDefinition.label}>
            <p className="rt-muted">{toolDefinition.description}</p>
            <div className="rt-toolbar rt-toolbar-stack">
              <Field label="Domain">
                <input
                  name="domain"
                  autoComplete="off"
                  spellCheck={false}
                  value={toolDomainInput}
                  onChange={(event) => updateToolTarget(event.target.value)}
                  placeholder="example.com"
                />
              </Field>
              {toolKey === 'dkim' ? (
                <Field label="DKIM selector">
                  <input
                    name="dkim-selector"
                    autoComplete="off"
                    spellCheck={false}
                    value={toolSelectorInput}
                    onChange={(event) => updateToolSelector(event.target.value)}
                    placeholder="selector"
                  />
                </Field>
              ) : null}
              <ActionButton
                icon="search"
                onClick={() => void runTool()}
                disabled={loadingDetail || !canEdit}
                disabledReason={!canEdit ? 'Editor role required to run checks.' : undefined}
              >
                {loadingDetail ? 'Running…' : `Run ${toolDefinition.label} check`}
              </ActionButton>
            </div>
          </DetailCard>

          <DetailCard title="Bulk check">
            <div className="rt-toolbar rt-toolbar-stack">
              <Field label="Domains">
                <textarea
                  name="domains-bulk"
                  autoComplete="off"
                  spellCheck={false}
                  rows={7}
                  value={toolBulkText}
                  onChange={(event) => updateBulkInput(event.target.value)}
                  placeholder="example.com&#10;example.net"
                />
              </Field>
              <ActionButton
                icon="layers"
                onClick={() => void runBulkTool()}
                disabled={loadingDetail || !canEdit}
                disabledReason={!canEdit ? 'Editor role required to run bulk checks.' : undefined}
              >
                {loadingDetail ? 'Running…' : `Run bulk ${toolDefinition.label}`}
              </ActionButton>
            </div>
          </DetailCard>
        </aside>

        <div className="rt-detail">
          {toolResult ? (
            <DetailCard
              title={`${toolDefinition.label} result`}
              meta={
                <span className="rt-card-note">Checked {formatDate(toolResult.checkedAt)}</span>
              }
            >
              {renderResultBody(toolResult)}
            </DetailCard>
          ) : (
            <EmptyState
              title={`Run a ${toolDefinition.label} check`}
              description="Run a live check or pick an older run from Recent checks."
            />
          )}

          {renderBulkDomainTable()}

          <DetailCard title="Recent checks">{renderHistory(toolHistory)}</DetailCard>
        </div>
      </div>
    );
  }

  function renderIpTool() {
    return (
      <div className="rt-workbench rt-workbench-tools">
        <aside className="rt-sidebar">
          <DetailCard title="FCrDNS">
            <p className="rt-muted">{toolDefinition.description}</p>
            <div className="rt-toolbar rt-toolbar-stack">
              <Field label="IP address">
                <input
                  name="ip-address"
                  autoComplete="off"
                  spellCheck={false}
                  value={toolIpInput}
                  onChange={(event) => updateToolTarget(event.target.value)}
                  placeholder="203.0.113.10"
                />
              </Field>
              <ActionButton
                icon="search"
                onClick={() => void runTool()}
                disabled={loadingDetail || !canEdit}
                disabledReason={!canEdit ? 'Editor role required to run checks.' : undefined}
              >
                {loadingDetail ? 'Running…' : 'Run FCrDNS check'}
              </ActionButton>
            </div>
          </DetailCard>

          <DetailCard title="Bulk check">
            <div className="rt-toolbar rt-toolbar-stack">
              <Field label="IP addresses">
                <textarea
                  name="ip-addresses-bulk"
                  autoComplete="off"
                  spellCheck={false}
                  rows={7}
                  value={toolBulkText}
                  onChange={(event) => updateBulkInput(event.target.value)}
                  placeholder="203.0.113.10&#10;2001:db8::1"
                />
              </Field>
              <ActionButton
                icon="layers"
                onClick={() => void runBulkTool()}
                disabled={loadingDetail || !canEdit}
                disabledReason={!canEdit ? 'Editor role required to run bulk checks.' : undefined}
              >
                {loadingDetail ? 'Running…' : 'Run bulk FCrDNS'}
              </ActionButton>
            </div>
          </DetailCard>
        </aside>

        <div className="rt-detail">
          {toolResult ? (
            <DetailCard
              title="FCrDNS result"
              meta={
                <span className="rt-card-note">Checked {formatDate(toolResult.checkedAt)}</span>
              }
            >
              {renderResultBody(toolResult)}
            </DetailCard>
          ) : (
            <EmptyState
              title="Run an FCrDNS check"
              description="Run a live check or pick an older run from Recent checks."
            />
          )}

          {renderBulkIpTable()}

          <DetailCard title="Recent checks">{renderHistory(toolHistory)}</DetailCard>
        </div>
      </div>
    );
  }

  function renderProviderSettingsCard(kind: 'rbl' | 'dbl') {
    if (!settings) {
      return null;
    }

    const label = kind.toUpperCase();
    const value = kind === 'rbl' ? rblProviderText : dblProviderText;
    const onChange =
      kind === 'rbl'
        ? (event: React.ChangeEvent<HTMLTextAreaElement>) => setRblProviderText(event.target.value)
        : (event: React.ChangeEvent<HTMLTextAreaElement>) => setDblProviderText(event.target.value);

    return (
      <DetailCard title={`${label} config`}>
        <div className="rt-toolbar rt-toolbar-stack">
          <Field label={`${label} providers`}>
            <textarea
              name={`${kind}-providers`}
              autoComplete="off"
              spellCheck={false}
              rows={5}
              value={value}
              onChange={(event) => {
                onChange(event);
                storageSet(
                  canonicalInputKey('reputation-providers', `${kind}-providers`),
                  event.target.value
                );
              }}
              disabled={!canAdmin}
            />
          </Field>
          <ActionButton
            icon="save"
            onClick={() => void saveBlocklistSettings()}
            disabled={loadingDetail || !canAdmin}
            disabledReason={
              !canAdmin ? 'Admin role required to change provider settings.' : undefined
            }
          >
            Save settings
          </ActionButton>
        </div>
      </DetailCard>
    );
  }

  function renderBlocklistTool() {
    const placeholder =
      toolKey === 'rbl' ? '203.0.113.10\n2001:db8::1' : 'example.com\nlinks.example.net';
    return (
      <div className="rt-workbench rt-workbench-tools">
        <aside className="rt-sidebar">
          <DetailCard title={toolDefinition.label}>
            <p className="rt-muted">{toolDefinition.description}</p>
            <div className="rt-toolbar rt-toolbar-stack">
              <Field label={`${toolDefinition.label} targets`}>
                <textarea
                  name="blocklist-targets"
                  autoComplete="off"
                  spellCheck={false}
                  rows={8}
                  value={blocklistText}
                  onChange={(event) => updateBlocklistInput(event.target.value)}
                  placeholder={placeholder}
                />
              </Field>
              <ActionButton
                icon="shield"
                onClick={() => void runBlocklistTool()}
                disabled={loadingDetail || !canEdit}
                disabledReason={
                  !canEdit ? 'Editor role required to run reputation checks.' : undefined
                }
              >
                {loadingDetail ? 'Running…' : `Run ${toolDefinition.label} check`}
              </ActionButton>
            </div>
          </DetailCard>
        </aside>

        <div className="rt-detail">
          {toolResult ? (
            <DetailCard
              title={`${toolDefinition.label} result`}
              meta={
                <span className="rt-card-note">Checked {formatDate(toolResult.checkedAt)}</span>
              }
            >
              {renderResultBody(toolResult)}
            </DetailCard>
          ) : (
            <EmptyState
              title={`Run a ${toolDefinition.label} check`}
              description="Results include provider query names, response codes, TXT context, and disputed resolver notes."
            />
          )}

          <DetailCard title="Recent checks">{renderHistory(toolHistory)}</DetailCard>
        </div>
      </div>
    );
  }

  function announceUpload(message: string) {
    setUploadStatus(message);
    if (uploadStatusTimerRef.current) clearTimeout(uploadStatusTimerRef.current);
    uploadStatusTimerRef.current = setTimeout(() => {
      setUploadStatus('');
      uploadStatusTimerRef.current = null;
    }, 4000);
  }

  function openFilePicker() {
    if (uploadReaderRef.current?.readyState === 1) return;
    uploadInputRef.current?.click();
  }

  function handleFileUpload(event: React.ChangeEvent<HTMLInputElement>) {
    const input = event.currentTarget;
    const file = input.files?.[0];
    if (!file) return;

    setUploadFilename(file.name);
    const reader = new FileReader();
    uploadReaderRef.current = reader;
    reader.onloadstart = () => announceUpload(`Reading ${file.name}…`);
    reader.onload = () => {
      const content = reader.result;
      if (typeof content === 'string') {
        setAnalysisInput(content);
        if (content.includes('From:') || content.includes('DKIM-Signature:')) {
          setAnalysisInputKind('raw');
          storageSet(canonicalInputKey('message-analysis', 'mode'), 'raw');
        }
        announceUpload(`Loaded ${file.name}.`);
      } else {
        announceUpload(`Could not read ${file.name}.`);
      }
    };
    reader.onerror = () => announceUpload(`Could not read ${file.name}.`);
    reader.onabort = () => announceUpload(`Reading ${file.name} was canceled.`);
    reader.onloadend = () => {
      input.value = '';
      if (uploadReaderRef.current === reader) uploadReaderRef.current = null;
    };
    reader.readAsText(file);
  }

  async function runTransform() {
    if (!isTransformKey(toolKey)) return;
    setError(null);
    setCopyStatus('');
    try {
      const output = await (() => {
        switch (toolKey) {
          case 'base64-encode':
            return base64Encode(transformInput);
          case 'base64-decode':
            return base64Decode(transformInput);
          case 'base64url-encode':
            return base64UrlEncode(transformInput);
          case 'base64url-decode':
            return base64UrlDecode(transformInput);
          case 'url-encode':
            return urlEncode(transformInput);
          case 'url-decode':
            return urlDecode(transformInput);
          case 'md5':
            return md5Hex(transformInput);
          case 'sha256':
            return sha256Hex(transformInput);
          case 'saml-encode':
            return samlRedirectEncode(transformInput);
          case 'saml-decode':
            return samlRedirectDecode(transformInput);
          case 'pretty-json':
            return prettyJson(transformInput);
          case 'quoted-printable-encode':
            return quotedPrintableEncode(transformInput);
          case 'quoted-printable-decode':
            return quotedPrintableDecode(transformInput);
          case 'uu-encode':
            return uuEncode(transformInput);
          case 'uu-decode':
            return uuDecode(transformInput);
          case 'utf16-decode':
            return utf16HexDecode(transformInput);
          case 'hex-decode':
            return hexDecode(transformInput);
          case 'jwt-decode': {
            const decoded = decodeJwt(transformInput);
            return `Header (not verified):\n${decoded.header}\n\nPayload (not verified):\n${decoded.payload}`;
          }
          case 'unix-time':
            return JSON.stringify(convertUnixTimestamp(transformInput), null, 2);
        }
      })();
      setTransformOutput(output);
    } catch (err) {
      setTransformOutput('');
      setError((err as Error).message || `Failed to run ${toolDefinition.label}`);
    }
  }

  function swapTransform(): void {
    if (!isTransformKey(toolKey)) return;
    const activeFormat = findTransformFormat(toolKey);
    const nextToolKey =
      activeFormat?.encode && activeFormat.decode
        ? activeFormat.decode === toolKey
          ? activeFormat.encode
          : activeFormat.decode
        : toolKey;
    const previousInput = transformInput;
    setTransformInput(transformOutput);
    setTransformOutput(previousInput);
    setError(null);
    if (nextToolKey !== toolKey) {
      selectTab(nextToolKey);
    }
  }

  async function copyTransformOutput(): Promise<void> {
    try {
      if (!navigator.clipboard) {
        throw new Error('Clipboard access is unavailable.');
      }
      await navigator.clipboard.writeText(transformOutput);
      setCopyStatus('Result copied to clipboard.');
    } catch {
      setCopyStatus('Could not copy the result. Select the result and copy it manually.');
    }
  }

  function handleTabKeyDown(
    event: KeyboardEvent<HTMLButtonElement>,
    tabs: readonly ToolKey[],
    activeTab: ToolKey
  ): void {
    const currentIndex = Math.max(0, tabs.indexOf(activeTab));
    let nextIndex: number;
    switch (event.key) {
      case 'ArrowRight':
      case 'ArrowDown':
        nextIndex = (currentIndex + 1) % tabs.length;
        break;
      case 'ArrowLeft':
      case 'ArrowUp':
        nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
        break;
      case 'Home':
        nextIndex = 0;
        break;
      case 'End':
        nextIndex = tabs.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    selectTab(tabs[nextIndex]);
    const tabList = event.currentTarget.closest('[role="tablist"]');
    requestAnimationFrame(() => {
      tabList?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[nextIndex]?.focus();
    });
  }

  function renderToolNav() {
    if (toolPage !== 'transforms') {
      return (
        <div className="rt-tabs" role="tablist" aria-label={`${toolPage} tools`}>
          {PAGE_TABS[toolPage].map((tabKey) => (
            <button
              key={tabKey}
              id={getTabId(toolPage, tabKey)}
              type="button"
              role="tab"
              aria-selected={toolKey === tabKey}
              aria-controls="rt-tool-panel"
              tabIndex={toolKey === tabKey ? 0 : -1}
              className={`rt-tab${toolKey === tabKey ? ' rt-tab-active' : ''}`}
              onClick={() => selectTab(tabKey)}
              onKeyDown={(event) => handleTabKeyDown(event, PAGE_TABS[toolPage], toolKey)}
            >
              <UiIcon name={TOOL_TAB_ICONS[tabKey]} />
              {TOOL_DEFINITIONS[tabKey].label}
            </button>
          ))}
        </div>
      );
    }

    const activeFormat =
      (isTransformKey(toolKey) ? findTransformFormat(toolKey) : undefined) ?? TRANSFORM_FORMATS[0];
    const direction: 'encode' | 'decode' = activeFormat.decode === toolKey ? 'decode' : 'encode';
    const activeCategory = TRANSFORM_CATEGORIES.find(
      (category) => category.id === activeFormat.category
    )!;
    const formatsInCategory = TRANSFORM_FORMATS.filter(
      (format) => format.category === activeCategory.id
    );
    const hasBothDirections = Boolean(activeFormat.encode && activeFormat.decode);
    const categoryTabs = TRANSFORM_CATEGORIES.map((category) =>
      defaultTransformKey(TRANSFORM_FORMATS.find((format) => format.category === category.id)!)
    );
    const activeCategoryTab = defaultTransformKey(
      TRANSFORM_FORMATS.find((format) => format.category === activeCategory.id)!
    );
    const formatTabs = formatsInCategory.map(defaultTransformKey);
    const activeFormatTab = defaultTransformKey(activeFormat);

    return (
      <div className="rt-encode-nav">
        <div className="rt-tabs" role="tablist" aria-label="Transform categories">
          {TRANSFORM_CATEGORIES.map((category) => {
            const active = category.id === activeCategory.id;
            const firstInCategory = TRANSFORM_FORMATS.find(
              (format) => format.category === category.id
            )!;
            return (
              <button
                key={category.id}
                id={getTabId('category', category.id)}
                type="button"
                role="tab"
                aria-selected={active}
                aria-controls="rt-tool-panel"
                tabIndex={active ? 0 : -1}
                className={`rt-tab${active ? ' rt-tab-active' : ''}`}
                onClick={() => selectTab(defaultTransformKey(firstInCategory))}
                onKeyDown={(event) => handleTabKeyDown(event, categoryTabs, activeCategoryTab)}
              >
                <UiIcon name={category.icon} />
                {category.label}
              </button>
            );
          })}
        </div>
        <div className="rt-encode-subnav">
          <div className="rt-subtabs" role="tablist" aria-label={`${activeCategory.label} formats`}>
            {formatsInCategory.map((format) => {
              const active = format.id === activeFormat.id;
              return (
                <button
                  key={format.id}
                  id={getTabId('format', format.id)}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  aria-controls="rt-tool-panel"
                  tabIndex={active ? 0 : -1}
                  className={`rt-subtab${active ? ' rt-subtab-active' : ''}`}
                  onClick={() => selectTab(defaultTransformKey(format))}
                  onKeyDown={(event) => handleTabKeyDown(event, formatTabs, activeFormatTab)}
                >
                  {format.label}
                </button>
              );
            })}
          </div>
          {hasBothDirections ? (
            <fieldset className="rt-direction" aria-label="Operation">
              <legend>Operation</legend>
              <label>
                <input
                  type="radio"
                  name="rt-transform-direction"
                  checked={direction === 'encode'}
                  onChange={() => selectTab(activeFormat.encode!)}
                />
                Encode
              </label>
              <label>
                <input
                  type="radio"
                  name="rt-transform-direction"
                  checked={direction === 'decode'}
                  onChange={() => selectTab(activeFormat.decode!)}
                />
                Decode
              </label>
            </fieldset>
          ) : activeFormat.note ? (
            <span className="rt-dir-note">{activeFormat.note}</span>
          ) : null}
        </div>
      </div>
    );
  }

  function renderTransformTool() {
    const activeFormat = isTransformKey(toolKey) ? findTransformFormat(toolKey) : undefined;
    const canSwapDirection = Boolean(
      activeFormat?.encode && activeFormat.decode && transformOutput
    );

    return (
      <DetailCard title={toolDefinition.label}>
        <div className="rt-encode-workbench">
          <div className="rt-encode-field">
            <div className="rt-encode-field-head">
              <label htmlFor="rt-transform-input">Input</label>
              <span className="rt-muted rt-small">{transformInput.length} chars</span>
            </div>
            <textarea
              id="rt-transform-input"
              aria-label={`${toolDefinition.label} input`}
              name="transform-input"
              autoComplete="off"
              spellCheck={false}
              rows={8}
              value={transformInput}
              onChange={(event) => {
                setTransformInput(event.target.value);
                storageSet(canonicalInputKey(toolKey), event.target.value);
              }}
              placeholder="Paste or type here…"
            />
          </div>

          <div className="rt-encode-field">
            <div className="rt-encode-field-head">
              <label htmlFor="rt-transform-result">Result</label>
              <span className="rt-encode-field-actions">
                <span className="rt-muted rt-small">{transformOutput.length} chars</span>
                {canSwapDirection ? (
                  <button type="button" className="rt-copy" onClick={swapTransform}>
                    <UiIcon name="swap" />
                    Swap
                  </button>
                ) : null}
                {transformOutput ? (
                  <button
                    type="button"
                    className="rt-copy"
                    onClick={() => void copyTransformOutput()}
                  >
                    <UiIcon name="copy" />
                    Copy
                  </button>
                ) : null}
                {transformInput || transformOutput ? (
                  <button
                    type="button"
                    className="rt-copy"
                    onClick={() => {
                      setTransformInput('');
                      setTransformOutput('');
                      setCopyStatus('');
                      setError(null);
                    }}
                  >
                    <UiIcon name="trash" />
                    Clear
                  </button>
                ) : null}
              </span>
            </div>
            <textarea
              id="rt-transform-result"
              aria-label={`${toolDefinition.label} result`}
              rows={10}
              value={transformOutput}
              readOnly
              placeholder="Result appears here."
            />
            <p className="rt-live-status" aria-live="polite">
              {copyStatus}
            </p>
          </div>

          <p className="rt-inline-note">
            {toolDefinition.description} Nothing is sent or saved — it runs locally in your browser.
          </p>
        </div>
      </DetailCard>
    );
  }

  function renderAnalysisTool() {
    const placeholder =
      analysisInputKind === 'domain'
        ? 'example.com'
        : analysisInputKind === 'email'
          ? 'sender@example.com'
          : 'From: Sender <sender@example.com>\nDate: Thu, 20 Aug 2026 12:00:00 +0000\nSubject: Test\nMessage-ID: <id@example.com>';
    return (
      <div className="rt-workbench rt-workbench-tools">
        <aside className="rt-sidebar">
          <DetailCard title="Message Analysis">
            <p className="rt-muted">{toolDefinition.description}</p>
            <div className="rt-toolbar rt-toolbar-stack">
              <fieldset className="rt-radio-group">
                <legend>Input type</legend>
                {(
                  [
                    ['domain', 'Domain'],
                    ['email', 'Email address'],
                    ['headers', 'Headers'],
                    ['raw', 'Raw email'],
                  ] as const
                ).map(([value, label]) => (
                  <label key={value} className="rt-radio-option">
                    <input
                      type="radio"
                      name="rt-analysis-input-kind"
                      value={value}
                      checked={analysisInputKind === value}
                      onChange={() => updateAnalysisMode(value)}
                    />
                    <span>{label}</span>
                  </label>
                ))}
              </fieldset>
              {analysisInputKind === 'domain' || analysisInputKind === 'email' ? (
                <Field label={analysisInputKind === 'domain' ? 'Domain' : 'Email address'}>
                  <input
                    name="analysis-target"
                    type={analysisInputKind === 'email' ? 'email' : 'text'}
                    inputMode={analysisInputKind === 'email' ? 'email' : 'text'}
                    autoComplete="off"
                    spellCheck={false}
                    value={analysisInput}
                    onChange={(event) => updateAnalysisInput(event.target.value)}
                    placeholder={placeholder}
                  />
                </Field>
              ) : (
                <>
                  <Field label={analysisInputKind === 'headers' ? 'Message headers' : 'Raw email'}>
                    <textarea
                      name="analysis-content"
                      autoComplete="off"
                      spellCheck={false}
                      rows={14}
                      value={analysisInput}
                      onChange={(event) => updateAnalysisInput(event.target.value)}
                      placeholder={placeholder}
                    />
                  </Field>
                  <div className="rt-file-upload">
                    <input
                      ref={uploadInputRef}
                      className="rt-visually-hidden"
                      aria-label="Upload message file"
                      type="file"
                      accept=".eml,.txt,text/plain,message/rfc822"
                      onChange={handleFileUpload}
                    />
                    <button type="button" className="rt-file-button" onClick={openFilePicker}>
                      <UiIcon name="upload" />
                      Upload .eml or text file
                    </button>
                    {uploadFilename ? (
                      <span className="rt-file-name" title={uploadFilename}>
                        {uploadFilename}
                      </span>
                    ) : null}
                    <span
                      className="rt-live-status rt-upload-status"
                      role="status"
                      aria-live="polite"
                    >
                      {uploadStatus}
                    </span>
                  </div>
                </>
              )}
              <ActionButton
                icon="mail"
                onClick={() => void runAnalysisTool()}
                disabled={loadingDetail || !canEdit}
                disabledReason={!canEdit ? 'Editor role required to run mail tests.' : undefined}
              >
                {loadingDetail ? 'Analyzing…' : 'Analyze'}
              </ActionButton>
            </div>
          </DetailCard>
        </aside>

        <div className="rt-detail">
          {toolResult ? (
            <DetailCard
              title="Message analysis result"
              meta={
                <span className="rt-card-note">Checked {formatDate(toolResult.checkedAt)}</span>
              }
            >
              {renderResultBody(toolResult)}
            </DetailCard>
          ) : (
            <EmptyState
              title="Run message analysis"
              description="Submit a domain, email address, headers, or raw message to extract DNS, authentication, and reputation evidence."
            />
          )}

          <DetailCard title="Recent checks">{renderHistory(toolHistory)}</DetailCard>
        </div>
      </div>
    );
  }

  function renderServerTool() {
    return (
      <div className="rt-workbench rt-workbench-tools">
        <aside className="rt-sidebar">
          <DetailCard title="Mail Server Test">
            <p className="rt-muted">{toolDefinition.description}</p>
            <div className="rt-toolbar rt-toolbar-stack">
              <Field label="Server target">
                <input
                  name="server-target"
                  autoComplete="off"
                  spellCheck={false}
                  value={serverTarget}
                  onChange={(event) => {
                    setServerTarget(event.target.value);
                    storageSet(canonicalInputKey('mail-server-test'), event.target.value);
                  }}
                  placeholder="example.com or mail.example.com"
                />
              </Field>
              <Field label="Ports to test" hint="Comma-separated ports.">
                <input
                  name="server-ports"
                  autoComplete="off"
                  spellCheck={false}
                  value={serverPorts}
                  onChange={(event) => {
                    setServerPorts(event.target.value);
                    storageSet(canonicalInputKey('mail-server-test', 'ports'), event.target.value);
                  }}
                  placeholder="25,465,587,110,143,993,995"
                />
              </Field>
              <ActionButton
                icon="server"
                onClick={() => void runServerTool()}
                disabled={loadingDetail || !canEdit}
                disabledReason={!canEdit ? 'Editor role required to run mail tests.' : undefined}
              >
                {loadingDetail ? 'Testing…' : 'Run mail server test'}
              </ActionButton>
            </div>
          </DetailCard>
        </aside>

        <div className="rt-detail">
          {toolResult ? (
            <DetailCard
              title="Mail server test result"
              meta={
                <span className="rt-card-note">Checked {formatDate(toolResult.checkedAt)}</span>
              }
            >
              {renderResultBody(toolResult)}
            </DetailCard>
          ) : (
            <EmptyState
              title="Run mail server test"
              description="Tests MX routing, broad mail ports, SMTP banner, EHLO, STARTTLS, and TLS certificate details."
            />
          )}

          <DetailCard title="Recent checks">{renderHistory(toolHistory)}</DetailCard>
        </div>
      </div>
    );
  }

  function renderBlocklistConfigTool() {
    const rblCount = settings?.rblProviders.filter((provider) => provider.enabled).length ?? 0;
    const dblCount = settings?.dblProviders.filter((provider) => provider.enabled).length ?? 0;
    const resolverCount = settings?.resolvers.length ?? 0;

    return (
      <div className="rt-workbench rt-workbench-config">
        {renderProviderSettingsCard('rbl')}
        {renderProviderSettingsCard('dbl')}

        <div className="rt-config-panel">
          <DetailCard title="DNS resolvers">
            <div className="rt-toolbar rt-toolbar-stack">
              <p className="rt-muted" style={{ margin: 0, fontSize: '0.88rem' }}>
                Leave empty to use system default. Public resolvers (1.1.1.1, 8.8.8.8) are blocked
                by Spamhaus.
              </p>
              <Field label="DNS resolvers">
                <textarea
                  name="dns-resolvers"
                  autoComplete="off"
                  spellCheck={false}
                  rows={3}
                  value={resolversText}
                  onChange={(event) => {
                    setResolversText(event.target.value);
                    storageSet(
                      canonicalInputKey('reputation-providers', 'resolvers'),
                      event.target.value
                    );
                  }}
                  disabled={!canAdmin}
                  placeholder="(system default)"
                />
              </Field>
              <ActionButton
                icon="save"
                onClick={() => void saveBlocklistSettings()}
                disabled={loadingDetail || !canAdmin}
                disabledReason={
                  !canAdmin ? 'Admin role required to change resolver settings.' : undefined
                }
              >
                Save settings
              </ActionButton>
            </div>
          </DetailCard>

          <DetailCard title="Status">
            <dl className="rt-provider-list">
              <div className="rt-provider-item">
                <dt>RBL providers</dt>
                <dd className="rt-provider-count">{rblCount} enabled</dd>
              </div>
              <div className="rt-provider-item">
                <dt>DBL providers</dt>
                <dd className="rt-provider-count">{dblCount} enabled</dd>
              </div>
              <div className="rt-provider-item">
                <dt>Resolvers</dt>
                <dd className="rt-provider-count">
                  {resolverCount > 0 ? `${resolverCount} configured` : 'system default'}
                </dd>
              </div>
            </dl>
          </DetailCard>
        </div>
      </div>
    );
  }

  return (
    <section
      className={isHosted ? 'rt-shell rt-shell-hosted' : 'rt-shell'}
      aria-label={moduleDefinition.title}
    >
      {error ? (
        <div className="rt-alert" role="alert">
          {error}
        </div>
      ) : null}

      {loading && !context ? (
        <EmptyState
          title="Loading Robin Tools"
          description="Loading DNS and IP verification context."
        />
      ) : null}

      {context ? (
        <>
          {renderToolNav()}
          <div id="rt-tool-panel" role="tabpanel" aria-labelledby={activePanelLabelId}>
            {isTransformKey(toolKey)
              ? renderTransformTool()
              : toolKey === 'reputation-providers'
                ? renderBlocklistConfigTool()
                : toolKey === 'rbl' || toolKey === 'dbl'
                  ? renderBlocklistTool()
                  : toolKey === 'message-analysis'
                    ? renderAnalysisTool()
                    : toolKey === 'mail-server-test'
                      ? renderServerTool()
                      : toolKey === 'fcrdns'
                        ? renderIpTool()
                        : renderDomainTool()}
          </div>
        </>
      ) : null}
    </section>
  );
}

export default ModulePage;
