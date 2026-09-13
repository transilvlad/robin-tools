// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ActionButton, Field, getTabId, ModulePage, PAGE_TABS, UiIcon } from './remote';
import { moduleApiFetch } from './moduleApi';

vi.mock('./moduleApi', () => ({
  moduleApiFetch: vi.fn((_basePath: string, path: string, init?: RequestInit) => {
    if (path === '/context') {
      return Promise.resolve({
        optionalChecks: { mtaSts: true, tlsRpt: true, dane: true, bimi: true },
      });
    }
    if (path === '/settings') {
      return Promise.resolve({
        settings: {
          rblProviders: [],
          dblProviders: [],
          resolvers: [],
          confirmResolvers: [],
          timeoutMs: 5000,
          concurrency: 4,
          serverPorts: [2525, 2465],
        },
      });
    }
    if (path === '/domains/bulk-check') {
      return Promise.resolve({
        results: [
          {
            domain: 'EXAMPLE.com',
            checks: {
              mx: true,
              spf: true,
              dmarc: false,
              dkim: null,
              mtaSts: null,
              tlsRpt: null,
              dane: null,
              bimi: null,
            },
            issues: [],
          },
        ],
      });
    }
    if (path.endsWith('/run')) {
      const request = init?.body
        ? (JSON.parse(String(init.body)) as {
            toolKind?: string;
            targetValue?: string;
            selector?: string;
          })
        : {};
      const toolKind =
        request.toolKind ??
        (path.includes('mail-server-test') ? 'mail-server-test' : 'message-analysis');
      const targetValue = request.targetValue ?? 'example.com';
      const records =
        toolKind === 'mail-server-test'
          ? [
              {
                key: 'port-25',
                label: 'SMTP 25',
                value:
                  'Phase: starttls\nHost: mx.example.com\nPort: 25\nReason: STARTTLS unavailable\nNext step: Enable STARTTLS.',
                ok: false,
                explanation: 'SMTP transport security is unavailable.',
              },
            ]
          : [
              {
                key: 'dns-posture',
                label: 'DNS posture',
                value: 'SPF: ✓\nDMARC: ✗',
                ok: false,
                explanation: 'Authentication coverage.',
              },
              {
                key: 'parsed-input',
                label: 'Parsed evidence',
                value: 'Message-ID: <Raw-ID@EXAMPLE.com>',
                ok: true,
                explanation: 'Values extracted from the message.',
              },
              {
                key: 'raw-record',
                label: 'Raw TXT',
                value: 'v=spf1 include:_spf.EXAMPLE.com ~all',
                ok: true,
                explanation: 'The record exactly as returned.',
              },
            ];
      return Promise.resolve({
        result: {
          toolKind,
          targetType: request.toolKind ? 'domain' : 'raw',
          targetValue,
          selector: request.selector ?? null,
          status: 'pass',
          summary: 'Complete',
          checkedAt: new Date().toISOString(),
          records,
          findings: [],
        },
        historyEntry: {
          id: 1,
          issueId: null,
          subjectValue: null,
          toolKind,
          targetType: 'domain',
          targetValue,
          selector: request.selector ?? null,
          status: 'pass',
          summary: 'Complete',
          result: {
            toolKind,
            targetType: request.toolKind ? 'domain' : 'raw',
            targetValue,
            selector: request.selector ?? null,
            status: 'pass',
            summary: 'Complete',
            checkedAt: new Date().toISOString(),
            records: [
              {
                key: 'raw-record',
                label: 'Raw TXT',
                value: 'v=spf1 include:_spf.EXAMPLE.com ~all',
                ok: true,
                explanation: 'The record exactly as returned.',
              },
            ],
            findings: [],
          },
          createdAt: new Date().toISOString(),
        },
      });
    }
    return Promise.resolve({ items: [] });
  }),
}));

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  vi.clearAllMocks();
});

function historyEntry(overrides: Record<string, unknown> = {}) {
  const toolKind = String(overrides.toolKind ?? 'a');
  const targetValue = String(overrides.targetValue ?? 'saved.example');
  return {
    id: Number(overrides.id ?? 41),
    issueId: null,
    subjectValue: null,
    toolKind,
    targetType: 'domain',
    targetValue,
    selector: null,
    status: 'pass',
    summary: `Saved ${toolKind}`,
    result: {
      toolKind,
      targetType: 'domain',
      targetValue,
      selector: null,
      status: 'pass',
      summary: `Saved ${toolKind}`,
      checkedAt: '2026-09-09T12:00:00.000Z',
      records: [],
      findings: [],
    },
    createdAt: '2026-09-09T12:00:00.000Z',
    ...overrides,
  };
}

describe('Robin Tools inventory and primitives', () => {
  it('keeps the exact 43 stable route keys in the required families', () => {
    expect(
      Object.fromEntries(Object.entries(PAGE_TABS).map(([family, tools]) => [family, tools.length]))
    ).toEqual({
      'dns-lookup': 9,
      'mail-posture': 10,
      reputation: 3,
      'mail-tests': 2,
      transforms: 19,
    });
    expect(Object.values(PAGE_TABS).flat()).toHaveLength(43);
    expect(PAGE_TABS['mail-posture']).toContain('srv');
    expect(Object.values(PAGE_TABS).flat()).not.toContain('tlsa');
  });

  it('associates visible labels and hints with controls', () => {
    render(
      <Field label="Server target" hint="Enter a host name.">
        <input />
      </Field>
    );
    const input = screen.getByLabelText('Server target');
    expect(input.getAttribute('aria-describedby')).toBe(screen.getByText('Enter a host name.').id);
  });

  it('exposes disabled explanations and hides canonical Lucide icons', () => {
    render(
      <ActionButton icon="search" disabled disabledReason="Editor role required.">
        Run check
      </ActionButton>
    );
    const button = screen.getByRole('button', { name: 'Run check' });
    expect(button.getAttribute('aria-describedby')).toBe(
      screen.getByText('Editor role required.').id
    );
    expect(button.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');

    const { container } = render(<UiIcon name="shield" />);
    expect(container.querySelector('svg')?.classList.contains('lucide-shield-check')).toBe(true);
    expect(getTabId('Mail Posture', 'MTA-STS')).toBe('rt-tab-mail-posture-mta-sts');
  });
});

describe('module route and tab navigation', () => {
  it.each([
    { routePath: 'dns-lookup/a', tablist: 'dns-lookup tools', activeTab: 'A', count: 9 },
    {
      routePath: 'mail-posture/srv',
      tablist: 'mail-posture tools',
      activeTab: 'Mail SRV',
      count: 10,
    },
    { routePath: 'reputation/rbl', tablist: 'reputation tools', activeTab: 'RBL', count: 3 },
    {
      routePath: 'mail-tests/message-analysis',
      tablist: 'mail-tests tools',
      activeTab: 'Message Analysis',
      count: 2,
    },
    {
      routePath: 'transforms/base64-encode',
      tablist: 'Transform categories',
      activeTab: 'Base64 & Binary',
      count: 4,
    },
  ])(
    'resolves $routePath with icons on every top tab',
    async ({ routePath, tablist, activeTab, count }) => {
      render(
        <ModulePage routePath={routePath} navigate={vi.fn()} currentAdmin={{ role: 'editor' }} />
      );
      const familyTabs = await screen.findByRole('tablist', { name: tablist });
      const tabs = within(familyTabs).getAllByRole('tab');
      expect(tabs).toHaveLength(count);
      expect(
        within(familyTabs).getByRole('tab', { name: activeTab }).getAttribute('aria-selected')
      ).toBe('true');
      for (const tab of tabs) expect(tab.querySelector('svg[class*="lucide-"]')).toBeTruthy();
    }
  );

  it('navigates by the stable srv key rather than its Mail SRV label', async () => {
    const navigate = vi.fn();
    render(
      <ModulePage
        basePath="/modules/robin-tools"
        routePath="mail-posture/mx"
        navigate={navigate}
        currentAdmin={{ role: 'editor' }}
      />
    );
    fireEvent.click(await screen.findByRole('tab', { name: 'Mail SRV' }));
    expect(navigate).toHaveBeenCalledWith('/modules/robin-tools/mail-posture/srv');
  });

  it('resolves a valid tool key through its owning family even under a mismatched prefix', async () => {
    render(
      <ModulePage routePath="dns-lookup/srv" navigate={vi.fn()} currentAdmin={{ role: 'editor' }} />
    );
    const tabs = await screen.findByRole('tablist', { name: 'mail-posture tools' });
    expect(within(tabs).getByRole('tab', { name: 'Mail SRV' }).getAttribute('aria-selected')).toBe(
      'true'
    );
  });

  it('wraps safely through tabs with the keyboard and links the panel', async () => {
    const navigate = vi.fn();
    render(
      <ModulePage
        basePath="/modules/robin-tools"
        routePath="dns-lookup/a"
        navigate={navigate}
        currentAdmin={{ role: 'editor' }}
      />
    );
    const activeTab = await screen.findByRole('tab', { name: 'A' });
    fireEvent.keyDown(activeTab, { key: 'ArrowLeft' });
    expect(navigate).toHaveBeenCalledWith('/modules/robin-tools/dns-lookup/dnssec');
    expect(screen.getByRole('tabpanel').getAttribute('aria-labelledby')).toBe(
      getTabId('dns-lookup', 'a')
    );
  });
});

describe('clipboard and mail-test behavior', () => {
  it.each([
    { rejected: false, message: 'Result copied to clipboard.' },
    {
      rejected: true,
      message: 'Could not copy the result. Select the result and copy it manually.',
    },
  ])('announces clipboard feedback (rejected: $rejected)', async ({ rejected, message }) => {
    const writeText = rejected
      ? vi.fn().mockRejectedValue(new Error('denied'))
      : vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    render(
      <ModulePage
        routePath="transforms/base64-encode"
        navigate={vi.fn()}
        currentAdmin={{ role: 'editor' }}
      />
    );
    fireEvent.change(await screen.findByLabelText('Base64 Encode input'), {
      target: { value: 'Robin' },
    });
    fireEvent.click(await screen.findByRole('button', { name: 'Copy' }));
    expect(await screen.findByText(message)).toBeTruthy();
  });

  it.each([
    {
      routePath: 'mail-tests/message-analysis',
      field: 'Domain',
      value: 'example.com',
      button: 'Analyze',
      endpoint: '/mail-tests/message-analysis/run',
    },
    {
      routePath: 'mail-tests/mail-server-test',
      field: 'Server target',
      value: 'mail.example.com',
      button: 'Run mail server test',
      endpoint: '/mail-tests/mail-server-test/run',
    },
  ])(
    'uses the current $endpoint endpoint',
    async ({ routePath, field, value, button, endpoint }) => {
      render(
        <ModulePage routePath={routePath} navigate={vi.fn()} currentAdmin={{ role: 'editor' }} />
      );
      fireEvent.change(await screen.findByRole('textbox', { name: field }), { target: { value } });
      fireEvent.click(await screen.findByRole('button', { name: button }));
      await waitFor(() =>
        expect(moduleApiFetch).toHaveBeenCalledWith(
          '/api/modules/robin-tools',
          endpoint,
          expect.objectContaining({ method: 'POST' }),
          { csrf: true }
        )
      );
    }
  );
});

describe('compact inspector results', () => {
  it('uses shared inspector rows for statuses, evidence, raw values, and history', async () => {
    render(
      <ModulePage routePath="dns-lookup/a" navigate={vi.fn()} currentAdmin={{ role: 'editor' }} />
    );
    fireEvent.change(await screen.findByLabelText('Domain'), { target: { value: 'EXAMPLE.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run A check' }));

    expect((await screen.findByText('DNS posture')).classList.contains('rt-record-title')).toBe(
      true
    );
    expect(screen.getByText('SPF').classList.contains('rt-status-label')).toBe(true);
    expect(screen.getByText('Message-ID').classList.contains('rt-evidence-label')).toBe(true);
    expect(screen.getByText('<Raw-ID@EXAMPLE.com>').classList.contains('rt-evidence-value')).toBe(
      true
    );
    expect(
      screen
        .getAllByText('v=spf1 include:_spf.EXAMPLE.com ~all')
        .every((node) => node.textContent === 'v=spf1 include:_spf.EXAMPLE.com ~all')
    ).toBe(true);
    expect(
      screen
        .getAllByText('Complete')
        .some((node) => node.closest('details')?.classList.contains('rt-history-item'))
    ).toBe(true);
  });

  it('keeps bulk data in a responsive semantic table without changing raw tokens', async () => {
    render(
      <ModulePage
        routePath="mail-posture/mx"
        navigate={vi.fn()}
        currentAdmin={{ role: 'editor' }}
      />
    );
    fireEvent.change(await screen.findByLabelText('Domains'), { target: { value: 'EXAMPLE.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run bulk MX' }));

    const table = await screen.findByRole('table');
    expect(table.closest('.rt-table-scroll')).toBeTruthy();
    expect(within(table).getByRole('columnheader', { name: 'Domain' })).toBeTruthy();
    expect(within(table).getByRole('rowheader', { name: 'EXAMPLE.com' })).toBeTruthy();
  });
});

describe('tool-key persistence and migration', () => {
  it('restores inputs after remount and isolates values between DNS tools', async () => {
    const first = render(
      <ModulePage routePath="dns-lookup/a" navigate={vi.fn()} currentAdmin={{ role: 'editor' }} />
    );
    fireEvent.change(await screen.findByLabelText('Domain'), { target: { value: 'a.example' } });
    first.rerender(
      <ModulePage
        routePath="dns-lookup/cname"
        navigate={vi.fn()}
        currentAdmin={{ role: 'editor' }}
      />
    );
    await waitFor(() =>
      expect((screen.getByLabelText('Domain') as HTMLInputElement).value).toBe('')
    );
    fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'cname.example' } });
    first.unmount();

    const second = render(
      <ModulePage routePath="dns-lookup/a" navigate={vi.fn()} currentAdmin={{ role: 'editor' }} />
    );
    await waitFor(() =>
      expect((screen.getByLabelText('Domain') as HTMLInputElement).value).toBe('a.example')
    );
    second.rerender(
      <ModulePage
        routePath="dns-lookup/cname"
        navigate={vi.fn()}
        currentAdmin={{ role: 'editor' }}
      />
    );
    await waitFor(() =>
      expect((screen.getByLabelText('Domain') as HTMLInputElement).value).toBe('cname.example')
    );
  });

  it('keeps local history isolated across DNS Lookup and Mail Posture tool keys', async () => {
    window.localStorage.setItem('robin-tools:tool:a:input', 'a.example');
    window.localStorage.setItem(
      'robin-tools:tool:a:history',
      JSON.stringify([
        historyEntry({ id: 51, toolKind: 'a', summary: 'A-only result', targetValue: 'a.example' }),
      ])
    );
    window.localStorage.setItem('robin-tools:tool:mx:input', 'mx.example');
    window.localStorage.setItem(
      'robin-tools:tool:mx:history',
      JSON.stringify([
        historyEntry({
          id: 52,
          toolKind: 'mx',
          summary: 'MX-only result',
          targetValue: 'mx.example',
        }),
      ])
    );

    const rendered = render(
      <ModulePage routePath="dns-lookup/a" navigate={vi.fn()} currentAdmin={{ role: 'editor' }} />
    );
    expect((await screen.findAllByText('A-only result')).length).toBeGreaterThan(0);
    expect(screen.queryByText('MX-only result')).toBeNull();
    rendered.rerender(
      <ModulePage
        routePath="mail-posture/mx"
        navigate={vi.fn()}
        currentAdmin={{ role: 'editor' }}
      />
    );
    expect((await screen.findAllByText('MX-only result')).length).toBeGreaterThan(0);
    expect(screen.queryByText('A-only result')).toBeNull();
  });

  it('migrates old family, route, tool ID, input, and history keys without deleting the source', async () => {
    const legacyHistoryKey = 'robin-tools-history-email-dns';
    window.localStorage.setItem('robin-tools-email-dns-spf-record-input', 'legacy.example');
    window.localStorage.setItem(
      legacyHistoryKey,
      JSON.stringify({
        'spf-record': [historyEntry({ toolKind: 'spf-record', targetValue: 'legacy.example' })],
        'mx-record': 'malformed sibling',
      })
    );

    render(
      <ModulePage
        routePath="email-dns/spf-record"
        navigate={vi.fn()}
        currentAdmin={{ role: 'editor' }}
      />
    );
    await waitFor(() =>
      expect((screen.getByLabelText('Domain') as HTMLInputElement).value).toBe('legacy.example')
    );
    expect((await screen.findAllByText('Saved spf-record')).length).toBeGreaterThan(0);
    expect(window.localStorage.getItem('robin-tools:tool:spf:input')).toBe('legacy.example');
    expect(window.localStorage.getItem('robin-tools:tool:spf:history')).toContain(
      '"toolKind":"spf"'
    );
    expect(window.localStorage.getItem(legacyHistoryKey)).toContain('malformed sibling');
  });

  it('uses canonical tool IDs rather than renamed display labels and restores the family tab', async () => {
    window.localStorage.setItem('robin-tools-last-tab-email-dns', 'mail-srv');
    const navigate = vi.fn();
    render(
      <ModulePage routePath="mail-posture" navigate={navigate} currentAdmin={{ role: 'editor' }} />
    );
    const tab = await screen.findByRole('tab', { name: 'Mail SRV' });
    expect(tab.getAttribute('aria-selected')).toBe('true');
    expect(navigate).toHaveBeenCalledWith('/modules/robin-tools/mail-posture/srv');

    fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'srv.example' } });
    expect(window.localStorage.getItem('robin-tools:tool:srv:input')).toBe('srv.example');
    expect(
      [...Array(window.localStorage.length)].map((_, index) => window.localStorage.key(index))
    ).not.toContain('robin-tools:tool:Mail SRV:input');
  });

  it('persists added history, restores it on remount, and clears only after success', async () => {
    const first = render(
      <ModulePage
        routePath="mail-posture/mx"
        navigate={vi.fn()}
        currentAdmin={{ role: 'editor' }}
      />
    );
    fireEvent.change(await screen.findByLabelText('Domain'), {
      target: { value: 'persist.example' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Run MX check' }));
    await screen.findAllByText('Complete');
    expect(window.localStorage.getItem('robin-tools:tool:mx:history')).toContain('persist.example');
    first.unmount();

    render(
      <ModulePage
        routePath="mail-posture/mx"
        navigate={vi.fn()}
        currentAdmin={{ role: 'editor' }}
      />
    );
    expect((await screen.findAllByText('Complete')).length).toBeGreaterThan(0);
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
    await waitFor(() =>
      expect(window.localStorage.getItem('robin-tools:tool:mx:history')).toBe('[]')
    );
    expect(screen.queryByText('Complete')).toBeNull();
  });

  it('ignores a malformed tool entry while preserving valid unrelated legacy history', async () => {
    const key = 'robin-tools-history-email-dns';
    const mx = historyEntry({ id: 88, toolKind: 'mx-record', targetValue: 'mail.example' });
    window.localStorage.setItem(
      key,
      JSON.stringify({ 'mx-record': [mx], 'spf-record': { broken: true } })
    );
    render(
      <ModulePage
        routePath="mail-posture/mx"
        navigate={vi.fn()}
        currentAdmin={{ role: 'editor' }}
      />
    );
    expect((await screen.findAllByText('Saved mx-record')).length).toBeGreaterThan(0);
    expect(window.localStorage.getItem(key)).toContain('"broken":true');
  });
});

describe('message file upload', () => {
  class MockFileReader {
    static instances: MockFileReader[] = [];
    readyState = 0;
    result: string | ArrayBuffer | null = null;
    onloadstart: ((event: ProgressEvent<FileReader>) => void) | null = null;
    onload: ((event: ProgressEvent<FileReader>) => void) | null = null;
    onerror: ((event: ProgressEvent<FileReader>) => void) | null = null;
    onabort: ((event: ProgressEvent<FileReader>) => void) | null = null;
    onloadend: ((event: ProgressEvent<FileReader>) => void) | null = null;
    abort = vi.fn(() => {
      this.readyState = 2;
    });

    constructor() {
      MockFileReader.instances.push(this);
    }

    readAsText() {
      this.readyState = 1;
      this.onloadstart?.({} as ProgressEvent<FileReader>);
    }

    finish(kind: 'load' | 'error' | 'abort', result = '') {
      this.result = result;
      this.readyState = 2;
      this[`on${kind}`]?.({} as ProgressEvent<FileReader>);
      this.onloadend?.({} as ProgressEvent<FileReader>);
    }
  }

  async function renderUploader() {
    vi.stubGlobal('FileReader', MockFileReader);
    MockFileReader.instances = [];
    const rendered = render(
      <ModulePage
        routePath="mail-tests/message-analysis"
        navigate={vi.fn()}
        currentAdmin={{ role: 'editor' }}
      />
    );
    fireEvent.click(await screen.findByRole('radio', { name: 'Headers' }));
    return rendered;
  }

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  describe('safe input persistence', () => {
    it.each([
      {
        route: 'reputation/rbl',
        label: 'RBL targets',
        value: '203.0.113.9',
        key: 'robin-tools:tool:rbl:input',
      },
      {
        route: 'reputation/dbl',
        label: 'DBL targets',
        value: 'sender.example',
        key: 'robin-tools:tool:dbl:input',
      },
      {
        route: 'mail-tests/mail-server-test',
        label: 'Server target',
        value: 'mx.example',
        key: 'robin-tools:tool:mail-server-test:input',
      },
    ])('restores $label by canonical tool key', async ({ route, label, value, key }) => {
      const first = render(
        <ModulePage routePath={route} navigate={vi.fn()} currentAdmin={{ role: 'editor' }} />
      );
      fireEvent.change(await screen.findByLabelText(label), { target: { value } });
      expect(window.localStorage.getItem(key)).toBe(value);
      first.unmount();
      render(<ModulePage routePath={route} navigate={vi.fn()} currentAdmin={{ role: 'editor' }} />);
      await waitFor(() =>
        expect((screen.getByLabelText(label) as HTMLInputElement | HTMLTextAreaElement).value).toBe(
          value
        )
      );
    });

    it('persists small analysis inputs independently by mode', async () => {
      const first = render(
        <ModulePage
          routePath="mail-tests/message-analysis"
          navigate={vi.fn()}
          currentAdmin={{ role: 'editor' }}
        />
      );
      fireEvent.change(await screen.findByRole('textbox', { name: 'Domain' }), {
        target: { value: 'domain.example' },
      });
      fireEvent.click(screen.getByRole('radio', { name: 'Email address' }));
      fireEvent.change(screen.getByRole('textbox', { name: 'Email address' }), {
        target: { value: 'user@example.com' },
      });
      fireEvent.click(screen.getByRole('radio', { name: 'Domain' }));
      expect((screen.getByRole('textbox', { name: 'Domain' }) as HTMLInputElement).value).toBe(
        'domain.example'
      );
      first.unmount();

      render(
        <ModulePage
          routePath="mail-tests/message-analysis"
          navigate={vi.fn()}
          currentAdmin={{ role: 'editor' }}
        />
      );
      expect(
        ((await screen.findByRole('radio', { name: 'Domain' })) as HTMLInputElement).checked
      ).toBe(true);
      expect((screen.getByRole('textbox', { name: 'Domain' }) as HTMLInputElement).value).toBe(
        'domain.example'
      );
    });

    it('restores provider and resolver configuration drafts', async () => {
      const first = render(
        <ModulePage
          routePath="reputation/reputation-providers"
          navigate={vi.fn()}
          currentAdmin={{ role: 'admin' }}
        />
      );
      fireEvent.change(await screen.findByLabelText('RBL providers'), {
        target: { value: 'rbl.example' },
      });
      fireEvent.change(screen.getByLabelText('DNS resolvers'), { target: { value: '9.9.9.9' } });
      first.unmount();

      render(
        <ModulePage
          routePath="reputation/reputation-providers"
          navigate={vi.fn()}
          currentAdmin={{ role: 'admin' }}
        />
      );
      await waitFor(() =>
        expect((screen.getByLabelText('RBL providers') as HTMLTextAreaElement).value).toBe(
          'rbl.example'
        )
      );
      expect((screen.getByLabelText('DNS resolvers') as HTMLTextAreaElement).value).toBe('9.9.9.9');
    });

    it('restores transform inputs by stable operation key without leaking between formats', async () => {
      const first = render(
        <ModulePage
          routePath="transforms/base64-encode"
          navigate={vi.fn()}
          currentAdmin={{ role: 'editor' }}
        />
      );
      fireEvent.change(await screen.findByLabelText('Base64 Encode input'), {
        target: { value: 'Robin' },
      });
      first.rerender(
        <ModulePage
          routePath="transforms/url-encode"
          navigate={vi.fn()}
          currentAdmin={{ role: 'editor' }}
        />
      );
      await waitFor(() =>
        expect((screen.getByLabelText('URL Encode input') as HTMLTextAreaElement).value).toBe('')
      );
      fireEvent.change(screen.getByLabelText('URL Encode input'), { target: { value: 'a b' } });
      first.unmount();

      const second = render(
        <ModulePage
          routePath="transforms/base64-encode"
          navigate={vi.fn()}
          currentAdmin={{ role: 'editor' }}
        />
      );
      await waitFor(() =>
        expect((screen.getByLabelText('Base64 Encode input') as HTMLTextAreaElement).value).toBe(
          'Robin'
        )
      );
      second.rerender(
        <ModulePage
          routePath="transforms/url-encode"
          navigate={vi.fn()}
          currentAdmin={{ role: 'editor' }}
        />
      );
      await waitFor(() =>
        expect((screen.getByLabelText('URL Encode input') as HTMLTextAreaElement).value).toBe('a b')
      );
    });

    it('uses configured mail-server ports unless a canonical draft overrides them', async () => {
      const first = render(
        <ModulePage
          routePath="mail-tests/mail-server-test"
          navigate={vi.fn()}
          currentAdmin={{ role: 'editor' }}
        />
      );
      await waitFor(() =>
        expect((screen.getByLabelText('Ports to test') as HTMLInputElement).value).toBe('2525,2465')
      );
      first.unmount();

      window.localStorage.setItem('robin-tools:tool:mail-server-test:ports', '25,587');
      render(
        <ModulePage
          routePath="mail-tests/mail-server-test"
          navigate={vi.fn()}
          currentAdmin={{ role: 'editor' }}
        />
      );
      await waitFor(() =>
        expect((screen.getByLabelText('Ports to test') as HTMLInputElement).value).toBe('25,587')
      );
    });
  });

  it('uses a native radio group, persists its mode, and never stores header or raw content', async () => {
    window.localStorage.setItem('robin-tools-message-analysis-input', 'legacy raw message content');
    const first = await renderUploader();
    const radios = screen.getAllByRole('radio');
    expect(radios).toHaveLength(4);
    expect((screen.getByRole('radio', { name: 'Headers' }) as HTMLInputElement).checked).toBe(true);
    fireEvent.change(screen.getByLabelText('Message headers'), {
      target: { value: 'Authorization: secret' },
    });
    expect(window.localStorage.getItem('robin-tools:tool:message-analysis:headers')).toBeNull();
    expect(window.localStorage.getItem('robin-tools:tool:message-analysis:input')).toBeNull();
    fireEvent.click(screen.getByRole('radio', { name: 'Raw email' }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Raw email' }), {
      target: { value: 'raw secret' },
    });
    expect(window.localStorage.getItem('robin-tools:tool:message-analysis:raw')).toBeNull();
    expect(window.localStorage.getItem('robin-tools:tool:message-analysis:mode')).toBe('raw');
    first.unmount();

    render(
      <ModulePage
        routePath="mail-tests/message-analysis"
        navigate={vi.fn()}
        currentAdmin={{ role: 'editor' }}
      />
    );
    expect(
      ((await screen.findByRole('radio', { name: 'Raw email' })) as HTMLInputElement).checked
    ).toBe(true);
    expect((screen.getByRole('textbox', { name: 'Raw email' }) as HTMLTextAreaElement).value).toBe(
      ''
    );
  });

  it('opens the hidden input exactly once for one button click', async () => {
    await renderUploader();
    const input = screen.getByLabelText('Upload message file') as HTMLInputElement;
    const click = vi.spyOn(HTMLInputElement.prototype, 'click');
    fireEvent.click(screen.getByRole('button', { name: 'Upload .eml or text file' }));
    expect(click).toHaveBeenCalledTimes(1);
    expect(input.type).toBe('file');
  });

  it('loads content and reports the filename with transient status', async () => {
    await renderUploader();
    vi.useFakeTimers();
    const input = screen.getByLabelText('Upload message file') as HTMLInputElement;
    const file = new File(['From: sender@example.com'], 'message.eml', { type: 'message/rfc822' });
    fireEvent.change(input, { target: { files: [file] } });
    act(() => MockFileReader.instances[0].finish('load', 'From: sender@example.com'));

    expect(screen.getByText('message.eml')).toBeTruthy();
    expect(screen.getByRole('status').textContent).toBe('Loaded message.eml.');
    expect((screen.getByRole('textbox', { name: 'Raw email' }) as HTMLTextAreaElement).value).toBe(
      'From: sender@example.com'
    );
    act(() => vi.advanceTimersByTime(4000));
    expect(screen.getByRole('status').textContent).toBe('');
  });

  it.each([
    { kind: 'error' as const, message: 'Could not read broken.eml.' },
    { kind: 'abort' as const, message: 'Reading broken.eml was canceled.' },
  ])('reports a reader $kind and clears the input after completion', async ({ kind, message }) => {
    await renderUploader();
    const input = screen.getByLabelText('Upload message file') as HTMLInputElement;
    const file = new File(['broken'], 'broken.eml');
    fireEvent.change(input, { target: { files: [file] } });
    act(() => MockFileReader.instances[0].finish(kind));
    expect(screen.getByRole('status').textContent).toBe(message);
    expect(input.value).toBe('');
    expect(screen.getByText('broken.eml')).toBeTruthy();
  });

  it('supports selecting the same file again after each read completes', async () => {
    await renderUploader();
    const input = screen.getByLabelText('Upload message file') as HTMLInputElement;
    const file = new File(['headers'], 'same.eml');
    fireEvent.change(input, { target: { files: [file] } });
    act(() => MockFileReader.instances[0].finish('load', 'headers'));
    fireEvent.change(input, { target: { files: [file] } });
    act(() => MockFileReader.instances[1].finish('load', 'headers again'));
    expect(MockFileReader.instances).toHaveLength(2);
    expect((screen.getByLabelText('Message headers') as HTMLTextAreaElement).value).toBe(
      'headers again'
    );
  });

  it('aborts an in-progress reader when the module unmounts', async () => {
    const { unmount } = await renderUploader();
    const input = screen.getByLabelText('Upload message file');
    fireEvent.change(input, { target: { files: [new File(['pending'], 'pending.eml')] } });
    const reader = MockFileReader.instances[0];
    unmount();
    expect(reader.abort).toHaveBeenCalledTimes(1);
  });

  it('aborts an in-progress reader before switching to a small persisted input mode', async () => {
    await renderUploader();
    fireEvent.change(screen.getByLabelText('Upload message file'), {
      target: { files: [new File(['pending'], 'pending.eml')] },
    });
    const reader = MockFileReader.instances[0];
    fireEvent.click(screen.getByRole('radio', { name: 'Domain' }));
    expect(reader.abort).toHaveBeenCalledTimes(1);
    expect((screen.getByRole('textbox', { name: 'Domain' }) as HTMLInputElement).value).toBe('');
  });
});
