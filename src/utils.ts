// Small, dependency-light helpers shared across the module: DOM/tab id
// generation, module stylesheet injection into the host's Shadow DOM,
// route <-> tool-key/page resolution, and RBAC role comparison. Split out
// of remote.tsx.

import toolsStylesText from './styles.css?inline';
import { PAGE_TABS, TOOL_PAGE_BY_KEY } from './toolDefinitions';
import { normalizeStoredToolKey } from './storage';
import type { AdminRole, ToolKey, ToolPage } from './types';

const TOOLS_STYLE_TAG_ID = 'robin-tools-module-styles';

export function getTabId(group: string, key: string): string {
  return `rt-tab-${group}-${key}`.replace(/[^a-z0-9-]+/gi, '-').toLowerCase();
}

export function ensureModuleStyles(styleRoot?: ShadowRoot | Document) {
  if (typeof document === 'undefined') {
    return;
  }

  const root = styleRoot ?? document;
  let styleTag = root.querySelector?.(
    `style[data-module-style-id="${TOOLS_STYLE_TAG_ID}"]`
  ) as HTMLStyleElement | null;
  if (styleTag) {
    return;
  }

  styleTag = document.createElement('style');
  styleTag.dataset.moduleStyleId = TOOLS_STYLE_TAG_ID;
  styleTag.textContent = toolsStylesText;

  if (root instanceof ShadowRoot) {
    root.appendChild(styleTag);
    return;
  }

  root.head.appendChild(styleTag);
}

export function getToolKey(routePath?: string): ToolKey | null {
  const parts = (routePath ?? '').split('/').filter(Boolean);
  if (parts.length === 0) {
    return null;
  }

  const [first, second] = parts;
  const family =
    first === 'dns' ||
    first === 'email-dns' ||
    first === 'dns-lookup' ||
    first === 'mail-posture' ||
    first === 'reputation' ||
    first === 'mail-tests' ||
    first === 'transforms';
  return normalizeStoredToolKey(family ? second : first);
}

export function getToolPage(routePath: string | undefined, toolKey: ToolKey | null): ToolPage {
  const first = (routePath ?? '').split('/').filter(Boolean)[0];
  if (first === 'dns')
    return toolKey && PAGE_TABS['dns-lookup'].includes(toolKey)
      ? 'dns-lookup'
      : toolKey
        ? TOOL_PAGE_BY_KEY[toolKey]
        : 'dns-lookup';
  if (first === 'email-dns')
    return toolKey && PAGE_TABS['mail-posture'].includes(toolKey)
      ? 'mail-posture'
      : toolKey
        ? TOOL_PAGE_BY_KEY[toolKey]
        : 'mail-posture';
  if (
    first === 'dns-lookup' ||
    first === 'mail-posture' ||
    first === 'reputation' ||
    first === 'mail-tests' ||
    first === 'transforms'
  ) {
    return toolKey && !PAGE_TABS[first].includes(toolKey)
      ? ((Object.entries(PAGE_TABS).find(([, tabs]) => tabs.includes(toolKey))?.[0] as
          ToolPage | undefined) ?? 'dns-lookup')
      : first;
  }
  return toolKey
    ? ((Object.entries(PAGE_TABS).find(([, tabs]) => tabs.includes(toolKey))?.[0] as
        ToolPage | undefined) ?? 'dns-lookup')
    : 'dns-lookup';
}

export function joinModulePath(basePath: string, relativePath?: string): string {
  const normalized = (relativePath ?? '').replace(/^\/+|\/+$/g, '');
  return normalized ? `${basePath}/${normalized}` : basePath;
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return '—';
  return new Date(value).toLocaleString();
}

export function hasRole(role: AdminRole | undefined, required: AdminRole) {
  const hierarchy: Record<AdminRole, number> = {
    viewer: 1,
    editor: 2,
    admin: 3,
  };

  return hierarchy[role ?? 'viewer'] >= hierarchy[required];
}
