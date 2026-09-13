import { useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ModulePage, moduleDefinition } from './remote';
import { UiIcon } from './components';
import type { UiIconName } from './types';

const PAGES: Array<{ path: string; label: string; icon: UiIconName }> = [
  { path: 'dns-lookup', label: 'DNS Lookup', icon: 'search' },
  { path: 'mail-posture', label: 'Mail Posture', icon: 'mail' },
  { path: 'reputation', label: 'Reputation', icon: 'shield' },
  { path: 'mail-tests', label: 'Mail Tests', icon: 'wrench' },
  { path: 'transforms', label: 'Transforms', icon: 'file' },
];

function readHashPath(): string {
  if (typeof window === 'undefined') return moduleDefinition.defaultPath;
  const hash = window.location.hash.replace(/^#\/?/, '');
  return hash || moduleDefinition.defaultPath;
}

function StandaloneApp() {
  const [routePath, setRoutePath] = useState(readHashPath);

  const navigate = useCallback((next: string) => {
    const clean = next.replace(/^\/+/, '');
    if (typeof window !== 'undefined') {
      const target = `#/${clean}`;
      if (window.location.hash !== target) window.history.pushState(null, '', target);
    }
    setRoutePath(clean);
  }, []);

  useEffect(() => {
    const onPop = () => setRoutePath(readHashPath());
    window.addEventListener('hashchange', onPop);
    window.addEventListener('popstate', onPop);
    return () => {
      window.removeEventListener('hashchange', onPop);
      window.removeEventListener('popstate', onPop);
    };
  }, []);

  const currentPage = routePath.split('/').filter(Boolean)[0] ?? 'dns-lookup';

  return (
    <div className="rt-standalone-shell">
      <header className="rt-standalone-header">
        <div className="rt-standalone-brand">
          <UiIcon name="wrench" />
          <span className="rt-standalone-title">{moduleDefinition.title}</span>
        </div>
        <nav className="rt-standalone-nav" aria-label="Robin Tools sections">
          {PAGES.map((page) => {
            const active = currentPage === page.path;
            return (
              <button
                key={page.path}
                type="button"
                className={
                  active
                    ? 'rt-standalone-nav-item rt-standalone-nav-item-active'
                    : 'rt-standalone-nav-item'
                }
                aria-current={active ? 'page' : undefined}
                onClick={() => navigate(page.path)}
              >
                <UiIcon name={page.icon} />
                <span>{page.label}</span>
              </button>
            );
          })}
        </nav>
      </header>
      <main className="rt-standalone-main">
        <ModulePage
          basePath=""
          routePath={routePath}
          navigate={navigate}
          apiBasePath="/api"
          standalone
          currentAdmin={{ role: 'admin' }}
        />
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<StandaloneApp />);
