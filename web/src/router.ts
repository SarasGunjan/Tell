import type { PageId } from './api';
import { state, emit } from './state';
import { destroyAllCharts } from './charts';
import { clear, reducedMotion } from './util';
import { mountDashboard } from './pages/dashboard';
import { mountOverview } from './pages/overview';
import { mountTop500 } from './pages/top500';
import { mountFamilies } from './pages/families';
import { mountResearch } from './pages/research';
import { mountModels } from './pages/models';
import { mountAnalyst } from './pages/analyst';

type Mount = (root: HTMLElement) => void | (() => void);
export const PAGES: { id: PageId; label: string; title: string; mount: Mount }[] = [
  { id: 'dashboard', label: 'Dashboard', title: 'Dashboard', mount: mountDashboard },
  { id: 'overview', label: 'Overview', title: 'Overview', mount: mountOverview },
  { id: 'top500', label: 'Top 500', title: 'Top 500', mount: mountTop500 },
  { id: 'families', label: 'Families', title: 'Families', mount: mountFamilies },
  { id: 'research', label: 'Research', title: 'Research Discoveries', mount: mountResearch },
  { id: 'models', label: 'Model Evaluation', title: 'Model Evaluation', mount: mountModels },
  { id: 'analyst', label: 'AI Analyst', title: 'AI Analyst', mount: mountAnalyst },
];
const ids = new Set<string>(PAGES.map((p) => p.id));

let main: HTMLElement;
let cleanup: (() => void) | null = null;
let current: PageId | null = null;

export function navigate(page: PageId): void {
  if (pathOf() === page) { if (current !== page) void show(page); return; }
  location.hash = `#/${page}`;
}
const pathOf = (): string => /^#\/([a-z0-9]+)/.exec(location.hash)?.[1] ?? '';
const fromHash = (): PageId => {
  const p = pathOf();
  return ids.has(p) ? (p as PageId) : 'dashboard';
};

async function show(page: PageId): Promise<void> {
  const def = PAGES.find((p) => p.id === page)!;
  const swap = () => {
    cleanup?.(); cleanup = null;
    destroyAllCharts();
    clear(main);
    current = page; state.page = page;
    cleanup = def.mount(main) ?? null;
    document.title = `${def.title} · Tell`;
    document.querySelectorAll<HTMLAnchorElement>('[data-nav]').forEach((a) => {
      if (a.dataset.nav === page) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    window.scrollTo(0, 0);
    main.focus({ preventScroll: true });
    emit('pagerendered', page);
  };
  const vt = (document as Document & { startViewTransition?: (cb: () => void) => { finished: Promise<void> } }).startViewTransition;
  if (current && vt && !reducedMotion()) {
    try { vt.call(document, swap); return; } catch { /* fall through */ }
  }
  swap();
  if (!reducedMotion()) main.animate([{ opacity: 0, transform: 'translateY(8px)' }, { opacity: 1, transform: 'none' }], { duration: 240, easing: 'cubic-bezier(0.23,1,0.32,1)' });
}

export function startRouter(mainEl: HTMLElement): void {
  main = mainEl;
  window.addEventListener('hashchange', () => void show(fromHash()));
  void show(fromHash());
}
