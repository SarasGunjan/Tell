import { api, type Status } from '../api';
import { h, clear, store, fmtInt, nextId } from '../util';
import { app, bus, emit } from '../state';
import { PAGES } from '../router';
import { rethemeCharts } from '../charts';

const fmtWhen = (iso: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '–');
const TOP500_SRC = { file: 'top500.csv (Member 1)', derived: 'derived from predictions, rank ≤ 500 (top500.csv not delivered)' } as const;

function popoverBody(s: Status | null, err: boolean): HTMLElement[] {
  if (!s) return [h('p', { class: 'muted' }, err ? 'Cannot reach the API. Is the backend running on :8000? Click the status pill again to retry.' : 'Checking API…')];
  return [
    h('div', { class: 'pop-head' }, h('b', {}, 'Results data'),
      h('span', { class: `chip ${s.data_label === 'demo' ? 'chip-warn' : ''}` }, s.data_label === 'demo' ? 'Demo data' : 'Final')),
    h('p', { class: 'muted pop-sub' }, 'Folder ', h('span', { class: 'mono' }, s.results_dir + '/'), ' · checked on every request'),
    h('ul', { class: 'pop-files' }, s.files.map((f) => {
      const bad = f.present && f.missing_required.length > 0;
      return h('li', { class: 'pop-file' },
        h('span', { class: `pop-mark ${f.present && !bad ? 'ok' : bad ? 'bad' : ''}`, 'aria-hidden': 'true' }, f.present && !bad ? '✓' : '✗'),
        h('div', {},
          h('div', { class: 'pop-file-top' }, h('span', { class: 'mono' }, f.name), h('span', { class: 'muted' }, f.owner)),
          h('div', { class: 'muted pop-file-meta' },
            h('span', { class: 'sr-only' }, f.present ? (bad ? 'present but unusable. ' : 'present. ') : 'missing. '),
            f.present ? `${fmtInt(f.rows)} rows · updated ${fmtWhen(f.modified)}` : f.optional ? 'not delivered (optional)' : 'not delivered yet'),
          bad ? h('div', { class: 'pop-missing' }, 'Missing required columns: ', f.missing_required.join(', ')) : null));
    })),
    h('p', { class: 'muted pop-sub' }, 'Top 500 source: ', s.top500_source ? TOP500_SRC[s.top500_source] : 'not computed yet'),
    h('p', { class: 'muted pop-sub' }, `Gemini: ${s.gemini ? 'live' : 'offline'} (${s.model}) · Snowflake Cortex: ${s.snowflake ? 'live' : 'offline'} · Descriptions: ${s.descriptions ? 'loaded' : 'not loaded'}`),
  ];
}

const sigOf = (s: Status) => Object.fromEntries(s.files.map((f) => [f.name, `${f.modified}|${f.rows}`]));
let toastEl: HTMLElement | null = null;
function showToast(owners: string[]): void {
  toastEl?.remove();
  const t = h('div', { class: 'toast', role: 'status' },
    h('span', {}, `New results from ${owners.join(' & ')}. Refresh to load them.`),
    h('button', { type: 'button', class: 'btn', onClick: () => location.reload() }, 'Refresh'),
    h('button', { type: 'button', class: 'btn btn-ghost', 'aria-label': 'Dismiss notification', onClick: () => { t.remove(); toastEl = null; } }, 'Dismiss'));
  toastEl = t;
  document.body.appendChild(t);
}

let lastSig: Record<string, string> | null = null;
export async function refreshStatus(): Promise<Status | null> {
  try {
    const s = await api.status();
    app.status = s;
    const sig = sigOf(s);
    if (lastSig) {
      const changed = s.files.filter((f) => lastSig![f.name] !== sig[f.name]);
      if (changed.length) showToast([...new Set(changed.map((f) => f.owner))]);
    }
    lastSig = sig;
    emit('statuschange');
    return s;
  } catch {
    emit('statuschange');
    return null;
  }
}

function statusPill(): HTMLElement {
  const popId = nextId('status-pop');
  const pill = h('button', { type: 'button', class: 'status-pill', 'aria-live': 'polite', 'aria-expanded': 'false', 'aria-controls': popId, 'aria-haspopup': 'true' }, 'Checking API…');
  const pop = h('div', { class: 'status-pop', id: popId, role: 'region', 'aria-label': 'Data and service status', hidden: true });
  const wrap = h('div', { class: 'status-wrap' }, pill, pop);
  let failed = false;
  const paint = () => {
    const s = app.status;
    clear(pill);
    pill.removeAttribute('data-state');
    if (!s) {
      pill.dataset.state = 'down';
      pill.append(h('i', { 'aria-hidden': 'true' }), failed ? 'API unreachable' : 'Checking API…');
    } else {
      pill.dataset.state = s.gemini ? 'live' : 'offline';
      pill.append(h('i', { 'aria-hidden': 'true' }), s.gemini ? 'Gemini live' : 'Offline mode');
      const detail = `Gemini: ${s.gemini ? 'live' : 'offline'} (${s.model}). Snowflake Cortex: ${s.snowflake ? 'live' : 'offline'}. Descriptions: ${s.descriptions ? 'loaded' : 'not loaded'}. ${s.data_label === 'demo' ? 'Demo data.' : 'Final data.'} Open for details.`;
      pill.setAttribute('title', detail);
      pill.setAttribute('aria-label', detail);
      pill.append(h('span', { class: 'status-sub' }, s.snowflake ? 'Cortex live' : 'Cortex off'));
    }
    clear(pop);
    pop.append(...popoverBody(s, failed));
  };
  const setOpen = (open: boolean) => {
    pop.hidden = !open;
    pill.setAttribute('aria-expanded', String(open));
  };
  pill.addEventListener('click', () => {
    const open = !!pop.hidden;
    setOpen(open);
    if (open) void refreshStatus().then((s) => { failed = !s; paint(); });
  });
  wrap.addEventListener('keydown', (e) => { if ((e as KeyboardEvent).key === 'Escape' && !pop.hidden) { setOpen(false); pill.focus(); } });
  document.addEventListener('click', (e) => { if (!pop.hidden && !wrap.contains(e.target as Node)) setOpen(false); });
  bus.addEventListener('statuschange', paint);
  paint();
  return wrap;
}

function demoBanner(): HTMLElement {
  let dismissed = false; // per page load: comes back on reload by design
  const el = h('div', { class: 'demo-banner', role: 'status', hidden: true },
    h('span', {}, h('b', {}, 'Demo data'), ' — not final results from Members 1 & 2. Numbers will change when their files land.'),
    h('button', { type: 'button', class: 'demo-dismiss', 'aria-label': 'Dismiss demo data notice', onClick: () => { dismissed = true; el.hidden = true; } }, '×'));
  bus.addEventListener('statuschange', () => { el.hidden = dismissed || app.status?.data_label !== 'demo'; });
  return el;
}

function themeToggle(): HTMLElement {
  const root = document.documentElement;
  const btn = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Toggle color theme' });
  const paint = () => {
    const dark = root.dataset.theme !== 'light';
    btn.textContent = dark ? '☾' : '☀';
    btn.setAttribute('aria-pressed', String(!dark));
    btn.setAttribute('title', dark ? 'Switch to light theme' : 'Switch to dark theme');
  };
  btn.addEventListener('click', () => {
    root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light';
    store.set('tr.theme', root.dataset.theme);
    paint();
    rethemeCharts();
  });
  paint();
  return btn;
}

export function buildShell(root: HTMLElement): HTMLElement {
  const nav = h('nav', { class: 'nav-links', 'aria-label': 'Primary' },
    PAGES.map((p) => h('a', { href: `#/${p.id}`, 'data-nav': p.id }, p.label)));
  const header = h('header', { class: 'topbar' },
    h('div', { class: 'topbar-in' },
      h('a', { class: 'brand', href: '#/overview', 'aria-label': 'Tell home', title: 'Every attack has a tell.' },
        h('span', { class: 'brand-mark', 'aria-hidden': 'true' }), h('span', { class: 'brand-name' }, 'Tell')),
      nav,
      h('div', { class: 'topbar-tools' }, statusPill(), themeToggle())));
  const main = h('main', { id: 'main', tabindex: '-1', class: 'page' });
  const credit = h('footer', { class: 'site-credit' },
    h('p', {}, 'Built for the IBM Before the Breach track · Sheridan Datathon 2026'),
    h('p', {}, 'Guide sprite: Crafternauta by Railly / Crafter Station via ',
    h('a', { href: 'https://petdex.dev/pets/cosmo', target: '_blank', rel: 'noopener noreferrer' }, 'petdex.dev'), ' (MIT)'));
  root.append(header, demoBanner(), main, credit);
  void refreshStatus();
  window.setInterval(() => { if (!document.hidden) void refreshStatus(); }, 30000);
  return main;
}
