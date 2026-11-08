import { api, type CVE } from '../api';
import { h, clear, fmtEpss, fmtScore, reducedMotion } from '../util';
import { state, emit } from '../state';
import { skeleton, errorState, signalChips, cveFacts } from './ui';
import { provenanceTag } from '../charts';
import { explainButton } from './explain';
import { aiPanel } from './ai';

let current: { root: HTMLElement; scrim: HTMLElement; opener: HTMLElement | null; onKey: (e: KeyboardEvent) => void } | null = null;
const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select,textarea,[tabindex]:not([tabindex="-1"])';

export function closeDrawer(): void {
  if (!current) return;
  const { root, scrim, opener, onKey } = current;
  current = null;
  document.removeEventListener('keydown', onKey, true);
  root.classList.remove('open'); scrim.classList.remove('open');
  const done = () => { root.remove(); scrim.remove(); document.documentElement.classList.remove('has-drawer'); };
  if (reducedMotion()) done(); else window.setTimeout(done, 340);
  (opener && document.contains(opener) ? opener : document.querySelector<HTMLElement>('#main'))?.focus({ preventScroll: true });
  state.selection = null;
  emit('selectionchange');
}

export function openCve(id: string): void {
  if (current) { current.root.remove(); current.scrim.remove(); document.removeEventListener('keydown', current.onKey, true); current = null; }
  const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const body = h('div', { class: 'drawer-body' });
  const title = h('h2', { class: 'drawer-title mono', id: 'drawer-title' }, id);
  const closeBtn = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Close CVE details', onClick: closeDrawer }, '✕');
  const root = h('aside', { class: 'drawer', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'drawer-title', 'data-explain': 'panel-cve' },
    h('header', { class: 'drawer-head' }, title, h('div', { class: 'card-tools' }, explainButton('panel-cve', 'CVE detail panel'), closeBtn)),
    body);
  const scrim = h('div', { class: 'scrim', onClick: closeDrawer });
  document.body.append(scrim, root);
  document.documentElement.classList.add('has-drawer');
  state.selection = id; emit('selectionchange');

  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeDrawer(); return; }
    if (e.key !== 'Tab') return;
    const f = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((x) => x.offsetParent !== null);
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (!root.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
    else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  document.addEventListener('keydown', onKey, true);
  current = { root, scrim, opener, onKey };
  requestAnimationFrame(() => { root.classList.add('open'); scrim.classList.add('open'); closeBtn.focus({ preventScroll: true }); });

  const load = async () => {
    clear(body); body.appendChild(skeleton(6, true));
    try {
      const c = await api.cve(id);
      if (current?.root !== root) return;
      clear(body); body.appendChild(renderCve(c));
    } catch (e) {
      clear(body); body.appendChild(errorState(e, () => void load()));
    }
  };
  void load();
}

export function renderCve(c: CVE): HTMLElement {
  return h('div', { class: 'cve-detail' },
    h('div', { class: 'score-row' },
      h('div', { class: 'score-cell' }, h('span', { class: 'label' }, 'Rank'), h('span', { class: 'big num' }, `#${c.rank}`), c.in_top500 ? h('span', { class: 'chip' }, 'Top 500') : h('span', { class: 'muted' }, 'Not in top 500')),
      h('div', { class: 'score-cell' }, h('span', { class: 'label' }, 'Model score'), h('span', { class: 'big num' }, fmtScore(c.prediction_score))),
      h('div', { class: 'score-cell' }, h('span', { class: 'label' }, 'EPSS'), h('span', { class: 'big num' }, fmtEpss(c.epss)))),
    h('div', { class: 'prov-row' }, provenanceTag('model'), h('span', { class: 'muted' }, 'Rank and score are model predictions, not observed KEV status; EPSS is an observed snapshot signal.')),
    h('section', { class: 'sect' },
      h('div', { class: 'sect-head' }, h('h3', { class: 'card-title' }, 'Public exploit signals'), provenanceTag('snapshot')),
      signalChips(c)),
    h('section', { class: 'sect' },
      h('div', { class: 'sect-head' }, h('h3', { class: 'card-title' }, 'Details'), provenanceTag('source')),
      cveFacts(c),
      c.description ? h('p', { class: 'desc' }, c.description) : h('p', { class: 'muted' }, 'No description available in the loaded data.')),
    aiPanel(c.cve_id));
}
