import '../../styles/dashboard.css';
import { api, type Galaxy, type BudgetPoint } from '../../api';
import { h, fmtInt, stagger } from '../../util';
import { bus } from '../../state';
import { provenanceTag } from '../../charts';
import { explainButton } from '../../components/explain';
import { openCve } from '../../components/drawer';
import { loadInto, skeleton, waitingState } from '../../components/ui';
import { pageHead } from '../shared';
import { prepare } from './data';
import { createStore } from './state';
import { createGalaxy } from './galaxy';
import { createCoach } from './coach';
import { judgeStrip } from './judge';
import { ENCODINGS, type Layout } from './encodings';
import { filtersRail, selectionPanel, scatterCard, budgetCard, familyFocusCard } from './panels';

function galaxyColors(): string[] {
  const cs = getComputedStyle(document.documentElement);
  return [...Array.from({ length: 10 }, (_, i) => cs.getPropertyValue(`--galaxy-${i + 1}`).trim() || '#a2a9b0'), cs.getPropertyValue('--galaxy-unknown').trim() || '#6f6f6f'];
}

export function mountDashboard(root: HTMLElement): () => void {
  const cleanups: (() => void)[] = [];
  root.appendChild(pageHead('Galaxy', 'Every CVE on the 2026 scoreboard as a star, grouped into IBM Granite families. Filter, pick a family, and watch every panel follow.'));
  const host = h('div', { class: 'page-host' });
  root.appendChild(host);

  const render = ([g, pts]: [Galaxy, BudgetPoint[]]): Node => {
    if (!g.available) return waitingState('predictions', 'Threat Galaxy not computed yet');
    const d = prepare(g);
    const store = createStore(d);
    const colors = galaxyColors();
    const view = createGalaxy(d, store, colors);
    cleanups.push(view.destroy);

    // linked hover from chat CVE cards (and any other component)
    const onCve = ((e: CustomEvent<string | null>) => store.set({ hoverId: e.detail && d.idx.has(e.detail) ? e.detail : null })) as EventListener;
    bus.addEventListener('cve:hover', onCve);
    cleanups.push(() => bus.removeEventListener('cve:hover', onCve));

    // layout toggle (Semantic map only when the API supplied x,y)
    const layouts: Layout[] = ['spiral', ...(d.hasFamilies ? (['split'] as Layout[]) : []), 'rows', ...(d.pos.embedding ? (['embedding'] as Layout[]) : [])];
    const segs = layouts.map((l) => h('button', { type: 'button', class: 'seg', onClick: () => store.set({ view: l }) }, ENCODINGS.layouts[l].label));
    const provNote = h('span', { class: 'chip', hidden: true });
    const paintView = () => {
      segs.forEach((b, i) => b.setAttribute('aria-pressed', String(store.state.view === layouts[i])));
      const pl = ENCODINGS.layouts[store.state.view].provenanceLabel;
      provNote.hidden = !pl; provNote.textContent = pl ?? '';
    };
    store.subscribe((_s, c) => { if (c.has('view')) paintView(); });
    paintView();

    const help = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'How to read this', title: 'How to read this', 'aria-expanded': 'false' }, '?');
    const stageWrap = h('div', { class: 'galaxy-wrap' }, view.el, familyFocusCard(d, store, colors, () => view.el.querySelector('canvas')?.focus({ preventScroll: true })));
    const coach = createCoach(stageWrap, view.spots, help, d.n);
    help.addEventListener('click', () => coach.open());
    cleanups.push(coach.destroy);
    coach.autoShow();

    // accessible equivalent: top 20 matching CVEs
    const srList = h('ol', { class: 'sr-only', 'aria-label': 'Top 20 matching CVEs by rank' });
    const paintSr = () => srList.replaceChildren(...store.derived.summary.firstIdx.slice(0, 20).map((i) =>
      h('li', {}, h('button', { type: 'button', onClick: () => openCve(d.ids[i]) }, `${d.ids[i]}, rank ${d.rank[i]}`))));
    store.subscribe((_s, c) => { if (c.has('filters')) paintSr(); });
    paintSr();

    const card = h('section', { class: 'card galaxy-card', 'data-explain': 'chart-galaxy', 'aria-label': 'Threat Galaxy' },
      h('header', { class: 'card-head' },
        h('div', {}, h('h2', { class: 'card-title' }, 'Threat Galaxy'),
          h('p', { class: 'card-sub' }, `${fmtInt(d.n)} CVEs · ranking method: ${d.ranking_method}. Scroll to zoom, drag to pan, double-click to reset. Tap a star to focus its family, tap again to open it.`)),
        h('div', { class: 'card-tools' }, h('div', { class: 'seg-group', role: 'group', 'aria-label': 'Layout' }, segs), help, explainButton('chart-galaxy', 'Threat Galaxy'))),
      h('div', { class: 'prov-row' }, provenanceTag('model'), h('span', { class: 'muted' }, 'rank (position)'), provenanceTag('snapshot'), h('span', { class: 'muted' }, 'EPSS and exploit code'), provNote),
      stageWrap, srList);

    const bottom = h('div', { class: 'dash-bottom' }, scatterCard(d, store, colors), budgetCard(pts, store, d.ranking_method));
    const layout = h('div', { class: 'dash' },
      h('div', { class: 'dash-galaxy' }, card, judgeStrip()), // strip right under the galaxy so it stays the hero
      h('div', { class: 'dash-rail-col' }, filtersRail(d, store, colors)),
      h('div', { class: 'dash-side-col' }, selectionPanel(d, store, colors)),
      bottom);
    stagger(bottom);
    return layout;
  };

  void loadInto(host, () => Promise.all([api.galaxy(), api.patchBudget().catch(() => [] as BudgetPoint[])]), render, skeleton(6, true));
  return () => { cleanups.forEach((f) => f()); };
}
