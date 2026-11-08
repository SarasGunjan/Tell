import { api, type Metric, type Overview } from '../api';
import { h, fmtPct } from '../util';
import { chartCard, baseOptions, axis, axisTitle, provenanceTag, tip, pointerOnHover, type Theme } from '../charts';
import { explainButton } from '../components/explain';
import { loadInto, skeleton, waitingState } from '../components/ui';
import { pageHead } from './shared';

const KS = [100, 250, 500] as const;
const hits = (m: Metric, k: number) => (k === 100 ? m.hits_100 : k === 250 ? m.hits_250 : m.hits_500);
const fixed = (v: number | null, d: number) => (v === null ? 'not computed' : v.toFixed(d));

function render(ms: Metric[], o: Overview): HTMLElement {
  if (!ms.length) return waitingState('metrics');
  const isRank = (m: Metric) => m.model.toLowerCase() === o.ranking_method.toLowerCase();
  const colorFor = (t: Theme, m: Metric) => (isRank(m) ? t.top : t.palette[ms.filter((x) => !isRank(x)).indexOf(m) % t.palette.length]);
  const topHits = ms.reduce((a, b) => (b.hits_500 > a.hits_500 ? b : a));
  const rk = o.ranking;
  const withAp = ms.filter((m) => m.average_precision !== null);
  const topAp = withAp.length ? withAp.reduce((a, b) => ((b.average_precision ?? 0) > (a.average_precision ?? 0) ? b : a)) : null;
  const hasP = ms.some((m) => m.precision_100 !== null || m.precision_250 !== null || m.precision_500 !== null);
  const hasR = ms.some((m) => m.recall_500 !== null);
  const hasRoc = ms.some((m) => m.roc_auc !== null);

  const note = h('section', { class: 'card note', 'aria-label': 'How to read these results' },
    h('div', { class: 'card-head' }, h('h3', { class: 'card-title' }, 'Reading these results honestly'), provenanceTag('observed')),
    h('ul', { class: 'bullets' },
      h('li', {}, `${topHits.model} has the most Hits@500 (${topHits.hits_500})${rk && rk.model !== topHits.model ? `; ${rk.model} scores ${rk.hits_500}` : ''}${o.epss_hits_500 !== null && rk && rk.model !== 'EPSS' ? `, against ${o.epss_hits_500} for EPSS alone${o.lift_over_epss ? ` (${o.lift_over_epss.toFixed(2)}×)` : ''}` : ''}.`),
      topAp ? h('li', {}, `Highest average precision: ${topAp.model} (${fixed(topAp.average_precision, 3)}). Models without a value (${ms.filter((m) => m.average_precision === null).map((m) => m.model).join(', ') || 'none'}) are not computed.`) : null,
      h('li', {}, 'Hits are counted at three review budgets (100, 250, 500). Nothing is measured in between, so the charts show discrete points, not a curve.'),
      h('li', {}, 'The validation cohort is small, so a hit or two is within noise. Hits are measured against past KEV outcomes; the 2026 Top 500 has no observed outcome yet.')));

  const grid = h('div', { class: 'grid grid-2' },
    chartCard({
      target: 'chart-hits', title: 'Hits at K', subtitle: 'KEV additions found in each model’s top 100, 250 and 500', provenance: 'observed', wide: true, height: 320,
      summary: `Hits@100, 250 and 500 for ${ms.length} models. At 500: ${ms.map((m) => `${m.model} ${m.hits_500}`).join('; ')}.`,
      table: { head: ['Model', 'Hits@100', 'Hits@250', 'Hits@500'], rows: ms.map((m) => [m.model, m.hits_100, m.hits_250, m.hits_500]) },
      build: (t) => ({
        type: 'bar' as const,
        data: { labels: KS.map((k) => `Top ${k}`), datasets: ms.map((m) => ({ label: m.model, data: KS.map((k) => hits(m, k)), backgroundColor: colorFor(t, m), borderRadius: 3 })) },
        options: { ...baseOptions(t), onHover: pointerOnHover, plugins: { ...(baseOptions(t).plugins as object), tooltip: tip(t) },
          scales: { x: axis(t, { grid: { display: false } }), y: axis(t, { beginAtZero: true, title: axisTitle(t, 'Hits'), ticks: { color: t.text3, precision: 0, font: { size: 11 } } }) } },
      }),
    }));

  const cols = ['Model', 'Hits@100', 'Hits@250', 'Hits@500', 'Average precision', ...(hasP ? ['Precision@500'] : []), ...(hasR ? ['Recall@500'] : []), ...(hasRoc ? ['ROC AUC'] : [])];
  const table = h('section', { class: 'card', 'data-explain': 'table-ap', 'aria-label': 'Model comparison table' },
    h('div', { class: 'card-head' },
      h('div', {}, h('h3', { class: 'card-title' }, 'Model comparison'), h('p', { class: 'card-sub' }, 'Best Hits@500 and best average precision are marked.')),
      h('div', { class: 'card-tools' }, provenanceTag('observed'), explainButton('table-ap', 'Model comparison'))),
    h('div', { class: 'table-wrap' }, h('table', { class: 'data-table' },
      h('thead', {}, h('tr', {}, cols.map((c, i) => h('th', { scope: 'col', class: i ? 'num' : null }, c)))),
      h('tbody', {}, ms.map((m) => h('tr', { class: isRank(m) ? 'row-hl' : '' },
        h('th', { scope: 'row' }, m.model, isRank(m) ? h('span', { class: 'chip' }, 'Current ranking') : null),
        h('td', { class: 'num' }, String(m.hits_100)), h('td', { class: 'num' }, String(m.hits_250)),
        h('td', { class: `num${m === topHits ? ' best' : ''}` }, String(m.hits_500)),
        h('td', { class: `num${m === topAp ? ' best' : ''}` }, m.average_precision === null ? h('span', { class: 'muted' }, 'not computed') : m.average_precision.toFixed(3)),
        hasP ? h('td', { class: 'num' }, fmtPct(m.precision_500)) : null,
        hasR ? h('td', { class: 'num' }, fmtPct(m.recall_500)) : null,
        hasRoc ? h('td', { class: 'num' }, fixed(m.roc_auc, 3)) : null))))));
  const page = h('div', { class: 'page-stack' }, note, grid, table);
  return page;
}

export function mountModels(root: HTMLElement): void {
  root.appendChild(pageHead('Model Evaluation', 'How the ranking compares with EPSS and two learned models on past KEV outcomes (validation cohort).'));
  const host = h('div', { class: 'page-host' });
  root.appendChild(host);
  void loadInto(host, () => Promise.all([api.metrics(), api.overview()]), ([m, o]) => render(m, o), skeleton(6, true));
}
