import { api, type Metric, type Overview } from '../api';
import { h, fmtPct, stagger, reducedMotion } from '../util';
import { chartCard, baseOptions, axis, axisTitle, alpha, provenanceTag, tip, pointerOnHover, theme, type Registered, type Theme } from '../charts';
import { explainButton } from '../components/explain';
import { loadInto, skeleton, waitingState } from '../components/ui';
import { pageHead } from './shared';

const isTell = (m: Metric) => /tell/i.test(m.model);
const isHeur = (m: Metric) => /heuristic/i.test(m.model);
/** Tell = blue; every other model takes the categorical palette in order. */
const colorFor = (t: Theme, m: Metric, ms: Metric[]) => (isTell(m) ? t.top : t.palette[ms.filter((x) => !isTell(x)).indexOf(m) % t.palette.length]);
const POINTS = ['circle', 'rect', 'triangle', 'rectRot', 'crossRot', 'star'] as const;
const KS = [100, 250, 500] as const;
const hits = (m: Metric, k: number) => (k === 100 ? m.hits_100 : k === 250 ? m.hits_250 : m.hits_500);
const prec = (m: Metric, k: number) => (k === 100 ? m.precision_100 : k === 250 ? m.precision_250 : m.precision_500);
const rec = (m: Metric, k: number) => (k === 100 ? m.recall_100 : k === 250 ? m.recall_250 : m.recall_500);
const pct100 = (v: number | null) => (v === null ? null : v * 100); // null stays a gap, never 0
const fixed = (v: number | null, d: number) => (v === null ? '–' : v.toFixed(d));

function best<T>(arr: T[], key: (x: T) => number | null): T { return arr.reduce((a, b) => ((key(b) ?? -Infinity) > (key(a) ?? -Infinity) ? b : a)); }

function render(ms: Metric[], o: Overview): HTMLElement {
  if (!ms.length) return waitingState('metrics');
  const tell = ms.find(isTell) ?? o.tell;
  const topHits = best(ms, (m) => m.hits_500);
  const hasRoc = ms.some((m) => m.roc_auc !== null), hasPr = ms.some((m) => m.pr_auc !== null);
  const topRoc = best(ms, (m) => m.roc_auc);
  const topPr = best(ms, (m) => m.pr_auc);
  const hasP = ms.some((m) => m.precision_100 !== null || m.precision_250 !== null || m.precision_500 !== null);
  const hasR = ms.some((m) => m.recall_100 !== null || m.recall_250 !== null || m.recall_500 !== null);
  const pos = o.positives_2025;
  const oneHit = pos ? fmtPct(1 / pos) : '–';

  const note = h('section', { class: 'card note', 'aria-label': 'How to read these results' },
    h('div', { class: 'card-head' }, h('h3', { class: 'card-title' }, 'Reading these results honestly'), provenanceTag('observed')),
    h('ul', { class: 'bullets' },
      h('li', {}, !tell ? `${topHits.model} has the most Hits@500 (${topHits.hits_500}). No Tell ensemble row yet.`
        : topHits.model === tell.model
        ? `${tell.model} has the most Hits@500 (${tell.hits_500}).`
        : `${topHits.model} has the most Hits@500 (${topHits.hits_500}); ${tell.model} scores ${tell.hits_500}.${isHeur(topHits) ? ' A simple heuristic currently outperforms the ensemble on this metric.' : ''}`),
      hasRoc || hasPr ? h('li', {}, `Highest ROC AUC: ${hasRoc ? `${topRoc.model} (${fixed(topRoc.roc_auc, 3)})` : 'not computed yet'}. Highest PR AUC: ${hasPr ? `${topPr.model} (${fixed(topPr.pr_auc, 3)})` : 'not computed yet'}.${tell ? ` ${tell.model}: ${fixed(tell.roc_auc, 3)} and ${fixed(tell.pr_auc, 3)}.` : ''}`) : null,
      pos ? h('li', {}, `The evaluation has ${pos} historical positives, so a single hit moves recall by ${oneHit}. Differences of a few hits are small.`) : h('li', {}, 'The number of historical positives is not computed yet (needs recall_500 in metrics.csv), so the size of these differences cannot be judged.'),
      h('li', {}, 'Hits are measured against past KEV outcomes. The 2026 Top 500 ranking is a prediction; those CVEs have no observed KEV outcome yet.')));

  // Highlight state: clicking a bar, line, legend entry, chip or table row focuses one model and dims the rest.
  let focus: string | null = null;
  const regs: Registered[] = [];
  const shade = (c: string, m: Metric) => (focus && focus !== m.model ? alpha(c, 0.2) : c);
  const toggleFocus = (name: string | undefined) => {
    if (!name) return;
    focus = focus === name ? null : name;
    const t = theme();
    for (const r of regs) {
      if (!r.chart) continue;
      r.chart.data = r.build(t).data;
      (r.chart.options as { animation: unknown }).animation = reducedMotion() ? false : { duration: 150 };
      r.chart.update();
    }
    page.querySelectorAll<HTMLElement>('[data-model]').forEach((el) => {
      const mine = el.dataset.model === focus;
      el.classList.toggle('is-dim', !!focus && !mine);
      el.classList.toggle('is-focus', mine);
      if (el.tagName === 'BUTTON') el.setAttribute('aria-pressed', String(mine));
    });
  };
  const byIndex = (els: { datasetIndex: number }[]) => (els[0] ? ms[els[0].datasetIndex]?.model : undefined);
  const pick = {
    onClick: (_e: unknown, els: { datasetIndex: number }[]) => toggleFocus(byIndex(els)),
    onHover: pointerOnHover,
  };
  const legendOf = (t: Theme) => ({
    ...((baseOptions(t).plugins as { legend: object }).legend),
    onClick: (_e: unknown, item: { datasetIndex?: number }) => toggleFocus(item.datasetIndex === undefined ? undefined : ms[item.datasetIndex]?.model),
    onHover: (e: { native?: Event | null }) => { const c = e.native?.target as HTMLElement | undefined; if (c) c.style.cursor = 'pointer'; },
    onLeave: (e: { native?: Event | null }) => { const c = e.native?.target as HTMLElement | undefined; if (c) c.style.cursor = 'default'; },
  });

  const prState = { metric: (hasP ? 'precision' : 'recall') as 'precision' | 'recall' };
  let prReg: Registered | null = null;
  const seg = (label: string, key: 'precision' | 'recall') => h('button', { type: 'button', class: 'seg', 'aria-pressed': String(key === prState.metric), onClick: () => {
    prState.metric = key;
    seg1.setAttribute('aria-pressed', String(key === 'precision')); seg2.setAttribute('aria-pressed', String(key === 'recall'));
    const chart = prReg?.chart;
    if (chart) {
      ms.forEach((m, i) => { chart.data.datasets[i].data = KS.map((k) => pct100(key === 'precision' ? prec(m, k) : rec(m, k))); });
      (chart.options.scales!.y as { title: { text: string } }).title.text = `${key === 'precision' ? 'Precision' : 'Recall'} (%)`;
      (chart.options as { animation: unknown }).animation = { duration: 300, easing: 'easeOutCubic', delay: 0 };
      chart.update();
    }
  } }, label);
  const seg1 = seg('Precision@K', 'precision'), seg2 = seg('Recall@K', 'recall');
  const toggle = !(hasP && hasR) ? undefined : h('div', { class: 'segmented', role: 'group', 'aria-label': 'Metric' }, seg1, seg2);

  const grid = h('div', { class: 'grid grid-2' },
    chartCard({
      target: 'chart-hits', title: 'Hits at K', subtitle: 'Historical KEV positives found in each model’s top K', provenance: 'observed',
      summary: `Hits@100, 250 and 500 for ${ms.length} models. At 500: ${ms.map((m) => `${m.model} ${m.hits_500}`).join('; ')}.`,
      table: { head: ['Model', 'Hits@100', 'Hits@250', 'Hits@500'], rows: ms.map((m) => [m.model, m.hits_100, m.hits_250, m.hits_500]) },
      height: 320,
      onReady: (r) => regs.push(r),
      build: (t) => ({
        type: 'bar' as const,
        data: { labels: KS.map((k) => `Top ${k}`), datasets: ms.map((m) => ({ label: m.model, data: KS.map((k) => hits(m, k)), backgroundColor: shade(colorFor(t, m, ms), m), borderRadius: 3 })) },
        options: { ...baseOptions(t), ...pick, plugins: { ...(baseOptions(t).plugins as object), legend: legendOf(t), tooltip: tip(t, {}, 'Click to highlight this model') }, scales: { x: axis(t, { grid: { display: false } }), y: axis(t, { beginAtZero: true, title: axisTitle(t, 'Hits') }) } },
      }),
    }),
    hasP || hasR ? chartCard({
      target: 'chart-precision-recall', title: hasP && hasR ? 'Precision and recall at K' : hasP ? 'Precision at K' : 'Recall at K', subtitle: hasP && hasR ? 'Switch between the two measures' : 'Only this measure is in metrics.csv so far', provenance: 'observed', extra: toggle,
      summary: `Precision and recall at K=100, 250, 500 for ${ms.length} models.`,
      table: { head: ['Model', 'P@100', 'P@250', 'P@500', 'R@100', 'R@250', 'R@500'], rows: ms.map((m) => [m.model, fmtPct(m.precision_100), fmtPct(m.precision_250), fmtPct(m.precision_500), fmtPct(m.recall_100), fmtPct(m.recall_250), fmtPct(m.recall_500)]) },
      height: 320,
      onReady: (r) => { prReg = r; regs.push(r); },
      build: (t) => ({
        type: 'line' as const,
        data: {
          labels: KS.map((k) => `Top ${k}`),
          datasets: ms.map((m, i) => ({
            label: m.model, data: KS.map((k) => pct100(prState.metric === 'precision' ? prec(m, k) : rec(m, k))),
            borderColor: shade(colorFor(t, m, ms), m), backgroundColor: shade(colorFor(t, m, ms), m), borderWidth: isTell(m) || m.model === focus ? 3 : 1.75,
            borderDash: isTell(m) ? [] : i % 2 ? [4, 3] : [], pointStyle: POINTS[i % POINTS.length],
            pointRadius: 3.5, pointHoverRadius: 6, tension: 0.15,
          })),
        },
        options: {
          ...baseOptions(t), ...pick, interaction: { mode: 'nearest' as const, intersect: false },
          plugins: { ...(baseOptions(t).plugins as object), legend: legendOf(t), tooltip: tip(t, {}, 'Click to highlight this model') },
          scales: { x: axis(t, { grid: { display: false } }), y: axis(t, { beginAtZero: true, title: axisTitle(t, `${prState.metric === 'precision' ? 'Precision' : 'Recall'} (%)`) }) },
        },
      }),
    }) : null,
  );
  stagger(grid);

  const cols = ['Model', ...(hasRoc ? ['ROC AUC'] : []), ...(hasPr ? ['PR AUC'] : []), 'Hits@500', ...(ms.some((x) => x.recall_500 !== null) ? ['Recall@500'] : [])];
  const aucTable = h('section', { class: 'card', 'data-explain': 'table-auc', 'aria-label': 'AUC table' },
    h('div', { class: 'card-head' },
      h('div', {}, h('h3', { class: 'card-title' }, hasRoc || hasPr ? 'Ranking quality across all candidates' : 'Model comparison'), h('p', { class: 'card-sub' }, hasRoc || hasPr ? 'ROC AUC and PR AUC per model. Best value in each column is marked.' : 'Hits per model. ROC AUC and PR AUC are not computed yet.')),
      h('div', { class: 'card-tools' }, provenanceTag('observed'), explainButton('table-auc', 'AUC table'))),
    h('div', { class: 'table-wrap' }, h('table', { class: 'data-table' },
      h('thead', {}, h('tr', {}, cols.map((c, i) => h('th', { scope: 'col', class: i ? 'num' : null }, c)))),
      h('tbody', {}, ms.map((m) => h('tr', { class: `row-model${isTell(m) ? ' row-hl' : ''}`, 'data-model': m.model, onClick: () => toggleFocus(m.model) },
        h('th', { scope: 'row' }, m.model, isTell(m) ? h('span', { class: 'chip' }, 'Production') : null),
        hasRoc ? h('td', { class: `num${m === topRoc ? ' best' : ''}` }, fixed(m.roc_auc, 4)) : null,
        hasPr ? h('td', { class: `num${m === topPr ? ' best' : ''}` }, fixed(m.pr_auc, 4)) : null,
        h('td', { class: `num${m === topHits ? ' best' : ''}` }, String(m.hits_500)),
        ms.some((x) => x.recall_500 !== null) ? h('td', { class: 'num' }, fmtPct(m.recall_500)) : null))))));

  const picker = h('div', { class: 'chips model-pick', role: 'group', 'aria-label': 'Highlight a model across both charts and the table' },
    h('span', { class: 'label' }, 'Highlight'),
    ms.map((m) => h('button', { type: 'button', class: 'chip chip-toggle', 'data-model': m.model, 'aria-pressed': 'false', onClick: () => toggleFocus(m.model) },
      h('i', { class: 'swatch', style: `background:var(${isTell(m) ? '--data-top' : ['--data-a', '--data-b', '--data-c', '--data-d', '--data-f', '--data-h'][ms.filter((x) => !isTell(x)).indexOf(m) % 6]})`, 'aria-hidden': 'true' }), m.model)));
  const page = h('div', { class: 'page-stack' }, note, picker, grid, aucTable);
  return page;
}

export function mountModels(root: HTMLElement): void {
  root.appendChild(pageHead('Model Evaluation', 'How the Tell ensemble compares with simpler baselines on historical KEV outcomes.'));
  const host = h('div', { class: 'page-host' });
  root.appendChild(host);
  void loadInto(host, () => Promise.all([api.metrics(), api.overview()]), ([m, o]) => render(m, o), skeleton(6, true));
}
