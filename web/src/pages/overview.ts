import { api, type Overview, type Distributions, type SignalCounts } from '../api';
import { h, fmtInt, fmtPct, stagger } from '../util';
import { chartCard, baseOptions, axis, axisTitle, tip, pointerOnHover, type Theme } from '../charts';
import { openTop500 } from '../actions';
import { kpi, loadInto, skeleton, waitingState, waitingCard } from '../components/ui';
import { pageHead } from './shared';

const numLabel = (x: number): string => {
  if (x === 0) return '0';
  const a = Math.abs(x);
  if (a >= 100) return x.toFixed(0);
  if (a >= 1) return x.toFixed(2).replace(/\.?0+$/, '');
  if (a >= 0.001) return x.toFixed(3).replace(/\.?0+$/, '');
  return Number(x.toPrecision(2)).toExponential().replace('e-', 'e−');
};
const binLabels = (edges: number[]) => edges.slice(0, -1).map((e, i) => `${numLabel(e)}–${numLabel(edges[i + 1])}`);

function histConfig(t: Theme, edges: number[], all: number[], top: number[], xTitle: string, onBin?: (i: number) => void) {
  const labels = binLabels(edges);
  return {
    type: 'bar' as const,
    data: {
      labels,
      datasets: [
        { label: 'All CVEs', data: all, backgroundColor: t.all, borderRadius: 2, order: 2 },
        { label: 'Top 500', data: top, backgroundColor: t.top, borderRadius: 2, order: 1 },
      ],
    },
    options: {
      ...baseOptions(t),
      interaction: { mode: 'index' as const, intersect: false },
      ...(onBin ? {
        onClick: (_e: unknown, els: { index: number }[]) => { if (els[0]) onBin(els[0].index); },
        onHover: pointerOnHover,
        plugins: { ...(baseOptions(t).plugins as object), tooltip: tip(t, {}, 'Click to filter the Top 500 from this bin up') },
      } : {}),
      scales: {
        x: axis(t, { title: axisTitle(t, xTitle), ticks: { color: t.text3, maxRotation: 0, autoSkip: true, maxTicksLimit: 7, font: { size: 11 }, callback: (_v: string | number, i: number) => numLabel(edges[i]) }, grid: { display: false } }),
        y: axis(t, { type: 'logarithmic', min: 1, title: axisTitle(t, 'CVEs (log scale)'), ticks: { color: t.text3, padding: 6, font: { size: 11 }, callback: (v: string | number) => (Number.isInteger(Math.round(Math.log10(Number(v)) * 1e6) / 1e6) ? fmtInt(Number(v)) : '') } }),
      },
    },
  };
}
const histSummary = (name: string, all: number[], top: number[]) =>
  `${name}: ${fmtInt(all.reduce((a, b) => a + b, 0))} CVEs across ${all.length} bins; ${fmtInt(top.reduce((a, b) => a + b, 0))} of them in the Top 500. Log-scale counts.`;
const histTable = (edges: number[], all: number[], top: number[]) => ({
  head: ['Bin', 'All CVEs', 'Top 500'], rows: binLabels(edges).map((l, i) => [l, all[i], top[i]]),
});

const SIG_KEYS: { key: keyof SignalCounts; label: string }[] = [
  { key: 'exploitdb', label: 'Exploit-DB' }, { key: 'metasploit', label: 'Metasploit' },
  { key: 'nuclei', label: 'Nuclei' }, { key: 'poc_github', label: 'GitHub PoC' }, { key: 'any', label: 'Any signal' },
];

function render(o: Overview, d: Distributions): HTMLElement {
  const best = o.best_hits_500, tell = o.ranking;
  const hasPreds = o.total_cves !== null;

  const kpis = h('div', { class: 'grid grid-3' },
    kpi({ target: 'kpi-candidates', label: 'CVEs ranked', value: hasPreds ? fmtInt(o.total_cves) : null, waiting: 'predictions',
      sub: `${fmtInt(o.top500_count)} shortlisted in the Top 500 · ${o.family_count === null ? 'families not computed yet' : `${fmtInt(o.family_count)} IBM Granite families`}`, prov: 'snapshot' }),
    kpi({ target: 'kpi-hits500', label: tell ? `Hits@500 · ${tell.model}` : `Hits@500 · ${o.ranking_method}`, value: tell ? String(tell.hits_500) : null, waiting: 'metrics',
      sub: tell ? `KEV additions caught in the top 500 (validation backtest)${tell.recall_500 === null ? '' : `, recall ${fmtPct(tell.recall_500)}`}` : undefined, prov: 'observed' }),
    kpi({ target: 'kpi-lift', label: `${o.ranking_method} lift over EPSS at 500`, value: o.lift_over_epss !== null ? `${o.lift_over_epss.toFixed(2)}×` : null, waiting: 'metrics',
      sub: tell ? `${tell.hits_500} vs ${o.epss_hits_500} hits for EPSS alone.${best && best.model !== tell.model ? `\nBest at 500: ${best.model} (${best.hits_500}).` : ''}` : undefined, prov: 'observed' }));

  const sc = o.signal_counts;
  const share = (c: SignalCounts, k: keyof SignalCounts, total: number | null) => ((total && c[k] !== null) ? ((c[k] as number) / total) * 100 : 0);
  const sigOk = !!sc && sc.all.any !== null;
  const sigAll = sc ? SIG_KEYS.map((s) => share(sc.all, s.key, o.total_cves)) : [];
  const sigTop = sc ? SIG_KEYS.map((s) => share(sc.top500, s.key, o.top500_count)) : [];
  const pmRaw = d.published_by_month;
  const pm = pmRaw ? { ...pmRaw, share: pmRaw.months.map((_, i) => (pmRaw.all[i] ? (pmRaw.top500[i] / pmRaw.all[i]) * 100 : 0)) } : null;
  const rb = d.rank_epss, eh = d.epss_hist;
  const cnt = (c: number | null) => (c === null ? '–' : c);

  const charts = h('div', { class: 'grid grid-2' },
    rb && rb.length ? chartCard({
      target: 'chart-rank-epss', title: 'Rank vs EPSS', subtitle: `Median EPSS by rank band (${o.ranking_method})`, provenance: 'snapshot',
      summary: `Median EPSS by rank band: ${rb.map((x) => `${x.label} ${x.median_epss.toFixed(4)}`).join('; ')}.`,
      table: { head: ['Rank band', 'CVEs', 'Median EPSS', 'Share with exploit signal'], rows: rb.map((x) => [x.label, x.count, x.median_epss.toFixed(4), x.share_with_signal === null ? '–' : fmtPct(x.share_with_signal)]) },
      build: (t) => ({
        type: 'bar' as const,
        data: { labels: rb.map((x) => x.label), datasets: [{ label: 'Median EPSS', data: rb.map((x) => x.median_epss * 100), backgroundColor: t.top, borderRadius: 3 }] },
        options: { ...baseOptions(t), plugins: { ...(baseOptions(t).plugins as object), legend: { display: false },
          tooltip: tip(t, { label: (c: { dataIndex: number; parsed: { y: number | null } }) => ` median EPSS ${(c.parsed.y ?? 0).toFixed(2)}% · ${fmtInt(rb[c.dataIndex].count)} CVEs` }) },
          scales: { x: axis(t, { grid: { display: false }, title: axisTitle(t, 'Rank band') }),
            y: axis(t, { type: 'logarithmic', title: axisTitle(t, 'Median EPSS (%, log scale)'), ticks: { color: t.text3, font: { size: 11 }, callback: (v: string | number) => (Number.isInteger(Math.round(Math.log10(Number(v)) * 1e6) / 1e6) ? `${v}%` : '') } }) } },
      }),
    }) : waitingCard('Rank vs EPSS', 'predictions'),
    eh ? chartCard({
      target: 'chart-epss-dist', title: 'EPSS distribution', subtitle: 'Top 500 vs all scored CVEs', provenance: 'snapshot',
      summary: histSummary('EPSS distribution', eh.all, eh.top500),
      table: histTable(eh.edges, eh.all, eh.top500),
      actionsLabel: 'Open the Top 500 filtered by minimum EPSS',
      actions: eh.edges.slice(0, -1).map((e, i) => ({ label: `EPSS ≥ ${numLabel(e)}`, run: () => openTop500({ min_epss: eh.edges[i] }) })),
      build: (t) => histConfig(t, eh.edges, eh.all, eh.top500, 'EPSS (log-spaced bins)', (i) => openTop500({ min_epss: eh.edges[i] })),
    }) : waitingCard('EPSS distribution', 'predictions'),
    sigOk && sc ? chartCard({
      target: 'chart-signals', title: 'Public exploit signals', subtitle: 'Share of CVEs with each signal', provenance: 'snapshot',
      summary: `Share of CVEs with a public exploit signal, Top 500 versus all. Any signal: ${sigTop[4].toFixed(1)}% of the Top 500 and ${sigAll[4].toFixed(1)}% of all CVEs.`,
      actionsLabel: 'Open the Top 500 filtered by signal',
      actions: SIG_KEYS.filter((s) => s.key !== 'any').map((s) => ({ label: `Top 500 with ${s.label}`, run: () => openTop500({ signals: [s.key] }) })),
      table: { head: ['Signal', 'Top 500 count', 'All count'], rows: SIG_KEYS.map((s) => [s.label, cnt(sc.top500[s.key]), cnt(sc.all[s.key])]) },
      build: (t) => ({
        type: 'bar' as const,
        data: {
          labels: SIG_KEYS.map((s) => s.label),
          datasets: [
            { label: 'All CVEs', data: sigAll, backgroundColor: t.all, borderRadius: 3 },
            { label: 'Top 500', data: sigTop, backgroundColor: t.top, borderRadius: 3 },
          ],
        },
        options: {
          ...baseOptions(t),
          onClick: (_e: unknown, els: { index: number }[]) => { const k = els[0] && SIG_KEYS[els[0].index].key; if (k && k !== 'any') openTop500({ signals: [k] }); },
          onHover: (e: { native?: Event | null }, els: { index: number }[]) => pointerOnHover(e, els.filter((x) => SIG_KEYS[x.index].key !== 'any')),
          plugins: {
            ...(baseOptions(t).plugins as object),
            tooltip: tip(t, {
              label: (ctx: { dataset: { label?: string }; dataIndex: number; parsed: { y: number | null } }) => {
                const grp = ctx.dataset.label === 'Top 500' ? sc.top500 : sc.all;
                return ` ${ctx.dataset.label}: ${(ctx.parsed.y ?? 0).toFixed(1)}% (${fmtInt(grp[SIG_KEYS[ctx.dataIndex].key] ?? 0)})`;
              },
              footer: (items: { dataIndex: number }[]) => (items[0] && SIG_KEYS[items[0].dataIndex].key !== 'any' ? 'Click to filter the Top 500' : ''),
            }),
          },
          scales: {
            x: axis(t, { grid: { display: false } }),
            y: axis(t, { title: axisTitle(t, '% of group'), ticks: { color: t.text3, callback: (v: string | number) => `${v}%`, font: { size: 11 } } }),
          },
        },
      }),
    }) : null,
    pm ? chartCard({
      target: 'chart-published', title: 'Published by month', subtitle: 'Share of each month’s CVEs that made the Top 500', provenance: 'mixed',
      summary: `Percentage of each month's CVEs that are in the Top 500, across ${pm.months.length} months. Counts are in the tooltip and the data table.`,
      table: { head: ['Month', 'All CVEs', 'Top 500', 'Top 500 share'], rows: pm.months.map((m, i) => [m, pm.all[i], pm.top500[i], `${pm.share[i].toFixed(1)}%`]) },
      build: (t) => ({
        type: 'bar' as const,
        data: { labels: pm.months, datasets: [{ label: 'Top 500 share', data: pm.share, backgroundColor: t.top, borderRadius: 3 }] },
        options: {
          ...baseOptions(t),
          plugins: {
            ...(baseOptions(t).plugins as object),
            legend: { display: false },
            tooltip: tip(t, {
              label: (ctx: { dataIndex: number; parsed: { y: number | null } }) =>
                ` ${(ctx.parsed.y ?? 0).toFixed(1)}% in Top 500 (${fmtInt(pm.top500[ctx.dataIndex])} of ${fmtInt(pm.all[ctx.dataIndex])} CVEs)`,
            }),
          },
          scales: {
            x: axis(t, { grid: { display: false } }),
            y: axis(t, { beginAtZero: true, title: axisTitle(t, "% of month's CVEs in Top 500"), ticks: { color: t.text3, callback: (v: string | number) => `${v}%`, font: { size: 11 } } }),
          },
        },
      }),
    }) : null,
  );
  const root = h('div', { class: 'page-stack' }, kpis, hasPreds ? charts : waitingState('predictions'));
  stagger(kpis); stagger(charts);
  return root;
}

export function mountOverview(root: HTMLElement): void {
  root.appendChild(h('div', { class: 'hero-wash', 'aria-hidden': 'true' }));
  root.appendChild(pageHead('Overview', 'Every attack has a tell. Which CVEs on the 2026 scoreboard are most likely to enter CISA KEV, ranked by public exploit code then EPSS.'));
  const host = h('div', { class: 'page-host' });
  root.appendChild(host);
  void loadInto(host, () => Promise.all([api.overview(), api.distributions()]), ([o, d]) => render(o, d), skeleton(6, true));
}
