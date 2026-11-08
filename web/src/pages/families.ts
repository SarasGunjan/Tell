import { api, type Family, type FamilyDetail } from '../api';
import { h, fmtInt, fmtPct, fmtEpss, stagger, reducedMotion, SIGNALS } from '../util';
import { chartCard, baseOptions, axis, axisTitle, alpha, provenanceTag, tip, pointerOnHover, type Theme } from '../charts';
import { loadInto, skeleton, cveMiniCard, waitingState, waitingCard } from '../components/ui';
import { openCve } from '../components/drawer';
import { pageHead } from './shared';
import type { Chart } from 'chart.js';

export function mountFamilies(root: HTMLElement): void {
  root.appendChild(pageHead('Families', 'Vulnerability families, their size, and how often their CVEs have historically reached KEV.'));
  const host = h('div', { class: 'page-host' });
  root.appendChild(host);
  void loadInto(host, () => api.families(), (fams) => render(fams), skeleton(6, true));
}

/** Split at the last space within 24 chars so long names wrap onto two lines instead of truncating. */
function wrapName(name: string): string | string[] {
  if (name.length <= 24) return name;
  const cut = name.lastIndexOf(' ', 24);
  return cut > 0 ? [name.slice(0, cut), name.slice(cut + 1)] : name;
}

function hbar(t: Theme, fams: Family[], pick: (f: Family) => number | null, label: string, fmt: (n: number) => string, onPick: (id: string) => void, xTitle: string) {
  return {
    type: 'bar' as const,
    data: {
      labels: fams.map((f) => wrapName(f.family_name)),
      datasets: [{ label, data: fams.map(pick), backgroundColor: fams.map((f) => (f.high_risk ? t.risk : alpha(t.top, 0.4))), borderColor: fams.map((f) => (f.high_risk ? t.risk : t.top)), borderWidth: 1.5, borderRadius: 3, barThickness: 16 }],
    },
    options: {
      ...baseOptions(t),
      indexAxis: 'y' as const,
      onClick: (_e: unknown, els: { index: number }[]) => { if (els[0]) onPick(fams[els[0].index].family_id); },
      onHover: pointerOnHover,
      plugins: {
        ...(baseOptions(t).plugins as object),
        legend: { display: false },
        tooltip: tip(t, { label: (c: { parsed: { x: number | null } }) => ` ${label}: ${fmt(c.parsed.x ?? 0)}` }, 'Click to open'),
      },
      scales: {
        x: axis(t, { beginAtZero: true, title: axisTitle(t, xTitle), ticks: { color: t.text3, callback: (v: string | number) => fmt(Number(v)), font: { size: 11 } } }),
        y: axis(t, { grid: { display: false }, ticks: { color: t.text2, font: { size: 11 }, } }),
      },
    },
  };
}

function render(famsRaw: Family[]): HTMLElement {
  if (!famsRaw.length) return waitingState('families');
  const bySize = [...famsRaw].sort((a, b) => b.family_size - a.family_size);
  const hasKev = famsRaw.some((f) => f.hist_kev_rate !== null);
  const hasEpss = famsRaw.some((f) => f.avg_epss_2026 !== null);
  const byKev = [...famsRaw].sort((a, b) => (b.hist_kev_rate ?? -1) - (a.hist_kev_rate ?? -1));
  const detail = h('section', { class: 'card family-detail', 'aria-label': 'Family detail', 'aria-live': 'polite' },
    h('p', { class: 'muted' }, 'Select a family in a chart or the list to see its top-ranked CVEs.'));

  const select = (id: string) => {
    list.querySelectorAll<HTMLButtonElement>('[data-fam]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.fam === id)));
    void loadInto(detail, () => api.family(id), (d) => renderDetail(d), skeleton(5));
    detail.scrollIntoView({ block: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' });
  };

  const maxEpss = Math.max(...famsRaw.map((f) => f.avg_epss_2026 ?? 0), 1e-9);
  const rad = (f: Family) => (f.avg_epss_2026 === null ? 10 : 7 + 20 * Math.sqrt(f.avg_epss_2026 / maxEpss));

  const grid = h('div', { class: 'grid grid-2' },
    chartCard({
      target: 'chart-family-size', title: 'Family size', subtitle: 'CVEs per family. Red bars are high-risk families.', provenance: 'observed',
      summary: `Number of scored CVEs per family. Largest: ${bySize[0].family_name} with ${fmtInt(bySize[0].family_size)}.`,
      table: { head: ['Family', 'CVEs'], rows: bySize.map((f) => [f.family_name, f.family_size]) },
      actionsLabel: 'Open a family', actions: bySize.map((f) => ({ label: f.family_name, run: () => select(f.family_id) })),
      height: Math.max(240, bySize.length * 36 + 60),
      build: (t) => hbar(t, bySize, (f) => f.family_size, 'CVEs', fmtInt, select, 'Scored CVEs'),
    }),
    hasKev ? chartCard({
      target: 'chart-family-kev', title: 'Historical KEV rate', subtitle: 'Share of each family’s CVEs that reached KEV', provenance: 'observed',
      summary: `Historical KEV rate by family. Highest: ${byKev[0].family_name} at ${fmtPct(byKev[0].hist_kev_rate)}.`,
      table: { head: ['Family', 'Historical KEV rate'], rows: byKev.map((f) => [f.family_name, fmtPct(f.hist_kev_rate)]) },
      actionsLabel: 'Open a family', actions: byKev.map((f) => ({ label: f.family_name, run: () => select(f.family_id) })),
      height: Math.max(240, byKev.length * 36 + 60),
      build: (t) => hbar(t, byKev, (f) => f.hist_kev_rate, 'KEV rate', (n) => fmtPct(n), select, 'Historical KEV rate'),
    }) : waitingCard('Historical KEV rate', 'Waiting on Member 2\'s family_summary.csv (hist_kev_rate column)'),
    hasKev ? chartCard({
      target: 'chart-family-bubble', title: 'Size × KEV rate × EPSS', subtitle: hasEpss ? 'Bubble area follows average 2026 EPSS. Click a bubble to open the family.' : 'Average 2026 EPSS is not computed yet, so bubbles are a fixed size. Click a bubble to open the family.', provenance: 'snapshot', wide: true, height: 340,
      actionsLabel: 'Open a family', actions: famsRaw.map((f) => ({ label: f.family_name, run: () => select(f.family_id) })),
      summary: `Each family plotted by size (log) and historical KEV rate; bubble size is average 2026 EPSS. ${famsRaw.length} families.`,
      table: { head: ['Family', 'Size', 'KEV rate', 'Avg EPSS 2026'], rows: famsRaw.map((f) => [f.family_name, f.family_size, fmtPct(f.hist_kev_rate), fmtEpss(f.avg_epss_2026)]) },
      build: (t) => {
        const ds = (label: string, set: Family[], color: string) => ({
          label, data: set.map((f) => ({ x: f.family_size, y: (f.hist_kev_rate ?? 0) * 100, r: rad(f), f })),
          backgroundColor: alpha(color, 0.5), borderColor: color, borderWidth: 1.5, hoverBackgroundColor: alpha(color, 0.78),
        });
        return {
          type: 'bubble' as const,
          data: { datasets: [ds('High-risk family', famsRaw.filter((f) => f.high_risk), t.risk), ds('Other family', famsRaw.filter((f) => !f.high_risk), t.top)] },
          options: {
            ...baseOptions(t),
            onHover: pointerOnHover,
            onClick: (_e: unknown, els: { datasetIndex: number; index: number }[], chart: Chart) => {
              const el = els[0]; if (!el) return;
              const raw = chart.data.datasets[el.datasetIndex].data[el.index] as unknown as { f: Family };
              select(raw.f.family_id);
            },
            plugins: {
              ...(baseOptions(t).plugins as object),
              tooltip: tip(t, {
                title: (items: { raw: unknown }[]) => (items[0].raw as { f: Family }).f.family_name,
                label: (c: { raw: unknown }) => { const f = (c.raw as { f: Family }).f; return [`Size: ${fmtInt(f.family_size)}`, `KEV rate: ${fmtPct(f.hist_kev_rate)}`, `Avg EPSS 2026: ${fmtEpss(f.avg_epss_2026)}`]; },
              }, 'Click to open'),
            },
            layout: { padding: 16 },
            scales: {
              x: axis(t, { type: 'logarithmic', title: axisTitle(t, 'Family size (log scale)'), ticks: { color: t.text3, padding: 6, font: { size: 11 }, callback: (v: string | number) => ([500, 1000, 2000, 5000, 10000, 20000, 40000].includes(Number(v)) ? fmtInt(Number(v)) : '') } }),
              y: axis(t, { beginAtZero: true, title: axisTitle(t, 'Historical KEV rate (%)') }),
            },
          },
        };
      },
    }) : null,
  );
  stagger(grid);

  const list = h('section', { class: 'card', 'aria-label': 'Family list' },
    h('div', { class: 'card-head' }, h('h3', { class: 'card-title' }, 'All families'), provenanceTag('observed')),
    h('div', { class: 'table-wrap' }, h('table', { class: 'data-table' },
      h('thead', {}, h('tr', {}, ['Family', 'CVEs', 'KEV rate', 'Avg EPSS 2026', 'Risk'].map((x, i) => h('th', { scope: 'col', class: i >= 1 && i <= 3 ? 'num' : null }, x)))),
      h('tbody', {}, byKev.map((f) => h('tr', {},
        h('th', { scope: 'row' }, h('button', { type: 'button', class: 'link-btn', 'data-fam': f.family_id, 'aria-pressed': 'false', onClick: () => select(f.family_id) }, f.family_name)),
        h('td', { class: 'num' }, fmtInt(f.family_size)), h('td', { class: 'num' }, fmtPct(f.hist_kev_rate)),
        h('td', { class: 'num' }, fmtEpss(f.avg_epss_2026)), h('td', {}, f.high_risk ? h('span', { class: 'chip chip-warn' }, 'High risk') : '–')))))));
  return h('div', { class: 'page-stack' }, grid, detail, list);
}

function renderDetail(d: FamilyDetail): HTMLElement {
  const f = d.family;
  return h('div', { class: 'family-body fade-in' },
    h('div', { class: 'card-head' },
      h('div', {}, h('h3', { class: 'card-title' }, f.family_name), f.key_traits ? h('p', { class: 'card-sub' }, f.key_traits) : null),
      h('div', { class: 'card-tools' }, provenanceTag('observed'))),
    h('dl', { class: 'facts facts-row' },
      fact('CVEs in family', fmtInt(f.family_size)), fact('In Top 500', d.in_top500 === null ? 'not computed yet' : fmtInt(d.in_top500)),
      fact('Historical KEV rate', f.hist_kev_rate === null ? 'not computed yet' : fmtPct(f.hist_kev_rate)), fact('Avg EPSS 2026', f.avg_epss_2026 === null ? 'not computed yet' : fmtEpss(f.avg_epss_2026))),
    d.signal_counts ? h('div', { class: 'chips' }, SIGNALS.map((s) => h('span', { class: `chip chip-${s.key}` }, `${s.label}: ${fmtInt(d.signal_counts![s.key])}`))) : null,
    h('h4', { class: 'sub-title' }, 'Top-ranked CVEs in this family ', provenanceTag('model')),
    (() => { const g = h('div', { class: 'mini-grid' }, d.top_cves.map((c) => cveMiniCard(c, openCve))); stagger(g, 8); return g; })());
}
const fact = (k: string, v: string) => h('div', { class: 'fact' }, h('dt', {}, k), h('dd', { class: 'num' }, v));
