import { api, type Family, type FamilyDetail, type Breakdown } from '../api';
import { h, clear, fmtInt, fmtPct, stagger, reducedMotion, SIGNALS } from '../util';
import { emitAsk } from '../state';
import { chartCard, baseOptions, axis, axisTitle, alpha, provenanceTag, tip, pointerOnHover, type Theme } from '../charts';
import { loadInto, skeleton, cveMiniCard, waitingState } from '../components/ui';
import { openCve } from '../components/drawer';
import { pageHead } from './shared';
import type { Chart } from 'chart.js';

const BASIS = 'Observed (historical), population-weighted';

export function mountFamilies(root: HTMLElement): void {
  root.appendChild(pageHead('Exploit Family Explorer', 'Ten IBM Granite families of 2026 CVEs, with how often each family’s historical CVEs reached KEV. Family rates describe past patterns, not the chance for any one CVE.'));
  const host = h('div', { class: 'page-host' });
  root.appendChild(host);
  void loadInto(host, () => Promise.all([api.families(), api.research().catch(() => null)]), ([fams, rs]) => render(fams, rs && rs.available ? rs.sample_caption : null), skeleton(6, true));
}

function wrapName(name: string): string | string[] {
  if (name.length <= 24) return name;
  const cut = name.lastIndexOf(' ', 24);
  return cut > 0 ? [name.slice(0, cut), name.slice(cut + 1)] : name;
}
const lift = (v: number | null) => (v === null ? 'not computed yet' : `${v.toFixed(2)}×`);

function render(famsRaw: Family[], caption: string | null): HTMLElement {
  if (!famsRaw.length) return waitingState('families');
  const hasLift = famsRaw.some((f) => f.population_lift !== null);
  const byLift = [...famsRaw].sort((a, b) => (b.population_lift ?? -1) - (a.population_lift ?? -1));
  const maxKev = Math.max(...famsRaw.map((f) => f.historical_kev_count ?? 0), 1);
  const detail = h('section', { class: 'card family-detail', 'aria-label': 'Family detail', 'aria-live': 'polite' },
    h('p', { class: 'muted' }, 'Select a family in a chart or the list to see its profile.'));
  let showSample = false;
  const listHost = h('div', {});

  const select = (id: string) => {
    document.querySelectorAll<HTMLButtonElement>('[data-fam]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.fam === id)));
    void loadInto(detail, () => api.family(id), (d) => renderDetail(d), skeleton(5));
    detail.scrollIntoView({ block: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' });
  };

  const grid = h('div', { class: 'grid grid-2' },
    chartCard({
      target: 'chart-family-kev', title: 'Historical population lift', subtitle: `${BASIS}. 1.0× = the average CVE.`, provenance: 'observed',
      summary: hasLift ? `Population-weighted KEV lift by family. Highest: ${byLift[0].family_name} at ${lift(byLift[0].population_lift)}.` : 'Lift not computed yet.',
      table: { head: ['Family', 'Population KEV rate', 'Population lift'], rows: byLift.map((f) => [f.family_name, fmtPct(f.population_kev_rate, 2), lift(f.population_lift)]) },
      actionsLabel: 'Open a family', actions: byLift.map((f) => ({ label: f.family_name, run: () => select(f.family_id) })),
      height: Math.max(260, byLift.length * 36 + 60),
      build: (t: Theme) => ({
        type: 'bar' as const,
        data: { labels: byLift.map((f) => wrapName(f.family_name)), datasets: [{ label: 'Population lift', data: byLift.map((f) => f.population_lift), backgroundColor: byLift.map((f) => ((f.population_lift ?? 0) >= 1 ? t.risk : alpha(t.top, 0.45))), borderRadius: 3, barThickness: 16 }] },
        options: { ...baseOptions(t), indexAxis: 'y' as const, onHover: pointerOnHover,
          onClick: (_e: unknown, els: { index: number }[]) => { if (els[0]) select(byLift[els[0].index].family_id); },
          plugins: { ...(baseOptions(t).plugins as object), legend: { display: false }, tooltip: tip(t, { label: (c: { dataIndex: number }) => { const f = byLift[c.dataIndex]; return [` Lift ${lift(f.population_lift)}`, ` Population KEV rate ${fmtPct(f.population_kev_rate, 2)}`]; } }, 'Click to open') },
          scales: { x: axis(t, { beginAtZero: true, title: axisTitle(t, 'Population lift (×)') }), y: axis(t, { grid: { display: false }, ticks: { color: t.text2, font: { size: 11 } } }) } },
      }),
    }),
    chartCard({
      target: 'chart-family-size', title: 'Family size in 2026', subtitle: 'CVEs per family on the 2026 scoreboard', provenance: 'granite',
      summary: `Number of 2026 CVEs per family. Largest: ${[...famsRaw].sort((a, b) => b.family_size - a.family_size)[0].family_name}.`,
      table: { head: ['Family', '2026 CVEs', 'In Top 500'], rows: famsRaw.map((f) => [f.family_name, f.family_size, f.in_top500 ?? '–']) },
      height: Math.max(260, famsRaw.length * 36 + 60),
      build: (t: Theme) => ({
        type: 'bar' as const,
        data: { labels: famsRaw.map((f) => wrapName(f.family_name)), datasets: [{ label: '2026 CVEs', data: famsRaw.map((f) => f.family_size), backgroundColor: alpha(t.top, 0.5), borderColor: t.top, borderWidth: 1.5, borderRadius: 3, barThickness: 16 }] },
        options: { ...baseOptions(t), indexAxis: 'y' as const, onHover: pointerOnHover,
          onClick: (_e: unknown, els: { index: number }[]) => { if (els[0]) select(famsRaw[els[0].index].family_id); },
          plugins: { ...(baseOptions(t).plugins as object), legend: { display: false }, tooltip: tip(t, {}, 'Click to open') },
          scales: { x: axis(t, { beginAtZero: true, title: axisTitle(t, '2026 CVEs'), ticks: { color: t.text3, callback: (v: string | number) => fmtInt(Number(v)), font: { size: 11 } } }), y: axis(t, { grid: { display: false }, ticks: { color: t.text2, font: { size: 11 } } }) } },
      }),
    }),
    hasLift ? chartCard({
      target: 'chart-family-bubble', title: 'Size × lift × historical KEVs', subtitle: 'x: 2026 family size · y: population lift · bubble: historical KEV count. Click a bubble to open the family.', provenance: 'observed', wide: true, height: 340,
      actionsLabel: 'Open a family', actions: famsRaw.map((f) => ({ label: f.family_name, run: () => select(f.family_id) })),
      summary: `Each family plotted by 2026 size and historical population lift; bubble size is historical KEV count. ${famsRaw.length} families.`,
      table: { head: ['Family', '2026 size', 'Population lift', 'Historical KEVs'], rows: famsRaw.map((f) => [f.family_name, f.family_size, lift(f.population_lift), f.historical_kev_count ?? '–']) },
      build: (t: Theme) => ({
        type: 'bubble' as const,
        data: { datasets: [{ label: 'Family', data: famsRaw.map((f) => ({ x: f.family_size, y: f.population_lift ?? 0, r: 6 + 22 * Math.sqrt((f.historical_kev_count ?? 0) / maxKev), f })), backgroundColor: famsRaw.map((_, i) => alpha(t.palette[i % t.palette.length], 0.55)), borderColor: famsRaw.map((_, i) => t.palette[i % t.palette.length]), borderWidth: 1.5 }] },
        options: { ...baseOptions(t), onHover: pointerOnHover, layout: { padding: 16 },
          onClick: (_e: unknown, els: { index: number }[], chart: Chart) => { const el = els[0]; if (!el) return; select((chart.data.datasets[0].data[el.index] as unknown as { f: Family }).f.family_id); },
          plugins: { ...(baseOptions(t).plugins as object), legend: { display: false }, tooltip: tip(t, {
            title: (items: { raw: unknown }[]) => (items[0].raw as { f: Family }).f.family_name,
            label: (c: { raw: unknown }) => { const f = (c.raw as { f: Family }).f; return [`2026 size: ${fmtInt(f.family_size)}`, `Population lift: ${lift(f.population_lift)}`, `Historical KEVs: ${f.historical_kev_count ?? '–'}`]; } }, 'Click to open') },
          scales: { x: axis(t, { type: 'logarithmic', title: axisTitle(t, '2026 family size (log scale)'), ticks: { color: t.text3, font: { size: 11 }, callback: (v: string | number) => ([500, 1000, 2000, 5000, 10000, 20000].includes(Number(v)) ? fmtInt(Number(v)) : '') } }),
            y: axis(t, { beginAtZero: true, title: axisTitle(t, 'Population lift (×)') }) } },
      }),
    }) : null,
  );
  stagger(grid);

  const paintList = () => {
    clear(listHost);
    const cols = ['Family', '2026 CVEs', 'In Top 500', 'Historical KEVs', 'Population KEV rate', 'Population lift', ...(showSample ? ['Sample KEV rate', 'Sample lift', '95% CI'] : [])];
    listHost.append(
      h('div', { class: 'table-wrap' }, h('table', { class: 'data-table' },
        h('caption', { class: 'sr-only' }, 'Families with 2026 size and historical rates'),
        h('thead', {}, h('tr', {}, cols.map((x, i) => h('th', { scope: 'col', class: i ? 'num' : null }, x)))),
        h('tbody', {}, famsRaw.map((f) => h('tr', {},
          h('th', { scope: 'row' }, h('button', { type: 'button', class: 'link-btn', 'data-fam': f.family_id, 'aria-pressed': 'false', onClick: () => select(f.family_id) }, `${f.family_id} · ${f.family_name}`), f.caveat ? h('span', { class: 'chip chip-warn' }, 'caveat') : null),
          h('td', { class: 'num' }, fmtInt(f.family_size)), h('td', { class: 'num' }, fmtInt(f.in_top500)), h('td', { class: 'num' }, fmtInt(f.historical_kev_count)),
          h('td', { class: 'num' }, fmtPct(f.population_kev_rate, 2)), h('td', { class: 'num' }, lift(f.population_lift)),
          ...(showSample ? [h('td', { class: 'num' }, fmtPct(f.sample_kev_rate, 1)), h('td', { class: 'num' }, lift(f.sample_lift)),
            h('td', { class: 'num' }, f.ci_95_low === null ? '–' : `${fmtPct(f.ci_95_low, 1)}–${fmtPct(f.ci_95_high, 1)}`)] : [])))))),
      ...(showSample ? [h('p', { class: 'state-body', role: 'note' }, caption ?? 'Sample rates come from the historical research cohort; use population rates for real-world probabilities.')] : []));
  };
  const toggle = h('button', { type: 'button', class: 'chip chip-toggle', 'aria-pressed': 'false', onClick: () => { showSample = !showSample; toggle.setAttribute('aria-pressed', String(showSample)); paintList(); } }, 'Show sample rates (research cohort)');
  paintList();
  const list = h('section', { class: 'card', 'aria-label': 'Family list' },
    h('div', { class: 'card-head' }, h('div', {}, h('h3', { class: 'card-title' }, 'All families'), h('p', { class: 'card-sub' }, `${BASIS}. Historical family patterns, not the probability for any 2026 CVE.`)), h('div', { class: 'card-tools' }, provenanceTag('observed'), toggle)),
    listHost);
  return h('div', { class: 'page-stack' }, grid, detail, list);
}

function bars(title: string, rows: Breakdown[]): HTMLElement {
  const top = rows.slice(0, 8);
  return h('div', { class: 'bd' }, h('h4', { class: 'sub-title' }, title),
    h('ul', { class: 'bd-list' }, top.map((r) => h('li', { class: 'bd-row' },
      h('span', { class: 'bd-label' }, r.label), h('span', { class: 'bd-track', 'aria-hidden': 'true' }, h('i', { style: `width:${Math.max(1, r.share * 100).toFixed(1)}%` })),
      h('span', { class: 'num bd-val' }, `${fmtPct(r.share, 1)} · ${fmtInt(r.count)}`)))));
}

function renderDetail(d: FamilyDetail): HTMLElement {
  const f = d.family;
  const chipsFor = (ids: string[]) => h('div', { class: 'chips' }, ids.map((id) => h('button', { type: 'button', class: 'chip chip-toggle', onClick: () => openCve(id) }, id)));
  return h('div', { class: 'family-body fade-in' },
    h('div', { class: 'card-head' },
      h('div', {}, h('h3', { class: 'card-title' }, `Family ${f.family_id}: ${f.family_name}`), f.top_characteristics ? h('p', { class: 'card-sub' }, f.top_characteristics) : null),
      h('div', { class: 'card-tools' }, provenanceTag('observed'),
        h('button', { type: 'button', class: 'btn', onClick: () => emitAsk(`Tell me about family ${f.family_id}`, `Family ${f.family_id}: ${f.family_name}`) }, 'Ask about this family'))),
    f.caveat ? h('div', { class: 'state state-waiting', role: 'note' }, h('p', { class: 'state-title' }, 'Family 8 caveat'), h('p', { class: 'state-body' }, f.caveat)) : null,
    h('dl', { class: 'facts facts-row' },
      fact('2026 CVEs', fmtInt(f.family_size)), fact('In Top 500', d.in_top500 === null ? 'not computed yet' : fmtInt(d.in_top500)),
      fact('Historical KEVs', fmtInt(f.historical_kev_count)), fact('Population KEV rate', fmtPct(f.population_kev_rate, 2)), fact('Population lift', lift(f.population_lift))),
    h('p', { class: 'muted' }, `${BASIS}. A historical family pattern, not the probability for any 2026 CVE.`),
    d.signal_counts ? h('div', { class: 'chips' }, SIGNALS.map((s) => h('span', { class: `chip chip-${s.key}` }, `${s.label}: ${fmtInt(d.signal_counts![s.key])}`))) : null,
    h('div', { class: 'grid grid-2' }, bars('Attack surface (2026 members, Granite extraction)', d.attack_surface), bars('Vulnerability type (2026 members, Granite extraction)', d.vulnerability_type)),
    d.historical_examples.length ? h('div', {}, h('h4', { class: 'sub-title' }, d.historical_examples_label), chipsFor(d.historical_examples)) : null,
    d.representative_2026.length ? h('div', {}, h('h4', { class: 'sub-title' }, d.representative_2026_label), chipsFor(d.representative_2026)) : null,
    h('h4', { class: 'sub-title' }, 'Top-ranked 2026 CVEs in this family ', provenanceTag('model')),
    (() => { const g = h('div', { class: 'mini-grid' }, d.top_cves.map((c) => cveMiniCard(c, openCve))); stagger(g, 8); return g; })());
}
const fact = (k: string, v: string) => h('div', { class: 'fact' }, h('dt', {}, k), h('dd', { class: 'num' }, v));
