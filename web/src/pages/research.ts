import { api, type Research } from '../api';
import { h, fmtPct, fmtInt } from '../util';
import { chartCard, baseOptions, axis, axisTitle, alpha, provenanceTag, tip, type Theme } from '../charts';
import { explainButton } from '../components/explain';
import { loadInto, skeleton, emptyState } from '../components/ui';
import { pageHead } from './shared';

const wrap = (name: string): string | string[] => {
  if (name.length <= 26) return name;
  const cut = name.lastIndexOf(' ', 26);
  return cut > 0 ? [name.slice(0, cut), name.slice(cut + 1)] : name;
};

function section(target: string, kicker: string, title: string, prov: string, cohort: string, ...body: (Node | null)[]): HTMLElement {
  return h('section', { class: 'card story-sect', 'data-explain': target, 'aria-label': title },
    h('header', { class: 'card-head' },
      h('div', {}, h('p', { class: 'story-kicker' }, kicker), h('h2', { class: 'card-title' }, title)),
      h('div', { class: 'card-tools' }, h('span', { class: 'chip' }, prov), explainButton(target, title))),
    h('p', { class: 'muted' }, cohort), ...body);
}
const stat = (label: string, value: string, sub?: string) => h('div', { class: 'fact' }, h('dt', {}, label), h('dd', { class: 'num big' }, value), sub ? h('span', { class: 'muted' }, sub) : null);

function render(r: Research): HTMLElement {
  if (!r.available) return emptyState('Not computed yet', r.waiting);
  const cap = h('p', { class: 'state-body', role: 'note' }, r.sample_caption);
  const fams = r.families?.data ?? [];
  const nameOf = (id: string) => fams.find((f) => f.family_id === id)?.family_name ?? `Family ${id}`;
  const sections: (HTMLElement | null)[] = [];

  const c = r.concentration, f = r.families;
  if (c) {
    const d = c.data;
    sections.push(section('research-concentration', 'Act 1 · Where exploitation concentrates', 'Three families hold most of the KEVs', c.provenance, c.cohort_label,
      h('div', { class: 'big-stat' }, stat('Share of all KEVs', fmtPct(d.kev_share), `top 3 families (${d.method})`), stat('Share of CVE volume', fmtPct(d.population_volume_share), 'population-weighted'), stat('Concentration', `${d.population_ratio.toFixed(2)}×`, 'KEV share ÷ volume share')),
      f && f.data.some((x) => x.population_lift !== null) ? chartCard({
        target: 'research-concentration-lift', title: 'Population lift by family', subtitle: 'Historical, population-weighted. 1.0× = the average CVE.', provenance: 'observed', height: 300,
        summary: `Population lift per family: ${f.data.map((x) => `${x.family_name} ${x.population_lift?.toFixed(2)}×`).join('; ')}.`,
        table: { head: ['Family', 'Population KEV rate', 'Lift'], rows: f.data.map((x) => [x.family_name, fmtPct(x.population_kev_rate, 2), x.population_lift?.toFixed(2) ?? '–']) },
        build: (t: Theme) => ({ type: 'bar' as const,
          data: { labels: f.data.map((x) => wrap(`${x.family_id} · ${x.family_name}`)), datasets: [{ label: 'Population lift', data: f.data.map((x) => x.population_lift), backgroundColor: f.data.map((x) => ((x.population_lift ?? 0) >= 1 ? t.risk : alpha(t.top, 0.45))), borderRadius: 3 }] },
          options: { ...baseOptions(t), plugins: { ...(baseOptions(t).plugins as object), legend: { display: false }, tooltip: tip(t) },
            scales: { x: axis(t, { grid: { display: false }, ticks: { color: t.text3, font: { size: 10 }, maxRotation: 0 } }), y: axis(t, { beginAtZero: true, title: axisTitle(t, 'Lift (×)') }) } } }),
      }) : null, cap));
  }
  const tp = r.temporal;
  if (tp) {
    const d = tp.data, hd = d.headline, rows = d.rows;
    sections.push(section('research-temporal', 'Act 2 · Does it hold out of time?', `Rank on ${d.train_year ?? '2024'}, check on ${d.val_year ?? '2025'}`, tp.provenance, tp.cohort_label,
      hd ? h('div', { class: 'big-stat' }, stat('Share of 2025 KEVs', fmtPct(hd.kev_share), `${hd.val_kev_top3} of ${hd.val_kev_total}`), stat('Share of 2025 CVEs', fmtPct(hd.volume_share), `${fmtInt(hd.val_n_top3)} of ${fmtInt(hd.val_n_total)}`), stat('Enrichment', `${hd.lift.toFixed(2)}×`, `top 3 by ${d.train_year ?? '2024'} rate: ${hd.top3_family_ids.map(nameOf).join(', ')}`)) : null,
      hd && hd.matches_reported !== null ? h('p', { class: 'muted' }, hd.matches_reported ? 'Computed from the per-family file and matches the figures reported in research_metrics.json.' : 'Computed from the per-family file; it differs from research_metrics.json.') : null,
      chartCard({
        target: 'research-temporal-chart', title: 'Lift by family: training year vs validation year', subtitle: 'Sample lift within the research cohort', provenance: 'observed', height: 300,
        summary: `Per-family lift in ${d.train_year} and ${d.val_year}.`,
        table: { head: ['Family', 'Train rate', 'Train lift', 'Val rate', 'Val lift'], rows: rows.map((x) => [nameOf(x.family_id), fmtPct(x.train_2024_rate), x.train_2024_lift, fmtPct(x.val_2025_rate), x.val_2025_lift]) },
        build: (t: Theme) => ({ type: 'bar' as const,
          data: { labels: rows.map((x) => wrap(`${x.family_id} · ${nameOf(x.family_id)}`)), datasets: [
            { label: `${d.train_year} (train)`, data: rows.map((x) => x.train_2024_lift), backgroundColor: t.all, borderRadius: 3 },
            { label: `${d.val_year} (validation)`, data: rows.map((x) => x.val_2025_lift), backgroundColor: t.top, borderRadius: 3 }] },
          options: { ...baseOptions(t), plugins: { ...(baseOptions(t).plugins as object), tooltip: tip(t) },
            scales: { x: axis(t, { grid: { display: false }, ticks: { color: t.text3, font: { size: 10 }, maxRotation: 0 } }), y: axis(t, { beginAtZero: true, title: axisTitle(t, 'Lift (×)') }) } } }),
      }), cap));
  }
  const bl = r.baselines;
  if (bl) {
    const rows = bl.data.filter((x) => x.population_top3_concentration_ratio !== null);
    sections.push(section('research-baselines', 'Act 3 · Is Granite better than simple groupings?', 'Baseline comparison', bl.provenance, bl.cohort_label,
      h('p', { class: 'muted' }, bl.note ?? ''),
      chartCard({
        target: 'research-baselines-chart', title: 'Top-3 concentration ratio by method', subtitle: 'Population-weighted. Coverage is the share of CVEs the method could place.', provenance: 'observed', height: 280,
        summary: `Concentration ratio by method: ${rows.map((x) => `${x.method} ${x.population_top3_concentration_ratio?.toFixed(2)}× at ${fmtPct(x.non_missing_coverage, 0)} coverage`).join('; ')}.`,
        table: { head: ['Method', 'Concentration ratio', 'Coverage'], rows: rows.map((x) => [x.method, x.population_top3_concentration_ratio?.toFixed(2) ?? '–', fmtPct(x.non_missing_coverage, 0)]) },
        build: (t: Theme) => ({ type: 'bar' as const,
          data: { labels: rows.map((x) => wrap(`${x.method} (${fmtPct(x.non_missing_coverage, 0)} coverage)`)), datasets: [{ label: 'Concentration ratio', data: rows.map((x) => x.population_top3_concentration_ratio), backgroundColor: rows.map((x) => (/granite/i.test(x.method) ? t.top : t.all)), borderRadius: 3 }] },
          options: { ...baseOptions(t), plugins: { ...(baseOptions(t).plugins as object), legend: { display: false }, tooltip: tip(t) },
            scales: { x: axis(t, { grid: { display: false }, ticks: { color: t.text3, font: { size: 10 }, maxRotation: 0 } }), y: axis(t, { beginAtZero: true, title: axisTitle(t, 'KEV share ÷ volume share (×)') }) } } }),
      }), h('p', { class: 'muted' }, 'Keyword rules and CWE categories leave some CVEs ungrouped, which can flatter their ratio; Granite embeddings cover every CVE.')));
  }
  const cw = r.cwe;
  if (cw) {
    const d = cw.data;
    const shade = (v: number | null) => (v === null ? '' : `background:color-mix(in srgb, var(--accent) ${Math.round(Math.min(1, v) * 70)}%, transparent)`);
    sections.push(section('research-cwe', 'Act 4 · What weaknesses sit inside the families?', 'CWE × family', cw.provenance, cw.cohort_label,
      h('p', { class: 'muted' }, cw.note ?? ''),
      h('div', { class: 'table-wrap' }, h('table', { class: 'heat' },
        h('caption', { class: 'sr-only' }, 'Share of each family’s CVEs carrying each of the twelve most common CWEs'),
        h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'CWE'), d.families.map((fid) => h('th', { scope: 'col', title: nameOf(fid) }, `F${fid}`)))),
        h('tbody', {}, d.rows.map((row) => h('tr', {}, h('th', { scope: 'row', title: row.cwe_name ?? '' }, `${row.cwe_id} · ${fmtInt(row.total)}`),
          d.families.map((fid) => { const cell = row.cells[fid]; return cell ? h('td', { style: shade(cell.share), title: `${fmtInt(cell.count)} CVEs` }, cell.share === null ? String(cell.count) : fmtPct(cell.share, 0)) : h('td', { class: 'blank', 'aria-label': 'not listed' }, '·'); })))))),
      h('p', { class: 'muted' }, `${fmtInt(d.unassigned)} cohort CVEs have no CWE assigned and are left out. Family names: ${d.families.map((fid) => `F${fid} ${nameOf(fid)}`).join(' · ')}.`), cap));
  }
  const co = r.cohort;
  return h('div', { class: 'page-stack' },
    h('section', { class: 'card note', 'aria-label': 'Cohort' },
      h('div', { class: 'card-head' }, h('h3', { class: 'card-title' }, r.cohort_label), provenanceTag('observed')),
      h('p', { class: 'muted' }, `Separate from the 2026 benchmark. ${co.kev_total ? `${co.kev_total} KEVs` : ''}${co.population_total_cves ? ` out of ${fmtInt(co.population_total_cves)} CVEs in the population` : ''}${co.mean_cosine_cohesion !== null ? ` · mean cohesion ${co.mean_cosine_cohesion}` : ''}${co.silhouette_cosine !== null ? ` · silhouette ${co.silhouette_cosine}` : ''}${co.embedding_model ? ` · ${co.embedding_model}` : ''}.`),
      h('ul', { class: 'bullets' }, r.caveats.map((x) => h('li', {}, x)))),
    ...sections);
}

export function mountResearch(root: HTMLElement): void {
  root.appendChild(pageHead('Discoveries', 'What IBM Granite embeddings found in 2,500 historical CVEs: where exploitation concentrates and whether it holds up out of time.'));
  const host = h('div', { class: 'page-host' });
  root.appendChild(host);
  void loadInto(host, () => api.research(), render, skeleton(6, true));
}
