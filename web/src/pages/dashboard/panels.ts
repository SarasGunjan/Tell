// Dashboard side panels and bottom charts. Every one re-renders from the shared store.
import type { Chart } from 'chart.js';
import type { BudgetPoint } from '../../api';
import { h, fmtEpss, fmtInt, fmtPct, reducedMotion, SIGNALS, type SignalKey } from '../../util';
import { chartCard, baseOptions, axis, axisTitle, tip, pointerOnHover, provenanceTag, alpha, type Registered, type Theme } from '../../charts';
import { explainButton } from '../../components/explain';
import { openCve } from '../../components/drawer';
import { familyWaiting } from '../../state';
import { waitingCard } from '../../components/ui';
import { fromSlider, toSlider, fmtEpssSlider } from '../top500';
import { EPSS_BINS, EPSS_LOG_MIN, epssBinLabel, familyCounts, scatterSample, type GalaxyData } from './data';
import type { Store } from './state';

const raf = (fn: () => void): (() => void) => { let p = 0; return () => { if (!p) p = requestAnimationFrame(() => { p = 0; fn(); }); }; };
const pctOf = (a: number, b: number) => (b ? (a / b) * 100 : 0);

/** Numbers swap with a 150ms cross-fade (no count-up). */
function setText(el: HTMLElement, text: string): void {
  if (el.textContent === text) return;
  el.textContent = text;
  if (!reducedMotion()) el.animate([{ opacity: 0.25 }, { opacity: 1 }], { duration: 150, easing: 'cubic-bezier(0.23,1,0.32,1)' });
}
function fillTable(card: HTMLElement, rows: (string | number)[][]): void {
  const tb = card.querySelector('table tbody');
  if (!tb) return;
  tb.replaceChildren(...rows.map((r) => h('tr', {}, r.map((c, i) => h(i === 0 ? 'th' : 'td', i === 0 ? { scope: 'row' } : {}, String(c))))));
}

// ------------------------------------------------------------------ filters rail
export function filtersRail(d: GalaxyData, store: Store, colors: string[]): HTMLElement {
  const seg = (label: string, scope: 'top500' | 'all') => h('button', { type: 'button', class: 'seg', onClick: () => store.set({ scope }) }, label);
  const sTop = seg('Top 500', 'top500'), sAll = seg('All CVEs', 'all');
  const scope = h('div', { class: 'seg-group', role: 'group', 'aria-label': 'Scope' }, sTop, sAll);

  const famBtns = d.families.map((f, i) => {
    const count = h('span', { class: 'num muted' }, '');
    const b = h('button', { type: 'button', class: 'fam-row', 'aria-pressed': 'false', title: f.family_name ?? f.family_id, onClick: () => store.set({ familyIdx: store.state.familyIdx === i ? null : i }) },
      h('i', { class: 'swatch', style: `background:${colors[i % (colors.length - 1)]}`, 'aria-hidden': 'true' }),
      h('span', { class: 'fam-name' }, f.family_name ?? f.family_id), count);
    return { b, count };
  });
  const famList = d.hasFamilies
    ? h('div', { class: 'fam-list' }, famBtns.map((x) => x.b))
    : h('p', { class: 'muted fam-wait', role: 'status' }, `Not computed yet. ${familyWaiting() ? 'Waiting on Member 2\'s family files.' : 'No family assignments in the loaded data.'}`);

  const sigBtns = SIGNALS.map((s) => {
    const avail = d.signals_available.includes(s.key);
    const b = h('button', { type: 'button', class: 'chip chip-toggle', 'aria-pressed': 'false', disabled: !avail, title: avail ? undefined : 'Not delivered yet', onClick: () => {
      const next = new Set(store.state.signals); next.has(s.key) ? next.delete(s.key) : next.add(s.key); store.set({ signals: next });
    } }, s.label);
    return { key: s.key, b };
  });

  const epss = h('input', { type: 'range', id: 'd-epss', min: '0', max: '100', step: '1', value: String(toSlider(store.state.minEpss)) }) as HTMLInputElement;
  const epssOut = h('output', { class: 'num', for: 'd-epss' }, fmtEpssSlider(store.state.minEpss));
  epss.addEventListener('input', () => { const v = fromSlider(Number(epss.value)); epssOut.textContent = fmtEpssSlider(v); store.set({ minEpss: v }); });

  const reset = h('button', { type: 'button', class: 'btn btn-sm', onClick: () => { store.reset(); } }, 'Reset');
  const anyAvail = d.signals_available.length > 0;

  const paint = () => {
    const s = store.state;
    sTop.setAttribute('aria-pressed', String(s.scope === 'top500')); sAll.setAttribute('aria-pressed', String(s.scope === 'all'));
    const counts = familyCounts(d, s);
    famBtns.forEach((x, i) => { x.b.setAttribute('aria-pressed', String(s.familyIdx === i)); setText(x.count, fmtInt(counts[i])); });
    sigBtns.forEach((x) => x.b.setAttribute('aria-pressed', String(s.signals.has(x.key))));
    if (document.activeElement !== epss) epss.value = String(toSlider(s.minEpss));
    epssOut.textContent = fmtEpssSlider(s.minEpss);
    reset.toggleAttribute('disabled', store.isDefault());
  };
  const paintSoon = raf(paint);
  store.subscribe((_s, c) => { if (c.has('filters')) paintSoon(); });
  paint();

  return h('aside', { class: 'card dash-rail', 'aria-label': 'Filters' },
    h('header', { class: 'card-head' }, h('h2', { class: 'card-title' }, 'Filters'), reset),
    h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Scope'), scope),
    h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Family', h('span', { class: 'muted' }, 'colour = galaxy arm')), famList),
    h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Public exploit signals', h('span', { class: 'muted' }, anyAvail ? 'all selected' : '')),
      h('div', { class: 'chips', role: 'group', 'aria-label': 'Public exploit signals' }, sigBtns.map((x) => x.b))),
    h('div', { class: 'field' }, h('label', { for: 'd-epss' }, 'Minimum EPSS', epssOut), epss));
}

// ------------------------------------------------------------------ focused-family card (overlay on the galaxy stage)
export function familyFocusCard(d: GalaxyData, store: Store, colors: string[], refocus: () => void): HTMLElement {
  const F = d.nFam, tot = new Int32Array(F), topTot = new Int32Array(F);
  for (let i = 0; i < d.n; i++) { const f = d.famA[i]; if (f >= 0 && f < F) { tot[f]++; if (d.topA[i]) topTot[f]++; } }
  const swatch = h('i', { class: 'swatch', 'aria-hidden': 'true' }), name = h('h3', { class: 'ff-name' });
  const vCves = h('dd', { class: 'num' }), vTop = h('dd', { class: 'num' }), vSig = h('dd', { class: 'num' });
  const link = h('a', { class: 'btn btn-sm', href: '#/families' }, 'View family →') as HTMLAnchorElement;
  const clear = h('button', { type: 'button', class: 'btn btn-sm btn-ghost', onClick: () => { store.set({ familyIdx: null }); refocus(); } }, 'Clear');
  const row = (k: string, v: HTMLElement, tip?: string) => h('div', { class: 'ff-row', title: tip }, h('dt', {}, k), v);
  const el = h('section', { class: 'ff-card', 'aria-label': 'Focused family', hidden: true },
    h('div', { class: 'ff-head' }, swatch, name),
    h('dl', { class: 'ff-facts' },
      row('CVEs matching', vCves), row('In Top 500', vTop),
      row('Public exploit code (snapshot)', vSig, 'Any of Exploit-DB, Metasploit, Nuclei or GitHub PoC (observed signals, snapshot)')),
    h('div', { class: 'ff-prov' }, provenanceTag('granite')),
    h('div', { class: 'ff-actions' }, link, clear));
  const of = (a: number, b: number) => (a === b ? fmtInt(b) : `${fmtInt(a)} of ${fmtInt(b)}`);
  const paint = () => {
    const f = store.state.familyIdx;
    if (f === null) { el.hidden = true; return; }
    const s = store.derived.summary, fam = d.families[f], fresh = el.hidden;
    swatch.style.background = colors[f % (colors.length - 1)];
    name.textContent = fam.family_name ?? fam.family_id;
    vCves.textContent = of(s.count, tot[f]); vTop.textContent = of(s.top500, topTot[f]);
    vSig.textContent = !d.signals_available.length ? 'not delivered yet' : s.count ? `${fmtPct(s.withSignal / s.count)} · ${fmtInt(s.withSignal)}` : '–';
    link.href = `#/families?fam=${encodeURIComponent(fam.family_id)}`;
    if (fresh) {
      el.hidden = false;
      if (!reducedMotion()) el.animate([{ opacity: 0, transform: 'translateY(6px)' }, { opacity: 1, transform: 'none' }], { duration: 180, easing: 'ease-out' });
    }
  };
  const paintSoon = raf(paint);
  store.subscribe((_s, c) => { if (c.has('filters')) paintSoon(); });
  paint();
  return el;
}

// ------------------------------------------------------------------ selection panel
export function selectionPanel(d: GalaxyData, store: Store, colors: string[]): HTMLElement {
  const tile = (label: string, kind: Parameters<typeof provenanceTag>[0]) => {
    const v = h('div', { class: 'dkpi-value num' }, '–'), sub = h('div', { class: 'kpi-sub' }, '');
    return { v, sub, el: h('div', { class: 'dkpi' }, h('span', { class: 'label' }, label), v, sub, h('div', { class: 'kpi-foot' }, provenanceTag(kind))) };
  };
  const tMatch = tile('CVEs matching', 'snapshot'), tTop = tile('In Top 500', 'model'), tSig = tile('With public exploit signal', 'snapshot'), tEpss = tile('Median EPSS', 'snapshot');
  const kpis = h('section', { class: 'card', 'data-explain': 'dash-kpis', 'aria-label': 'Selection summary' },
    h('header', { class: 'card-head' }, h('h2', { class: 'card-title' }, 'Selection'), explainButton('dash-kpis', 'Selection summary')),
    h('div', { class: 'dkpi-grid', 'aria-live': 'polite' }, tMatch.el, tTop.el, tSig.el, tEpss.el));

  // ---- Top CVEs in view
  const list = h('ol', { class: 'dash-list' });
  const listCard = h('section', { class: 'card', 'aria-label': 'Top CVEs in view' },
    h('header', { class: 'card-head' }, h('div', {}, h('h3', { class: 'card-title' }, 'Top CVEs in view'), h('p', { class: 'card-sub' }, `Highest rank (${d.ranking_method}) in the selection`)), provenanceTag('model')), list);

  // ---- mini charts
  const allHist = new Array(EPSS_BINS).fill(0) as number[];
  const allSig: Record<SignalKey, number> = { exploitdb: 0, metasploit: 0, nuclei: 0, poc_github: 0 };
  for (let i = 0; i < d.n; i++) {
    allHist[Math.min(EPSS_BINS - 1, Math.max(0, d.epssA[i] <= 0 ? 0 : Math.floor(((Math.log10(d.epssA[i]) - EPSS_LOG_MIN) / -EPSS_LOG_MIN) * EPSS_BINS)))]++;
  }
  void allSig;
  const edgePct = (b: number) => fmtEpss(10 ** (EPSS_LOG_MIN + (b * -EPSS_LOG_MIN) / EPSS_BINS));
  let epssReg: Registered | null = null, sigReg: Registered | null = null;
  const sumNow = () => store.derived.summary;
  const epssData = () => { const s = sumNow(); return { sel: s.hist.map((c) => pctOf(c, s.count)), all: allHist.map((c) => pctOf(c, d.n)) }; };
  const epssCard = chartCard({
    target: 'chart-epss-dist', title: 'EPSS distribution', subtitle: 'Share of the selection vs all CVEs in each log-spaced bin', provenance: 'snapshot', height: 170,
    summary: 'EPSS distribution of the current selection versus all scored CVEs, as a share of each group in log-spaced bins. The data table has the bin values.',
    table: { head: ['EPSS bin', 'All CVEs (%)', 'Selection (%)'], rows: allHist.map((_, b) => [epssBinLabel(b), pctOf(allHist[b], d.n).toFixed(2), pctOf(sumNow().hist[b], sumNow().count).toFixed(2)]) },
    build: (t) => {
      const e = epssData();
      return {
        type: 'bar' as const,
        data: { labels: allHist.map((_, b) => edgePct(b)), datasets: [
          { label: 'All CVEs', data: e.all, backgroundColor: t.all, borderRadius: 1 },
          { label: 'Selection', data: e.sel, backgroundColor: t.top, borderRadius: 1 }] },
        options: { ...baseOptions(t), interaction: { mode: 'index' as const, intersect: false },
          plugins: { ...(baseOptions(t).plugins as object), legend: { position: 'bottom' as const, labels: { color: t.text2, boxWidth: 10, boxHeight: 10, font: { size: 11 } } },
            tooltip: tip(t, { title: (it: { dataIndex: number }[]) => `EPSS ${epssBinLabel(it[0].dataIndex)}`, label: (c: { dataset: { label?: string }; parsed: { y: number | null } }) => ` ${c.dataset.label}: ${(c.parsed.y ?? 0).toFixed(1)}%` }) },
          scales: { x: axis(t, { grid: { display: false }, ticks: { color: t.text3, maxRotation: 0, autoSkip: true, maxTicksLimit: 5, font: { size: 10 } } }), y: axis(t, { beginAtZero: true, ticks: { color: t.text3, callback: (v: string | number) => `${v}%`, font: { size: 10 }, maxTicksLimit: 4 } }) } },
      };
    },
    onReady: (r) => { epssReg = r; },
  });

  const sigPct = (k: SignalKey) => pctOf(sumNow().sigCounts[k], sumNow().count);
  const sigCard = chartCard({
    target: 'chart-signals', title: 'Exploit signals in selection', subtitle: 'Click a bar to filter by that signal', provenance: 'snapshot', height: 150,
    summary: 'Share of the current selection with each public exploit signal. Activating a bar toggles that signal as a filter.',
    actionsLabel: 'Toggle signal filter',
    actions: SIGNALS.filter((s) => d.signals_available.includes(s.key)).map((s) => ({ label: s.label, run: () => { const n2 = new Set(store.state.signals); n2.has(s.key) ? n2.delete(s.key) : n2.add(s.key); store.set({ signals: n2 }); } })),
    table: { head: ['Signal', 'CVEs in selection', 'Share'], rows: SIGNALS.map((s) => [s.label, sumNow().sigCounts[s.key], `${sigPct(s.key).toFixed(1)}%`]) },
    build: (t) => ({
      type: 'bar' as const,
      data: { labels: SIGNALS.map((s) => s.label), datasets: [{ label: 'Selection', data: SIGNALS.map((s) => sigPct(s.key)),
        backgroundColor: SIGNALS.map((s) => (store.state.signals.has(s.key) ? t.accent : alpha(t.top, 0.55))), borderRadius: 2 }] },
      options: { ...baseOptions(t), indexAxis: 'y' as const,
        onClick: (_e: unknown, els: { index: number }[]) => { const k = els[0] && SIGNALS[els[0].index]; if (k && d.signals_available.includes(k.key)) { const n2 = new Set(store.state.signals); n2.has(k.key) ? n2.delete(k.key) : n2.add(k.key); store.set({ signals: n2 }); } },
        onHover: pointerOnHover,
        plugins: { ...(baseOptions(t).plugins as object), legend: { display: false },
          tooltip: tip(t, { label: (c: { dataIndex: number; parsed: { x: number | null } }) => ` ${(c.parsed.x ?? 0).toFixed(1)}% (${fmtInt(sumNow().sigCounts[SIGNALS[c.dataIndex].key])} of ${fmtInt(sumNow().count)})` }, 'Click to toggle this filter') },
        scales: { x: axis(t, { beginAtZero: true, max: 100, ticks: { color: t.text3, callback: (v: string | number) => `${v}%`, font: { size: 10 }, maxTicksLimit: 5 } }), y: axis(t, { grid: { display: false }, ticks: { color: t.text2, font: { size: 11 } } }) } },
    }),
    onReady: (r) => { sigReg = r; },
  });

  function refresh(): void {
    const s = sumNow(), st = store.state;
    setText(tMatch.v, fmtInt(s.count)); tMatch.sub.textContent = `of ${fmtInt(d.n)} scored`;
    setText(tTop.v, fmtInt(s.top500)); tTop.sub.textContent = s.count ? `${fmtPct(s.top500 / s.count)} of selection` : 'nothing selected';
    setText(tSig.v, s.count ? fmtPct(s.withSignal / s.count) : '–'); tSig.sub.textContent = d.signals_available.length ? `${fmtInt(s.withSignal)} CVEs` : 'signals not delivered yet';
    setText(tEpss.v, s.medianEpss === null ? '–' : fmtEpss(s.medianEpss)); tEpss.sub.textContent = '';
    // list
    list.replaceChildren(...(s.firstIdx.length ? s.firstIdx.slice(0, 8).map((i) => {
      const id = d.ids[i], f = d.famA[i];
      const b = h('button', { type: 'button', class: 'dash-row', 'data-id': id,
        onClick: () => openCve(id), onPointerEnter: () => store.set({ hoverId: id }), onPointerLeave: () => store.set({ hoverId: null }),
        onFocus: () => store.set({ hoverId: id }), onBlur: () => store.set({ hoverId: null }) },
        h('i', { class: 'swatch', style: `background:${f >= 0 ? colors[f % (colors.length - 1)] : colors[colors.length - 1]}`, 'aria-hidden': 'true' }),
        h('span', { class: 'mono' }, id), h('span', { class: 'num muted' }, `#${fmtInt(d.rank[i])}`), h('span', { class: 'num muted dash-row-epss' }, fmtEpss(d.epssA[i])));
      return h('li', {}, b);
    }) : [h('li', { class: 'muted pad' }, 'No CVEs match these filters.')]));
    markHover();
    // charts
    const e = epssData();
    if (epssReg?.chart) { const c = epssReg.chart as Chart; c.data.datasets[0].data = e.all; c.data.datasets[1].data = e.sel; c.update(reducedMotion() ? 'none' : undefined); }
    if (sigReg?.chart) {
      const c = sigReg.chart as Chart, t = c.options as unknown;
      void t;
      c.data.datasets[0].data = SIGNALS.map((x) => sigPct(x.key));
      const acc = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim(), top = getComputedStyle(document.documentElement).getPropertyValue('--data-top').trim();
      c.data.datasets[0].backgroundColor = SIGNALS.map((x) => (st.signals.has(x.key) ? acc : alpha(top, 0.55)));
      c.update(reducedMotion() ? 'none' : undefined);
    }
    fillTable(epssCard, allHist.map((_, b) => [epssBinLabel(b), pctOf(allHist[b], d.n).toFixed(2), pctOf(s.hist[b], s.count).toFixed(2)]));
    fillTable(sigCard, SIGNALS.map((x) => [x.label, s.sigCounts[x.key], `${sigPct(x.key).toFixed(1)}%`]));
  }
  function markHover(): void {
    const id = store.state.hoverId;
    list.querySelectorAll<HTMLElement>('.dash-row').forEach((b) => b.classList.toggle('is-hover', b.dataset.id === id));
  }
  const refreshSoon = raf(refresh);
  store.subscribe((_s, c) => { if (c.has('filters')) refreshSoon(); else if (c.has('hoverId')) markHover(); });
  refresh();

  return h('div', { class: 'dash-side' }, kpis, listCard, epssCard, sigCard);
}

// ------------------------------------------------------------------ scatter: EPSS vs model score
export function scatterCard(d: GalaxyData, store: Store, colors: string[]): HTMLElement {
  const sample = scatterSample(d, 4000);
  const ix = sample.idx;
  const pts = Array.from(ix, (i) => ({ x: d.epssA[i], y: d.rank[i] }));
  const pos = new Map<string, number>();
  ix.forEach((i, p) => pos.set(d.ids[i], p));
  let minE = 1;
  for (const p of pts) if (p.x < minE) minE = p.x;
  const xMin = 10 ** Math.floor(Math.log10(minE));
  const famHex = (f: number) => (f >= 0 ? colors[f % (colors.length - 1)] : colors[colors.length - 1]);
  const cache = new Map<string, string>();
  const col = (f: number, a: number) => { const k = `${f}|${a}`; let v = cache.get(k); if (!v) { v = alpha(famHex(f), a); cache.set(k, v); } return v; };
  const style = () => {
    const m = store.derived.match;
    return {
      bg: Array.from(ix, (i) => col(d.famA[i], m[i] ? (d.topA[i] ? 0.95 : 0.5) : 0.07)),
      r: Array.from(ix, (i) => (d.topA[i] ? 3.6 : 2.2)),
    };
  };
  let reg: Registered | null = null;
  const lbl = (c: { dataIndex: number }) => d.ids[ix[c.dataIndex]];
  const card = chartCard({
    target: 'chart-scatter', title: 'EPSS vs rank', subtitle: 'All Top 500 + 4,000 sampled (fixed by CVE id hash). Hover a dot to find it in the galaxy.', provenance: 'mixed', height: 300,
    summary: `Scatter of EPSS (observed snapshot signal, log scale) against rank (${d.ranking_method}, not a probability; rank 1 at the top) for ${fmtInt(ix.length)} CVEs: every Top 500 CVE with EPSS above zero and a fixed sample of 4,000 others.${sample.zeroEpssTop ? ` ${sample.zeroEpssTop} Top 500 CVEs with EPSS of 0 cannot be shown on a log axis.` : ''}`,
    table: { head: ['CVE', 'EPSS', 'Rank'], rows: Array.from(ix.slice(-30).reverse(), (i) => [d.ids[i], fmtEpss(d.epssA[i]), d.rank[i]]) },
    extra: h('div', { class: 'scatter-key' }, provenanceTag('snapshot'), h('span', { class: 'muted' }, 'x: EPSS'), provenanceTag('model'), h('span', { class: 'muted' }, `y: rank (${d.ranking_method})`)),
    build: (t) => {
      const s = style();
      return {
        type: 'scatter' as const,
        data: { datasets: [{ label: 'CVEs', data: pts, pointBackgroundColor: s.bg, pointRadius: s.r, pointHoverRadius: 6, pointHitRadius: 7, pointBorderWidth: 0, borderWidth: 0 }] },
        options: { ...baseOptions(t), animation: false, interaction: { mode: 'nearest' as const, intersect: true },
          onHover: (e: { native?: Event | null }, els: { index: number }[]) => { pointerOnHover(e, els); store.set({ hoverId: els[0] ? d.ids[ix[els[0].index]] : null }); },
          onClick: (_e: unknown, els: { index: number }[]) => { if (els[0]) openCve(d.ids[ix[els[0].index]]); },
          plugins: { ...(baseOptions(t).plugins as object), legend: { display: false },
            tooltip: tip(t, { title: (it: { dataIndex: number }[]) => lbl(it[0]), label: (c: { dataIndex: number }) => { const i = ix[c.dataIndex]; return [` EPSS ${fmtEpss(d.epssA[i])}`, ` Rank #${fmtInt(d.rank[i])} (${d.ranking_method})`]; } }, 'Click to open') },
          scales: {
            x: axis(t, { type: 'logarithmic', min: xMin, max: 1, title: axisTitle(t, 'EPSS (log scale)'), ticks: { color: t.text3, font: { size: 10 }, callback: (v: string | number) => (Number.isInteger(Math.round(Math.log10(Number(v)) * 1e6) / 1e6) ? fmtEpss(Number(v)) : '') } }),
            y: axis(t, { type: 'logarithmic', reverse: true, min: 1, title: axisTitle(t, `Rank (${d.ranking_method}), log scale, #1 on top`), ticks: { color: t.text3, font: { size: 10 }, callback: (v: string | number) => (Number.isInteger(Math.round(Math.log10(Number(v)) * 1e6) / 1e6) ? fmtInt(Number(v)) : '') } }),
          } },
      };
    },
    onReady: (r) => {
      reg = r;
      r.chart?.config.plugins?.push?.({
        id: 'galaxyLink',
        afterDatasetsDraw(chart: Chart) {
          const id = store.state.hoverId, p = id ? pos.get(id) : undefined;
          if (p === undefined) return;
          const el = chart.getDatasetMeta(0).data[p];
          if (!el) return;
          const c = chart.ctx; c.save();
          c.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim(); c.lineWidth = 2;
          c.beginPath(); c.arc(el.x, el.y, 8, 0, Math.PI * 2); c.stroke(); c.restore();
        },
      } as never);
    },
  });
  const redraw = raf(() => reg?.chart?.draw());
  const restyle = raf(() => {
    const c = reg?.chart; if (!c) return;
    const s = style(); const ds = c.data.datasets[0] as unknown as Record<string, unknown>;
    ds.pointBackgroundColor = s.bg; c.update('none');
  });
  store.subscribe((_s, ch) => { if (ch.has('filters')) restyle(); else if (ch.has('hoverId')) redraw(); });
  return card;
}

// ------------------------------------------------------------------ patch budget
export function budgetCard(pts: BudgetPoint[], store: Store, method: string): HTMLElement {
  if (!pts.length) return waitingCard('Patch budget', 'Waiting on Member 1\'s patch_budget.csv');
  const models = [...new Set(pts.map((p) => p.model))];
  const budgets = [...new Set(pts.map((p) => p.budget))].sort((a, b) => a - b); // measured points only, never a curve
  const isRank = (m: string) => m.toLowerCase() === method.toLowerCase();
  const hitsOf = (m: string, k: number) => pts.find((p) => p.model === m && p.budget === k)?.hits ?? null;
  const idx = (m: string) => models.filter((x) => !isRank(x)).indexOf(m);
  const colorOf = (t: Theme, m: string) => (isRank(m) ? t.top : t.palette[idx(m) % t.palette.length]);
  const derived = pts.some((p) => p.derived);
  let reg: Registered | null = null;
  const chips = models.map((m) => h('button', { type: 'button', class: 'chip chip-toggle', 'aria-pressed': 'false', onClick: () => store.set({ highlightModel: store.state.highlightModel === m ? null : m }) },
    h('i', { class: 'swatch', style: `background:var(${isRank(m) ? '--data-top' : ['--data-a', '--data-b', '--data-c', '--data-d', '--data-f', '--data-h'][idx(m) % 6]})`, 'aria-hidden': 'true' }), m));
  const hl = () => store.state.highlightModel;
  const barStyle = (t: Theme, m: string) => {
    const on = hl() === m, focus = hl() !== null, emph = focus ? on : isRank(m);
    const c = colorOf(t, m);
    return { backgroundColor: emph ? c : alpha(c, focus ? 0.25 : 0.55), borderColor: emph ? c : 'transparent', borderWidth: emph ? 1.5 : 0 };
  };
  const card = chartCard({
    target: 'chart-budget', title: 'Patch budget', subtitle: `KEV additions caught if a team can review only K CVEs (validation backtest). Measured at ${budgets.length} budgets only${derived ? ' (derived from model metrics)' : ''}.`, provenance: 'observed', height: 300,
    summary: `Hits at ${budgets.join(', ')} reviewed CVEs for ${models.length} models, measured at those budgets only. ${models.filter(isRank).map((m) => `${m}: ${budgets.map((k) => hitsOf(m, k)).join(', ')}.`).join(' ')}`,
    table: { head: ['Model', ...budgets.map((k) => `Hits@${k}`)], rows: models.map((m) => [m, ...budgets.map((k) => hitsOf(m, k) ?? '–')]) },
    extra: h('div', { class: 'chips budget-chips', role: 'group', 'aria-label': 'Highlight a model' }, chips),
    build: (t) => ({
      type: 'bar' as const,
      data: { labels: budgets.map(String), datasets: models.map((m) => ({ label: m, data: budgets.map((k) => hitsOf(m, k)), borderRadius: 2, ...barStyle(t, m) })) },
      options: { ...baseOptions(t), interaction: { mode: 'nearest' as const, intersect: true },
        onClick: (_e: unknown, els: { datasetIndex: number }[]) => { if (els[0]) { const m = models[els[0].datasetIndex]; store.set({ highlightModel: hl() === m ? null : m }); } },
        onHover: pointerOnHover,
        plugins: { ...(baseOptions(t).plugins as object), legend: { display: false }, tooltip: tip(t, { title: (it: { dataset: { label?: string } }[]) => it[0].dataset.label ?? '', label: (c: { parsed: { y: number | null }; label: string }) => ` ${c.parsed.y} hits in the top ${c.label}` }, 'Click to highlight this model') },
        scales: {
          x: axis(t, { title: axisTitle(t, 'Review budget K (CVEs)'), grid: { display: false }, ticks: { color: t.text3, font: { size: 11 } } }),
          y: axis(t, { beginAtZero: true, title: axisTitle(t, 'Hits (KEV additions caught)'), ticks: { color: t.text3, precision: 0, font: { size: 11 } } }),
        } },
    }),
    onReady: (r) => { reg = r; },
  });
  const paint = raf(() => {
    chips.forEach((b, i) => b.setAttribute('aria-pressed', String(hl() === models[i])));
    const c = reg?.chart; if (!c) return;
    const cs = getComputedStyle(document.documentElement);
    const pal = ['--data-a', '--data-b', '--data-c', '--data-d', '--data-f', '--data-h'].map((v) => cs.getPropertyValue(v).trim());
    const t = { top: cs.getPropertyValue('--data-top').trim(), palette: pal } as Theme;
    models.forEach((m, i) => Object.assign(c.data.datasets[i], barStyle(t, m)));
    c.update(reducedMotion() ? 'none' : undefined);
  });
  store.subscribe((_s, ch) => { if (ch.has('highlightModel')) paint(); });
  return card;
}
