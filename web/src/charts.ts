import {
  Chart, BarController, LineController, BubbleController, ScatterController,
  CategoryScale, LinearScale, LogarithmicScale,
  BarElement, LineElement, PointElement, Tooltip, Legend,
  type ChartConfiguration,
} from 'chart.js';
import { h, reducedMotion } from './util';
import { explainButton } from './components/explain';
import { state } from './state';

Chart.register(BarController, LineController, BubbleController, ScatterController, CategoryScale, LinearScale, LogarithmicScale,
  BarElement, LineElement, PointElement, Tooltip, Legend);

export type Theme = {
  text: string; text2: string; text3: string; line: string; surface: string; surface2: string;
  top: string; accent: string; all: string; risk: string; grid: string; sans: string; mono: string; palette: string[];
};
export function theme(): Theme {
  const cs = getComputedStyle(document.documentElement);
  const v = (n: string) => cs.getPropertyValue(n).trim();
  return {
    text: v('--text'), text2: v('--text-2'), text3: v('--text-3'), line: v('--line'),
    surface: v('--surface-1'), surface2: v('--surface-3'),
    top: v('--data-top'), accent: v('--accent'), all: v('--data-all'), risk: v('--data-risk'), grid: v('--grid'),
    sans: v('--font-sans'), mono: v('--font-mono'),
    // categorical order; red (= high-risk) and blue (= Tell) are reserved and left out
    palette: ['--data-a', '--data-b', '--data-c', '--data-d', '--data-f', '--data-h'].map(v),
  };
}
export const alpha = (hex: string, a: number): string => {
  const m = /^#([0-9a-f]{6})$/i.exec(hex);
  if (!m) return hex;
  const n = parseInt(m[1], 16);
  return `rgb(${(n >> 16) & 255} ${(n >> 8) & 255} ${n & 255} / ${a})`;
};

/** Shared Chart.js defaults: subtle motion, theme-aware axes, 150ms hover. */
export function baseOptions(t: Theme): Record<string, unknown> {
  const rm = reducedMotion();
  Chart.defaults.font.family = t.sans;
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: rm ? false : {
      duration: 500,
      easing: 'easeOutQuart',
      delay: (ctx: { type: string; mode: string; dataIndex: number }) =>
        ctx.type === 'data' && ctx.mode === 'default' ? Math.min(ctx.dataIndex, 8) * 15 : 0,
    },
    transitions: { active: { animation: { duration: rm ? 0 : 150 } } },
    interaction: { mode: 'nearest', intersect: true },
    plugins: {
      legend: { labels: { color: t.text2, boxWidth: 10, boxHeight: 10, usePointStyle: true, pointStyle: 'rectRounded', font: { family: t.sans, size: 12 } } },
      tooltip: tip(t),
    },
  };
}
/** Tooltip on surface tokens, Plex Mono numbers; `hint` adds a footer on clickable charts. */
export function tip(t: Theme, callbacks: Record<string, unknown> = {}, hint?: string): Record<string, unknown> {
  return {
    backgroundColor: t.surface2, titleColor: t.text, bodyColor: t.text2, footerColor: t.accent, borderColor: t.line, borderWidth: 1,
    padding: 10, cornerRadius: 4, displayColors: true, boxPadding: 4, usePointStyle: false,
    titleFont: { family: t.sans, weight: 600, size: 12 },
    bodyFont: { family: t.mono, size: 12 },
    footerFont: { family: t.sans, weight: 500, size: 11 },
    footerMarginTop: 8,
    callbacks: { ...(hint ? { footer: () => hint } : {}), ...callbacks },
  };
}
/** Pointer cursor while hovering a clickable mark. */
export function pointerOnHover(e: { native?: Event | null }, els: unknown[]): void {
  const c = e.native?.target as HTMLElement | undefined;
  if (c) c.style.cursor = els.length ? 'pointer' : 'default';
}
export function axis(t: Theme, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    grid: { color: t.grid, drawTicks: false },
    border: { color: t.line },
    ticks: { color: t.text3, padding: 6, font: { family: t.mono, size: 11 } },
    ...extra,
  };
}
export function axisTitle(t: Theme, text: string): Record<string, unknown> {
  return { display: true, text, color: t.text3, font: { family: t.sans, size: 11, weight: 500 } };
}

export type Registered = { canvas: HTMLCanvasElement; build: (t: Theme) => ChartConfiguration; chart: Chart | null };
const live = new Set<Registered>();
let generation = 0;
/** Entrance animation plays once per page per session; later visits render instantly (hover stays animated). */
const visited = new Set<string>();
const touched = new Set<string>();

export function mountChart(canvas: HTMLCanvasElement, build: (t: Theme) => object): Registered {
  const reg: Registered = { canvas, build: build as (t: Theme) => ChartConfiguration, chart: null };
  live.add(reg);
  const cfg = reg.build(theme()) as ChartConfiguration & { options: Record<string, unknown> };
  if (visited.has(state.page)) cfg.options = { ...(cfg.options ?? {}), animation: { duration: 0 } };
  touched.add(state.page);
  reg.chart = new Chart(canvas, cfg);
  return reg;
}
/** Called when the router swaps pages: destroy every chart. */
export function destroyAllCharts(): void {
  for (const r of live) r.chart?.destroy();
  live.clear();
  touched.forEach((p) => visited.add(p));
  touched.clear();
  generation++;
}
/** Theme changed: swap data + options in place and redraw without animation. */
export function rethemeCharts(): void {
  const t = theme();
  for (const r of live) {
    if (!r.chart) continue;
    const cfg = r.build(t);
    r.chart.data = cfg.data;
    r.chart.options = cfg.options as typeof r.chart.options;
    r.chart.update('none');
  }
}

export type ChartCardOpts = {
  target: string; title: string; subtitle?: string; provenance?: ProvKind;
  summary: string;                       // aria-label + sr text
  table: { head: string[]; rows: (string | number)[][] }; // visually-hidden data table
  build: (t: Theme) => object;
  height?: number; wide?: boolean; extra?: Node; onReady?: (r: Registered) => void;
  /** Keyboard equivalent of clicking the chart: one button per mark, shown on focus. */
  actions?: { label: string; run: () => void }[]; actionsLabel?: string;
};
export type ProvKind = 'observed' | 'snapshot' | 'source' | 'model' | 'ai' | 'mixed' | 'template';
export function provenanceTag(kind: ProvKind): HTMLElement {
  const label = { observed: 'Observed (historical)', snapshot: 'Observed signal (snapshot)', source: 'Source data (NVD)', model: 'Model prediction', ai: 'AI-generated', mixed: 'Observed + model', template: 'Template from data' }[kind];
  return h('span', { class: `prov prov-${kind}` }, h('i', { 'aria-hidden': 'true' }), label);
}

export function chartCard(o: ChartCardOpts): HTMLElement {
  const canvas = h('canvas', { role: 'img', 'aria-label': o.summary });
  const wrap = h('div', { class: 'chart-wrap', style: `height:${o.height ?? 280}px` }, canvas);
  const table = h('table', { class: 'sr-only' },
    h('caption', {}, `${o.title}: data`),
    h('thead', {}, h('tr', {}, o.table.head.map((x) => h('th', { scope: 'col' }, x)))),
    h('tbody', {}, o.table.rows.map((r) => h('tr', {}, r.map((c, i) => h(i === 0 ? 'th' : 'td', i === 0 ? { scope: 'row' } : {}, String(c)))))),
  );
  const card = h('section', { class: `card chart-card${o.wide ? ' wide' : ''}`, 'data-explain': o.target, 'aria-label': o.title },
    h('header', { class: 'card-head' },
      h('div', {},
        h('h3', { class: 'card-title' }, o.title),
        o.subtitle ? h('p', { class: 'card-sub' }, o.subtitle) : null),
      h('div', { class: 'card-tools' }, o.provenance ? provenanceTag(o.provenance) : null, explainButton(o.target, o.title)),
    ),
    o.extra ?? null,
    wrap,
    h('p', { class: 'sr-only' }, o.summary),
    o.actions?.length ? h('div', { class: 'chart-actions', role: 'group', 'aria-label': o.actionsLabel ?? `${o.title}: actions` },
      o.actions.map((a) => h('button', { type: 'button', class: 'chip chip-toggle', onClick: a.run }, a.label))) : null,
    table,
  );
  // Mount after insertion so Chart.js can measure; page calls ready() on attach.
  const gen = generation;
  requestAnimationFrame(() => { if (gen !== generation) return; const r = mountChart(canvas, o.build); o.onReady?.(r); });
  return card;
}
