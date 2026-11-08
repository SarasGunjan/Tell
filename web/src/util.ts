import { marked } from 'marked';
import DOMPurify from 'dompurify';

type Child = Node | string | number | null | undefined | false | Child[];
type Attrs = Record<string, string | number | boolean | null | undefined | ((e: Event) => void)>;

/** Hyperscript-style element builder. Strings become text nodes (never HTML). */
export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v as EventListener);
    else if (k === 'class') node.className = String(v);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
  append(node, children);
  return node;
}
export function append(node: Node, children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(node, c);
    else node.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
  }
}
export function clear(node: Element): void { while (node.firstChild) node.removeChild(node.firstChild); }

DOMPurify.addHook('afterSanitizeAttributes', (n) => {
  if (n.tagName === 'A') { n.setAttribute('rel', 'noopener noreferrer'); n.setAttribute('target', '_blank'); }
});
/** All AI / markdown text goes through here: marked -> DOMPurify. */
export function mdToSafeHtml(md: string): string {
  const raw = marked.parse(md ?? '', { async: false, gfm: true, breaks: true }) as string;
  return DOMPurify.sanitize(raw, { USE_PROFILES: { html: true }, FORBID_TAGS: ['style', 'form', 'input', 'button', 'img'] });
}
/** Render sanitized markdown into a container. The only innerHTML sink in the app. */
export function setMarkdown(el: Element, md: string): void {
  el.innerHTML = mdToSafeHtml(md);
}

// ---- formatting ----
const nf = new Intl.NumberFormat('en-US');
export const fmtInt = (n: number | null | undefined) => (n === null || n === undefined ? '–' : nf.format(Math.round(n)));
export const fmtPct = (x: number | null | undefined, d = 1) => (x === null || x === undefined ? '–' : `${(x * 100).toFixed(d)}%`);
export function fmtScore(x: number | null | undefined): string {
  if (x === null || x === undefined) return '–';
  if (x !== 0 && Math.abs(x) < 0.001) return x.toExponential(1);
  return x.toFixed(3);
}
export function fmtEpss(x: number | null | undefined): string {
  if (x === null || x === undefined) return '–';
  if (x < 0.001) return `${(x * 100).toFixed(2)}%`;
  return `${(x * 100).toFixed(1)}%`;
}

// ---- motion helpers ----
export const reducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;
export function stagger(parent: Element, cap = 14): void {
  Array.from(parent.children).forEach((c, i) => (c as HTMLElement).style.setProperty('--i', String(Math.min(i, cap))));
  parent.classList.add('stagger');
}

// ---- storage (always guarded) ----
export const store = {
  get(k: string): string | null { try { return localStorage.getItem(k); } catch { return null; } },
  set(k: string, v: string): void { try { localStorage.setItem(k, v); } catch { /* ignore */ } },
};

export function debounce<A extends unknown[]>(fn: (...a: A) => void, ms: number): (...a: A) => void {
  let t: number | undefined;
  return (...a: A) => { window.clearTimeout(t); t = window.setTimeout(() => fn(...a), ms); };
}

let uid = 0;
export const nextId = (p = 'id') => `${p}-${++uid}`;

export const SIGNALS = [
  { key: 'exploitdb', label: 'Exploit-DB' },
  { key: 'metasploit', label: 'Metasploit' },
  { key: 'nuclei', label: 'Nuclei' },
  { key: 'poc_github', label: 'GitHub PoC' },
] as const;
export type SignalKey = (typeof SIGNALS)[number]['key'];

/** Chart/table target ids that live on each page; used to route highlight actions. */
export const TARGET_PAGE: Record<string, import('./api').PageId> = {
  'chart-galaxy': 'dashboard', 'dash-kpis': 'dashboard', 'chart-scatter': 'dashboard', 'chart-budget': 'dashboard',
  'kpi-candidates': 'overview', 'kpi-hits500': 'overview', 'kpi-lift': 'overview',
  'chart-rank-epss': 'overview', 'chart-epss-dist': 'overview', 'chart-signals': 'overview', 'chart-published': 'overview',
  'chart-family-size': 'families', 'chart-family-kev': 'families', 'chart-family-bubble': 'families',
  'chart-hits': 'models', 'table-ap': 'models',
  'research-concentration': 'research', 'research-temporal': 'research', 'research-baselines': 'research', 'research-cwe': 'research',
  'table-top500': 'top500',
  'panel-cve': 'analyst', 'panel-brief': 'analyst', 'panel-grounding': 'analyst',
};

