import { familyWaiting, emit } from '../state';
import { h, clear, setMarkdown, fmtPct, fmtEpss, SIGNALS, stagger, reducedMotion } from '../util';
import type { CVE, Grounding, AiSource } from '../api';
import { ApiError } from '../api';
import { provenanceTag, type ProvKind } from '../charts';
import { explainButton } from './explain';

export function skeleton(lines = 3, tall = false): HTMLElement {
  return h('div', { class: `skeleton${tall ? ' tall' : ''}`, 'aria-hidden': 'true' },
    Array.from({ length: lines }, (_, i) => h('span', { style: `width:${90 - ((i * 17) % 40)}%` })));
}
export function errorState(err: unknown, retry: () => void): HTMLElement {
  const msg = err instanceof ApiError || err instanceof Error ? err.message : 'Something went wrong.';
  return h('div', { class: 'state state-error', role: 'alert' },
    h('p', { class: 'state-title' }, 'Could not load this section'),
    h('p', { class: 'state-body' }, msg),
    h('button', { type: 'button', class: 'btn', onClick: retry }, 'Retry'));
}
export function emptyState(title: string, body?: string): HTMLElement {
  return h('div', { class: 'state' }, h('p', { class: 'state-title' }, title), body ? h('p', { class: 'state-body' }, body) : null);
}

export type Dataset = 'predictions' | 'metrics' | 'families' | 'research';
/** Who/what each dataset waits on (spec: docs/WEB_PLATFORM.md). */
export const WAITING: Record<Dataset, { who: string; file: string }> = {
  predictions: { who: 'Member 1', file: 'predictions.csv' },
  metrics: { who: 'Member 1', file: 'model_metrics.csv' },
  families: { who: 'Member 2', file: 'benchmark_2026/family_summary.csv' },
  research: { who: 'Member 2', file: 'temporal_validation_2024_2025.csv' },
};
export const waitingText = (d: Dataset) => `Waiting on ${WAITING[d].who}'s ${WAITING[d].file}`;
/** Whole-section empty state for data that has not been delivered yet. */
export function waitingState(d: Dataset, title = 'Not computed yet'): HTMLElement {
  return h('div', { class: 'state state-waiting', role: 'status' },
    h('p', { class: 'state-title' }, title),
    h('p', { class: 'state-body' }, `${waitingText(d)}. Nothing is estimated in the meantime. Refresh once the file is in the results folder; the status pill shows what has arrived.`));
}
/** Same, as a card that keeps a chart's place in a grid. */
export function waitingCard(title: string, d: Dataset | string): HTMLElement {
  const why = d in WAITING ? waitingText(d as Dataset) : d;
  return h('section', { class: 'card chart-card state-waiting-card', 'aria-label': title },
    h('header', { class: 'card-head' }, h('div', {}, h('h3', { class: 'card-title' }, title), h('p', { class: 'card-sub' }, 'Not computed yet'))),
    h('p', { class: 'muted pad', role: 'status' }, why + '.'));
}
/** Family label for a CVE; says why it is empty when the family files have not arrived. */
export function familyLabel(name: string | null | undefined, fallback = '–'): Node | string {
  if (name) return name;
  return familyWaiting() ? h('span', { class: 'muted' }, 'not computed yet') : fallback;
}

/** Fill `host` with a skeleton, run `load`, then `render`. Failures show retry. */
export async function loadInto<T>(host: HTMLElement, load: () => Promise<T>, render: (d: T) => Node, skel: Node = skeleton(4, true)): Promise<void> {
  clear(host);
  host.setAttribute('aria-busy', 'true');
  host.appendChild(skel);
  try {
    const data = await load();
    clear(host);
    const out = render(data);
    if (out instanceof HTMLElement) out.classList.add('fade-in');
    host.appendChild(out);
  } catch (e) {
    if ((e as Error).name === 'AbortError') return;
    clear(host);
    host.appendChild(errorState(e, () => void loadInto(host, load, render, skel)));
  } finally {
    host.removeAttribute('aria-busy');
  }
}

/** `value: null` renders a muted "not computed yet" with `waiting` (who/what) instead of a number. */
export function kpi(o: { target: string; label: string; value: string | null; sub?: string; waiting?: Dataset; prov: ProvKind; detail?: string }): HTMLElement {
  const none = o.value === null;
  return h('section', { class: 'card kpi', 'data-explain': o.target, 'aria-label': o.label },
    h('div', { class: 'kpi-top' }, h('span', { class: 'label' }, o.label), explainButton(o.target, o.label)),
    h('div', { class: `kpi-value num${none ? ' is-waiting' : ''}` }, none ? 'not computed yet' : o.value),
    none ? h('div', { class: 'kpi-sub' }, o.waiting ? waitingText(o.waiting) : '') : o.sub ? h('div', { class: 'kpi-sub' }, o.sub) : null,
    h('div', { class: 'kpi-foot' }, provenanceTag(o.prov)));
}

export function signalDots(c: Pick<CVE, 'exploitdb' | 'metasploit' | 'nuclei' | 'poc_github'>): HTMLElement {
  const active = SIGNALS.filter((s) => c[s.key] === 1);
  return h('span', { class: 'sigs', 'aria-label': active.length ? active.map((s) => s.label).join(', ') : 'No public exploit signals' },
    SIGNALS.map((s) => h('i', { class: `sig sig-${s.key}${c[s.key] === 1 ? ' on' : ''}`, title: s.label, 'aria-hidden': 'true' })),
    h('span', { class: 'sr-only' }, active.length ? active.map((s) => s.label).join(', ') : 'none'));
}
export function signalChips(c: CVE): HTMLElement {
  const active = SIGNALS.filter((s) => c[s.key] === 1);
  return h('div', { class: 'chips' }, active.length
    ? active.map((s) => h('span', { class: `chip chip-${s.key}` }, s.label))
    : h('span', { class: 'muted' }, 'No exploit signals recorded'));
}

/** True only for live AI output: chat/explain report "gemini"; brief/ask report e.g. "Google Gemini API (Live)". */
export const isLiveAi = (source: AiSource): boolean => source === 'gemini' || /live/i.test(source);

export function sourceTag(source: AiSource, model?: string): HTMLElement {
  const live = isLiveAi(source);
  return h('span', { class: `src ${live ? 'src-live' : 'src-off'}`, title: model ? `Model: ${model}` : undefined },
    h('i', { 'aria-hidden': 'true' }), live ? 'Gemini live' : 'Offline mode');
}

/** AI text block: sanitized markdown + provenance + source + grounding badge. */
export function aiBlock(md: string, source: AiSource, model: string | undefined, grounding?: Grounding): HTMLElement {
  const body = h('div', { class: 'md' });
  setMarkdown(body, md);
  return h('div', { class: 'ai-block' },
    h('div', { class: 'ai-meta' }, provenanceTag(isLiveAi(source) ? 'ai' : 'template'), sourceTag(source, model), grounding ? groundingBadge(grounding) : null),
    body);
}

function groundScore(g: Grounding): number {
  const s = g.grounding_score;
  return s <= 1 ? s * 100 : s;
}
export function groundingBadge(g: Grounding): HTMLElement {
  // No checkable claims → a % would read as "0% grounded"; say what actually happened.
  if (!g.checks?.length) return h('span', { class: 'badge', title: 'The reply makes no CVE-specific claims to verify' }, 'No claims to verify');
  return h('span', { class: `badge ${g.is_grounded ? 'badge-ok' : 'badge-warn'}`, title: g.status_label },
    g.is_grounded ? 'Grounded' : 'Check evidence', ' ', h('span', { class: 'num' }, `${groundScore(g).toFixed(0)}%`));
}
export function groundingReport(g: Grounding, withTarget = true): HTMLElement {
  const score = groundScore(g);
  const target = Math.max(2, Math.min(100, score)) / 100;
  const fill = h('span', { class: g.is_grounded ? 'ok' : 'warn', style: `--fill:${reducedMotion() ? target : 0}` });
  if (!reducedMotion()) requestAnimationFrame(() => requestAnimationFrame(() => fill.style.setProperty('--fill', String(target))));
  return h('section', { class: 'grounding', 'data-explain': withTarget ? 'panel-grounding' : null, 'aria-label': 'Grounding report' },
    h('div', { class: 'grounding-head' },
      h('div', {},
        h('h4', { class: 'card-title' }, 'Grounding report'),
        h('p', { class: 'card-sub' }, `${g.status_label} · ${g.target_cve}`)),
      withTarget ? explainButton('panel-grounding', 'Grounding report') : null),
    h('div', { class: 'meter', role: 'meter', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': score.toFixed(0), 'aria-label': 'Grounding score' },
      fill,
      h('b', { class: 'num' }, `${score.toFixed(0)}%`)),
    h('ul', { class: 'checks' }, g.checks.map((c) =>
      h('li', { class: `check check-${/pass|ok|true|verified|match/i.test(c.status) ? 'ok' : /fail|miss|false|unsupported/i.test(c.status) ? 'bad' : 'warn'}` },
        h('span', { class: 'check-status' }, c.status),
        h('span', { class: 'check-item' }, c.item),
        h('span', { class: 'check-detail' }, c.detail)))),
    g.hallucinations.length
      ? h('div', { class: 'halluc' }, h('b', {}, 'Unsupported claims'), h('ul', {}, g.hallucinations.map((x) => h('li', {}, x))))
      : null);
}

export function cveMiniCard(c: CVE, onOpen: (id: string) => void): HTMLElement {
  return h('button', { type: 'button', class: 'cve-mini', onClick: () => onOpen(c.cve_id),
    onPointerEnter: () => emit('cve:hover', c.cve_id), onPointerLeave: () => emit('cve:hover', null), onFocus: () => emit('cve:hover', c.cve_id), onBlur: () => emit('cve:hover', null) },
    h('span', { class: 'cve-mini-top' }, h('span', { class: 'mono' }, c.cve_id), h('span', { class: 'rank num' }, `#${c.rank}`)),
    h('span', { class: 'cve-mini-meta' }, familyLabel(c.family_name, 'Unassigned family')),
    h('span', { class: 'cve-mini-foot' }, signalDots(c), h('span', { class: 'num muted' }, `EPSS ${fmtEpss(c.epss)}`)));
}

export function cveFacts(c: CVE): HTMLElement {
  const row = (k: string, v: Node | string | null | undefined) => v === null || v === undefined || v === '' ? null : h('div', { class: 'fact' }, h('dt', {}, k), h('dd', {}, v));
  return h('dl', { class: 'facts' },
    row('Family', c.family_name ?? (familyWaiting() ? h('span', { class: 'muted' }, 'not computed yet') : null)),
    row('Published', c.published),
    row('Attack vector', c.attack_vector ?? c.remote_local),
    row('Authentication', c.auth_required),
    row('Vulnerability type', c.vulnerability_type),
    row('CVSS 3.x', c.cvss3_score === null ? null : String(c.cvss3_score)),
    row('CWE', c.cwe_ids));
}

export { stagger, fmtPct };
