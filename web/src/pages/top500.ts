import { api, type CVE, type Family } from '../api';
import { h, clear, fmtInt, fmtEpss, debounce, SIGNALS, stagger, type SignalKey } from '../util';
import { state, bus } from '../state';
import { emptyState, errorState, signalDots, skeleton, waitingState, familyLabel } from '../components/ui';
import { provenanceTag } from '../charts';
import { explainButton } from '../components/explain';
import { openCve } from '../components/drawer';
import { pageHead } from './shared';

const PAGE = 50;

export function mountTop500(root: HTMLElement): () => void {
  const f = () => state.top500;
  let ctrl: AbortController | null = null;

  const search = h('input', { type: 'search', class: 'input', id: 'f-q', placeholder: 'CVE ID or description', autocomplete: 'off', value: f().q });
  const family = h('select', { class: 'input', id: 'f-fam' }, h('option', { value: '' }, 'All families'));
  const epss = h('input', { type: 'range', id: 'f-epss', min: '0', max: '100', step: '1', value: String(toSlider(f().min_epss)) });
  const epssOut = h('output', { class: 'num', for: 'f-epss' }, fmtEpssSlider(f().min_epss));
  const sort = h('select', { class: 'input', id: 'f-sort' },
    h('option', { value: 'rank' }, 'Rank'), h('option', { value: 'epss' }, 'EPSS'));
  const chips = h('div', { class: 'chips', role: 'group', 'aria-label': 'Require exploit signals' },
    SIGNALS.map((s) => h('button', { type: 'button', class: 'chip chip-toggle', 'data-sig': s.key, 'aria-pressed': 'false' }, s.label)));
  const reset = h('button', { type: 'button', class: 'btn btn-ghost' }, 'Reset');

  const count = h('p', { class: 'muted num', role: 'status', 'aria-live': 'polite' });
  const tableHost = h('div', { class: 'table-wrap', tabindex: '-1' });
  const prev = h('button', { type: 'button', class: 'btn' }, 'Previous');
  const next = h('button', { type: 'button', class: 'btn' }, 'Next');
  const pager = h('div', { class: 'pager' }, prev, next);

  const syncControls = () => {
    (search as HTMLInputElement).value = f().q;
    (family as HTMLSelectElement).value = f().family_id;
    (epss as HTMLInputElement).value = String(toSlider(f().min_epss));
    epssOut.textContent = fmtEpssSlider(f().min_epss);
    (sort as HTMLSelectElement).value = f().sort;
    chips.querySelectorAll<HTMLButtonElement>('[data-sig]').forEach((b) => b.setAttribute('aria-pressed', String(f().signals.includes(b.dataset.sig as SignalKey))));
  };

  let shown = false; // skeleton + row cascade only before the first table is on screen
  const load = async () => {
    ctrl?.abort(); ctrl = new AbortController();
    const mine = ctrl;
    const first = !shown;
    if (first) { if (!tableHost.firstChild) tableHost.appendChild(skeleton(8, true)); }
    else { tableHost.style.opacity = '.55'; tableHost.setAttribute('aria-busy', 'true'); }
    try {
      const r = await api.cves({ ...f(), scope: 'top500', limit: PAGE }, mine.signal);
      if (mine.signal.aborted) return;
      clear(tableHost);
      tableHost.style.opacity = ''; tableHost.removeAttribute('aria-busy'); shown = true;
      const from = r.total ? f().offset + 1 : 0, to = Math.min(f().offset + PAGE, r.total);
      count.textContent = r.total ? `Showing ${fmtInt(from)}–${fmtInt(to)} of ${fmtInt(r.total)} CVEs` : 'No matches';
      prev.toggleAttribute('disabled', f().offset <= 0);
      next.toggleAttribute('disabled', f().offset + PAGE >= r.total);
      pager.hidden = r.total <= PAGE;
      const none = !r.total && !f().q && !f().family_id && !f().min_epss && !f().signals.length ? await api.status().then((s) => s.counts.cves === null, () => false) : false;
      if (mine.signal.aborted) return;
      tableHost.appendChild(none ? waitingState('predictions') : r.items.length ? table(r.items, first) : emptyState('No CVEs match these filters', 'Relax the EPSS threshold or clear a signal.'));
    } catch (e) {
      if ((e as Error).name === 'AbortError') return;
      tableHost.style.opacity = ''; tableHost.removeAttribute('aria-busy');
      clear(tableHost); tableHost.appendChild(errorState(e, () => void load()));
    }
  };

  const apply = (patch: Partial<typeof state.top500>) => { state.top500 = { ...f(), ...patch, offset: patch.offset ?? 0 }; void load(); };
  search.addEventListener('input', debounce(() => apply({ q: (search as HTMLInputElement).value.trim() }), 300));
  family.addEventListener('change', () => apply({ family_id: (family as HTMLSelectElement).value }));
  sort.addEventListener('change', () => apply({ sort: (sort as HTMLSelectElement).value as 'rank' | 'epss' }));
  const applyEpss = debounce((v: number) => apply({ min_epss: v }), 200);
  epss.addEventListener('input', () => { const v = fromSlider(Number((epss as HTMLInputElement).value)); epssOut.textContent = fmtEpssSlider(v); applyEpss(v); });
  chips.addEventListener('click', (e) => {
    const b = (e.target as HTMLElement).closest<HTMLButtonElement>('[data-sig]'); if (!b) return;
    const k = b.dataset.sig as SignalKey;
    const set = new Set(f().signals); set.has(k) ? set.delete(k) : set.add(k);
    b.setAttribute('aria-pressed', String(set.has(k)));
    apply({ signals: [...set] });
  });
  reset.addEventListener('click', () => { state.top500 = { q: '', family_id: '', min_epss: 0, signals: [], sort: 'rank', offset: 0 }; syncControls(); void load(); });
  prev.addEventListener('click', () => { apply({ offset: Math.max(0, f().offset - PAGE) }); tableHost.scrollIntoView({ block: 'nearest' }); });
  next.addEventListener('click', () => { apply({ offset: f().offset + PAGE }); tableHost.scrollIntoView({ block: 'nearest' }); });

  const onExternal = () => { syncControls(); void load(); };
  bus.addEventListener('filterschange', onExternal);

  const bar = h('div', { class: 'filters card', role: 'search', 'aria-label': 'Filter Top 500' },
    field('Search', 'f-q', search), field('Family', 'f-fam', family),
    h('div', { class: 'field' }, h('label', { for: 'f-epss' }, 'Min EPSS ', epssOut), epss),
    field('Sort by', 'f-sort', sort),
    h('div', { class: 'field field-wide' }, h('span', { class: 'field-label' }, 'Exploit signals (all selected must be present)'), chips),
    h('div', { class: 'field field-end' }, reset));

  root.append(
    pageHead('Top 500', 'The shortlist of CVEs on the 2026 scoreboard, ranked by the current ranking method (public exploit code, then EPSS). A prediction, not confirmed KEV status.', h('div', { class: 'head-tags' }, provenanceTag('model'))),
    bar,
    h('section', { class: 'card table-card', 'data-explain': 'table-top500', 'aria-label': 'Top 500 table' },
      h('div', { class: 'card-head' }, count, h('div', { class: 'card-tools' }, h('span', { class: 'sig-legend', 'aria-label': 'Signal legend' }, SIGNALS.map((s) => h('span', { class: 'sig-key' }, h('i', { class: `sig on sig-${s.key}`, 'aria-hidden': 'true' }), s.label))), explainButton('table-top500', 'Top 500 table'))),
      tableHost, pager));

  syncControls();
  void api.families().then((fams: Family[]) => {
    for (const x of fams) family.appendChild(h('option', { value: x.family_id }, x.family_name));
    (family as HTMLSelectElement).value = f().family_id;
  }).catch(() => { /* filter still works without the family list */ });
  void load();
  return () => { ctrl?.abort(); bus.removeEventListener('filterschange', onExternal); };
}

/** Slider is log-scaled because EPSS is heavily skewed: 0 = any, 1..100 -> 0.01% .. 100%. */
export const fromSlider = (p: number) => (p <= 0 ? 0 : 10 ** (-4 + p / 25));
export const toSlider = (v: number) => (v <= 0 ? 0 : Math.round(Math.min(100, Math.max(1, (Math.log10(v) + 4) * 25))));
export const fmtEpssSlider = (v: number) => (v <= 0 ? 'any' : `≥ ${fmtEpss(v)}`);
const field = (label: string, id: string, ctl: Node) => h('div', { class: 'field' }, h('label', { for: id }, label), ctl);

function table(items: CVE[], animate: boolean): HTMLElement {
  const body = h('tbody', {}, items.map((c) => {
    const tr = h('tr', { class: 'row', 'data-cve': c.cve_id, onClick: () => openCve(c.cve_id) },
      h('td', { class: 'num rank-cell' }, `#${c.rank}`),
      h('th', { scope: 'row', class: 'id-cell' },
        h('button', { type: 'button', class: 'link-btn mono', 'aria-label': `Open details for ${c.cve_id}`, onClick: (e: Event) => { e.stopPropagation(); openCve(c.cve_id); } }, c.cve_id)),
      h('td', { class: 'num' }, fmtEpss(c.epss)),
      h('td', {}, signalDots(c)),
      h('td', { class: 'col-fam' }, familyLabel(c.family_name)),
      h('td', { class: 'col-vt' }, c.vulnerability_type && c.vulnerability_type !== 'unknown' ? c.vulnerability_type : h('span', { class: 'muted' }, 'unknown')),
      h('td', { class: 'col-pub num' }, c.published));
    return tr;
  }));
  const t = h('table', { class: 'data-table' },
    h('caption', { class: 'sr-only' }, 'Top 500 CVEs by rank'),
    h('thead', {}, h('tr', {},
      h('th', { scope: 'col', class: 'num' }, 'Rank'), h('th', { scope: 'col' }, 'CVE'),
      h('th', { scope: 'col', class: 'num' }, 'EPSS'),
      h('th', { scope: 'col' }, 'Signals'), h('th', { scope: 'col', class: 'col-fam' }, 'Family'), h('th', { scope: 'col', class: 'col-vt' }, 'Vuln type'), h('th', { scope: 'col', class: 'col-pub' }, 'Published'))),
    body);
  if (animate) stagger(body);
  return t;
}
