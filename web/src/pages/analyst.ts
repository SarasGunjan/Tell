import { api, type CVE } from '../api';
import { h, clear, debounce, fmtEpss } from '../util';
import { state, emit } from '../state';
import { aiPanel } from '../components/ai';
import { cveFacts, signalChips, skeleton, errorState, emptyState, cveMiniCard } from '../components/ui';
import { explainButton } from '../components/explain';
import { provenanceTag } from '../charts';
import { pageHead } from './shared';

export function mountAnalyst(root: HTMLElement): () => void {
  const input = h('input', { type: 'text', class: 'input', id: 'pick', placeholder: 'CVE-2026-… or keywords', autocomplete: 'off', role: 'combobox', 'aria-expanded': 'false', 'aria-controls': 'pick-list', 'aria-autocomplete': 'list' });
  const list = h('ul', { class: 'suggest', id: 'pick-list', role: 'listbox', 'aria-label': 'Matching CVEs', hidden: true });
  const empty = emptyState('Pick a CVE', 'Search the Top 500, choose a result, then generate a brief or ask a question.');
  const out = h('div', { class: 'analyst-out' }, empty);
  let ctrl: AbortController | null = null;

  const choose = async (id: string) => {
    state.selection = id; emit('selectionchange');
    list.hidden = true; input.setAttribute('aria-expanded', 'false');
    (input as HTMLInputElement).value = id;
    clear(out); out.appendChild(skeleton(5, true));
    try {
      const c = await api.cve(id);
      if (state.selection !== id) return;
      clear(out);
      out.appendChild(h('div', { class: 'analyst-grid' }, cveCard(c), aiPanel(c.cve_id)));
    } catch (e) { clear(out); out.appendChild(errorState(e, () => void choose(id))); }
  };

  const suggest = debounce(async () => {
    const q = (input as HTMLInputElement).value.trim();
    if (q.length < 2) { list.hidden = true; return; }
    ctrl?.abort(); ctrl = new AbortController();
    try {
      const r = await api.cves({ q, scope: 'top500', limit: 8 }, ctrl.signal);
      clear(list);
      if (!r.items.length) list.appendChild(h('li', { class: 'muted pad', role: 'presentation' }, 'No matches in the Top 500'));
      for (const c of r.items) {
        list.appendChild(h('li', { role: 'option', tabindex: '-1', class: 'suggest-item', onClick: () => void choose(c.cve_id), onKeydown: (e: Event) => {
          const k = (e as KeyboardEvent).key;
          if (k === 'Enter') void choose(c.cve_id);
          if (k === 'ArrowDown') ((e.currentTarget as HTMLElement).nextElementSibling as HTMLElement | null)?.focus();
          if (k === 'ArrowUp') (((e.currentTarget as HTMLElement).previousElementSibling as HTMLElement | null) ?? input).focus();
        } }, h('span', { class: 'mono' }, c.cve_id), h('span', { class: 'muted' }, `#${c.rank}${c.family_name ? ` · ${c.family_name}` : ''}`)));
      }
      list.hidden = false; input.setAttribute('aria-expanded', 'true');
    } catch (e) { if ((e as Error).name !== 'AbortError') { list.hidden = true; } }
  }, 250);
  input.addEventListener('input', suggest);
  input.addEventListener('keydown', (e) => {
    const k = (e as KeyboardEvent).key;
    if (k === 'ArrowDown') { (list.firstElementChild as HTMLElement | null)?.focus(); e.preventDefault(); }
    if (k === 'Enter') { const v = (input as HTMLInputElement).value.trim(); if (/^CVE-\d{4}-\d+$/i.test(v)) void choose(v.toUpperCase()); }
    if (k === 'Escape') list.hidden = true;
  });

  // One-click starting points: the five highest-ranked CVEs.
  void api.cves({ scope: 'top500', limit: 5 }).then((r) => {
    if (!empty.isConnected || !r.items.length) return;
    const grid = h('div', { class: 'mini-grid fade-in' }, r.items.map((c) => cveMiniCard(c, (id) => void choose(id))));
    empty.append(h('p', { class: 'label' }, 'Top 5 ranked'), grid);
  }).catch(() => { /* suggestions are optional */ });

  root.append(
    pageHead('Ask Tell', 'Generate a grounded brief for one CVE and ask follow-up questions. Every answer is checked against the data.'),
    h('div', { class: 'card picker' },
      h('label', { for: 'pick', class: 'field-label' }, 'CVE'),
      h('div', { class: 'picker-box' }, input, list)),
    out);

  return () => ctrl?.abort();
}

function cveCard(c: CVE): HTMLElement {
  return h('section', { class: 'card', 'data-explain': 'panel-cve', 'aria-label': `${c.cve_id} summary` },
    h('div', { class: 'card-head' },
      h('div', {}, h('h2', { class: 'card-title mono' }, c.cve_id), h('div', { class: 'prov-row' }, provenanceTag('model'), `Rank #${c.rank}`, provenanceTag('snapshot'), `EPSS ${fmtEpss(c.epss)}`)),
      h('div', { class: 'card-tools' }, explainButton('panel-cve', 'CVE summary'))),
    signalChips(c), cveFacts(c),
    c.description ? h('p', { class: 'desc' }, c.description) : h('p', { class: 'muted' }, 'No description available in the loaded data.'));
}
