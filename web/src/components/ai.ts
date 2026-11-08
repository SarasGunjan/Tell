import { api, type Grounding } from '../api';
import { h, clear } from '../util';
import { aiBlock, groundingReport, skeleton, errorState } from './ui';
import { explainButton } from './explain';

const fadeIn = (el: HTMLElement): HTMLElement => { el.classList.add('fade-in'); return el; };

/** Brief + Ask for one CVE. Used by the drawer and the Ask Telly page. */
export function aiPanel(cveId: string): HTMLElement {
  const briefOut = h('div', { class: 'ai-out', 'aria-live': 'polite' });
  const askOut = h('div', { class: 'ai-out', 'aria-live': 'polite' });
  const groundOut = h('div', { class: 'ai-out' });
  let busy = false;

  const showGrounding = (g: Grounding | undefined) => {
    clear(groundOut);
    if (g) groundOut.appendChild(groundingReport(g));
  };

  const briefBtn = h('button', { type: 'button', class: 'btn btn-primary' }, 'Generate brief');
  const runBrief = async () => {
    if (busy) return;
    busy = true; briefBtn.setAttribute('disabled', '');
    clear(briefOut); briefOut.appendChild(skeleton(5));
    try {
      const r = await api.brief(cveId);
      clear(briefOut);
      briefOut.appendChild(fadeIn(aiBlock(r.content, r.source, r.model, r.grounding)));
      showGrounding(r.grounding);
      briefBtn.textContent = 'Regenerate'; briefBtn.className = 'btn';
    } catch (e) {
      clear(briefOut); briefOut.appendChild(errorState(e, () => void runBrief()));
    } finally { busy = false; briefBtn.removeAttribute('disabled'); }
  };
  briefBtn.addEventListener('click', () => void runBrief());

  const input = h('input', { type: 'text', class: 'input', id: `ask-${cveId}`, placeholder: 'e.g. Why is this ranked highly?', autocomplete: 'off', maxlength: '300' });
  const askBtn = h('button', { type: 'submit', class: 'btn' }, 'Ask');
  const form = h('form', { class: 'ask-form', onSubmit: (e: Event) => { e.preventDefault(); void runAsk(); } },
    h('label', { class: 'sr-only', for: `ask-${cveId}` }, 'Question about this CVE'), input, askBtn);
  const runAsk = async () => {
    const q = (input as HTMLInputElement).value.trim();
    if (!q || busy) return;
    busy = true; askBtn.setAttribute('disabled', '');
    clear(askOut); askOut.appendChild(skeleton(3));
    try {
      const r = await api.ask(cveId, q);
      clear(askOut);
      askOut.appendChild(fadeIn(aiBlock(r.response, r.source, r.model, r.grounding)));
      showGrounding(r.grounding);
    } catch (e) {
      clear(askOut); askOut.appendChild(errorState(e, () => void runAsk()));
    } finally { busy = false; askBtn.removeAttribute('disabled'); }
  };

  return h('div', { class: 'ai-panel' },
    h('section', { class: 'ai-section', 'data-explain': 'panel-brief', 'aria-label': 'AI brief' },
      h('div', { class: 'section-head' }, h('h3', { class: 'card-title' }, 'Analyst brief'), h('div', { class: 'card-tools' }, explainButton('panel-brief', 'Analyst brief'), briefBtn)),
      briefOut),
    h('section', { class: 'ai-section', 'aria-label': 'Ask about this CVE' },
      h('div', { class: 'section-head' }, h('h3', { class: 'card-title' }, 'Ask about this CVE')),
      form, askOut),
    groundOut);
}
