import { api, type ChatMessage, type ChatResult, type CVE } from '../api';
import { h, clear } from '../util';
import { state, bus, emit } from '../state';
import { runActions, describeAction } from '../actions';
import { openCve } from './drawer';
import { aiBlock, cveMiniCard, skeleton } from './ui';

/** Starters the offline router and Gemini can both answer; context-aware and built from real API data. */
function starterList(top1: string | null, topFamily: string | null): string[] {
  const s: string[] = [];
  if (state.selection) s.push(`Explain ${state.selection}`);
  if (state.page === 'families' && topFamily) s.push(`Tell me about ${topFamily}`);
  if (top1) s.push(`Why is ${top1} ranked #1?`);
  s.push('Which model has the most hits?', 'What did the research discover?', 'Show top CVEs with Metasploit modules', 'Top 5 riskiest');
  return s.slice(0, 5);
}

export function mountChat(app: HTMLElement): void {
  const history: ChatMessage[] = [];
  let busy = false;
  let open = false;

  const log = h('div', { class: 'chat-log', role: 'log', 'aria-live': 'polite', 'aria-label': 'Conversation', tabindex: '0' });
  let top1: string | null = null, topFamily: string | null = null;
  const starterBtns = h('div', { class: 'starters' });
  const starters = h('div', { class: 'starters' },
    h('p', { class: 'muted' }, 'Ask about the ranking, families, or model results. Answers come from the loaded data.'),
    starterBtns);
  const paintStarters = () => {
    clear(starterBtns);
    starterList(top1, topFamily).forEach((s) => starterBtns.appendChild(h('button', { type: 'button', class: 'starter', onClick: () => void send(s) }, s)));
  };
  paintStarters();
  log.appendChild(starters);
  void api.cves({ scope: 'top500', limit: 1 }).then((r) => { top1 = r.items[0]?.cve_id ?? null; paintStarters(); }).catch(() => { /* generic starters remain */ });
  void api.families().then((f) => { topFamily = [...f].sort((a, b) => (b.population_lift ?? 0) - (a.population_lift ?? 0))[0]?.family_name ?? null; paintStarters(); }).catch(() => { /* generic starters remain */ });
  bus.addEventListener('selectionchange', paintStarters);
  bus.addEventListener('pagerendered', paintStarters);

  const input = h('textarea', { class: 'input chat-input', id: 'chat-input', rows: '1', placeholder: 'Ask Telly…', 'aria-label': 'Message', maxlength: '1000' });
  const sendBtn = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Send');
  const form = h('form', { class: 'chat-form', onSubmit: (e: Event) => { e.preventDefault(); const v = (input as HTMLTextAreaElement).value.trim(); if (v) void send(v); } }, input, sendBtn);
  input.addEventListener('keydown', (e) => {
    const k = e as KeyboardEvent;
    if (k.key === 'Enter' && !k.shiftKey) { k.preventDefault(); form.requestSubmit(); }
  });
  input.addEventListener('input', () => { const t = input as HTMLTextAreaElement; t.style.height = 'auto'; t.style.height = `${Math.min(t.scrollHeight, 120)}px`; });

  const closeBtn = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Close assistant', onClick: () => setOpen(false) }, '✕');
  const resetBtn = h('button', { type: 'button', class: 'btn btn-ghost btn-sm', onClick: () => { history.length = 0; clear(log); log.appendChild(starters); } }, 'New chat');
  const panel = h('section', { class: 'chat-panel', id: 'chat-panel', role: 'dialog', 'aria-label': 'Telly, the Tell assistant', 'aria-modal': 'false', hidden: true },
    h('header', { class: 'chat-head' }, h('h2', { class: 'chat-title' }, 'Telly'), h('div', { class: 'card-tools' }, resetBtn, closeBtn)),
    log, form);
  const launcher = h('button', { type: 'button', class: 'chat-launcher', 'aria-expanded': 'false', 'aria-controls': 'chat-panel', onClick: () => setOpen(!open) },
    h('span', { class: 'launcher-dot', 'aria-hidden': 'true' }), 'Ask');
  const dock = h('div', { class: 'chat-dock' }, panel, launcher);
  app.appendChild(dock);

  function setOpen(v: boolean) {
    if (v === open) return;
    open = v;
    launcher.setAttribute('aria-expanded', String(v));
    if (v) {
      panel.hidden = false;
      requestAnimationFrame(() => { dock.classList.add('open'); (input as HTMLTextAreaElement).focus({ preventScroll: true }); });
    } else {
      dock.classList.remove('open');
      window.setTimeout(() => { if (!open) panel.hidden = true; }, 260);
      if (panel.contains(document.activeElement)) launcher.focus({ preventScroll: true });
    }
    emit('chat:toggle', v);
  }
  bus.addEventListener('chat:open', () => setOpen(true));
  bus.addEventListener('chat:ask', ((e: CustomEvent<{ text: string; context: string }>) => { state.chatContext = e.detail.context; setOpen(true); void send(e.detail.text); }) as EventListener);
  bus.addEventListener('pagerendered', () => { state.chatContext = null; });
  panel.addEventListener('keydown', (e) => { if ((e as KeyboardEvent).key === 'Escape') { e.stopPropagation(); setOpen(false); } });

  const scrollEnd = () => { log.scrollTop = log.scrollHeight; };
  const bubble = (role: 'user' | 'assistant', ...c: (Node | null)[]) => h('div', { class: `msg msg-${role}` }, ...c);

  async function send(text: string) {
    if (busy) return;
    busy = true; sendBtn.setAttribute('disabled', ''); emit('chat:busy', { on: true });
    if (starters.parentNode === log) log.removeChild(starters);
    (input as HTMLTextAreaElement).value = ''; (input as HTMLTextAreaElement).style.height = 'auto';
    history.push({ role: 'user', content: text });
    log.appendChild(bubble('user', h('p', {}, text)));
    const pending = bubble('assistant', skeleton(2));
    pending.setAttribute('aria-busy', 'true');
    log.appendChild(pending); scrollEnd();
    let failed = false;
    try {
      const r = await api.chat(history.slice(-12), state.page, state.chatContext ?? state.selection);
      history.push({ role: 'assistant', content: r.reply });
      const msgEl = assistantMsg(r);
      pending.replaceWith(msgEl);
      log.scrollTop = Math.max(0, msgEl.offsetTop - 12);
      runActions(r.actions ?? []);
    } catch (e) {
      failed = true;
      history.pop();
      pending.replaceWith(bubble('assistant', h('p', { class: 'msg-error', role: 'alert' }, (e as Error).message),
        h('button', { type: 'button', class: 'btn btn-sm', onClick: () => { log.lastElementChild?.previousElementSibling?.remove(); log.lastElementChild?.remove(); void send(text); } }, 'Retry')));
    } finally { busy = false; sendBtn.removeAttribute('disabled'); emit('chat:busy', { on: false, failed }); }
  }

  function assistantMsg(r: ChatResult): HTMLElement {
    const cves: CVE[] = r.cves ?? [];
    const canned = r.source !== 'gemini' && !cves.length && !(r.actions ?? []).length; // offline help text: nothing to ground
    const actionBtns = (r.actions ?? []).map((a) => ({ a, label: describeAction(a) })).filter((x) => x.label);
    return bubble('assistant',
      aiBlock(r.reply, r.source, undefined, canned ? undefined : r.grounding),
      cves.length ? h('div', { class: 'mini-grid chat-cves' }, cves.map((c) => cveMiniCard(c, openCve))) : null,
      actionBtns.length ? h('div', { class: 'chips' }, actionBtns.map(({ a, label }) => h('button', { type: 'button', class: 'chip chip-toggle', onClick: () => runActions([a]) }, label))) : null);
  }
}
