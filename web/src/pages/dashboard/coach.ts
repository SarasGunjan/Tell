// "How to read this": a 3-step, skippable coach mark on the galaxy card. Crafternauta walks to each spot if visible.
import { h, store as lsStore } from '../../util';
import { bus, emit } from '../../state';

const KEY = 'tell.coach.galaxy.seen';
type Step = { title: string; body: string; spot: () => HTMLElement };

export function createCoach(host: HTMLElement, spots: { stage: HTMLElement; core: HTMLElement; legend: HTMLElement }, helpBtn: HTMLElement, n: number): { open(): void; autoShow(): void; destroy(): void } {
  const steps: Step[] = [
    { title: 'Each star is a CVE', body: `Every star is one CVE on the 2026 scoreboard, ${n.toLocaleString('en-US')} in all.`, spot: () => spots.stage },
    { title: 'Closer to the core = higher rank', body: 'The nearer a star sits to the core, the higher the current ranking method places it. The rings mark the Top 100, 250 and 500.', spot: () => spots.core },
    { title: 'Arm, glow and size', body: 'Each arm (or row) is a vulnerability family. Glow marks the Top 500 and size shows EPSS. Click a star or an arm to filter; every other panel updates.', spot: () => spots.legend },
  ];
  let i = 0, el: HTMLElement | null = null, timer = 0;
  const close = (markSeen = true) => {
    if (!el) return;
    el.remove(); el = null; window.clearTimeout(timer);
    document.removeEventListener('keydown', onKey, true);
    if (markSeen) lsStore.set(KEY, '1');
    helpBtn.setAttribute('aria-expanded', 'false');
    (helpBtn as HTMLElement).focus({ preventScroll: true });
  };
  const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && el) { e.preventDefault(); e.stopPropagation(); close(); } };
  function paint(): void {
    if (!el) return;
    const s = steps[i], last = i === steps.length - 1;
    const next = h('button', { type: 'button', class: 'btn btn-primary btn-sm', onClick: () => { if (last) close(); else { i++; paint(); } } }, last ? 'Done' : 'Next');
    el.replaceChildren(
      h('p', { class: 'label' }, `Step ${i + 1} of ${steps.length}`),
      h('h3', { class: 'card-title', id: 'coach-title' }, s.title),
      h('p', { class: 'coach-body' }, s.body),
      h('div', { class: 'coach-actions' },
        h('button', { type: 'button', class: 'btn btn-ghost btn-sm', onClick: () => close() }, 'Skip'),
        i > 0 ? h('button', { type: 'button', class: 'btn btn-sm', onClick: () => { i--; paint(); } }, 'Back') : null,
        next));
    next.focus({ preventScroll: true });
    emit('pet:goto', { el: s.spot() }); // no-op when the pet is hidden
  }
  function open(): void {
    if (el) return;
    i = 0;
    el = h('div', { class: 'coach', role: 'dialog', 'aria-labelledby': 'coach-title', 'aria-label': 'How to read the Threat Galaxy' });
    host.appendChild(el);
    helpBtn.setAttribute('aria-expanded', 'true');
    document.addEventListener('keydown', onKey, true);
    paint();
  }
  const onNav = () => close(false);
  bus.addEventListener('pagerendered', onNav);
  return {
    open,
    autoShow() { if (!lsStore.get(KEY)) timer = window.setTimeout(open, 1400); },
    destroy() { window.clearTimeout(timer); document.removeEventListener('keydown', onKey, true); bus.removeEventListener('pagerendered', onNav); el?.remove(); el = null; },
  };
}
