import { TARGET_PAGE, reducedMotion } from '../util';
import { state } from '../state';
import { navigate } from '../router';

/** First visible element for a contract target id. */
export function findTarget(id: string): HTMLElement | null {
  const all = Array.from(document.querySelectorAll<HTMLElement>(`[data-explain="${CSS.escape(id)}"]`));
  return all.find((e) => e.getClientRects().length > 0) ?? null;
}

function waitFor(id: string, ms = 4000): Promise<HTMLElement | null> {
  return new Promise((resolve) => {
    const t0 = performance.now();
    const tick = () => {
      const el = findTarget(id);
      if (el) return resolve(el);
      if (performance.now() - t0 > ms) return resolve(null);
      requestAnimationFrame(tick);
    };
    tick();
  });
}

/** Pulse ring: a transient overlay animated with transform + opacity only. */
function ring(el: HTMLElement): void {
  const r = el.getBoundingClientRect();
  const o = document.createElement('div');
  o.className = 'pulse-ring';
  o.setAttribute('aria-hidden', 'true');
  Object.assign(o.style, { left: `${r.left + window.scrollX - 6}px`, top: `${r.top + window.scrollY - 6}px`, width: `${r.width + 12}px`, height: `${r.height + 12}px` });
  document.body.appendChild(o);
  if (reducedMotion()) { o.style.opacity = '1'; window.setTimeout(() => o.remove(), 1600); return; }
  const a = o.animate(
    [{ opacity: 0, transform: 'scale(1.04)' }, { opacity: 1, transform: 'scale(1)', offset: 0.2 }, { opacity: 1, transform: 'scale(1)', offset: 0.55 }, { opacity: 0, transform: 'scale(1.015)' }],
    { duration: 1800, easing: 'cubic-bezier(0.23,1,0.32,1)' });
  a.onfinish = () => o.remove();
}

/** Navigate to the target's page if needed, scroll to it, pulse it. Resolves to the element. */
export async function highlightTarget(id: string): Promise<HTMLElement | null> {
  const page = TARGET_PAGE[id];
  if (page && page !== state.page && !findTarget(id)) navigate(page);
  const el = await waitFor(id);
  if (!el) return null;
  el.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' });
  await new Promise((r) => window.setTimeout(r, reducedMotion() ? 0 : 420));
  ring(el);
  return el;
}
