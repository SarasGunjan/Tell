/** Fixed full-viewport starfield behind the app. Decorative: aria-hidden, no pointer events, hidden in light theme. */
type Star = { x: number; y: number; r: number; a: number; layer: 0 | 1; tw: number; ph: number };

const COUNT = 120;
const LAYERS = [
  { drift: 2.5, parallax: 0.05 }, // far: slow, small
  { drift: 6, parallax: 0.14 },   // near: faster, a touch larger (parallax <= 0.15)
];

export function mountStarfield(): void {
  const canvas = document.createElement('canvas');
  canvas.className = 'starfield';
  canvas.setAttribute('aria-hidden', 'true');
  document.body.prepend(canvas);
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
  const rnd = (a: number, b: number) => a + Math.random() * (b - a);
  const stars: Star[] = Array.from({ length: COUNT }, (_, i) => {
    const layer = (i < COUNT * 0.58 ? 0 : 1) as 0 | 1;
    return { x: Math.random(), y: Math.random(), layer, r: layer ? rnd(0.9, 1.5) : rnd(0.5, 1), a: layer ? rnd(0.2, 0.35) : rnd(0.1, 0.24), tw: i % 9 === 0 ? rnd(0.6, 1.4) : 0, ph: rnd(0, 6.28) };
  });
  let w = 0, h = 0, dpr = 1, raf = 0, last = 0, t = 0;
  const drift = [0, 0];

  const draw = () => {
    ctx.clearRect(0, 0, w, h);
    if (document.documentElement.dataset.theme === 'light') return;
    const sy = window.scrollY;
    for (const s of stars) {
      const L = LAYERS[s.layer];
      const y = (((s.y * h - drift[s.layer] - sy * L.parallax) % h) + h) % h;
      const a = s.tw ? s.a * (0.55 + 0.45 * Math.sin(t * s.tw + s.ph)) : s.a;
      ctx.fillStyle = `rgb(205 220 255 / ${a.toFixed(3)})`;
      ctx.beginPath(); ctx.arc(s.x * w, y, s.r, 0, 6.2832); ctx.fill();
    }
  };

  const size = () => {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = window.innerWidth; h = window.innerHeight;
    canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
    canvas.style.width = `${w}px`; canvas.style.height = `${h}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw();
  };

  const frame = (now: number) => {
    const dt = Math.min((now - last) / 1000, 0.1); last = now; t += dt;
    drift[0] += LAYERS[0].drift * dt; drift[1] += LAYERS[1].drift * dt;
    draw();
    raf = requestAnimationFrame(frame);
  };
  const run = () => {
    cancelAnimationFrame(raf); raf = 0;
    if (mq.matches || document.hidden) { draw(); return; } // paused / static frame
    last = performance.now(); raf = requestAnimationFrame(frame);
  };

  let rt = 0;
  window.addEventListener('resize', () => { clearTimeout(rt); rt = window.setTimeout(size, 120); });
  document.addEventListener('visibilitychange', run);
  mq.addEventListener('change', run);
  new MutationObserver(draw).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  size(); run();
}
