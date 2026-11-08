// One shared "Continue the story" footer. The router appends it after every page, so no page needs to know about it.
import { h } from '../util';
import type { PageId } from '../api';

/** One plain sentence per destination, matching what that page actually renders. */
const BLURB: Record<PageId, string> = {
  galaxy: 'Back to the Galaxy: filter the 2026 scoreboard, pick a family, and watch every panel follow.',
  signals: 'The headline numbers: CVEs ranked, Hits@500, the lift over EPSS, and how the Top 500 differs from the rest.',
  top500: 'The full shortlist of 500 CVEs in a table you can filter by EPSS, exploit signals and family, then open for detail.',
  families: 'Ten IBM Granite families of 2026 CVEs, and how often each family’s historical CVEs reached KEV.',
  discoveries: 'Four short acts on what IBM Granite embeddings found in historical CVEs, and whether it holds out of time.',
  'how-we-ranked': 'How the ranking compares with EPSS and two learned models on past KEV outcomes.',
  ask: 'Generate a grounded brief for any CVE and ask follow-up questions, each answer checked against the data.',
  story: 'The problem, the data, what we found and where it falls short, written out in plain language.',
};

export function nextFooter(pages: { id: PageId; label: string }[], current: PageId): HTMLElement {
  const i = pages.findIndex((p) => p.id === current), next = pages[(i + 1) % pages.length];
  return h('nav', { class: 'next-step', 'aria-label': 'Continue the story' },
    h('a', { class: 'next-card', href: `#/${next.id}` },
      h('span', { class: 'next-kicker' }, 'Continue the story'),
      h('span', { class: 'next-title' }, `${next.label} →`),
      h('span', { class: 'next-lead' }, BLURB[next.id])));
}
