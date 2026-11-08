import { LEGACY_PAGE, type Action, type PageId } from './api';
import { navigate } from './router';
import { openCve } from './components/drawer';
import { applyFilter, emit } from './state';

/** Execute UI actions returned by /api/chat and /api/explain. show_cves is rendered by the chat dock. */
export function runActions(actions: Action[]): void {
  for (const a of actions) {
    switch (a.type) {
      case 'navigate': navigate(LEGACY_PAGE[a.page] ?? (a.page as PageId)); break;
      case 'open_cve': openCve(a.cve_id); break;
      case 'filter_top500': applyFilter(a); navigate('top500'); break;
      case 'highlight': emit('pet:explain', { target: a.target, source: 'chat' }); break;
      case 'show_cves': break;
    }
  }
}

const PAGE_LABEL: Record<string, string> = { galaxy: 'Galaxy', signals: 'Signals', top500: 'Top 500', families: 'Families', discoveries: 'Discoveries', 'how-we-ranked': 'How We Ranked', ask: 'Ask Telly', story: 'Our Story' };

export function describeAction(a: Action): string | null {
  switch (a.type) {
    case 'navigate': return `Go to ${PAGE_LABEL[LEGACY_PAGE[a.page] ?? a.page] ?? a.page}`;
    case 'open_cve': return `Open ${a.cve_id}`;
    case 'highlight': return 'Show me';
    case 'filter_top500': return 'Apply filter';
    default: return null;
  }
}

/** Chart click-through: reset Top 500 filters to `f`, then open the page. Same path as the chat's filter_top500 action. */
export const openTop500 = (f: { signals?: string[]; min_epss?: number; family_id?: string }): void => runActions([{ type: 'filter_top500', ...f }]);
