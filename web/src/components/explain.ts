import { h } from '../util';
import { emit } from '../state';

/** A real button that asks the pet to explain a [data-explain] target. */
export function explainButton(target: string, label: string): HTMLButtonElement {
  return h('button', {
    type: 'button', class: 'explain-btn', 'data-explain-for': target,
    'aria-label': `Explain: ${label}`, title: 'Ask the assistant to explain this',
    onClick: (e: Event) => { e.stopPropagation(); emit('pet:explain', { target, source: 'button' }); },
  }, h('span', { class: 'explain-dot', 'aria-hidden': 'true' }), 'Explain');
}
