import './styles/tokens.css';
import './styles/base.css';
import { buildShell } from './components/shell';
import { startRouter } from './router';
import { mountChat } from './components/chat';
import { mountPet } from './components/pet';
import { mountStarfield } from './components/starfield';

mountStarfield();
const app = document.getElementById('app')!;
const main = buildShell(app);
startRouter(main);
mountChat(app);
mountPet(app);
