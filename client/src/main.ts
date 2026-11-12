import './style.css';
import { loginAccount, registerAccount, type AuthenticatedSession } from './auth.js';
import { shareVaultItem, listItemAccess, type ItemAccess } from './sharing.js';
import { createVaultItem, readVaultItems, type VaultItem } from './vault.js';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('Application root was not found');

let session: AuthenticatedSession | null = null;
let accountEmail = '';
let authMode: 'login' | 'register' = 'register';
let items: VaultItem[] = [];
let accessByItem = new Map<string, ItemAccess[]>();
let notice = '';
let noticeKind: 'success' | 'error' = 'success';
let apiReady = false;
let busy = false;

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    const entities: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    };
    return entities[character] ?? character;
  });
}

function setNotice(message: string, kind: 'success' | 'error' = 'success'): void {
  notice = message;
  noticeKind = kind;
  render();
}

function renderAuth(): string {
  const registering = authMode === 'register';
  return `
    <section class="auth-card panel" aria-labelledby="auth-title">
      <div class="section-heading">
        <span class="eyebrow">Votre espace sécurisé</span>
        <h2 id="auth-title">${registering ? 'Créer un compte' : 'Se connecter'}</h2>
        <p>${registering ? 'Créez votre coffre personnel.' : 'Retrouvez votre coffre chiffré.'}</p>
      </div>
      <form id="auth-form" class="form-stack">
        <label for="email">Adresse e-mail</label>
        <input id="email" name="email" type="email" autocomplete="email" placeholder="vous@exemple.fr" required />
        <label for="master-password">Mot de passe maître</label>
        <input id="master-password" name="password" type="password" autocomplete="${registering ? 'new-password' : 'current-password'}" placeholder="${registering ? '12 caractères minimum' : 'Votre mot de passe'}" ${registering ? 'minlength="12"' : ''} required />
        <button class="button button-primary" type="submit" ${busy ? 'disabled' : ''}>${busy ? 'Veuillez patienter…' : registering ? 'Créer mon coffre' : 'Se connecter'}</button>
      </form>
      <p class="switch-mode">${registering ? 'Vous avez déjà un compte ?' : 'Nouveau ici ?'}
        <button type="button" class="text-button" data-action="toggle-auth">${registering ? 'Se connecter' : 'Créer un compte'}</button>
      </p>
      <p class="privacy-note"><span class="lock-icon" aria-hidden="true">◆</span> Votre mot de passe maître reste dans votre navigateur.</p>
    </section>`;
}

function renderItem(item: VaultItem): string {
  const ownItem = item.ownerId === session?.userId;
  const accesses = accessByItem.get(item.id) ?? [];
  const sharedUsers = accesses.filter((access) => access.userId !== item.ownerId);
  return `
    <article class="secret-card">
      <div class="secret-heading">
        <div>
          <span class="eyebrow">${ownItem ? 'Mon secret' : 'Partagé avec moi'}</span>
          <h3>${escapeHtml(item.name)}</h3>
        </div>
        <span class="badge">${ownItem ? 'Chiffré' : 'Reçu'}</span>
      </div>
      <dl class="secret-details">
        <div><dt>Identifiant</dt><dd>${escapeHtml(item.username || '—')}</dd></div>
        <div class="password-row"><dt>Mot de passe</dt><dd><input aria-label="Mot de passe de ${escapeHtml(item.name)}" data-password-for="${escapeHtml(item.id)}" type="password" readonly value="${escapeHtml(item.password)}" /><button type="button" class="text-button" data-action="reveal" data-id="${escapeHtml(item.id)}">Afficher</button></dd></div>
        ${item.notes ? `<div class="notes-row"><dt>Notes</dt><dd>${escapeHtml(item.notes)}</dd></div>` : ''}
      </dl>
      ${ownItem ? `
        <div class="share-area">
          <form class="share-form" data-share-id="${escapeHtml(item.id)}">
            <label for="recipient-${escapeHtml(item.id)}">Partager avec</label>
            <div class="inline-form"><input id="recipient-${escapeHtml(item.id)}" name="email" type="email" placeholder="destinataire@exemple.fr" required /><button type="submit" class="button button-secondary" ${busy ? 'disabled' : ''}>Partager</button></div>
          </form>
          <p class="shared-list">${sharedUsers.length ? `Partagé avec ${sharedUsers.map((access) => escapeHtml(access.email)).join(', ')}` : 'Pas encore partagé'}</p>
        </div>` : ''}
    </article>`;
}

function renderVault(): string {
  if (!session) return renderAuth();
  return `
    <section class="vault-layout" aria-label="Coffre-fort">
      <section class="panel create-panel" aria-labelledby="create-title">
        <div class="section-heading">
          <span class="eyebrow">Nouveau contenu</span>
          <h2 id="create-title">Ajouter un secret</h2>
          <p>Il est chiffré dans le navigateur avant son enregistrement.</p>
        </div>
        <form id="secret-form" class="form-stack">
          <label for="secret-name">Nom du secret</label>
          <input id="secret-name" name="name" placeholder="Ex. Compte de démonstration" required />
          <div class="two-columns">
            <div><label for="secret-username">Identifiant</label><input id="secret-username" name="username" autocomplete="off" /></div>
            <div><label for="secret-password">Mot de passe</label><input id="secret-password" name="password" type="password" autocomplete="new-password" /></div>
          </div>
          <label for="secret-notes">Notes</label>
          <textarea id="secret-notes" name="notes" rows="3" placeholder="Informations utiles (facultatif)"></textarea>
          <button class="button button-primary" type="submit" ${busy ? 'disabled' : ''}>${busy ? 'Enregistrement…' : 'Chiffrer et enregistrer'}</button>
        </form>
      </section>
      <section class="items-panel" aria-labelledby="items-title">
        <div class="items-heading"><div><span class="eyebrow">Stockage chiffré</span><h2 id="items-title">Mon coffre <span class="count">${items.length}</span></h2></div><button class="button button-quiet" data-action="refresh" type="button" ${busy ? 'disabled' : ''}>Actualiser</button></div>
        ${items.length ? `<div class="secret-list">${items.map(renderItem).join('')}</div>` : `<div class="empty-state"><div class="empty-icon" aria-hidden="true">◇</div><h3>Votre coffre est vide</h3><p>Ajoutez un premier secret avec le formulaire.</p></div>`}
      </section>
    </section>`;
}

function render(): void {
  app.innerHTML = `
    <div class="page-shell">
      <header class="topbar">
        <a class="brand" href="#" aria-label="Partage sécurisé, accueil"><span class="brand-mark" aria-hidden="true">◆</span><span>safe<span class="brand-light">share</span></span></a>
        <div class="topbar-right"><span class="api-indicator"><span class="status-dot ${apiReady ? 'is-online' : ''}"></span>${apiReady ? 'Service disponible' : 'Connexion…'}</span>
          ${session ? `<span class="account-email">${escapeHtml(accountEmail)}</span><button class="button button-quiet" type="button" data-action="logout">Déconnexion</button>` : ''}
        </div>
      </header>
      <main>
        <section class="hero">
          <div class="hero-copy"><span class="eyebrow">Partage confidentiel, simplement</span><h1>Vos secrets restent <span>à vous.</span></h1><p>Chiffrez vos informations dans le navigateur et partagez-les avec les bonnes personnes.</p>
            <div class="trust-points"><span><i aria-hidden="true">✓</i> Chiffrement côté navigateur</span><span><i aria-hidden="true">✓</i> Clés protégées par votre mot de passe maître</span></div>
          </div>
          <div class="hero-art" aria-hidden="true"><div class="orbit orbit-one"></div><div class="orbit orbit-two"></div><div class="shield"><span>◆</span></div><div class="float-card card-top"><span class="mini-dot"></span> Clé privée <b>protégée</b></div><div class="float-card card-bottom"><span class="mini-lock">◆</span> Chiffré sur cet appareil</div></div>
        </section>
        ${renderVault()}
        ${notice ? `<div class="toast ${noticeKind}" role="status">${escapeHtml(notice)}</div>` : ''}
      </main>
      <footer class="footer"><span>SafeShare</span><span>Vos données sont chiffrées avant leur envoi.</span><span>Démo pédagogique</span></footer>
    </div>`;
}

async function loadItems(): Promise<void> {
  if (!session) return;
  items = await readVaultItems(session);
  const ownerItems = items.filter((item) => item.ownerId === session?.userId);
  const accessEntries = await Promise.all(
    ownerItems.map(async (item) => [item.id, await listItemAccess(item.id, session as AuthenticatedSession)] as const),
  );
  accessByItem = new Map(accessEntries);
}

async function refreshAfterChange(message: string): Promise<void> {
  if (!session) return;
  await loadItems();
  setNotice(message);
}

app.addEventListener('click', async (event) => {
  const target = event.target;
  if (!(target instanceof Element)) return;
  const button = target.closest<HTMLButtonElement>('[data-action]');
  if (!button) return;
  const action = button.dataset.action;
  if (action === 'toggle-auth') {
    authMode = authMode === 'register' ? 'login' : 'register';
    notice = '';
    render();
  } else if (action === 'logout') {
    session = null;
    accountEmail = '';
    items = [];
    accessByItem.clear();
    notice = 'Vous êtes déconnecté de cet appareil.';
    render();
  } else if (action === 'refresh') {
    try {
      await loadItems();
      setNotice('Coffre actualisé.');
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Impossible de charger le coffre.', 'error');
    }
  } else if (action === 'reveal') {
    const input = app.querySelector<HTMLInputElement>(`[data-password-for="${CSS.escape(button.dataset.id ?? '')}"]`);
    if (input) {
      input.type = input.type === 'password' ? 'text' : 'password';
      button.textContent = input.type === 'password' ? 'Afficher' : 'Masquer';
    }
  }
});

app.addEventListener('submit', async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  event.preventDefault();
  const data = new FormData(form);

  if (form.id === 'auth-form') {
    const email = String(data.get('email') ?? '').trim().toLowerCase();
    const password = String(data.get('password') ?? '');
    busy = true;
    notice = '';
    render();
    try {
      if (authMode === 'register') await registerAccount(email, password);
      session = await loginAccount(email, password);
      accountEmail = email;
      await loadItems();
      busy = false;
      setNotice(authMode === 'register' ? 'Compte créé. Votre coffre est prêt.' : 'Connexion réussie.');
    } catch (error) {
      busy = false;
      setNotice(error instanceof Error ? error.message : 'La connexion a échoué.', 'error');
    }
  } else if (form.id === 'secret-form' && session) {
    const secret = {
      name: String(data.get('name') ?? '').trim(),
      username: String(data.get('username') ?? '').trim(),
      password: String(data.get('password') ?? ''),
      notes: String(data.get('notes') ?? '').trim(),
    };
    busy = true;
    notice = '';
    render();
    try {
      await createVaultItem(secret, session);
      busy = false;
      await refreshAfterChange('Secret chiffré et enregistré.');
    } catch (error) {
      busy = false;
      setNotice(error instanceof Error ? error.message : 'Impossible d’enregistrer ce secret.', 'error');
    }
  } else if (form.dataset.shareId && session) {
    const itemId = form.dataset.shareId;
    const email = String(data.get('email') ?? '').trim().toLowerCase();
    busy = true;
    notice = '';
    render();
    try {
      await shareVaultItem(itemId, email, session);
      busy = false;
      await refreshAfterChange(`Secret partagé avec ${email}.`);
    } catch (error) {
      busy = false;
      setNotice(error instanceof Error ? error.message : 'Le partage a échoué.', 'error');
    }
  }
});

render();
fetch('/api/health')
  .then((response) => {
    if (!response.ok) throw new Error('API unavailable');
    return response.json() as Promise<{ status: string }>;
  })
  .then(({ status }) => {
    apiReady = status === 'ok';
    render();
  })
  .catch(() => {
    apiReady = false;
    render();
  });
