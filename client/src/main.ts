import './style.css';
import { describeAuditEntry, readAuditLog, visibleAuditEntries, type AuditEntry } from './audit.js';
import { loginAccount, logoutAccount, registerAccount, type AuthenticatedSession } from './auth.js';
import { ApiError } from './http.js';
import { recoverAccount, regenerateRecoveryKey } from './recovery.js';
import { shareVaultItem, listItemAccess, type ItemAccess } from './sharing.js';
import { createVaultItem, readVaultItems, type VaultItem } from './vault.js';

const root = document.querySelector<HTMLDivElement>('#app');
if (!root) throw new Error('Application root was not found');
const app: HTMLDivElement = root;

let session: AuthenticatedSession | null = null;
let accountEmail = '';
let authMode: 'login' | 'register' | 'recover' = 'register';
// Shown once, right after it is created, then forgotten by the page.
let pendingRecoveryKey: string | null = null;
let items: VaultItem[] = [];
let accessByItem = new Map<string, ItemAccess[]>();
let auditEntries: AuditEntry[] = [];
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

function clearSession(): void {
  session = null;
  accountEmail = '';
  items = [];
  accessByItem.clear();
  auditEntries = [];
  pendingRecoveryKey = null;
}

// Server and crypto errors are in English (they end up in logs); the page speaks French.
const ERROR_MESSAGES: Record<string, string> = {
  'Invalid email or authentication proof': 'Adresse e-mail ou mot de passe maître incorrect.',
  'Account not found': 'Aucun compte ne correspond à cette adresse.',
  'Account already exists': 'Un compte existe déjà avec cette adresse.',
  'Invalid email or recovery key': 'Adresse e-mail ou clé de secours incorrecte.',
  'Invalid recovery key': 'Clé de secours mal saisie : 32 caractères, lettres A à Z et chiffres 2 à 7.',
  'Invalid master password': 'Mot de passe maître incorrect.',
  'Recipient not found': 'Aucun compte ne correspond à ce destinataire.',
  'Item is already shared with this user': 'Ce secret est déjà partagé avec cette personne.',
  'Cannot share an item with yourself': 'Vous avez déjà accès à ce secret.',
};

// A 401 while logged in means the server no longer knows this session
// (logged out elsewhere, expired, or account reset): drop the local state.
function showError(error: unknown, fallback: string): void {
  if (session && error instanceof ApiError && error.status === 401) {
    clearSession();
    setNotice('Votre session a expiré. Reconnectez-vous.', 'error');
    return;
  }
  const message = error instanceof Error ? error.message : fallback;
  setNotice(ERROR_MESSAGES[message] ?? message, 'error');
}

function renderRecoverForm(): string {
  return `
    <section class="auth-card panel" aria-labelledby="auth-title">
      <div class="section-heading">
        <span class="eyebrow">Mot de passe oublié</span>
        <h2 id="auth-title">Récupérer mon compte</h2>
        <p>Saisissez la clé de secours reçue à la création du compte, puis choisissez un nouveau mot de passe maître.</p>
      </div>
      <form id="recover-form" class="form-stack">
        <label for="recover-email">Adresse e-mail</label>
        <input id="recover-email" name="email" type="email" autocomplete="email" placeholder="vous@exemple.fr" required />
        <label for="recovery-key">Clé de secours</label>
        <input id="recovery-key" name="recoveryKey" class="mono-input" autocomplete="off" spellcheck="false" placeholder="ABCD-EFGH-…" required />
        <label for="new-master-password">Nouveau mot de passe maître</label>
        <input id="new-master-password" name="password" type="password" autocomplete="new-password" placeholder="12 caractères minimum" minlength="12" required />
        <button class="button button-primary" type="submit" ${busy ? 'disabled' : ''}>${busy ? 'Veuillez patienter…' : 'Réinitialiser mon accès'}</button>
      </form>
      <p class="switch-mode"><button type="button" class="text-button" data-action="show-login">Retour à la connexion</button></p>
      <p class="privacy-note"><span class="lock-icon" aria-hidden="true">◆</span> La clé de secours déchiffre votre coffre dans ce navigateur, elle n’est jamais envoyée.</p>
    </section>`;
}

function renderAuth(): string {
  if (authMode === 'recover') return renderRecoverForm();
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
      ${registering ? '' : '<p class="switch-mode"><button type="button" class="text-button" data-action="show-recover">Mot de passe oublié ?</button></p>'}
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

function renderAudit(): string {
  if (!session) return '';
  const userId = session.userId;
  const itemNames = new Map(items.map((item) => [item.id, item.name]));
  const entries = visibleAuditEntries(auditEntries, userId).slice(0, 30);
  const timeFormat = new Intl.DateTimeFormat('fr-FR', { dateStyle: 'short', timeStyle: 'short' });
  const rows = entries.map((entry) => {
    const line = describeAuditEntry(entry, userId, itemNames);
    return `
      <li class="audit-entry">
        <span class="audit-action">${escapeHtml(line.label)}</span>
        <span class="audit-detail">${escapeHtml(line.detail || '—')}</span>
        <span class="audit-meta">par ${escapeHtml(line.actor)} · <time datetime="${escapeHtml(entry.createdAt)}">${escapeHtml(timeFormat.format(new Date(entry.createdAt)))}</time></span>
      </li>`;
  });
  return `
    <section class="audit-panel" aria-labelledby="audit-title">
      <div class="items-heading"><div><span class="eyebrow">Traçabilité</span><h2 id="audit-title">Journal d’activité</h2></div></div>
      ${rows.length ? `<ol class="audit-list">${rows.join('')}</ol>` : '<p class="audit-empty">Aucune activité pour le moment.</p>'}
      <p class="audit-note">Vos propres lectures ne sont pas affichées. Les noms des secrets sont déchiffrés dans votre navigateur&nbsp;: le serveur ne voit que des identifiants.</p>
    </section>`;
}

function renderRecoveryKey(): string {
  if (!pendingRecoveryKey) return '';
  return `
    <section class="panel recovery-panel" aria-labelledby="recovery-title">
      <span class="eyebrow">À faire maintenant</span>
      <h2 id="recovery-title">Votre clé de secours</h2>
      <p>C’est le seul moyen de rouvrir votre coffre si vous oubliez votre mot de passe maître. Elle ne sera plus jamais affichée et personne, pas même le service, ne peut la retrouver. Notez-la et rangez-la hors de cet ordinateur.</p>
      <code class="recovery-key">${escapeHtml(pendingRecoveryKey)}</code>
      <div class="recovery-actions">
        <button class="button button-secondary" type="button" data-action="copy-recovery">Copier</button>
        <button class="button button-primary" type="button" data-action="dismiss-recovery">Je l’ai mise en lieu sûr</button>
      </div>
    </section>`;
}

function renderSecurity(): string {
  if (!session) return '';
  const missing = !session.hasRecoveryKey;
  return `
    <section class="panel security-panel ${missing ? 'needs-attention' : ''}" aria-labelledby="security-title">
      <div class="section-heading">
        <span class="eyebrow">Sécurité du compte</span>
        <h2 id="security-title">Clé de secours</h2>
        <p class="${missing ? 'warning-text' : ''}">${missing
          ? 'Ce compte n’a pas encore de clé de secours : un mot de passe oublié rendrait le coffre illisible.'
          : 'Perdue, ou vue par quelqu’un d’autre ? Remplacez-la : l’ancienne cessera aussitôt de fonctionner.'}</p>
      </div>
      <form id="security-form" class="form-stack">
        <label for="security-password">Mot de passe maître</label>
        <input id="security-password" name="password" type="password" autocomplete="current-password" required />
        <button class="button button-secondary" type="submit" name="intent" value="recovery" ${busy ? 'disabled' : ''}>Générer une nouvelle clé de secours</button>
      </form>
    </section>`;
}

function renderVault(): string {
  if (!session) return renderAuth();
  return `
    ${renderRecoveryKey()}
    <section class="vault-layout" aria-label="Coffre-fort">
      <div class="side-column">
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
      ${renderSecurity()}
      </div>
      <section class="items-panel" aria-labelledby="items-title">
        <div class="items-heading"><div><span class="eyebrow">Stockage chiffré</span><h2 id="items-title">Mon coffre <span class="count">${items.length}</span></h2></div><button class="button button-quiet" data-action="refresh" type="button" ${busy ? 'disabled' : ''}>Actualiser</button></div>
        ${items.length ? `<div class="secret-list">${items.map(renderItem).join('')}</div>` : `<div class="empty-state"><div class="empty-icon" aria-hidden="true">◇</div><h3>Votre coffre est vide</h3><p>Ajoutez un premier secret avec le formulaire.</p></div>`}
        ${renderAudit()}
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
  auditEntries = await readAuditLog(session);
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
  } else if (action === 'show-recover' || action === 'show-login') {
    authMode = action === 'show-recover' ? 'recover' : 'login';
    notice = '';
    render();
  } else if (action === 'copy-recovery' && pendingRecoveryKey) {
    await navigator.clipboard.writeText(pendingRecoveryKey).then(
      () => setNotice('Clé de secours copiée. Collez-la hors de cet ordinateur, puis videz le presse-papiers.'),
      () => setNotice('Copie impossible : recopiez la clé à la main.', 'error'),
    );
  } else if (action === 'dismiss-recovery') {
    pendingRecoveryKey = null;
    notice = '';
    render();
  } else if (action === 'logout') {
    const current = session;
    const serverConfirmed = current
      ? await logoutAccount(current).then(
          () => true,
          (error: unknown) => error instanceof ApiError && error.status === 401,
        )
      : true;
    clearSession();
    if (serverConfirmed) setNotice('Vous êtes déconnecté.');
    else setNotice('Déconnecté de cet appareil, mais le serveur est injoignable : la session expirera d’elle-même.', 'error');
  } else if (action === 'refresh') {
    try {
      await loadItems();
      setNotice('Coffre actualisé.');
    } catch (error) {
      showError(error, 'Impossible de charger le coffre.');
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
      const registration = authMode === 'register' ? await registerAccount(email, password) : null;
      session = await loginAccount(email, password);
      accountEmail = email;
      pendingRecoveryKey = registration?.recoveryKey ?? null;
      await loadItems();
      busy = false;
      setNotice(registration ? 'Compte créé. Notez votre clé de secours avant de continuer.' : 'Connexion réussie.');
    } catch (error) {
      busy = false;
      showError(error, 'La connexion a échoué.');
    }
  } else if (form.id === 'recover-form') {
    const email = String(data.get('email') ?? '').trim().toLowerCase();
    const recoveryKey = String(data.get('recoveryKey') ?? '');
    const password = String(data.get('password') ?? '');
    busy = true;
    notice = '';
    render();
    try {
      const newRecoveryKey = await recoverAccount(email, recoveryKey, password);
      session = await loginAccount(email, password);
      accountEmail = email;
      authMode = 'login';
      pendingRecoveryKey = newRecoveryKey;
      await loadItems();
      busy = false;
      setNotice('Mot de passe réinitialisé. L’ancienne clé de secours ne fonctionne plus : notez la nouvelle.');
    } catch (error) {
      busy = false;
      showError(error, 'La récupération du compte a échoué.');
    }
  } else if (form.id === 'security-form' && session) {
    const password = String(data.get('password') ?? '');
    busy = true;
    notice = '';
    render();
    try {
      pendingRecoveryKey = await regenerateRecoveryKey(session, password);
      busy = false;
      await refreshAfterChange('Nouvelle clé de secours créée. L’ancienne ne fonctionne plus.');
    } catch (error) {
      busy = false;
      showError(error, 'Impossible de créer une nouvelle clé de secours.');
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
      showError(error, 'Impossible d’enregistrer ce secret.');
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
      showError(error, 'Le partage a échoué.');
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
