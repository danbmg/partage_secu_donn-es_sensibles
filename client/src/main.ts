import './style.css';
import { describeAuditEntry, readAuditLog, visibleAuditEntries, type AuditEntry } from './audit.js';
import { loginAccount, logoutAccount, registerAccount, type AuthenticatedSession } from './auth.js';
import { publicKeyFingerprint } from './crypto/index.js';
import { ApiError } from './http.js';
import { rotateAccountKeys } from './keys.js';
import { recoverAccount, regenerateRecoveryKey } from './recovery.js';
import { listItemAccess, revokeVaultItemAccess, shareVaultItem, type ItemAccess } from './sharing.js';
import { createVaultItem, deleteVaultItem, readVaultItems, updateVaultItem, type VaultItem } from './vault.js';

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
let editingItemId: string | null = null;
let confirmingDeleteId: string | null = null;
// Public key (base64) -> fingerprint, computed once per key.
const fingerprints = new Map<string, string>();
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
  editingItemId = null;
  confirmingDeleteId = null;
  fingerprints.clear();
}

// Empties a form in the current DOM, so render() has no draft to restore into it.
function clearDraft(selector: string): void {
  for (const field of app.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(`${selector} input, ${selector} textarea`)) {
    field.value = '';
  }
}

// Server and crypto errors are in English (they end up in logs); the page speaks French.
const ERROR_MESSAGES: Record<string, string> = {
  'Invalid email or authentication proof': 'Adresse e-mail ou mot de passe maître incorrect.',
  'Account not found': 'Aucun compte ne correspond à cette adresse.',
  'Account already exists': 'Un compte existe déjà avec cette adresse.',
  'Invalid email or recovery key': 'Adresse e-mail ou clé de secours incorrecte.',
  'Invalid recovery key': 'Clé de secours mal saisie : 32 caractères, lettres A à Z et chiffres 2 à 7.',
  'Invalid master password': 'Mot de passe maître incorrect.',
  'Too many failed attempts, try again later': 'Trop de tentatives échouées : réessayez dans quelques minutes.',
  'Recipient not found': 'Aucun compte ne correspond à ce destinataire.',
  'Item is already shared with this user': 'Ce secret est déjà partagé avec cette personne.',
  'Cannot share an item with yourself': 'Vous avez déjà accès à ce secret.',
  'The access list changed, reload and try again': 'La liste des accès a changé entre-temps : actualisez puis recommencez.',
  'A recipient changed keys, reload and try again': 'Un destinataire vient de renouveler ses clés : actualisez puis recommencez.',
  'Public key does not match private key': 'La clé publique fournie par le serveur ne correspond pas à votre clé privée : connexion refusée.',
  'Your item list changed, reload and try again': 'Un secret vient d’être partagé avec vous : actualisez puis recommencez.',
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
        <input id="new-master-password" data-no-draft name="password" type="password" autocomplete="new-password" placeholder="12 caractères minimum" minlength="12" required />
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
        <input id="master-password" data-no-draft name="password" type="password" autocomplete="${registering ? 'new-password' : 'current-password'}" placeholder="${registering ? '12 caractères minimum' : 'Votre mot de passe'}" ${registering ? 'minlength="12"' : ''} required />
        <button class="button button-primary" type="submit" ${busy ? 'disabled' : ''}>${busy ? 'Veuillez patienter…' : registering ? 'Créer mon coffre' : 'Se connecter'}</button>
      </form>
      <p class="switch-mode">${registering ? 'Vous avez déjà un compte ?' : 'Nouveau ici ?'}
        <button type="button" class="text-button" data-action="toggle-auth">${registering ? 'Se connecter' : 'Créer un compte'}</button>
      </p>
      ${registering ? '' : '<p class="switch-mode"><button type="button" class="text-button" data-action="show-recover">Mot de passe oublié ?</button></p>'}
      <p class="privacy-note"><span class="lock-icon" aria-hidden="true">◆</span> Votre mot de passe maître reste dans votre navigateur.</p>
    </section>`;
}

function renderItemActions(item: VaultItem): string {
  const id = escapeHtml(item.id);
  if (confirmingDeleteId === item.id) {
    return `
      <div class="card-actions confirm">
        <span>Supprimer définitivement ce secret, pour vous et pour les personnes avec qui il est partagé ?</span>
        <button type="button" class="button button-danger" data-action="confirm-delete" data-id="${id}" ${busy ? 'disabled' : ''}>Supprimer</button>
        <button type="button" class="button button-quiet" data-action="cancel-delete">Annuler</button>
      </div>`;
  }
  return `
    <div class="card-actions">
      <button type="button" class="text-button" data-action="edit" data-id="${id}" ${busy ? 'disabled' : ''}>Modifier</button>
      <button type="button" class="text-button danger" data-action="delete" data-id="${id}" ${busy ? 'disabled' : ''}>Supprimer</button>
    </div>`;
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
      ${ownItem ? renderItemActions(item) : ''}
      ${ownItem ? `
        <div class="share-area">
          <form class="share-form" data-share-id="${escapeHtml(item.id)}">
            <label for="recipient-${escapeHtml(item.id)}">Partager avec</label>
            <div class="inline-form"><input id="recipient-${escapeHtml(item.id)}" name="email" type="email" placeholder="destinataire@exemple.fr" required /><button type="submit" class="button button-secondary" ${busy ? 'disabled' : ''}>Partager</button></div>
          </form>
          ${sharedUsers.length ? `
          <ul class="access-list" aria-label="Personnes ayant accès">
            ${sharedUsers.map((access) => `
              <li><span class="access-who">${escapeHtml(access.email)}${access.publicKey && fingerprints.has(access.publicKey) ? `<code class="fingerprint" title="Empreinte de sa clé publique">${escapeHtml(fingerprints.get(access.publicKey) ?? '')}</code>` : ''}</span><button type="button" class="text-button danger" data-action="revoke" data-item-id="${escapeHtml(item.id)}" data-user-id="${escapeHtml(access.userId)}" data-email="${escapeHtml(access.email)}" ${busy ? 'disabled' : ''}>Retirer l’accès</button></li>`).join('')}
          </ul>` : '<p class="shared-list">Pas encore partagé</p>'}
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
        <h2 id="security-title">Clés et secours</h2>
        <p class="${missing ? 'warning-text' : ''}">${missing
          ? 'Ce compte n’a pas encore de clé de secours : un mot de passe oublié rendrait le coffre illisible.'
          : 'Clé de secours perdue ou vue par quelqu’un ? Remplacez-la : l’ancienne cessera aussitôt de fonctionner.'}</p>
        <p>Renouveler vos clés remplace votre paire de clés de chiffrement, ré-enveloppe l’accès à chaque secret, ferme vos autres sessions et vous donne une nouvelle clé de secours.</p>
        <p class="fingerprint-block">Empreinte de votre clé publique
          <code class="fingerprint">${escapeHtml(fingerprints.get(session.publicKey) ?? '…')}</code>
          <span>Pour vérifier un partage, comparez-la de vive voix avec celle que votre interlocuteur voit à côté de votre adresse.</span>
        </p>
      </div>
      <form id="security-form" class="form-stack">
        <label for="security-password">Mot de passe maître</label>
        <input id="security-password" data-no-draft name="password" type="password" autocomplete="current-password" required />
        <button class="button button-secondary" type="submit" name="intent" value="recovery" ${busy ? 'disabled' : ''}>Générer une nouvelle clé de secours</button>
        <button class="button button-quiet" type="submit" name="intent" value="rotate" ${busy ? 'disabled' : ''}>Renouveler mes clés de chiffrement</button>
      </form>
    </section>`;
}

function renderVault(): string {
  if (!session) return renderAuth();
  const editing = editingItemId ? (items.find((item) => item.id === editingItemId) ?? null) : null;
  const prefill = (value: string | undefined) => (editing ? escapeHtml(value ?? '') : '');
  return `
    ${renderRecoveryKey()}
    <section class="vault-layout" aria-label="Coffre-fort">
      <div class="side-column">
      <section class="panel create-panel ${editing ? 'is-editing' : ''}" aria-labelledby="create-title">
        <div class="section-heading">
          <span class="eyebrow">${editing ? 'Modification' : 'Nouveau contenu'}</span>
          <h2 id="create-title">${editing ? 'Modifier le secret' : 'Ajouter un secret'}</h2>
          <p>${editing
            ? 'Il est rechiffré dans le navigateur ; les personnes qui y ont accès verront la nouvelle version.'
            : 'Il est chiffré dans le navigateur avant son enregistrement.'}</p>
        </div>
        <form id="secret-form" class="form-stack">
          <label for="secret-name">Nom du secret</label>
          <input id="secret-name" name="name" placeholder="Ex. Compte de démonstration" value="${prefill(editing?.name)}" required />
          <div class="two-columns">
            <div><label for="secret-username">Identifiant</label><input id="secret-username" name="username" autocomplete="off" value="${prefill(editing?.username)}" /></div>
            <div><label for="secret-password">Mot de passe</label><input id="secret-password" name="password" type="password" autocomplete="new-password" value="${prefill(editing?.password)}" /></div>
          </div>
          <label for="secret-notes">Notes</label>
          <textarea id="secret-notes" name="notes" rows="3" placeholder="Informations utiles (facultatif)">${prefill(editing?.notes)}</textarea>
          <button class="button button-primary" type="submit" ${busy ? 'disabled' : ''}>${busy ? 'Enregistrement…' : editing ? 'Rechiffrer et enregistrer' : 'Chiffrer et enregistrer'}</button>
          ${editing ? '<button class="button button-quiet" type="button" data-action="cancel-edit">Annuler la modification</button>' : ''}
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

// render() rebuilds the whole page: without this, any notice (an error, a busy state)
// would wipe what the user was typing. Master passwords are deliberately not kept.
function captureDrafts(): Map<string, string> {
  const drafts = new Map<string, string>();
  for (const field of app.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('input[id], textarea[id]')) {
    if (!field.hasAttribute('data-no-draft') && field.value) drafts.set(field.id, field.value);
  }
  return drafts;
}

function restoreDrafts(drafts: Map<string, string>): void {
  for (const [id, value] of drafts) {
    const field = document.getElementById(id);
    if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) field.value = value;
  }
}

function render(): void {
  const drafts = captureDrafts();
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
  restoreDrafts(drafts);
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
  const keys = new Set([session.publicKey]);
  for (const accesses of accessByItem.values()) {
    for (const access of accesses) if (access.publicKey) keys.add(access.publicKey);
  }
  await Promise.all(
    [...keys]
      .filter((key) => !fingerprints.has(key))
      .map(async (key) => fingerprints.set(key, await publicKeyFingerprint(key))),
  );
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
  } else if (action === 'revoke' && session) {
    const { itemId, userId, email } = button.dataset;
    if (!itemId || !userId) return;
    busy = true;
    notice = '';
    render();
    try {
      await revokeVaultItemAccess(itemId, userId, session);
      busy = false;
      await refreshAfterChange(`Accès retiré à ${email ?? 'ce destinataire'}. Le secret a été rechiffré avec une nouvelle clé.`);
    } catch (error) {
      busy = false;
      showError(error, 'Le retrait d’accès a échoué.');
    }
  } else if (action === 'edit' && button.dataset.id) {
    clearDraft('#secret-form');
    editingItemId = button.dataset.id;
    confirmingDeleteId = null;
    notice = '';
    render();
    app.querySelector<HTMLInputElement>('#secret-name')?.focus();
  } else if (action === 'cancel-edit') {
    clearDraft('#secret-form');
    editingItemId = null;
    render();
  } else if (action === 'delete' && button.dataset.id) {
    confirmingDeleteId = button.dataset.id;
    notice = '';
    render();
  } else if (action === 'cancel-delete') {
    confirmingDeleteId = null;
    render();
  } else if (action === 'confirm-delete' && button.dataset.id && session) {
    const id = button.dataset.id;
    busy = true;
    render();
    try {
      await deleteVaultItem(id, session);
      busy = false;
      confirmingDeleteId = null;
      if (editingItemId === id) {
        clearDraft('#secret-form');
        editingItemId = null;
      }
      await refreshAfterChange('Secret supprimé : plus personne n’y a accès.');
    } catch (error) {
      busy = false;
      showError(error, 'La suppression a échoué.');
    }
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
    const submitter = (event as SubmitEvent).submitter;
    const intent = submitter instanceof HTMLButtonElement ? submitter.value : 'recovery';
    busy = true;
    notice = '';
    render();
    try {
      if (intent === 'rotate') {
        const rotation = await rotateAccountKeys(session, password);
        session = rotation.session;
        pendingRecoveryKey = rotation.recoveryKey;
        busy = false;
        await refreshAfterChange(
          `Clés renouvelées : ${rotation.itemCount} secret(s) ré-enveloppé(s), autres sessions fermées. Notez votre nouvelle clé de secours.`,
        );
      } else {
        pendingRecoveryKey = await regenerateRecoveryKey(session, password);
        busy = false;
        await refreshAfterChange('Nouvelle clé de secours créée. L’ancienne ne fonctionne plus.');
      }
    } catch (error) {
      busy = false;
      showError(error, intent === 'rotate' ? 'Le renouvellement des clés a échoué.' : 'Impossible de créer une nouvelle clé de secours.');
    }
  } else if (form.id === 'secret-form' && session) {
    const secret = {
      name: String(data.get('name') ?? '').trim(),
      username: String(data.get('username') ?? '').trim(),
      password: String(data.get('password') ?? ''),
      notes: String(data.get('notes') ?? '').trim(),
    };
    const editedId = editingItemId;
    busy = true;
    notice = '';
    render();
    try {
      if (editedId) await updateVaultItem(editedId, secret, session);
      else await createVaultItem(secret, session);
      busy = false;
      editingItemId = null;
      clearDraft('#secret-form');
      await refreshAfterChange(editedId ? 'Secret modifié et rechiffré.' : 'Secret chiffré et enregistré.');
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
      clearDraft(`[data-share-id="${CSS.escape(itemId)}"]`);
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
