# Partage sécurisé de données sensibles

Coffre-fort de partage construit autour d'un modèle zero-knowledge : le navigateur chiffre chaque élément avant l'envoi et chiffre la clé privée de chaque compte avec une clé dérivée du mot de passe maître.

## Prérequis

- Node.js 20.19+ (ou 22.12+)
- npm

## Installation et lancement

```sh
npm install
npm run dev
```

Le client Vite est disponible sur <http://localhost:5173> et l'API Express sur <http://localhost:3000>. Le client relaie `/api` vers l'API. SQLite crée automatiquement `data/app.sqlite` au premier démarrage.

Pour stabiliser les sessions entre redémarrages et configurer l'emplacement SQLite, définir `SESSION_SECRET` (au moins 32 caractères aléatoires) et `DB_PATH`. Sans secret fourni, le serveur génère un secret éphémère pour le développement local.

## Vérifications

```sh
npm test
npm run check:types
npm run lint
npm run build
```

## Flux disponibles

1. `registerAccount()` crée le sel, le dérivé d'authentification, la paire RSA et une **clé de secours** dans le navigateur. Le serveur conserve le dérivé re-haché avec scrypt, la clé publique, la clé privée chiffrée par le mot de passe maître, et une seconde copie de la clé privée chiffrée par la clé de secours. La clé de secours est affichée une seule fois et n'est jamais envoyée.
2. `loginAccount()` récupère le sel public, prouve le mot de passe avec le dérivé et déchiffre la clé privée uniquement en mémoire côté client.
3. `createVaultItem()` chiffre le contenu avec une clé AES-256-GCM unique, puis enveloppe cette clé avec la clé publique du propriétaire.
4. `shareVaultItem()` enveloppe la même clé d'élément avec la clé publique du destinataire. Le destinataire peut alors lire le ciphertext avec sa clé privée.
5. `revokeVaultItemAccess()` retire l'accès d'un destinataire. Supprimer sa clé enveloppée ne suffit pas (il a pu garder la clé de l'élément) : le navigateur du propriétaire déchiffre l'élément, le rechiffre avec une **nouvelle** clé AES et l'enveloppe pour chaque accès restant. Le serveur applique le tout dans une transaction et refuse (409) un jeu de clés qui oublierait un détenteur ou en ajouterait un.
6. `logoutAccount()` demande au serveur d'oublier la session : le jeton devient inutilisable immédiatement, même s'il a été copié. Si une requête renvoie 401 alors que l'utilisateur est connecté (session fermée ailleurs ou expirée), l'interface revient à l'écran de connexion.
7. `recoverAccount()` (mot de passe oublié) : la clé de secours prouve l'identité (`/api/recovery/key`), déchiffre la clé privée dans le navigateur, qui la rechiffre sous le nouveau mot de passe. La réinitialisation (`/api/recovery/reset`) remplace aussi la clé de secours utilisée par une nouvelle et ferme toutes les sessions du compte.
8. `regenerateRecoveryKey()` remplace la clé de secours d'un utilisateur connecté (clé perdue, ou compte créé avant la récupération). Le serveur exige en plus de la session la preuve du mot de passe maître : un jeton volé ne suffit pas à poser sa propre clé de secours.
9. `rotateAccountKeys()` remplace la paire RSA du compte. Le navigateur déballe chaque clé d'élément avec l'ancienne clé privée et la ré-enveloppe pour la nouvelle clé publique (le contenu des éléments n'est pas rechiffré), chiffre la nouvelle clé privée avec le mot de passe maître et génère une nouvelle clé de secours — l'ancienne protégeait une clé privée devenue inutile. Le serveur exige la preuve du mot de passe, refuse (409) une liste qui oublierait un élément détenu, et ferme les autres sessions du compte, qui gardaient l'ancienne clé privée en mémoire.
10. `readAuditLog()` récupère le journal d'activité : les actions de l'utilisateur et toute action d'un tiers sur un élément dont il est propriétaire (lecture, partage). Le serveur ne connaît que des identifiants d'éléments ; le navigateur les remplace par les noms déchiffrés.

## Routes de l'API

| Méthode | Route | Session | Rôle |
|---|---|---|---|
| GET | `/api/health` | non | état du service |
| GET | `/api/auth/salt?email=` | non | sel de dérivation du compte |
| GET | `/api/users/:email/public-key` | non | clé publique d'un destinataire |
| POST | `/api/register` | non | création de compte (dérivé d'authentification, clé publique, clé privée chiffrée) |
| POST | `/api/login` | non | preuve du mot de passe → jeton de session et clé privée chiffrée |
| POST | `/api/logout` | oui | ferme la session courante (les autres appareils restent connectés) |
| POST | `/api/recovery/key` | non | preuve de la clé de secours → clé privée chiffrée par la clé de secours |
| POST | `/api/recovery/reset` | non | preuve de la clé de secours → nouveau mot de passe, nouvelle clé de secours, sessions fermées |
| PUT | `/api/account/recovery` | oui + preuve du mot de passe | nouvelle clé de secours |
| POST | `/api/account/rotate-keys` | oui + preuve du mot de passe | nouvelle paire de clés, clés d'éléments ré-enveloppées, nouvelle clé de secours |
| GET | `/api/items` | oui | éléments accessibles (ciphertext + clé enveloppée pour l'appelant) |
| POST | `/api/items` | oui | création d'un élément chiffré |
| GET/PUT/DELETE | `/api/items/:id` | oui | lecture, remplacement du ciphertext, suppression (propriétaire) |
| GET/POST | `/api/items/:id/shares` | oui | liste des accès (avec clés publiques), partage (propriétaire) |
| DELETE | `/api/items/:id/shares/:userId` | oui | révocation + nouveau ciphertext et nouvelles clés enveloppées (propriétaire) |
| GET | `/api/audit` | oui | 100 dernières entrées du journal visibles par l'appelant |

## Base de données

Le schéma initial (`baseSchema` dans `server/src/db.ts`) n'est plus modifié : chaque évolution est une migration numérotée, appliquée une seule fois au démarrage grâce à `PRAGMA user_version`. Une base locale existante est donc mise à niveau sans perte de données.

Les jetons de session sont signés (HMAC-SHA-256) **et** enregistrés dans la table `sessions` : un jeton n'est accepté que si sa ligne existe encore. La signature écarte les jetons forgés sans requête SQL ; la table permet de fermer une session avant son expiration (8 h).

Le journal d'audit est écrit uniquement par `recordAudit()` (`server/src/audit.ts`), qui porte la liste des actions autorisées. Une lecture est journalisée par élément renvoyé, pour qu'un propriétaire voie qui a consulté ses secrets.

## Clé de secours : pourquoi ce n'est pas une porte dérobée

La clé de secours fait 160 bits aléatoires, affichés en 8 groupes de 4 caractères base32. Elle est générée et utilisée uniquement dans le navigateur ; le serveur ne stocke qu'un dérivé re-haché (pour vérifier une preuve) et une copie de la clé privée qu'elle chiffre. Sans elle ni le mot de passe, personne — administrateur compris — ne peut rouvrir le coffre. Elle est dérivée avec HKDF plutôt que PBKDF2 : n'étant pas choisie par un humain, il n'y a pas de dictionnaire à ralentir.

Limite assumée : si l'utilisateur perd à la fois son mot de passe maître et sa clé de secours, ses données sont perdues. C'est le prix du modèle zero-knowledge.

## Révocation : ce qu'elle garantit, et ce qu'elle ne peut pas garantir

Après révocation, l'ancien destinataire ne reçoit plus l'élément, et une clé qu'il aurait conservée ne déchiffre plus la version actuelle. En revanche, ce qu'il a déjà lu ou copié avant la révocation reste en sa possession : aucun système ne peut effacer un secret déjà vu. Un mot de passe partagé puis révoqué doit donc aussi être changé à la source.

## Rotation : trois niveaux de clés

| Clé | Quand elle change | Ce qui est refait |
|---|---|---|
| Clé d'élément (AES-256-GCM) | à chaque révocation | contenu rechiffré, clé ré-enveloppée pour les accès restants |
| Paire RSA du compte | « Renouveler mes clés » | clés d'éléments ré-enveloppées, clé privée rechiffrée, nouvelle clé de secours |
| Clé dérivée du mot de passe | réinitialisation par clé de secours | clé privée rechiffrée sous le nouveau mot de passe |

Limites connues : les clés publiques sont distribuées par le serveur sans vérification d'empreinte (un serveur malveillant pourrait substituer la sienne au moment d'un partage) ; aucune limitation du nombre d'essais n'est appliquée sur la connexion et la récupération.
