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

1. `registerAccount()` crée le sel, le dérivé d'authentification et la paire RSA dans le navigateur. Le serveur conserve le dérivé re-haché avec scrypt, la clé publique et la clé privée chiffrée.
2. `loginAccount()` récupère le sel public, prouve le mot de passe avec le dérivé et déchiffre la clé privée uniquement en mémoire côté client.
3. `createVaultItem()` chiffre le contenu avec une clé AES-256-GCM unique, puis enveloppe cette clé avec la clé publique du propriétaire.
4. `shareVaultItem()` enveloppe la même clé d'élément avec la clé publique du destinataire. Le destinataire peut alors lire le ciphertext avec sa clé privée.
5. `readAuditLog()` récupère le journal d'activité : les actions de l'utilisateur et toute action d'un tiers sur un élément dont il est propriétaire (lecture, partage). Le serveur ne connaît que des identifiants d'éléments ; le navigateur les remplace par les noms déchiffrés.

## Routes de l'API

| Méthode | Route | Session | Rôle |
|---|---|---|---|
| GET | `/api/health` | non | état du service |
| GET | `/api/auth/salt?email=` | non | sel de dérivation du compte |
| GET | `/api/users/:email/public-key` | non | clé publique d'un destinataire |
| POST | `/api/register` | non | création de compte (dérivé d'authentification, clé publique, clé privée chiffrée) |
| POST | `/api/login` | non | preuve du mot de passe → jeton de session et clé privée chiffrée |
| GET | `/api/items` | oui | éléments accessibles (ciphertext + clé enveloppée pour l'appelant) |
| POST | `/api/items` | oui | création d'un élément chiffré |
| GET/PUT/DELETE | `/api/items/:id` | oui | lecture, remplacement du ciphertext, suppression (propriétaire) |
| GET/POST | `/api/items/:id/shares` | oui | liste des accès, partage (propriétaire) |
| GET | `/api/audit` | oui | 100 dernières entrées du journal visibles par l'appelant |

## Base de données

Le schéma initial (`baseSchema` dans `server/src/db.ts`) n'est plus modifié : chaque évolution est une migration numérotée, appliquée une seule fois au démarrage grâce à `PRAGMA user_version`. Une base locale existante est donc mise à niveau sans perte de données.

Le journal d'audit est écrit uniquement par `recordAudit()` (`server/src/audit.ts`), qui porte la liste des actions autorisées. Une lecture est journalisée par élément renvoyé, pour qu'un propriétaire voie qui a consulté ses secrets.

Les interfaces de récupération de compte, de révocation et de rotation de clés restent à réaliser dans les tâches suivantes.
