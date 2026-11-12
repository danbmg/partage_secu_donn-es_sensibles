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

Les interfaces de coffre, d'authentification, de récupération de compte, de révocation et de journal d'audit détaillé restent à réaliser dans les tâches suivantes.
