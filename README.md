# Partage sécurisé de données sensibles

Application de coffre-fort partagé dont le serveur ne reçoit que des données chiffrées. Le chiffrement et les clés privées restent côté navigateur.

## Prérequis

- Node.js 20 ou plus récent
- npm

## Installation et lancement

```sh
npm install
npm run dev
```

Le client Vite est disponible sur <http://localhost:5173> et l'API sur <http://localhost:3000>. Le client relaie `/api` vers l'API.

## Vérifications

```sh
npm test
npm run lint
npm run build
```
