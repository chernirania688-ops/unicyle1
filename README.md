# UniCycle Logistics

Application web complète (frontend + backend) de micro-logistique et d'économie circulaire entre étudiants.

- **Backend** : Node.js, Express, base SQLite intégrée à Node.js, sans compilation (fichier `data/unicycle.db`)
- **Comptes** : e-mail + mot de passe (bcrypt), session par cookie sécurisé valable 30 jours (reconnexion automatique)
- **Frontend** : `public/index.html`, servi par le même serveur

## Lancer en local

Prérequis : Node.js 22.13 ou plus (24 recommandé) (https://nodejs.org).

```bash
npm install
npm start
```

Ouvre http://localhost:3000, crée un compte, publie une annonce. Pour tester le flux complet, crée un second compte
dans une fenêtre de navigation privée (acheteur) et un troisième avec « Je veux aussi livrer » (livreur).

`npm test` exécute les 43 vérifications automatiques de l'API.

## Fonctionnalités

- Inscription, connexion, déconnexion, modification du profil, mode étudiant livreur
- Annonces avec recherche, filtres par catégorie et campus, retrait d'annonce
- **Photo** sur chaque annonce (réduite automatiquement dans le navigateur avant l'envoi)
- Commande avec choix de remise : main propre (0 €), livraison étudiante (3 €), point relais (2 €)
- **Demande d'achat** : le vendeur reçoit un message avec le prix et doit **confirmer la vente ou la refuser**. L'acheteur ne paie rien tant que le vendeur n'a pas confirmé, et peut annuler avant sa réponse
- Onglet **Messages** : demandes d'achat, confirmations, réclamations, avec compteur de nouveaux messages
- Paiement **en séquestre simulé** : après confirmation du vendeur, l'acheteur confirme la réception, sinon libération automatique 48 h après le début de la livraison, ou litige
- **Réclamation après vente** : pendant 7 jours après la réception, l'acheteur peut signaler un objet qui ne convient pas (motif + détails). Le vendeur est prévenu et accepte (achat remboursé) ou refuse en expliquant sa décision
- Missions de livraison pour les livreurs (80 % du tarif)
- Historique des paiements, ventes et gains, conservé dans la base

## Variables d'environnement

| Variable | Rôle | Défaut |
|---|---|---|
| `PORT` | port du serveur | 3000 |
| `DATA_DIR` | dossier de la base SQLite | `./data` |
| `JWT_SECRET` | secret de signature des sessions | généré dans `data/.secret` |
| `NODE_ENV=production` | cookies `secure` (HTTPS obligatoire) | |

## Mettre en ligne

Il faut un hébergeur Node.js avec un **disque persistant** (Render, Railway, Fly.io, un VPS...) :
commande de build `npm install`, commande de démarrage `npm start`, `DATA_DIR` pointant vers le disque persistant,
HTTPS activé et `NODE_ENV=production`.

## Limites actuelles (à traiter avant un vrai lancement)

- Le séquestre est **simulé** : aucun argent ne circule. Pour de vrais paiements, intégrer un prestataire
  agréé avec compte de cantonnement (par exemple Stripe Connect ou Mangopay).
- Pas de vérification de l'e-mail étudiant, ni de réinitialisation de mot de passe par e-mail.
- Pas de discussion libre entre acheteur et vendeur (seulement des messages automatiques), pas de photos multiples, pas de modération : si le vendeur refuse une réclamation, aucun support humain n'intervient encore.
- Le remboursement est simulé, comme le paiement.
- Pas d'algorithme de matching par trajet, ni de location de kits, ni de tableaux de bord pour les universités.
- Limiteur de tentatives de connexion en mémoire, adapté à un seul serveur.
