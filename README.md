# ERA – serveur

## Lancer en local
    npm install
    ADMIN_CODE=moncode npm start      # http://localhost:3000

## Déployer sur Render
1. Mets ce dossier dans un dépôt GitHub.
2. Render → New → Web Service → ce dépôt. Build : `npm install` · Start : `npm start`.
3. Code admin : par défaut `OASIS`. Pour le changer, ajoute `ADMIN_CODE` dans Environment.
4. **Important – sauvegardes** : le disque gratuit de Render est effacé à chaque redéploiement/redémarrage.
   Ajoute un *Disk* (payant) monté sur `/var/data` et mets `DATA_DIR=/var/data`, sinon les comptes disparaissent.

Le jeu est servi par le serveur (`public/index.html`, `window.ERA_API=''`).
Pour l'héberger ailleurs (GitHub Pages), mets `window.ERA_API='https://ton-serveur.onrender.com'` dans le fichier.
