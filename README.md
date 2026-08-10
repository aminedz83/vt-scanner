# VT Scanner — version Vercel (un seul déploiement, connecté à GitHub)

Ici, **frontend et backend sont dans le même projet** : Vercel héberge la page
(`index.html`) ET les fonctions serveur (`api/scan.js`, `api/status.js`) qui parlent à
VirusTotal. Un seul service à gérer.

## 1. Récupérer une clé API VirusTotal (gratuite)

1. Crée un compte sur https://www.virustotal.com
2. Copie ta clé sur https://www.virustotal.com/gui/my-apikey

## 2. Mettre le projet sur GitHub

1. Crée un nouveau repo GitHub (ex: `vt-scanner`)
2. Mets-y tout le contenu de ce dossier (`index.html`, `api/`, `package.json`, `vercel.json`)
3. Push

## 3. Déployer sur Vercel

1. Crée un compte sur https://vercel.com (tu peux te connecter directement avec GitHub)
2. **Add New → Project** → sélectionne ton repo `vt-scanner`
3. Vercel détecte automatiquement le dossier `api/` comme fonctions serverless — pas de config de build particulière à changer
4. Avant de cliquer "Deploy", ouvre **Environment Variables** et ajoute :
   - `VT_API_KEY` = ta clé copiée à l'étape 1
5. Clique **Deploy**

Vercel te donne une URL du type `https://vt-scanner-xxxx.vercel.app` — le frontend et le
backend fonctionnent déjà ensemble à cette adresse.

## 4. Utiliser sur iPhone

Ouvre l'URL Vercel dans Safari → bouton Partager → **Sur l'écran d'accueil**. L'appli
s'ouvre alors en plein écran, sans barre d'adresse, comme une vraie appli.

## Comment ça évite le problème de timeout

Les fonctions gratuites de Vercel doivent répondre vite (quelques secondes). Comme une
analyse VirusTotal peut prendre 15–60 secondes, le travail est coupé en deux :
- `/api/scan` envoie le fichier et répond immédiatement avec un identifiant d'analyse
- le frontend interroge ensuite `/api/status` toutes les 3 secondes jusqu'à ce que
  l'analyse soit terminée

Tu verras "Analyse en cours…" défiler dans le Journal pendant l'attente — c'est normal.

## Limites à connaître

- Fichiers jusqu'à **32 Mo** (limite de l'endpoint standard VirusTotal).
- Le compte VirusTotal gratuit est limité à ~4 requêtes/minute.
- Si un fichier identique a déjà été scanné par quelqu'un d'autre sur VirusTotal, le
  résultat est renvoyé instantanément (badge "résultat déjà connu").
- À chaque modification du code, il suffit de faire un `git push` — Vercel redéploie
  automatiquement.
