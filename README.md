# 🛡️ VULNIX - Trivy + Gemini CVE detection tool

**VULNIX** est un outil de sécurité défensive. 

Il combine la puissance de **Trivy** (scanner de vulnérabilités) avec l'IA de **Google Gemini**.

Son but ? Non seulement détecter les failles, mais **générer automatiquement des scripts de correction sécurisés** en Bash à exécuter pour résoudre les CVE.

![Status](https://img.shields.io/badge/Status-Stable-green) ![Platform](https://img.shields.io/badge/Platform-Linux-black) ![AI](https://img.shields.io/badge/AI-Gemini-blue)

---

## 📂 Contenu du Dépôt

Ce dépôt contient deux choses :
1.  **Le Code Source (`.py`)** : Pour les développeurs qui veulent comprendre la logique, modifier le prompt de l'IA ou améliorer l'outil.
2.  **L'Exécutable (Releases)** : Une version binaire autonome qui fonctionne sans Python, avec une UI. (Méthode à privilégier pour tester Vulnix)

---

## 📥 Installation (Pour les utilisateurs)

Pas besoin d'installer Python ou des librairies.

1.  Allez dans la section **[Releases](https://github.com/GuillaumeGrs/Vulnix/releases/tag/v2.3)** (à droite de cette page).
2.  Téléchargez le fichier **`vulnix`**.
3.  Transférez-le sur votre machine Linux (VM Debian, Ubuntu, Kali...).
4.  Rendez-le exécutable :
    ```bash
    chmod +x vulnix
    ```

---
## ⚡ Tutoriel : Test de A à Z (Proof of Concept)

Voici comment vérifier la puissance de VULNIX en 3 minutes sur une machine vierge.

### 1. Prérequis
VULNIX a besoin du moteur Trivy et d'une clé API Gemini.

```bash
# Installation Trivy (Sur Debian/Ubuntu)
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - [https://aquasecurity.github.io/trivy-repo/deb/public.key](https://aquasecurity.github.io/trivy-repo/deb/public.key) | sudo apt-key add -
echo deb [https://aquasecurity.github.io/trivy-repo/deb](https://aquasecurity.github.io/trivy-repo/deb) $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy
```
Pour plus d'info sur Trivy, n'hésitez pas à consulter : https://trivy.dev/docs/latest/guide/scanner/vulnerability/

### 🔑 Configurer votre clé API (Gratuite via Google AI Studio)

Pour utiliser les fonctions d'IA de VULNIX, vous avez besoin d'une clé API Google (gratuite).

1.  Rendez-vous sur **[Google AI Studio](https://aistudio.google.com/)**.
2.  Connectez-vous avec votre compte Google.
3.  Cliquez sur le bouton bleu **"Get API key"** (en haut à gauche).
4.  Cliquez sur **"Create API key in new project"**.
5.  Copiez la clé (elle commence par `AIza...`) et configurez-la dans votre terminal.
6.  N'oubliez pas : 
```bash
export GEMINI_API_KEY="votre_clé_ici"
```
> **Astuce :** Pour ne pas avoir à taper cette commande à chaque fois, ajoutez-la dans votre fichier de configuration (`~/.bashrc` ou `~/.zshrc`).
### 2. Créer un "Piège" (Vulnérabilité simulée)

Nous allons créer un dossier contenant une demande pour une très vieille librairie Python (2018), connue pour ses failles.
```bash
mkdir ~/demo_vuln
```
### On demande expressément une version vulnérable
```bash
echo "requests==2.19.0" > ~/demo_vuln/requirements.txt
```
### 3. Lancer le Scan
Exécutez VULNIX en ciblant ce dossier.

```bash
./vulnix --path ~/demo_vuln
````

👉 **Résultat :** VULNIX va détecter des vulnérabilités (HIGH/MEDIUM), générer un rapport HTML, et vous proposer de générer un script de correction. **Répondez "Oui"**.

### 4. Appliquer la Correction

VULNIX a généré un script du type `VULNIX_fix_DATE.sh`. Lancez-le.



### Remplacez les XXXXX par les chiffres de votre fichier

```bash
sudo ./VULNIX_fix_XXXXXX.sh ./VULNIX_report_XXXXXX.json
```

👉 **Action :** Le script va analyser le problème. Pour des raisons de sécurité, il ne modifiera pas le fichier `requirements.txt` automatiquement (risque de casse applicative), mais il vous avertira dans les logs qu'une action manuelle est requise.


### 5. Validation finale
Modifiez le fichier pour simuler l'action du développeur (comme suggéré par l'outil) et relancez le scan.


### On met à jour vers une version sûre

```bash
echo "requests>=2.31.0" > ~/demo_vuln/requirements.txt
```
### On re-scan le dossier

```bash
./vulnix --path ~/demo_vuln
````

✅ **Victoire :** Le rapport affichera **"System is CLEAN"** (0 vulnérabilités).

---

## 👨💻 Pour les Développeurs

Si vous souhaitez modifier le code source ou comprendre la logique :

1. Clonez ce dépôt.
    
2. Installez les dépendances :
    
    
    
    ```Bash
    pip install google-generativeai rich pyfiglet questionary jinja2
    ```
    
3. Le fichier principal est `Vulnix-TestVersion.py`.
    

Amusez-vous bien !

---

## 👤 À Propos & Philosophie

Ce projet est maintenu par **[@GuillaumeGRS](https://github.com/GuillaumeGRS)**.

**L'objectif de VULNIX** est de démocratiser l'automatisation de la sécurité défensive. En couplant un scanner éprouvé (**Trivy**) avec la flexibilité de l'**IA Générative**, ce projet vise à réduire drastiquement le temps entre la détection d'une CVE et sa correction effective (MTTR). 

Il s'agit d'une initiative personnelle **Open Source**, conçue pour être portable, transparente et facile à auditer.

### 🤝 Contribuer
Ce projet est vivant ! Si vous souhaitez améliorer les prompts de l'IA, ajouter le support d'autres gestionnaires de paquets (dnf, pacman) ou optimiser le code :
* Les **Pull Requests** sont les bienvenues.
* N'hésitez pas à me contacter ou à ouvrir une **Issue** pour discuter d'idées.

---

## ⚖️ Disclaimer (Avertissement)

**VULNIX est un outil puissant qui exécute des commandes avec des privilèges élevés (`sudo`).**

Bien que des mécanismes de sécurité soient en place (mode Dry-Run, vérification d'OS, non-modification des fichiers applicatifs), l'auteur décline toute responsabilité en cas de dommages, pertes de données ou instabilités système causés par l'utilisation de cet outil ou des scripts générés.

* 🔴 **Ne lancez jamais** de scripts de correction en production sans les avoir testés au préalable.
* ✅ L'utilisateur est seul responsable de la validation des commandes suggérées par l'IA.

*Licence : Ce projet est distribué sous licence MIT - Utilisez-le, modifiez-le, apprenez !*