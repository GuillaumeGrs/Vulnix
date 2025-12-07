# 🛡️ VULNIX - AI Vulnerability Remediator

**VULNIX** est un outil de sécurité offensive/défensive nouvelle génération. 
Il combine la puissance de **Trivy** (scanner de vulnérabilités) avec l'intelligence artificielle de **Google Gemini**.

Son but ? Non seulement détecter les failles, mais **générer automatiquement des scripts de correction sécurisés** (Bash) pour les réparer.

![Status](https://img.shields.io/badge/Status-Stable-green) ![Platform](https://img.shields.io/badge/Platform-Linux-black) ![AI](https://img.shields.io/badge/AI-Gemini-blue)

---

## 📂 Contenu du Dépôt

Ce dépôt contient deux choses :
1.  **Le Code Source (`.py`)** : Pour les développeurs qui veulent comprendre la logique, modifier le prompt de l'IA ou améliorer l'outil.
2.  **L'Exécutable (Releases)** : Une version binaire autonome qui fonctionne sans Python.

---

## 📥 Installation (Pour les utilisateurs)

Pas besoin d'installer Python ou des librairies.

1.  Allez dans la section **[Releases](https://github.com/TON_PSEUDO/vulnix/releases)** (à droite de cette page).
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
# 1. Installer Trivy (Sur Debian/Ubuntu)
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - [https://aquasecurity.github.io/trivy-repo/deb/public.key](https://aquasecurity.github.io/trivy-repo/deb/public.key) | sudo apt-key add -
echo deb [https://aquasecurity.github.io/trivy-repo/deb](https://aquasecurity.github.io/trivy-repo/deb) $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

# 2. Configurer votre clé API (Gratuite via Google AI Studio)
export GEMINI_API_KEY="votre_clé_ici"

### 2. Créer un "Piège" (Vulnérabilité simulée)

Nous allons créer un dossier contenant une demande pour une très vieille librairie Python (2018), connue pour ses failles.

Bash

```
mkdir ~/demo_vuln
# On demande expressément une version vulnérable
echo "requests==2.19.0" > ~/demo_vuln/requirements.txt
```

````

### 📋 BLOC 3 : Tutoriel (Scan et Correction)

```markdown
### 3. Lancer le Scan
Exécutez VULNIX en ciblant ce dossier.

```bash
./vulnix --path ~/demo_vuln
````

👉 **Résultat :** VULNIX va détecter des vulnérabilités (HIGH/MEDIUM), générer un rapport HTML, et vous proposer de générer un script de correction. **Répondez "Oui"**.

### 4. Appliquer la Correction

VULNIX a généré un script du type `VULNIX_fix_DATE.sh`. Lancez-le.

Bash

```
# Remplacez les XXXXX par les chiffres de votre fichier
sudo ./VULNIX_fix_XXXXXX.sh ./VULNIX_report_XXXXXX.json
```

👉 **Action :** Le script va analyser le problème. Pour des raisons de sécurité, il ne modifiera pas le fichier `requirements.txt` automatiquement (risque de casse applicative), mais il vous avertira dans les logs qu'une action manuelle est requise.

````

### 📋 BLOC 4 : Validation et Info Dev

```markdown
### 5. Validation finale
Modifiez le fichier pour simuler l'action du développeur (comme suggéré par l'outil) et relancez le scan.

```bash
# On met à jour vers une version sûre
echo "requests>=2.31.0" > ~/demo_vuln/requirements.txt

# On re-scan le dossier
./vulnix --path ~/demo_vuln
````

✅ **Victoire :** Le rapport affichera **"System is CLEAN"** (0 vulnérabilités).

---

## 👨💻 Pour les Développeurs

Si vous souhaitez modifier le code source ou comprendre la logique :

1. Clonez ce dépôt.
    
2. Installez les dépendances :
    
    Bash
    
    ```
    pip install google-generativeai rich pyfiglet questionary jinja2
    ```
    
3. Le fichier principal est `trivy_auto_fix_vGemini.py`.
    

Amusez-vous bien !