# VULNIX v2.2 🛡️  
**AI-Powered Vulnerability Scanner & Auto-Remediator**

VULNIX est un outil de sécurité offensive/défensive nouvelle génération.  
Il combine :

- **Trivy** (scanner de vulnérabilités leader du marché)  
- **Google Gemini** (IA générative)

pour **détecter les failles** et **générer automatiquement des scripts de correction Bash** robustes et sécurisés.

Il propose :

- Une **interface TUI interactive** (terminal user interface) immersive
- Un **mode CLI** pour l’automatisation (CI/CD, cron, scripts, etc.)

---

## ✨ Fonctionnalités principales

- 🕵️ **Scan hybride**
  - Scan complet du système de fichiers
  - Scan rapide *Light Scan* des dossiers critiques

- 🤖 **Auto-remédiation par IA**
  - Génération de scripts Bash correctifs intelligents
  - Gestion des mises à jour de paquets système
  - Détection de contextes spécifiques (ex : Debian EOL)

- 🎨 **Interface TUI "Hacker-Style"**
  - Menus interactifs
  - Barres de chargement
  - Tableaux colorés  
  *(basé sur `rich` et `questionary`)*

- 📦 **Zero-Config**
  - Gestion automatique de l’environnement virtuel Python (`venv`)
  - Installation automatique des dépendances

- 🛡️ **Sécurité renforcée**
  - Vérification de l’OS cible avant exécution des correctifs
  - Parsing JSON natif en Python (aucune dépendance à `jq`)
  - Mode **Dry-Run** pour valider chaque commande avant exécution

- 🖥️ **Cross-Platform**
  - Linux
  - WSL (Windows Subsystem for Linux)
  - Windows

---

## ⚙️ Prérequis

Avant de lancer VULNIX, assurez-vous d’avoir installé :

- **Python 3.8+**
- **Trivy**

### Installation de Trivy

#### Debian / Ubuntu / Kali

```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release

wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -

echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main   | sudo tee -a /etc/apt/sources.list.d/trivy.list

sudo apt-get update && sudo apt-get install trivy
```

#### Windows (via Chocolatey)

```bash
choco install trivy
```

---

## 🚀 Installation

1. **Cloner le projet**

```bash
git clone https://github.com/votre-username/vulnix.git
cd vulnix
chmod +x trivy_auto_fix_vGemini.py
```

2. **Configurer la clé API Gemini**

VULNIX a besoin d’une **clé API Google Gemini** (gratuite).

Deux possibilités :

### Option A – Variable d’environnement (recommandée)

```bash
export GEMINI_API_KEY="votre_clé_api_ici"
```

### Option B – Fichier texte

Créer un fichier `API.txt` dans le **dossier parent du projet** contenant **uniquement** la clé :

```text
/chemin/vers/
├── API.txt      # contient la clé
└── vulnix/
    └── trivy_auto_fix_vGemini.py
```

---

## 🎮 Utilisation

VULNIX peut être utilisé de deux façons : **Mode Interactif (TUI)** ou **Mode CLI**.

---

### 1. Mode Interactif (TUI)

Lancer simplement le script **sans argument** :

```bash
./trivy_auto_fix_vGemini.py
```

- Navigation : flèches **↑** / **↓**
- Validation : touche **Entrée**

Idéal pour une utilisation **manuelle**, exploratoire ou pour découvrir l’outil.

---

### 2. Mode CLI (Automatisation)

Conçu pour :

- Scripts **CI/CD**
- Tâches planifiées (`cron`)
- Automatisation sur serveurs / pipelines

#### Options principales

- `--light-scan`  
  Scan uniquement les dossiers système critiques (`/usr`, `/etc`, `/bin`, …) pour un résultat rapide.

- `--path <path>`  
  Scan un dossier spécifique (ex : `./mon_projet`).

- `--dry-run`  
  Génère un script de correction qui **demande confirmation** pour chaque commande (`Y/n`).

#### Exemple

```bash
# Scan rapide avec demande de confirmation pour chaque correction
./trivy_auto_fix_vGemini.py --light-scan --dry-run
```

---

## 📂 Structure des sorties

VULNIX sauvegarde automatiquement les résultats sur votre **Bureau**  
(détection automatique sous Linux, Windows et WSL).

- 📄 **Rapport de Scan (JSON brut Trivy)**  
  `VULNIX_report_YYYYMMDD_HHMMSS.json`

- 🛠️ **Script de Correction (Bash généré par l’IA)**  
  `VULNIX_fix_YYYYMMDD_HHMMSS.sh`

### Exemple d’application des correctifs

```bash
sudo ./VULNIX_fix_20251206_XXXXXX.sh ./VULNIX_report_20251206_XXXXXX.json
```

> ⚠️ Toujours vérifier que le script correspond bien au système ciblé avant exécution.

---

## 🧠 Intelligence du script de correction

Les scripts générés par VULNIX ne sont **pas** de simples séries de :

```bash
apt-get upgrade -y
```

Ils intègrent une logique avancée :

### ✅ Safety Check

- Vérifie si **l’OS qui exécute le script** correspond à **l’OS du rapport de scan**.
- En cas de mismatch, le script **s’arrête immédiatement** pour éviter de casser votre machine hôte.

### 🧩 Parsing JSON sans dépendance

- Utilise **Python** (présent sur la plupart des systèmes)
- Lecture directe du rapport JSON Trivy
- **Aucune dépendance externe** (pas besoin d’installer `jq`)

### 📦 Gestion des Debian EOL

- Si une Debian obsolète est détectée (`Jessie`, `Stretch`, etc.) :
  - Configuration automatique des dépôts `archive.debian.org`
  - Gestion des clés GPG expirées
  - Permet la mise à jour des paquets malgré la fin de support

---

## ⚠️ Avertissement

VULNIX est un outil **puissant**. L’application automatique de correctifs de sécurité peut :

- casser des **dépendances**
- modifier des **comportements applicatifs**
- impacter des **services en production**

**Recommandations :**

- Toujours faire des **sauvegardes** avant d’exécuter un script `VULNIX_fix_*.sh`
- Tester en priorité sur :
  - Environnements de **préproduction**
  - Machines de **lab**
- Utiliser ce programme **uniquement** sur des systèmes sur lesquels vous avez les **droits d’administration** et l’**autorisation explicite**

L’auteur décline toute responsabilité en cas de dommages causés à vos systèmes.

---

## 👤 Auteur & Licence

- **Auteur** : `GuillaumeGrs`
- **Licence** : `MIT`

---

## 📌 Version

- **Version actuelle** : `2.2.0`
