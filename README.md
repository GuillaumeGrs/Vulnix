# Vulnix

Vulnix est un outil d’audit et de remédiation automatisée des vulnérabilités sur systèmes Linux.  
Il s’appuie sur **Trivy** pour la détection des CVE, puis génère des correctifs adaptés et propose leur application de manière **interactable**, avec confirmation utilisateur avant chaque action critique.

Ce projet a été réalisé dans un objectif de **montée en compétences pratique** en cybersécurité défensive, durcissement système et automatisation sur Linux.

---

## 🎯 Objectifs

- Détecter rapidement les vulnérabilités présentes sur un système Linux
- Classer les CVE par niveau de criticité pour prioriser les corrections
- Générer des correctifs reproductibles et compréhensibles
- Réduire le temps entre détection et remédiation
- Standardiser la gestion de la sécurité dans des environnements variés

Vulnix est particulièrement adapté aux contextes :
- Homelab / lab de formation
- Maintien en condition de sécurité
- Audit interne
- DevSecOps léger

---

## 🧩 Fonctionnement

1. **Scan** du système via Trivy (base mise à jour ou locale)
2. Extraction des vulnérabilités détectées (format JSON)
3. Analyse des paquets et dépendances concernés
4. Génération de **solutions proposées** : mise à jour, remplacement, suppression
5. Affichage clair + **confirmation utilisateur**
6. Application des correctifs
7. Rapport synthétique final

---

## ⚙️ Prérequis

- Distribution Linux basée sur APT (Debian, Ubuntu, Kali…)
- `trivy` installé et disponible dans le `$PATH`
- `python3` installé
- Accès `sudo` pour appliquer les correctifs

---

## 📦 Installation

```bash
git clone https://github.com/guillaumegrs/vulnix.git
cd vulnix
chmod +x vulnix.sh
```

---

## 🚀 Utilisation

### Mode script Bash
```bash
sudo ./vulnix.sh
```

### Mode script Python direct
```bash
sudo python3 vulnix_auto_fix_confirm.py
```

---

## 📝 Exemple de sortie (simplifié)

```
CVE-2023-XXXX (High) detected in openssl
Proposition : apt upgrade openssl
Confirmer ? (o/n)
```

---

## 📌 Roadmap

- [ ] Support RPM (RHEL / CentOS / Rocky / Fedora)
- [ ] Export automatique des rapports (JSON / HTML)
- [ ] Mode « non-interactif » pour CI/CD
- [ ] Intégration possible avec SIEM / SOC via webhooks

---

## 🤝 Contributions

Les pull requests sont les bienvenues.  
Pour toute suggestion, merci d’ouvrir une *issue*.

---

## 📜 Licence

MIT License.

---

## 👤 Auteur

**Guillaume Greslé**  
Ingénieur Réseau & Sécurité — Automatisation & Linux  
GitHub : https://github.com/guillaumegrs
