# ZennComp - AVHIRAL PE Static Decompiler Workbench

**Version V16 Unwind-Aware Engine** – Analyse statique de binaires Windows (PE) x64/x86, désassemblage, décompilation en pseudo-C, et extraction d’informations avancées.

---

## Table des matières
- [Présentation](#présentation)
- [Fonctionnalités principales](#fonctionnalités-principales)
- [Avertissement légal](#avertissement-légal)
- [Installation et compilation](#installation-et-compilation)
- [Utilisation](#utilisation)
- [Exemples de sortie](#exemples-de-sortie)
- [Contribution](#contribution)
- [Licence](#licence)
- [Crédits et dons](#crédits-et-dons)

---

## Présentation

**ZennComp** est un atelier de rétro-ingénierie statique pour les exécutables Windows (PE). Il repose sur un moteur d’analyse avancé utilisant **Capstone** pour le désassemblage, et une heuristique de décompilation en pseudo-C avec reconstruction de graphe de flot de contrôle (CFG), détection de fonctions via `.pdata`/unwind, extraction d’imports, de chaînes, de thunks, et de tables de saut. Il intègre également des modules de **détection de code packé/chiffré**, de **recherche de clés XOR** (1 et 2 octets), et de **dump mémoire en direct**.

ZennComp est conçu pour l’audit, l’analyse de sécurité et la formation. Il **n’exécute jamais** le binaire cible, garantissant une approche 100 % statique.

---

## Fonctionnalités principales

- **Analyse PE complète** – Headers, sections, imports, exports, ressources, exceptions (`.pdata`), etc.
- **Désassemblage** – Linéaire et récursif, avec fallback en interne.
- **Décompilation en pseudo-C** – Génération de code C lisible avec CFG, SSA simplifié, et annotation des appels d’API.
- **Moteur Unwind-Aware (V16)** – Utilise les tables `.pdata` pour découper les fonctions x64 et éviter de faux positifs massifs.
- **Extraction de chaînes** – ASCII et UTF-16.
- **IAT, thunks, jump tables** – Résolution des imports, détection des thunks et des tables de saut.
- **Détection de code packé/chiffré** – Analyse d’entropie, ratio d’instructions `db`, et signalement.
- **Module XDR** – Recherche de clés XOR (1 et 2 octets) par minimisation d’entropie, avec export du code déchiffré.
- **Dump mémoire** – Sauvegarde de la mémoire d’un processus (en direct ou depuis un dump).
- **DumpLive** – Décompilation en temps réel pendant l’exécution du processus.
- **Éditeur de code** – Visualisation et édition des fichiers générés, avec coloration syntaxique asynchrone.
- **Recompilation** – Compilation du pseudo-C généré en EXE/DLL via Visual Studio ou MinGW.

---

## Avertissement légal

**ZennComp est un outil à usage éducatif et d’audit.**  
L’utilisateur est seul responsable de l’utilisation qu’il fait de cet outil.  
Toute utilisation sur des logiciels dont vous n’êtes pas propriétaire ou sans autorisation explicite est interdite.  
Respectez les lois en vigueur et les droits d’auteur.

---

## Installation et compilation

### Prérequis
- Windows 10/11 (x64)
- Visual Studio 2022 (avec C++ v143) ou Build Tools
- [Capstone](https://www.capstone-engine.org/) (inclus via vcpkg ou à placer manuellement)
- [UPX](https://upx.github.io/) (optionnel, pour la décompression)

### Compilation avec Visual Studio

1. Clonez le dépôt :
   ```bash
   git clone https://github.com/AVHIRAL/ZennComp.git
   cd ZennComp

### DON PAYPAL 

https://www.paypal.com/donate/?hosted_button_id=FSX7RHUT4BDRY
