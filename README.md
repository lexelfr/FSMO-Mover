# Transfert des rôles FSMO - Active Directory

Ce dépôt contient un script PowerShell interactif et robuste, `Transfer-FSMORoles.ps1`, conçu pour simplifier et sécuriser le transfert ou la saisie (seize) des rôles FSMO (Flexible Single Master Operations) entre les contrôleurs de domaine (DC) d'un environnement Active Directory.

## 📋 Description

Le script guide l'administrateur étape par étape dans le processus de transfert de rôles FSMO. Il effectue de nombreuses vérifications préalables pour s'assurer que l'opération se déroule sans erreur, notamment en vérifiant les droits d'administration locaux et sur l'Active Directory.

## ✨ Fonctionnalités principales

1. **Vérifications de sécurité et de prérequis :**
   - S'assure que la console PowerShell est exécutée avec les privilèges Administrateur.
   - Vérifie la présence et le chargement du module PowerShell `ActiveDirectory`.
   - Analyse l'appartenance de l'utilisateur courant aux groupes critiques (`Schema Admins`, `Enterprise Admins`, `Domain Admins`).
2. **Gestion des tickets Kerberos :**
   - Propose de purger et de renouveler automatiquement les tickets Kerberos (utile si l'utilisateur vient d'être ajouté au groupe `Schema Admins`).
3. **Découverte interactive de l'environnement :**
   - Liste tous les contrôleurs de domaine de la forêt.
   - Affiche leur état de connectivité, le site AD auquel ils appartiennent, et les rôles FSMO qu'ils détiennent actuellement.
4. **Transfert personnalisé :**
   - Sélection du DC cible par un simple numéro.
   - Sélection à la carte des rôles à transférer (ou tous d'un coup).
   - Supporte le mode "Transfert normal" (le DC source est en ligne) et le mode "Saisie forcée / Seize" (le DC source est définitivement hors service).
5. **Vérification post-opération :**
   - Affiche les nouveaux détenteurs des rôles après l'exécution.
   - Utilise `netdom query fsmo` si disponible pour une double vérification.

## 🛠️ Prérequis

- **Système d'exploitation :** Windows Server (ou Windows 10/11 avec les outils RSAT).
- **PowerShell :** Version 5.1 ou supérieure.
- **Droits requis :** 
  - Exécution en tant qu'Administrateur.
  - Membre du groupe `Domain Admins`.
  - Membre du groupe `Enterprise Admins` (pour transférer le *Domain Naming Master*).
  - Membre du groupe `Schema Admins` (pour transférer le *Schema Master*).
- **Module PowerShell :** `ActiveDirectory` (RSAT-AD-PowerShell).

## 🚀 Utilisation

1. Ouvrez une console PowerShell en tant qu'**Administrateur**.
2. Naviguez vers le répertoire contenant le script.
3. Exécutez le script :

```powershell
.\Transfer-FSMORoles.ps1
```

4. Suivez les instructions interactives à l'écran.

## ⚠️ Avertissement concernant le mode "Saisie" (Seize)

Le script propose une option de **saisie forcée (seize)**. Cette opération est **strictement réservée** aux situations où l'ancien contrôleur de domaine (détenteur des rôles) est définitivement hors service ou détruit.
Si vous effectuez un "seize", l'ancien DC ne doit **jamais** être reconnecté au réseau avant d'avoir été complètement formaté ou rétrogradé de force (metadata cleanup).

## 📝 Licence et Crédits

Script généré et maintenu par Antigravity.
Date de création : Juin 2026.
