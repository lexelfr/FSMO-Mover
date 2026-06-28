# Transfert des rôles FSMO - Active Directory

Ce dépôt contient un script PowerShell interactif et robuste, `Transfer-FSMORoles.ps1`, conçu pour simplifier et sécuriser le transfert des rôles FSMO (Flexible Single Master Operations) entre les contrôleurs de domaine (DC) d'un environnement Active Directory.

## 📋 Description

Le script guide l'administrateur étape par étape dans le processus de transfert de rôles FSMO. Il effectue de nombreuses vérifications préalables pour s'assurer que l'opération se déroule sans erreur, notamment en vérifiant les droits d'administration locaux et sur l'Active Directory.

## ✨ Fonctionnalités principales

1. **Vérifications de sécurité et de prérequis :**
   - S'assure que la console PowerShell est exécutée avec les privilèges Administrateur.
   - Vérifie la présence et le chargement du module PowerShell `ActiveDirectory`.
   - Analyse l'appartenance de l'utilisateur courant aux groupes critiques (`Schema Admins`, `Enterprise Admins`, `Domain Admins`).
   - *NOUVEAU* : Propose une **élévation temporaire** au groupe `Schema Admins` si l'utilisateur est un `Domain Admin`, puis retire cette élévation proprement à la fin de l'opération si le transfert du Schema Master a réussi.
   - **Support multi-langue universel** : Détecte automatiquement les groupes critiques (Schema Admins, Enterprise Admins, Domain Admins) peu importe la langue du système d'exploitation Windows (grâce à la résolution des SIDs bien connus).
2. **Gestion des tickets Kerberos :**
   - Propose de purger et de renouveler automatiquement les tickets Kerberos (utile si l'utilisateur vient d'être ajouté au groupe `Schema Admins`).
3. **Découverte interactive de l'environnement :**
   - Liste tous les contrôleurs de domaine de la forêt.
   - Affiche leur état de connectivité, le site AD auquel ils appartiennent, et les rôles FSMO qu'ils détiennent actuellement.
4. **Transfert personnalisé :**
   - Sélection du DC cible par un simple numéro.
   - Sélection à la carte des rôles à transférer (ou tous d'un coup).
   - Supporte le mode "Transfert normal" (le DC source est en ligne).
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


## 📝 Licence et Crédits

Script généré et maintenu par Antigravity.
Date de création : Juin 2026.
Version : 1.2

## 📋 Changelog

### v1.2 (2026-06-28)
- **Correction** : Le retrait du groupe `Schema Admins` après un transfert réussi est maintenant garanti grâce à des variables de portée script (`$Script:`), évitant tout problème de propagation d'état.
- **Correction** : Ajout d'un avertissement explicite si l'utilisateur refuse le retrait du groupe.
- **Correction** : Correction de 4 bugs internes (type de retour de `Test-SchemaAdminMembership`, variable réservée `$input`, flux Kerberos absent, `$transferResults` pouvant être nul).
- **Amélioration** : Recherche des groupes AD par SID universel (compatible toutes langues).

### v1.1 (2026-06-28)
- **Nouveau** : Élévation temporaire au groupe `Schema Admins` si l'utilisateur est `Domain Admin`.
- **Nouveau** : Retrait automatique (avec confirmation) du groupe `Schema Admins` après un transfert réussi du Schema Master.
- **Nouveau** : Affichage du DC Source dans le résumé de l'opération.
- **Nouveau** : Support multi-langue universel (détection par SID).
- **Suppression** : Option de saisie forcée (Seize) retirée.
