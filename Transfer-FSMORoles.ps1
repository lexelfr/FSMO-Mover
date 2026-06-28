#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Transfère les rôles FSMO entre contrôleurs de domaine Active Directory.

.DESCRIPTION
    Ce script permet de transférer (ou saisir) les rôles FSMO d'un DC à un autre.
    Il effectue les vérifications suivantes avant toute opération :
      - Console exécutée en tant qu'Administrateur
      - Appartenance au groupe Schema Admins (et Enterprise Admins)
      - Connectivité avec les DC
      - Proposition de renouvellement du ticket Kerberos

.NOTES
    Auteur  : Script généré par Antigravity
    Date    : 2026-06-28
    Version : 1.0
#>

[CmdletBinding()]
param()

# ============================================================================
# REGION : Configuration & Couleurs
# ============================================================================

$Script:Colors = @{
    Title   = 'Cyan'
    Success = 'Green'
    Warning = 'Yellow'
    Error   = 'Red'
    Info    = 'White'
    Prompt  = 'Magenta'
}

$Script:FSMORoleNames = @{
    0 = 'Schema Master'
    1 = 'Domain Naming Master'
    2 = 'PDC Emulator'
    3 = 'RID Master'
    4 = 'Infrastructure Master'
}

# ============================================================================
# REGION : Fonctions utilitaires
# ============================================================================

function Write-Banner {
    $banner = @"

  ╔══════════════════════════════════════════════════════════════╗
  ║            TRANSFERT DES RÔLES FSMO - Active Directory      ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  Ce script transfère les rôles FSMO entre les DC.           ║
  ║  Vérifications de sécurité automatiques avant transfert.    ║
  ╚══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor $Script:Colors.Title
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "  ── $Title ──" -ForegroundColor $Script:Colors.Title
    Write-Host ""
}

function Write-StatusLine {
    param(
        [string]$Label,
        [string]$Value,
        [string]$Status = 'Info'  # Info, Success, Warning, Error
    )
    $color = $Script:Colors[$Status]
    $icon = switch ($Status) {
        'Success' { '✓' }
        'Warning' { '⚠' }
        'Error'   { '✗' }
        default   { '●' }
    }
    Write-Host "    $icon " -ForegroundColor $color -NoNewline
    Write-Host "$Label : " -ForegroundColor Gray -NoNewline
    Write-Host $Value -ForegroundColor $color
}

function Confirm-Action {
    param([string]$Message)
    Write-Host ""
    Write-Host "    $Message " -ForegroundColor $Script:Colors.Prompt -NoNewline
    $response = Read-Host "[O/N]"
    return ($response -match '^[OoYy]')
}

# ============================================================================
# REGION : Vérifications préalables
# ============================================================================

function Test-ElevatedSession {
    <#
    .SYNOPSIS
        Vérifie que la console PowerShell est exécutée en tant qu'Administrateur.
    #>
    Write-Section "Vérification des privilèges de la console"

    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin) {
        Write-StatusLine -Label "Console Administrateur" -Value "Oui" -Status Success
        return $true
    }
    else {
        Write-StatusLine -Label "Console Administrateur" -Value "Non — Relancez PowerShell en tant qu'Administrateur" -Status Error
        return $false
    }
}

function Test-SchemaAdminMembership {
    <#
    .SYNOPSIS
        Vérifie que l'utilisateur courant est membre des groupes Schema Admins
        et Enterprise Admins (requis pour certains rôles FSMO).
    #>
    Write-Section "Vérification de l'appartenance aux groupes d'administration"

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userName = $currentUser.Name
    Write-StatusLine -Label "Utilisateur courant" -Value $userName -Status Info

    $results = @{ SchemaAdmins = $false; EnterpriseAdmins = $false; DomainAdmins = $false; TempSchemaAdmin = $false; SchemaGroup = $null; SamName = $null }

    try {
        # Récupération du SamAccountName
        $samName = ($userName -split '\\')[-1]
        $adUser = Get-ADUser -Identity $samName -Properties MemberOf

        # Récupérer les groupes critiques
        $rootDSE = Get-ADRootDSE
        $schemaDN = $rootDSE.schemaNamingContext
        $configDN = $rootDSE.configurationNamingContext
        $domainDN = $rootDSE.defaultNamingContext

        # Schema Admins
        try {
            $schemaAdminsGroup = Get-ADGroup -Filter "Name -eq 'Schema Admins'" -SearchBase $domainDN
            if ($schemaAdminsGroup) {
                $results.SchemaGroup = $schemaAdminsGroup
                $members = Get-ADGroupMember -Identity $schemaAdminsGroup -Recursive | Select-Object -ExpandProperty SamAccountName
                $results.SchemaAdmins = $members -contains $samName
            }
        }
        catch {
            # Tenter via le SID bien connu (S-1-5-21-<domain>-518)
            try {
                $schemaAdminsGroup = Get-ADGroup -Filter "SID -like '*-518'"
                if ($schemaAdminsGroup) {
                    $results.SchemaGroup = $schemaAdminsGroup
                    $members = Get-ADGroupMember -Identity $schemaAdminsGroup -Recursive | Select-Object -ExpandProperty SamAccountName
                    $results.SchemaAdmins = $members -contains $samName
                }
            }
            catch { }
        }

        # Enterprise Admins
        try {
            $enterpriseAdminsGroup = Get-ADGroup -Filter "Name -eq 'Enterprise Admins'" -SearchBase $domainDN
            if (-not $enterpriseAdminsGroup) {
                $enterpriseAdminsGroup = Get-ADGroup -Filter "Name -eq 'Administrateurs de l''entreprise'" -SearchBase $domainDN
            }
            if ($enterpriseAdminsGroup) {
                $members = Get-ADGroupMember -Identity $enterpriseAdminsGroup -Recursive | Select-Object -ExpandProperty SamAccountName
                $results.EnterpriseAdmins = $members -contains $samName
            }
        }
        catch { }

        # Domain Admins
        try {
            $domainAdminsGroup = Get-ADGroup -Filter "Name -eq 'Domain Admins' -or Name -eq 'Admins du domaine'" -SearchBase $domainDN
            if ($domainAdminsGroup) {
                $members = Get-ADGroupMember -Identity $domainAdminsGroup -Recursive | Select-Object -ExpandProperty SamAccountName
                $results.DomainAdmins = $members -contains $samName
            }
        }
        catch { }
    }
    catch {
        Write-StatusLine -Label "Erreur AD" -Value $_.Exception.Message -Status Error
        return $false
    }

    # Affichage des résultats
    $statusSA = if ($results.SchemaAdmins) { 'Success' } else { 'Warning' }
    $statusEA = if ($results.EnterpriseAdmins) { 'Success' } else { 'Warning' }
    $statusDA = if ($results.DomainAdmins) { 'Success' } else { 'Warning' }

    Write-StatusLine -Label "Schema Admins" -Value $(if ($results.SchemaAdmins) { "Membre" } else { "Non membre" }) -Status $statusSA
    Write-StatusLine -Label "Enterprise Admins" -Value $(if ($results.EnterpriseAdmins) { "Membre" } else { "Non membre" }) -Status $statusEA
    Write-StatusLine -Label "Domain Admins" -Value $(if ($results.DomainAdmins) { "Membre" } else { "Non membre" }) -Status $statusDA

    $results.SamName = $samName

    if (-not $results.SchemaAdmins) {
        Write-Host ""
        Write-Host "    ⚠  ATTENTION : Vous n'êtes pas membre du groupe Schema Admins." -ForegroundColor $Script:Colors.Warning
        Write-Host "       Le transfert du rôle Schema Master échouera sans cette appartenance." -ForegroundColor $Script:Colors.Warning
        
        if ($results.DomainAdmins -and $results.SchemaGroup) {
            if (Confirm-Action "Voulez-vous être ajouté temporairement au groupe Schema Admins ?") {
                try {
                    Add-ADGroupMember -Identity $results.SchemaGroup -Members $samName -ErrorAction Stop
                    Write-StatusLine -Label "Ajout Schema Admins" -Value "Réussi" -Status Success
                    $results.SchemaAdmins = $true
                    $results.TempSchemaAdmin = $true
                } catch {
                    Write-StatusLine -Label "Ajout Schema Admins" -Value "ÉCHEC — $($_.Exception.Message)" -Status Error
                }
            }
        } else {
            Write-Host "       Ajoutez votre compte au groupe Schema Admins et renouvelez votre ticket Kerberos." -ForegroundColor $Script:Colors.Warning
        }
    }

    if (-not $results.EnterpriseAdmins) {
        Write-Host "    ⚠  ATTENTION : Vous n'êtes pas membre du groupe Enterprise Admins." -ForegroundColor $Script:Colors.Warning
        Write-Host "       Le transfert du rôle Domain Naming Master pourrait échouer." -ForegroundColor $Script:Colors.Warning
    }

    return $results
}

function Invoke-KerberosTicketRenewal {
    <#
    .SYNOPSIS
        Propose à l'utilisateur de purger et renouveler ses tickets Kerberos.
        Utile après un ajout récent dans Schema Admins ou Enterprise Admins.
    #>
    Write-Section "Gestion des tickets Kerberos"

    # Afficher les tickets actuels
    Write-Host "    Tickets Kerberos actuels :" -ForegroundColor Gray
    Write-Host ""
    try {
        $klistOutput = klist 2>&1
        if ($klistOutput) {
            $klistOutput | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
        }
        else {
            Write-Host "      Aucun ticket trouvé." -ForegroundColor $Script:Colors.Warning
        }
    }
    catch {
        Write-Host "      Impossible de lister les tickets." -ForegroundColor $Script:Colors.Warning
    }

    Write-Host ""
    if (Confirm-Action "Souhaitez-vous purger et renouveler vos tickets Kerberos ?") {
        Write-Host ""
        Write-Host "    Purge des tickets en cours..." -ForegroundColor $Script:Colors.Info

        try {
            # Purge des tickets
            $purgeResult = klist purge 2>&1
            Write-StatusLine -Label "klist purge" -Value "Effectué" -Status Success
            $purgeResult | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }

            # Forcer l'obtention d'un nouveau TGT en accédant à AD
            Write-Host ""
            Write-Host "    Acquisition d'un nouveau TGT..." -ForegroundColor $Script:Colors.Info
            $null = Get-ADDomain -ErrorAction Stop
            Write-StatusLine -Label "Nouveau TGT" -Value "Obtenu avec succès" -Status Success

            # Afficher les nouveaux tickets
            Write-Host ""
            Write-Host "    Nouveaux tickets :" -ForegroundColor Gray
            $klistOutput = klist 2>&1
            $klistOutput | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
        }
        catch {
            Write-StatusLine -Label "Erreur" -Value $_.Exception.Message -Status Error
            Write-Host "    Vous pouvez aussi fermer/rouvrir votre session Windows." -ForegroundColor $Script:Colors.Warning
        }
    }
    else {
        Write-StatusLine -Label "Renouvellement Kerberos" -Value "Ignoré par l'utilisateur" -Status Info
    }
}

# ============================================================================
# REGION : Découverte de l'environnement AD
# ============================================================================

function Get-DomainControllerList {
    <#
    .SYNOPSIS
        Liste tous les contrôleurs de domaine avec leur état et les rôles FSMO détenus.
    #>
    Write-Section "Découverte des contrôleurs de domaine"

    try {
        $domain = Get-ADDomain
        $forest = Get-ADForest

        Write-StatusLine -Label "Forêt" -Value $forest.Name -Status Info
        Write-StatusLine -Label "Domaine" -Value $domain.DNSRoot -Status Info
        Write-Host ""

        # Récupération des DC
        $dcList = Get-ADDomainController -Filter * | Sort-Object Name

        if (-not $dcList -or $dcList.Count -eq 0) {
            Write-StatusLine -Label "Erreur" -Value "Aucun contrôleur de domaine trouvé" -Status Error
            return $null
        }

        # Récupération des détenteurs actuels des rôles FSMO
        $fsmoHolders = @{
            'Schema Master'           = $forest.SchemaMaster
            'Domain Naming Master'    = $forest.DomainNamingMaster
            'PDC Emulator'            = $domain.PDCEmulator
            'RID Master'              = $domain.RIDMaster
            'Infrastructure Master'   = $domain.InfrastructureMaster
        }

        Write-Host "    ┌─────┬──────────────────────────────┬──────────────────────┬────────────┬────────────────────────────────────────┐" -ForegroundColor DarkGray
        Write-Host "    │  #  │ Nom du DC                    │ Site AD              │ État       │ Rôles FSMO détenus                     │" -ForegroundColor DarkGray
        Write-Host "    ├─────┼──────────────────────────────┼──────────────────────┼────────────┼────────────────────────────────────────┤" -ForegroundColor DarkGray

        $index = 1
        $dcInfo = @()

        foreach ($dc in $dcList) {
            # Test de connectivité
            $isReachable = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -ErrorAction SilentlyContinue
            $stateText = if ($isReachable) { "En ligne" } else { "Hors ligne" }
            $stateColor = if ($isReachable) { $Script:Colors.Success } else { $Script:Colors.Error }

            # Rôles détenus par ce DC
            $heldRoles = @()
            foreach ($role in $fsmoHolders.GetEnumerator()) {
                if ($role.Value -eq $dc.HostName) {
                    $heldRoles += $role.Key
                }
            }
            $rolesText = if ($heldRoles.Count -gt 0) { ($heldRoles -join ', ') } else { '-' }

            # Troncature pour l'affichage
            $nameDisplay = $dc.HostName.PadRight(28).Substring(0, 28)
            $siteDisplay = ($dc.Site -as [string]).PadRight(20).Substring(0, 20)
            $stateDisplay = $stateText.PadRight(10).Substring(0, 10)
            $rolesDisplay = $rolesText
            if ($rolesDisplay.Length -gt 38) { $rolesDisplay = $rolesDisplay.Substring(0, 35) + '...' }
            $rolesDisplay = $rolesDisplay.PadRight(38).Substring(0, 38)

            Write-Host "    │ " -ForegroundColor DarkGray -NoNewline
            Write-Host ("{0,2}" -f $index) -ForegroundColor $Script:Colors.Prompt -NoNewline
            Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
            Write-Host $nameDisplay -ForegroundColor White -NoNewline
            Write-Host " │ " -ForegroundColor DarkGray -NoNewline
            Write-Host $siteDisplay -ForegroundColor White -NoNewline
            Write-Host " │ " -ForegroundColor DarkGray -NoNewline
            Write-Host $stateDisplay -ForegroundColor $stateColor -NoNewline
            Write-Host " │ " -ForegroundColor DarkGray -NoNewline
            Write-Host $rolesDisplay -ForegroundColor $Script:Colors.Title -NoNewline
            Write-Host " │" -ForegroundColor DarkGray

            $dcInfo += [PSCustomObject]@{
                Index       = $index
                Name        = $dc.Name
                HostName    = $dc.HostName
                Site        = $dc.Site
                IsReachable = $isReachable
                HeldRoles   = $heldRoles
                IPv4Address = $dc.IPv4Address
                IsGC        = $dc.IsGlobalCatalog
            }

            $index++
        }

        Write-Host "    └─────┴──────────────────────────────┴──────────────────────┴────────────┴────────────────────────────────────────┘" -ForegroundColor DarkGray

        # Résumé des rôles FSMO
        Write-Host ""
        Write-Section "Détenteurs actuels des rôles FSMO"
        foreach ($role in $fsmoHolders.GetEnumerator() | Sort-Object Name) {
            Write-StatusLine -Label $role.Key -Value $role.Value -Status Info
        }

        return $dcInfo
    }
    catch {
        Write-StatusLine -Label "Erreur" -Value $_.Exception.Message -Status Error
        return $null
    }
}

# ============================================================================
# REGION : Transfert des rôles FSMO
# ============================================================================

function Select-TargetDC {
    <#
    .SYNOPSIS
        Permet à l'utilisateur de sélectionner le DC cible pour le transfert.
    #>
    param([array]$DCList)

    Write-Host ""
    Write-Host "    Entrez le numéro du DC cible pour le transfert : " -ForegroundColor $Script:Colors.Prompt -NoNewline
    $selection = Read-Host

    if ($selection -match '^\d+$') {
        $idx = [int]$selection
        $targetDC = $DCList | Where-Object { $_.Index -eq $idx }

        if ($targetDC) {
            if (-not $targetDC.IsReachable) {
                Write-StatusLine -Label "Attention" -Value "Le DC '$($targetDC.HostName)' semble hors ligne" -Status Warning
                if (-not (Confirm-Action "Voulez-vous continuer malgré tout ?")) {
                    return $null
                }
            }
            Write-StatusLine -Label "DC cible sélectionné" -Value $targetDC.HostName -Status Success
            return $targetDC
        }
    }

    Write-StatusLine -Label "Sélection invalide" -Value "Numéro '$selection' non reconnu" -Status Error
    return $null
}

function Select-FSMORoles {
    <#
    .SYNOPSIS
        Permet à l'utilisateur de sélectionner les rôles FSMO à transférer.
    #>
    Write-Section "Sélection des rôles FSMO à transférer"

    Write-Host "    1. Schema Master            (forêt)" -ForegroundColor White
    Write-Host "    2. Domain Naming Master      (forêt)" -ForegroundColor White
    Write-Host "    3. PDC Emulator              (domaine)" -ForegroundColor White
    Write-Host "    4. RID Master                (domaine)" -ForegroundColor White
    Write-Host "    5. Infrastructure Master     (domaine)" -ForegroundColor White
    Write-Host "    A. Tous les rôles" -ForegroundColor $Script:Colors.Prompt
    Write-Host ""
    Write-Host "    Entrez les numéros séparés par des virgules (ex: 1,3,5) ou 'A' pour tous : " -ForegroundColor $Script:Colors.Prompt -NoNewline
    $input = Read-Host

    $selectedRoles = @()

    if ($input -match '^[Aa]$') {
        $selectedRoles = @(
            'SchemaMaster',
            'DomainNamingMaster',
            'PDCEmulator',
            'RIDMaster',
            'InfrastructureMaster'
        )
        Write-StatusLine -Label "Sélection" -Value "Tous les rôles (5/5)" -Status Info
    }
    else {
        $numbers = $input -split ',' | ForEach-Object { $_.Trim() }
        $roleMap = @{
            '1' = 'SchemaMaster'
            '2' = 'DomainNamingMaster'
            '3' = 'PDCEmulator'
            '4' = 'RIDMaster'
            '5' = 'InfrastructureMaster'
        }

        foreach ($num in $numbers) {
            if ($roleMap.ContainsKey($num)) {
                $selectedRoles += $roleMap[$num]
            }
            else {
                Write-StatusLine -Label "Ignoré" -Value "Numéro '$num' non reconnu" -Status Warning
            }
        }

        if ($selectedRoles.Count -gt 0) {
            Write-StatusLine -Label "Sélection" -Value "$($selectedRoles.Count) rôle(s) sélectionné(s)" -Status Info
        }
    }

    return $selectedRoles
}

function Invoke-FSMOTransfer {
    <#
    .SYNOPSIS
        Effectue le transfert des rôles FSMO vers le DC cible.
    #>
    param(
        [PSCustomObject]$TargetDC,
        [string[]]$Roles
    )

    Write-Section "Transfert des rôles FSMO"

    $friendlyNames = @{
        'SchemaMaster'          = 'Schema Master'
        'DomainNamingMaster'    = 'Domain Naming Master'
        'PDCEmulator'           = 'PDC Emulator'
        'RIDMaster'             = 'RID Master'
        'InfrastructureMaster'  = 'Infrastructure Master'
    }

    # Résumé avant transfert
    Write-Host "    ┌────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "    │  RÉSUMÉ DE L'OPÉRATION                                    │" -ForegroundColor $Script:Colors.Warning
    Write-Host "    ├────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    Write-Host "    │  DC Cible  : $($TargetDC.HostName)" -ForegroundColor White
    Write-Host "    │  Mode      : Transfert (Move)" -ForegroundColor $Script:Colors.Success
    Write-Host "    │  Rôles     :" -ForegroundColor White
    foreach ($role in $Roles) {
        Write-Host "    │    → $($friendlyNames[$role])" -ForegroundColor $Script:Colors.Title
    }
    Write-Host "    └────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray

    if (-not (Confirm-Action "Confirmez-vous l'opération ?")) {
        Write-StatusLine -Label "Opération" -Value "Annulée par l'utilisateur" -Status Warning
        return
    }

    # Exécution du transfert
    $successCount = 0
    $failCount = 0
    $transferStatus = @{}

    foreach ($role in $Roles) {
        $roleFriendly = $friendlyNames[$role]
        Write-Host ""
        Write-Host "    ─── Transfert : $roleFriendly ───" -ForegroundColor $Script:Colors.Title
        $transferStatus[$role] = $false

        try {
            # Transfert normal (graceful)
            Move-ADDirectoryServerOperationMasterRole `
                -Identity $TargetDC.Name `
                -OperationMasterRole $role `
                -Confirm:$false `
                -ErrorAction Stop

            Write-StatusLine -Label $roleFriendly -Value "Transféré avec succès vers $($TargetDC.HostName)" -Status Success
            $successCount++
            $transferStatus[$role] = $true
        }
        catch {
            Write-StatusLine -Label $roleFriendly -Value "ÉCHEC — $($_.Exception.Message)" -Status Error
            $failCount++
        }
    }

    # Bilan
    Write-Host ""
    Write-Host "    ════════════════════════════════════════" -ForegroundColor DarkGray
    Write-StatusLine -Label "Réussis" -Value "$successCount / $($Roles.Count)" -Status $(if ($successCount -eq $Roles.Count) { 'Success' } else { 'Warning' })
    if ($failCount -gt 0) {
        Write-StatusLine -Label "Échoués" -Value "$failCount / $($Roles.Count)" -Status Error
    }

    return $transferStatus
}

function Show-PostTransferVerification {
    <#
    .SYNOPSIS
        Affiche l'état des rôles FSMO après le transfert pour vérification.
    #>
    Write-Section "Vérification post-transfert"

    try {
        $domain = Get-ADDomain
        $forest = Get-ADForest

        Write-StatusLine -Label "Schema Master" -Value $forest.SchemaMaster -Status Info
        Write-StatusLine -Label "Domain Naming Master" -Value $forest.DomainNamingMaster -Status Info
        Write-StatusLine -Label "PDC Emulator" -Value $domain.PDCEmulator -Status Info
        Write-StatusLine -Label "RID Master" -Value $domain.RIDMaster -Status Info
        Write-StatusLine -Label "Infrastructure Master" -Value $domain.InfrastructureMaster -Status Info

        Write-Host ""

        # Vérification rapide via netdom (si disponible)
        try {
            $netdomOutput = netdom query fsmo 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    Sortie netdom query fsmo :" -ForegroundColor Gray
                $netdomOutput | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
            }
        }
        catch { }
    }
    catch {
        Write-StatusLine -Label "Erreur de vérification" -Value $_.Exception.Message -Status Error
    }
}

# ============================================================================
# REGION : Point d'entrée principal
# ============================================================================

function Main {
    Clear-Host
    Write-Banner

    # ── Étape 1 : Vérification de la console administrateur ──
    if (-not (Test-ElevatedSession)) {
        Write-Host ""
        Write-Host "    ✗ Ce script doit être exécuté dans une console PowerShell élevée (Administrateur)." -ForegroundColor $Script:Colors.Error
        Write-Host "    Clic droit sur PowerShell → 'Exécuter en tant qu'administrateur'" -ForegroundColor $Script:Colors.Info
        Write-Host ""
        return
    }

    # ── Étape 2 : Vérification du module ActiveDirectory ──
    Write-Section "Vérification du module ActiveDirectory"
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-StatusLine -Label "Module ActiveDirectory" -Value "Non installé" -Status Error
        Write-Host "    Installez-le via : Install-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor $Script:Colors.Warning
        Write-Host "    Ou : Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor $Script:Colors.Warning
        return
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-StatusLine -Label "Module ActiveDirectory" -Value "Chargé" -Status Success

    # ── Étape 3 : Vérification Schema Admins / Enterprise Admins ──
    $groupStatus = Test-SchemaAdminMembership

    # ── Étape 4 : Proposition de renouvellement Kerberos ──
    Invoke-KerberosTicketRenewal

    # ── Étape 5 : Liste des DC ──
    $dcList = Get-DomainControllerList
    if (-not $dcList) {
        Write-Host ""
        Write-Host "    ✗ Impossible de récupérer la liste des contrôleurs de domaine." -ForegroundColor $Script:Colors.Error
        return
    }

    # ── Étape 6 : Sélection du DC cible ──
    $targetDC = Select-TargetDC -DCList $dcList
    if (-not $targetDC) {
        Write-Host ""
        Write-Host "    ✗ Aucun DC cible sélectionné. Opération annulée." -ForegroundColor $Script:Colors.Error
        return
    }

    # ── Étape 7 : Sélection des rôles ──
    $selectedRoles = Select-FSMORoles
    if ($selectedRoles.Count -eq 0) {
        Write-Host ""
        Write-Host "    ✗ Aucun rôle sélectionné. Opération annulée." -ForegroundColor $Script:Colors.Error
        return
    }

    # ── Étape 8 : Exécution du transfert ──
    $transferResults = Invoke-FSMOTransfer -TargetDC $targetDC -Roles $selectedRoles

    # ── Étape 9 : Vérification post-transfert ──
    Show-PostTransferVerification

    # ── Étape 10 : Nettoyage temporaire Schema Admins ──
    if ($groupStatus.TempSchemaAdmin -and $transferResults['SchemaMaster']) {
        if (Confirm-Action "Le rôle Schema Master a été transféré avec succès. Voulez-vous être retiré du groupe Schema Admins ?") {
            try {
                Remove-ADGroupMember -Identity $groupStatus.SchemaGroup -Members $groupStatus.SamName -Confirm:$false -ErrorAction Stop
                Write-StatusLine -Label "Retrait Schema Admins" -Value "Réussi" -Status Success
            } catch {
                Write-StatusLine -Label "Retrait Schema Admins" -Value "ÉCHEC — $($_.Exception.Message)" -Status Error
            }
        }
    }

    # ── Fin ──
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor $Script:Colors.Title
    Write-Host "  ║               Opération terminée                            ║" -ForegroundColor $Script:Colors.Title
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor $Script:Colors.Title
    Write-Host ""

    # Log
    $logEntry = [PSCustomObject]@{
        Date       = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        User       = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        TargetDC   = $targetDC.HostName
        Roles      = ($selectedRoles -join ', ')
        Mode       = 'Transfer'
    }
    Write-Host "    Journal de l'opération :" -ForegroundColor Gray
    $logEntry | Format-List | Out-String | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
}

# Lancement
Main
