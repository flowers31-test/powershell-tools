<#
.SYNOPSIS
    Script centralisé de gestion des utilisateurs et groupes AD vs Cerbère.
    Auteur : La Fleur
    Date : 2025-10-20

.SANS PARAMETRE 
    Fait le CHK et affiche les différentes anomalies entre Cerbère et AD.

.PARAMETRE -rapport
    Génère un rapport hebdomadaire et l’envoie par email.

.PARAMETRE -sync
    Simule la synchronisation entre Cerbère et AD.

.PARAMETRE -sync -run
    Exécute réellement la synchronisation (création / suppression / ajout).

.EXAMPLE
    C:\ROOT\SCRIPTS_ADMIN\gestion_users_et_groupes.ps1 -rapport
    C:\ROOT\SCRIPTS_ADMIN\gestion_users_et_groupes.ps1
    C:\ROOT\SCRIPTS_ADMIN\gestion_users_et_groupes.ps1 -sync
    C:\ROOT\SCRIPTS_ADMIN\gestion_users_et_groupes.ps1 -sync -run
#>

param(
    [switch]$rapport,
    [switch]$sync,
    [switch]$run,
    [switch]$h,  # home
    [switch]$d,  # data
    [switch]$i,  # internet
    [switch]$w,  # devweb
    [switch]$n,  # harbin/wuhan
    [switch]$a,  # ambassadeurs
    [switch]$r,   # reseauxsociaux
    [string]$user # utilisateur spécifique pour les switches

)

if ($PSBoundParameters.Count -eq 0) {
    Write-Host "Lancement sans paramètre : exécution du CHK par défaut..." -ForegroundColor Green
        $rapport = $false
        $sync    = $false
        $run     = $false
}

. "C:\ROOT\LOCAL\env.ps1"

$OUPath = "OU=u3-users,DC=win,DC=groupe-pap,DC=fr"
$CerbereUsersCsv = "C:\ROOT\DATA\logins.csv"
$CerbereGroupsCsv = "C:\ROOT\DATA\groups.csv"


# Utilisateurs à ignorer
$IgnoredUsers = @(
    "l.chollet@pap.fr",
    "d.quienot@pap.fr",
    "a.hamdi@pap.fr",
    "i.marrakchi@pap.fr",
    "c.neressis@pap.fr",
    "z.el-kanari@pap.fr",
    "c.grillou-cabos@pap.fr",
    "e.alcan@pap.fr"
)

# Groupes à ignorer
$IgnoredGroups = @("L_rw")

# Fonction de log
function Write-Log {
    param([string]$message)
    $logFile = "$dirpath_logs\check_ad.log"

    if ($sync -and $run) { $prefix = 'RUN::' }
    elseif ($sync -and -not $run) { $prefix = 'TEST::' }
    else { $prefix = 'CHK::' }

    $logMessage = "$prefix$message"
    $logMessage | Out-File -FilePath $logFile -Append -Encoding UTF8
    Write-Host $logMessage
}

# Téléchargement des donnees cerbere

Invoke-WebRequest -Uri $csvUrlLogins -OutFile $CerbereUsersCsv -ErrorAction Stop
Invoke-WebRequest -Uri $csvUrlGroups -OutFile $CerbereGroupsCsv -ErrorAction Stop

# Fonction récupération données Cerbère
function Get-CerbereData {
    $users     = @()
    $groups    = @{}
    $userCsv   = Import-Csv -Path $CerbereUsersCsv -Delimiter ';'
    $groupsCsv = Import-Csv -Path $CerbereGroupsCsv -Delimiter ';'


    foreach ($user in $userCsv) {
        $groupsList = @()
        if ($user.'groupes globaux') {
            $groupsList = $user.'groupes globaux' -split '\+' | ForEach-Object { $_.Trim() }
        }
        $users += [PSCustomObject]@{
            Email   = $user.email.Trim().ToLower()
            Nom     = $user.nom
            Prenom  = $user.prenom
            Groupes = $groupsList
        }
    }

    foreach ($group in $groupsCsv) {
        $global = $group.'groupe global'.Trim()
        $locals = @()
        if ($group.'groupes locaux') {
            $locals = $group.'groupes locaux' -split '\+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        }
        $groups[$global] = $locals
    }

    return [PSCustomObject]@{ Users = $users; Groups = $groups }
}

# Fonction récupération données AD
function Get-ADData {
    $users = @()
    $groups = @{}

    $adUsers = Get-ADUser -Filter * -SearchBase $OUPath -Properties mail, GivenName, Surname, memberOf, SamAccountName  | Where-Object { $_.SamAccountName -ne "ldapsafeq" }
    foreach ($user in $adUsers) {
        $groupsList = @()
        if ($user.MemberOf) { 
            $groupsList = $user.MemberOf | ForEach-Object {  (Get-ADGroup $_ -ErrorAction SilentlyContinue).Name } 
        }

        $users += [PSCustomObject]@{
            Email          = ($user.mail) -as [string]
            Nom            = $user.Surname
            Prenom         = $user.GivenName
            Groupes        = $groupsList
            SamAccountName = $user.SamAccountName
        }
    }

    $adGroups = Get-ADGroup -Filter * -SearchBase $OUPath -Properties memberOf, GroupScope
    foreach ($group in $adGroups) {
        if ($IgnoredGroups -contains $group.Name) { continue }
        $locals = @()
        if ($group.MemberOf) {
            $locals = $group.MemberOf | ForEach-Object { (Get-ADGroup $_ -ErrorAction SilentlyContinue).Name } 
        }

        $groups[$group.Name] = [PSCustomObject]@{
            Scope  = $group.GroupScope   
            Locals = $locals              
        }
    }

    return [PSCustomObject]@{ Users = $users; Groups = $groups }
}

# Fonction comparaison Cerbère ↔ AD
function Compare-CerbereAD {
    param([object]$cerbere, [object]$ad)

    $anomalies = @()
    $groupAnomalies = @()

    # Utilisateurs à créer ou supprimer
    foreach ($user in $cerbere.Users) {
        if (-not $user.Email) { continue }
        if ($IgnoredUsers -contains $user.Email.ToLower()) { continue }
        if ($user.Email -notin ($ad.Users | Select-Object -ExpandProperty Email)) { $anomalies += "anomalie detectee : l'utilisateur $($user.Email) : doit etre cree" }
    }

    foreach ($user in $ad.Users) {
        if (-not $user.Email) { continue }
        if ($IgnoredUsers -contains $user.Email.ToLower()) { continue }

        if ($user.Email -notin ($cerbere.Users | Select-Object -ExpandProperty Email)) { $anomalies += "anomalie detectee : l'utilisateur $($user.Email) : doit etre supprime" }
    }

    # Vérification groupes globaux pour utilisateurs
    foreach ($user in $cerbere.Users) {
        if (-not $user.Email) { continue }
        if ($IgnoredUsers -contains $user.Email.ToLower()) { continue }
        $adUser = $ad.Users | Where-Object { $_.Email -eq $user.Email }

        if ($adUser) {
            # Groupes à ajouter au user
            foreach ($group in $user.Groupes) {
                if ($group -and ($group -notin $adUser.Groupes)) { $anomalies += "anomalie sur $($user.Email) : doit etre ajoute au groupe $group" }
            }
            # Groupes à supprimer au user
            foreach ($group in $adUser.Groupes) {
                if ($group -and ($group -notin $user.Groupes)) { $anomalies += "anomalie sur $($user.Email) : doit etre supprime du groupe $group" }
            }
        }
    }

    # Groupes globaux manquants dans AD 
    foreach ($cerbGroup in $cerbere.Groups.Keys) {
        if ($IgnoredGroups -contains $cerbGroup) { continue }
        if (-not $ad.Groups.ContainsKey($cerbGroup)) { $groupAnomalies += "anomalie detectee sur le groupe global $cerbGroup : doit etre cree" }
    }

    # Groupes globaux en trop dans AD
    foreach ($adGroupName in $ad.Groups.Keys) {
        if ($IgnoredGroups -contains $adGroupName) { continue }
        $adGroup = $ad.Groups[$adGroupName]
        if ($adGroup -and $adGroup.Scope -eq "Global" -and ($adGroupName -notin $cerbere.Groups.Keys)) { $groupAnomalies += "anomalie detectee sur le groupe global $adGroupName : doit etre supprime" }
    }

    # Liste des groupes locaux Cerbère 
    $allCerbereLocals = @()
    foreach ($locals in $cerbere.Groups.Values) { $allCerbereLocals += $locals }
    $allCerbereLocals = $allCerbereLocals | Sort-Object -Unique

    #  Liste des groupes locaux AD
    $allADLocals = @()
    foreach ($adGroupName in $ad.Groups.Keys) {
        $adGroup = $ad.Groups[$adGroupName]
        if ($adGroup.Scope -eq "DomainLocal") { $allADLocals += $adGroupName }
    }

    $allADLocals = $allADLocals | ForEach-Object { ($_ -as [string]).Trim().ToUpper() }
    $allCerbereLocals = $allCerbereLocals | ForEach-Object { ($_ -as [string]).Trim().ToUpper() }

    # Groupes locaux en trop dans AD
    foreach ($adLocal in $allADLocals) {
        if ($adLocal -notin $allCerbereLocals) {
            $groupAnomalies += "anomalie detectee sur le groupe local $adLocal : doit etre supprime" }
    }


    # Groupes locaux manquants dans AD
    foreach ($cerbereLocal in $allCerbereLocals) {
        if (-not $ad.Groups.ContainsKey($cerbereLocal)) {
            $groupAnomalies += "anomalie detectee sur le groupe local $cerbereLocal : doit etre cree" }
    }

    # Vérification membres globaux dans les groupes locaux
    foreach ($global in $cerbere.Groups.Keys) {
        $expectedLocals = $cerbere.Groups[$global]
        $actualLocals = @()
        if ($ad.Groups.ContainsKey($global)) { $actualLocals = $ad.Groups[$global].Locals }

        # Groupes global manquants dans un g local
        foreach ($local in $expectedLocals) {
            if ($local -and ($local -notin $actualLocals)) {
                $groupAnomalies += "anomalie detectee sur le groupe $global : doit etre ajoute au groupe local $local"
            }
        }

        # Groupes global en trop dans un g local
        foreach ($local in $actualLocals) {
            if ($local -and ($local -notin $expectedLocals)) {
                $groupAnomalies += "anomalie detectee sur le groupe $global : doit etre supprime du groupe local $local"
            }
        }
    }

    return [PSCustomObject]@{ UserAnomalies = $anomalies; GroupAnomalies = $groupAnomalies }
}


# Fonction création utilisateur
function creation_user {
    param([object]$user)
    $sam = $user.Email.Split("@")[0]
    $tri = $user.Email -replace "@(pap\.fr|pentalog\.com|globant\.com)$", "@win.groupe-pap.fr"
    $pass = "a." + (Get-Random -Maximum 99999999)
    $securePass = ConvertTo-SecureString -String $pass -AsPlainText -Force

    New-ADUser -Name "$($user.Prenom) $($user.Nom)" `
               -GivenName $user.Prenom -Surname $user.Nom `
               -SamAccountName $sam `
               -UserPrincipalName $tri `
               -EmailAddress $user.Email `
               -AccountPassword $securePass `
               -ChangePasswordAtLogon $true `
               -Enabled $true `
               -Path $OUPath

    Write-Log "l'utilisateur $($user.Email) a été créé avec mot de passe $pass"
}

# Fonction suppression utilisateur
function supprime_user {
    param([object]$user)
    $login = $user.SamAccountName
    $email = $user.Email

    Remove-ADUser -Identity $login -Confirm:$false -ErrorAction Stop
    Write-Log "l'utilisateur $email a été supprimé"

}

# Fonction ajout utilisateur aux groupes globaux
function ajout_user_au_groupe {
    param([object]$user)
    if ($IgnoredUsers -contains $user.Email.ToLower()) { continue }
    $adUser = Get-ADUser -Filter "mail -eq '$($user.Email)'" -Properties memberOf, SamAccountName -ErrorAction SilentlyContinue

    $oldGroups = Get-ADUser -Identity $adUser.SamAccountName -Property MemberOf | Select-Object -ExpandProperty MemberOf
    foreach ($group in $oldGroups) { 
        Remove-ADGroupMember -Identity $group -Members $adUser.SamAccountName -Confirm:$false 
        Write-Log "l'utilisateur $($user.Email) ajouté supprimer du groupe $group"
    }

    $adGroupNames = @()
    if ($adUser.MemberOf) { $adGroupNames = $adUser.MemberOf | ForEach-Object { (Get-ADGroup $_ -ErrorAction SilentlyContinue).Name } }

    foreach ($group in $user.Groupes) {
        if ($group -and ($group -notin $adGroupNames)) {
            Add-ADGroupMember -Identity $group -Members $adUser.SamAccountName -ErrorAction Stop
            Write-Log "l'utilisateur $($user.Email) ajouté au groupe $group"
            
        }
    }
}

# Fonction vérification et création des groupes AD
function creation_group {
    param(
        [string]$groupName,
        [ValidateSet("Global","DomainLocal","Universal")]
        [string]$groupScope = "Global",  
        [string]$groupCategory = "Security"  
    )

    $existingGroup = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
    if (-not $existingGroup) {
            New-ADGroup -Name $groupName `
                        -GroupScope $groupScope `
                        -GroupCategory $groupCategory `
                        -Path $OUPath `
                        -ErrorAction Stop
       Write-Log "le groupe $groupName a été créé"
    }
}

# Fonction ajout des groupes globaux aux groupes locaux
function ajout_gg_gl {
    param(
        [string]$globalGroup,
        [array]$localGroups
    )

    foreach ($local in $localGroups) {

        if (-not $local) { continue }
             Add-ADGroupMember -Identity $local -Members $globalGroup -ErrorAction Stop
             Write-Log "le groupe $globalGroup : a été ajouté au groupe local $local"

    }
}

# Fonction suppression d'un groupe
function supprime_group {
    param([string]$groupName)

    # Vérifie que le groupe existe
    $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
    if (-not $group) { return }

    Remove-ADGroup -Identity $groupName -Confirm:$false -ErrorAction Stop
    Write-Log "le groupe $groupName a été supprimé"
} 

# Fonction d'appel aux scripts externes 
function Invoke-Ext {
    param(
        [bool]$switchFlag,
        [string]$scriptPath,
        [array]$args,
        [string]$samAccount
    )

    if (-not $switchFlag) { return }
    if (-not (Test-Path $scriptPath)) {
        Write-Log "WARN::Script introuvable : $scriptPath"
        return
    }

    if ($sync -and -not $run) {
            continue
    } elseif ($sync -and $run) {
        try {
            & $scriptPath @args
            Write-Log "Script $(Split-Path $scriptPath -Leaf) exécuté pour $samAccount"
        } catch {
            Write-Log "exécution $(Split-Path $scriptPath -Leaf) pour $samAccount : $_"
        }
    }
}

# Fonction envoi mail
function Send-RapportMail {
    param([array]$anomalies, [array]$groupAnomalies)

    try {
        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = $exp_mail_check
        $mail.To.Add($dest_mail_check)
        $mail.Subject = "RESULTATS DE LA VERIFICATION AD/CERBERE"
        $mail.IsBodyHtml = $true
        $mail.BodyEncoding = [System.Text.Encoding]::UTF8
        $mail.SubjectEncoding = [System.Text.Encoding]::UTF8

        $mailBody = "<html><body>"

        if ($anomalies.Count -eq 0) {
            $mailBody += "<p><b>Aucune anomalie détectée entre les utilisateurs AD et Cerbère</b></p>"
        } else {
            $mailBody += "<p><b>Anomalies détectées entre les utilisateurs AD et Cerbère :</b></p><pre>"
            $mailBody += ($anomalies -join "`n")
            $mailBody += "</pre>"
        }

        if ($groupAnomalies.Count -eq 0) {
            $mailBody += "<p><b>Aucune anomalie détectée entre les groupes AD et Cerbère</b></p>"
        } else {
            $mailBody += "<p><b>Anomalies détectées entre les groupes AD et Cerbère :</b></p><pre>"
            $mailBody += ($groupAnomalies -join "`n")
            $mailBody += "</pre>"
        }

        $mailBody += "</body></html>"
        $mail.Body = $mailBody

        $smtp = New-Object System.Net.Mail.SmtpClient($smtp_serveur)
        $smtp.Send($mail)

        Write-Log "Le mail a été envoyé à $dest_mail_check avec succès."
    }
    catch {
        Write-Log "Erreur lors de l'envoi du mail : $_"
    }
}


# Chargement des données cerbère et AD
$cerbere = Get-CerbereData
$ad      = Get-ADData

# Comparaison des données cerbère et AD
$comparison = Compare-CerbereAD -cerbere $cerbere -ad $ad

if (-not $sync) {
    $comparison.UserAnomalies  | ForEach-Object { Write-Log $_ }
    $comparison.GroupAnomalies | ForEach-Object { Write-Log $_ }
}

# -------------TEST et RUN --------------------------------

# Création utilisateurs et ajout au groupe globaux
foreach ($user in $cerbere.Users) {
    if (-not $user.Email) { continue }
    if ($IgnoredUsers -contains $user.Email.ToLower()) { continue }

    $adUser = $ad.Users | Where-Object { $_.Email -eq $user.Email }
    $samAccount = $user.Email.Split("@")[0]

    if ($sync -and $run) {
        if (-not $adUser) { creation_user -user $user }
        ajout_user_au_groupe -user $user
        foreach ($group in $user.Groupes) { Write-Log "l'utilisateur $($user.Email) a ete ajoute au groupe $group" }
    } elseif ($sync -and -not $run) {
        if (-not $adUser) { Write-Log "l'utilisateur $($user.Email) serait cree" }
        $groupsAdd = $user.Groupes
        if ($adUser) { $groupsAdd = $user.Groupes | Where-Object { $_ -notin $adUser.Groupes } }
        foreach ($group in $groupsAdd) { Write-Log "l'utilisateur $($user.Email) serait ajoute au groupe $group" }
    }
}

# Suppression utilisateurs
foreach ($adUser in $ad.Users) {
    if (-not $adUser.Email) { continue }
    if ($adUser.Email -notin ($cerbere.Users | Select-Object -ExpandProperty Email)) {
        if ($sync -and $run) { supprime_user -user $adUser }
        elseif ($sync -and -not $run) { Write-Log "l'utilisateur $($adUser.Email) serait supprime de l'AD" }
    }
}

# Création groupe 
foreach ($global in $cerbere.Groups.Keys) {
    $locals = $cerbere.Groups[$global]

    if ($sync -and $run) {
        if ($global -notin $ad.Groups.Keys) { creation_group -groupName $global -groupScope "Global"}
        foreach ($local in $locals) {
            if ($local -notin $ad.Groups.Keys) { creation_group -groupName $local -groupScope "DomainLocal"}
        }
    }
    elseif ($sync -and -not $run) {
        if ($global -notin $ad.Groups.Keys) { Write-Log "le groupe global $global serait créé" }
        foreach ($local in $locals) {
            if ($local -notin $ad.Groups.Keys) { Write-Log "le groupe local $local serait créé" }
        }
    }
}

# Mapping groupes globaux -> locaux

foreach ($globalGroup in $cerbere.Groups.Keys) {
    $expectedLocals = $cerbere.Groups[$globalGroup]

    foreach ($localGroup in $expectedLocals) {
        if (-not $localGroup) { continue }

        try {
            $currentMembers = @(Get-ADGroupMember -Identity $localGroup -ErrorAction Stop | Where-Object { $_.objectClass -eq 'group' } | Select-Object -ExpandProperty Name)
        } catch {
            $currentMembers = @()  
        }

        if ($globalGroup -notin $currentMembers) {
            if ($sync -and $run) {
                ajout_gg_gl -globalGroup $globalGroup -localGroups $localGroup
            }
            elseif ($sync -and -not $run) {
                Write-Log "le groupe global $globalGroup serait ajouté au groupe local $localGroup"
            }
        }
    }
}


# Suppression groupes globaux et locaux
$expectedGroups = @($cerbere.Groups.Keys + ($cerbere.Groups.Values | ForEach-Object { $_ }) | Sort-Object -Unique)

foreach ($adGroupName in $ad.Groups.Keys) {
    if ($adGroupName -notin $expectedGroups) {
        if ($sync -and $run) { 
            supprime_group -groupName $adGroupName 
        }
        elseif ($sync -and -not $run) { 
            Write-Log "le groupe $adGroupName serait supprimé"
        }
    }
}
# Suppression des groupes locaux en trop
foreach ($globalGroupName in $cerbere.Groups.Keys) {
    if ($IgnoredGroups -contains $globalGroupName) { continue }

    $adGroupInfo = $ad.Groups[$globalGroupName]
    $actualLocals = $adGroupInfo.Locals
    $expectedLocals = $cerbere.Groups[$globalGroupName]

    foreach ($localGroupName in $actualLocals) {
        if ($IgnoredGroups -contains $localGroupName) { continue }
        if ($localGroupName -notin $expectedLocals) {
            if ($sync -and $run) { 
                supprime_group -groupName $localGroupName 
            }
            elseif ($sync -and -not $run) { 
                Write-Log "le groupe $localGroupName serait supprimé"
            }
        }
    }
}


foreach ($user in $cerbere.Users) {
    if (-not $user.Email) { continue }
    $samAccount = $user.Email.Split("@")[0]

    Invoke-Ext -switchFlag $true -scriptPath (Join-Path $dirpath_scripts "generer_un_code_safeq.ps1") -args @("-UserName",$samAccount) -samAccount $samAccount
    Invoke-Ext -switchFlag $h -scriptPath (Join-Path $dirpath_scripts "netlogon_ajouter_home.ps1") -args @("-utilisateur",$samAccount) -samAccount $samAccount
    Invoke-Ext -switchFlag $d -scriptPath (Join-Path $dirpath_scripts "netlogon_ajouter_gesco.ps1") -args @("-utilisateur",$samAccount) -samAccount $samAccount
    Invoke-Ext -switchFlag $i -scriptPath (Join-Path $dirpath_scripts "netlogon_ajouter_internet.ps1") -args @("-utilisateur",$samAccount) -samAccount $samAccount
    Invoke-Ext -switchFlag $w -scriptPath (Join-Path $dirpath_scripts "netlogon_ajouter_devweb.ps1") -args @("-utilisateur",$samAccount) -samAccount $samAccount
    Invoke-Ext -switchFlag $n -scriptPath (Join-Path $dirpath_scripts "netlogon_ajouter_harbinw.ps1") -args @("-utilisateur",$samAccount) -samAccount $samAccount
    Invoke-Ext -switchFlag $a -scriptPath (Join-Path $dirpath_scripts "netlogon_ajouter_ambassadeurs.ps1") -args @("-utilisateur",$samAccount) -samAccount $samAccount
    Invoke-Ext -switchFlag $r -scriptPath (Join-Path $dirpath_scripts "netlogon_ajouter_reseauxsociaux.ps1") -args @("-utilisateur",$samAccount) -samAccount $samAccount
}
if ($rapport) {
    Send-RapportMail -anomalies $comparison.UserAnomalies -groupAnomalies $comparison.GroupAnomalies
}
