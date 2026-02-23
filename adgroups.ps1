#requires -Version 7.0
# Copyright (c) 2026 xyOps. All rights reserved.
<#!
xyOps Active Directory Groups Event Plugin v1.0 (PowerShell 7)
A comprehensive collection of Active Directory group management action tools (10 tools):

Group Lifecycle:  Create Group, Delete Group, Rename Group, Copy Group
Membership:       Add Members, Remove Members, List Members
Organisation:     Move Group, Set Group Scope, Set Group Category

Safety:
- Destructive tools default to dry-run mode (preview changes without executing)
- Every action emits structured audit data (who, what, when)
- Multi-target support with per-group success/failure tracking

Prerequisites:
- ActiveDirectory PowerShell module (RSAT)
- Domain-joined machine or connectivity to a domain controller
- Account with Write access to target AD objects

I/O contract:
- Read one JSON object from STDIN (job), write progress/messages as JSON lines of the
  form: { "xy": 1, ... } to STDOUT.
- On success, emit: { "xy": 1, "code": 0, "data": <result>, "description": "..." }
- On error, emit:   { "xy": 1, "code": <nonzero>, "description": "..." } and exit 1.

Test locally:
  pwsh -NoProfile -ExecutionPolicy Bypass -File .\adgroups.ps1 < job.json
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region xyOps Output Helpers

function Write-XY {
  param([hashtable]$Object)
  $payload = [ordered]@{ xy = 1 }
  foreach ($k in $Object.Keys) { $payload[$k] = $Object[$k] }
  [Console]::Out.WriteLine(($payload | ConvertTo-Json -Depth 20 -Compress))
  [Console]::Out.Flush()
}

function Write-XYProgress {
  param([double]$Value, [string]$Status)
  $o = @{ progress = [math]::Round($Value, 4) }
  if ($Status) { $o.status = $Status }
  Write-XY $o
}

function Write-XYSuccess {
  param($Data, [string]$Description, [array]$Files = @())
  $o = @{ code = 0; data = $Data }
  if ($Description) { $o.description = $Description }
  if ($Files.Count -gt 0) { $o.files = $Files }
  Write-XY $o
}

function Write-XYError {
  param([int]$Code, [string]$Description)
  Write-XY @{ code = $Code; description = $Description }
}

function Write-XYWarning {
  param($Data, [string]$Description, [array]$Files = @())
  $o = @{ code = 'warning'; data = $Data }
  if ($Description) { $o.description = $Description }
  if ($Files.Count -gt 0) { $o.files = $Files }
  Write-XY $o
}

function Read-JobFromStdin {
  $raw = [Console]::In.ReadToEnd()
  if ([string]::IsNullOrWhiteSpace($raw)) { throw 'No job JSON received on STDIN' }
  return $raw | ConvertFrom-Json -ErrorAction Stop
}

function Get-Param {
  param($Params, [string]$Name, $Default = $null)
  if ($Params.PSObject.Properties.Name -contains $Name) { return $Params.$Name }
  return $Default
}

#endregion

#region Module Check

function Assert-ActiveDirectoryModule {
  Write-XYProgress 0.05 'Checking ActiveDirectory module...'

  if (-not (Get-Module -ListAvailable -Name 'ActiveDirectory')) {
    throw @"
ActiveDirectory PowerShell module is not installed.

To install RSAT on Windows 10/11:
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

On Windows Server:
  Install-WindowsFeature RSAT-AD-PowerShell

The machine must be domain-joined or able to reach a domain controller.
The account running xyOps must have Write access to the relevant AD objects.
"@
  }

  Import-Module ActiveDirectory -ErrorAction Stop
  Write-XYProgress 0.08 'ActiveDirectory module loaded'
}

#endregion

#region Shared Helpers

function Format-ADValue {
  param($Value, [string]$PropertyName)

  if ($null -eq $Value) { return '-' }

  if ($Value -is [datetime]) {
    if ($Value.Year -le 1601) { return 'Never' }
    return $Value.ToString('yyyy-MM-dd HH:mm')
  }

  if ($Value -is [bool]) {
    if ($Value) { return 'Yes' } else { return 'No' }
  }

  if ($Value -is [System.Security.Principal.SecurityIdentifier]) {
    return $Value.ToString()
  }

  if ($PropertyName -in @('Manager', 'ManagedBy') -and $Value -is [string] -and $Value -match 'CN=([^,]+)') {
    return $Matches[1]
  }

  if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
    $items = @($Value)
    if ($items.Count -eq 0) { return '-' }
    if ($items.Count -le 3) { return ($items -join ', ') }
    return "$($items[0..2] -join ', ') (+$($items.Count - 3) more)"
  }

  $str = [string]$Value
  if ([string]::IsNullOrWhiteSpace($str)) { return '-' }
  return $str
}

function Get-MultipleInputs {
  param($Value, [int]$MaxItems = 50)
  $items = @()
  if ($null -eq $Value) { return $items }
  if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
    $items = @($Value | ForEach-Object { if ($_ -is [string]) { $_.Trim() } else { [string]$_ } } | Where-Object { $_ -ne '' })
  } else {
    $items = @([string]$Value -split '[,;\n\r]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
  }
  return @($items | Select-Object -First $MaxItems)
}

function Get-DryRunFlag {
  param($Params)
  if ($Params.PSObject.Properties.Name -contains 'dryRun') { return [bool]$Params.dryRun }
  return $true  # Default: dry-run enabled (safe)
}

function Get-DryRunLabel {
  param([bool]$IsDryRun)
  if ($IsDryRun) { return '[DRY-RUN] ' } else { return '' }
}

function Resolve-ADGroups {
  param([array]$Identities, [double]$ProgressStart = 0.15, [double]$ProgressEnd = 0.35)

  $resolved = [System.Collections.Generic.List[object]]::new()
  $idx = 0
  foreach ($identity in $Identities) {
    $idx++
    $pct = $ProgressStart + (($ProgressEnd - $ProgressStart) * $idx / $Identities.Count)
    Write-XYProgress $pct "Resolving group '$identity'..."
    try {
      $group = Get-ADGroup -Identity $identity -Properties Name, SamAccountName, GroupScope,
        GroupCategory, Description, ManagedBy, Members, MemberOf,
        DistinguishedName, Created, Modified -ErrorAction Stop
      $resolved.Add([PSCustomObject]@{
        Group    = $group
        Identity = $identity
        Success  = $true
        Error    = $null
      })
    } catch {
      # Fallback: search by Name
      $escaped = $identity -replace "'", "''"
      $fbGroup = Get-ADGroup -Filter "Name -eq '$escaped'" -Properties Name, SamAccountName, GroupScope,
        GroupCategory, Description, ManagedBy, Members, MemberOf,
        DistinguishedName, Created, Modified -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($fbGroup) {
        $resolved.Add([PSCustomObject]@{
          Group    = $fbGroup
          Identity = $identity
          Success  = $true
          Error    = $null
        })
      } else {
        $resolved.Add([PSCustomObject]@{
          Group    = $null
          Identity = $identity
          Success  = $false
          Error    = "Cannot find group '$identity'"
        })
      }
    }
  }
  return $resolved
}

function Resolve-SingleGroup {
  param([string]$Identity, [string[]]$Properties = @())
  try {
    $p = @{ Identity = $Identity; ErrorAction = 'Stop' }
    if ($Properties.Count -gt 0) { $p.Properties = $Properties }
    return Get-ADGroup @p
  } catch {
    $escaped = $Identity -replace "'", "''"
    $p = @{ Filter = "Name -eq '$escaped'"; ErrorAction = 'Stop' }
    if ($Properties.Count -gt 0) { $p.Properties = $Properties }
    $results = @(Get-ADGroup @p)
    if ($results.Count -eq 1) { return $results[0] }
    if ($results.Count -gt 1) { throw "Multiple groups match name '$Identity'. Use SamAccountName or DN." }
    throw "Cannot find group '$Identity'"
  }
}

#endregion

#region Group Lifecycle Tools

function Invoke-CreateGroup {
  param($Params)

  Write-XYProgress 0.10 'Preparing to create group...'

  $groupName     = (Get-Param $Params 'groupName' '').Trim()
  $samAccount    = (Get-Param $Params 'samAccountName' '').Trim()
  $displayName   = (Get-Param $Params 'displayName' '').Trim()
  $description   = (Get-Param $Params 'description' '').Trim()
  $targetOU      = (Get-Param $Params 'targetOU' '').Trim()
  $groupScope    = (Get-Param $Params 'groupScope' 'Global').Trim()
  $groupCategory = (Get-Param $Params 'groupCategory' 'Security').Trim()
  $managedBy     = (Get-Param $Params 'managedBy' '').Trim()

  if (-not $groupName) { throw 'Group name is required.' }
  if (-not $samAccount) { $samAccount = $groupName -replace '[^a-zA-Z0-9._-]', '' }
  if (-not $displayName) { $displayName = $groupName }

  # Validate scope
  if ($groupScope -notin @('Global', 'Universal', 'DomainLocal')) {
    throw "Invalid group scope '$groupScope'. Use Global, Universal, or DomainLocal."
  }

  Write-XYProgress 0.30 'Creating group...'

  $newGroupParams = @{
    Name           = $groupName
    SamAccountName = $samAccount
    DisplayName    = $displayName
    GroupScope     = $groupScope
    GroupCategory  = $groupCategory
  }
  if ($description) { $newGroupParams.Description = $description }
  if ($targetOU) { $newGroupParams.Path = $targetOU }

  New-ADGroup @newGroupParams -ErrorAction Stop
  Write-XYProgress 0.55 'Group created'

  if ($managedBy) {
    try { Set-ADGroup -Identity $samAccount -ManagedBy $managedBy -ErrorAction Stop } catch {}
  }

  Write-XYProgress 0.80 'Building output...'

  $createdGroup = Get-ADGroup -Identity $samAccount -Properties * -ErrorAction Stop

  $rows = @(
    @('Name', $createdGroup.Name),
    @('SAM Account', $createdGroup.SamAccountName),
    @('Display Name', $createdGroup.DisplayName),
    @('Scope', [string]$createdGroup.GroupScope),
    @('Category', [string]$createdGroup.GroupCategory),
    @('Description', $(if ($createdGroup.Description) { $createdGroup.Description } else { '-' })),
    @('OU', $createdGroup.DistinguishedName -replace "^CN=[^,]+,", ""),
    @('Managed By', $(Format-ADValue -Value $createdGroup.ManagedBy -PropertyName 'ManagedBy'))
  )

  Write-XY @{ table = @{
    title   = "Group Created — $($createdGroup.Name)"
    header  = @('Property', 'Value')
    rows    = $rows
    caption = "Group '$samAccount' created successfully"
  } }

  return [PSCustomObject]@{
    tool = 'Create Group'; success = $true
    samAccountName = $samAccount; name = $groupName
    scope = $groupScope; category = $groupCategory
    dn = $createdGroup.DistinguishedName
    generatedFiles = @()
  }
}

function Invoke-DeleteGroup {
  param($Params)

  $dryRun = Get-DryRunFlag $Params
  $label = Get-DryRunLabel $dryRun
  $targetGroupsInput = Get-Param $Params 'targetGroups' ''
  $targets = @(Get-MultipleInputs $targetGroupsInput 50)
  if ($targets.Count -eq 0) { throw 'No target group(s) specified.' }

  Write-XYProgress 0.10 "${label}Resolving groups..."
  $resolved = Resolve-ADGroups -Identities $targets

  Write-XYProgress 0.40 "${label}Processing deletions..."

  $displayHeaders = @('#', 'Name', 'SAM Account', 'Status', 'Detail')
  $tableRows = @()
  $successCount = 0; $failCount = 0
  $idx = 0

  foreach ($r in $resolved) {
    $idx++
    $pct = 0.40 + (0.45 * $idx / $resolved.Count)
    if (-not $r.Success) {
      $failCount++
      $tableRows += ,@($idx, '-', $r.Identity, 'FAILED', "Not found: $($r.Error)")
      continue
    }

    $group = $r.Group
    Write-XYProgress $pct "${label}Processing '$($group.SamAccountName)'..."

    if ($dryRun) {
      $memberCount = if ($group.Members) { @($group.Members).Count } else { 0 }
      $successCount++
      $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'WOULD DELETE',
        "Scope: $($group.GroupScope) | Category: $($group.GroupCategory) | Members: $memberCount")
    } else {
      try {
        Remove-ADGroup -Identity $group.DistinguishedName -Confirm:$false -ErrorAction Stop
        $successCount++
        $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'DELETED', 'Group removed from AD')
      } catch {
        $failCount++
        $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'FAILED', $_.Exception.Message)
      }
    }
  }

  $modeText = if ($dryRun) { 'DRY-RUN — no changes made' } else { "$successCount deleted, $failCount failed" }
  Write-XY @{ table = @{
    title   = "${label}Delete Group"
    header  = $displayHeaders
    rows    = $tableRows
    caption = $modeText
  } }

  return [PSCustomObject]@{
    tool = 'Delete Group'; success = ($failCount -eq 0); dryRun = $dryRun
    totalTargets = $targets.Count; successCount = $successCount; failCount = $failCount
    generatedFiles = @()
  }
}

function Invoke-RenameGroup {
  param($Params)

  $dryRun = Get-DryRunFlag $Params
  $label = Get-DryRunLabel $dryRun
  $targetGroup    = (Get-Param $Params 'targetGroup' '').Trim()
  $newName        = (Get-Param $Params 'newName' '').Trim()
  $newSamAccount  = (Get-Param $Params 'newSamAccountName' '').Trim()
  $newDisplayName = (Get-Param $Params 'newDisplayName' '').Trim()
  $newDescription = (Get-Param $Params 'description' '').Trim()
  $newManagedBy   = (Get-Param $Params 'managedBy' '').Trim()

  if (-not $targetGroup) { throw 'Target group is required.' }
  if (-not $newName -and -not $newSamAccount -and -not $newDisplayName -and -not $newDescription -and -not $newManagedBy) {
    throw 'At least one new value must be provided.'
  }

  Write-XYProgress 0.15 "${label}Loading group..."
  $group = Resolve-SingleGroup -Identity $targetGroup -Properties @('DisplayName', 'SamAccountName', 'Description', 'ManagedBy')

  Write-XYProgress 0.35 "${label}Preparing rename..."

  $changes = @()
  if ($newSamAccount -and $newSamAccount -ne $group.SamAccountName) {
    $changes += ,@('SamAccountName', $group.SamAccountName, $newSamAccount)
  }
  if ($newDisplayName -and $newDisplayName -ne $group.DisplayName) {
    $changes += ,@('DisplayName', $(if ($group.DisplayName) { $group.DisplayName } else { '-' }), $newDisplayName)
  }
  if ($newName -and $newName -ne $group.Name) {
    $changes += ,@('CN (Name)', $group.Name, $newName)
  }
  if ($newDescription -and $newDescription -ne $group.Description) {
    $changes += ,@('Description', $(if ($group.Description) { $group.Description } else { '-' }), $newDescription)
  }
  if ($newManagedBy) {
    $oldManaged = Format-ADValue -Value $group.ManagedBy -PropertyName 'ManagedBy'
    $changes += ,@('Managed By', $oldManaged, $newManagedBy)
  }

  if ($changes.Count -eq 0) {
    throw 'No changes detected — all new values match current values.'
  }

  $displayHeaders = @('Property', 'Current', 'New')
  $tableRows = @()
  foreach ($c in $changes) {
    $tableRows += ,@($c[0], $c[1], $c[2])
  }

  if (-not $dryRun) {
    Write-XYProgress 0.55 'Applying changes...'

    $setParams = @{}
    if ($newSamAccount -and $newSamAccount -ne $group.SamAccountName) { $setParams.SamAccountName = $newSamAccount }
    if ($newDisplayName -and $newDisplayName -ne $group.DisplayName) { $setParams.DisplayName = $newDisplayName }
    if ($newDescription -and $newDescription -ne $group.Description) { $setParams.Description = $newDescription }
    if ($newManagedBy) { $setParams.ManagedBy = $newManagedBy }

    if ($setParams.Count -gt 0) {
      Set-ADGroup -Identity $group.DistinguishedName @setParams -ErrorAction Stop
    }

    if ($newName -and $newName -ne $group.Name) {
      Rename-ADObject -Identity $group.DistinguishedName -NewName $newName -ErrorAction Stop
    }
  }

  $modeText = if ($dryRun) { 'DRY-RUN — no changes made' } else { "$($tableRows.Count) attribute(s) updated" }
  Write-XY @{ table = @{
    title   = "${label}Rename Group — $($group.Name)"
    header  = $displayHeaders
    rows    = $tableRows
    caption = $modeText
  } }

  return [PSCustomObject]@{
    tool = 'Rename Group'; success = $true; dryRun = $dryRun
    targetGroup = $group.SamAccountName; changesCount = $tableRows.Count
    generatedFiles = @()
  }
}

function Invoke-CopyGroup {
  param($Params)

  Write-XYProgress 0.10 'Preparing to copy group...'

  $sourceGroup   = (Get-Param $Params 'sourceGroup' '').Trim()
  $newGroupName  = (Get-Param $Params 'newGroupName' '').Trim()
  $newSamAccount = (Get-Param $Params 'newSamAccountName' '').Trim()
  $targetOU      = (Get-Param $Params 'targetOU' '').Trim()
  $description   = (Get-Param $Params 'description' '').Trim()
  $managedBy     = (Get-Param $Params 'managedBy' '').Trim()
  $copyMembers   = if ($Params.PSObject.Properties.Name -contains 'copyMembers') { [bool]$Params.copyMembers } else { $true }

  if (-not $sourceGroup) { throw 'Source group is required.' }
  if (-not $newGroupName) { throw 'New group name is required.' }
  if (-not $newSamAccount) { $newSamAccount = $newGroupName -replace '[^a-zA-Z0-9._-]', '' }

  Write-XYProgress 0.20 "Loading source group '$sourceGroup'..."
  $template = Resolve-SingleGroup -Identity $sourceGroup -Properties @('Description', 'ManagedBy', 'Members', 'GroupScope', 'GroupCategory', 'DisplayName', 'DistinguishedName')

  Write-XYProgress 0.35 'Creating new group from template...'

  $ou = if ($targetOU) { $targetOU } else { $template.DistinguishedName -replace '^CN=[^,]+,' }

  $newGroupParams = @{
    Name           = $newGroupName
    SamAccountName = $newSamAccount
    DisplayName    = $newGroupName
    GroupScope     = $template.GroupScope
    GroupCategory  = $template.GroupCategory
    Path           = $ou
  }
  $finalDesc = if ($description) { $description } elseif ($template.Description) { $template.Description } else { $null }
  if ($finalDesc) { $newGroupParams.Description = $finalDesc }

  New-ADGroup @newGroupParams -ErrorAction Stop
  Write-XYProgress 0.50 'Group created, copying settings...'

  $finalManagedBy = if ($managedBy) { $managedBy } elseif ($template.ManagedBy) { $template.ManagedBy } else { $null }
  if ($finalManagedBy) {
    try { Set-ADGroup -Identity $newSamAccount -ManagedBy $finalManagedBy -ErrorAction Stop } catch {}
  }

  # Copy members
  $membersCopied = 0
  if ($copyMembers -and $template.Members) {
    Write-XYProgress 0.60 'Copying members...'
    $members = @($template.Members)
    foreach ($memberDN in $members) {
      try {
        Add-ADGroupMember -Identity $newSamAccount -Members $memberDN -ErrorAction Stop
        $membersCopied++
      } catch {}
    }
  }

  Write-XYProgress 0.85 'Building output...'

  $totalMembers = if ($template.Members) { @($template.Members).Count } else { 0 }
  $rows = @(
    @('Source Group', "$($template.Name) ($($template.SamAccountName))"),
    @('New Group', "$newGroupName ($newSamAccount)"),
    @('Scope', [string]$template.GroupScope),
    @('Category', [string]$template.GroupCategory),
    @('OU', $ou),
    @('Members Copied', "$membersCopied of $totalMembers"),
    @('Managed By', $(Format-ADValue -Value $template.ManagedBy -PropertyName 'ManagedBy'))
  )

  Write-XY @{ table = @{
    title   = "Group Copied — $newGroupName"
    header  = @('Property', 'Value')
    rows    = $rows
    caption = "Group '$newSamAccount' created from template '$($template.SamAccountName)'"
  } }

  return [PSCustomObject]@{
    tool = 'Copy Group'; success = $true
    sourceGroup = $template.SamAccountName; newGroup = $newSamAccount
    membersCopied = $membersCopied; totalMembers = $totalMembers
    generatedFiles = @()
  }
}

#endregion

#region Membership Tools

function Invoke-AddMembers {
  param($Params)

  $targetGroupsInput = Get-Param $Params 'targetGroups' ''
  $membersInput      = Get-Param $Params 'members' ''
  $groups  = @(Get-MultipleInputs $targetGroupsInput 50)
  $members = @(Get-MultipleInputs $membersInput 50)

  if ($groups.Count -eq 0) { throw 'No target group(s) specified.' }
  if ($members.Count -eq 0) { throw 'No member(s) specified.' }

  # Pre-validate: resolve all target groups before processing
  Write-XYProgress 0.05 "Validating $($groups.Count) target group(s)..."
  $resolvedGroups = Resolve-ADGroups -Identities $groups -ProgressStart 0.05 -ProgressEnd 0.15
  $failedGroups = @($resolvedGroups | Where-Object { -not $_.Success })
  if ($failedGroups.Count -gt 0) {
    $names = ($failedGroups | ForEach-Object { "'$($_.Identity)'" }) -join ', '
    throw "Target group(s) not found: $names"
  }

  Write-XYProgress 0.15 "Adding $($members.Count) member(s) to $($groups.Count) group(s)..."

  $displayHeaders = @('#', 'Member', 'Group', 'Status', 'Detail')
  $tableRows = @()
  $successCount = 0; $failCount = 0; $skippedCount = 0
  $idx = 0

  foreach ($memberIdentity in $members) {
    foreach ($rg in $resolvedGroups) {
      $idx++
      $groupObj = $rg.Group
      $pct = 0.15 + (0.75 * $idx / ($members.Count * $resolvedGroups.Count))
      Write-XYProgress $pct "Adding '$memberIdentity' to '$($groupObj.Name)'..."

      try {
        # Try user first, then computer, then group
        $memberObj = $null
        try { $memberObj = Get-ADUser -Identity $memberIdentity -ErrorAction Stop } catch {}
        if (-not $memberObj) { try { $memberObj = Get-ADComputer -Identity $memberIdentity -ErrorAction Stop } catch {} }
        if (-not $memberObj) { try { $memberObj = Get-ADGroup -Identity $memberIdentity -ErrorAction Stop } catch {} }
        if (-not $memberObj) { throw "Could not find AD object '$memberIdentity'" }

        $isMember = $groupObj.Members -contains $memberObj.DistinguishedName

        if ($isMember) {
          $skippedCount++
          $tableRows += ,@($idx, $memberObj.Name, $groupObj.Name, 'SKIPPED', 'Already a member')
        } else {
          Add-ADGroupMember -Identity $groupObj -Members $memberObj -ErrorAction Stop
          $successCount++
          $tableRows += ,@($idx, $memberObj.Name, $groupObj.Name, 'ADDED', 'Successfully added')
        }
      } catch {
        $failCount++
        $tableRows += ,@($idx, $memberIdentity, $groupObj.Name, 'FAILED', $_.Exception.Message)
      }
    }
  }

  Write-XY @{ table = @{
    title   = 'Add Members'
    header  = $displayHeaders
    rows    = $tableRows
    caption = "$successCount added, $skippedCount already members, $failCount failed"
  } }

  return [PSCustomObject]@{
    tool = 'Add Members'; success = ($failCount -eq 0)
    warning = ($failCount -gt 0)
    totalOperations = $idx; successCount = $successCount
    skippedCount = $skippedCount; failCount = $failCount
    generatedFiles = @()
  }
}

function Invoke-RemoveMembers {
  param($Params)

  $dryRun = Get-DryRunFlag $Params
  $label = Get-DryRunLabel $dryRun
  $targetGroupsInput = Get-Param $Params 'targetGroups' ''
  $membersInput      = Get-Param $Params 'members' ''
  $groups  = @(Get-MultipleInputs $targetGroupsInput 50)
  $members = @(Get-MultipleInputs $membersInput 50)

  if ($groups.Count -eq 0) { throw 'No target group(s) specified.' }
  if ($members.Count -eq 0) { throw 'No member(s) specified.' }

  # Pre-validate: resolve all target groups before processing
  Write-XYProgress 0.05 "${label}Validating $($groups.Count) target group(s)..."
  $resolvedGroups = Resolve-ADGroups -Identities $groups -ProgressStart 0.05 -ProgressEnd 0.15
  $failedGroups = @($resolvedGroups | Where-Object { -not $_.Success })
  if ($failedGroups.Count -gt 0) {
    $names = ($failedGroups | ForEach-Object { "'$($_.Identity)'" }) -join ', '
    throw "Target group(s) not found: $names"
  }

  Write-XYProgress 0.15 "${label}Removing $($members.Count) member(s) from $($groups.Count) group(s)..."

  $displayHeaders = @('#', 'Member', 'Group', 'Status', 'Detail')
  $tableRows = @()
  $successCount = 0; $failCount = 0; $skippedCount = 0
  $idx = 0

  foreach ($memberIdentity in $members) {
    foreach ($rg in $resolvedGroups) {
      $idx++
      $groupObj = $rg.Group
      $pct = 0.15 + (0.75 * $idx / ($members.Count * $resolvedGroups.Count))
      Write-XYProgress $pct "${label}Processing '$memberIdentity' from '$($groupObj.Name)'..."

      try {
        $memberObj = $null
        try { $memberObj = Get-ADUser -Identity $memberIdentity -ErrorAction Stop } catch {}
        if (-not $memberObj) { try { $memberObj = Get-ADComputer -Identity $memberIdentity -ErrorAction Stop } catch {} }
        if (-not $memberObj) { try { $memberObj = Get-ADGroup -Identity $memberIdentity -ErrorAction Stop } catch {} }
        if (-not $memberObj) { throw "Could not find AD object '$memberIdentity'" }

        $isMember = $groupObj.Members -contains $memberObj.DistinguishedName

        if (-not $isMember) {
          $skippedCount++
          $tableRows += ,@($idx, $memberObj.Name, $groupObj.Name, 'SKIPPED', 'Not a member')
        } elseif ($dryRun) {
          $successCount++
          $tableRows += ,@($idx, $memberObj.Name, $groupObj.Name, 'WOULD REMOVE', 'Currently a member')
        } else {
          Remove-ADGroupMember -Identity $groupObj -Members $memberObj -Confirm:$false -ErrorAction Stop
          $successCount++
          $tableRows += ,@($idx, $memberObj.Name, $groupObj.Name, 'REMOVED', 'Successfully removed')
        }
      } catch {
        $failCount++
        $tableRows += ,@($idx, $memberIdentity, $groupObj.Name, 'FAILED', $_.Exception.Message)
      }
    }
  }

  $modeText = if ($dryRun) { 'DRY-RUN — no changes made' } else { "$successCount removed, $skippedCount not members, $failCount failed" }
  Write-XY @{ table = @{
    title   = "${label}Remove Members"
    header  = $displayHeaders
    rows    = $tableRows
    caption = $modeText
  } }

  return [PSCustomObject]@{
    tool = 'Remove Members'; success = ($failCount -eq 0); dryRun = $dryRun
    warning = ($failCount -gt 0 -and -not $dryRun)
    totalOperations = $idx; successCount = $successCount
    skippedCount = $skippedCount; failCount = $failCount
    generatedFiles = @()
  }
}

function Invoke-ListMembers {
  param($Params)

  $targetGroup = (Get-Param $Params 'targetGroup' '').Trim()
  $recursive   = if ($Params.PSObject.Properties.Name -contains 'recursive') { [bool]$Params.recursive } else { $false }

  if (-not $targetGroup) { throw 'Target group is required.' }

  Write-XYProgress 0.15 "Loading group '$targetGroup'..."
  $group = Resolve-SingleGroup -Identity $targetGroup -Properties @('Description', 'ManagedBy', 'GroupScope', 'GroupCategory')

  Write-XYProgress 0.30 'Retrieving members...'

  $getMemberParams = @{ Identity = $group.DistinguishedName }
  if ($recursive) { $getMemberParams.Recursive = $true }

  $memberObjects = @(Get-ADGroupMember @getMemberParams -ErrorAction Stop)

  Write-XYProgress 0.60 "Processing $($memberObjects.Count) member(s)..."

  $displayHeaders = @('#', 'Name', 'SAM Account', 'Type', 'Enabled')
  $tableRows = @()
  $idx = 0

  foreach ($member in $memberObjects) {
    $idx++
    $enabled = '-'
    if ($member.objectClass -eq 'user') {
      try {
        $u = Get-ADUser -Identity $member.DistinguishedName -Properties Enabled -ErrorAction Stop
        $enabled = Format-ADValue -Value $u.Enabled -PropertyName 'Enabled'
      } catch { $enabled = '?' }
    } elseif ($member.objectClass -eq 'computer') {
      try {
        $c = Get-ADComputer -Identity $member.DistinguishedName -Properties Enabled -ErrorAction Stop
        $enabled = Format-ADValue -Value $c.Enabled -PropertyName 'Enabled'
      } catch { $enabled = '?' }
    }

    $typeLabel = switch ($member.objectClass) {
      'user'     { 'User' }
      'computer' { 'Computer' }
      'group'    { 'Group' }
      default    { $member.objectClass }
    }

    $tableRows += ,@($idx, $member.Name, $member.SamAccountName, $typeLabel, $enabled)
  }

  $recursiveText = if ($recursive) { ' (recursive)' } else { '' }
  Write-XY @{ table = @{
    title   = "Members of $($group.Name)$recursiveText"
    header  = $displayHeaders
    rows    = $tableRows
    caption = "$($memberObjects.Count) member(s) | Scope: $($group.GroupScope) | Category: $($group.GroupCategory)"
  } }

  return [PSCustomObject]@{
    tool = 'List Members'; success = $true
    targetGroup = $group.SamAccountName; memberCount = $memberObjects.Count
    recursive = $recursive
    generatedFiles = @()
  }
}

#endregion

#region Organisation Tools

function Invoke-MoveGroup {
  param($Params)

  $dryRun = Get-DryRunFlag $Params
  $label = Get-DryRunLabel $dryRun
  $targetGroupsInput = Get-Param $Params 'targetGroups' ''
  $targets = @(Get-MultipleInputs $targetGroupsInput 50)
  $targetOU = (Get-Param $Params 'targetOU' '').Trim()

  if ($targets.Count -eq 0) { throw 'No target group(s) specified.' }
  if (-not $targetOU) { throw 'Target OU is required. Provide a Distinguished Name (e.g., OU=Groups,DC=contoso,DC=com).' }

  Write-XYProgress 0.10 "${label}Resolving $($targets.Count) group(s)..."
  $resolved = Resolve-ADGroups -Identities $targets

  Write-XYProgress 0.40 "${label}Moving groups..."

  $displayHeaders = @('#', 'Name', 'SAM Account', 'Status', 'From OU', 'To OU')
  $tableRows = @()
  $successCount = 0; $failCount = 0
  $idx = 0

  foreach ($r in $resolved) {
    $idx++
    if (-not $r.Success) {
      $failCount++
      $tableRows += ,@($idx, '-', $r.Identity, 'FAILED', '-', "Not found: $($r.Error)")
      continue
    }

    $group = $r.Group
    $currentOU = $group.DistinguishedName -replace '^CN=[^,]+,'

    if ($dryRun) {
      $successCount++
      $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'WOULD MOVE', $currentOU, $targetOU)
    } else {
      try {
        Move-ADObject -Identity $group.DistinguishedName -TargetPath $targetOU -ErrorAction Stop
        $successCount++
        $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'MOVED', $currentOU, $targetOU)
      } catch {
        $failCount++
        $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'FAILED', $currentOU, $_.Exception.Message)
      }
    }
  }

  $modeText = if ($dryRun) { 'DRY-RUN — no changes made' } else { "$successCount moved, $failCount failed" }
  Write-XY @{ table = @{
    title   = "${label}Move Group"
    header  = $displayHeaders
    rows    = $tableRows
    caption = $modeText
  } }

  return [PSCustomObject]@{
    tool = 'Move Group'; success = ($failCount -eq 0); dryRun = $dryRun
    totalTargets = $targets.Count; successCount = $successCount; failCount = $failCount
    generatedFiles = @()
  }
}

function Invoke-SetGroupScope {
  param($Params)

  $dryRun = Get-DryRunFlag $Params
  $label = Get-DryRunLabel $dryRun
  $targetGroupsInput = Get-Param $Params 'targetGroups' ''
  $targets = @(Get-MultipleInputs $targetGroupsInput 50)
  $newScope = (Get-Param $Params 'newScope' '').Trim()

  if ($targets.Count -eq 0) { throw 'No target group(s) specified.' }
  if (-not $newScope) { throw 'New scope is required (Global, Universal, or DomainLocal).' }
  if ($newScope -notin @('Global', 'Universal', 'DomainLocal')) {
    throw "Invalid scope '$newScope'. Use Global, Universal, or DomainLocal."
  }

  Write-XYProgress 0.10 "${label}Resolving $($targets.Count) group(s)..."
  $resolved = Resolve-ADGroups -Identities $targets

  Write-XYProgress 0.40 "${label}Changing scope..."

  $displayHeaders = @('#', 'Name', 'SAM Account', 'Status', 'Previous Scope', 'New Scope')
  $tableRows = @()
  $successCount = 0; $failCount = 0; $skippedCount = 0
  $idx = 0

  foreach ($r in $resolved) {
    $idx++
    if (-not $r.Success) {
      $failCount++
      $tableRows += ,@($idx, '-', $r.Identity, 'FAILED', '-', "Not found: $($r.Error)")
      continue
    }

    $group = $r.Group
    $currentScope = [string]$group.GroupScope

    if ($currentScope -eq $newScope) {
      $skippedCount++
      $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'SKIPPED', $currentScope, "Already $newScope")
      continue
    }

    if ($dryRun) {
      $successCount++
      $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'WOULD CHANGE', $currentScope, $newScope)
    } else {
      try {
        Set-ADGroup -Identity $group.DistinguishedName -GroupScope $newScope -ErrorAction Stop
        $successCount++
        $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'CHANGED', $currentScope, $newScope)
      } catch {
        $failCount++
        $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'FAILED', $currentScope, $_.Exception.Message)
      }
    }
  }

  $modeText = if ($dryRun) { 'DRY-RUN — no changes made' } else { "$successCount changed, $skippedCount already $newScope, $failCount failed" }
  Write-XY @{ table = @{
    title   = "${label}Set Group Scope"
    header  = $displayHeaders
    rows    = $tableRows
    caption = $modeText
  } }

  return [PSCustomObject]@{
    tool = 'Set Group Scope'; success = ($failCount -eq 0); dryRun = $dryRun
    totalTargets = $targets.Count; successCount = $successCount
    skippedCount = $skippedCount; failCount = $failCount
    generatedFiles = @()
  }
}

function Invoke-SetGroupCategory {
  param($Params)

  $dryRun = Get-DryRunFlag $Params
  $label = Get-DryRunLabel $dryRun
  $targetGroupsInput = Get-Param $Params 'targetGroups' ''
  $targets = @(Get-MultipleInputs $targetGroupsInput 50)
  $newCategory = (Get-Param $Params 'newCategory' '').Trim()

  if ($targets.Count -eq 0) { throw 'No target group(s) specified.' }
  if (-not $newCategory) { throw 'New category is required (Security or Distribution).' }
  if ($newCategory -notin @('Security', 'Distribution')) {
    throw "Invalid category '$newCategory'. Use Security or Distribution."
  }

  Write-XYProgress 0.10 "${label}Resolving $($targets.Count) group(s)..."
  $resolved = Resolve-ADGroups -Identities $targets

  Write-XYProgress 0.40 "${label}Changing category..."

  $displayHeaders = @('#', 'Name', 'SAM Account', 'Status', 'Previous', 'New')
  $tableRows = @()
  $successCount = 0; $failCount = 0; $skippedCount = 0
  $idx = 0

  foreach ($r in $resolved) {
    $idx++
    if (-not $r.Success) {
      $failCount++
      $tableRows += ,@($idx, '-', $r.Identity, 'FAILED', '-', "Not found: $($r.Error)")
      continue
    }

    $group = $r.Group
    $currentCategory = [string]$group.GroupCategory

    if ($currentCategory -eq $newCategory) {
      $skippedCount++
      $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'SKIPPED', $currentCategory, "Already $newCategory")
      continue
    }

    if ($dryRun) {
      $successCount++
      $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'WOULD CHANGE', $currentCategory, $newCategory)
    } else {
      try {
        Set-ADGroup -Identity $group.DistinguishedName -GroupCategory $newCategory -ErrorAction Stop
        $successCount++
        $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'CHANGED', $currentCategory, $newCategory)
      } catch {
        $failCount++
        $tableRows += ,@($idx, $group.Name, $group.SamAccountName, 'FAILED', $currentCategory, $_.Exception.Message)
      }
    }
  }

  $modeText = if ($dryRun) { 'DRY-RUN — no changes made' } else { "$successCount changed, $skippedCount unchanged, $failCount failed" }
  Write-XY @{ table = @{
    title   = "${label}Set Group Category"
    header  = $displayHeaders
    rows    = $tableRows
    caption = $modeText
  } }

  return [PSCustomObject]@{
    tool = 'Set Group Category'; success = ($failCount -eq 0); dryRun = $dryRun
    totalTargets = $targets.Count; successCount = $successCount
    skippedCount = $skippedCount; failCount = $failCount
    generatedFiles = @()
  }
}

function Invoke-SetGroupDescription {
  param($Params)

  $targetGroupsInput = Get-Param $Params 'targetGroups' ''
  $targets = @(Get-MultipleInputs $targetGroupsInput 50)
  $newDescription = (Get-Param $Params 'description' '').Trim()
  $managedBy      = (Get-Param $Params 'managedBy' '').Trim()
  $clearManagedBy = if ($Params.PSObject.Properties.Name -contains 'clearManagedBy') { [bool]$Params.clearManagedBy } else { $false }

  if ($targets.Count -eq 0) { throw 'No target group(s) specified.' }
  if (-not $newDescription -and -not $managedBy -and -not $clearManagedBy) {
    throw 'At least one change must be specified (description, managedBy, or clearManagedBy).'
  }

  Write-XYProgress 0.10 "Resolving $($targets.Count) group(s)..."
  $resolved = Resolve-ADGroups -Identities $targets

  Write-XYProgress 0.40 'Updating groups...'

  $displayHeaders = @('#', 'Name', 'Status', 'Changes')
  $tableRows = @()
  $successCount = 0; $failCount = 0
  $idx = 0

  foreach ($r in $resolved) {
    $idx++
    if (-not $r.Success) {
      $failCount++
      $tableRows += ,@($idx, $r.Identity, 'FAILED', "Not found: $($r.Error)")
      continue
    }

    $group = $r.Group
    $changes = @()

    try {
      $setParams = @{}
      $clearAttrs = @()

      if ($newDescription) {
        $setParams.Description = $newDescription
        $changes += "Description='$newDescription'"
      }
      if ($managedBy) {
        $setParams.ManagedBy = $managedBy
        $changes += "ManagedBy='$managedBy'"
      }
      if ($clearManagedBy -and $group.ManagedBy) {
        $clearAttrs += 'ManagedBy'
        $changes += 'ManagedBy=cleared'
      }

      if ($setParams.Count -gt 0) {
        Set-ADGroup -Identity $group.DistinguishedName @setParams -ErrorAction Stop
      }
      if ($clearAttrs.Count -gt 0) {
        Set-ADGroup -Identity $group.DistinguishedName -Clear $clearAttrs -ErrorAction Stop
      }

      $successCount++
      $tableRows += ,@($idx, $group.Name, 'UPDATED', ($changes -join ' | '))
    } catch {
      $failCount++
      $tableRows += ,@($idx, $group.Name, 'FAILED', $_.Exception.Message)
    }
  }

  Write-XY @{ table = @{
    title   = 'Set Group Description'
    header  = $displayHeaders
    rows    = $tableRows
    caption = "$successCount updated, $failCount failed"
  } }

  return [PSCustomObject]@{
    tool = 'Set Group Description'; success = ($failCount -eq 0)
    totalTargets = $targets.Count; successCount = $successCount; failCount = $failCount
    generatedFiles = @()
  }
}

#endregion

#region Main Entry Point

try {
  $job = Read-JobFromStdin
  $Params = $job.params
  $tool = if ($Params.PSObject.Properties.Name -contains 'tool') { $Params.tool } else { 'createGroup' }
  $Cwd = if ($job.PSObject.Properties.Name -contains 'cwd') { $job.cwd } else { $null }
  if ($Cwd -and (Test-Path $Cwd -PathType Container)) { Set-Location $Cwd }

  Write-XYProgress 0.02 'Starting AD Groups...'

  # Check AD module
  Assert-ActiveDirectoryModule

  $result = $null
  switch ($tool) {
    # Group Lifecycle
    'createGroup'       { $result = Invoke-CreateGroup -Params $Params }
    'deleteGroup'       { $result = Invoke-DeleteGroup -Params $Params }
    'renameGroup'       { $result = Invoke-RenameGroup -Params $Params }
    'copyGroup'         { $result = Invoke-CopyGroup -Params $Params }

    # Membership
    'addMembers'        { $result = Invoke-AddMembers -Params $Params }
    'removeMembers'     { $result = Invoke-RemoveMembers -Params $Params }
    'listMembers'       { $result = Invoke-ListMembers -Params $Params }

    # Organisation
    'moveGroup'         { $result = Invoke-MoveGroup -Params $Params }
    'setGroupScope'     { $result = Invoke-SetGroupScope -Params $Params }
    'setGroupCategory'  { $result = Invoke-SetGroupCategory -Params $Params }
    'setGroupDescription' { $result = Invoke-SetGroupDescription -Params $Params }

    default             { throw "Unknown tool: $tool" }
  }

  # Ensure generatedFiles is an array
  $filesArray = @()
  if ($result.PSObject.Properties['generatedFiles'] -and $result.generatedFiles) {
    $filesArray = @($result.generatedFiles)
  }

  $desc = if ($result.PSObject.Properties['totalTargets']) {
    "$($result.tool): $($result.successCount)/$($result.totalTargets) succeeded"
  } elseif ($result.PSObject.Properties['totalOperations']) {
    "$($result.tool): $($result.successCount)/$($result.totalOperations) succeeded"
  } elseif ($result.PSObject.Properties['memberCount']) {
    "$($result.tool): $($result.memberCount) members found"
  } else {
    "$($result.tool) completed successfully"
  }

  # Check if result indicates a warning (e.g. partial member failures)
  $isWarning = $result.PSObject.Properties['warning'] -and $result.warning

  if ($isWarning) {
    Write-XYWarning -Data $result -Files $filesArray -Description $desc
  } else {
    Write-XYSuccess -Data $result -Files $filesArray -Description $desc
  }
  exit 0
}
catch {
  Write-XYError -Code 1 -Description $_.Exception.Message
  exit 1
}

#endregion
