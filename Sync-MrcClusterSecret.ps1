<#
.SYNOPSIS
    Copy the Milestone XProtect IDP client secrets from one clustered node to its sibling node, so the
    passive node can start its Milestone services after a failover. Works for both a clustered Management
    Server and a clustered Event Server. Runs ON the node (Windows PowerShell 5.1, as local administrator).

.DESCRIPTION
    Why this is needed. Every time Milestone's Server Configurator runs its "register" or encryption step
    on ONE cluster node, it replaces that component's IDP client secret in the shared Surveillance_IDP
    database and stores a copy of the new secret ONLY on that node (an "idp.sec" file under
    C:\ProgramData\Milestone\<component>\, protected for the NETWORK SERVICE account). The other node still
    holds the OLD secret, so after a failover it cannot authenticate to the IDP:
      - the Management Server fails to start with 'Idp returned 400 with the error: invalid_client';
      - the Event Server's calls fail 401, e.g. 'Can't get EventTypes from MS because of Exception:
        Unauthorized'.
    This tool decrypts the current secrets on the node that registered last and re-encrypts them on the
    other node, so both nodes hold the same, current secret and the role can run on either.

    How it works. The decrypt and the re-encrypt are done by Milestone's own crypto library
    (VideoOS.Common.Crypto.FileSecretProvider), run as the NETWORK SERVICE account through a one-shot
    scheduled task, because the secret files are DPAPI-protected for that account. The plaintext secrets
    never touch the console and are never written to disk in the clear: the only on-disk scratch is an
    ACL-restricted folder (Administrators, SYSTEM, NETWORK SERVICE only) that is deleted before the tool
    returns. The export file that carries the secrets between nodes is encrypted with a passphrase the
    operator types (AES-256-CBC + HMAC-SHA256, keys from PBKDF2-SHA256).

    Which components. The tool handles the clustered IDP components that have an idp.sec on the node:
    Management Server, its IIS Management Server app, API Gateway, Data Collector Server, and the Event
    Server. It only touches the folders you pass with -ComponentFolders (the default list above), and only
    those that actually exist on the node, so it never disturbs non-clustered components.

.PARAMETER Export
    On the node that registered LAST (usually the active node): read every component's secret and write
    them into one passphrase-encrypted export file (-Path). You are asked for the passphrase twice.

.PARAMETER Import
    On the OTHER node (usually the passive node): read the export file (-Path), ask for the passphrase,
    verify it, and re-encrypt each secret into that component's idp.sec. The old idp.sec is kept as
    idp.sec.bak-<yyyyMMdd-HHmmss>. Each write is verified by a read-back. If this node currently owns the
    cluster role of a component, the import is refused unless you also pass -Force.

.PARAMETER Check
    Read-only, no passphrase. Compare the secret on this node with the export file (-Path) per component
    and print SAME / DIFFERENT / MISSING. Use it before and after an import.

.PARAMETER Undo
    Restore the newest idp.sec.bak-<stamp> for each component on this node (reverses the last import).

.PARAMETER Path
    The export file. Required for -Export, -Import and -Check. Not used by -Undo.

.PARAMETER Force
    Allow -Import on a node that currently owns the component's cluster role (not the normal case).

.PARAMETER ComponentFolders
    The component folders to handle, relative to C:\ProgramData\Milestone. Defaults to the clustered IDP
    components. Only those that have an idp.sec on the node are handled.

.EXAMPLE
    # On the node that ran Server Configurator last (e.g. the active node):
    powershell -ExecutionPolicy Bypass -File .\Sync-MrcClusterSecret.ps1 -Export -Path C:\Temp\idp-secrets.dat

.EXAMPLE
    # Copy the file to the other node, then on that node:
    powershell -ExecutionPolicy Bypass -File .\Sync-MrcClusterSecret.ps1 -Check  -Path C:\Temp\idp-secrets.dat
    powershell -ExecutionPolicy Bypass -File .\Sync-MrcClusterSecret.ps1 -Import -Path C:\Temp\idp-secrets.dat
    powershell -ExecutionPolicy Bypass -File .\Sync-MrcClusterSecret.ps1 -Check  -Path C:\Temp\idp-secrets.dat

.EXAMPLE
    # If an import made things worse, roll it back on the node you imported to:
    powershell -ExecutionPolicy Bypass -File .\Sync-MrcClusterSecret.ps1 -Undo

.NOTES
    RISKS AND LIMITS
    - This uses an undocumented internal of the Milestone crypto library. A Milestone update could change
      it; test on one node pair before relying on it. The tool never changes the database, never runs
      Server Configurator and never restarts a Milestone service.
    - It works only while the Milestone services run as NETWORK SERVICE (the installer default). A domain
      service account is not handled.
    - Every import keeps the previous idp.sec as idp.sec.bak-<stamp>; -Undo restores the newest one.
    - DELETE THE EXPORT FILE after a successful import. It contains the live secrets (passphrase-encrypted)
      and must not be left on disk or shared.
    - After a later Server Configurator "register" or encryption run on either node, the nodes differ
      again: run -Export / -Import once more.
    - Requires .NET Framework 4.7.2 or later (for PBKDF2-SHA256), present on Milestone 2025 servers.
#>
[CmdletBinding(DefaultParameterSetName = 'Export')]
param(
    [Parameter(ParameterSetName = 'Export', Mandatory)][switch]$Export,
    [Parameter(ParameterSetName = 'Import', Mandatory)][switch]$Import,
    [Parameter(ParameterSetName = 'Check',  Mandatory)][switch]$Check,
    [Parameter(ParameterSetName = 'Undo',   Mandatory)][switch]$Undo,
    [Parameter(ParameterSetName = 'Export', Mandatory)]
    [Parameter(ParameterSetName = 'Import', Mandatory)]
    [Parameter(ParameterSetName = 'Check',  Mandatory)]
    [string]$Path,
    [Parameter(ParameterSetName = 'Import')][switch]$Force,
    [string[]]$ComponentFolders = @(
        'XProtect Management Server',
        'XProtect Management Server\IIS\ManagementServer',
        'XProtect API Gateway',
        'XProtect Data Collector Server',
        'XProtect Event Server\security')
)
$ErrorActionPreference = 'Stop'
# A PSModulePath inherited from PowerShell 7 hides Windows PowerShell's own modules; reset to the machine
# value when running under Windows PowerShell 5.1 so the built-in modules autoload.
if ($PSVersionTable.PSVersion.Major -lt 6) { $env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine') }

# ---------------------------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------------------------
function Write-Status { param([string]$Text, [string]$Level = 'Info')
    $c = switch ($Level) { 'Good' { 'Green' } 'Warn' { 'Yellow' } 'Err' { 'Red' } default { 'Gray' } }
    Write-Host $Text -ForegroundColor $c
}
function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This tool must be run as a local administrator (open Windows PowerShell with "Run as administrator").'
    }
}
# The Milestone crypto DLL on this node (any component's copy is the same type).
function Get-CryptoDll {
    $cands = @(
        (Join-Path $env:ProgramFiles 'Milestone\XProtect Management Server\VideoOS.Common.Crypto.dll'),
        (Join-Path $env:ProgramFiles 'Milestone\XProtect Event Server\VideoOS.Common.Crypto.dll'),
        (Join-Path $env:ProgramFiles 'Milestone\XProtect Data Collector Server\VideoOS.Common.Crypto.dll'),
        (Join-Path $env:ProgramFiles 'Milestone\XProtect API Gateway\VideoOS.Common.Crypto.dll'))
    foreach ($c in $cands) { if (Test-Path -LiteralPath $c -PathType Leaf) { return $c } }
    $root = Join-Path $env:ProgramFiles 'Milestone'
    if (Test-Path -LiteralPath $root) {
        $hit = Get-ChildItem -LiteralPath $root -Recurse -Filter 'VideoOS.Common.Crypto.dll' -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    throw 'VideoOS.Common.Crypto.dll was not found under Program Files\Milestone - is this a Milestone server?'
}
# The clustered component folders that have an idp.sec on this node.
function Get-Components {
    $pd = Join-Path $env:ProgramData 'Milestone'
    $out = @()
    foreach ($rel in $ComponentFolders) {
        $abs = Join-Path $pd $rel
        if (Test-Path -LiteralPath (Join-Path $abs 'idp.sec') -PathType Leaf) {
            $out += [pscustomobject]@{ Key = $rel; Path = $abs }
        }
    }
    , $out
}
# Milestone service names, so the cluster check can tell whether this node is the active one.
function Get-MilestoneServiceNames {
    @('Milestone XProtect Management Server', 'Milestone XProtect Data Collector Server',
      'Milestone XProtect Log Server', 'MilestoneEventServerService', 'Milestone XProtect Event Server')
}
# True if this node currently owns (Online) a Milestone cluster role. Best-effort: on no cluster, returns $null.
function Test-ActiveHere {
    try { Import-Module FailoverClusters -ErrorAction Stop } catch { return $null }
    try {
        $svcNames = Get-MilestoneServiceNames
        $res = @(Get-ClusterResource -ErrorAction Stop | Where-Object { $_.ResourceType -eq 'Generic Service' })
        foreach ($r in $res) {
            $sn = [string]($r | Get-ClusterParameter -Name ServiceName -ErrorAction SilentlyContinue).Value
            $isMs = $false
            foreach ($n in $svcNames) { if ($sn -ieq $n -or ([string]$r.Name) -ieq $n) { $isMs = $true; break } }
            if ($isMs -and [string]$r.State -eq 'Online' -and [string]$r.OwnerNode -ieq $env:COMPUTERNAME) { return $true }
        }
        return $false
    } catch { return $null }
}

# ---------------------------------------------------------------------------------------------------------
# NETWORK SERVICE one-shot task: read / hash / write / restore the idp.sec files
# ---------------------------------------------------------------------------------------------------------
$script:NsRead = @'
$ErrorActionPreference = 'Continue'
$w = '@@WORK@@'; $lg = Join-Path $w 'log.txt'
try { $a = [Reflection.Assembly]::LoadFrom('@@DLL@@') } catch { ('assembly load failed: ' + $_.Exception.Message) | Add-Content -LiteralPath $lg; exit 1 }
('running as ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name) | Add-Content -LiteralPath $lg
$t = $a.GetType('VideoOS.Common.Crypto.FileSecretProvider')
if (-not $t) { 'FileSecretProvider type not found' | Add-Content -LiteralPath $lg; exit 1 }
$sha = [System.Security.Cryptography.SHA256]::Create()
$i = 0
foreach ($f in @(Get-Content -LiteralPath (Join-Path $w 'folders.txt'))) {
  $i++; $plain = $null; $how = ''
  try { $p = [Activator]::CreateInstance($t, [object[]]@([string]$f, 'idp.tmp', 'idp.sec')) } catch { $m = $_.Exception.Message; if ($_.Exception.InnerException) { $m += ' / ' + $_.Exception.InnerException.Message }; ('s' + $i + ' ctor failed: ' + $m) | Add-Content -LiteralPath $lg; continue }
  try { $enc = $p.ReadSecret() } catch { $m = $_.Exception.Message; if ($_.Exception.InnerException) { $m += ' / ' + $_.Exception.InnerException.Message }; ('s' + $i + ' read failed: ' + $m) | Add-Content -LiteralPath $lg; continue }
  foreach ($scope in 'CurrentUser', 'LocalMachine') { try { $plain = $p.DecryptSecret($enc, [Security.Cryptography.DataProtectionScope]::$scope); $how = $scope; break } catch {} }
  if ($plain) {
    [IO.File]::WriteAllText((Join-Path $w ('s' + $i + '.b64')), [Convert]::ToBase64String($plain))
    [IO.File]::WriteAllText((Join-Path $w ('s' + $i + '.sha')), ([BitConverter]::ToString($sha.ComputeHash($plain)) -replace '-', '').ToLowerInvariant())
    ('s' + $i + ' ok scope=' + $how) | Add-Content -LiteralPath $lg
    [Array]::Clear($plain, 0, $plain.Length)
  } else { ('s' + $i + ' FAILED to decrypt') | Add-Content -LiteralPath $lg }
}
'@
$script:NsHash = @'
$ErrorActionPreference = 'Continue'
$w = '@@WORK@@'; $lg = Join-Path $w 'log.txt'
try { $a = [Reflection.Assembly]::LoadFrom('@@DLL@@') } catch { ('assembly load failed: ' + $_.Exception.Message) | Add-Content -LiteralPath $lg; exit 1 }
('running as ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name) | Add-Content -LiteralPath $lg
$t = $a.GetType('VideoOS.Common.Crypto.FileSecretProvider')
if (-not $t) { 'FileSecretProvider type not found' | Add-Content -LiteralPath $lg; exit 1 }
$sha = [System.Security.Cryptography.SHA256]::Create()
$i = 0
foreach ($f in @(Get-Content -LiteralPath (Join-Path $w 'folders.txt'))) {
  $i++; $plain = $null; $how = ''
  try { $p = [Activator]::CreateInstance($t, [object[]]@([string]$f, 'idp.tmp', 'idp.sec')) } catch { $m = $_.Exception.Message; if ($_.Exception.InnerException) { $m += ' / ' + $_.Exception.InnerException.Message }; ('s' + $i + ' ctor failed: ' + $m) | Add-Content -LiteralPath $lg; continue }
  try { $enc = $p.ReadSecret() } catch { $m = $_.Exception.Message; if ($_.Exception.InnerException) { $m += ' / ' + $_.Exception.InnerException.Message }; ('s' + $i + ' read failed: ' + $m) | Add-Content -LiteralPath $lg; continue }
  foreach ($scope in 'CurrentUser', 'LocalMachine') { try { $plain = $p.DecryptSecret($enc, [Security.Cryptography.DataProtectionScope]::$scope); $how = $scope; break } catch {} }
  if ($plain) {
    [IO.File]::WriteAllText((Join-Path $w ('s' + $i + '.sha')), ([BitConverter]::ToString($sha.ComputeHash($plain)) -replace '-', '').ToLowerInvariant())
    ('s' + $i + ' ok scope=' + $how) | Add-Content -LiteralPath $lg
    [Array]::Clear($plain, 0, $plain.Length)
  } else { ('s' + $i + ' FAILED to decrypt') | Add-Content -LiteralPath $lg }
}
'@
$script:NsWrite = @'
$ErrorActionPreference = 'Continue'
$w = '@@WORK@@'; $lg = Join-Path $w 'log.txt'
try { $a = [Reflection.Assembly]::LoadFrom('@@DLL@@') } catch { ('assembly load failed: ' + $_.Exception.Message) | Add-Content -LiteralPath $lg; exit 1 }
('running as ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name) | Add-Content -LiteralPath $lg
$t = $a.GetType('VideoOS.Common.Crypto.FileSecretProvider')
if (-not $t) { 'FileSecretProvider type not found' | Add-Content -LiteralPath $lg; exit 1 }
$i = 0
foreach ($f in @(Get-Content -LiteralPath (Join-Path $w 'folders.txt'))) {
  $i++; $src = Join-Path $w ('s' + $i + '.b64')
  if (-not (Test-Path -LiteralPath $src)) { ('w' + $i + ' skipped (no data for this component)') | Add-Content -LiteralPath $lg; continue }
  if (-not (Test-Path -LiteralPath ([string]$f) -PathType Container)) { ('w' + $i + ' skipped (component not installed on this node)') | Add-Content -LiteralPath $lg; try { [IO.File]::Delete($src) } catch {}; continue }
  try {
    $p = [Activator]::CreateInstance($t, [object[]]@([string]$f, 'idp.tmp', 'idp.sec'))
    $plain = [Convert]::FromBase64String(([IO.File]::ReadAllText($src)).Trim())
    $enc = $p.EncryptSecret($plain, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $perm = Join-Path ([string]$f) 'idp.sec'
    if (Test-Path -LiteralPath $perm) { Copy-Item -LiteralPath $perm -Destination ($perm + '.bak-@@STAMP@@') -Force }
    $p.WriteSecret($enc)
    $chk = $p.DecryptSecret($p.ReadSecret(), [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $same = ($chk.Length -eq $plain.Length); if ($same) { for ($k = 0; $k -lt $plain.Length; $k++) { if ($chk[$k] -ne $plain[$k]) { $same = $false; break } } }
    if ($same) { ('w' + $i + ' OK written and read back') | Add-Content -LiteralPath $lg } else { ('w' + $i + ' FAILED read-back differs') | Add-Content -LiteralPath $lg }
    [Array]::Clear($plain, 0, $plain.Length)
  } catch { $m = $_.Exception.Message; if ($_.Exception.InnerException) { $m += ' / ' + $_.Exception.InnerException.Message }; ('w' + $i + ' FAILED: ' + $m) | Add-Content -LiteralPath $lg }
  try { [IO.File]::Delete($src) } catch {}
}
'@
$script:NsRestore = @'
$ErrorActionPreference = 'Continue'
$w = '@@WORK@@'; $lg = Join-Path $w 'log.txt'
try { $a = [Reflection.Assembly]::LoadFrom('@@DLL@@') } catch { ('assembly load failed: ' + $_.Exception.Message) | Add-Content -LiteralPath $lg; exit 1 }
('running as ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name) | Add-Content -LiteralPath $lg
$t = $a.GetType('VideoOS.Common.Crypto.FileSecretProvider')
if (-not $t) { 'FileSecretProvider type not found' | Add-Content -LiteralPath $lg; exit 1 }
$i = 0
foreach ($f in @(Get-Content -LiteralPath (Join-Path $w 'folders.txt'))) {
  $i++
  if (-not (Test-Path -LiteralPath ([string]$f) -PathType Container)) { ('u' + $i + ' skipped (component not installed on this node)') | Add-Content -LiteralPath $lg; continue }
  $perm = Join-Path ([string]$f) 'idp.sec'
  $baks = @(Get-ChildItem -LiteralPath ([string]$f) -Filter 'idp.sec.bak-*' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
  if (-not $baks.Count) { ('u' + $i + ' no backup found') | Add-Content -LiteralPath $lg; continue }
  $nb = $baks[0]
  try {
    Copy-Item -LiteralPath $nb.FullName -Destination $perm -Force
    $p = [Activator]::CreateInstance($t, [object[]]@([string]$f, 'idp.tmp', 'idp.sec'))
    $null = $p.DecryptSecret($p.ReadSecret(), [Security.Cryptography.DataProtectionScope]::CurrentUser)
    ('u' + $i + ' restored from ' + $nb.Name) | Add-Content -LiteralPath $lg
  } catch { $m = $_.Exception.Message; if ($_.Exception.InnerException) { $m += ' / ' + $_.Exception.InnerException.Message }; ('u' + $i + ' FAILED (restored file, read-back error): ' + $m) | Add-Content -LiteralPath $lg }
}
'@
# Run one of the inner scripts above as NETWORK SERVICE. $Folders is an ordered list of absolute component
# folders; $InputB64 (parallel, for -Import) is the plaintext base64 to write. Returns Log + per-index
# Out objects ({ B64; Sha }). The scratch folder is ACL-restricted and deleted before returning.
function Invoke-NsOperation {
    param([ValidateSet('read', 'hash', 'write', 'restore')][string]$Mode, [string[]]$Folders, [string[]]$InputB64, [string]$Dll)
    $tmpl = switch ($Mode) { 'read' { $script:NsRead } 'hash' { $script:NsHash } 'write' { $script:NsWrite } 'restore' { $script:NsRestore } }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $work = $null; $tn = $null
    $result = [pscustomobject]@{ Log = @(); Out = @() }
    try {
        $work = Join-Path (Join-Path $env:windir 'Temp') ('MRC-sec-' + [guid]::NewGuid().ToString('N'))
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-20')) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        [void][IO.Directory]::CreateDirectory($work, $acl)
        [IO.File]::WriteAllLines((Join-Path $work 'folders.txt'), [string[]]$Folders)
        if ($Mode -eq 'write') {
            for ($i = 0; $i -lt $Folders.Count; $i++) {
                if ($i -lt $InputB64.Count -and $InputB64[$i]) { [IO.File]::WriteAllText((Join-Path $work ('s' + ($i + 1) + '.b64')), [string]$InputB64[$i]) }
            }
        }
        $inner = $tmpl.Replace('@@WORK@@', $work.Replace("'", "''")).Replace('@@DLL@@', $Dll.Replace("'", "''")).Replace('@@STAMP@@', $stamp)
        $scriptPath = Join-Path $work 'op.ps1'
        [IO.File]::WriteAllText($scriptPath, $inner)
        $tn = 'MRC-SecSync-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        [void](Register-ScheduledTask -TaskName $tn -Principal (New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\NETWORK SERVICE' -LogonType ServiceAccount) -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '"')))
        Start-ScheduledTask -TaskName $tn
        $t0 = Get-Date
        do {
            Start-Sleep -Seconds 2
            $st = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
            $notYet = $false
            if ($st -and [string]$st.State -ne 'Running') { $notYet = ([int](Get-ScheduledTaskInfo -TaskName $tn -ErrorAction SilentlyContinue).LastTaskResult -eq 267011) }
        } while ($st -and ([string]$st.State -eq 'Running' -or $notYet) -and ((Get-Date) - $t0).TotalSeconds -lt 120)
        $lgFile = Join-Path $work 'log.txt'
        if (Test-Path -LiteralPath $lgFile) { $result.Log = @(Get-Content -LiteralPath $lgFile) }
        $out = @()
        for ($i = 1; $i -le $Folders.Count; $i++) {
            $b64 = $null; $sha = $null
            $bf = Join-Path $work ('s' + $i + '.b64'); $sf = Join-Path $work ('s' + $i + '.sha')
            if (Test-Path -LiteralPath $bf -PathType Leaf) { $b64 = ([IO.File]::ReadAllText($bf)).Trim() }
            if (Test-Path -LiteralPath $sf -PathType Leaf) { $sha = ([IO.File]::ReadAllText($sf)).Trim() }
            $out += [pscustomobject]@{ B64 = $b64; Sha = $sha }
        }
        $result.Out = @($out)
    } finally {
        if ($tn) {
            try { $tk = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue; if ($tk -and [string]$tk.State -eq 'Running') { Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue } } catch {}
            Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
        }
        if ($work -and (Test-Path -LiteralPath $work)) {
            try {
                $wIt = Get-Item -LiteralPath $work -Force -ErrorAction Stop
                if (-not ($wIt.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                    foreach ($wk in @(Get-ChildItem -LiteralPath $work -Force -ErrorAction Stop)) { if (-not $wk.PSIsContainer -and -not ($wk.Attributes -band [IO.FileAttributes]::ReparsePoint)) { [IO.File]::Delete($wk.FullName) } }
                    [IO.Directory]::Delete($work, $false)
                }
            } catch {}
        }
    }
    $result
}

# ---------------------------------------------------------------------------------------------------------
# Passphrase + export-file crypto (AES-256-CBC + HMAC-SHA256, keys from PBKDF2-SHA256)
# ---------------------------------------------------------------------------------------------------------
function ConvertFrom-SecureStringToBytes { param([Security.SecureString]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
    try { $uni = [Runtime.InteropServices.Marshal]::PtrToStringUni($bstr); return [Text.Encoding]::UTF8.GetBytes($uni) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($bstr) }
}
function Read-Passphrase { param([switch]$Confirm)
    while ($true) {
        $a = Read-Host -AsSecureString 'Passphrase'
        if ($a.Length -lt 8) { Write-Status 'The passphrase must be at least 8 characters.' 'Warn'; continue }
        if (-not $Confirm) { return $a }
        $b = Read-Host -AsSecureString 'Passphrase (again)'
        $pa = $null; $pb = $null
        $ba = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($a)
        $bb = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($b)
        try { $pa = [Runtime.InteropServices.Marshal]::PtrToStringUni($ba); $pb = [Runtime.InteropServices.Marshal]::PtrToStringUni($bb) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ba); [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($bb) }
        if ($pa -ceq $pb) { return $a }
        Write-Status 'The two entries did not match - try again.' 'Warn'
    }
}
function Get-DerivedKeys { param([byte[]]$PassBytes, [byte[]]$Salt, [int]$Iterations)
    $deriver = $null
    try { $deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($PassBytes, $Salt, $Iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256) }
    catch { throw 'PBKDF2-SHA256 is not available. Install .NET Framework 4.7.2 or later on this node.' }
    try { return $deriver.GetBytes(64) } finally { $deriver.Dispose() }
}
function Get-MetaString { param($Version, [string]$SourceComputer, [int]$Iterations, $Components)
    $sb = 'V=' + $Version + '|SC=' + $SourceComputer + '|IT=' + $Iterations
    foreach ($c in $Components) { $sb += '|C=' + $c.Key + ':' + $c.Sha256 }
    $sb
}
function Protect-Export { param([Security.SecureString]$Pass, $Components, [hashtable]$Secrets, [string]$OutPath)
    # $Components: list of { Key; Sha256 } in order. $Secrets: Key -> base64 plaintext.
    $iters = 200000
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $salt = New-Object byte[] 16; $rng.GetBytes($salt)
    $iv = New-Object byte[] 16; $rng.GetBytes($iv)
    $passBytes = ConvertFrom-SecureStringToBytes $Pass
    $keyMat = Get-DerivedKeys $passBytes $salt $iters
    [Array]::Clear($passBytes, 0, $passBytes.Length)
    $aesKey = $keyMat[0..31]; $macKey = $keyMat[32..63]
    # Plaintext payload: a JSON array of { Key; B64 } in component order.
    $items = @(); foreach ($c in $Components) { $items += [pscustomobject]@{ Key = $c.Key; B64 = [string]$Secrets[$c.Key] } }
    $payload = [pscustomobject]@{ Secrets = @($items) } | ConvertTo-Json -Depth 5 -Compress
    $pt = [Text.Encoding]::UTF8.GetBytes($payload)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256; $aes.BlockSize = 128; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $aesKey; $aes.IV = $iv
    $enc = $aes.CreateEncryptor(); $ct = $enc.TransformFinalBlock($pt, 0, $pt.Length)
    [Array]::Clear($pt, 0, $pt.Length)
    $meta = Get-MetaString 1 $env:COMPUTERNAME $iters $Components
    $metaBytes = [Text.Encoding]::UTF8.GetBytes($meta)
    $macInput = New-Object byte[] ($salt.Length + $iv.Length + $ct.Length + $metaBytes.Length)
    [Array]::Copy($salt, 0, $macInput, 0, $salt.Length)
    [Array]::Copy($iv, 0, $macInput, $salt.Length, $iv.Length)
    [Array]::Copy($ct, 0, $macInput, $salt.Length + $iv.Length, $ct.Length)
    [Array]::Copy($metaBytes, 0, $macInput, $salt.Length + $iv.Length + $ct.Length, $metaBytes.Length)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $macKey)
    $mac = $hmac.ComputeHash($macInput)
    [Array]::Clear($keyMat, 0, $keyMat.Length); [Array]::Clear($aesKey, 0, $aesKey.Length); [Array]::Clear($macKey, 0, $macKey.Length)
    $obj = [ordered]@{
        Format = 'MrcClusterSecret'; Version = 1; Created = ([DateTime]::UtcNow.ToString('o')); SourceComputer = $env:COMPUTERNAME
        Kdf = [ordered]@{ Algo = 'PBKDF2-SHA256'; Iterations = $iters; Salt = [Convert]::ToBase64String($salt) }
        Cipher = 'AES-256-CBC'; Iv = [Convert]::ToBase64String($iv)
        Components = @($Components | ForEach-Object { [ordered]@{ Key = $_.Key; Sha256 = $_.Sha256 } })
        Data = [Convert]::ToBase64String($ct); Mac = [Convert]::ToBase64String($mac)
    }
    [IO.File]::WriteAllText($OutPath, (([pscustomobject]$obj) | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
}
function Unprotect-Export { param([Security.SecureString]$Pass, $Doc)
    $salt = [Convert]::FromBase64String($Doc.Kdf.Salt)
    $iv = [Convert]::FromBase64String($Doc.Iv)
    $ct = [Convert]::FromBase64String($Doc.Data)
    $iters = [int]$Doc.Kdf.Iterations
    $passBytes = ConvertFrom-SecureStringToBytes $Pass
    $keyMat = Get-DerivedKeys $passBytes $salt $iters
    [Array]::Clear($passBytes, 0, $passBytes.Length)
    $aesKey = $keyMat[0..31]; $macKey = $keyMat[32..63]
    $comps = @($Doc.Components | ForEach-Object { [pscustomobject]@{ Key = [string]$_.Key; Sha256 = [string]$_.Sha256 } })
    $meta = Get-MetaString $Doc.Version $Doc.SourceComputer $iters $comps
    $metaBytes = [Text.Encoding]::UTF8.GetBytes($meta)
    $macInput = New-Object byte[] ($salt.Length + $iv.Length + $ct.Length + $metaBytes.Length)
    [Array]::Copy($salt, 0, $macInput, 0, $salt.Length)
    [Array]::Copy($iv, 0, $macInput, $salt.Length, $iv.Length)
    [Array]::Copy($ct, 0, $macInput, $salt.Length + $iv.Length, $ct.Length)
    [Array]::Copy($metaBytes, 0, $macInput, $salt.Length + $iv.Length + $ct.Length, $metaBytes.Length)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $macKey)
    $calc = $hmac.ComputeHash($macInput)
    $given = [Convert]::FromBase64String($Doc.Mac)
    $diff = $calc.Length -bxor $given.Length
    for ($k = 0; $k -lt [Math]::Min($calc.Length, $given.Length); $k++) { $diff = $diff -bor ($calc[$k] -bxor $given[$k]) }
    if ($diff -ne 0) { [Array]::Clear($keyMat, 0, $keyMat.Length); throw 'The passphrase is wrong, or the export file has been changed. Nothing was written.' }
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256; $aes.BlockSize = 128; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $aesKey; $aes.IV = $iv
    $dec = $aes.CreateDecryptor(); $pt = $dec.TransformFinalBlock($ct, 0, $ct.Length)
    [Array]::Clear($keyMat, 0, $keyMat.Length); [Array]::Clear($aesKey, 0, $aesKey.Length); [Array]::Clear($macKey, 0, $macKey.Length)
    $payload = [Text.Encoding]::UTF8.GetString($pt) | ConvertFrom-Json
    [Array]::Clear($pt, 0, $pt.Length)
    $map = @{}; foreach ($s in @($payload.Secrets)) { $map[[string]$s.Key] = [string]$s.B64 }
    [pscustomobject]@{ Components = $comps; Secrets = $map }
}
function Read-ExportDoc { param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { throw "Export file not found: $FilePath" }
    $doc = $null
    try { $doc = Get-Content -LiteralPath $FilePath -Raw | ConvertFrom-Json } catch { throw "The export file is not valid: $($_.Exception.Message)" }
    if ([string]$doc.Format -ne 'MrcClusterSecret') { throw 'The export file is not an MrcClusterSecret export.' }
    $doc
}

# ---------------------------------------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------------------------------------
function Invoke-Export {
    $dll = Get-CryptoDll
    $comps = Get-Components
    if (-not $comps.Count) { throw 'No clustered Milestone component with an idp.sec was found on this node.' }
    Write-Status ("Components found on {0}: {1}" -f $env:COMPUTERNAME, (($comps | ForEach-Object { $_.Key }) -join ', '))
    Write-Status 'Reading the secrets as NETWORK SERVICE...'
    $r = Invoke-NsOperation -Mode 'read' -Folders @($comps | ForEach-Object { $_.Path }) -Dll $dll
    foreach ($l in $r.Log) { Write-Verbose $l }
    $components = @(); $secrets = @{}; $bad = @()
    for ($i = 0; $i -lt $comps.Count; $i++) {
        $o = $r.Out[$i]
        if ($o -and $o.B64 -and $o.Sha) { $components += [pscustomobject]@{ Key = $comps[$i].Key; Sha256 = $o.Sha }; $secrets[$comps[$i].Key] = $o.B64 }
        else { $bad += $comps[$i].Key }
    }
    if ($bad.Count) { throw ("These components could not be read, so no file was written: {0}. See -Verbose for details." -f ($bad -join ', ')) }
    $pass = Read-Passphrase -Confirm
    Protect-Export -Pass $pass -Components $components -Secrets $secrets -OutPath $Path
    foreach ($k in @($secrets.Keys)) { $secrets[$k] = $null }
    Write-Status ("Wrote {0} secret(s) to {1}" -f $components.Count, $Path) 'Good'
    Write-Status 'Next: copy this file to the OTHER node, run -Check then -Import there, and DELETE the file afterwards.' 'Good'
}
function Invoke-Import {
    $dll = Get-CryptoDll
    $doc = Read-ExportDoc $Path
    $active = Test-ActiveHere
    if ($active -eq $true -and -not $Force) {
        throw 'This node currently OWNS a Milestone cluster role (it is the active node). Importing here is unusual - re-run with -Force only if you are sure.'
    }
    if ($null -eq $active) { Write-Status 'Could not read the cluster state - continuing without the active-node check.' 'Warn' }
    elseif ($active -eq $true) { Write-Status 'WARNING: this node owns a Milestone cluster role; proceeding because -Force was given.' 'Warn' }
    $pass = Read-Passphrase
    $plain = Unprotect-Export -Pass $pass -Doc $doc
    Write-Status ("Export is from {0}, created {1} UTC." -f $doc.SourceComputer, $doc.Created)
    $pd = Join-Path $env:ProgramData 'Milestone'
    $folders = @(); $inputs = @()
    foreach ($c in $plain.Components) {
        $folders += (Join-Path $pd $c.Key)
        $inputs += [string]$plain.Secrets[$c.Key]
    }
    Write-Status 'Writing the secrets as NETWORK SERVICE (old files kept as idp.sec.bak-<stamp>)...'
    $r = Invoke-NsOperation -Mode 'write' -Folders $folders -InputB64 $inputs -Dll $dll
    foreach ($k in @($plain.Secrets.Keys)) { $plain.Secrets[$k] = $null }
    $ok = 0; $fail = 0; $skip = 0
    for ($i = 0; $i -lt $plain.Components.Count; $i++) {
        $key = $plain.Components[$i].Key
        $line = @($r.Log | Where-Object { $_ -match ('^w' + ($i + 1) + ' ') }) | Select-Object -First 1
        if ($line -match ' OK ') { Write-Status ("  {0}: OK" -f $key) 'Good'; $ok++ }
        elseif ($line -match ' skipped ') { Write-Status ("  {0}: skipped ({1})" -f $key, ($line -replace '^w\d+ skipped ', '')) 'Warn'; $skip++ }
        else { Write-Status ("  {0}: FAILED ({1})" -f $key, ($(if ($line) { $line -replace '^w\d+ ', '' } else { 'no result' }))) 'Err'; $fail++ }
    }
    Write-Status ("Import done: {0} OK, {1} skipped, {2} failed." -f $ok, $skip, $fail) $(if ($fail) { 'Err' } else { 'Good' })
    if ($ok -gt 0 -and $fail -eq 0) {
        Write-Status ''
        Write-Status 'Next steps on this node:' 'Good'
        Write-Status '  1. Run:  iisreset' 'Good'
        Write-Status '  2. The cluster role can now be moved to this node (failover will work).' 'Good'
        Write-Status '  3. DELETE the export file now.' 'Good'
        Write-Status 'Note: any later Server Configurator "register" or encryption run makes the nodes differ again - run Export/Import again after it.' 'Warn'
    }
    if ($fail) { exit 1 }
}
function Invoke-Check {
    $dll = Get-CryptoDll
    $doc = Read-ExportDoc $Path
    $pd = Join-Path $env:ProgramData 'Milestone'
    $expected = @{}; foreach ($c in $doc.Components) { $expected[[string]$c.Key] = [string]$c.Sha256 }
    $present = @(); $presentKeys = @()
    foreach ($c in $doc.Components) {
        $abs = Join-Path $pd $c.Key
        if (Test-Path -LiteralPath (Join-Path $abs 'idp.sec') -PathType Leaf) { $present += $abs; $presentKeys += [string]$c.Key }
    }
    $localSha = @{}
    if ($present.Count) {
        $r = Invoke-NsOperation -Mode 'hash' -Folders $present -Dll $dll
        for ($i = 0; $i -lt $presentKeys.Count; $i++) { if ($r.Out[$i] -and $r.Out[$i].Sha) { $localSha[$presentKeys[$i]] = $r.Out[$i].Sha } }
    }
    Write-Status ("Comparing this node ({0}) with the export from {1}:" -f $env:COMPUTERNAME, $doc.SourceComputer)
    $same = 0; $diff = 0; $miss = 0
    foreach ($c in $doc.Components) {
        $key = [string]$c.Key
        if (-not ($presentKeys -contains $key)) { Write-Status ("  {0}: MISSING (not installed on this node)" -f $key) 'Warn'; $miss++; continue }
        if (-not $localSha.ContainsKey($key)) { Write-Status ("  {0}: MISSING (could not read the local secret)" -f $key) 'Warn'; $miss++; continue }
        if ($localSha[$key] -eq $expected[$key]) { Write-Status ("  {0}: SAME" -f $key) 'Good'; $same++ }
        else { Write-Status ("  {0}: DIFFERENT" -f $key) 'Err'; $diff++ }
    }
    Write-Status ("Result: {0} same, {1} different, {2} missing." -f $same, $diff, $miss) $(if ($diff -or $miss) { 'Warn' } else { 'Good' })
}
function Invoke-Undo {
    $dll = Get-CryptoDll
    $comps = Get-Components
    if (-not $comps.Count) { throw 'No clustered Milestone component with an idp.sec was found on this node.' }
    Write-Status 'Restoring the newest idp.sec.bak-<stamp> per component as NETWORK SERVICE...'
    $r = Invoke-NsOperation -Mode 'restore' -Folders @($comps | ForEach-Object { $_.Path }) -Dll $dll
    for ($i = 0; $i -lt $comps.Count; $i++) {
        $key = $comps[$i].Key
        $line = @($r.Log | Where-Object { $_ -match ('^u' + ($i + 1) + ' ') }) | Select-Object -First 1
        if ($line -match ' restored from ') { Write-Status ("  {0}: {1}" -f $key, ($line -replace '^u\d+ ', '')) 'Good' }
        elseif ($line -match ' no backup ') { Write-Status ("  {0}: no backup to restore" -f $key) 'Warn' }
        else { Write-Status ("  {0}: {1}" -f $key, ($(if ($line) { $line -replace '^u\d+ ', '' } else { 'no result' }))) 'Err' }
    }
    Write-Status 'Run iisreset on this node if you restored the Management Server secrets.' 'Warn'
}

# ---------------------------------------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------------------------------------
try {
    Assert-Administrator
    switch ($PSCmdlet.ParameterSetName) {
        'Export' { Invoke-Export }
        'Import' { Invoke-Import }
        'Check'  { Invoke-Check }
        'Undo'   { Invoke-Undo }
    }
} catch {
    Write-Status ("ERROR: " + $_.Exception.Message) 'Err'
    exit 2
}
