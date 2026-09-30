#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone XProtect Doctor - read-only health check of the whole system (one file, run on the
    Management Server).

.DESCRIPTION
    Checks every server (Management Server + cluster nodes, Event Server + cluster nodes, every
    recording server) against the same "how it should be wired" rules the guided wizard relies on -
    registration, encryption/certificates, cluster health, IIS, config files, environment - and writes
    a PASS/WARN/FAIL/INFO report with a plain "how to fix" line per finding.

    THIS TOOL NEVER CHANGES ANYTHING. No Set-/Start-/Stop-/Restart-/Remove-/New- (other than in-memory
    objects and the report files it writes locally)/Suspend-/Resume-/Move-/Register-/Unregister-/Enable-/
    Disable- command is used against any server, no registry or file is written on any remote computer,
    no cluster is changed, and WinRM TrustedHosts is never changed - a server reachable only by an IP
    address that is not yet trusted is reported as a FAIL (NET-1) with the exact fix command, instead of
    being trusted automatically the way the guided wizard would.

    WHERE TO RUN IT: on the Management Server itself, as Administrator - same refusal rules as
    Mrc-Guided.ps1 (exit 3 if this is not a Management Server, or not elevated).

    Connect page (same fields as the guided wizard's step 1): domain, Event Server host (or "no
    separate Event Server"), admin account, optional separate recording-server account, extra recording
    servers, search folders for ServerConfigurator.exe, open log. Recording servers are otherwise
    discovered from the VMS. Click "Run checks" to collect facts from every computer and render the
    report; nothing runs until that button is pressed.

    Architecture: Targets (same box/cluster model as the wizard) -> Collect (one read-only facts
    scriptblock per box kind, run once per box) -> Evaluate (pure Test-<Area><N> functions, no I/O,
    unit-tested offline by tools/Test-Doctor.ps1) -> Render (HTML + CSV + TXT) -> shown in a window, or
    written headless with -Run.
.NOTES
    Interactive (on the Management Server console):
        powershell -ExecutionPolicy Bypass -STA -File .\Mrc-Doctor.ps1

    Headless (no window):
        powershell -ExecutionPolicy Bypass -File .\Mrc-Doctor.ps1 -Run -Domain company.local `
            -EsHost <event-server-fqdn> -AdminUser '<DOMAIN>\Administrator' -AdminPwFile <path-to-pw-file> `
            [-RecTargets '<rec1-fqdn>,<REC2>=<rec2-ip>'] [-RecUser <user> -RecPwFile <path>] `
            [-SearchPaths 'D:\Milestone'] [-MsAddr <address>] [-ReportDir <folder>] [-LogFile <path>]
    -NoEventServer instead of -EsHost when there is no standalone Event Server. Without -RecTargets the
    recording servers are discovered from the VMS (needs MilestonePSTools). mrc.defaults.psd1 (same file
    as the other Mrc-*.ps1 tools) is honoured for Domain / MsUser / RecUser / MsFqdn / EsHost /
    SearchPaths / MsAddr when the matching parameter is left at its placeholder or empty.
    Exit codes: 0 = no FAIL (WARN allowed), 1 = at least one FAIL, 2 = error, 3 = refused (not a
    Management Server / not elevated / missing input).
#>
[CmdletBinding()]
param(
    [switch]$Run,                                       # headless: collect + render, no window
    [string]$Domain = '',                                # DNS domain suffix (default: this machine's primary DNS suffix)
    [string]$EsHost = '',                                # standalone Event Server host (FQDN, short name or IP)
    [switch]$NoEventServer,                              # there is no standalone Event Server
    [string]$AdminUser = '',                             # admin account (Management Server + Event Server + default for recorders)
    [string]$AdminPwFile,                                # file holding the admin password (headless only)
    [string]$RecTargets = '',                            # comma list of recorders ('host' or 'name=ip'); empty = discover from the VMS
    [string]$RecUser = '',                                # optional separate recording-server account
    [string]$RecPwFile,                                  # file holding the recording-server password (headless only)
    [string]$SearchPaths = '',                            # ';' list of folders (or exe paths) to search for ServerConfigurator.exe / MilestonePSTools
    [string]$MsAddr = '',                                 # VMS address for recorder discovery (default: this machine)
    [string]$ReportDir = '',                              # headless: where to write the report (default %TEMP%\MilestoneRecorderCertManager-runs)
    [string]$LogFile                                     # optional: tee the log here
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Deployment defaults (client-ready) ------------------------------------------------------
# NEUTRAL placeholders only. For repeat use in ONE known environment, drop a 'mrc.defaults.psd1' next
# to this script (the same file the other Mrc-*.ps1 tools read; keys not used here are ignored). That
# file is gitignored and must NEVER be shipped to a client - it is operator convenience only.
$script:Defaults = @{
    MsAddr      = '<management-server-address>'
    Domain      = '<domain-suffix>'
    MsUser      = '<DOMAIN>\Administrator'
    RecUser     = ''
    MsFqdn      = '<mgmt-fqdn>'
    EsHost      = '<event-server-host>'
    SearchPaths = ''
}
$script:DefaultsLoaded = @()
$script:DefaultsLoadError = $null
if ($PSScriptRoot) {
    $script:DefFile = Join-Path $PSScriptRoot 'mrc.defaults.psd1'
    if (Test-Path -LiteralPath $script:DefFile) {
        try { $ov = Import-PowerShellDataFile -LiteralPath $script:DefFile
              foreach ($k in @($ov.Keys)) { if ($script:Defaults.ContainsKey($k)) { $script:Defaults[$k] = $ov[$k] } }
              $script:DefaultsLoaded = @(@($ov.Keys) | Where-Object { $script:Defaults.ContainsKey($_) }) }
        catch { $script:DefaultsLoadError = $_.Exception.Message
                Write-Warning "mrc.defaults.psd1 found but FAILED to parse - using built-in placeholders. $($_.Exception.Message)" }
    }
}
function Resolve-Default { param([string]$Value,[string]$Key)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '<[^>]+>') { [string]$script:Defaults[$Key] } else { $Value } }
$AdminUser   = Resolve-Default $AdminUser   'MsUser'
$RecUser     = Resolve-Default $RecUser     'RecUser'
$Domain      = Resolve-Default $Domain      'Domain'
$EsHost      = Resolve-Default $EsHost      'EsHost'
$SearchPaths = Resolve-Default $SearchPaths 'SearchPaths'
$MsAddr      = Resolve-Default $MsAddr      'MsAddr'

$script:Headless    = [bool]$Run
$script:LogFilePath = $LogFile

function Stop-DoctorRefused { param([string]$Msg)
    if($script:Headless){
        Write-Host "REFUSED: $Msg"
        if($script:LogFilePath){ try { Add-Content -LiteralPath $script:LogFilePath -Value "REFUSED: $Msg" -Encoding UTF8 } catch {} }
        exit 3
    }
    [System.Windows.Forms.MessageBox]::Show($Msg,'Milestone Doctor',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    exit 3
}

# This tool must run ON the Management Server: facts for THIS computer are collected locally, in-process.
$script:MsServiceName = 'Milestone XProtect Management Server'
if(-not (Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $script:MsServiceName })){
    Stop-DoctorRefused ("This computer ($env:COMPUTERNAME) is not a Milestone Management Server - the service '$($script:MsServiceName)' was not found here.`r`n`r`n" +
                  "Copy this file to the Management Server and run it there, as Administrator.")
}

if (-not $script:Headless) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        try {
            $exe = (Get-Process -Id $PID).Path; if (-not $exe) { $exe = 'powershell.exe' }
            $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-File', ('"{0}"' -f $PSCommandPath))
            foreach ($kv in $PSBoundParameters.GetEnumerator()) {
                if ($kv.Value -is [switch]) { if ($kv.Value.IsPresent) { $argList += ('-{0}' -f $kv.Key) } }
                else { $argList += ('-{0}' -f $kv.Key); $argList += ('"{0}"' -f $kv.Value) }
            }
            Start-Process -FilePath $exe -Verb RunAs -ArgumentList $argList
        } catch {
            [System.Windows.Forms.MessageBox]::Show("This tool must run as Administrator.`r`nAccept the UAC prompt, or right-click PowerShell -> Run as administrator.`r`n`r`n$($_.Exception.Message)", 'Administrator required', 'OK', 'Warning') | Out-Null
        }
        return
    }
}
if ($script:Headless) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) { Stop-DoctorRefused 'This tool must run elevated (as Administrator).' }
}

$script:RunsDir = if($ReportDir -and -not ($ReportDir -match '<[^>]+>')){ $ReportDir } else { Join-Path ([IO.Path]::GetTempPath()) 'MilestoneRecorderCertManager-runs' }
$script:LastReportPath = ''
$script:LastReportHtml = ''

# ===================== HELPERS (verbatim from Mrc-Guided.ps1) =====================
# Every function/scriptblock in this section is copied text-for-text from Mrc-Guided.ps1 (see
# docs/doctor/spec.md "Reuse"). tools/Test-EngineParity.ps1's second pass fails the build if any of
# them drifts from Mrc-Guided.ps1's copy - a fix belongs in BOTH files, never here alone.
# The one deliberate exception is Ensure-TrustedHosts: Mrc-Guided.ps1's version calls
# Set-Item WSMan:\localhost\Client\TrustedHosts (a real change) and is NOT copied - see the read-only
# replacement further down, right after this section.

function Write-Log { param([string]$Msg,[string]$Level='Info')
    $line="[{0:HH:mm:ss}] {1}" -f (Get-Date),$Msg
    $script:Log.SelectionStart=$script:Log.TextLength; $script:Log.SelectionLength=0
    $script:Log.SelectionColor = switch($Level){'Err'{[Drawing.Color]::DarkRed}'Good'{[Drawing.Color]::DarkGreen}default{[Drawing.Color]::DimGray}}
    $script:Log.AppendText("$line`n"); $script:Log.ScrollToCaret(); [Windows.Forms.Application]::DoEvents()
    if($script:Headless){
        Write-Host $line
        if($script:LogFilePath){ try { Add-Content -LiteralPath $script:LogFilePath -Value $line -Encoding UTF8 } catch {} }
    } }

function Get-Cred { param([string]$User,[string]$Pw)
    if([string]::IsNullOrWhiteSpace($User)){throw 'Username required.'}
    $s=[securestring]::new(); foreach($c in $Pw.ToCharArray()){$s.AppendChar($c)}; $s.MakeReadOnly()
    [pscredential]::new($User,$s) }

function Format-Err { param($ErrRec)
    $ex=$ErrRec.Exception; $s=$ex.ToString()
    if([string]::IsNullOrWhiteSpace($s)){ $s="$($ErrRec)" }
    while($ex.InnerException){ $ex=$ex.InnerException; $s+=" --> $($ex.Message)" }
    $s }

function Test-LocalTarget { param([string]$Target)
    $t=([string]$Target).Trim().ToLowerInvariant()
    if(-not $t){ return $false }
    if($t -in @('localhost','127.0.0.1','::1')){ return $true }
    $cn=$env:COMPUTERNAME.ToLowerInvariant()
    if($t -eq $cn -or $t.Split('.')[0] -eq $cn){ return $true }
    try {
        $mine=@([System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) | ForEach-Object { $_.IPAddressToString })
        foreach($ip in @([System.Net.Dns]::GetHostAddresses($t))){ if($mine -contains $ip.IPAddressToString){ return $true } }
    } catch {}
    return $false
}

function Save-UiLog {
    try {
        if(-not (Test-Path -LiteralPath $script:RunsDir)){ [void](New-Item -ItemType Directory -Path $script:RunsDir -Force) }
        if(-not $script:UiLogPath){ $script:UiLogPath = Join-Path $script:RunsDir ("guided-{0:yyyyMMdd-HHmmss}-log.txt" -f (Get-Date)) }
        [IO.File]::WriteAllText($script:UiLogPath, ([string]$script:Log.Text -replace "(?<!`r)`n","`r`n"), [Text.UTF8Encoding]::new($false))
        $script:UiLogPath
    } catch { '' }
}

function Get-VmsErrorText { param($Err)
    $parts = @(); $e = $Err.Exception
    while($e){ $m = Get-FirstLine $e.Message; if($m -and ($parts -notcontains $m)){ $parts += $m }; $e = $e.InnerException }
    "$($Err.Exception.GetType().Name): $((@($parts) | Select-Object -First 3) -join ' | ')"
}
function Get-VmsCredVariants { param([pscredential]$Cred)
    $v = @()
    if(-not $Cred){ return @() }
    $u = [string]$Cred.UserName
    $v += [pscustomobject]@{ Label=$u; Cred=$Cred }
    $bare = $null
    if($u -match '^\.\\(.+)$'){ $bare = $Matches[1] } elseif($u -notmatch '[\\@]'){ $bare = $u }
    if($bare){ $v += [pscustomobject]@{ Label="$env:COMPUTERNAME\$bare"; Cred=[pscredential]::new("$env:COMPUTERNAME\$bare",$Cred.Password) } }
    $v
}
function Connect-VmsAny { param([string[]]$Urls,[pscredential]$Cred,[switch]$AllowCurrentUser,[string]$Purpose)
    $reasons = [System.Collections.Generic.List[string]]::new()
    $variants = @(Get-VmsCredVariants $Cred)
    if($AllowCurrentUser){ $variants += [pscustomobject]@{ Label="$env:USERDOMAIN\$env:USERNAME (the Windows user running this wizard)"; Cred=$null } }
    $unreachable = '(?i)could not be resolved|no such host|unable to connect|actively refused|timed out|timeout|ServerNotFound|remote name|no connection could be made'
    foreach($url in @($Urls)){
        foreach($v in $variants){
            $cp = @{ ServerAddress=[uri]$url; AcceptEula=$true; ErrorAction='Stop' }
            if($v.Cred){ $cp.Credential = $v.Cred }
            try {
                Connect-Vms @cp | Out-Null
                Write-Log "VMS login OK ($Purpose): $url as $($v.Label)" 'Good'
                return [pscustomobject]@{ Ok=$true; Url=$url; As=$v.Label; Reasons=$reasons.ToArray() }
            } catch {
                $m = Get-VmsErrorText $_
                $reasons.Add("$url as $($v.Label): $m")
                Write-Log "  VMS login ($Purpose) $url as $($v.Label) -> $m"
                if($m -match $unreachable){ break }   # nothing answers at this address - other accounts will not help
            }
        }
    }
    [pscustomobject]@{ Ok=$false; Url=''; As=''; Reasons=$reasons.ToArray() }
}

# -- Certificate helpers (verbatim from Mrc-Guided.ps1) --------------------
function Normalize-RecorderHostName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { throw 'Recorder hostname is empty.' }
    ($Value.Trim() -split '\.')[0].ToUpperInvariant()
}
function Get-DomainSuffix {
    param([string]$Value)
    $s = $Value.Trim().TrimStart('.').TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($s)) { throw 'Domain suffix is required.' }
    $s.ToLowerInvariant()
}
function Get-RecorderFqdn {
    param([string]$HostName, [string]$DomainSuffix)
    "{0}.{1}" -f (Normalize-RecorderHostName $HostName), (Get-DomainSuffix $DomainSuffix)
}

# Recorder discovery from the VMS. ADAPTED from Mrc-Rec-Gui.ps1 Do-Load (same candidate-URL
# logic and the same skip of the recorder co-located on the management server), returning plain
# objects instead of filling a grid. Needs MilestonePSTools on this machine.
function Get-VmsRecorderList { param([string]$Domain,[pscredential]$VmsCred,[string]$MsAddrText)
    if(-not (Get-Module -ListAvailable MilestonePSTools)){ throw 'MilestonePSTools is not installed on this computer, so the recording servers cannot be found automatically. Type them in the "Extra recording servers" box (headless: -RecTargets), or install MilestonePSTools.' }
    Import-Module MilestonePSTools -ErrorAction Stop
    $typedAddr = ([string]$MsAddrText).Trim(); if($typedAddr -match '<[^>]+>'){ $typedAddr = '' }
    $rawHost = if($typedAddr){ try { ([uri]$typedAddr).Host } catch { $typedAddr } } else { '' }
    if([string]::IsNullOrWhiteSpace($rawHost)){ $rawHost=$typedAddr }
    # An ENCRYPTED management server's SDK endpoint answers ONLY on its real server FQDN (the cert CN)
    # over https, an UNENCRYPTED one on http only - so try every candidate host as https:// and http://.
    $hosts=[System.Collections.Generic.List[string]]::new()
    $addh={ param($h) if($h -and ($hosts -notcontains $h)){ [void]$hosts.Add($h) } }
    & $addh ("{0}.{1}" -f $env:COMPUTERNAME,$Domain)
    if($rawHost){
        if($rawHost -match '^\d{1,3}(\.\d{1,3}){3}$'){
            try { $rev=[System.Net.Dns]::GetHostEntry($rawHost).HostName; & $addh $rev } catch {}
            & $addh $rawHost
        } else {
            & $addh $rawHost
            if($rawHost -notmatch '\.'){ & $addh ("{0}.{1}" -f $rawHost,$Domain) }
        }
    }
    & $addh $env:COMPUTERNAME
    $cands=[System.Collections.Generic.List[string]]::new()
    $addc={ param($u) if($u -and ($cands -notcontains $u)){ [void]$cands.Add($u) } }
    if($typedAddr -match '^https?://'){ & $addc $typedAddr }
    foreach($h in $hosts){ & $addc "https://$h" }
    foreach($h in $hosts){ & $addc "http://$h" }
    Write-Log "Logging in to the VMS to find the recording servers (addresses: $($cands -join ', '))..."
    $vl = Connect-VmsAny -Urls $cands.ToArray() -Cred $VmsCred -AllowCurrentUser -Purpose 'recorder discovery'
    if(-not $vl.Ok){
        $why = (@($vl.Reasons) | Select-Object -First 8) -join "`r`n  "
        throw "Could not log in to the VMS (Milestone management server). Tried:`r`n  $why`r`nMost common causes: a local Windows account must be typed as COMPUTERNAME\user, and the account must be in the Milestone Administrators role (Management Client > Security > Roles > Administrators)."
    }
    $connectedUrl=$vl.Url
    $msNames = [System.Collections.Generic.List[string]]::new()
    $addMs = { param($n) if($n){ try { $s = Normalize-RecorderHostName $n; if($msNames -notcontains $s){ [void]$msNames.Add($s) } } catch {} } }
    try { $vmsMs = Get-VmsManagementServer -ErrorAction Stop; if($vmsMs -and $vmsMs.Name){ & $addMs $vmsMs.Name } } catch {}
    if($connectedUrl){ try { & $addMs (([uri]$connectedUrl).Host) } catch {} }
    if($rawHost -and $rawHost -notmatch '^\d{1,3}(\.\d{1,3}){3}$'){ & $addMs $rawHost }
    elseif($rawHost){ try { & $addMs ([System.Net.Dns]::GetHostEntry($rawHost).HostName) } catch {} }
    & $addMs $env:COMPUTERNAME
    $found=[System.Collections.Generic.List[object]]::new()
    $seenFqdn=@{}
    foreach($rec in (Get-VmsRecordingServer | Sort-Object Name)){
        $src= if(-not [string]::IsNullOrWhiteSpace($rec.HostName)){$rec.HostName}else{$rec.Name}
        $isIp = $src -match '^\d{1,3}(\.\d{1,3}){3}$'
        $srcTrim = ([string]$src).Trim()
        $short= Normalize-RecorderHostName $(if($isIp){ $rec.Name } else { $src })
        # W13: keep a real discovered FQDN VERBATIM - never rebuild it from the wizard's own Domain box.
        # That silently rewrites cross-domain names (the same bug class Resolve-CertFqdn avoids for the
        # certificate CN); only a bare short name (or an IP) gets the Domain suffix appended here.
        $fqdn = if($isIp){ $src } elseif($srcTrim -match '\.'){ $srcTrim.ToLowerInvariant() } else { Get-RecorderFqdn -HostName $short -DomainSuffix $Domain }
        if($msNames -contains $short){
            Write-Log "Recording server '$($rec.Name)' runs on this Management Server - it is covered by the Management Server step, not handled separately."
            continue
        }
        # W13: dedup by the full FQDN (not the short name) - two entries can share a short name only when
        # they are genuinely the same recorder reported twice.
        $dedupKey = ($(if($isIp){ $short } else { $fqdn })).ToUpperInvariant()
        if($seenFqdn.ContainsKey($dedupKey)){ continue }
        $seenFqdn[$dedupKey] = $true
        [void]$found.Add([pscustomobject]@{ Name=[string]$rec.Name; Target=$short; Fqdn=$fqdn })
    }
    Write-Log "Discovered $($found.Count) recording server(s)." 'Good'
    Disconnect-ManagementServer -ErrorAction SilentlyContinue
    $found.ToArray()
}

# -- boxes (one per computer) --------------------------------------------------------------
$script:MsBox = $null; $script:EsBox = $null; $script:RecBoxes = @()
$script:SessOpt = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 180000
function New-Box { param([string]$Role,[string]$Name,[string]$Target,[string]$Addr,[pscredential]$Cred)
    [pscustomobject]@{ Role=$Role; Name=$Name; Target=$Target; Addr=$Addr; Cred=$Cred; Reachable=$false; Encrypted=$null; Detail='not checked yet'; Excluded=$false
                       IsNode=$false; ClusterKey=''; Active=$false } }
# Cluster state (WSFC). $script:MsCluster / $script:EsCluster are $null for a single (standalone) server.
$script:MsCluster = $null; $script:MsNodeBoxes = @(); $script:MsDetectError = ''
$script:EsCluster = $null; $script:EsNodeBoxes = @(); $script:EsDetectError = ''
function Get-First { param($Items) $a=@($Items); if($a.Count){ $a[0] } else { $null } }
function Get-ClusterObj { param([string]$Key) if($Key -eq 'MS'){ $script:MsCluster } elseif($Key -eq 'ES'){ $script:EsCluster } else { $null } }
function Get-NodeBoxes { param([string]$Key) if($Key -eq 'MS'){ @($script:MsNodeBoxes) } elseif($Key -eq 'ES'){ @($script:EsNodeBoxes) } else { @() } }
function Get-MsBoxes { if($script:MsCluster){ @($script:MsNodeBoxes) } elseif($script:MsBox){ @($script:MsBox) } else { @() } }
function Get-EsBoxes { if($script:EsCluster){ @($script:EsNodeBoxes) } elseif($script:EsBox){ @($script:EsBox) } else { @() } }
function Get-AllBoxes {
    $a=@(); $a+=@(Get-MsBoxes); $a+=@(Get-EsBoxes); $a+=@($script:RecBoxes); $a }
function Get-BoxKind { param($Box) if($Box.Role -eq 'Management Server'){ 'MS' } elseif($Box.Role -eq 'Event Server'){ 'ES' } else { 'REC' } }
function Get-RoleText { param($Box)
    if(-not $Box.IsNode){ return [string]$Box.Role }
    "$($Box.Role) - cluster node, $(if($Box.Active){'active (runs the role now)'}else{'passive (standby)'})" }
function Get-FirstLine { param([string]$Text) if(-not $Text){ return '' }; ($Text -split "`r?`n")[0].Trim() }
function Test-IpAddress { param([string]$Value) $ip=$null; [System.Net.IPAddress]::TryParse(([string]$Value).Trim(),[ref]$ip) }

# Ground truth readers (verbatim from Mrc-Guided.ps1). See that file for the W4 netsh-localization note.
$script:BindingsSb = {
    $addrRe = '(\d{1,3}(?:\.\d{1,3}){3}:\d+|\[[0-9A-Fa-f:]+\]:\d+)'
    $raw = $null
    try { $raw = @(netsh http show sslcert 2>&1) } catch { return [pscustomobject]@{ Ok=$false; Bindings=''; Count=0; Error=$_.Exception.Message } }
    if ($LASTEXITCODE) { return [pscustomobject]@{ Ok=$false; Bindings=''; Count=0; Error="netsh exited $LASTEXITCODE" } }
    $b = @()
    foreach ($ln in $raw) {
        $m = [regex]::Match([string]$ln, $addrRe)
        if ($m.Success) { $b += $m.Groups[1].Value }
    }
    $b = @($b | Where-Object { $_ -notmatch ':(443|5986)$' })
    [pscustomobject]@{ Ok=$true; Bindings=($b -join ','); Count=$b.Count }
}
$script:RecorderStateSb = {
    $cfgPath = Join-Path $env:ProgramData 'Milestone\XProtect Recording Server\RecorderConfig.xml'
    if (Test-Path -LiteralPath $cfgPath) {
        try {
            $x = [xml](Get-Content -LiteralPath $cfgPath -Raw)
            $n = $x.SelectSingleNode('//serverEncryption')
            if ($n) {
                $en = [string]$n.GetAttribute('enabled')
                if ($en -eq 'true' -or $en -eq 'false') {
                    return [pscustomobject]@{ Source='xml'; Ok=$true; Bindings=''; Count=0; Enabled=($en -eq 'true'); Hash=[string]$n.GetAttribute('certificateHash') }
                }
            }
        } catch {}
    }
    $addrRe = '(\d{1,3}(?:\.\d{1,3}){3}:\d+|\[[0-9A-Fa-f:]+\]:\d+)'
    $raw = $null
    try { $raw = @(netsh http show sslcert 2>&1) } catch { return [pscustomobject]@{ Source='bindings'; Ok=$false; Bindings=''; Count=0; Enabled=$null; Hash=''; Error=$_.Exception.Message } }
    if ($LASTEXITCODE) { return [pscustomobject]@{ Source='bindings'; Ok=$false; Bindings=''; Count=0; Enabled=$null; Hash=''; Error="netsh exited $LASTEXITCODE" } }
    $b = @()
    foreach ($ln in $raw) {
        $m = [regex]::Match([string]$ln, $addrRe)
        if ($m.Success) { $b += $m.Groups[1].Value }
    }
    $b = @($b | Where-Object { $_ -notmatch ':(443|5986)$' })
    [pscustomobject]@{ Source='bindings'; Ok=$true; Bindings=($b -join ','); Count=$b.Count; Enabled=($b.Count -gt 0); Hash='' }
}
$script:EsStateSb = {
    $p = Join-Path $env:ProgramData 'Milestone\XProtect Event Server\config\ServiceEndpoints.xml'
    if(-not (Test-Path -LiteralPath $p)){ return [pscustomobject]@{ Found=$false; Value=''; Path=$p } }
    $x = [xml](Get-Content -LiteralPath $p -Raw)
    $n = $x.SelectSingleNode('/eventserverconfig/CertificateEnabled')
    [pscustomobject]@{ Found=$true; Value=$(if($n){ ([string]$n.InnerText).Trim() } else { '(element missing)' }); Path=$p }
}

# -- connection helpers (verbatim from Mrc-Guided.ps1) ---------------------------------------
$script:ConnCache    = @{}   # HOST path: lower-case typed name -> working address (the name or its DNS IP)
$script:NodeConn     = @{}   # NODE path: upper-case node name -> verified address (its FQDN or its own IP)
$script:NodeInfo     = @{}   # upper-case node name -> Name, Fqdn, own Ips, ClusterKey
$script:ClusterIpSet = @{}   # every cluster / role 'IP Address' resource address (all groups, both clusters)
function Test-KerberosError { param([string]$Msg) ([string]$Msg) -match '0x80090322|0x8009030e|0x80090311|Kerberos' }
function Get-IdentityErrorText { param([string]$Actual,[string]$Node) "Connected to $Actual instead of cluster node $Node; nothing was changed on $Node." }
function Test-IdentityError { param([string]$Msg) ([string]$Msg) -match 'instead of cluster node' }
function Get-IdentityMessage { param([string]$Msg) if(([string]$Msg) -match '(Connected to \S+ instead of cluster node \S+; nothing was changed on [^.\s]+\.)'){ $Matches[1] } else { [string]$Msg } }
function Get-NodeKey { param([string]$Node) ([string]$Node).Trim().ToUpperInvariant() }
function Test-NodeIsLocal { param([string]$Node) (Get-NodeKey $Node) -eq $env:COMPUTERNAME.ToUpperInvariant() }
function Forget-NodeConn { param([string]$Node) [void]$script:NodeConn.Remove((Get-NodeKey $Node)) }
function Resolve-HostIPv4 { param([string]$Name)
    try { @([System.Net.Dns]::GetHostAddresses($Name) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }) } catch { @() } }
function Register-NodeAddresses { param($Cl)
    if($Cl.PSObject.Properties['ClusterIps']){ foreach($ip in @($Cl.ClusterIps)){ if($ip){ $script:ClusterIpSet[[string]$ip]=$true } } }
    foreach($n in @($Cl.Nodes)){
        $ips=@(); if($n.PSObject.Properties['Ips']){ $ips=@($n.Ips | Where-Object { $_ }) }
        $script:NodeInfo[(Get-NodeKey $n.Name)] = [pscustomobject]@{ Name=[string]$n.Name; Fqdn=[string]$n.Fqdn; Ips=$ips; ClusterKey=[string]$Cl.Key }
    } }
function Invoke-OnBoxRaw { param([string]$Computer,[pscredential]$Cred,[scriptblock]$Sb,[object[]]$ArgumentList=@())
    $p=@{ ComputerName=$Computer; ScriptBlock=$Sb; ErrorAction='Stop'; SessionOption=$script:SessOpt }
    if($Cred){ $p.Credential=$Cred }
    if(@($ArgumentList).Count){ $p.ArgumentList=@($ArgumentList) }
    Invoke-Command @p }
# Which computer answers on $Address (one round trip).
function Get-AnsweringComputer { param([string]$Address,[pscredential]$Cred)
    [string](Get-First -Items @(Invoke-OnBoxRaw -Computer $Address -Cred $Cred -Sb { $env:COMPUTERNAME })) }
# Run $Sb on $Address ONLY if that address is really $Node: identity check and action in ONE session.
function Invoke-GuardedOnAddress { param([string]$Address,[pscredential]$Cred,[string]$Node,[scriptblock]$Sb,[object[]]$ArgumentList=@())
    $sp=@{ ComputerName=$Address; ErrorAction='Stop'; SessionOption=$script:SessOpt }; if($Cred){ $sp.Credential=$Cred }
    $s = New-PSSession @sp
    try {
        $cn = [string](Get-First -Items @(Invoke-Command -Session $s -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop))
        if($cn -ne $Node){ throw (Get-IdentityErrorText $cn $Node) }
        $p=@{ Session=$s; ScriptBlock=$Sb; ErrorAction='Stop' }; if(@($ArgumentList).Count){ $p.ArgumentList=@($ArgumentList) }
        Invoke-Command @p
    } finally { Remove-PSSession -Session $s -ErrorAction SilentlyContinue }
}

# ---- HOST path ----
function Find-IpConnection { param([string]$Computer,[pscredential]$Cred,[string]$Why)
    $k=([string]$Computer).Trim().ToLowerInvariant()
    $isKnownClusterName = [bool]($script:EsCluster -and (@($script:EsCluster.NetName,$script:EsCluster.Address) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ -eq $k }))
    foreach($ip in @(Resolve-HostIPv4 $Computer)){
        if(Test-LocalTarget $ip){ continue }
        Ensure-TrustedHosts -Hosts @($ip)
        try {
            $cn = Get-AnsweringComputer $ip $Cred
            $script:ConnCache[$k]=$ip
            $because = if($isKnownClusterName){ "because the name belongs to a cluster ($Why)" } else { "because Kerberos could not be used for the name ($Why)" }
            Write-Log "[$Computer] connected by IP address $ip (answers as $cn) $because." 'Good'
            return $ip
        } catch { Write-Log "[$Computer] address ${ip}: $(Get-FirstLine $_.Exception.Message)" 'Err' }
    }
    $null
}
function Get-ConnAddr { param([string]$Computer,[pscredential]$Cred)
    if(Test-LocalTarget $Computer){ return $Computer }
    $k=([string]$Computer).Trim().ToLowerInvariant()
    if($script:ConnCache.ContainsKey($k)){ return [string]$script:ConnCache[$k] }
    try { [void](Invoke-OnBoxRaw -Computer $Computer -Cred $Cred -Sb { 1 }); $script:ConnCache[$k]=$Computer; return $Computer }
    catch {
        $m=$_.Exception.Message
        if(-not (Test-KerberosError $m)){ throw }
        $ip = Find-IpConnection $Computer $Cred (Get-FirstLine $m)
        if($ip){ return $ip }
        throw
    }
}
# HOST targets only - never a cluster node (use Invoke-OnNode for those).
function Invoke-OnBox { param([string]$Computer,[pscredential]$Cred,[scriptblock]$Sb,[object[]]$ArgumentList=@())
    if(Test-LocalTarget $Computer){ return (& $Sb @ArgumentList) }
    $conn = Get-ConnAddr $Computer $Cred
    try { Invoke-OnBoxRaw -Computer $conn -Cred $Cred -Sb $Sb -ArgumentList $ArgumentList }
    catch {
        # A name that worked before can stop working when a cluster role moves: fall back once.
        if($conn -ne $Computer -or -not (Test-KerberosError $_.Exception.Message)){ throw }
        $k=([string]$Computer).Trim().ToLowerInvariant(); [void]$script:ConnCache.Remove($k)
        $ip = Find-IpConnection $Computer $Cred (Get-FirstLine $_.Exception.Message)
        if(-not $ip){ throw }
        Invoke-OnBoxRaw -Computer $ip -Cred $Cred -Sb $Sb -ArgumentList $ArgumentList
    }
}
# One Invoke-Command fan-out over many recorders (WinRM runs them in parallel). Returns Addr -> result.
# W14: connects through Get-ConnAddr (Kerberos-to-IP fallback), same as every other recorder path - the
# result stays keyed by each box's ORIGINAL Addr so callers do not need to know about the resolved address.
function Invoke-RecorderFanOut { param([object[]]$Boxes,[scriptblock]$Sb,[object[]]$ArgumentList=@())
    $res = @{}
    $connOf = @{}
    foreach($b in @($Boxes)){ try { $connOf[[string]$b.Addr] = Get-ConnAddr $b.Addr $b.Cred } catch {} }
    $addrs = @(@($Boxes) | ForEach-Object { $connOf[[string]$_.Addr] } | Where-Object { $_ } | Select-Object -Unique)
    if(-not $addrs.Count){ return $res }
    $ev = $null
    $p = @{ ComputerName=$addrs; ScriptBlock=$Sb; SessionOption=$script:SessOpt; ThrottleLimit=32; ErrorAction='SilentlyContinue'; ErrorVariable='ev' }
    if(@($ArgumentList).Count){ $p.ArgumentList = @($ArgumentList) }
    $c = Get-First -Items @(@($Boxes) | ForEach-Object { $_.Cred } | Where-Object { $_ })
    if($c){ $p.Credential = $c }
    $byAddr = @{}
    foreach($o in @(Invoke-Command @p)){ $byAddr[[string]$o.PSComputerName] = $o }
    foreach($b in @($Boxes)){
        $conn = $connOf[[string]$b.Addr]
        if($conn -and $byAddr.ContainsKey($conn)){ $res[[string]$b.Addr] = $byAddr[$conn] }
    }
    $res }

# ---- NODE path ----
function Resolve-NodeConn { param([string]$Node,[pscredential]$Cred)
    $k = Get-NodeKey $Node
    if($script:NodeConn.ContainsKey($k)){ return [string]$script:NodeConn[$k] }
    if(-not $script:NodeInfo.ContainsKey($k)){ throw "Cluster node $Node is not known to the wizard (click Check again). Nothing was changed on $Node." }
    $info = $script:NodeInfo[$k]
    $cands = @()
    $fq = [string]$info.Fqdn
    if($fq){
        $res = @(Resolve-HostIPv4 $fq)
        $toCluster = @($res | Where-Object { $script:ClusterIpSet.ContainsKey($_) })
        $toHere    = @($res | Where-Object { Test-LocalTarget $_ })
        if($res.Count -and -not $toCluster.Count -and -not $toHere.Count){ $cands += $fq }
        else { Write-Log "[$($info.Name)] its name $fq resolves to $(if($res.Count){$res -join ', '}else{'nothing'})$(if($toCluster.Count){' (a cluster / role address)'}elseif($toHere.Count){' (this computer)'}) - the node's own IP address is used instead." }
    }
    foreach($ip in @($info.Ips)){ if($ip -and -not $script:ClusterIpSet.ContainsKey([string]$ip) -and -not (Test-LocalTarget $ip) -and $cands -notcontains $ip){ $cands += [string]$ip } }
    foreach($c in $cands){
        if(Test-IpAddress $c){ Ensure-TrustedHosts -Hosts @($c) }
        try {
            $cn = Get-AnsweringComputer $c $Cred
            if($cn -ne $info.Name){ Write-Log "[$($info.Name)] address $c answers as $cn, not as $($info.Name) - not used" 'Err'; continue }
            $script:NodeConn[$k] = $c
            if($c -ne $fq){ Write-Log "[$($info.Name)] connected to cluster node $($info.Name) by its own IP address $c." 'Good' }
            return $c
        } catch { Write-Log "[$($info.Name)] ${c}: $(Get-FirstLine $_.Exception.Message)" 'Err' }
    }
    throw "Cannot reach cluster node $($info.Name) on its own name or its own IP addresses ($(if($cands.Count){$cands -join ', '}else{'none known'})). Nothing was changed on $($info.Name)."
}
# The address to hand to an ENGINE function for a node, verified right now (identity check on exactly
# that address). The local node gets its FQDN: the engine's Test-LocalTarget then runs it in-process.
function Get-VerifiedNodeAddr { param($Box)
    if(Test-NodeIsLocal $Box.Target){ return [string]$Box.Addr }
    for($try=1; $try -le 2; $try++){
        $addr = Resolve-NodeConn $Box.Target $Box.Cred
        try { $cn = Get-AnsweringComputer $addr $Box.Cred }
        catch { Forget-NodeConn $Box.Target; if($try -lt 2){ continue }; throw }
        if($cn -ne [string]$Box.Target){ Forget-NodeConn $Box.Target; throw (Get-IdentityErrorText $cn $Box.Target) }
        return $addr
    }
}
# Run $Sb on cluster node $Node (in-process when it is this computer), identity-checked in the same session.
function Invoke-OnNode { param([string]$Node,[pscredential]$Cred,[scriptblock]$Sb,[object[]]$ArgumentList=@())
    if(Test-NodeIsLocal $Node){ return (& $Sb @ArgumentList) }
    $addr = Resolve-NodeConn $Node $Cred
    try { Invoke-GuardedOnAddress -Address $addr -Cred $Cred -Node $Node -Sb $Sb -ArgumentList $ArgumentList }
    catch {
        $m = $_.Exception.Message
        Forget-NodeConn $Node
        if((Test-IdentityError $m) -or -not (Test-KerberosError $m)){ throw }
        # A Kerberos refusal on a cached name: resolve again (identity-verified) and try once more.
        $addr = Resolve-NodeConn $Node $Cred
        Invoke-GuardedOnAddress -Address $addr -Cred $Cred -Node $Node -Sb $Sb -ArgumentList $ArgumentList
    }
}

# ===================== WINDOWS FAILOVER CLUSTER (WSFC) DETECTION (verbatim) =====================
$script:MsSvcDisplay = 'Milestone XProtect Management Server'
$script:EsSvcDisplay = 'Milestone XProtect Event Server'

$script:ClusterInfoSb = {
    param([string]$Kind)
    $ErrorActionPreference = 'Stop'
    $nm = { param($o) if($null -eq $o){ return '' }; if($o -is [string]){ return $o }; $pp=$o.PSObject.Properties['Name']; if($pp){ return [string]$pp.Value }; [string]$o }
    $snOf = { param($r) try { [string](($r | Get-ClusterParameter -Name ServiceName -ErrorAction Stop).Value) } catch { '' } }
    $msNames = @('Milestone XProtect Management Server')
    $esNames = @('MilestoneEventServerService','MilestoneEventServer')
    foreach($s in @(Get-Service -ErrorAction SilentlyContinue)){
        if($s.DisplayName -eq 'Milestone XProtect Management Server' -and $msNames -notcontains $s.Name){ $msNames += $s.Name }
        if($s.DisplayName -eq 'Milestone XProtect Event Server' -and $esNames -notcontains $s.Name){ $esNames += $s.Name }
    }
    $o = [ordered]@{ Clustered=$false; Note=''; Computer=$env:COMPUTERNAME; Group=''; State=''; Owner=''; NetName=''; Address=''; Domain=''; Nodes=@(); Offline=@(); ClusterIps=@(); Excluded=@() }
    $cs = Get-Service -Name ClusSvc -ErrorAction SilentlyContinue
    if(-not $cs){ $o.Note = 'Windows failover clustering is not installed' }
    else {
        # W2: fail CLOSED from here on - a box counts as standalone only if ClusSvc is absent (above), or
        # the cluster is readable and the Milestone service turns out not to be a cluster resource (below).
        # A present-but-unreadable cluster must never be silently treated as "not clustered".
        if([string]$cs.Status -ne 'Running'){ throw "the Windows Cluster Service (ClusSvc) is installed but not running (status: $($cs.Status)) on $env:COMPUTERNAME. Start the Cluster service, or fully remove Windows failover clustering, before this wizard can tell whether this computer is part of a cluster." }
        if(-not (Get-Module -ListAvailable -Name FailoverClusters)){ throw "the Cluster service is running on $env:COMPUTERNAME but the 'Failover Cluster Module for Windows PowerShell' (RSAT-Clustering-PowerShell) is not installed, so cluster membership cannot be checked. Install it (Server Manager > Add Roles and Features > Features > Remote Server Administration Tools > Failover Clustering Tools > Failover Cluster Module for Windows PowerShell), then try again." }
        Import-Module FailoverClusters -ErrorAction Stop
        $gen = @(Get-ClusterResource | Where-Object { (& $nm $_.ResourceType) -eq 'Generic Service' })
        $wantNames = if($Kind -eq 'MS'){ $msNames } else { $esNames }
        $msGroups = @()
        foreach($r in $gen){ if($msNames -contains (& $snOf $r)){ $msGroups += (& $nm $r.OwnerGroup) } }
        $hit = $null
        foreach($r in $gen){
            if($wantNames -notcontains (& $snOf $r)){ continue }
            # The Event Server resource INSIDE the Management Server role is not an Event Server role.
            if($Kind -eq 'ES' -and $msGroups -contains (& $nm $r.OwnerGroup)){ continue }
            $hit = $r; break
        }
        if(-not $hit){ $o.Note = 'the Milestone service is not a cluster resource here' }
        else {
            $gName = & $nm $hit.OwnerGroup
            $g = Get-ClusterGroup -Name $gName
            $dom = [string](Get-CimInstance Win32_ComputerSystem).Domain
            $o.Clustered = $true; $o.Group = $gName; $o.State = [string]$g.State; $o.Owner = (& $nm $g.OwnerNode); $o.Domain = $dom
            foreach($r in @(Get-ClusterResource | Where-Object { (& $nm $_.OwnerGroup) -eq $gName })){
                $rt = & $nm $r.ResourceType
                if($rt -eq 'Network Name' -and -not $o.NetName){
                    $dns = ''
                    try { $dns = [string](($r | Get-ClusterParameter -Name DnsName -ErrorAction Stop).Value) } catch {}
                    if($dns){ $o.NetName = $dns.ToLowerInvariant(); $o.Address = $(if($dom -and $dns -notmatch '\.'){ "$dns.$dom" } else { $dns }).ToLowerInvariant() }
                }
                if([string]$r.State -ne 'Online'){
                    $sn = if($rt -eq 'Generic Service'){ & $snOf $r } else { '' }
                    $isEs = ($esNames -contains $sn) -or ($rt -eq 'Generic Service' -and [string]$r.Name -match 'Event Server')
                    $o.Offline += [pscustomobject]@{ Name=[string]$r.Name; Type=$rt; State=[string]$r.State; ServiceName=$sn; IsEs=[bool]$isEs }
                }
            }
            # W3: nodes that may run THIS role = the possible owners of its Milestone service resource.
            # (The group's owner list is only a preference order, not a restriction.) Get-ClusterOwnerNode
            # returns ONE ClusterOwnerNodeList object; the nodes are in its .OwnerNodes. Empty = all nodes.
            $possible = @()
            try { $possible = @(@((Get-ClusterOwnerNode -Resource (& $nm $hit) -ErrorAction Stop).OwnerNodes) | ForEach-Object { & $nm $_ } | Where-Object { $_ }) } catch {}
            foreach($n in @(Get-ClusterNode)){
                $nn = [string]$n.Name
                if($possible.Count -and $possible -notcontains $nn){ $o.Excluded += $nn; continue }
                # The node's own addresses as the CLUSTER knows them - used when its name cannot be trusted.
                $ips = @()
                try { $ips = @(Get-ClusterNetworkInterface -Node $nn -ErrorAction Stop | ForEach-Object { [string]$_.Address } | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notmatch '^169\.254\.' }) } catch {}
                $o.Nodes += [pscustomobject]@{ Name=$nn; Fqdn=$(if($dom){ "$nn.$dom" } else { $nn }).ToLowerInvariant(); State=[string]$n.State; Ips=$ips }
            }
            # Every cluster / role IP address (all groups, incl. the core 'Cluster Group'): these move between
            # nodes, so they must never be used to reach one particular node.
            foreach($r in @(Get-ClusterResource | Where-Object { (& $nm $_.ResourceType) -eq 'IP Address' })){
                try { $a = [string](($r | Get-ClusterParameter -Name Address -ErrorAction Stop).Value); if($a){ $o.ClusterIps += $a } } catch {}
            }
        }
    }
    [pscustomobject]$o
}

function Get-StageName { param([string]$Key) switch($Key){ 'ES' { 'Event Server' } 'MS' { 'Management Server' } 'FT' { 'Failover test' } 'REG' { 'Re-register this node' } 'ROLE' { 'Move cluster roles back' } default { 'Recording servers' } } }
function New-ClusterObj { param([string]$Key,$Info,[string]$Via)
    [pscustomobject]@{ Key=$Key; Group=[string]$Info.Group; Address=[string]$Info.Address; NetName=[string]$Info.NetName; Domain=[string]$Info.Domain
                       Owner=[string]$Info.Owner; State=[string]$Info.State; Nodes=@($Info.Nodes); Offline=@($Info.Offline)
                       ClusterIps=@(if($Info.PSObject.Properties['ClusterIps']){ @($Info.ClusterIps) })
                       Excluded=@(if($Info.PSObject.Properties['Excluded']){ @($Info.Excluded) })
                       Via=$Via; Error='' } }   # Via = the NODE NAME cluster commands are sent to (Invoke-OnNode); Excluded = nodes that are not possible owners of this role (W3)
function Write-ExcludedNodes { param([string]$Key,$Info)
    if(-not $Info.PSObject.Properties['Excluded']){ return }
    foreach($n in @($Info.Excluded)){ Write-Log "$(Get-StageName $Key): node $n is not a possible owner of role '$($Info.Group)' - excluded from certificate install, the per-node loop, the registration check and suspend/resume." }
}
function New-NodeBox { param([string]$Key,$Node,[pscredential]$Cred)
    $b = New-Box $(if($Key -eq 'MS'){'Management Server'}else{'Event Server'}) ([string]$Node.Name) ([string]$Node.Name) ([string]$Node.Fqdn) $Cred
    $b.IsNode=$true; $b.ClusterKey=$Key; $b }
function Set-ActiveFlags { param([string]$Key)
    $cl = Get-ClusterObj $Key; if(-not $cl){ return }
    foreach($b in @(Get-NodeBoxes $Key)){ $b.Active = ([string]$b.Target -eq [string]$cl.Owner) } }
function Format-NodeList { param($Cl)
    (@($Cl.Nodes) | ForEach-Object { if([string]$_.Name -eq [string]$Cl.Owner){ "$($_.Name) (active)" } else { "$($_.Name) (passive)" } }) -join ', ' }

# Detect the Management Server cluster (this computer, in-process). Runs before the recorder list is
# built so recorders on MS nodes are recognized as covered by the Management Server step.
function Initialize-MsCluster {
    $script:MsCluster = $null; $script:MsNodeBoxes = @(); $script:MsDetectError = ''
    $script:ConnCache = @{}; $script:NodeConn = @{}; $script:NodeInfo = @{}; $script:ClusterIpSet = @{}   # re-learned from the cluster
    try {
        $i = Get-First -Items @(& $script:ClusterInfoSb 'MS')
        if($i -and $i.Clustered){
            $script:MsCluster = New-ClusterObj 'MS' $i $env:COMPUTERNAME
            Register-NodeAddresses $script:MsCluster
            $script:MsNodeBoxes = @(foreach($n in @($i.Nodes)){ New-NodeBox 'MS' $n $script:AdminCred })
            Set-ActiveFlags 'MS'
            Write-Log "Management Server: this computer is a node of Windows failover cluster role '$($i.Group)' (cluster address $(if($i.Address){$i.Address}else{'(none)'}); nodes $(Format-NodeList $script:MsCluster))." 'Good'
            Write-ExcludedNodes 'MS' $i
            if(-not $i.Address){ Write-Log "WARNING: cluster role '$($i.Group)' has no Network Name resource - the cluster address is unknown." 'Err' }
        } elseif($i){ Write-Log "Management Server: single server, not clustered ($($i.Note))." }
    } catch { $script:MsDetectError = Get-FirstLine $_.Exception.Message; Write-Log "Management Server cluster check FAILED: $(Format-Err $_)" 'Err' }
}
# Detect the Event Server cluster over WinRM to the host entered in step 1. Cluster commands are then
# sent to that NODE (not to the cluster name, which moves with the role).
function Initialize-EsCluster {
    $script:EsCluster = $null; $script:EsNodeBoxes = @(); $script:EsDetectError = ''
    if(-not $script:EsBox){ return }
    try {
        $i = Get-First -Items @(Invoke-OnBox -Computer $script:EsAddr -Cred $script:AdminCred -Sb $script:ClusterInfoSb -ArgumentList @('ES'))
        if($i -and $i.Clustered){
            # The typed name may point at whichever node owns the role; from here on cluster commands go to
            # the node that answered, by NODE NAME (Invoke-OnNode), never to the typed name.
            $via = Get-First -Items @(@($i.Nodes) | Where-Object { [string]$_.Name -eq [string]$i.Computer } | ForEach-Object { [string]$_.Name })
            if(-not $via){ $via = [string](Get-First -Items @(@($i.Nodes) | ForEach-Object { $_.Name })) }
            $script:EsCluster = New-ClusterObj 'ES' $i $via
            Register-NodeAddresses $script:EsCluster
            $script:EsNodeBoxes = @(foreach($n in @($i.Nodes)){ New-NodeBox 'ES' $n $script:AdminCred })
            Set-ActiveFlags 'ES'
            Write-Log "Event Server: '$($script:EsAddr)' is Windows failover cluster role '$($i.Group)' (cluster address $(if($i.Address){$i.Address}else{'(none)'}); nodes $(Format-NodeList $script:EsCluster))." 'Good'
            Write-ExcludedNodes 'ES' $i
        } elseif($i){ Write-Log "Event Server: single server, not clustered ($($i.Note))." }
    } catch { $script:EsDetectError = Get-FirstLine $_.Exception.Message; Write-Log "Event Server cluster check FAILED (cannot connect to $($script:EsAddr)?): $(Get-FirstLine $_.Exception.Message)" 'Err' }
}

# -- ServerConfigurator finder (verbatim from Mrc-Guided.ps1) --------------------------------
$script:ScSearchPaths = ''
$script:ScFindSb = {
    param([string]$ConfPath)
    $scExe = $null; $scLook = [System.Collections.Generic.List[string]]::new()
    $scDirs = @(([string]$ConfPath) -split ';' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ })
    foreach ($scP in $scDirs) { if ($scP -match '\.exe$') { $scLook.Add($scP) } else { foreach ($scSub in @('', 'Server Configurator', 'Milestone\Server Configurator')) { $scLook.Add((Join-Path (Join-Path $scP $scSub) 'ServerConfigurator.exe')) } } }
    foreach ($scSvc in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Milestone XProtect*' -or $_.Name -like 'MilestoneEventServer*' })) {
        try { if ([string]$scSvc.PathName -match '^\s*"?([^"]+?\.exe)') { $scUp = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($Matches[1])); foreach ($scRoot in @($scUp, $(if ($scUp) { [IO.Path]::GetDirectoryName($scUp) }))) { if ($scRoot) { $scLook.Add((Join-Path $scRoot 'Server Configurator\ServerConfigurator.exe')) } } } } catch {}
    }
    $scLook.Add((Join-Path $env:ProgramFiles 'Milestone\Server Configurator\ServerConfigurator.exe'))
    foreach ($scC in $scLook) { if (Test-Path -LiteralPath $scC -PathType Leaf) { $scExe = $scC; break } }
    if (-not $scExe) { foreach ($scP in @($scDirs | Where-Object { $_ -notmatch '\.exe$' -and (Test-Path -LiteralPath $_ -PathType Container) })) { $scHit = Get-ChildItem -LiteralPath $scP -Filter 'ServerConfigurator.exe' -File -Recurse -Depth 4 -ErrorAction SilentlyContinue | Select-Object -First 1; if ($scHit) { $scExe = $scHit.FullName; break } } }
    if (-not $scExe) { $scExe = '(not found - looked in: ' + ((@($scLook) | Select-Object -Unique) -join '; ') + $(if (@($scDirs).Count) { '; and searched below: ' + ($scDirs -join '; ') } else { '' }) + ')' }
    [pscustomobject]@{ Found=[bool](Test-Path -LiteralPath $scExe -PathType Leaf); Path=$scExe }
}

# -- registered-address reader (verbatim from Mrc-Guided.ps1) --------------------------------
$script:RegAddrSb = {
    param([bool]$IsEs)
    $dir = Join-Path $env:ProgramFiles 'Milestone\XProtect Data Collector Server'   # fallback only: the service path below wins
    try {
        $svc = Get-CimInstance Win32_Service -Filter "DisplayName='Milestone XProtect Data Collector Server'" -ErrorAction Stop | Select-Object -First 1
        if($svc -and $svc.PathName){
            $pn = ([string]$svc.PathName).Trim()
            $exe = if($pn -match '^"([^"]+)"'){ $Matches[1] } elseif($pn -match '^(.+?\.exe)'){ $Matches[1] } else { $pn }
            $d = Split-Path -Path $exe -Parent
            if($d){ $dir = $d }
        }
    } catch {}
    $addr = ''; $src = ''
    $f = Join-Path $dir 'appsettings.json'
    if(Test-Path -LiteralPath $f){
        try {
            $j = Get-Content -LiteralPath $f -Raw -ErrorAction Stop | ConvertFrom-Json
            # ManagementServerAddress wherever it sits in the file (first one found, a few levels deep).
            $find = { param($n,[int]$depth)
                if($null -eq $n -or $depth -gt 4){ return '' }
                if($n -is [System.Management.Automation.PSCustomObject]){
                    foreach($pp in $n.PSObject.Properties){ if($pp.Name -eq 'ManagementServerAddress' -and $pp.Value -is [string] -and $pp.Value){ return [string]$pp.Value } }
                    foreach($pp in $n.PSObject.Properties){ $v = & $find $pp.Value ($depth + 1); if($v){ return $v } }
                } elseif($n -is [System.Collections.IEnumerable] -and $n -isnot [string]){
                    foreach($x in $n){ $v = & $find $x ($depth + 1); if($v){ return $v } }
                }
                ''
            }
            $a = [string](& $find $j 0)
            if($a){ $addr = $a; $src = $f }
        } catch {}
    }
    $esAddr = ''
    if($IsEs){
        try { $v = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Milestone\XProtect Event Server' -Name ManagementServerAddress -ErrorAction Stop).ManagementServerAddress; if($v){ $esAddr = [string]$v } } catch {}
    }
    # Is a Management Server installed on THIS box (standalone / all-in-one / MS node)? Then a loopback or
    # own-name address can be legitimate (see Test-OwnBoxAddress).
    $hasMs = $false; $fq = ''
    try { $hasMs = [bool](Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Milestone XProtect Management Server' }) } catch {}
    try { $dom = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain; if($dom){ $fq = ("$env:COMPUTERNAME.$dom").ToLowerInvariant() } } catch {}
    [pscustomobject]@{ Computer=$env:COMPUTERNAME; Fqdn=$fq; HasMs=$hasMs; Address=$addr; Source=$src; EsAddress=$esAddr }
}
function Get-UrlHost { param([string]$Url)
    $u = ([string]$Url).Trim(); if(-not $u){ return '' }
    try { if($u -match '^[A-Za-z][A-Za-z0-9+.-]*://'){ return ([uri]$u).Host.ToLowerInvariant() } } catch {}
    (($u -split '[/:]')[0]).ToLowerInvariant() }
# Same management server? Equal hosts (a bare short name counts as its FQDN), or IPv4 sets that intersect
# when both are resolved HERE. A name that resolves to an MS cluster NODE instead of the cluster address
# therefore does not match.
function Test-MsAddressMatch { param([string]$Addr,[string]$TargetHost)
    $h = Get-UrlHost $Addr; $t = ([string]$TargetHost).Trim().ToLowerInvariant()
    if(-not $h -or -not $t){ return $true }   # nothing to compare - not a finding
    if($h -eq $t){ return $true }
    $hShort = ($h -notmatch '\.') -and -not (Test-IpAddress $h); $tShort = ($t -notmatch '\.') -and -not (Test-IpAddress $t)
    if(($hShort -and $t.Split('.')[0] -eq $h) -or ($tShort -and $h.Split('.')[0] -eq $t)){ return $true }
    $a = @(Resolve-HostIPv4 $h); $b = @(Resolve-HostIPv4 $t)
    (@($a | Where-Object { $b -contains $_ }).Count -gt 0) }
# The management server this tool works with: the MS cluster address, else this Management Server.
function Get-TargetMsHost { if($script:MsCluster -and $script:MsCluster.Address){ [string]$script:MsCluster.Address } else { [string]$script:MsFqdn } }

# ===================== END OF VERBATIM REUSE =====================

# Ensure-TrustedHosts is deliberately NOT copied from Mrc-Guided.ps1: that version calls
# Set-Item WSMan:\localhost\Client\TrustedHosts -Force, a real change, which this read-only tool must
# never make (docs/doctor/spec.md: "no WinRM TrustedHosts change ... FAIL with the fix command").
# Find-IpConnection / Resolve-NodeConn / Initialize-Targets above call a function of this exact name
# (that call text is part of their verbatim copy) - this is a different, read-only implementation that
# never touches TrustedHosts: it only records which address would have needed trusting, for NET-1 to
# turn into a FAIL. Defined via the function: drive (not a `function` statement) so it is not a
# same-named function Mrc-Guided.ps1 also defines - tools/Test-EngineParity.ps1's parity pass therefore
# has nothing here to compare it against, matching the spec's "is NOT copied".
$script:TrustedHostsGaps = [System.Collections.Generic.List[string]]::new()
${function:Ensure-TrustedHosts} = {
    param([string[]]$Hosts)
    try {
        $cur = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value
        $set = @($cur -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    } catch { $set = @() }
    if ($set -contains '*') { return }   # trust-all already covers every address - nothing missing
    foreach ($h in @($Hosts)) {
        if ($h -and ($set -notcontains $h) -and -not (Test-LocalTarget $h) -and ($script:TrustedHostsGaps -notcontains $h)) {
            [void]$script:TrustedHostsGaps.Add([string]$h)
        }
    }
}

# ===================== DOCTOR: INPUTS / TARGETS =====================
# Read-DoctorInputs is NOT a verbatim copy of Mrc-Guided.ps1's Read-Inputs (that one also validates the
# certificate SAN box, which Doctor has no use for) - same idea, same script-scope variables, so that
# Initialize-Targets below (verbatim) works unmodified.
function Read-DoctorInputs {
    $d=$script:DomainBox.Text.Trim()
    if(-not $d -or $d -match '<[^>]+>'){ throw 'Enter the DNS domain of these computers (for example company.local).' }
    $script:DomainName=Get-DomainSuffix $d
    $script:NoEs=[bool]$script:NoEsChk.Checked
    $e=$script:EsHostBox.Text.Trim()
    if(-not $script:NoEs -and (-not $e -or $e -match '<[^>]+>')){ throw "Enter the name of the Event Server computer, or tick 'The Event Server is on this computer, or not installed'." }
    $script:EsAddr=$e
    $u=$script:AdminUserBox.Text.Trim()
    if(-not $u -or $u -match '<[^>]+>'){ throw 'Enter the admin account (for example COMPANY\Administrator).' }
    if(-not $script:AdminPwBox.Text){ throw 'Enter the password of the admin account.' }
    $script:AdminCred=Get-Cred $u $script:AdminPwBox.Text
    if($script:RecSepChk.Checked){
        $ru=$script:RecUserBox.Text.Trim()
        if(-not $ru -or $ru -match '<[^>]+>'){ throw 'Enter the recording server account, or untick "Recording servers use a different account".' }
        if(-not $script:RecPwBox.Text){ throw 'Enter the password of the recording server account.' }
        $script:RecCred=Get-Cred $ru $script:RecPwBox.Text
    } else { $script:RecCred=$script:AdminCred }
    $mf=[string]$script:Defaults.MsFqdn
    $script:MsFqdn = if($mf -and $mf -notmatch '<[^>]+>'){ $mf.Trim().ToLowerInvariant() } else { (Get-RecorderFqdn -HostName $env:COMPUTERNAME -DomainSuffix $script:DomainName).ToLowerInvariant() }
}

# ---- Initialize-Targets (verbatim from Mrc-Guided.ps1) ----
# Build the box list: this Management Server, the Event Server (unless none), and the recorders
# (discovered from the VMS and/or listed by hand; 'name=address' allowed). Returns the discovery
# error text ('' when discovery worked or was not asked for).
function Initialize-Targets { param([string]$ManualList,[bool]$Discover)
    $script:MsBox = New-Box 'Management Server' $env:COMPUTERNAME $env:COMPUTERNAME $script:MsFqdn $script:AdminCred
    $script:EsBox = $null
    if(-not $script:NoEs){ $script:EsBox = New-Box 'Event Server' $script:EsAddr $script:EsAddr $script:EsAddr $script:AdminCred }
    Initialize-MsCluster
    if($script:NoEs -and -not $script:EsBox){
        # W6: all-in-one. No separate Event Server was given, but if 'Milestone XProtect Event Server' is
        # installed on THIS computer and not Disabled, it still gets its own step (Event Server certificate
        # group) rather than being silently skipped. Runs AFTER Initialize-MsCluster (needs cluster
        # membership) and skips when: this MS is itself clustered (its local ES service, Disabled or not,
        # is either offline by design or belongs to a DIFFERENT cluster role - never a plain local step);
        # or the local ES service is a cluster resource under any OTHER role (a customer site can have it
        # Manual instead of Disabled - the lab's Disabled-only case cannot catch that, so this is checked
        # directly rather than trusting StartType alone).
        try {
            $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $script:EsSvcDisplay } | Select-Object -First 1
            if($svc -and [string]$svc.StartType -ne 'Disabled'){
                $esIsClusterResource = [bool]$script:MsCluster
                if(-not $esIsClusterResource){
                    try {
                        $cs = Get-Service -Name ClusSvc -ErrorAction SilentlyContinue
                        if($cs -and [string]$cs.Status -eq 'Running' -and (Get-Module -ListAvailable -Name FailoverClusters)){
                            Import-Module FailoverClusters -ErrorAction Stop
                            foreach($r in @(Get-ClusterResource -ErrorAction Stop | Where-Object { [string]$_.ResourceType -eq 'Generic Service' })){
                                $sn = try { [string](($r | Get-ClusterParameter -Name ServiceName -ErrorAction Stop).Value) } catch { '' }
                                if($sn -and $sn -eq $svc.Name){ $esIsClusterResource = $true; break }
                            }
                        }
                    } catch { $esIsClusterResource = $false }   # no cluster (or unreadable) = not a resource
                }
                if($esIsClusterResource){
                    Write-Log 'Event Server service on this computer belongs to the cluster role - not handled as a separate step' 'Good'
                } else {
                    $script:EsAddr = $env:COMPUTERNAME
                    $script:EsBox = New-Box 'Event Server' $env:COMPUTERNAME $env:COMPUTERNAME $script:MsFqdn $script:AdminCred
                    Write-Log "The Event Server runs on this computer - it gets its own step." 'Good'
                }
            }
        } catch {}
    }
    $list=[System.Collections.Generic.List[object]]::new(); $seen=@{}
    $add={ param([string]$Name,[string]$Target,[string]$Addr)
        if((Test-LocalTarget $Addr) -or (Test-LocalTarget $Target)){ Write-Log "Recording server '$Name' runs on this Management Server - it is covered by the Management Server step, not handled separately."; return }
        if($script:MsCluster -and @(@($script:MsCluster.Nodes) | Where-Object { [string]$_.Name -eq $Target -or [string]$_.Fqdn -eq $Addr }).Count){ Write-Log "Recording server '$Name' runs on Management Server cluster node $Target - it is covered by the Management Server step, not handled separately."; return }
        $k=$Target.ToUpperInvariant(); if($seen.ContainsKey($k)){ return }; $seen[$k]=$true
        [void]$list.Add((New-Box 'Recording server' $Name $Target $Addr $script:RecCred)) }
    $discErr=''
    # On a clustered Management Server the VMS answers on the cluster address, not on a node name.
    $vmsAddr = [string]$script:MsAddrValue
    if($script:MsCluster -and $script:MsCluster.Address -and ([string]::IsNullOrWhiteSpace($vmsAddr) -or $vmsAddr -match '<[^>]+>')){ $vmsAddr = [string]$script:MsCluster.Address }
    if($Discover){
        try { foreach($r in @(Get-VmsRecorderList -Domain $script:DomainName -VmsCred $script:AdminCred -MsAddrText $vmsAddr)){ & $add $r.Name $r.Target $r.Fqdn } }
        catch { $discErr=([string]$_.Exception.Message).Trim(); Write-Log "Recording server discovery failed: $(Format-Err $_)" 'Err' }
    }
    foreach($h in @(([string]$ManualList) -split '[;,\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })){
        $parts=$h -split '=',2
        if($parts.Count -ge 2){ & $add $parts[0].Trim() (Normalize-RecorderHostName $parts[0]) $parts[1].Trim() }
        else { $isIp = $h -match '^\d{1,3}(\.\d{1,3}){3}$'; & $add $h $(if($isIp){$h}else{Normalize-RecorderHostName $h}) $h }
    }
    $script:RecBoxes=@($list.ToArray())
    # WinRM to a computer addressed by IP needs it in TrustedHosts - before the first state check.
    $ips=@(@($script:EsBox) + @($script:RecBoxes) | Where-Object { $_ -and (Test-IpAddress $_.Addr) } | ForEach-Object { [string]$_.Addr })
    if($ips.Count){ Ensure-TrustedHosts -Hosts $ips }
    Initialize-EsCluster
    $msTxt = if($script:MsCluster){ "cluster '$($script:MsCluster.Group)' ($(@($script:MsCluster.Nodes).Count) nodes)" } else { "$env:COMPUTERNAME ($($script:MsFqdn))" }
    $esTxt = if($script:EsCluster){ "cluster '$($script:EsCluster.Group)' ($(@($script:EsCluster.Nodes).Count) nodes)" } elseif($script:EsBox){ $script:EsAddr } else { '(none)' }
    Write-Log "Computers: Management Server $msTxt; Event Server $esTxt; $(@($script:RecBoxes).Count) recording server(s)" 'Good'
    $discErr
}

# ===================== DOCTOR: COLLECT (one read-only facts scriptblock per box kind) =====================
# NOT verbatim from Mrc-Guided.ps1 - the wizard never needed private-key ACLs, certificate thumbprints,
# IIS state, config file hashes, event logs or SQL reachability. Every scriptblock here is read-only: no
# Set-/Start-/Stop-/Remove-/New-Item/etc (tools/Test-Doctor.ps1 scans this file's AST to prove it).
# Self-contained (no $script: refs, no calls to named functions) so Invoke-OnBox / Invoke-OnNode can run
# them on a remote box exactly like $script:BindingsSb etc - only the scriptblock's own text travels.

# Parse every netsh http sslcert binding into {Addr, Port, Thumbprint} - address:port token per W4 (never
# the localized column label), paired with the following 'Certificate Hash' line in the same block.
$script:SslBindingsSb = {
    $addrRe = '(\d{1,3}(?:\.\d{1,3}){3}):(\d+)|\[([0-9A-Fa-f:]+)\]:(\d+)'
    $raw = $null
    try { $raw = @(netsh http show sslcert 2>&1) } catch { return [pscustomobject]@{ Ok=$false; Error=$_.Exception.Message; Bindings=@() } }
    if ($LASTEXITCODE) { return [pscustomobject]@{ Ok=$false; Error="netsh exited $LASTEXITCODE"; Bindings=@() } }
    $list = New-Object System.Collections.Generic.List[object]
    $cur = $null
    foreach ($ln in $raw) {
        $s = [string]$ln
        $m = [regex]::Match($s, $addrRe)
        if ($m.Success -and $s -match '(IP|Hostname):port') {
            if ($cur) { $list.Add([pscustomobject]$cur) }
            $port = if ($m.Groups[2].Success) { [int]$m.Groups[2].Value } else { [int]$m.Groups[4].Value }
            $cur = @{ Port = $port; Thumbprint = '' }
        } elseif ($cur -and $s -match 'Hash\s*:\s*([0-9A-Fa-f]{20,40})') {
            $cur.Thumbprint = $Matches[1].ToUpperInvariant()
        }
    }
    if ($cur) { $list.Add([pscustomobject]$cur) }
    # WinRM's own HTTPS listener (5986) - and 5985, which never has an sslcert binding anyway - is not a
    # Milestone port; spec: "every non-443/5986 sslcert binding and the 443 binding". Excluded here, once,
    # so ENC-3/ENC-4/IIS-3 (everything built from these Bindings) never examine a WinRM certificate.
    $filtered = @($list.ToArray() | Where-Object { $_.Port -ne 5985 -and $_.Port -ne 5986 })
    [pscustomobject]@{ Ok = $true; Error = ''; Bindings = $filtered }
}

# Certificate details for one thumbprint in LocalMachine\My - subject, SAN, expiry, EKU, chain trust
# (revocation check off, per spec). Read-only: Get-Item / X509Chain.Build only, no store writes.
$script:CertInfoSb = {
    param([string]$Tp)
    try { $c = Get-Item -LiteralPath "Cert:\LocalMachine\My\$Tp" -ErrorAction Stop }
    catch { return [pscustomobject]@{ Found=$false; Thumbprint=$Tp; Subject=''; San=@(); NotAfter=$null; HasPrivateKey=$false; ServerAuthEku=$false; ChainTrusted=$false; ChainError='certificate not found in LocalMachine\My' } }
    $san = New-Object System.Collections.Generic.List[string]
    try {
        $ext = $c.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' } | Select-Object -First 1
        if ($ext) {
            $asn = New-Object System.Security.Cryptography.AsnEncodedData($ext.Oid, $ext.RawData)
            $txt = $asn.Format($true)
            foreach ($ln in ($txt -split "`r?`n")) { if ($ln -match 'DNS Name\s*=\s*(.+)$') { $san.Add($Matches[1].Trim()) } }
        }
    } catch {}
    $eku = @($c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
    $hasServerAuth = $eku -contains '1.3.6.1.5.5.7.3.1'
    $chainOk = $false; $chainErr = ''
    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chainOk = $chain.Build($c)
        if (-not $chainOk) { $chainErr = ((@($chain.ChainStatus) | ForEach-Object { $_.StatusInformation }) -join '; ').Trim() }
    } catch { $chainErr = $_.Exception.Message }
    [pscustomobject]@{
        Found=$true; Thumbprint=$Tp; Subject=[string]$c.Subject; San=$san.ToArray(); NotAfter=$c.NotAfter.ToString('o')
        HasPrivateKey=[bool]$c.HasPrivateKey; ServerAuthEku=$hasServerAuth; ChainTrusted=$chainOk; ChainError=$chainErr
    }
}

# Read-only equivalent of Mrc-Guided.ps1's $script:KeyGrantSb: same private-key-file lookup, but only
# CHECKS whether the Milestone service account already has Read - never calls Set-Acl.
$script:KeyAccessSb = {
    param([string]$Tp,[string]$Dn)
    $svc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $Dn } | Select-Object -First 1
    if (-not $svc) { return [pscustomobject]@{ Account=''; Readable=$null; Note="service '$Dn' not found" } }
    $acct = [string]$svc.StartName
    if (-not $acct -or $acct -match '^(NT AUTHORITY\\)?Network ?Service$' -or $acct -match '^(LocalSystem|NT AUTHORITY\\SYSTEM)$') {
        return [pscustomobject]@{ Account=$acct; Readable=$true; Note='built-in account - no extra permission needed' }
    }
    if ($acct.StartsWith('.\')) { $acct = "$env:COMPUTERNAME\$($acct.Substring(2))" }
    try {
        $c = Get-Item -LiteralPath "Cert:\LocalMachine\My\$Tp" -ErrorAction Stop
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
        $keyName = $null
        if ($rsa -and $rsa.PSObject.Properties['Key'] -and $rsa.Key) { $keyName = $rsa.Key.UniqueName }
        elseif ($c.PrivateKey) { $keyName = $c.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName }
        if (-not $keyName) { return [pscustomobject]@{ Account=$acct; Readable=$null; Note='private key not found in the store' } }
        $keyFile = $null
        foreach ($d in @("$env:ProgramData\Microsoft\Crypto\Keys", "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys")) {
            $p = Join-Path $d $keyName
            if (Test-Path -LiteralPath $p) { $keyFile = $p; break }
        }
        if (-not $keyFile) { return [pscustomobject]@{ Account=$acct; Readable=$null; Note='private key file not located on disk' } }
        $kAcl = Get-Acl -Path $keyFile
        $short = ($acct -split '\\')[-1]
        $has = [bool](@($kAcl.Access) | Where-Object { ($_.FileSystemRights -match 'Read|FullControl') -and (([string]$_.IdentityReference) -eq $acct -or ([string]$_.IdentityReference) -match [regex]::Escape($short)) })
        [pscustomobject]@{ Account=$acct; Readable=$has; Note=$(if($has){'has Read on the private key'}else{'no Read grant found on the private key for this account'}) }
    } catch { [pscustomobject]@{ Account=$acct; Readable=$null; Note="could not read the private key ACL: $($_.Exception.Message)" } }
}

function Get-MilestoneServices { param([string]$Prefix='Milestone')
    @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Milestone*' -or $_.Name -like 'Milestone*' -or $_.Name -like 'VideoOS*' } | ForEach-Object {
        $exe=''; $ver=''
        try { if([string]$_.PathName -match '^\s*"?([^"]+?\.exe)'){ $exe=$Matches[1]; if(Test-Path -LiteralPath $exe){ $ver=[string](Get-Item -LiteralPath $exe).VersionInfo.ProductVersion } } } catch {}
        [pscustomobject]@{ Name=[string]$_.Name; DisplayName=[string]$_.DisplayName; State=[string]$_.State; StartMode=[string]$_.StartMode; StartName=[string]$_.StartName; ExePath=$exe; ExeVersion=$ver }
    })
}

# Identity + services + media folders - every box kind needs this, so it is its own scriptblock.
$script:FactsCommonSb = {
    $out = [ordered]@{}
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $ips = @([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString })
        $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction SilentlyContinue
        $out.Identity = [pscustomobject]@{
            ComputerName=$env:COMPUTERNAME; Fqdn=$(if($cs.Domain){"$env:COMPUTERNAME.$($cs.Domain)".ToLowerInvariant()}else{$env:COMPUTERNAME})
            Ips=$ips; UtcNow=[DateTime]::UtcNow.ToString('o'); OsCaption=[string]$os.Caption; OsBuild=[string]$os.BuildNumber
            MemFreeMb=[math]::Round($os.FreePhysicalMemory/1024); MemTotalMb=[math]::Round($cs.TotalPhysicalMemory/1MB)
            SysDriveFreeGb=$(if($drive){[math]::Round($drive.FreeSpace/1GB,1)}else{$null}); SysDriveTotalGb=$(if($drive){[math]::Round($drive.Size/1GB,1)}else{$null})
        }
    } catch { $out.Identity = $null; $out.IdentityError = $_.Exception.Message }
    $media = New-Object System.Collections.Generic.List[object]
    try {
        $mp = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\VideoOS\Recorder\Installation' -Name MediaDBFolder -ErrorAction Stop
        if ($mp.MediaDBFolder) {
            foreach ($folder in (([string]$mp.MediaDBFolder) -split ';' | Where-Object { $_ })) {
                try {
                    $root = [IO.Path]::GetPathRoot($folder)
                    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($root.TrimEnd('\'))'" -ErrorAction SilentlyContinue
                    $media.Add([pscustomobject]@{ Path=$folder; FreeGb=$(if($d){[math]::Round($d.FreeSpace/1GB,1)}else{$null}); TotalGb=$(if($d){[math]::Round($d.Size/1GB,1)}else{$null}) })
                } catch {}
            }
        }
    } catch {}
    $out.Media = $media.ToArray()
    $svcs = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.DisplayName -like 'Milestone*' -or $_.Name -like 'Milestone*' -or $_.Name -like 'VideoOS*' })) {
            $exe=''; $ver=''
            try { if ([string]$s.PathName -match '^\s*"?([^"]+?\.exe)') { $exe=$Matches[1]; if (Test-Path -LiteralPath $exe) { $ver=[string](Get-Item -LiteralPath $exe).VersionInfo.ProductVersion } } } catch {}
            $svcs.Add([pscustomobject]@{ Name=[string]$s.Name; DisplayName=[string]$s.DisplayName; State=[string]$s.State; StartMode=[string]$s.StartMode; StartName=[string]$s.StartName; ExePath=$exe; ExeVersion=$ver })
        }
    } catch {}
    $out.Services = $svcs.ToArray()
    # Clock skew reference: this box's own UTC now, compared by the caller (Collect runs right after).
    [pscustomobject]$out
}

# MS-only facts: registered addresses (registry side, RegAddrSb covers the Data Collector JSON side
# separately), connection strings, web ports, IIS, config file hashes, event log, SQL reachability.
$script:FactsMsSb = {
    $out = [ordered]@{}
    $regEntries = New-Object System.Collections.Generic.List[object]
    $regTry = {
        param($path,$name,$label)
        try { $v = (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop).$name; if ($v) { return [string]$v } } catch {}
        return $null
    }
    foreach ($x in @(
        @('HKLM:\SOFTWARE\WOW6432Node\Milestone\XProtect Event Server','ManagementServerAddress','Event Server (registry)'),
        @('HKLM:\SOFTWARE\Milestone\XProtect Log Server','ManagementServerUrl','Log Server'),
        @('HKLM:\SOFTWARE\Milestone\XProtect Incident Manager','ManagementServerAddress','Incident Manager'),
        @('HKLM:\SOFTWARE\VideoOS\GatewayService','ServiceUrl','Gateway Service')
    )) {
        $v = & $regTry $x[0] $x[1] $x[2]
        if ($v) { $regEntries.Add([pscustomobject]@{ Source=$x[2]; Value=$v }) }
    }
    $out.RegAddr = $regEntries.ToArray()
    # Connection strings (Data Source / Initial Catalog only - never a password/user id).
    $cs = New-Object System.Collections.Generic.List[object]
    try {
        $vals = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\VideoOS\Server\ConnectionString' -ErrorAction Stop
        foreach ($p in $vals.PSObject.Properties) {
            if ($p.Name -match '^PS') { continue }
            $v = [string]$p.Value
            $ds = ''; $cat = ''; $isec = $false
            foreach ($part in ($v -split ';')) {
                if ($part -match '^\s*Data Source\s*=\s*(.+)$') { $ds = $Matches[1].Trim() }
                elseif ($part -match '^\s*Initial Catalog\s*=\s*(.+)$') { $cat = $Matches[1].Trim() }
                elseif ($part -match '^\s*Integrated Security\s*=\s*(.+)$') { $isec = ($Matches[1].Trim() -match '^(true|sspi|yes)$') }
            }
            $cs.Add([pscustomobject]@{ Name=[string]$p.Name; DataSource=$ds; Catalog=$cat; IntegratedSecurity=$isec })
        }
    } catch {}
    $out.ConnStrings = $cs.ToArray()
    # Web ports
    $ports = [pscustomobject]@{ Http=$null; Https=$null; ServerPort=$null; VmoPort=$null; HttpsPort=$null }
    try {
        $wi = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\VideoOS\Installation\Server' -ErrorAction Stop
        if ($wi.PSObject.Properties['WebSitePort']) { $ports.Http = [string]$wi.WebSitePort }
        if ($wi.PSObject.Properties['WebSiteSecurePort']) { $ports.Https = [string]$wi.WebSiteSecurePort }
    } catch {}
    try {
        $scPath = Join-Path $env:ProgramData 'Milestone\XProtect Management Server\ServerConfig.xml'
        if (Test-Path -LiteralPath $scPath) {
            $x = [xml](Get-Content -LiteralPath $scPath -Raw)
            $ports.ServerPort = [string]$x.SelectSingleNode('/server/serverport/port').InnerText
            $ports.VmoPort = [string]$x.SelectSingleNode('/server/VMOCommunication/Port').InnerText
            $ports.HttpsPort = [string]$x.SelectSingleNode('/server/HttpsPort').InnerText
        }
    } catch {}
    $out.Ports = $ports
    # IIS
    $iis = [pscustomobject]@{ Ok=$false; Error=''; W3svc=''; Was=''; SiteState=''; Bindings=@(); Apps=@(); Pools=@() }
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $iis.W3svc = [string](Get-Service -Name W3SVC -ErrorAction SilentlyContinue).Status
        $iis.Was = [string](Get-Service -Name WAS -ErrorAction SilentlyContinue).Status
        $site = Get-Website -Name 'Default Web Site' -ErrorAction SilentlyContinue
        if ($site) {
            $iis.SiteState = [string]$site.State
            $iis.Bindings = @($site.Bindings.Collection | ForEach-Object { [string]$_.bindingInformation + ' (' + [string]$_.protocol + ')' })
            $apps = New-Object System.Collections.Generic.List[object]
            foreach ($a in @(Get-WebApplication -Site 'Default Web Site' -ErrorAction SilentlyContinue)) {
                $apps.Add([pscustomobject]@{ Path=[string]$a.Path; Pool=[string]$a.applicationPool })
            }
            $iis.Apps = $apps.ToArray()
        }
        $pools = New-Object System.Collections.Generic.List[object]
        foreach ($p in @(Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'VideoOS*' -or $_.Name -like '*Milestone*' })) {
            $pools.Add([pscustomobject]@{ Name=[string]$p.Name; State=[string]$p.State; IdentityType=[string]$p.processModel.identityType; UserName=[string]$p.processModel.userName })
        }
        $iis.Pools = $pools.ToArray()
        $iis.Ok = $true
    } catch { $iis.Error = $_.Exception.Message }
    $out.Iis = $iis
    # Config files (parse-try + sha256, path only - never opened as a secret store)
    $cfgList = New-Object System.Collections.Generic.List[object]
    $checkCfg = {
        param($path,$kind)
        if (-not (Test-Path -LiteralPath $path)) { return $null }
        $ok = $true; $err = ''
        try { if ($kind -eq 'xml') { [void][xml](Get-Content -LiteralPath $path -Raw) } else { [void](Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } }
        catch { $ok = $false; $err = $_.Exception.Message }
        $sha = ''
        try { $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
        [pscustomobject]@{ Path=$path; Ok=$ok; Error=$err; Sha256=$sha }
    }
    $msRoot = Join-Path $env:ProgramData 'Milestone\XProtect Management Server'
    foreach ($c in @(
        @((Join-Path $msRoot 'ServerConfig.xml'),'xml'),
        @((Join-Path $msRoot 'ServiceEndpoints.xml'),'xml'),
        @('C:\inetpub\wwwroot\ManagementServer\IIS\ManagementServer\Web.config','xml'),
        @('C:\inetpub\wwwroot\ManagementServer\IIS\IDP\appsettings.json','json')
    )) { $r = & $checkCfg $c[0] $c[1]; if ($r) { $cfgList.Add($r) } }
    try {
        foreach ($svc in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Milestone XProtect Data Collector Server' -or $_.Name -like '*ApiGateway*' })) {
            if ([string]$svc.PathName -match '^\s*"?([^"]+?\.exe)') {
                $d = [IO.Path]::GetDirectoryName($Matches[1])
                if ($d) { $r = & $checkCfg (Join-Path $d 'appsettings.json') 'json'; if ($r) { $cfgList.Add($r) } }
            }
        }
    } catch {}
    $out.ConfigFiles = $cfgList.ToArray()
    # Event log (Application, last 24h, Milestone/VideoOS providers, Error/Warning)
    $ev = [pscustomobject]@{ Ok=$false; Error=''; ErrorCount=0; WarnCount=0; Top=@(); InvalidClient=$false; CertSsl=$false; CouldNotStop=$false }
    try {
        $since = (Get-Date).AddHours(-24)
        $entries = @(Get-WinEvent -FilterHashtable @{ LogName='Application'; Level=2,3; StartTime=$since } -ErrorAction Stop | Where-Object { $_.ProviderName -match 'Milestone|VideoOS' })
        $ev.ErrorCount = @($entries | Where-Object { $_.Level -eq 2 }).Count
        $ev.WarnCount = @($entries | Where-Object { $_.Level -eq 3 }).Count
        $grp = $entries | Group-Object { ($_.Message -split "`r?`n")[0] } | Sort-Object Count -Descending | Select-Object -First 5
        $ev.Top = @($grp | ForEach-Object { [pscustomobject]@{ Line=[string]$_.Name; Count=$_.Count } })
        $txt = ($entries | ForEach-Object { $_.Message }) -join ' '
        $ev.InvalidClient = [bool]($txt -match 'invalid_client')
        $ev.CertSsl = [bool]($txt -match 'certificate|SSL|TLS')
        $ev.CouldNotStop = [bool]($txt -match 'Could not stop service')
        $ev.Ok = $true
    } catch { $ev.Error = $_.Exception.Message }
    $out.EventLog = $ev
    # SQL reachability - DNS + TCP + SqlConnection open, 5s timeout, never a password.
    $sqlList = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($c in @($out.ConnStrings)) {
        if (-not $c.DataSource -or $seen.ContainsKey($c.DataSource.ToLowerInvariant())) { continue }
        $seen[$c.DataSource.ToLowerInvariant()] = $true
        $ds = $c.DataSource
        $named = $ds -match '\\'
        $hostPart = ($ds -split '\\')[0] -split ',' | Select-Object -First 1
        $portPart = if ($ds -match ',(\d+)') { [int]$Matches[1] } else { 1433 }
        $row = [pscustomobject]@{ DataSource=$ds; DnsOk=$false; TcpOk=$false; TcpMs=$null; OpenOk=$false; OpenMs=$null; Note='' }
        try { [void][System.Net.Dns]::GetHostAddresses($hostPart); $row.DnsOk = $true } catch { $row.Note = 'DNS resolve failed'; $sqlList.Add($row); continue }
        if ($named) { $row.Note = 'named instance, port not checked'; $sqlList.Add($row); continue }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($hostPart, $portPart, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(5000)) { $tc.EndConnect($iar); $row.TcpOk = $tc.Connected }
            $tc.Close()
        } catch {}
        $row.TcpMs = [int]$sw.ElapsedMilliseconds
        if ($row.TcpOk) {
            $sw2 = [Diagnostics.Stopwatch]::StartNew()
            try {
                $csb = "Data Source=$ds;Initial Catalog=$($c.Catalog);Integrated Security=True;Connection Timeout=5"
                $conn = New-Object System.Data.SqlClient.SqlConnection($csb)
                $conn.Open(); $conn.Close(); $row.OpenOk = $true
            } catch {
                if ($_.Exception.Message -match 'login failed|cannot open|permission') { $row.OpenOk = $true; $row.Note = 'reachable (login refused for this account)' }
                else { $row.Note = $_.Exception.Message }
            }
            $row.OpenMs = [int]$sw2.ElapsedMilliseconds
        }
        $sqlList.Add($row)
    }
    $out.Sql = $sqlList.ToArray()
    [pscustomobject]$out
}

# ES-only facts: registered MS address (registry) + ServerConfigurator log.
$script:FactsEsSb = {
    $out = [ordered]@{}
    $addr = $null
    try { $v = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Milestone\XProtect Event Server' -Name ManagementServerAddress -ErrorAction Stop).ManagementServerAddress; if ($v) { $addr = [string]$v } } catch {}
    $out.RegAddr = $addr
    [pscustomobject]$out
}

# Recorder-only facts: RecorderConfig.xml server + auth server address.
$script:FactsRecSb = {
    $out = [ordered]@{}
    $srv = $null; $auth = $null
    try {
        $p = Join-Path $env:ProgramData 'Milestone\XProtect Recording Server\RecorderConfig.xml'
        if (Test-Path -LiteralPath $p) {
            $x = [xml](Get-Content -LiteralPath $p -Raw)
            $n1 = $x.SelectSingleNode('/recorderconfig/server/address'); if ($n1) { $srv = [string]$n1.InnerText }
            $n2 = $x.SelectSingleNode('/recorderconfig/server/authorizationserveraddress'); if ($n2) { $auth = [string]$n2.InnerText }
        }
    } catch {}
    $out.ServerAddress = $srv; $out.AuthServerAddress = $auth
    [pscustomobject]$out
}

# ServerConfigurator log: the newest timestamp of the line that is really "this node just took over the
# MS IDP client secret" - 'ManagementServerClientEndpointRegistrar.RegisterClient' ... Status = Success
# (lab-verified 2026-09-29, appears on every SC encryption enable/disable run on an MS node). 'Registration
# done with result = Success' is kept only as a secondary/fallback pattern. Searches every *.log file,
# newest file first, last 5000 lines each, scanned newest-line-first within the file, and stops at the
# first hit (lab fix round 2). Timestamps carry a UTC offset (e.g. +02:00) - parsed with DateTimeOffset
# and reported in UTC so nodes in different time zones still compare correctly.
$script:ScLogSb = {
    $out = [pscustomobject]@{ Found=$false; LastRegisteredUtc=$null; LastMsAddress='' }
    try {
        $dir = Join-Path $env:ProgramData 'Milestone\Server Configurator\Logs'
        $files = @(Get-ChildItem -LiteralPath $dir -Filter '*.log' -ErrorAction Stop | Sort-Object LastWriteTime -Descending)
        if ($files.Count) { $out.Found = $true }
        $tsPat = '\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?'
        $primaryRe = "(?<ts>$tsPat).*RegisterClient.*Status\s*=\s*Success"
        $secondaryRe = "(?<ts>$tsPat).*Registration done with result\s*=\s*Success"
        $secondaryNoTsRe = 'Registration done with result\s*=\s*Success'
        foreach ($f in $files) {
            $lines = @(Get-Content -LiteralPath $f.FullName -Tail 5000 -ErrorAction Stop)
            $hit = $null
            for ($i = $lines.Count - 1; $i -ge 0; $i--) { if ($lines[$i] -match $primaryRe) { $hit = $Matches['ts']; break } }
            if (-not $hit) { for ($i = $lines.Count - 1; $i -ge 0; $i--) { if ($lines[$i] -match $secondaryRe) { $hit = $Matches['ts']; break } } }
            if (-not $hit) { for ($i = $lines.Count - 1; $i -ge 0; $i--) { if ($lines[$i] -match $secondaryNoTsRe) { $hit = 'unknown-time'; break } } }
            if ($hit) {
                if ($hit -eq 'unknown-time') { $out.LastRegisteredUtc = 'unknown-time' }
                else {
                    $parsedUtc = $null
                    try { $parsedUtc = ([DateTimeOffset]::Parse($hit, [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime } catch {}
                    if (-not $parsedUtc) { try { $parsedUtc = [DateTime]::Parse($hit, [Globalization.CultureInfo]::InvariantCulture) } catch {} }
                    $out.LastRegisteredUtc = if ($parsedUtc) { $parsedUtc.ToString('o') } else { 'unknown-time' }
                }
                break
            }
        }
        if ($files.Count) {
            $lines0 = @(Get-Content -LiteralPath $files[0].FullName -Tail 5000 -ErrorAction Stop)
            foreach ($ln in $lines0) { if ($ln -match 'ManagementServer for Unsecure communication is set to\s*(\S+)') { $out.LastMsAddress = $Matches[1] } }
        }
    } catch {}
    $out
}

# One Facts object for a box, combining the scriptblocks above (several small round trips, same pattern
# Mrc-Guided.ps1 itself uses for BindingsSb / ScFindSb / RegAddrSb - never merged into one giant call).
# -- ONE remote/local round trip per box (lab fix round 1) ----------------------------------------
# Every part's SOURCE TEXT (never the scriptblock object) travels as a string argument and is rebuilt
# with [scriptblock]::Create INSIDE the target process/session - a scriptblock object invoked with '&'
# in the CURRENT runspace is not a closure and can see the caller's variables (this caused the lab's
# in-process "property cannot be found" failures); text rebuilt fresh in a brand-new runspace (this
# computer) or a real remote session (WinRM) cannot reach any Mrc-Doctor.ps1 variable. Each part runs in
# its OWN try/catch so one failing part never hides the rest and never turns into a false "unreachable".
$script:CollectBundleSb = {
    param([object[]]$Jobs,[string]$CertInfoText,[string]$KeyAccessText,[string]$SvcDisplay)
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    $results = @{}; $errors = @{}
    foreach ($j in @($Jobs)) {
        try {
            $sb = [scriptblock]::Create([string]$j.Text)
            $a = @($j.Args)
            $results[[string]$j.Name] = if ($a.Count) { & $sb @a } else { & $sb }
        } catch {
            $stackLine = ((([string]$_.ScriptStackTrace) -split "`r?`n") | Select-Object -First 1)
            $errors[[string]$j.Name] = "$($_.Exception.GetType().Name): $($_.Exception.Message) @ $stackLine"
        }
    }
    # One extra pass, SAME round trip: certificate detail per bound thumbprint (needs Ssl's own result -
    # so it cannot be a job upfront; this is why it is NOT folded into the $Jobs loop above).
    $certs = New-Object System.Collections.Generic.List[object]
    if ($results.ContainsKey('Ssl') -and $CertInfoText -and $KeyAccessText) {
        try {
            $ciSb = [scriptblock]::Create($CertInfoText)
            $kaSb = [scriptblock]::Create($KeyAccessText)
            foreach ($b in @($results['Ssl'].Bindings)) {
                if (-not $b.Thumbprint) { continue }
                $ci = $null; $ka = $null
                try { $ci = & $ciSb $b.Thumbprint } catch {}
                try { $ka = & $kaSb $b.Thumbprint $SvcDisplay } catch {}
                $certs.Add([pscustomobject]@{
                    Port=$b.Port; Thumbprint=$b.Thumbprint
                    Found=$(if($ci){$ci.Found}else{$false}); Subject=$(if($ci){$ci.Subject}else{''}); San=$(if($ci){$ci.San}else{@()})
                    NotAfter=$(if($ci){$ci.NotAfter}else{$null}); HasPrivateKey=$(if($ci){$ci.HasPrivateKey}else{$false})
                    ServerAuthEku=$(if($ci){$ci.ServerAuthEku}else{$false}); ChainTrusted=$(if($ci){$ci.ChainTrusted}else{$false}); ChainError=$(if($ci){$ci.ChainError}else{''})
                    KeyAccount=$(if($ka){$ka.Account}else{''}); KeyReadable=$(if($ka){$ka.Readable}else{$null})
                })
            }
        } catch { $errors['Certs'] = "$($_.Exception.GetType().Name): $($_.Exception.Message)" }
    }
    [pscustomobject]@{ Results=$results; Errors=$errors; Certs=$certs.ToArray(); UtcNow=[DateTime]::UtcNow.ToString('o') }
}
# The job list for one box kind - every part's TEXT (ToString of the verbatim scriptblocks above) plus
# its arguments. Identical for every recorder, so ONE list is reused across the whole fan-out.
function Get-CollectJobs { param([string]$Kind)
    $jobs = New-Object System.Collections.Generic.List[object]
    $jobs.Add([pscustomobject]@{ Name='Common';   Text=$script:FactsCommonSb.ToString(); Args=@() })
    $jobs.Add([pscustomobject]@{ Name='ScFinder'; Text=$script:ScFindSb.ToString();      Args=@($script:ScSearchPaths) })
    $jobs.Add([pscustomobject]@{ Name='ScLog';    Text=$script:ScLogSb.ToString();       Args=@() })
    $jobs.Add([pscustomobject]@{ Name='Ssl';      Text=$script:SslBindingsSb.ToString(); Args=@() })
    switch ($Kind) {
        'MS' {
            $jobs.Add([pscustomobject]@{ Name='Enc'; Text=$script:BindingsSb.ToString(); Args=@() })
            $jobs.Add([pscustomobject]@{ Name='Ms';  Text=$script:FactsMsSb.ToString();  Args=@() })
            $jobs.Add([pscustomobject]@{ Name='RegAddr'; Text=$script:RegAddrSb.ToString(); Args=@($false) })
        }
        'ES' {
            $jobs.Add([pscustomobject]@{ Name='Enc'; Text=$script:EsStateSb.ToString(); Args=@() })
            $jobs.Add([pscustomobject]@{ Name='Es';  Text=$script:FactsEsSb.ToString(); Args=@() })
            $jobs.Add([pscustomobject]@{ Name='RegAddr'; Text=$script:RegAddrSb.ToString(); Args=@($true) })
        }
        default {
            $jobs.Add([pscustomobject]@{ Name='Enc'; Text=$script:RecorderStateSb.ToString(); Args=@() })
            $jobs.Add([pscustomobject]@{ Name='Rec'; Text=$script:FactsRecSb.ToString(); Args=@() })
            $jobs.Add([pscustomobject]@{ Name='RegAddr'; Text=$script:RegAddrSb.ToString(); Args=@($false) })
        }
    }
    $jobs.ToArray()
}
function Get-SvcDisplayFor { param([string]$Kind) switch ($Kind) { 'MS' { 'Milestone XProtect Management Server' } 'ES' { 'Milestone XProtect Event Server' } default { 'Milestone XProtect Recording Server' } } }
# Run the bundle once against ONE box: node path (Invoke-OnNode), host path (Invoke-OnBox), or - for
# THIS computer - a fresh, isolated runspace ([powershell]::Create), never '&' in the current runspace.
function Invoke-CollectBundleOn { param($Box,[object[]]$Jobs)
    $ciText = $script:CertInfoSb.ToString(); $kaText = $script:KeyAccessSb.ToString(); $svcDn = Get-SvcDisplayFor (Get-BoxKind $Box)
    $t0 = [DateTime]::UtcNow; $out = $null; $connErr = ''
    try {
        if ($Box.IsNode) {
            $out = Get-First -Items @(Invoke-OnNode -Node $Box.Target -Cred $Box.Cred -Sb $script:CollectBundleSb -ArgumentList @($Jobs,$ciText,$kaText,$svcDn))
        } elseif (Test-LocalTarget $Box.Addr) {
            $ps = [powershell]::Create()
            try {
                [void]$ps.AddScript([scriptblock]::Create($script:CollectBundleSb.ToString()))
                [void]$ps.AddArgument($Jobs); [void]$ps.AddArgument($ciText); [void]$ps.AddArgument($kaText); [void]$ps.AddArgument($svcDn)
                $out = Get-First -Items @($ps.Invoke())
                if (-not $out -and $ps.HadErrors) { $e = Get-First -Items @($ps.Streams.Error); if ($e) { throw $e.Exception } }
            } finally { $ps.Dispose() }
        } else {
            $out = Get-First -Items @(Invoke-OnBox -Computer $Box.Addr -Cred $Box.Cred -Sb $script:CollectBundleSb -ArgumentList @($Jobs,$ciText,$kaText,$svcDn))
        }
    } catch { $connErr = Get-FirstLine $_.Exception.Message }
    $t1 = [DateTime]::UtcNow
    [pscustomobject]@{ Out=$out; ConnError=$connErr; T0=$t0; T1=$t1 }
}
# Fill a box's Facts from ONE bundle response (Complete-BoxFacts never itself makes a remote call).
# Reachable = the 'Common' job returned - every OTHER part's failure becomes a CollectErrors entry
# (-> a WARN row in its own area, never a NET-1 FAIL). Clock offset/uncertainty per fix #4: measured
# around the SAME round trip (t0/t1 here), never against a time taken minutes apart.
function Complete-BoxFacts { param($f,[bool]$IsLocal,$Bundle)
    if ($IsLocal) { $f.ClockOffsetSec = 0.0; $f.ClockUncertaintySec = 0.0 }
    if (-not $Bundle -or $Bundle.ConnError -or -not $Bundle.Out) {
        $f.Reachable = $false
        $f.ConnError = if ($Bundle -and $Bundle.ConnError) { $Bundle.ConnError } else { 'no response' }
        return $f
    }
    $out = $Bundle.Out
    $results = $out.Results; $errs = $out.Errors
    $f.CollectErrors = @(@($errs.Keys) | Sort-Object | ForEach-Object { [pscustomobject]@{ Part=$_; Error=$errs[$_] } })
    foreach ($e in $f.CollectErrors) { Write-Log "[$($f.Name)] could not read $($e.Part): $($e.Error)" 'Err' }
    if (-not $results.ContainsKey('Common')) {
        $f.Reachable = $false
        $f.ConnError = if ($errs.ContainsKey('Common')) { $errs['Common'] } else { 'Common facts not returned' }
        return $f
    }
    $f.Reachable = $true
    $f.Common = $results['Common']
    if ($results.ContainsKey('ScFinder')) { $f.ScFinder = $results['ScFinder'] }
    if ($results.ContainsKey('ScLog')) { $f.ScLog = $results['ScLog'] }
    if ($results.ContainsKey('Ssl')) { $f.Ssl = $results['Ssl'] }
    if ($results.ContainsKey('Enc')) { $f.Enc = $results['Enc'] }
    if ($results.ContainsKey('Ms')) { $f.Ms = $results['Ms'] }
    if ($results.ContainsKey('Es')) { $f.Es = $results['Es'] }
    if ($results.ContainsKey('Rec')) { $f.Rec = $results['Rec'] }
    $f.Certs = @($out.Certs); $f.KeyAccess = $f.Certs
    $entries = New-Object System.Collections.Generic.List[object]
    if ($results.ContainsKey('RegAddr')) {
        $regRes = $results['RegAddr']
        if ($regRes.Address) { $entries.Add([pscustomobject]@{ Source='Data Collector (appsettings.json)'; Value=$regRes.Address }) }
        if ($f.Kind -eq 'ES' -and $regRes.EsAddress) { $entries.Add([pscustomobject]@{ Source='Event Server (registry)'; Value=$regRes.EsAddress }) }
    }
    if ($f.Kind -eq 'MS' -and $f.Ms) { foreach ($e2 in @($f.Ms.RegAddr)) { $entries.Add($e2) } }
    if ($f.Kind -eq 'REC' -and $f.Rec) {
        if ($f.Rec.ServerAddress) { $entries.Add([pscustomobject]@{ Source='RecorderConfig.xml (server/address)'; Value=$f.Rec.ServerAddress }) }
        if ($f.Rec.AuthServerAddress) { $entries.Add([pscustomobject]@{ Source='RecorderConfig.xml (authorizationserveraddress)'; Value=$f.Rec.AuthServerAddress }) }
    }
    $f.RegAddr = $entries.ToArray()
    if (-not $IsLocal -and $out.PSObject.Properties['UtcNow'] -and $out.UtcNow) {
        try {
            $remote = [DateTime]::Parse([string]$out.UtcNow, $null, [Globalization.DateTimeStyles]::RoundtripKind)
            $mid = $Bundle.T0.AddTicks([int64](($Bundle.T1 - $Bundle.T0).Ticks / 2))
            $f.ClockOffsetSec = ($remote - $mid).TotalSeconds
            $f.ClockUncertaintySec = ($Bundle.T1 - $Bundle.T0).TotalSeconds / 2
        } catch {}
    }
    $f
}
function New-BoxFactsSkeleton { param($Box)
    $kind = Get-BoxKind $Box
    [ordered]@{
        Kind=$kind; Name=[string]$Box.Name; Target=[string]$Box.Target; Addr=[string]$Box.Addr
        IsNode=[bool]$Box.IsNode; ClusterKey=[string]$Box.ClusterKey; Active=[bool]$Box.Active
        Reachable=$false; ConnError=''; CollectErrors=@()
        Common=$null; Enc=$null; ScFinder=$null; RegAddr=@(); Ssl=$null; KeyAccess=@(); ScLog=$null
        Ms=$null; Es=$null; Rec=$null; Dns=$null; PortProbe=@(); Certs=@()
        ClockOffsetSec=$null; ClockUncertaintySec=$null
    }
}
# DNS (NET-2) and TCP port probe (NET-3) - always from THIS computer, regardless of WinRM reachability.
function Add-LocalFacts { param($f,$Box)
    $kind = $f.Kind
    try {
        $fwd = @(Resolve-HostIPv4 $Box.Target)
        $rev = New-Object System.Collections.Generic.List[string]
        foreach ($ip in $fwd) { try { $rev.Add(([System.Net.Dns]::GetHostEntry($ip)).HostName) } catch {} }
        $f.Dns = [pscustomobject]@{ Forward=$fwd; Reverse=$rev.ToArray() }
    } catch { $f.Dns = [pscustomobject]@{ Forward=@(); Reverse=@() } }
    $probePorts = switch ($kind) { 'MS' { @(80,443,9000,9001) } 'ES' { @(22331) } default { @(7563,9001) } }
    $portRows = New-Object System.Collections.Generic.List[object]
    foreach ($p in $probePorts) {
        $open = $false
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Box.Addr, $p, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(3000)) { $tc.EndConnect($iar); $open = $tc.Connected }
            $tc.Close()
        } catch {}
        $portRows.Add([pscustomobject]@{ Port=$p; Open=$open })
    }
    $f.PortProbe = $portRows.ToArray()
}
# One box, one remote/local round trip (MS / ES / cluster node - not fanned-out recorders, see
# Invoke-DoctorCollect, which uses Invoke-CollectBundleFanOut for those instead).
function Get-BoxFacts { param($Box)
    $f = [pscustomobject](New-BoxFactsSkeleton $Box)
    Add-LocalFacts $f $Box
    $jobs = Get-CollectJobs (Get-BoxKind $Box)
    $bundle = Invoke-CollectBundleOn $Box $jobs
    Complete-BoxFacts $f (Test-LocalTarget $Box.Addr) $bundle
}
# All recorders, ONE Invoke-Command -ComputerName @(addresses) -ThrottleLimit 32 fan-out (verbatim
# Invoke-RecorderFanOut, resolved connection addresses via Get-ConnAddr first) - never one-by-one.
function Invoke-CollectBundleFanOut { param([object[]]$Boxes)
    if (-not @($Boxes).Count) { return @() }
    $jobs = Get-CollectJobs 'REC'
    $ciText = $script:CertInfoSb.ToString(); $kaText = $script:KeyAccessSb.ToString(); $svcDn = Get-SvcDisplayFor 'REC'
    $t0 = [DateTime]::UtcNow
    $byAddr = Invoke-RecorderFanOut -Boxes $Boxes -Sb $script:CollectBundleSb -ArgumentList @($jobs,$ciText,$kaText,$svcDn)
    $t1 = [DateTime]::UtcNow
    foreach ($b in @($Boxes)) {
        $f = [pscustomobject](New-BoxFactsSkeleton $b)
        Add-LocalFacts $f $b
        $out = if ($byAddr.ContainsKey([string]$b.Addr)) { $byAddr[[string]$b.Addr] } else { $null }
        $connErr = if (-not $out) { 'could not be reached over WinRM (fan-out) - check it is powered on and WinRM is enabled' } else { '' }
        $bundle = [pscustomobject]@{ Out=$out; ConnError=$connErr; T0=$t0; T1=$t1 }
        Complete-BoxFacts $f $false $bundle
    }
}

function Get-ClusterFacts { param([string]$Key)
    $cl = Get-ClusterObj $Key; if (-not $cl) { return $null }
    [pscustomobject]@{
        Key=$Key; Group=$cl.Group; State=$cl.State; Owner=$cl.Owner; NetName=$cl.NetName; Address=$cl.Address
        Nodes=@($cl.Nodes | ForEach-Object { [pscustomobject]@{ Name=[string]$_.Name; Fqdn=[string]$_.Fqdn; State=[string]$_.State } })
        Offline=@($cl.Offline | ForEach-Object { [pscustomobject]@{ Name=[string]$_.Name; Type=[string]$_.Type; State=[string]$_.State; ServiceName=[string]$_.ServiceName; IsEs=[bool]$_.IsEs } })
        Excluded=@($cl.Excluded); ClusterIps=@($cl.ClusterIps)
    }
}

# Collect facts for every known box (MS/ES/cluster nodes: one round trip each; recorders: fanned out
# together) and both cluster roles.
function Invoke-DoctorCollect {
    $boxes = New-Object System.Collections.Generic.List[object]
    foreach ($b in @(@(Get-MsBoxes) + @(Get-EsBoxes))) {
        Write-Log "Collecting facts: $($b.Name) ($(Get-RoleText $b))..."
        $boxes.Add((Get-BoxFacts $b))
    }
    $recBoxes = @($script:RecBoxes)
    if ($recBoxes.Count) {
        Write-Log "Collecting facts: $($recBoxes.Count) recording server(s), fanned out (ThrottleLimit 32)..."
        foreach ($rf in @(Invoke-CollectBundleFanOut $recBoxes)) { $boxes.Add($rf) }
    }
    [pscustomobject]@{
        GeneratedUtc=[DateTime]::UtcNow.ToString('o')
        MsComputer=$env:COMPUTERNAME
        Account=[string]$script:AdminCred.UserName
        TargetMsHost=(Get-TargetMsHost)
        Boxes=$boxes.ToArray()
        ClusterMs=(Get-ClusterFacts 'MS')
        ClusterEs=(Get-ClusterFacts 'ES')
        TrustedHostsGaps=@($script:TrustedHostsGaps.ToArray())
    }
}

# ===================== DOCTOR: EVALUATE (pure functions, no I/O - unit tested by tools/Test-Doctor.ps1) =====================
function New-Row { param([string]$Id,[string]$Area,[string]$Status,[string]$Computer,[string]$Check,[string]$Finding,[string]$Fix='')
    [pscustomobject]@{ Id=$Id; Area=$Area; Status=$Status; Computer=$Computer; Check=$Check; Finding=$Finding; Fix=$Fix }
}
function Get-BoxCoreVersion { param($Box)
    $name = switch ($Box.Kind) { 'MS' { 'Milestone XProtect Management Server' } 'ES' { 'Milestone XProtect Event Server' } default { 'Milestone XProtect Recording Server' } }
    $svc = @($Box.Common.Services) | Where-Object { $_.DisplayName -eq $name } | Select-Object -First 1
    if ($svc -and $svc.ExeVersion) { return $svc.ExeVersion }
    $any = @($Box.Common.Services) | Where-Object { $_.ExeVersion } | Select-Object -First 1
    if ($any) { return $any.ExeVersion }
    $null
}
# Normalizes to a tri-state bool ($true/$false/$null=Unknown) across the THREE different verbatim Enc
# shapes Collect stores per Kind: MS uses $script:BindingsSb (Ok/Bindings/Count - no Enabled field, so
# Enabled = Count>0 when Ok), ES uses $script:EsStateSb (Found/Value='true'|'false' string), REC uses
# $script:RecorderStateSb (already has a boolean Enabled field).
function Get-BoxEncEnabled { param($Box)
    if (-not $Box.Enc) { return $null }
    if ($Box.Kind -eq 'ES') {
        if ($Box.Enc.PSObject.Properties['Value']) {
            if ($Box.Enc.Value -eq 'true') { return $true }
            if ($Box.Enc.Value -eq 'false') { return $false }
        }
        return $null
    }
    if ($Box.Enc.PSObject.Properties['Enabled']) { return $Box.Enc.Enabled }
    if ($Box.Enc.PSObject.Properties['Ok'] -and $Box.Enc.PSObject.Properties['Count']) {
        if ($Box.Enc.Ok) { return ($Box.Enc.Count -gt 0) }
        return $null
    }
    $null
}

# Win32_Service.StartMode reports 'Auto' for what everyone calls "Automatic" - 'Manual'/'Disabled' are
# already the real WMI values, unchanged.
function Get-NormalizedStartMode { param([string]$Mode) if ($Mode -eq 'Auto') { 'Automatic' } else { $Mode } }
# The account an IIS pool ACTUALLY runs as - never the raw UserName field, which IIS keeps around (and
# ignores) even when IdentityType is not SpecificUser (e.g. a stale domain service account left behind after switching back to NetworkService).
function Get-EffectivePoolIdentity { param($Pool)
    switch ([string]$Pool.IdentityType) {
        'SpecificUser' { [string]$Pool.UserName }
        'NetworkService' { 'NT AUTHORITY\NETWORK SERVICE' }
        'LocalSystem' { 'NT AUTHORITY\SYSTEM' }
        'LocalService' { 'NT AUTHORITY\LOCAL SERVICE' }
        'ApplicationPoolIdentity' { "IIS APPPOOL\$($Pool.Name)" }
        default { [string]$Pool.UserName }
    }
}
# Canonical form so 'NT AUTHORITY\NetworkService' / 'NT AUTHORITY\NETWORK SERVICE' / 'NetworkService' /
# 'LocalSystem' / 'SYSTEM' etc all compare equal, case-insensitively.
function Get-NormalizedAccount { param([string]$Acct)
    if (-not $Acct) { return '' }
    $key = ($Acct.Trim().ToUpperInvariant() -replace '\s+',' ')
    $map = @{
        'NT AUTHORITY\NETWORKSERVICE'='NT AUTHORITY\NETWORK SERVICE'; 'NETWORKSERVICE'='NT AUTHORITY\NETWORK SERVICE'; 'NETWORK SERVICE'='NT AUTHORITY\NETWORK SERVICE'
        'LOCALSYSTEM'='NT AUTHORITY\SYSTEM'; 'SYSTEM'='NT AUTHORITY\SYSTEM'; 'NT AUTHORITY\SYSTEM'='NT AUTHORITY\SYSTEM'
        'LOCALSERVICE'='NT AUTHORITY\LOCAL SERVICE'; 'LOCAL SERVICE'='NT AUTHORITY\LOCAL SERVICE'; 'NT AUTHORITY\LOCALSERVICE'='NT AUTHORITY\LOCAL SERVICE'
    }
    if ($map.ContainsKey($key)) { return $map[$key] }
    $key
}

# ---- INV: inventory ----
function Test-INV1 { param($Result)
    $rows=@()
    $msTxt = if($Result.ClusterMs){ "cluster '$($Result.ClusterMs.Group)', $(@($Result.ClusterMs.Nodes).Count) node(s), owner $($Result.ClusterMs.Owner)" } else { "standalone ($($Result.MsComputer))" }
    $rows += New-Row 'INV-1' 'INV' 'INFO' $Result.MsComputer 'Management Server topology' $msTxt ''
    $esBoxes = @($Result.Boxes | Where-Object { $_.Kind -eq 'ES' })
    $esTxt = if($Result.ClusterEs){ "cluster '$($Result.ClusterEs.Group)', $(@($Result.ClusterEs.Nodes).Count) node(s), owner $($Result.ClusterEs.Owner)" } elseif($esBoxes.Count){ "standalone ($($esBoxes[0].Addr))" } else { '(none / all-in-one)' }
    $rows += New-Row 'INV-1' 'INV' 'INFO' '' 'Event Server topology' $esTxt ''
    $recCount = @($Result.Boxes | Where-Object { $_.Kind -eq 'REC' }).Count
    $rows += New-Row 'INV-1' 'INV' 'INFO' '' 'Recording servers' "$recCount recording server(s)" ''
    $rows
}
function Test-INV2 { param($Result)
    $rows=@()
    $msBoxes = @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.Reachable })
    $msVer = $null; foreach($b in $msBoxes){ $v=Get-BoxCoreVersion $b; if($v){ $msVer=$v; break } }
    foreach($b in @($Result.Boxes)){
        if(-not $b.Reachable){ continue }
        $vers = @(@($b.Common.Services) | Where-Object { $_.ExeVersion } | ForEach-Object { $_.ExeVersion } | Select-Object -Unique)
        if($vers.Count -gt 1){ $rows += New-Row 'INV-2' 'INV' 'FAIL' $b.Name 'Milestone service versions on this box' "Different Milestone service versions found on $($b.Name): $($vers -join ', ')." 'Re-run the Milestone installer/upgrade on this box so every Milestone component is the same version.' }
        $v = Get-BoxCoreVersion $b
        if($v -and $msVer -and $v -ne $msVer){ $rows += New-Row 'INV-2' 'INV' 'WARN' $b.Name 'Version vs Management Server' "$($b.Name) is version $v; the Management Server is $msVer." 'Upgrade this box (or the Management Server) so every component runs the same Milestone version.' }
    }
    foreach($key in 'MS','ES'){
        $nodes = @($Result.Boxes | Where-Object { $_.ClusterKey -eq $key -and $_.Reachable })
        if(@($nodes).Count -lt 2){ continue }
        $vs = @($nodes | ForEach-Object { Get-BoxCoreVersion $_ } | Where-Object { $_ } | Select-Object -Unique)
        if($vs.Count -gt 1){ $rows += New-Row 'INV-2' 'INV' 'WARN' '' "$key cluster node versions" "Cluster nodes of the $key role run different versions: $($vs -join ', ')." 'Upgrade every node of this cluster role to the same Milestone version.' }
    }
    $rows
}

# ---- NET: reachability ----
function Test-NET1 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes)){
        if($b.Reachable){ continue }
        $err = if($b.ConnError){ $b.ConnError } else { 'unknown error' }
        $fix = 'Check the computer is powered on and reachable, and that WinRM (PowerShell remoting) is enabled (Enable-PSRemoting), port 5985.'
        if($err -match 'Access is denied'){ $fix = "A local account was used: set LocalAccountTokenFilterPolicy=1 on $($b.Name), or use a domain account." }
        elseif(Test-KerberosError $err){ $fix = "Kerberos could not be used for '$($b.Target)'. If it is reachable only by IP, trust it first: Set-Item WSMan:\localhost\Client\TrustedHosts -Value ((Get-Item WSMan:\localhost\Client\TrustedHosts).Value + ',$($b.Addr)') -Force (run on $($Result.MsComputer))." }
        if($Result.TrustedHostsGaps -contains $b.Addr){ $fix = "$($b.Name) is reachable only by IP address ($($b.Addr)), which is not yet in this computer's TrustedHosts. Fix: Set-Item WSMan:\localhost\Client\TrustedHosts -Value ((Get-Item WSMan:\localhost\Client\TrustedHosts).Value + ',$($b.Addr)') -Force" }
        $rows += New-Row 'NET-1' 'NET' 'FAIL' $b.Name 'WinRM reachability' "$($b.Name) ($($b.Target)) could not be reached: $err" $fix
    }
    $rows
}
function Test-NET2 { param($Result)
    $rows=@()
    $clusterIps = New-Object System.Collections.Generic.List[string]
    if ($Result.ClusterMs) { foreach ($ip in @($Result.ClusterMs.ClusterIps)) { $clusterIps.Add([string]$ip) } }
    if ($Result.ClusterEs) { foreach ($ip in @($Result.ClusterEs.ClusterIps)) { $clusterIps.Add([string]$ip) } }
    foreach($b in @($Result.Boxes)){
        if(Test-LocalTarget $b.Addr){ continue }
        if(-not $b.Dns -or @($b.Dns.Forward).Count -eq 0){
            $rows += New-Row 'NET-2' 'NET' 'FAIL' $b.Name 'DNS resolution' "'$($b.Target)' does not resolve to an IP address from $($Result.MsComputer)." 'Add an A/host record for this computer, or use its IP address instead.'
            continue
        }
        $ip = [string]$b.Dns.Forward[0]
        $revText = if (@($b.Dns.Reverse).Count) { $b.Dns.Reverse -join ', ' } else { '(no reverse name)' }
        $short = ($b.Target -split '\.')[0].ToLowerInvariant()
        $revShorts = @($b.Dns.Reverse | ForEach-Object { ($_ -split '\.')[0].ToLowerInvariant() })
        if ($clusterIps -contains $ip) {
            $rows += New-Row 'NET-2' 'NET' 'WARN' $b.Name 'DNS reverse lookup' "$($b.Target) resolves to $ip, which is a cluster ROLE address (not this node's own address), whose reverse name is $revText. This is a real DNS problem: the A record for $($b.Target) must point at the node's own IP, never at a role/cluster address." 'Fix the DNS A record so the node name resolves to the node''s own address, not a cluster role address.'
        }
        elseif($revShorts.Count -and ($revShorts -notcontains $short)){
            $rows += New-Row 'NET-2' 'NET' 'WARN' $b.Name 'DNS reverse lookup' "$($b.Target) resolves to $ip, whose reverse name is $revText, not '$($b.Target)'." 'Fix the PTR record, or confirm the forward name is the one actually used for registration.'
        }
    }
    $rows
}
function Test-NET3 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes)){
        if(-not $b.Reachable){ continue }
        # Every port belongs to ONE Milestone service and only counts when that service runs on this box: a
        # passive cluster node (services stopped) is never failed for closed ports. 9000 = Management Server,
        # 9001 = Recording Server (on an MS box only when a local Recording Server runs there), 7563 = Recording
        # Server clients, 22331 = Event Server; 80/443 = IIS in front of the Management Server.
        $running = { param([string]$Dn) $s = @($b.Common.Services) | Where-Object { $_.DisplayName -eq $Dn } | Select-Object -First 1; [bool]($s -and $s.State -eq 'Running') }
        $msSvc = 'Milestone XProtect Management Server'; $recSvc = 'Milestone XProtect Recording Server'; $esSvc = 'Milestone XProtect Event Server'
        $encOn = ((Get-BoxEncEnabled $b) -eq $true)
        foreach($pp in @($b.PortProbe)){
            $owner = $null; $needEnc = $false
            switch($pp.Port){
                80    { if($b.Kind -eq 'MS'){ $owner = $msSvc } }
                443   { if($b.Kind -eq 'MS'){ $owner = $msSvc } }
                9000  { if($b.Kind -eq 'MS'){ $owner = $msSvc; $needEnc = $true } }
                9001  { if($b.Kind -in 'MS','REC'){ $owner = $recSvc; $needEnc = $true } }
                7563  { if($b.Kind -eq 'REC'){ $owner = $recSvc } }
                22331 { if($b.Kind -eq 'ES'){ $owner = $esSvc } }
            }
            if(-not $owner){ continue }
            if($needEnc -and -not $encOn){ continue }
            if(-not (& $running $owner)){ continue }
            if(-not $pp.Open){
                $rows += New-Row 'NET-3' 'NET' 'FAIL' $b.Name "Port $($pp.Port) reachability" "$($b.Name): port $($pp.Port) ($owner) is closed from $($Result.MsComputer), although '$owner' is running there." 'Check the Windows Firewall on that computer, and that the service is actually listening on that port.'
            }
        }
    }
    $rows
}

# Clock offset is measured around the SAME collection round trip (Complete-BoxFacts: remote UtcNow vs
# the midpoint of the local t0/t1 straddling that call), never against a local time taken minutes apart.
# Only the part of |offset| beyond the round trip's own uncertainty (half the round-trip time) counts.
function Test-NET4 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes)){
        if(-not $b.Reachable){ continue }
        if($null -eq $b.ClockOffsetSec){ continue }
        $off = [double]$b.ClockOffsetSec; $unc = [double]$(if($null -ne $b.ClockUncertaintySec){$b.ClockUncertaintySec}else{0})
        $eff = [math]::Max(0.0, [math]::Abs($off) - $unc)
        if($eff -gt 300){ $rows += New-Row 'NET-4' 'NET' 'FAIL' $b.Name 'Clock skew' "$($b.Name)'s clock differs from $($Result.MsComputer) by about $([int]$off) seconds (uncertainty +/-$([int]$unc)s)." 'Fix time sync (w32tm /resync), or the domain time source - Kerberos and TLS both fail with clock skew this large.' }
        elseif($eff -gt 60){ $rows += New-Row 'NET-4' 'NET' 'WARN' $b.Name 'Clock skew' "$($b.Name)'s clock differs from $($Result.MsComputer) by about $([int]$off) seconds (uncertainty +/-$([int]$unc)s)." 'Check time sync (w32tm /resync).' }
    }
    $rows
}
# Collection errors (a part other than Common could not be read) become a WARN here, never a NET-1 FAIL -
# the box stays Reachable, only the affected area is short one fact.
function Test-COL1 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes)){
        if(-not $b.Reachable){ continue }
        foreach($e in @($b.CollectErrors)){
            $rows += New-Row 'COL-1' 'COL' 'WARN' $b.Name "Could not read: $($e.Part)" "$($b.Name): could not read $($e.Part) ($($e.Error))." 'Re-run the check; if it persists, check the exact error text above and the corresponding read on that box by hand.'
        }
    }
    $rows
}

# ---- SVC: services ----
function Test-SVC1 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes)){
        if(-not $b.Reachable){ continue }
        $coreName = switch($b.Kind){ 'MS'{'Milestone XProtect Management Server'} 'ES'{'Milestone XProtect Event Server'} default {'Milestone XProtect Recording Server'} }
        $svc = @($b.Common.Services) | Where-Object { $_.DisplayName -eq $coreName } | Select-Object -First 1
        if(-not $svc){
            $rows += New-Row 'SVC-1' 'SVC' 'FAIL' $b.Name 'Core service present' "$($b.Name): the '$coreName' service was not found." 'Install/repair the Milestone role on this computer.'
            continue
        }
        $startMode = Get-NormalizedStartMode $svc.StartMode
        if($b.IsNode){
            if($startMode -eq 'Manual'){ $rows += New-Row 'SVC-1' 'SVC' 'PASS' $b.Name 'Core service state' "$($b.Name): '$coreName' is cluster-managed (Manual startup)." '' }
            elseif($b.Active -and $svc.State -ne 'Running'){ $rows += New-Row 'SVC-1' 'SVC' 'FAIL' $b.Name 'Core service state (active node)' "$($b.Name) owns the role now but '$coreName' is $($svc.State)." 'In Failover Cluster Manager, bring the role resource online, or restart the service.' }
            elseif($b.Active -and $svc.State -eq 'Running'){ $rows += New-Row 'SVC-1' 'SVC' 'PASS' $b.Name 'Core service state (active node)' "$($b.Name) owns the role now and '$coreName' is Running." '' }
            elseif((-not $b.Active) -and $svc.State -eq 'Running' -and $startMode -eq 'Automatic'){ $rows += New-Row 'SVC-1' 'SVC' 'WARN' $b.Name 'Core service on passive node' "$($b.Name) is a passive node but '$coreName' is Running with Automatic startup (should be cluster-managed / Manual)." 'Set the service startup type to Manual on cluster nodes - the cluster starts/stops it.' }
            elseif((-not $b.Active) -and $svc.State -eq 'Stopped'){ $rows += New-Row 'SVC-1' 'SVC' 'PASS' $b.Name 'Core service state (passive node)' "$($b.Name) is a passive node and '$coreName' is Stopped, as expected." '' }
        } else {
            if($svc.State -ne 'Running'){ $rows += New-Row 'SVC-1' 'SVC' 'WARN' $b.Name 'Core service state' "$($b.Name): '$coreName' is $($svc.State)." 'Start the service (net start, or Services.msc).' }
            elseif($startMode -ne 'Automatic'){ $rows += New-Row 'SVC-1' 'SVC' 'WARN' $b.Name 'Core service startup type' "$($b.Name): '$coreName' startup type is $($svc.StartMode), not Automatic." "Set the service's startup type to Automatic." }
            else { $rows += New-Row 'SVC-1' 'SVC' 'PASS' $b.Name 'Core service state' "$($b.Name): '$coreName' is Running (Automatic)." '' }
        }
        if($b.Kind -eq 'MS' -and $b.IsNode){
            $es = @($b.Common.Services) | Where-Object { $_.DisplayName -eq 'Milestone XProtect Event Server' } | Select-Object -First 1
            if($es -and (Get-NormalizedStartMode $es.StartMode) -eq 'Disabled'){ $rows += New-Row 'SVC-1' 'SVC' 'INFO' $b.Name 'Event Server service on MS node' "$($b.Name): the Event Server service is Disabled here (by design - it runs on the Event Server role)." '' }
        }
    }
    $rows
}
# Compares the EFFECTIVE account (never IIS's stale, ignored UserName field when IdentityType is not
# SpecificUser), normalized so common NT AUTHORITY spellings compare equal, case-insensitively.
function Test-SVC2 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes)){
        if(-not $b.Reachable){ continue }
        $accts = New-Object System.Collections.Generic.List[object]
        foreach($s in @($b.Common.Services)){ if($s.StartName){ $accts.Add([pscustomobject]@{ Raw=[string]$s.StartName; Norm=(Get-NormalizedAccount $s.StartName); Source="service $($s.DisplayName)" }) } }
        if($b.Kind -eq 'MS' -and $b.Ms -and $b.Ms.Iis -and $b.Ms.Iis.Ok){
            $stale = @()
            foreach($p in @($b.Ms.Iis.Pools)){
                $eff = Get-EffectivePoolIdentity $p
                if($eff){ $accts.Add([pscustomobject]@{ Raw=$eff; Norm=(Get-NormalizedAccount $eff); Source="IIS pool $($p.Name)" }) }
                if($p.IdentityType -ne 'SpecificUser' -and $p.UserName){ $stale += "'$($p.Name)' ($($p.UserName), identity $($p.IdentityType))" }
            }
            # one row per computer, not one per pool
            if(@($stale).Count){ $rows += New-Row 'SVC-2' 'SVC' 'INFO' $b.Name 'Stale pool user names' "$($b.Name): $(@($stale).Count) IIS pool(s) keep a leftover user name that IIS ignores (the identity type is not SpecificUser): $($stale -join '; ')." '' }
        }
        $u = @($accts | ForEach-Object { $_.Norm } | Where-Object { $_ } | Select-Object -Unique)
        if($u.Count -gt 1){
            $detail = ($accts | ForEach-Object { "$($_.Source)=$($_.Raw)" }) -join '; '
            $rows += New-Row 'SVC-2' 'SVC' 'WARN' $b.Name 'Service account consistency' "$($b.Name): Milestone services / IIS pools run as different EFFECTIVE accounts: $detail." 'Use one consistent service account across the Milestone services and the VideoOS IIS application pools on this box.'
        }
    }
    $rows
}
function Test-SVC3 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes)){
        if(-not $b.Reachable){ continue }
        if(-not $b.ScFinder -or -not $b.ScFinder.Found){
            $rows += New-Row 'SVC-3' 'SVC' 'FAIL' $b.Name 'ServerConfigurator.exe found' "$($b.Name): ServerConfigurator.exe was not found. $($b.ScFinder.Path)" "If Milestone is installed in another folder on that computer, add the folder as a search path (headless: -SearchPaths 'D:\Milestone')."
        }
    }
    $rows
}

# ---- REG: registration ----
function Test-REG1 { param($Result)
    $rows=@()
    $target = $Result.TargetMsHost
    foreach($b in @($Result.Boxes)){
        if(-not $b.Reachable){ continue }
        foreach($e in @($b.RegAddr)){
            if(-not $e.Value){ continue }
            if(-not (Test-MsAddressMatch -Addr $e.Value -TargetHost $target)){
                $rows += New-Row 'REG-1' 'REG' 'FAIL' $b.Name "Registration ($($e.Source))" "$($b.Name) is registered to management server '$($e.Value)' ($($e.Source)), but this Management Server is '$target'." 'Run Mrc-Guided.ps1 (Fix registration / Re-register this node) to point this computer back at the right management server.'
            }
        }
    }
    $rows
}
function Test-REG2 { param($Result)
    $rows=@()
    if(-not $Result.ClusterMs){ return $rows }
    $nodeNames = @($Result.ClusterMs.Nodes | ForEach-Object { ([string]$_.Name).ToLowerInvariant() })
    foreach($b in @($Result.Boxes)){
        if(-not $b.Reachable){ continue }
        foreach($e in @($b.RegAddr)){
            if(-not $e.Value){ continue }
            $h = Get-UrlHost $e.Value
            $short = ($h -split '\.')[0]
            if($nodeNames -contains $short){
                $rows += New-Row 'REG-2' 'REG' 'FAIL' $b.Name "Registration points at a node ($($e.Source))" "$($b.Name) is registered to Management Server cluster NODE '$($e.Value)' instead of the cluster address '$($Result.ClusterMs.Address)'." 'Re-register with the cluster address, not a node name - a failover will otherwise break this computer.'
            }
        }
    }
    $rows
}

# ---- ENC: encryption and certificates ----
function Test-ENC1 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes)){
        if(-not $b.Reachable){ continue }
        $enabled = Get-BoxEncEnabled $b
        if($null -eq $enabled){
            $why = if($b.Enc -and $b.Enc.PSObject.Properties['Error'] -and $b.Enc.Error){ $b.Enc.Error } else { 'could not be read' }
            $rows += New-Row 'ENC-1' 'ENC' 'WARN' $b.Name 'Encryption state' "$($b.Name): encryption state is Unknown ($why)." 'Re-run the check; if it persists, verify netsh http show sslcert / RecorderConfig.xml / ServiceEndpoints.xml are readable on that box.'
        } else {
            $rows += New-Row 'ENC-1' 'ENC' 'INFO' $b.Name 'Encryption state' "$($b.Name): $(if($enabled){'encrypted'}else{'not encrypted'})." ''
        }
    }
    $rows
}
function Test-ENC2 { param($Result)
    $rows=@()
    $msBoxes = @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.Reachable })
    $msEnc = $null; foreach($b in $msBoxes){ $v=Get-BoxEncEnabled $b; if($null -ne $v){ $msEnc=$v; break } }
    if($null -ne $msEnc){
        foreach($b in @($Result.Boxes | Where-Object { $_.Kind -eq 'REC' -and $_.Reachable })){
            $v = Get-BoxEncEnabled $b
            if($null -ne $v -and $v -ne $msEnc){
                $rows += New-Row 'ENC-2' 'ENC' 'FAIL' $b.Name 'Encryption vs Management Server' "$($b.Name) is $(if($v){'encrypted'}else{'not encrypted'}) but the Management Server is $(if($msEnc){'encrypted'}else{'not encrypted'})." 'Run Mrc-Guided.ps1 to bring this recorder back in line with the Management Server (correct order: ON = ES, MS, recorders; OFF = MS, recorders, ES).'
            }
        }
        foreach($b in @($Result.Boxes | Where-Object { $_.Kind -eq 'ES' -and $_.Reachable })){
            $v = Get-BoxEncEnabled $b
            if($null -ne $v -and $v -ne $msEnc){
                $rows += New-Row 'ENC-2' 'ENC' 'WARN' $b.Name 'Encryption vs Management Server' "The Event Server is $(if($v){'encrypted'}else{'not encrypted'}) but the Management Server is $(if($msEnc){'encrypted'}else{'not encrypted'}) - a half-finished change." 'Finish the change with Mrc-Guided.ps1.'
            }
        }
    }
    foreach($key in 'MS','ES'){
        $nodes = @($Result.Boxes | Where-Object { $_.ClusterKey -eq $key -and $_.Reachable })
        if(@($nodes).Count -lt 2){ continue }
        $vals = @($nodes | ForEach-Object { Get-BoxEncEnabled $_ } | Where-Object { $null -ne $_ } | Select-Object -Unique)
        if($vals.Count -gt 1){ $rows += New-Row 'ENC-2' 'ENC' 'FAIL' '' "$key cluster node encryption state" "Nodes of the $key cluster role do not agree on encryption state." 'Bring every node of this role to the same encryption state with Mrc-Guided.ps1.' }
    }
    $rows
}
function Test-ENC3 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes)){
        if(-not $b.Reachable){ continue }
        $expectNames = New-Object System.Collections.Generic.List[string]
        if($b.Common -and $b.Common.Identity -and $b.Common.Identity.Fqdn){ $expectNames.Add(([string]$b.Common.Identity.Fqdn).ToLowerInvariant()) }
        if($b.Kind -eq 'MS'){
            if($Result.ClusterMs -and $Result.ClusterMs.Address){ $expectNames.Add(([string]$Result.ClusterMs.Address).ToLowerInvariant()) }
            foreach($e in @($b.RegAddr)){ $h=Get-UrlHost $e.Value; if($h){ $expectNames.Add($h) } }
        }
        foreach($c in @($b.Certs)){
            if(-not $c.Found){ $rows += New-Row 'ENC-3' 'ENC' 'FAIL' $b.Name "Certificate on port $($c.Port)" "$($b.Name) port $($c.Port): the bound certificate (thumbprint $($c.Thumbprint)) was not found in LocalMachine\My." 'Re-issue and import the certificate for this box with Mrc-Guided.ps1 / the role GUI.'; continue }
            $now = Get-Date
            $notAfter=$null; try { $notAfter=[DateTime]$c.NotAfter } catch {}
            if($notAfter -and $notAfter -lt $now){ $rows += New-Row 'ENC-3' 'ENC' 'FAIL' $b.Name "Certificate on port $($c.Port)" "$($b.Name) port $($c.Port): certificate expired $($notAfter.ToString('yyyy-MM-dd'))." 'Issue a new certificate and re-run the encryption step for this box.' }
            elseif($notAfter -and ($notAfter-$now).TotalDays -lt 60){ $rows += New-Row 'ENC-3' 'ENC' 'WARN' $b.Name "Certificate on port $($c.Port)" "$($b.Name) port $($c.Port): certificate expires $($notAfter.ToString('yyyy-MM-dd')) (in $([int]($notAfter-$now).TotalDays) days)." 'Plan a certificate renewal before it expires.' }
            if(-not $c.HasPrivateKey){ $rows += New-Row 'ENC-3' 'ENC' 'FAIL' $b.Name "Certificate on port $($c.Port)" "$($b.Name) port $($c.Port): the certificate has no private key on this box." 'Re-import the PFX (with private key) for this box.' }
            if(-not $c.ChainTrusted){ $rows += New-Row 'ENC-3' 'ENC' 'FAIL' $b.Name "Certificate on port $($c.Port)" "$($b.Name) port $($c.Port): the certificate chain does not build/trust ($($c.ChainError))." 'Import the signing CA certificate into LocalMachine\Root on this box.' }
            $sanLower = @($c.San | ForEach-Object { ([string]$_).ToLowerInvariant() })
            $uniqExpect = @($expectNames | Select-Object -Unique)
            $matched = $false
            foreach($n in $uniqExpect){ if($sanLower -contains $n){ $matched=$true; break } }
            if($uniqExpect.Count -and -not $matched){ $rows += New-Row 'ENC-3' 'ENC' 'FAIL' $b.Name "Certificate on port $($c.Port)" "$($b.Name) port $($c.Port): the certificate SAN ($($c.San -join ', ')) does not include any expected name ($($uniqExpect -join ', '))." 'Re-issue the certificate with the correct SAN names (Mrc-Guided.ps1).' }
            if($c.KeyReadable -eq $false){ $rows += New-Row 'ENC-3' 'ENC' 'WARN' $b.Name "Certificate on port $($c.Port)" "$($b.Name) port $($c.Port): the Milestone service account ($($c.KeyAccount)) does not have Read on the certificate's private key." 'Grant that account Read on the private key (Mrc-Guided.ps1 does this when it imports a certificate).' }
        }
    }
    $rows
}
function Test-ENC4 { param($Result)
    $rows=@()
    $msNodes = @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.ClusterKey -eq 'MS' -and $_.Reachable })
    if(@($msNodes).Count -ge 2){
        $tps = @($msNodes | ForEach-Object { $c9=@($_.Certs) | Where-Object { $_.Port -eq 9000 } | Select-Object -First 1; if($c9){ $c9.Thumbprint } } | Where-Object { $_ } | Select-Object -Unique)
        if($tps.Count -gt 1){ $rows += New-Row 'ENC-4' 'ENC' 'WARN' '' 'MS cluster node certificate thumbprints (9000)' 'The Management Server cluster nodes use different certificate thumbprints on port 9000.' 'Re-issue one certificate for the role (Mrc-Guided.ps1 clusters it automatically) and import it on every node.' }
    }
    foreach($b in @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.Reachable })){
        if((Get-BoxEncEnabled $b) -ne $true){ continue }
        $c9000 = @($b.Certs) | Where-Object { $_.Port -eq 9000 } | Select-Object -First 1
        $c443 = @($b.Certs) | Where-Object { $_.Port -eq 443 } | Select-Object -First 1
        if($c9000 -and $c443 -and $c9000.Thumbprint -and $c443.Thumbprint -and $c9000.Thumbprint -ne $c443.Thumbprint){
            $rows += New-Row 'ENC-4' 'ENC' 'WARN' $b.Name '443 vs 9000 certificate' "$($b.Name): the IIS (443) certificate differs from the Management Server (9000) certificate." 'Use the same certificate on both bindings, or confirm this is intentional.'
        }
    }
    $rows
}

# ---- CLU: cluster (only when clustered) ----
function Test-CLU1 { param($Result)
    $rows=@()
    foreach($key in 'MS','ES'){
        $cl = if($key -eq 'MS'){ $Result.ClusterMs } else { $Result.ClusterEs }
        if(-not $cl){ continue }
        if($cl.State -eq 'Online'){ $rows += New-Row 'CLU-1' 'CLU' 'PASS' '' "$key cluster role state" "Cluster role '$($cl.Group)' is Online." '' }
        elseif($cl.State -eq 'PartialOnline'){
            $other = @($cl.Offline | Where-Object { -not ($key -eq 'MS' -and $_.IsEs) })
            if($other.Count){ $rows += New-Row 'CLU-1' 'CLU' 'FAIL' '' "$key cluster role state" "Cluster role '$($cl.Group)' is only partly running. Not running: $((@($other | ForEach-Object { "$($_.Name) ($($_.State))" })) -join ', ')." 'Start the offline resources in Failover Cluster Manager.' }
            else { $rows += New-Row 'CLU-1' 'CLU' 'PASS' '' "$key cluster role state" "Cluster role '$($cl.Group)' is PartialOnline, but only the Event Server resource is offline (by design)." '' }
        } else {
            $rows += New-Row 'CLU-1' 'CLU' 'FAIL' '' "$key cluster role state" "Cluster role '$($cl.Group)' is '$($cl.State)', not Online." 'In Failover Cluster Manager > Roles, start the role.'
        }
        foreach($n in @($cl.Nodes)){
            if($n.State -eq 'Down'){ $rows += New-Row 'CLU-1' 'CLU' 'FAIL' $n.Name "$key cluster node state" "Node $($n.Name) is Down." 'Power it on / investigate why it left the cluster.' }
            elseif($n.State -eq 'Paused'){ $rows += New-Row 'CLU-1' 'CLU' 'WARN' $n.Name "$key cluster node state" "Node $($n.Name) is Paused." 'Resume the node in Failover Cluster Manager once maintenance is done.' }
            elseif($n.State -eq 'Up'){ $rows += New-Row 'CLU-1' 'CLU' 'PASS' $n.Name "$key cluster node state" "Node $($n.Name) is Up." '' }
        }
    }
    $rows
}
function Test-CLU2 { param($Result)
    $rows=@()
    foreach($key in 'MS','ES'){
        $cl = if($key -eq 'MS'){ $Result.ClusterMs } else { $Result.ClusterEs }
        if(-not $cl){ continue }
        foreach($n in @($cl.Nodes)){
            $box = @($Result.Boxes | Where-Object { $_.ClusterKey -eq $key -and $_.Target -eq $n.Name }) | Select-Object -First 1
            if($box -and $box.Reachable -and @($box.Common.Services).Count -eq 0){
                $rows += New-Row 'CLU-2' 'CLU' 'WARN' $n.Name "$key possible owner without Milestone" "$($n.Name) can own the $key role but no Milestone service was found on it." "Install the Milestone role on this node, or exclude it from the cluster's possible owners if it should never run this role."
            }
        }
        foreach($ex in @($cl.Excluded)){
            $rows += New-Row 'CLU-2' 'CLU' 'INFO' $ex "$key excluded node" "$ex is a cluster node but not a possible owner of the $key role - excluded from its checks." ''
        }
    }
    $rows
}
function Test-CLU3 { param($Result)
    $rows=@()
    foreach($key in 'MS','ES'){
        $cl = if($key -eq 'MS'){ $Result.ClusterMs } else { $Result.ClusterEs }
        if(-not $cl){ continue }
        foreach($r in @($cl.Offline)){
            if($key -eq 'MS' -and $r.IsEs){ continue }
            if($r.Type -ne 'Generic Service'){ continue }
            $rows += New-Row 'CLU-3' 'CLU' 'FAIL' $cl.Owner "$key cluster resource" "Cluster resource '$($r.Name)' (service $($r.ServiceName)) of the $key role is $($r.State), not Online, on owner node $($cl.Owner)." 'Bring the resource online in Failover Cluster Manager, or check why its service will not start.'
        }
    }
    $rows
}
function Test-CLU4 { param($Result)
    $rows=@()
    if(-not $Result.ClusterMs){ return $rows }
    $nodes = @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.ClusterKey -eq 'MS' -and $_.Reachable })
    $dated = @($nodes | Where-Object { $_.ScLog -and $_.ScLog.Found -and $_.ScLog.LastRegisteredUtc -and $_.ScLog.LastRegisteredUtc -ne 'unknown-time' } | ForEach-Object {
        # [DateTimeOffset] keeps it UTC; a plain [DateTime] cast of an ISO '...Z' string converts to LOCAL time.
        [pscustomobject]@{ Box=$_; When=([DateTimeOffset]::Parse([string]$_.ScLog.LastRegisteredUtc, [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime }
    })
    if(@($dated).Count -lt 2){
        $rows += New-Row 'CLU-4' 'CLU' 'INFO' '' 'MS cluster node that can take over' 'The ServerConfigurator logs do not decide which node registered last.' ''
        return $rows
    }
    $nw = $dated | Sort-Object When -Descending | Select-Object -First 1
    $newest = $nw.Box
    foreach($d in $dated){
        if($d.Box.Target -ne $newest.Target){
            $rows += New-Row 'CLU-4' 'CLU' 'WARN' $d.Box.Name 'MS cluster node that can take over' "$($d.Box.Name) last registered $($d.When.ToString('yyyy-MM-dd HH:mm')) UTC - older than $($newest.Name) ($($nw.When.ToString('yyyy-MM-dd HH:mm')) UTC). It cannot take over the Management Server until it is re-registered (known Milestone limitation)." "After a failover, run Mrc-Guided.ps1 'Re-register this node' on $($d.Box.Name)."
        }
    }
    $rows
}
function Test-CLU5 { param($Result)
    $rows=@()
    $nodes = @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.ClusterKey -eq 'MS' -and $_.Reachable -and $_.Ms })
    if(@($nodes).Count -lt 2){ return $rows }
    $names = @($nodes | ForEach-Object { $_.Ms.ConnStrings } | ForEach-Object { $_.Name } | Select-Object -Unique)
    foreach($n in $names){
        $vals = @($nodes | ForEach-Object { (@($_.Ms.ConnStrings) | Where-Object { $_.Name -eq $n } | Select-Object -First 1) } | Where-Object { $_ } | ForEach-Object { "$($_.DataSource)|$($_.Catalog)" } | Select-Object -Unique)
        if($vals.Count -gt 1){ $rows += New-Row 'CLU-5' 'CLU' 'WARN' '' "MS cluster node drift: connection string '$n'" "Nodes of the MS cluster role do not agree on the '$n' connection string (Data Source / Initial Catalog)." 'Point every node at the same database (ServerConfigurator / SQL configuration).' }
    }
    $portVals = @($nodes | ForEach-Object { $p=$_.Ms.Ports; "$($p.ServerPort)|$($p.VmoPort)|$($p.HttpsPort)|$($p.Http)|$($p.Https)" } | Select-Object -Unique)
    if($portVals.Count -gt 1){ $rows += New-Row 'CLU-5' 'CLU' 'WARN' '' 'MS cluster node drift: ports' 'Nodes of the MS cluster role do not agree on ServerConfig.xml / IIS ports.' 'Align ServerConfig.xml and the IIS site bindings across every node.' }
    $regVals = @($nodes | ForEach-Object { (@($_.RegAddr | ForEach-Object { $_.Value }) -join ',') } | Select-Object -Unique)
    if($regVals.Count -gt 1){ $rows += New-Row 'CLU-5' 'CLU' 'WARN' '' 'MS cluster node drift: registered addresses' 'Nodes of the MS cluster role are registered to different management-server addresses.' 'Re-register every node to the same (cluster) address.' }
    $poolNames = @($nodes | ForEach-Object { $_.Ms.Iis.Pools } | ForEach-Object { $_.Name } | Select-Object -Unique)
    foreach($pn in $poolNames){
        $vals = @($nodes | ForEach-Object { (@($_.Ms.Iis.Pools) | Where-Object { $_.Name -eq $pn } | Select-Object -First 1) } | Where-Object { $_ } | ForEach-Object { "$($_.IdentityType)|$($_.UserName)" } | Select-Object -Unique)
        if($vals.Count -gt 1){ $rows += New-Row 'CLU-5' 'CLU' 'WARN' '' "MS cluster node drift: IIS pool '$pn'" "Nodes of the MS cluster role run IIS pool '$pn' under different identities." 'Use the same application pool identity on every node.' }
    }
    $paths = @($nodes | ForEach-Object { $_.Ms.ConfigFiles } | ForEach-Object { $_.Path } | Select-Object -Unique)
    foreach($p in $paths){
        $vals = @($nodes | ForEach-Object { (@($_.Ms.ConfigFiles) | Where-Object { $_.Path -eq $p } | Select-Object -First 1) } | Where-Object { $_ } | ForEach-Object { $_.Sha256 } | Select-Object -Unique)
        if($vals.Count -gt 1){ $rows += New-Row 'CLU-5' 'CLU' 'INFO' '' "MS cluster node drift: config file $p" "Nodes of the MS cluster role have different content for $p (hash drift)." '' }
    }
    $rows
}

# ---- IIS (MS nodes / MS) ----
function Test-IIS1 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.Reachable -and $_.Ms })){
        if($b.IsNode -and -not $b.Active){ continue }
        $iis = $b.Ms.Iis
        if(-not $iis -or -not $iis.Ok){ $rows += New-Row 'IIS-1' 'IIS' 'WARN' $b.Name 'IIS state' "$($b.Name): IIS state could not be read ($($iis.Error))." 'Confirm the Web-Mgmt-Console / WebAdministration module is available on this box.'; continue }
        if($iis.W3svc -ne 'Running'){ $rows += New-Row 'IIS-1' 'IIS' 'FAIL' $b.Name 'W3SVC service' "$($b.Name): the W3SVC (World Wide Web Publishing) service is $($iis.W3svc)." 'Start the W3SVC service.' }
        if($iis.Was -ne 'Running'){ $rows += New-Row 'IIS-1' 'IIS' 'FAIL' $b.Name 'WAS service' "$($b.Name): the WAS (Windows Process Activation Service) is $($iis.Was)." 'Start the WAS service.' }
        if($iis.SiteState -and $iis.SiteState -ne 'Started'){ $rows += New-Row 'IIS-1' 'IIS' 'FAIL' $b.Name 'Default Web Site' "$($b.Name): Default Web Site is $($iis.SiteState)." 'Start the Default Web Site in IIS Manager.' }
        $wantHttp = $b.Ms.Ports.Http; $wantHttps = $b.Ms.Ports.Https
        if($wantHttp -and -not (@($iis.Bindings) | Where-Object { $_ -match ":$wantHttp\D*\(http\)" })){ $rows += New-Row 'IIS-1' 'IIS' 'WARN' $b.Name 'HTTP binding' "$($b.Name): no http binding found on the configured WebSitePort ($wantHttp)." "Check the Default Web Site bindings in IIS Manager match ServerConfigurator's configured ports." }
        if($wantHttps -and -not (@($iis.Bindings) | Where-Object { $_ -match ":$wantHttps\D*\(https\)" })){ $rows += New-Row 'IIS-1' 'IIS' 'WARN' $b.Name 'HTTPS binding' "$($b.Name): no https binding found on the configured WebSiteSecurePort ($wantHttps)." "Check the Default Web Site bindings in IIS Manager match ServerConfigurator's configured ports." }
    }
    $rows
}
function Test-IIS2 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.Reachable -and $_.Ms })){
        if($b.IsNode -and -not $b.Active){ continue }
        $iis = $b.Ms.Iis; if(-not $iis -or -not $iis.Ok){ continue }
        $poolState = @{}; foreach($p in @($iis.Pools)){ $poolState[$p.Name] = $p.State }
        foreach($req in '/ManagementServer','/IDP','/API'){
            $app = @($iis.Apps | Where-Object { $_.Path -eq $req }) | Select-Object -First 1
            if(-not $app){ $rows += New-Row 'IIS-2' 'IIS' 'FAIL' $b.Name "IIS application $req" "$($b.Name): IIS application $req is missing under Default Web Site." 'Repair the Management Server installation (re-run ServerConfigurator / the installer).'; continue }
            $st = $poolState[$app.Pool]
            if($st -and $st -ne 'Started'){ $rows += New-Row 'IIS-2' 'IIS' 'FAIL' $b.Name "IIS application pool for $req" "$($b.Name): the application pool '$($app.Pool)' for $req is $st." 'Start the application pool in IIS Manager.' }
        }
        foreach($app in @($iis.Apps | Where-Object { $_.Path -notin '/ManagementServer','/IDP','/API' })){
            $st = $poolState[$app.Pool]
            if($st -and $st -ne 'Started'){ $rows += New-Row 'IIS-2' 'IIS' 'WARN' $b.Name "IIS application pool for $($app.Path)" "$($b.Name): the application pool '$($app.Pool)' for $($app.Path) is $st." 'Start the application pool in IIS Manager.' }
        }
        foreach($p in @($iis.Pools)){
            if($p.IdentityType -ne 'NetworkService' -and -not $p.UserName){ $rows += New-Row 'IIS-2' 'IIS' 'WARN' $b.Name "IIS pool identity ($($p.Name))" "$($b.Name): application pool '$($p.Name)' identity type is $($p.IdentityType) with no account configured." 'Set the pool identity to NetworkService or the Milestone service account.' }
        }
    }
    $rows
}
function Test-IIS3 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.Reachable })){
        $c443 = @($b.Certs) | Where-Object { $_.Port -eq 443 } | Select-Object -First 1
        if(-not $c443){ continue }
        if(-not $c443.Found){ $rows += New-Row 'IIS-3' 'IIS' 'FAIL' $b.Name '443 certificate' "$($b.Name): the certificate bound to port 443 was not found." 'Bind a valid certificate to port 443 in IIS Manager.'; continue }
        $now=Get-Date; $notAfter=$null; try { $notAfter=[DateTime]$c443.NotAfter } catch {}
        if($notAfter -and $notAfter -lt $now){ $rows += New-Row 'IIS-3' 'IIS' 'FAIL' $b.Name '443 certificate' "$($b.Name): the port 443 certificate expired $($notAfter.ToString('yyyy-MM-dd'))." 'Renew the certificate and re-bind it in IIS Manager.' }
        elseif($notAfter -and ($notAfter-$now).TotalDays -lt 60){ $rows += New-Row 'IIS-3' 'IIS' 'WARN' $b.Name '443 certificate' "$($b.Name): the port 443 certificate expires $($notAfter.ToString('yyyy-MM-dd'))." 'Plan a renewal before it expires.' }
    }
    $rows
}

# ---- CFG: config ----
function Test-CFG1 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes | Where-Object { $_.Reachable })){
        $files = if($b.Ms){ $b.Ms.ConfigFiles } else { @() }
        foreach($cf in @($files)){
            if(-not $cf.Ok){ $rows += New-Row 'CFG-1' 'CFG' 'FAIL' $b.Name 'Config file parses' "$($b.Name): $($cf.Path) exists but does not parse ($($cf.Error))." 'Restore this file from a backup, or re-run ServerConfigurator to regenerate it.' }
        }
    }
    $rows
}
function Test-CFG2 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.Reachable -and $_.Ms })){
        $cs = @($b.Ms.ConnStrings | Where-Object { $_.DataSource })
        if(@($cs).Count -lt 2){ continue }
        $ds = @($cs | ForEach-Object { $_.DataSource } | Select-Object -Unique)
        if($ds.Count -gt 1){ $rows += New-Row 'CFG-2' 'CFG' 'WARN' $b.Name 'Connection string Data Sources' "$($b.Name): components use different SQL Data Sources: $($ds -join ', ')." 'Point every Milestone component at the same SQL Server.' }
        $cats = (@($cs) | ForEach-Object { "$($_.Name)=$($_.Catalog)" }) -join ', '
        $rows += New-Row 'CFG-2' 'CFG' 'INFO' $b.Name 'Connection string catalogs' "$($b.Name): $cats" ''
    }
    $rows
}
# /server/serverport/port is the Management Server SERVICE's own port (not IIS - an earlier version of
# this rule wrongly compared it to the IIS WebSitePort and false-WARNed on every normal install where
# they legitimately differ, e.g. 8080 vs 80). The only thing that must agree is these ServerConfig.xml
# ports across every node of an MS cluster role - one INFO row lists them otherwise (spec.md CFG-3,
# lab fix round 2; see docs/plans/2026-09-29-xprotect-doctor.md Deviations).
function Test-CFG3 { param($Result)
    $rows=@()
    $nodes = @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.Reachable -and $_.Ms })
    if(-not $nodes.Count){ return $rows }
    if($nodes.Count -ge 2){
        $vals = @($nodes | ForEach-Object { $p=$_.Ms.Ports; "$($p.ServerPort)|$($p.VmoPort)|$($p.HttpsPort)" } | Select-Object -Unique)
        if($vals.Count -gt 1){
            $rows += New-Row 'CFG-3' 'CFG' 'WARN' '' 'ServerConfig.xml ports differ between MS cluster nodes' "Nodes of the MS cluster role do not agree on ServerConfig.xml ports (serverport / VMOCommunication Port / HttpsPort): $($vals -join '  vs  ')." 'Align ServerConfig.xml across every node of the MS role (Mrc-Guided.ps1 / ServerConfigurator).'
        } else {
            $p = $nodes[0].Ms.Ports
            $rows += New-Row 'CFG-3' 'CFG' 'INFO' '' 'ServerConfig.xml ports' "serverport=$($p.ServerPort), VMOCommunication Port=$($p.VmoPort), HttpsPort=$($p.HttpsPort) (same on every MS cluster node)." ''
        }
    } else {
        $p = $nodes[0].Ms.Ports
        $rows += New-Row 'CFG-3' 'CFG' 'INFO' $nodes[0].Name 'ServerConfig.xml ports' "serverport=$($p.ServerPort), VMOCommunication Port=$($p.VmoPort), HttpsPort=$($p.HttpsPort)." ''
    }
    $rows
}

# ---- ENV: environment ----
function Test-ENV1 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.Reachable -and $_.Ms })){
        foreach($s in @($b.Ms.Sql)){
            if(-not $s.DnsOk){ $rows += New-Row 'ENV-1' 'ENV' 'FAIL' $b.Name 'SQL host DNS' "$($b.Name): SQL host '$($s.DataSource)' does not resolve." 'Fix DNS for the SQL Server, or use its IP address in the connection string.'; continue }
            if($s.Note -eq 'named instance, port not checked'){ $rows += New-Row 'ENV-1' 'ENV' 'INFO' $b.Name 'SQL named instance' "$($b.Name): '$($s.DataSource)' is a named instance - port not checked (SQL Browser is UDP 1434, out of scope)." ''; continue }
            if(-not $s.TcpOk){ $rows += New-Row 'ENV-1' 'ENV' 'FAIL' $b.Name 'SQL TCP reachability' "$($b.Name): could not open a TCP connection to '$($s.DataSource)'." 'Check the SQL Server is running, the firewall allows TCP 1433, and the Data Source is correct.'; continue }
            if($s.TcpMs -gt 200){ $rows += New-Row 'ENV-1' 'ENV' 'WARN' $b.Name 'SQL TCP latency' "$($b.Name): TCP connect to '$($s.DataSource)' took $($s.TcpMs) ms." 'Investigate network latency to the SQL Server.' }
            if($s.OpenMs -and $s.OpenMs -gt 2000){ $rows += New-Row 'ENV-1' 'ENV' 'WARN' $b.Name 'SQL open latency' "$($b.Name): opening a SQL connection to '$($s.DataSource)' took $($s.OpenMs) ms." 'Investigate SQL Server load / network latency.' }
            if($s.Note -match 'login refused'){ $rows += New-Row 'ENV-1' 'ENV' 'INFO' $b.Name 'SQL login' "$($b.Name): '$($s.DataSource)' is reachable; login was refused for the operator account (expected)." '' }
        }
    }
    $rows
}
function Test-ENV2 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes | Where-Object { $_.Reachable -and $_.Common -and $_.Common.Identity })){
        $id = $b.Common.Identity
        if($null -ne $id.SysDriveFreeGb -and $id.SysDriveTotalGb){
            $pct = if($id.SysDriveTotalGb -gt 0){ ($id.SysDriveFreeGb/$id.SysDriveTotalGb)*100 } else { 100 }
            if($id.SysDriveFreeGb -lt 5 -or $pct -lt 10){ $rows += New-Row 'ENV-2' 'ENV' 'WARN' $b.Name 'System drive free space' "$($b.Name): system drive has $($id.SysDriveFreeGb) GB free ($([int]$pct)%)." 'Free up disk space on the system drive.' }
        }
        foreach($m in @($b.Common.Media)){
            if($null -eq $m.FreeGb -or $null -eq $m.TotalGb -or $m.TotalGb -le 0){ continue }
            $pct = ($m.FreeGb/$m.TotalGb)*100
            if($m.FreeGb -lt 5 -or $pct -lt 10){ $rows += New-Row 'ENV-2' 'ENV' 'WARN' $b.Name 'Recorder media folder free space' "$($b.Name): media folder $($m.Path) has $($m.FreeGb) GB free ($([int]$pct)%)." 'Free up space, or add storage, on the recording media volume.' }
        }
    }
    $rows
}
function Test-ENV3 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes | Where-Object { $_.Reachable -and $_.Common -and $_.Common.Identity })){
        $id = $b.Common.Identity
        if($id.MemTotalMb -and $id.MemTotalMb -gt 0 -and $null -ne $id.MemFreeMb){
            $pct = ($id.MemFreeMb/$id.MemTotalMb)*100
            if($pct -lt 10){ $rows += New-Row 'ENV-3' 'ENV' 'WARN' $b.Name 'Free physical memory' "$($b.Name): $([int]$pct)% free physical memory ($($id.MemFreeMb) MB of $($id.MemTotalMb) MB)." 'Investigate memory pressure on this box.' }
        }
    }
    $rows
}
function Test-ENV4 { param($Result)
    $rows=@()
    foreach($b in @($Result.Boxes | Where-Object { $_.Kind -eq 'MS' -and $_.Reachable -and $_.Ms })){
        $ev = $b.Ms.EventLog
        if(-not $ev -or -not $ev.Ok){ continue }
        $isOwner = (-not $b.IsNode) -or $b.Active
        if($ev.InvalidClient -and $isOwner){ $rows += New-Row 'ENV-4' 'ENV' 'FAIL' $b.Name 'Event log: invalid_client' "$($b.Name): the Application log shows 'invalid_client' in the last 24h - the Management Server cannot authenticate." 'Re-register this node with Mrc-Guided.ps1 (Re-register this node).' }
        if($ev.ErrorCount -gt 0 -or $ev.WarnCount -gt 0){
            $top = (@($ev.Top) | ForEach-Object { "$($_.Line) (x$($_.Count))" }) -join '; '
            $rows += New-Row 'ENV-4' 'ENV' 'WARN' $b.Name 'Event log: Milestone errors/warnings (24h)' "$($b.Name): $($ev.ErrorCount) error(s), $($ev.WarnCount) warning(s) in the last 24h. Top: $top" 'Review the Application event log for the root cause.'
        }
        if($ev.CertSsl){ $rows += New-Row 'ENV-4' 'ENV' 'WARN' $b.Name 'Event log: certificate/SSL errors' "$($b.Name): certificate/SSL/TLS errors found in the Application log in the last 24h." 'Check certificate validity, trust and bindings on this box.' }
    }
    $rows
}

$script:AllEvaluators = @(
    'Test-INV1','Test-INV2',
    'Test-NET1','Test-NET2','Test-NET3','Test-NET4',
    'Test-SVC1','Test-SVC2','Test-SVC3',
    'Test-REG1','Test-REG2',
    'Test-ENC1','Test-ENC2','Test-ENC3','Test-ENC4',
    'Test-CLU1','Test-CLU2','Test-CLU3','Test-CLU4','Test-CLU5',
    'Test-IIS1','Test-IIS2','Test-IIS3',
    'Test-CFG1','Test-CFG2','Test-CFG3',
    'Test-ENV1','Test-ENV2','Test-ENV3','Test-ENV4',
    'Test-COL1'
)
function Invoke-DoctorEvaluate { param($Result)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($fn in $script:AllEvaluators) { foreach ($r in @(& (Get-Item "Function:$fn") $Result)) { $rows.Add($r) } }
    $rows.ToArray()
}

# ===================== DOCTOR: RENDER (HTML + CSV + TXT) =====================
function Get-HtmlEsc { param([string]$Text) if($null -eq $Text){ return '' }; ([string]$Text) -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }
function Get-StatusRank { param([string]$Status) switch($Status){ 'FAIL'{0} 'WARN'{1} 'PASS'{2} 'INFO'{3} default{4} } }

$script:AreaTitles = [ordered]@{
    INV='Inventory'; NET='Reachability'; SVC='Services'; REG='Registration'; ENC='Encryption and certificates'
    CLU='Cluster'; IIS='IIS'; CFG='Config'; ENV='Environment'; COL='Collection (parts that could not be read)'
}

function New-DoctorHtml { param($Result,[object[]]$Rows)
    $fail = @($Rows | Where-Object { $_.Status -eq 'FAIL' }).Count
    $warn = @($Rows | Where-Object { $_.Status -eq 'WARN' }).Count
    $pass = @($Rows | Where-Object { $_.Status -eq 'PASS' }).Count
    $info = @($Rows | Where-Object { $_.Status -eq 'INFO' }).Count
    $verdict = if($fail){'FAIL'} elseif($warn){'WARN'} else {'OK'}
    $verdictColor = if($fail){'#b00020'} elseif($warn){'#b8860b'} else {'#1b7a1b'}
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<!doctype html><html><head><meta charset="utf-8"><title>Milestone XProtect Doctor report</title><style>')
    [void]$sb.Append('body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222;background:#fff}')
    [void]$sb.Append('h1{margin-bottom:4px} h2{margin-top:32px;border-bottom:2px solid #ccc;padding-bottom:4px}')
    [void]$sb.Append('table{border-collapse:collapse;width:100%;margin:8px 0} th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top;font-size:13px}')
    [void]$sb.Append('th{background:#f2f2f2} tr.FAIL{background:#fdecea} tr.WARN{background:#fff8e1} tr.PASS{background:#eef7ee} tr.INFO{background:#f5f5f5}')
    [void]$sb.Append('.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-weight:bold;color:#fff;font-size:12px}')
    [void]$sb.Append('.badge-FAIL{background:#b00020} .badge-WARN{background:#b8860b} .badge-PASS{background:#1b7a1b} .badge-INFO{background:#607d8b}')
    [void]$sb.Append('summary{cursor:pointer;color:#555;margin:6px 0}')
    [void]$sb.Append('</style></head><body>')
    [void]$sb.Append("<h1>Milestone XProtect Doctor report</h1>")
    [void]$sb.Append("<p><b>Generated (UTC):</b> $(Get-HtmlEsc $Result.GeneratedUtc)<br>")
    [void]$sb.Append("<b>Management Server:</b> $(Get-HtmlEsc $Result.MsComputer) (target: $(Get-HtmlEsc $Result.TargetMsHost))<br>")
    [void]$sb.Append("<b>Account used:</b> $(Get-HtmlEsc $Result.Account)<br>")
    [void]$sb.Append("<b>Counts:</b> FAIL $fail, WARN $warn, PASS $pass, INFO $info<br>")
    [void]$sb.Append("<b>Overall verdict:</b> <span class='badge' style='background:$verdictColor'>$verdict</span></p>")
    foreach ($area in $script:AreaTitles.Keys) {
        $areaRows = @($Rows | Where-Object { $_.Area -eq $area } | Sort-Object { Get-StatusRank $_.Status })
        if (-not $areaRows.Count) { continue }
        [void]$sb.Append("<h2>$area - $(Get-HtmlEsc $script:AreaTitles[$area])</h2>")
        $main = @($areaRows | Where-Object { $_.Status -ne 'PASS' })
        $passRows = @($areaRows | Where-Object { $_.Status -eq 'PASS' })
        if ($main.Count) {
            [void]$sb.Append('<table><tr><th>Id</th><th>Status</th><th>Computer</th><th>Check</th><th>Finding</th><th>Fix</th></tr>')
            foreach ($r in $main) {
                [void]$sb.Append("<tr class='$($r.Status)'><td>$(Get-HtmlEsc $r.Id)</td><td><span class='badge badge-$($r.Status)'>$($r.Status)</span></td><td>$(Get-HtmlEsc $r.Computer)</td><td>$(Get-HtmlEsc $r.Check)</td><td>$(Get-HtmlEsc $r.Finding)</td><td>$(Get-HtmlEsc $r.Fix)</td></tr>")
            }
            [void]$sb.Append('</table>')
        }
        if ($passRows.Count) {
            [void]$sb.Append("<details><summary>PASS rows ($($passRows.Count)) - click to expand</summary><table><tr><th>Id</th><th>Status</th><th>Computer</th><th>Check</th><th>Finding</th></tr>")
            foreach ($r in $passRows) {
                [void]$sb.Append("<tr class='$($r.Status)'><td>$(Get-HtmlEsc $r.Id)</td><td><span class='badge badge-$($r.Status)'>$($r.Status)</span></td><td>$(Get-HtmlEsc $r.Computer)</td><td>$(Get-HtmlEsc $r.Check)</td><td>$(Get-HtmlEsc $r.Finding)</td></tr>")
            }
            [void]$sb.Append('</table></details>')
        }
    }
    [void]$sb.Append('</body></html>')
    $sb.ToString()
}

function New-DoctorCsv { param([object[]]$Rows)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('Id,Area,Status,Computer,Check,Finding,Fix')
    $esc = { param($v) '"' + (([string]$v) -replace '"','""') + '"' }
    foreach ($r in ($Rows | Sort-Object { Get-StatusRank $_.Status })) {
        $lines.Add((@($r.Id,$r.Area,$r.Status,$r.Computer,$r.Check,$r.Finding,$r.Fix) | ForEach-Object { & $esc $_ }) -join ',')
    }
    ($lines.ToArray() -join "`r`n")
}
function New-DoctorTxt { param($Result,[object[]]$Rows)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('MILESTONE XPROTECT DOCTOR REPORT')
    $lines.Add("Generated (UTC): $($Result.GeneratedUtc)")
    $lines.Add("Management Server: $($Result.MsComputer) (target: $($Result.TargetMsHost))")
    $lines.Add("Account: $($Result.Account)")
    $fail = @($Rows | Where-Object { $_.Status -eq 'FAIL' }).Count
    $warn = @($Rows | Where-Object { $_.Status -eq 'WARN' }).Count
    $lines.Add("Counts: FAIL $fail, WARN $warn, PASS $(@($Rows | Where-Object { $_.Status -eq 'PASS' }).Count), INFO $(@($Rows | Where-Object { $_.Status -eq 'INFO' }).Count)")
    $lines.Add('')
    foreach ($area in $script:AreaTitles.Keys) {
        $areaRows = @($Rows | Where-Object { $_.Area -eq $area } | Sort-Object { Get-StatusRank $_.Status })
        if (-not $areaRows.Count) { continue }
        $lines.Add("--- $area - $($script:AreaTitles[$area]) ---")
        foreach ($r in $areaRows) {
            $lines.Add("[$($r.Status)] $($r.Id) $($r.Computer): $($r.Check) - $($r.Finding)$(if($r.Fix){" FIX: $($r.Fix)"})")
        }
        $lines.Add('')
    }
    ($lines.ToArray() -join "`r`n")
}

# Report-writer: the ONLY place in this file allowed to create a folder / write a file - allowlisted by
# name in tools/Test-Doctor.ps1's read-only AST scan (New-Item here only ever creates the LOCAL report
# folder; nothing on any other computer is ever written).
function Save-DoctorReport { param($Result,[object[]]$Rows)
    if (-not (Test-Path -LiteralPath $script:RunsDir)) { [void](New-Item -ItemType Directory -Path $script:RunsDir -Force) }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $htmlPath = Join-Path $script:RunsDir "doctor-$stamp.html"
    $csvPath  = Join-Path $script:RunsDir "doctor-$stamp.csv"
    $txtPath  = Join-Path $script:RunsDir "doctor-$stamp.txt"
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($htmlPath, (New-DoctorHtml $Result $Rows), $utf8)
    [IO.File]::WriteAllText($csvPath, (New-DoctorCsv $Rows), $utf8)
    [IO.File]::WriteAllText($txtPath, (New-DoctorTxt $Result $Rows), $utf8)
    $script:LastReportPath = $txtPath
    $script:LastReportHtml = $htmlPath
    [pscustomobject]@{ Html=$htmlPath; Csv=$csvPath; Txt=$txtPath }
}

# ===================== DOCTOR: RUN PIPELINE (Targets -> Collect -> Evaluate -> Render) =====================
function Invoke-DoctorRun {
    Read-DoctorInputs
    Write-Log "Domain: $script:DomainName; Event Server: $(if($script:NoEs){'(none typed - discovered/local only)'}else{$script:EsAddr})" 'Good'
    $discover = [string]::IsNullOrWhiteSpace($script:ManualRecBox.Text)
    $derr = Initialize-Targets -ManualList $script:ManualRecBox.Text -Discover $discover
    if ($derr -and $discover) { Write-Log "Recording server discovery failed: $derr (continuing with none found - type them in 'Extra recording servers' and run again for full coverage)" 'Err' }
    $script:ScSearchPaths = $script:SearchPathsBox.Text.Trim()
    Write-Log "Computers: $(@(Get-AllBoxes).Count) box(es) to check." 'Good'
    Write-Log 'Collecting facts (read-only)...'
    $result = Invoke-DoctorCollect
    Write-Log 'Evaluating...'
    $rows = Invoke-DoctorEvaluate $result
    $paths = Save-DoctorReport $result $rows
    $fail = @($rows | Where-Object { $_.Status -eq 'FAIL' }).Count
    $warn = @($rows | Where-Object { $_.Status -eq 'WARN' }).Count
    Write-Log "Report: $($paths.Html)" 'Good'
    Write-Log "OVERALL: FAIL=$fail WARN=$warn" $(if($fail -or $warn){'Err'}else{'Good'})
    [pscustomobject]@{ Result=$result; Rows=$rows; Paths=$paths; Fail=$fail; Warn=$warn }
}

# ===================== DOCTOR: WINDOW (Connect page, reused fields, + Run checks) =====================
function New-DoctorLabel { param([string]$Text,[int]$X,[int]$Y,[int]$W=290,[int]$H=24)
    $l=[Windows.Forms.Label]::new(); $l.Text=$Text; $l.Location=[Drawing.Point]::new($X,$Y); $l.Size=[Drawing.Size]::new($W,$H); $l.TextAlign='MiddleLeft'; $l }
function New-UiText { param([int]$X,[int]$Y,[int]$W=320,[string]$Text='',[bool]$Pw=$false)
    $b=[Windows.Forms.TextBox]::new(); $b.Location=[Drawing.Point]::new($X,$Y); $b.Width=$W; $b.Text=$Text; if($Pw){$b.UseSystemPasswordChar=$true}; $b }
function New-DoctorButton { param([string]$Text,[int]$X,[int]$Y,[int]$W=180,[int]$H=34)
    $b=[Windows.Forms.Button]::new(); $b.Text=$Text; $b.Location=[Drawing.Point]::new($X,$Y); $b.Size=[Drawing.Size]::new($W,$H); $b }
function New-DoctorCheck { param([string]$Text,[int]$X,[int]$Y,[int]$W=560)
    $c=[Windows.Forms.CheckBox]::new(); $c.Text=$Text; $c.Location=[Drawing.Point]::new($X,$Y); $c.Size=[Drawing.Size]::new($W,26); $c }

function Build-DoctorWindow {
    $script:Form = [Windows.Forms.Form]::new()
    $script:Form.Text = 'Milestone XProtect Doctor (read-only health check)'
    $script:Form.Size = [Drawing.Size]::new(720,760)
    $script:Form.StartPosition = 'CenterScreen'
    $script:Form.MinimumSize = [Drawing.Size]::new(640,600)

    $y=16
    $script:Form.Controls.Add((New-DoctorLabel 'Domain (DNS suffix):' 16 $y 200)); $script:DomainBox=New-UiText 230 $y 300 ([string]$script:Defaults.Domain); $script:Form.Controls.Add($script:DomainBox); $y+=34
    $script:NoEsChk = New-DoctorCheck 'The Event Server is on this computer, or not installed' 16 $y 620; $script:Form.Controls.Add($script:NoEsChk); $y+=30
    $script:Form.Controls.Add((New-DoctorLabel 'Event Server host:' 16 $y 200)); $script:EsHostBox=New-UiText 230 $y 300 ([string]$script:Defaults.EsHost); $script:Form.Controls.Add($script:EsHostBox); $y+=34
    $script:Form.Controls.Add((New-DoctorLabel 'Admin account:' 16 $y 200)); $script:AdminUserBox=New-UiText 230 $y 300 ([string]$script:Defaults.MsUser); $script:Form.Controls.Add($script:AdminUserBox); $y+=34
    $script:Form.Controls.Add((New-DoctorLabel 'Admin password:' 16 $y 200)); $script:AdminPwBox=New-UiText 230 $y 300 '' $true; $script:Form.Controls.Add($script:AdminPwBox); $y+=34
    $script:RecSepChk = New-DoctorCheck 'Recording servers use a different account' 16 $y 500; $script:Form.Controls.Add($script:RecSepChk); $y+=30
    $script:Form.Controls.Add((New-DoctorLabel 'Recording server account:' 16 $y 200)); $script:RecUserBox=New-UiText 230 $y 300 ([string]$script:Defaults.RecUser); $script:Form.Controls.Add($script:RecUserBox); $y+=34
    $script:Form.Controls.Add((New-DoctorLabel 'Recording server password:' 16 $y 200)); $script:RecPwBox=New-UiText 230 $y 300 '' $true; $script:Form.Controls.Add($script:RecPwBox); $y+=34
    $script:Form.Controls.Add((New-DoctorLabel 'Extra recording servers (one per line, name or name=IP; blank = discover from the VMS):' 16 $y 660)); $y+=22
    $script:ManualRecBox=[Windows.Forms.TextBox]::new(); $script:ManualRecBox.Multiline=$true; $script:ManualRecBox.ScrollBars='Vertical'
    $script:ManualRecBox.Location=[Drawing.Point]::new(16,$y); $script:ManualRecBox.Size=[Drawing.Size]::new(660,64); $script:Form.Controls.Add($script:ManualRecBox); $y+=74
    $script:Form.Controls.Add((New-DoctorLabel 'Search folders for ServerConfigurator.exe (; separated):' 16 $y 660)); $y+=22
    $script:SearchPathsBox=New-UiText 16 $y 660 ([string]$script:Defaults.SearchPaths); $script:Form.Controls.Add($script:SearchPathsBox); $y+=36
    $script:RunBtn = New-DoctorButton 'Run checks' 16 $y 200 40; $script:Form.Controls.Add($script:RunBtn)
    $script:OpenReportBtn = New-DoctorButton 'Open report' 230 $y 200 40; $script:OpenReportBtn.Enabled=$false; $script:Form.Controls.Add($script:OpenReportBtn)
    $script:OpenLogBtn = New-DoctorButton 'Open log' 444 $y 200 40; $script:Form.Controls.Add($script:OpenLogBtn); $y+=50
    $script:StatusLabel = New-DoctorLabel '' 16 $y 660 24; $script:StatusLabel.ForeColor=[Drawing.Color]::DarkOrange; $script:Form.Controls.Add($script:StatusLabel); $y+=26
    $script:CountsLabel = New-DoctorLabel '' 16 $y 660 24; $script:Form.Controls.Add($script:CountsLabel); $y+=30
    $script:Log = [Windows.Forms.RichTextBox]::new(); $script:Log.Location=[Drawing.Point]::new(16,$y); $script:Log.Size=[Drawing.Size]::new(660,220); $script:Log.ReadOnly=$true
    $script:Log.Anchor='Top,Bottom,Left,Right'; $script:Log.Font=[Drawing.Font]::new('Consolas',9); $script:Form.Controls.Add($script:Log)

    $script:RunBtn.Add_Click({
        $script:RunBtn.Enabled=$false; $script:OpenReportBtn.Enabled=$false; $script:StatusLabel.Text='Running checks - this can take a few minutes (recorders are checked in parallel). Nothing is changed.'
        [Windows.Forms.Application]::DoEvents()
        try {
            $r = Invoke-DoctorRun
            $script:CountsLabel.Text = "FAIL $($r.Fail)   WARN $($r.Warn)   PASS $(@($r.Rows | Where-Object { $_.Status -eq 'PASS' }).Count)   INFO $(@($r.Rows | Where-Object { $_.Status -eq 'INFO' }).Count)"
            $script:OpenReportBtn.Enabled = $true
        } catch {
            Write-Log "DOCTOR FAILED: $(Format-Err $_)" 'Err'
            $lp = Save-UiLog
            [Windows.Forms.MessageBox]::Show("Could not complete the checks:`r`n$(Get-FirstLine $_.Exception.Message)$(if($lp){"`r`n`r`nFull details: click 'Open log' ($lp)."})",'Milestone Doctor',0,'Error') | Out-Null
        } finally { $script:StatusLabel.Text=''; $script:RunBtn.Enabled=$true }
    })
    $script:OpenReportBtn.Add_Click({ if($script:LastReportHtml -and (Test-Path -LiteralPath $script:LastReportHtml)){ Start-Process $script:LastReportHtml } })
    $script:OpenLogBtn.Add_Click({ $p=Save-UiLog; if($p -and (Test-Path -LiteralPath $p)){ Start-Process notepad.exe $p } })
}

# ===================== DOCTOR: MAIN =====================
Build-DoctorWindow
$script:MsAddrValue = [string]$MsAddr

if ($script:Headless) {
    try {
        if ([string]::IsNullOrWhiteSpace($AdminPwFile) -or -not (Test-Path -LiteralPath $AdminPwFile)) { Write-Log "REFUSED: -AdminPwFile not found: $AdminPwFile" 'Err'; exit 3 }
        $script:DomainBox.Text     = $Domain
        $script:NoEsChk.Checked    = [bool]$NoEventServer
        $script:EsHostBox.Text     = $(if ($NoEventServer) { '' } else { $EsHost })
        $script:AdminUserBox.Text  = $AdminUser
        $script:AdminPwBox.Text    = (Get-Content -Raw -LiteralPath $AdminPwFile).Trim()
        if ($RecPwFile) {
            if (-not (Test-Path -LiteralPath $RecPwFile)) { Write-Log "REFUSED: -RecPwFile not found: $RecPwFile" 'Err'; exit 3 }
            if ([string]::IsNullOrWhiteSpace($RecUser)) { Write-Log 'REFUSED: -RecPwFile given without -RecUser' 'Err'; exit 3 }
            $script:RecSepChk.Checked = $true; $script:RecUserBox.Text = $RecUser; $script:RecPwBox.Text = (Get-Content -Raw -LiteralPath $RecPwFile).Trim()
        }
        $script:ManualRecBox.Text   = $RecTargets
        $script:SearchPathsBox.Text = $SearchPaths
        Write-Log "Output dir: $script:RunsDir" 'Good'
        if ($script:DefaultsLoadError) { Write-Log "WARNING: mrc.defaults.psd1 failed to parse: $script:DefaultsLoadError - using built-in placeholders" 'Err' }
        elseif ($script:DefaultsLoaded.Count) { Write-Log "Loaded defaults from mrc.defaults.psd1: $($script:DefaultsLoaded -join ', ')" }
        $r = Invoke-DoctorRun
        exit ([int]([bool]$r.Fail))
    } catch { Write-Log "DOCTOR FATAL: $(Format-Err $_)" 'Err'; exit 2 }
} else {
    [void]$script:Form.ShowDialog()
}
