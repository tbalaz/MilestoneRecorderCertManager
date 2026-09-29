#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone XProtect recording-server encryption console (GUI) - remote recorders only.

.DESCRIPTION
    Point-and-click front end to enable / disable Milestone XProtect server encryption on
    RECORDING SERVERS via ServerConfigurator.exe, run over WinRM against each recorder in
    parallel (throttled runspace pool), with self-verifying Confirm (reconnect, heal Milestone
    services, check the cert binding) after every apply.

    This tool does NOT touch the Management Server or the Event Server - separate single-file
    GUIs cover those roles now (run them locally on those machines). Run THIS tool on the
    management server or any admin workstation with WinRM reach and local admin rights on every
    target recorder; discovering recorders from the VMS needs MilestonePSTools installed on the
    machine running this GUI (manual "Add recorder" / "Load list..." work without it).

    Enable issues a fresh CA-signed certificate per recorder (CN = the recorder's own DNS name),
    imports it (+ trusts the signer CA, grants NETWORK SERVICE on the key) and runs
    ServerConfigurator /enableencryption for the Server certificate group (84430eb7) - the same
    group a recorder co-located on the management server already gets from that box's own GUI -
    plus, optionally, the Streaming media group (549df21d) for recorders running an image server
    component. Disable runs ServerConfigurator /disableencryption for the same group(s).
    Minted certificates carry CN = the resolved recorder FQDN, with SANs = FQDN + short name +
    any Extra SANs (per-row 'Sans' grid cell or -ExtraSans), for recorders reachable/registered
    under alias addresses.

    Recorder certificates must chain to the SAME CA that signed the management server's own
    certificate, or the recorder's re-registration with the management server fails. Point the
    'Sign with MilestoneCA from cert store' / 'Signer PFX' controls at that CA. The signer CA's
    public .cer is trusted into each recorder's LocalMachine\Root store automatically as part of
    the enable flow - no manual cert distribution needed.

    Connecting to remote/workgroup recorders by IP needs them in WinRM TrustedHosts - the app
    tries to add them automatically (run elevated for that to succeed). Edit the FQDN cell to an
    IP when the recorder's name does not resolve.

    All site-specific defaults ship CLEARED to placeholders (e.g. <management-server-fqdn>). Fill
    them in the GUI for your environment. For convenient repeat use in one environment, drop a
    'mrc.defaults.psd1' next to this script (see Deployment defaults below); it is gitignored and
    must never be shipped to a client.
.NOTES
    Interactive (operator on the management-server console or a workstation, run elevated):
        powershell -ExecutionPolicy Bypass -STA -File .\Mrc-Rec-Gui.ps1

    Headless discovery check (prints the discovered recorder grid, no encryption changes):
        powershell -ExecutionPolicy Bypass -File .\Mrc-Rec-Gui.ps1 -TestDiscover `
            -MsAddr <mgmt-fqdn-or-url> -MsUser '<MGMTSERVER>\Administrator' -MsPwFile <path-to-pw-file> `
            -SelfTestDomain <domain-suffix>

    Headless recorder test (same Do-Enable/Do-Disable code paths the buttons call - no clicks);
    supply your own values, password read from a file (never on the command line):
        powershell -ExecutionPolicy Bypass -File .\Mrc-Rec-Gui.ps1 -RecTargets '<rec1-fqdn>,<rec2-fqdn>' `
            -RecAction cycle -RecUser <domain>\Administrator -RecPwFile <path-to-pw-file> `
            -SelfTestDomain <domain-suffix> -RootSubject '<signer-subject>' -LogFile <path-to-log>
    -RecAction enable|disable|cycle (cycle = disable then enable). Exits 0 only if every recorder
    ends the run in the expected state.
    -ExtraSans adds extra SAN DNS names (e.g. alias addresses) to every minted certificate.
#>
[CmdletBinding()]
param(
    [string]$MsAddr = '<management-server-address>',    # VMS address for discovery (Connect-Vms) - NOT a target; used only to find recorders
    [string]$SelfTestDomain = '<domain-suffix>',
    [switch]$TestDiscover,                              # headless: run discovery via Do-Load and print the grid rows, then exit
    [string]$MsUser = '<MGMTSERVER>\Administrator',     # VMS discovery credential (Connect-Vms), used by -TestDiscover and the GUI 'VMS user' box
    [string]$MsPwFile,                                  # file holding the VMS discovery password (headless only)
    [string]$LogFile,                                   # optional: tee the log here (survives WinRM session drops)
    [string]$RecTargets,                                # headless: comma-separated recorder host/IP list to test (parallel)
    [ValidateSet('enable','disable','cycle')][string]$RecAction = 'cycle',
    [string]$RecUser = '',                              # resolves via mrc.defaults.psd1 RecUser, default Administrator
    [string]$RecPwFile,                                 # file holding the recorder admin password
    [int]$MaxParallel = 32,                             # runspace throttle for recorder parallelism
    [switch]$CreateRoot,                                # headless: generate a fresh self-signed root CA before the run
    [string]$RootSubject = '<signer-subject>',          # subject for -CreateRoot AND for store-mode signer lookup (matched by CN)
    [string]$ExtraSans = '',                            # extra SAN DNS names for minted certs (comma/space/semicolon/newline separated), e.g. recorder alias addresses
    [switch]$SkipOrderCheck                             # headless: bypass the role-order gate (recorders must follow the management server's encryption state)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Deployment defaults (client-ready) ------------------------------------------------------
# This tool ships with NEUTRAL placeholders so nothing site-specific is baked into the file.
# Fill the real values in the GUI for your environment. For convenient repeat use in ONE known
# environment, drop a 'mrc.defaults.psd1' next to this script containing any subset of the keys
# below, e.g.:
#     @{ MsAddr='https://mgmt.contoso.local'; Domain='contoso.local'; MsUser='MGMT01\Administrator'
#        SignerSubject='CN=Contoso VMS CA'; RecUser='Administrator'; ExtraSans='vms-alias.contoso.local' }
# That file is gitignored and must NEVER be shipped to a client - it is operator convenience only.
$script:Defaults = @{
    MsAddr        = '<management-server-fqdn-url>'   # GUI 'Management Server' box - used only to connect for VMS discovery (Connect-Vms), e.g. https://mgmt.company.local
    Domain        = '<domain-suffix>'                # GUI 'Domain suffix' box, e.g. company.local (or DNS suffix / workgroup)
    MsUser        = '<MGMTSERVER>\Administrator'      # GUI 'VMS user' (Connect-Vms discovery credential only)
    RecUser       = 'Administrator'                   # GUI 'Recorder admin user' (generic)
    SignerSubject = 'CN=<Your Organization> CA'       # GUI 'Root CA subject' (store-mode signer match / Create root CA)
    ExtraSans     = ''                                # extra cert SAN names (aliases); also GUI per-row 'Extra SANs' cell
}
$script:DefaultsLoaded = @()
$script:DefaultsLoadError = $null
if ($PSScriptRoot) {
    $script:DefFile = Join-Path $PSScriptRoot 'mrc.defaults.psd1'
    if (Test-Path -LiteralPath $script:DefFile) {
        try { $ov = Import-PowerShellDataFile -LiteralPath $script:DefFile
              foreach ($k in @($ov.Keys)) { $script:Defaults[$k] = $ov[$k] }
              $script:DefaultsLoaded = @($ov.Keys) }
        catch { $script:DefaultsLoadError = $_.Exception.Message
                Write-Warning "mrc.defaults.psd1 found but FAILED to parse - using built-in placeholders. $($_.Exception.Message)" }
    }
}
# Headless params left at their placeholder (or empty) fall back to the deployment defaults above,
# so a mrc.defaults.psd1 makes headless runs work without restating values; a client with no
# override gets the placeholder and a clear failure telling them to supply real values.
function Resolve-Default { param([string]$Value,[string]$Key)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '<[^>]+>') { [string]$script:Defaults[$Key] } else { $Value } }
$MsUser         = Resolve-Default $MsUser         'MsUser'
$SelfTestDomain = Resolve-Default $SelfTestDomain 'Domain'
$MsAddr         = Resolve-Default $MsAddr         'MsAddr'
$RootSubject    = Resolve-Default $RootSubject    'SignerSubject'
$RecUser        = Resolve-Default $RecUser        'RecUser'
$ExtraSans      = Resolve-Default $ExtraSans      'ExtraSans'

# ===================== INLINED ENGINE (from MrcEngine.psm1) =====================
<#
.SYNOPSIS
    Shared engine for Milestone recorder/management-server certificate + encryption automation.
.DESCRIPTION
    Single source of truth for the lab-verified ServerConfigurator SYSTEM-jump enable-encryption
    mechanism. Consumed by the GUI front-end (MilestoneRecorderCertManager.ps1) and the headless
    rollout runner (Invoke-MrcRollout.ps1).

    The two Invoke-Remote* functions and the inline launcher are copied VERBATIM from the
    lab-verified GUI script - do not "improve" or DRY-refactor the remote scriptblocks; their
    exact form is what was proven end-to-end (2026-05-29).

    Mechanism: a one-shot scheduled task runs as NT AUTHORITY\SYSTEM; an inline C# launcher does
    LogonUser(target, INTERACTIVE) + (elevated linked token under UAC) + CreateProcessAsUser(
    ServerConfigurator.exe). Interactive logon carries credential material so SC's
    recorder->management-server IDP re-registration second hop succeeds.
.NOTES
    ServerConfigurator /enableencryption exit codes:
       0    success
       100  local cert applied BUT MS registration failed ("not authorized") => run-as account
            is not in the Milestone Administrators role on the management server
       -4   silent failure: recorder cert chains to an untrusted root (install signer CA into
            LocalMachine\Root) OR a stuck ServerConfigurator instance holds the singleton lock
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Milestone certificate-group GUIDs (constant across XProtect installs).
$script:CertGroupServer    = '84430eb7-847c-422d-aa00-7915cd0d7a65'   # server / recording-server comms (port 7563)
$script:CertGroupStreaming = '549df21d-047c-456b-958e-99e65dd8b3ec'   # streaming media (mobile/web)
$script:SignerImportedForRun = $false

# -- SYSTEM-jump launcher: PS1 template with inline C# (VERBATIM) -----------
$script:LauncherCSharp = @'
$ErrorActionPreference = 'Stop'
$pwFile  = '__PWFILE__'
$cmdLine = '__CMDLINE__'
$workDir = '__WORKDIR__'
$user    = '__USER__'
$dom     = '__DOMAIN__'
$pw = (Get-Content -LiteralPath $pwFile -Raw)
Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class MrcLauncher2 {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
        public Int32 cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public Int32 dwX; public Int32 dwY; public Int32 dwXSize; public Int32 dwYSize;
        public Int32 dwXCountChars; public Int32 dwYCountChars; public Int32 dwFillAttribute;
        public Int32 dwFlags; public Int16 wShowWindow; public Int16 cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess; public IntPtr hThread; public Int32 dwProcessId; public Int32 dwThreadId;
    }
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LogonUser(string user, string domain, string pw,
        int logonType, int logonProvider, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUser(IntPtr token, string appName, string cmdLine,
        IntPtr procAttr, IntPtr threadAttr, bool inherit, UInt32 flags, IntPtr env,
        string curDir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, UInt32 size, out UInt32 retSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern UInt32 WaitForSingleObject(IntPtr h, UInt32 ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr h, out UInt32 exit);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    const int LOGON32_LOGON_INTERACTIVE = 2;
    const int LOGON32_PROVIDER_DEFAULT  = 0;
    const int TokenElevationType        = 18;
    const int TokenLinkedToken          = 19;
    const int TokenElevationTypeLimited = 3;
    const UInt32 CREATE_NO_WINDOW = 0x08000000;
    const UInt32 INFINITE         = 0xFFFFFFFF;
    static IntPtr GetElevatedToken(IntPtr baseToken) {
        IntPtr typePtr = Marshal.AllocHGlobal(4);
        try {
            UInt32 ret;
            if (!GetTokenInformation(baseToken, TokenElevationType, typePtr, 4, out ret)) return baseToken;
            int elevType = Marshal.ReadInt32(typePtr);
            if (elevType != TokenElevationTypeLimited) return baseToken;
            IntPtr linkPtr = Marshal.AllocHGlobal(IntPtr.Size);
            try {
                if (!GetTokenInformation(baseToken, TokenLinkedToken, linkPtr, (UInt32)IntPtr.Size, out ret)) return baseToken;
                IntPtr linked = Marshal.ReadIntPtr(linkPtr);
                return linked != IntPtr.Zero ? linked : baseToken;
            } finally { Marshal.FreeHGlobal(linkPtr); }
        } finally { Marshal.FreeHGlobal(typePtr); }
    }
    public static int Run(string user, string dom, string pw, string cmdLine, string workDir) {
        IntPtr token;
        if (!LogonUser(user, dom, pw, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out token)) {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, "LogonUser failed (Win32=" + err + ")");
        }
        IntPtr useToken = GetElevatedToken(token);
        bool linkedDifferent = (useToken != token);
        try {
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = "winsta0\\default";
            PROCESS_INFORMATION pi;
            if (!CreateProcessAsUser(useToken, null, cmdLine, IntPtr.Zero, IntPtr.Zero, false,
                    CREATE_NO_WINDOW, IntPtr.Zero, workDir, ref si, out pi)) {
                int err = Marshal.GetLastWin32Error();
                throw new Win32Exception(err, "CreateProcessAsUser failed (Win32=" + err + ")");
            }
            WaitForSingleObject(pi.hProcess, INFINITE);
            UInt32 exit;
            GetExitCodeProcess(pi.hProcess, out exit);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return (int)exit;
        } finally {
            if (linkedDifferent) CloseHandle(useToken);
            CloseHandle(token);
        }
    }
}
"@ -Language CSharp
exit [MrcLauncher2]::Run($user, $dom, $pw, $cmdLine, $workDir)
'@

# -- Certificate helpers ---------------------------------------------------
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
function ConvertTo-SanList {
    # Parse operator-entered extra SAN names: newline / comma / semicolon / space separated.
    # Returns validated, lowercased, deduplicated DNS names; throws on an invalid entry.
    param([string]$Raw)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($tok in ($Raw -split '[\r\n,; ]+')) {
        $t = $tok.Trim().TrimEnd('.').ToLowerInvariant()
        if (-not $t) { continue }
        if ($t -notmatch '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$') {
            throw "Extra SAN '$t' is not a valid DNS name."
        }
        if ($out -notcontains $t) { [void]$out.Add($t) }
    }
    $out.ToArray()
}
function Resolve-CertFqdn {
    # The encryption certificate MUST carry the DNS name the server knows itself by. The Management
    # Server validates its OWN cert during IDP registration (it connects to its configured
    # https://<fqdn>/). A cert minted from an IP (e.g. Normalize-RecorderHostName '192.168.1.10'
    # -> '192' -> CN=192.company.local) fails that validation -> SC exit 300000 -> the Management Server
    # service will not start. So: never derive a CN from an IP. Prefer a real DNS name; for the local
    # machine fall back to its own identity (the name it self-registers with); else fail loudly.
    param([string]$Target, [string]$Fqdn, [string]$DomainSuffix)
    $dom = Get-DomainSuffix $DomainSuffix
    $isIpish = {
        param($s)
        $ip = $null
        if ([System.Net.IPAddress]::TryParse($s, [ref]$ip)) { return $true }
        if ($s -match '^\d[\d.]*$') { return $true }   # all-numeric dotted labels: malformed/partial IP, never a hostname
        $false
    }
    $localFqdn = ("{0}.{1}" -f $env:COMPUTERNAME, $dom).ToLowerInvariant()
    foreach ($cand in @($Fqdn, $Target)) {
        $c = ([string]$cand).Trim()
        if (-not $c) { continue }
        if ($c -eq 'localhost' -or $c -eq '127.0.0.1' -or $c -eq '::1') { return $localFqdn }
        if (& $isIpish $c) { continue }
        if ($c -notmatch '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$') {
            throw "'$c' is neither a valid DNS name nor an IP address. Fix the FQDN cell - an invalid certificate CN breaks the server's IDP registration."
        }
        return $(if ($c -match '\.') { $c.ToLowerInvariant() } else { Get-RecorderFqdn -HostName $c -DomainSuffix $dom })
    }
    # Only IP(s) available. If an IP points at THIS machine, use its own FQDN (what it self-registers with).
    $localIps = @('127.0.0.1', '::1')
    try { $localIps += ([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) | ForEach-Object { $_.IPAddressToString }) } catch {}
    foreach ($cand in @($Target, $Fqdn)) { if (([string]$cand).Trim() -in $localIps) { return $localFqdn } }
    # Remote IP: last-resort reverse DNS, else refuse (an IP-named cert WILL break the server).
    foreach ($cand in @($Fqdn, $Target)) {
        $c = ([string]$cand).Trim()
        if ($c -and (& $isIpish $c)) { try { $r = [System.Net.Dns]::GetHostEntry($c).HostName; if ($r -and -not (& $isIpish $r)) { return $r.ToLowerInvariant() } } catch {} }
    }
    throw "Cannot mint a certificate for IP-only target '$Target'. Put the server's real DNS name in the FQDN cell - an IP-named certificate breaks the server's IDP registration."
}
function Test-SigningCertificate {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    if (-not $Certificate.HasPrivateKey) { throw 'The selected certificate does not contain a private key.' }
    $hasSign = $false; $isCA = $false
    foreach ($ext in $Certificate.Extensions) {
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
            $hasSign = (($ext.KeyUsages -band [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign) -ne 0)
        }
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            $isCA = $ext.CertificateAuthority
        }
    }
    if (-not $isCA)    { throw 'The selected certificate is not marked as a certificate authority.' }
    if (-not $hasSign) { throw 'The selected certificate does not include KeyCertSign usage.' }
}
function Import-SignerCertificate {
    param([string]$PfxPath, [securestring]$Password)
    if (-not (Test-Path -LiteralPath $PfxPath)) { throw "Signer PFX not found: $PfxPath" }
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    $loaded = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $Password, $flags)
    $existing = Get-ChildItem -LiteralPath "Cert:\CurrentUser\My\$($loaded.Thumbprint)" -ErrorAction SilentlyContinue
    $script:SignerImportedForRun = $null -eq $existing
    $imported = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation 'Cert:\CurrentUser\My' -Password $Password -Exportable -ErrorAction Stop
    if ($imported -is [array]) { $imported = $imported | Where-Object HasPrivateKey | Select-Object -First 1 }
    if ($null -eq $imported) { throw 'No private-key certificate was imported from the signer PFX.' }
    try { Test-SigningCertificate -Certificate $imported; $imported }
    catch {
        if ($script:SignerImportedForRun) {
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($imported.Thumbprint)" -Force -ErrorAction SilentlyContinue
            $script:SignerImportedForRun = $false
        }
        throw
    }
}
function New-RecorderCertificatePackage {
    param(
        [string]$HostName, [string]$DomainSuffix,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Signer,
        [securestring]$PfxPassword, [string]$OutputDir,
        [string[]]$ExtraDnsNames = @()
    )
    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $short = Normalize-RecorderHostName $HostName
    # A dotted HostName is a fully resolved cert FQDN (from Resolve-CertFqdn) - use it VERBATIM;
    # only a bare short name gets the Domain-suffix appended. Rebuilding from the domain box
    # silently rewrote cross-domain names and broke the CN.
    $fqdn  = if ($HostName.Trim() -match '\.') { $HostName.Trim().ToLowerInvariant() } else { Get-RecorderFqdn -HostName $short -DomainSuffix $DomainSuffix }
    $dns   = @(@($fqdn, $short) + $ExtraDnsNames | Where-Object { $_ } | Select-Object -Unique)
    $cert  = New-SelfSignedCertificate `
        -Subject "CN=$fqdn" -DnsName $dns -Signer $Signer `
        -KeyExportPolicy Exportable -KeyUsage DigitalSignature, KeyEncipherment `
        -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(2) -CertStoreLocation 'Cert:\CurrentUser\My' `
        -TextExtension @('2.5.29.19={text}CA=false', '2.5.29.37={text}1.3.6.1.5.5.7.3.1')
    try {
        $pfx = Join-Path $OutputDir "$short.pfx"
        $cer = Join-Path $OutputDir "$short.cer"
        Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $PfxPassword -Force | Out-Null
        Export-Certificate    -Cert $cert -FilePath $cer -Type CERT -Force | Out-Null
        [pscustomobject]@{ HostName = $short; Fqdn = $fqdn; Thumbprint = $cert.Thumbprint; PfxPath = $pfx; CerPath = $cer }
    } finally {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
    }
}

function New-RootCa {
    # Generate a fresh self-signed ROOT CA (basic constraint CA=true, KeyCertSign) usable as the
    # -Signer for per-host certs. Stays in <Store>\My with its private key; public cert exported to
    # OutputDir for distribution/trust. Satisfies Test-SigningCertificate (CA + KeyCertSign).
    param(
        [string]$Subject = 'CN=MilestoneCA',
        [string]$OutputDir,
        [int]$Years = 10,
        [ValidateSet('CurrentUser','LocalMachine')][string]$Store = 'CurrentUser'
    )
    $ca = New-SelfSignedCertificate `
        -Subject $Subject `
        -KeyExportPolicy Exportable -KeyLength 4096 -KeyAlgorithm RSA -HashAlgorithm SHA256 `
        -KeyUsage CertSign, CRLSign, DigitalSignature `
        -NotAfter (Get-Date).AddYears($Years) -CertStoreLocation "Cert:\$Store\My" `
        -TextExtension @('2.5.29.19={text}CA=true')
    if ($OutputDir) {
        if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
        $cn  = ($Subject -replace '.*CN=','' -replace ',.*','').Trim()
        $cer = Join-Path $OutputDir (($cn -replace '[^A-Za-z0-9._-]','_') + '-root.cer')
        Export-Certificate -Cert $ca -FilePath $cer -Type CERT -Force | Out-Null
    }
    $ca
}

# True when the target IS this machine (localhost, its short name, FQDN, or any local IP).
# Then WinRM is skipped entirely and scriptblocks run in-process: the GUI commonly runs ON the
# management server, where loopback WinRM is often not enabled and remoting to self fails.
# The SC SYSTEM-jump is unaffected - it authenticates via LogonUser inside the scriptblock,
# never via the session identity.
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

# -- Remote install + encryption (VERBATIM lab-verified SYSTEM-jump) --------
function Invoke-RemoteRecorderInstall {
    param(
        [string]$ComputerName, [pscredential]$Credential, [bool]$UseSsl,
        [string]$PfxPath, [securestring]$PfxPassword, [string]$SignerCerPath,
        [bool]$InstallSignerToRoot, [bool]$InstallSignerToIntermediate,
        [bool]$EnableEncryption, [string]$ServerConfiguratorPath,
        [pscredential]$ScCredential, [string]$CertificateGroup = ''
    )
    $LocalLauncherSource = if (Test-Path Variable:script:LauncherCSharp) { $script:LauncherCSharp } else { $LauncherCSharp }
    $session = $null; $scSession = $null
    $log = [System.Collections.Generic.List[string]]::new()
    try {
        $isLocal = Test-LocalTarget $ComputerName
        $icm = @{}
        if ($isLocal) {
            $log.Add("Target $ComputerName is THIS machine - running in-process (no WinRM)")
        } else {
            $sp = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }; if ($Credential) { $sp.Credential = $Credential }
            if ($UseSsl) { $sp.UseSSL = $true }
            $log.Add("Connecting to $ComputerName  [WinRM cred: $($Credential.UserName)]")
            $session   = New-PSSession @sp
            $log.Add('WinRM session established')
            $icm = @{ Session = $session }
        }
        $remoteDir = Invoke-Command @icm -ScriptBlock {
            $d = Join-Path $env:TEMP ("MRC-{0}" -f [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $d -Force | Out-Null; $d
        }
        $log.Add("Remote temp dir: $remoteDir")
        $rpfx = Join-Path $remoteDir (Split-Path $PfxPath -Leaf)
        if ($isLocal) { Copy-Item -Path $PfxPath -Destination $rpfx -Force }
        else { Copy-Item -Path $PfxPath -Destination $rpfx -ToSession $session -Force }
        $log.Add("PFX copied -> $rpfx")
        $rcer = $null
        if (($InstallSignerToRoot -or $InstallSignerToIntermediate) -and (Test-Path -LiteralPath $SignerCerPath)) {
            $rcer = Join-Path $remoteDir (Split-Path $SignerCerPath -Leaf)
            if ($isLocal) { Copy-Item -Path $SignerCerPath -Destination $rcer -Force }
            else { Copy-Item -Path $SignerCerPath -Destination $rcer -ToSession $session -Force }
            $log.Add("Signer CER copied -> $rcer")
        }
        $imp = Invoke-Command @icm -ScriptBlock {
            param([string]$RPfx, [securestring]$RPw, [string]$RCer, [bool]$Root, [bool]$Inter)
            $ErrorActionPreference = 'Stop'
            $rlog = [System.Collections.Generic.List[string]]::new()
            $rlog.Add("[$env:COMPUTERNAME] Importing PFX -> Cert:\LocalMachine\My")
            $c = Import-PfxCertificate -FilePath $RPfx -CertStoreLocation 'Cert:\LocalMachine\My' -Password $RPw -Exportable:$false
            if ($c -is [array]) { $c = $c | Select-Object -First 1 }
            if ($null -eq $c) { throw 'Recorder PFX import returned no certificate.' }
            $rlog.Add("[$env:COMPUTERNAME] Imported  tp=$($c.Thumbprint)  subj=$($c.Subject)")
            # Grant NETWORK SERVICE Read on private key so VideoOS.Recorder.Service (Schannel on port 7563) can use it.
            # Without this, port 7563 TLS handshake fails with "Local Security Authority cannot be contacted" and Smart Client gets no video.
            try {
                $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
                $keyName = if ($rsa -and $rsa.Key) { $rsa.Key.UniqueName } else { $c.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName }
                $keyFile = $null
                foreach ($d in @("$env:ProgramData\Microsoft\Crypto\Keys", "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys")) {
                    $p = Join-Path $d $keyName
                    if (Test-Path -LiteralPath $p) { $keyFile = $p; break }
                }
                if ($keyFile) {
                    $kAcl = Get-Acl -Path $keyFile
                    $kAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\NETWORK SERVICE','Read','Allow')))
                    Set-Acl -Path $keyFile -AclObject $kAcl
                    $rlog.Add("[$env:COMPUTERNAME] Granted NETWORK SERVICE Read on private key ($keyName)")
                } else {
                    $rlog.Add("[$env:COMPUTERNAME] WARNING: private key file not located for $($c.Thumbprint) - port 7563 TLS may fail")
                }
            } catch { $rlog.Add("[$env:COMPUTERNAME] WARNING: failed to grant NETWORK SERVICE on key: $($_.Exception.Message)") }
            if ($RCer) {
                if ($Root)  { Import-Certificate -FilePath $RCer -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null; $rlog.Add("[$env:COMPUTERNAME] Signer -> Root store") }
                if ($Inter) { Import-Certificate -FilePath $RCer -CertStoreLocation 'Cert:\LocalMachine\CA'   | Out-Null; $rlog.Add("[$env:COMPUTERNAME] Signer -> Intermediate store") }
            }
            Remove-Item -LiteralPath $RPfx -Force -ErrorAction SilentlyContinue
            if ($RCer) { Remove-Item -LiteralPath $RCer -Force -ErrorAction SilentlyContinue }
            Remove-Item -LiteralPath (Split-Path $RPfx -Parent) -Force -Recurse -ErrorAction SilentlyContinue
            [pscustomobject]@{ Thumbprint = $c.Thumbprint; Subject = $c.Subject; Logs = $rlog.ToArray() }
        } -ArgumentList $rpfx, $PfxPassword, $rcer, $InstallSignerToRoot, $InstallSignerToIntermediate
        foreach ($l in $imp.Logs) { $log.Add($l) }
        $encResult = $null
        if ($EnableEncryption) {
            if ($ScCredential -and -not $isLocal) {
                $ssp = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }; if ($ScCredential) { $ssp.Credential = $ScCredential }
                if ($UseSsl) { $ssp.UseSSL = $true }
                $log.Add("Opening SC session  [cred: $($ScCredential.UserName)]")
                $scSession = New-PSSession @ssp
                $log.Add('SC session established')
            }
            $icmEnc = if ($scSession) { @{ Session = $scSession } } else { $icm }
            $scRunCred = if ($ScCredential) { $ScCredential } else { $Credential }
            $log.Add("Calling Set-XProtectCertificate  tp=$($imp.Thumbprint)")
            $encOut = Invoke-Command @icmEnc -ScriptBlock {
                param([string]$Tp, [string]$ConfPath, [pscredential]$RunCred, [string]$LauncherSource, [string]$CertGroup)
                $ErrorActionPreference = 'Stop'
                $elog = [System.Collections.Generic.List[string]]::new()
                $Tp = ($Tp -replace '[^A-Fa-f0-9]', '').ToUpperInvariant()
                $elog.Add("[$env:COMPUTERNAME] Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)")
                $elog.Add("[$env:COMPUTERNAME] Thumbprint (sanitized): $Tp")
                # ServerConfigurator.exe location on THIS computer (install folders differ per server): the search
                # list in $ConfPath first (exe paths, or folders: <f>, <f>\Server Configurator, <f>\Milestone\Server
                # Configurator), then <Milestone root>\Server Configurator derived from the Milestone service image
                # paths, then %ProgramFiles%\Milestone; last, a bounded recursive search of the given folders.
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
                if (-not (Test-Path -LiteralPath $scExe)) { throw "ServerConfigurator not found: $scExe" }
                $scDir   = [System.IO.Path]::GetDirectoryName($scExe)
                # Kill any stale ServerConfigurator first: its singleton lock makes the next run exit -4/1 silently.
                Get-Process -Name ServerConfigurator -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 800
                $work    = Join-Path $env:windir ("Temp\MRC-{0}" -f [guid]::NewGuid().ToString('N'))
                New-Item -ItemType Directory -Path $work -Force | Out-Null
                $outFile = Join-Path $work 'out.txt'
                $errFile = Join-Path $work 'err.txt'
                $cmdFile = Join-Path $work 'run.cmd'
                $scArgs = "/enableencryption /quiet /thumbprint=$Tp"
                if ($CertGroup) { $scArgs += " /certificategroup=$CertGroup" }
                Set-Content -LiteralPath $cmdFile -Encoding ASCII -Value @('@echo off', "cd /d ""$scDir""", """$scExe"" $scArgs 1> ""$outFile"" 2> ""$errFile""", 'exit /b %ERRORLEVEL%')
                $nc = $RunCred.GetNetworkCredential()
                $launchUser = $nc.UserName
                $launchDom  = if ([string]::IsNullOrWhiteSpace($nc.Domain)) { '.' } else { $nc.Domain }
                $launchPw   = $nc.Password
                $cmdSpec    = '"{0}" /c "{1}"' -f "$env:windir\System32\cmd.exe", $cmdFile
                $pwFile     = Join-Path $work 'pw.txt'
                [IO.File]::WriteAllText($pwFile, $launchPw)
                $aclPw = Get-Acl -Path $pwFile
                $aclPw.SetAccessRuleProtection($true, $false)
                foreach ($idName in @('NT AUTHORITY\SYSTEM','BUILTIN\Administrators')) {
                    $aclPw.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($idName, 'FullControl', 'Allow')))
                }
                Set-Acl -Path $pwFile -AclObject $aclPw
                $launcherPs1 = Join-Path $work 'launcher.ps1'
                $ps1Body = $LauncherSource.
                    Replace('__USER__',    ($launchUser -replace "'","''")).
                    Replace('__DOMAIN__',  ($launchDom  -replace "'","''")).
                    Replace('__PWFILE__',  ($pwFile     -replace "'","''")).
                    Replace('__CMDLINE__', ($cmdSpec    -replace "'","''")).
                    Replace('__WORKDIR__', ($scDir      -replace "'","''"))
                [IO.File]::WriteAllText($launcherPs1, $ps1Body, [Text.UTF8Encoding]::new($true))
                $taskName = "MRC-SCSys-$([guid]::NewGuid().ToString('N').Substring(0,8))"
                $elog.Add("[$env:COMPUTERNAME] SYSTEM task ${taskName}: LogonUser+CreateProcessAsUser as ${launchDom}\${launchUser} -> $scExe $scArgs")
                $action    = New-ScheduledTaskAction -Execute "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$launcherPs1`""
                $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
                $sett      = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
                Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $sett -Force | Out-Null
                try {
                    Start-ScheduledTask -TaskName $taskName
                    $deadline = (Get-Date).AddMinutes(10)
                    do {
                        Start-Sleep -Seconds 2
                        $state  = (Get-ScheduledTask -TaskName $taskName).State
                        $scExit = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
                    } while (($state -eq 'Running' -or $scExit -eq 267009 -or $scExit -eq 267011) -and (Get-Date) -lt $deadline)
                } finally {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath $pwFile      -Force -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath $launcherPs1 -Force -ErrorAction SilentlyContinue
                    Get-Process -Name ServerConfigurator -ErrorAction SilentlyContinue | Where-Object { (New-TimeSpan -Start $_.StartTime -End (Get-Date)).TotalMinutes -lt 30 } | Stop-Process -Force -ErrorAction SilentlyContinue
                }
                $stdout = (Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue)
                $stderr = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
                Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
                $elog.Add("[$env:COMPUTERNAME] SC stdout: $(if ($stdout -and $stdout.Trim()) { $stdout.Trim() } else { '(empty)' })")
                $elog.Add("[$env:COMPUTERNAME] SC stderr: $(if ($stderr -and $stderr.Trim()) { $stderr.Trim() } else { '(empty)' })")
                $elog.Add("[$env:COMPUTERNAME] SC exit code: $scExit")
                $scLog = Get-ChildItem -Path (Join-Path $env:ProgramData 'Milestone') -Recurse -Filter '*.log' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match 'erver.?onfigurator' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                $runLines = @()
                if ($scLog) {
                    $allLog = @(Get-Content -LiteralPath $scLog.FullName -ErrorAction SilentlyContinue)
                    # Scope to THIS invocation only: lines from the last 'Arguments:' enableencryption marker onward.
                    # A blind tail spans earlier runs and produces FALSE 'Registration done = Success' positives.
                    $argIdx = -1
                    for ($i = $allLog.Count - 1; $i -ge 0; $i--) { if ($allLog[$i] -match 'Arguments:.*enableencryption') { $argIdx = $i; break } }
                    $runLines = if ($argIdx -ge 0) { @($allLog[$argIdx..($allLog.Count - 1)]) } else { @($allLog | Select-Object -Last 60) }
                    $scTail = ($runLines | Select-Object -Last 80) -join ' || '
                    $elog.Add("[$env:COMPUTERNAME] SC log [$($scLog.Name)] (this run): $scTail")
                } else {
                    $elog.Add("[$env:COMPUTERNAME] SC log: none found")
                }
                $certApplied = (($runLines -match "\.ApplyCertificate'? Status = Success").Count -gt 0) -or (($runLines -match 'Registration done with result = Success').Count -gt 0)
                if ($scExit -ne 0 -and $scExit -ne 100 -and $scExit -ne 200000 -and -not $certApplied) { throw "ServerConfigurator exited $scExit | $($elog.ToArray() -join ' | ')" }
                if ($scExit -eq 100) { $elog.Add("[$env:COMPUTERNAME] NOTE: SC exit 100 - local cert applied but MS registration FAILED - encryption NOT fully enabled") }
                elseif ($scExit -eq 300000 -or $scExit -eq 100000) { $elog.Add("[$env:COMPUTERNAME] NOTE: SC exit $scExit - cert was BOUND but IDP/system registration FAILED (usually cert CN does not match the server's configured address, or IDP 403). This is a FAILURE: the server may not start.") }
                elseif ($scExit -ne 0 -and $certApplied) { $elog.Add("[$env:COMPUTERNAME] NOTE: SC exit $scExit - cert APPLIED successfully; post-apply step failed (likely mgmt server unreachable) - treating as success") }
                [pscustomobject]@{ ExitCode = [int64]$scExit; CertApplied = [bool]$certApplied; Logs = $elog.ToArray() }
            } -ArgumentList $imp.Thumbprint, $ServerConfiguratorPath, $scRunCred, $LocalLauncherSource, $CertificateGroup
            foreach ($l in $encOut.Logs) { $log.Add($l) }
            $encResult = if ($encOut.ExitCode -eq 300000 -or $encOut.ExitCode -eq 100000) { 'Failed' } elseif ($encOut.ExitCode -eq 0 -or $encOut.CertApplied) { 'Enabled' } elseif ($encOut.ExitCode -eq 100) { 'PartialNotAuthorized' } else { 'Failed' }
        }
        [pscustomobject]@{ Thumbprint = $imp.Thumbprint; Subject = $imp.Subject; Encryption = $encResult; ExitCode = $(if ($encResult) { $encOut.ExitCode } else { $null }); Logs = $log.ToArray() }
    } finally {
        if ($scSession) { Remove-PSSession -Session $scSession -ErrorAction SilentlyContinue }
        if ($session)   { Remove-PSSession -Session $session   -ErrorAction SilentlyContinue }
    }
}
function Invoke-RemoteServerEncryption {
    param([string]$ComputerName, [pscredential]$Credential, [bool]$UseSsl,
          [string]$Thumbprint, [string]$ServerConfiguratorPath,
          [pscredential]$ScCredential, [string]$CertificateGroup = '',
          [ValidateSet('enableencryption','disableencryption')][string]$Action = 'enableencryption')
    $LocalLauncherSource = if (Test-Path Variable:script:LauncherCSharp) { $script:LauncherCSharp } else { $LauncherCSharp }
    $session = $null
    $log = [System.Collections.Generic.List[string]]::new()
    try {
        $connCred = if ($ScCredential) { $ScCredential } else { $Credential }
        $icm = @{}
        if (Test-LocalTarget $ComputerName) {
            $log.Add("Target $ComputerName is THIS machine - running in-process (no WinRM)")
        } else {
            $sp = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }; if ($connCred) { $sp.Credential = $connCred }
            if ($UseSsl) { $sp.UseSSL = $true }
            $log.Add("Connecting to $ComputerName  [cred: $($connCred.UserName)]")
            $session = New-PSSession @sp
            $log.Add('Session established')
            $icm = @{ Session = $session }
        }
        $log.Add("Calling Set-XProtectCertificate  tp=$Thumbprint")
        $encOut = Invoke-Command @icm -ScriptBlock {
            param([string]$Tp, [string]$ConfPath, [pscredential]$RunCred, [string]$LauncherSource, [string]$CertGroup, [string]$EncAction)
            $ErrorActionPreference = 'Stop'
            $elog = [System.Collections.Generic.List[string]]::new()
            $Tp = ($Tp -replace '[^A-Fa-f0-9]', '').ToUpperInvariant()
            $elog.Add("[$env:COMPUTERNAME] Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)")
            $elog.Add("[$env:COMPUTERNAME] Action: $EncAction  Thumbprint (sanitized): $Tp")
            $certTp = $Tp
            if ($EncAction -eq 'enableencryption') {
                try { $cert = Get-ChildItem -LiteralPath "Cert:\LocalMachine\My\$Tp" -ErrorAction Stop }
                catch { throw "Cert not found in LocalMachine\My: $Tp | $($elog.ToArray() -join ' | ')" }
                $certTp = $cert.Thumbprint
                $elog.Add("[$env:COMPUTERNAME] Found cert: $($cert.Subject)")
            }
            # ServerConfigurator.exe location on THIS computer (install folders differ per server): the search
            # list in $ConfPath first (exe paths, or folders: <f>, <f>\Server Configurator, <f>\Milestone\Server
            # Configurator), then <Milestone root>\Server Configurator derived from the Milestone service image
            # paths, then %ProgramFiles%\Milestone; last, a bounded recursive search of the given folders.
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
            if (-not (Test-Path -LiteralPath $scExe)) { throw "ServerConfigurator not found: $scExe | $($elog.ToArray() -join ' | ')" }
            $scDir   = [System.IO.Path]::GetDirectoryName($scExe)
            # Kill any stale ServerConfigurator first: its singleton lock makes the next run exit -4/1 silently.
            Get-Process -Name ServerConfigurator -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 800
            $work    = Join-Path $env:windir ("Temp\MRC-{0}" -f [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $work -Force | Out-Null
            # E1: protect the work folder itself (SYSTEM + Administrators, no inheritance) before ANY
            # file is written into it - pw.txt must never land in a folder any authenticated user can read.
            $aclWork = Get-Acl -Path $work
            $aclWork.SetAccessRuleProtection($true, $false)
            foreach ($idName in @('NT AUTHORITY\SYSTEM','BUILTIN\Administrators')) {
                $aclWork.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($idName, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            }
            Set-Acl -Path $work -AclObject $aclWork
            $outFile = Join-Path $work 'out.txt'
            $errFile = Join-Path $work 'err.txt'
            $cmdFile = Join-Path $work 'run.cmd'
            if ($EncAction -eq 'disableencryption') {
                $scArgs = "/disableencryption /quiet"
            } else {
                $scArgs = "/enableencryption /quiet /thumbprint=$Tp"
            }
            if ($CertGroup) { $scArgs += " /certificategroup=$CertGroup" }
            Set-Content -LiteralPath $cmdFile -Encoding ASCII -Value @('@echo off', "cd /d ""$scDir""", """$scExe"" $scArgs 1> ""$outFile"" 2> ""$errFile""", 'exit /b %ERRORLEVEL%')
            $nc = $RunCred.GetNetworkCredential()
            $launchUser = $nc.UserName
            $launchDom  = if ([string]::IsNullOrWhiteSpace($nc.Domain)) { '.' } else { $nc.Domain }
            $launchPw   = $nc.Password
            $cmdSpec    = '"{0}" /c "{1}"' -f "$env:windir\System32\cmd.exe", $cmdFile
            $pwFile     = Join-Path $work 'pw.txt'
            $taskName   = "MRC-SCSys-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            $taskRegistered = $false
            $launcherPs1 = $null
            $state = $null; $scExit = $null
            try {
                # E1: everything from the pw.txt write to the end of the task is ONE try/finally - a
                # failure anywhere in here (Set-Acl, Register-ScheduledTask, the wait loop) still cleans
                # up the secret file and the launcher, and unregisters the task only if it was registered.
                [IO.File]::WriteAllText($pwFile, $launchPw)
                $aclPw = Get-Acl -Path $pwFile
                $aclPw.SetAccessRuleProtection($true, $false)
                foreach ($idName in @('NT AUTHORITY\SYSTEM','BUILTIN\Administrators')) {
                    $aclPw.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($idName, 'FullControl', 'Allow')))
                }
                Set-Acl -Path $pwFile -AclObject $aclPw
                $launcherPs1 = Join-Path $work 'launcher.ps1'
                $ps1Body = $LauncherSource.
                    Replace('__USER__',    ($launchUser -replace "'","''")).
                    Replace('__DOMAIN__',  ($launchDom  -replace "'","''")).
                    Replace('__PWFILE__',  ($pwFile     -replace "'","''")).
                    Replace('__CMDLINE__', ($cmdSpec    -replace "'","''")).
                    Replace('__WORKDIR__', ($scDir      -replace "'","''"))
                [IO.File]::WriteAllText($launcherPs1, $ps1Body, [Text.UTF8Encoding]::new($true))
                $elog.Add("[$env:COMPUTERNAME] SYSTEM task ${taskName}: LogonUser+CreateProcessAsUser as ${launchDom}\${launchUser} -> $scExe $scArgs")
                $action    = New-ScheduledTaskAction -Execute "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$launcherPs1`""
                $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
                $sett      = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
                Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $sett -Force | Out-Null
                $taskRegistered = $true
                Start-ScheduledTask -TaskName $taskName
                $deadline = (Get-Date).AddMinutes(10)
                do {
                    Start-Sleep -Seconds 2
                    $state  = (Get-ScheduledTask -TaskName $taskName).State
                    $scExit = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
                } while (($state -eq 'Running' -or $scExit -eq 267009 -or $scExit -eq 267011) -and (Get-Date) -lt $deadline)
                if ($state -eq 'Running' -or $scExit -eq 267009 -or $scExit -eq 267011) {
                    # E2: the 10-minute deadline passed and the task is still running - do not give up here.
                    # Wait up to 10 more minutes for the ServerConfigurator PROCESS itself to exit. Never kill it.
                    $elog.Add("[$env:COMPUTERNAME] still running after 10 minutes - waiting up to 10 more minutes for ServerConfigurator to exit on its own")
                    $procDeadline = (Get-Date).AddMinutes(10)
                    $procGone = $false
                    do {
                        Start-Sleep -Seconds 2
                        if (-not (Get-Process -Name ServerConfigurator -ErrorAction SilentlyContinue)) { $procGone = $true; break }
                    } while ((Get-Date) -lt $procDeadline)
                    if (-not $procGone) {
                        throw "ServerConfigurator is still running after 20 minutes on $env:COMPUTERNAME - stopped here so nothing else changes while it works. Wait for it to finish, check the state, then run again."
                    }
                    $settleDeadline = (Get-Date).AddSeconds(30)
                    do {
                        Start-Sleep -Seconds 2
                        $state  = (Get-ScheduledTask -TaskName $taskName).State
                        $scExit = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
                    } while (($state -eq 'Running' -or $scExit -eq 267009 -or $scExit -eq 267011) -and (Get-Date) -lt $settleDeadline)
                }
            } finally {
                if ($taskRegistered) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
                Remove-Item -LiteralPath $pwFile      -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $launcherPs1 -Force -ErrorAction SilentlyContinue
            }
            $stdout = (Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue)
            $stderr = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
            Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
            $elog.Add("[$env:COMPUTERNAME] SC stdout: $(if ($stdout -and $stdout.Trim()) { $stdout.Trim() } else { '(empty)' })")
            $elog.Add("[$env:COMPUTERNAME] SC stderr: $(if ($stderr -and $stderr.Trim()) { $stderr.Trim() } else { '(empty)' })")
            $elog.Add("[$env:COMPUTERNAME] SC exit code: $scExit")
            $scLog = Get-ChildItem -Path (Join-Path $env:ProgramData 'Milestone') -Recurse -Filter '*.log' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match 'erver.?onfigurator' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            $runLines = @()
            if ($scLog) {
                $allLog = @(Get-Content -LiteralPath $scLog.FullName -ErrorAction SilentlyContinue)
                # Scope to THIS invocation only: lines from the last 'Arguments:' enableencryption marker onward.
                # A blind tail spans earlier runs and produces FALSE 'Registration done = Success' positives.
                $argIdx = -1
                for ($i = $allLog.Count - 1; $i -ge 0; $i--) { if ($allLog[$i] -match 'Arguments:.*(enable|disable)encryption') { $argIdx = $i; break } }
                $runLines = if ($argIdx -ge 0) { @($allLog[$argIdx..($allLog.Count - 1)]) } else { @($allLog | Select-Object -Last 60) }
                $scTail = ($runLines | Select-Object -Last 80) -join ' || '
                $elog.Add("[$env:COMPUTERNAME] SC log [$($scLog.Name)] (this run): $scTail")
            } else {
                $elog.Add("[$env:COMPUTERNAME] SC log: none found")
            }
            if ($EncAction -eq 'disableencryption') {
                $certApplied = (($runLines -match 'Applying No Certificate = Unencrypted').Count -gt 0) -or (($runLines -match "\.ApplyCertificate'? Status = Success").Count -gt 0) -or (($runLines -match "\.RemoveCertificate'? Status = Success").Count -gt 0) -or (($runLines -match 'Registration done with result = Success').Count -gt 0)
            } else {
                $certApplied = (($runLines -match "\.ApplyCertificate'? Status = Success").Count -gt 0) -or (($runLines -match 'Registration done with result = Success').Count -gt 0)
            }
            # /disableencryption returns exit 1 (no apply) when there is nothing to disable - e.g. a recording
            # server while the management server still enforces server-to-server encryption (disable the MS first),
            # or an already-unencrypted host. Do NOT throw; return the code so the caller can judge by the binding.
            if ($scExit -ne 0 -and $scExit -ne 100 -and $scExit -ne 200000 -and -not $certApplied -and -not ($EncAction -eq 'disableencryption' -and $scExit -eq 1)) { throw "ServerConfigurator exited $scExit | $($elog.ToArray() -join ' | ')" }
            if ($scExit -eq 100) { $elog.Add("[$env:COMPUTERNAME] NOTE: SC exit 100 - local cert applied but MS registration FAILED - encryption NOT fully enabled") }
            elseif ($scExit -eq 300000 -or $scExit -eq 100000) { $elog.Add("[$env:COMPUTERNAME] NOTE: SC exit $scExit - cert was BOUND but IDP/system registration FAILED (usually cert CN does not match the server's configured address, or IDP 403). This is a FAILURE: the server may not start. Re-run with a certificate whose CN matches the server's own DNS name.") }
            elseif ($scExit -ne 0 -and $certApplied) { $elog.Add("[$env:COMPUTERNAME] NOTE: SC exit $scExit - $EncAction APPLIED; post-apply step failed (likely mgmt server unreachable) - treating as success") }
            [pscustomobject]@{ Thumbprint = $certTp; ExitCode = [int64]$scExit; CertApplied = [bool]$certApplied; Logs = $elog.ToArray() }
        } -ArgumentList $Thumbprint, $ServerConfiguratorPath, $connCred, $LocalLauncherSource, $CertificateGroup, $Action
        foreach ($l in $encOut.Logs) { $log.Add($l) }
        [pscustomobject]@{ Thumbprint = $encOut.Thumbprint; ExitCode = $encOut.ExitCode; CertApplied = $encOut.CertApplied; Logs = $log.ToArray() }
    } finally { if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue } }
}

# -- Wedge recovery ---------------------------------------------------------
# ServerConfigurator cannot stop a VideoOS service whose control handler has wedged (Win32 1061
# 'The service cannot accept control messages at this time') - SC exits 10000 having applied
# NOTHING. No passive probe detects the wedge beforehand (interrogate returns 1061 even on healthy
# VideoOS services), so SC's own failure IS the detection. This bounces the wedged service on the
# TARGET machine (Stop-Service, kill if the stop itself hits 1061) plus the two known wedge-prone
# siblings SC also has to stop (Log Server, Data Collector - left STOPPED on purpose; stopped is
# valid SC input and SC starts them itself). When the caller needs the service running again
# (Management Server before an enable, or SC skips the IIS 443 rebind) it is restarted and given
# the settle window (uptime >= 240s and :8080 answering) before the SC retry.
function Repair-WedgedService {
    param([string]$ComputerName,[pscredential]$Credential,[bool]$UseSsl,[string]$DisplayName,[bool]$WantRunning)
    $sp=@{}
    if(-not (Test-LocalTarget $ComputerName)){
        $sp=@{ComputerName=$ComputerName;ErrorAction='Stop'}; if($Credential){$sp.Credential=$Credential}; if($UseSsl){$sp.UseSSL=$true}
    }
    Invoke-Command @sp -ScriptBlock {
        param([string]$Dn,[bool]$WantRun)
        $out=[System.Collections.Generic.List[string]]::new()
        $stopOne={ param([string]$d)
            $s=Get-Service | Where-Object { $_.DisplayName -eq $d }
            if(-not $s){ return "service '$d' not present" }
            if($s.Status -eq 'Stopped'){ return "$d already stopped" }
            try { Stop-Service -Name $s.Name -Force -ErrorAction Stop; "stopped $d" }
            catch {
                $svcPid=(Get-CimInstance Win32_Service -Filter "Name='$($s.Name)'").ProcessId
                if($svcPid){ Stop-Process -Id $svcPid -Force -ErrorAction SilentlyContinue; "killed $d (pid $svcPid)" }
                else { "could not stop $d ($($_.Exception.Message))" }
            }
        }
        $out.Add((& $stopOne $Dn))
        foreach($sib in 'Milestone XProtect Data Collector Server','Milestone XProtect Log Server'){
            if($sib -ne $Dn){ $out.Add((& $stopOne $sib)) }
        }
        $svc=Get-Service | Where-Object { $_.DisplayName -eq $Dn }
        if($svc){
            $sw=[System.Diagnostics.Stopwatch]::StartNew()
            while((Get-Service -Name $svc.Name).Status -ne 'Stopped' -and $sw.Elapsed.TotalSeconds -lt 90){ Start-Sleep -Seconds 2 }
            if($WantRun){
                Start-Service -Name $svc.Name; $out.Add("started $Dn")
                $deadline=(Get-Date).AddSeconds(600); $settled=$false
                while((Get-Date) -lt $deadline){
                    Start-Sleep -Seconds 10
                    $age=0
                    $svcPid=(Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'").ProcessId
                    if($svcPid){ try { $age=((Get-Date)-(Get-Process -Id $svcPid -ErrorAction Stop).StartTime).TotalSeconds } catch {} }
                    $port=$false; try { $tc=[System.Net.Sockets.TcpClient]::new(); $tc.Connect('127.0.0.1',8080); $port=$tc.Connected; $tc.Close() } catch {}
                    if($age -ge 240 -and $port){ $out.Add("settled (uptime $([int]$age)s, :8080 up)"); $settled=$true; break }
                }
                if(-not $settled){ $out.Add('WARNING: settle timeout (600s) - retrying SC anyway') }
            }
        }
        $out.ToArray()
    } -ArgumentList $DisplayName,$WantRunning
}

# One SC invocation with a single-shot wedge recovery: if Invoke-RemoteServerEncryption throws the
# 1061 marker, bounce the service SC named in its error and run the SAME SC invocation once more.
function Invoke-ScWithWedgeRetry {
    param([string]$ComputerName,[pscredential]$Credential,[string]$Thumbprint,[string]$CertificateGroup,
          [ValidateSet('enableencryption','disableencryption')][string]$Action,
          [System.Collections.Generic.List[string]]$WorkLog,[string]$GroupName,[string]$ScPaths='')
    try {
        Invoke-RemoteServerEncryption -ComputerName $ComputerName -Credential $Credential -UseSsl:$false `
            -Thumbprint $Thumbprint -ServerConfiguratorPath $ScPaths -ScCredential $Credential -CertificateGroup $CertificateGroup -Action $Action
    } catch {
        $m=$_.Exception.Message
        if($m -notmatch 'cannot accept control messages|Unable to (?:stop|restart) the service|Could not stop service'){ throw }
        if(-not (Test-Path variable:script:WedgeDepth)){ $script:WedgeDepth = 0 }   # StrictMode-safe init (runspaces too)
        if($script:WedgeDepth -ge 3){ $WorkLog.Add("[$GroupName] WEDGE: giving up after 3 recovery attempts"); throw }   # bounded: SC + up to 3 recoveries
        $dn=if($m -match 'Unable to (?:stop|restart) the service (.+?)\.'){ $Matches[1].Trim() }
            elseif($m -match 'Could not stop service MilestoneEventServer'){ 'Milestone XProtect Event Server' }   # SC names the ES by its service name (MilestoneEventServerService)
            elseif($m -match 'Could not stop service (Milestone XProtect [A-Za-z ]+?Server)'){ $Matches[1].Trim() }   # SC 20000 PreExecute CouldNotStopServer variant
            else { 'Milestone XProtect Management Server' }
        $WorkLog.Add("[$GroupName] WEDGE: '$dn' stuck - SC could not stop/restart it (SC 10000) - bouncing it and retrying SC (recovery $($script:WedgeDepth + 1) of 3)")
        $want=($Action -eq 'enableencryption') -and ($dn -like '*Management Server*')
        foreach($l in @(Repair-WedgedService -ComputerName $ComputerName -Credential $Credential -UseSsl:$false -DisplayName $dn -WantRunning $want)){ $WorkLog.Add("[$GroupName] $l") }
        $script:WedgeDepth++
        try { Invoke-ScWithWedgeRetry @PSBoundParameters } finally { $script:WedgeDepth-- }
    }
}

# -- Post-apply confirmation (reconnect-tolerant) --------------------------
# The management-server (and recorder) service restart triggered by applying a
# certificate severs the WinRM session the SC task ran under, so the SC exit
# code often comes back as 267009 ("task still running") and some Milestone
# services can be left Stopped. This opens a FRESH session after the restart,
# starts any stopped Milestone services, and confirms the certificate is bound -
# the authoritative success signal (netsh binding), independent of SC's exit code.
function Confirm-ServerEncryption {
    param([string]$ComputerName, [pscredential]$Credential, [bool]$UseSsl,
          [string]$Thumbprint, [int]$TimeoutSeconds = 180)
    $tp = ($Thumbprint -replace '[^A-Fa-f0-9]', '').ToLowerInvariant()
    $log = [System.Collections.Generic.List[string]]::new()
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $session = $null
    $icm = @{}
    if (-not (Test-LocalTarget $ComputerName)) {
        # reconnect loop: the box may still be restarting services
        while ($null -eq $session -and (Get-Date) -lt $deadline) {
            try {
                $sp = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }; if ($Credential) { $sp.Credential = $Credential }
                if ($UseSsl) { $sp.UseSSL = $true }
                $session = New-PSSession @sp
            } catch { Start-Sleep -Seconds 5 }
        }
        if ($null -eq $session) { return [pscustomobject]@{ Bound = $false; AllServicesRunning = $false; Logs = @("Confirm: could not reconnect to $ComputerName within ${TimeoutSeconds}s") } }
        $icm = @{ Session = $session }
    }
    try {
        $res = Invoke-Command @icm -ScriptBlock {
            param([string]$Tp)
            $rlog = [System.Collections.Generic.List[string]]::new()
            # IIS (W3SVC/WAS) is stopped by the management-server encryption toggle and the IDP
            # web depends on it - start it first, before the Milestone services that talk to it.
            $iisSel = { $_.DisplayName -match 'Milestone XProtect|VideoOS' -or $_.Name -match 'MilestoneEventServer|^W3SVC$|^WAS$' }
            foreach ($iis in 'WAS','W3SVC') {
                $sv = Get-Service $iis -ErrorAction SilentlyContinue
                if ($sv -and $sv.Status -ne 'Running') {
                    try { Start-Service $iis -ErrorAction Stop; $rlog.Add("[$env:COMPUTERNAME] started service: $iis") } catch { $rlog.Add("[$env:COMPUTERNAME] FAILED to start ${iis}: $($_.Exception.Message)") }
                }
            }
            # A Disabled service (e.g. the Event Server service on a standalone MS whose ES role was moved
            # elsewhere) is a valid, intentional state - never a start attempt, never counted as "stopped".
            $svcAll = @(Get-Service | Where-Object $iisSel)
            $disabled = @($svcAll | Where-Object { [string]$_.StartType -eq 'Disabled' } | ForEach-Object { $_.Name })
            if ($disabled.Count) { $rlog.Add("[$env:COMPUTERNAME] skipped (Disabled): $($disabled -join ',')") }
            $svc = @($svcAll | Where-Object { [string]$_.StartType -ne 'Disabled' })
            foreach ($s in ($svc | Where-Object { $_.Status -ne 'Running' })) {
                try { Start-Service $s.Name -ErrorAction Stop; $rlog.Add("[$env:COMPUTERNAME] started service: $($s.Name)") }
                catch { $rlog.Add("[$env:COMPUTERNAME] FAILED to start $($s.Name): $($_.Exception.Message)") }
            }
            Start-Sleep -Seconds 3
            $svc = @(Get-Service | Where-Object $iisSel | Where-Object { [string]$_.StartType -ne 'Disabled' })
            $stopped = @($svc | Where-Object { $_.Status -ne 'Running' } | Select-Object -ExpandProperty Name)
            $binds = (netsh http show sslcert) -join "`n"
            $bound = $binds -match $Tp
            $rlog.Add("[$env:COMPUTERNAME] cert $Tp bound: $bound")
            $rlog.Add("[$env:COMPUTERNAME] services running: $(@($svc | Where-Object Status -eq Running).Count)/$($svc.Count)$(if ($stopped) { ' STILL STOPPED: ' + ($stopped -join ',') })")
            [pscustomobject]@{ Bound = [bool]$bound; AllServicesRunning = ($stopped.Count -eq 0); Stopped = $stopped; Logs = $rlog.ToArray() }
        } -ArgumentList $tp
        foreach ($l in $res.Logs) { $log.Add($l) }
        [pscustomobject]@{ Bound = $res.Bound; AllServicesRunning = $res.AllServicesRunning; Stopped = $res.Stopped; Logs = $log.ToArray() }
    } finally { if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue } }
}

# =================== END INLINED ENGINE ===================


$script:Headless    = $TestDiscover -or [bool]$RecTargets
$script:LogFilePath = $LogFile

# 'Run with PowerShell' (and a normal double-click) starts NON-elevated, but the GUI path needs admin:
# the SYSTEM-jump scheduled task, LocalMachine cert import, netsh SSL binding reads and TrustedHosts
# edits all require it. So relaunch ourselves elevated (+ -STA for WinForms) when interactive and not
# already admin. Headless automation callers manage their own elevation, so skip them.
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

$script:OutputDir = Join-Path ([IO.Path]::GetTempPath()) ("MrcRecGui-{0:yyyyMMdd-HHmmss}" -f (Get-Date))
[void](New-Item -ItemType Directory -Path $script:OutputDir -Force)
$script:RunResults = [System.Collections.Generic.List[object]]::new()
$script:RunsDir    = Join-Path ([IO.Path]::GetTempPath()) 'MilestoneRecorderCertManager-runs'
$script:CertGroupServer = '84430eb7-847c-422d-aa00-7915cd0d7a65'   # Server / recording-server comms (port 7563/9001)
$script:CertGroupStream = '549df21d-047c-456b-958e-99e65dd8b3ec'   # Streaming media (image server)
$script:RootSubjectForRun = $null                                   # set by -RootSubject in headless; else GUI subject box drives store-mode signer lookup

# -- WinForms helpers ------------------------------------------------------
function New-Label { param([string]$Text,[int]$X,[int]$Y,[int]$W=150)
    $l=[Windows.Forms.Label]::new(); $l.Text=$Text; $l.Location=[Drawing.Point]::new($X,$Y); $l.Size=[Drawing.Size]::new($W,22); $l.TextAlign='MiddleLeft'; $l }
function New-Tb { param([int]$X,[int]$Y,[int]$W=240,[string]$Text='',[bool]$Pw=$false)
    $b=[Windows.Forms.TextBox]::new(); $b.Location=[Drawing.Point]::new($X,$Y); $b.Size=[Drawing.Size]::new($W,22); $b.Text=$Text; if($Pw){$b.UseSystemPasswordChar=$true}; $b }
function New-Btn { param([string]$Text,[int]$X,[int]$Y,[int]$W=130)
    $b=[Windows.Forms.Button]::new(); $b.Text=$Text; $b.Location=[Drawing.Point]::new($X,$Y); $b.Size=[Drawing.Size]::new($W,30); $b }

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
function Get-SecurePw { param([string]$Pw) $s=[securestring]::new(); foreach($c in $Pw.ToCharArray()){$s.AppendChar($c)}; $s.MakeReadOnly(); $s }

function Get-CaSubjectCn { param([string]$Subject)
    $cn = ($Subject -replace '.*CN=','' -replace ',.*','').Trim()
    if (-not $cn) { throw "Subject '$Subject' has no CN= component." }
    $cn }
function Find-ExistingCa { param([string]$Subject)
    # Anchored CN match: 'CN=MilestoneCA' must NOT match 'CN=MilestoneCA2'.
    $cn = Get-CaSubjectCn $Subject
    @(Get-ChildItem Cert:\CurrentUser\My,Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
      Where-Object { $_.Subject -match ('(^|[,\s])CN=' + [regex]::Escape($cn) + '($|,)') -and $_.HasPrivateKey }) }

function Resolve-Signer {
    # CA from local cert store (MilestoneCA w/ private key) or a PFX file.
    if($script:SignerStoreRadio.Checked){
        $subj = if($script:SignerSubjectBox -and $script:SignerSubjectBox.Text.Trim()){ $script:SignerSubjectBox.Text }
                elseif($script:RootSubjectForRun){ $script:RootSubjectForRun } else { 'CN=MilestoneCA' }
        $cn = Get-CaSubjectCn $subj
        $ca = Find-ExistingCa $subj | Select-Object -First 1
        if(-not $ca){ throw "No root CA matching 'CN=$cn' with a private key in CurrentUser\My or LocalMachine\My. Click 'Create root CA' (or use -CreateRoot), or use a PFX." }
        return $ca
    } else {
        $p=$script:SignerPfxBox.Text.Trim()
        if(-not (Test-Path -LiteralPath $p)){ throw "Signer PFX not found: $p" }
        return (Import-SignerCertificate -PfxPath $p -Password (Get-SecurePw $script:SignerPwBox.Text))
    }
}

function Ensure-TrustedHosts { param([string[]]$Hosts)
    try {
        $cur=(Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value
        $set=@($cur -split ',' | ForEach-Object { $_.Trim() } | Where-Object {$_})
        # A bare '*' means trust-all and is only valid as the SOLE pattern - appending host names
        # to it makes WinRM reject the whole value. Nothing to add in that case anyway.
        if($set -contains '*'){ Write-Log 'TrustedHosts already "*" (trust-all) - nothing to add.'; return }
        $add=@($Hosts | Where-Object { $_ -and ($set -notcontains $_) -and -not (Test-LocalTarget $_) })
        if($add.Count){ Set-Item WSMan:\localhost\Client\TrustedHosts -Value (($set+$add) -join ',') -Force; Write-Log "TrustedHosts += $($add -join ',')" }
    } catch { Write-Log "TrustedHosts not updated ($($_.Exception.Message.Split([char]10)[0])) - run elevated if WinRM to IPs fails" 'Err' }
}

# -- grid helpers ----------------------------------------------------------
function Add-Row { param([string]$Target,[string]$Role,[string]$Fqdn,[string]$Name='',[string]$Sans='')
    [void]$script:Grid.Rows.Add($true,$Name,$Target,$Role,$Fqdn,$Sans,'','') }
function Get-SelectedRows { @($script:Grid.Rows | Where-Object { -not $_.IsNewRow -and [bool]$_.Cells['Sel'].Value }) }
function Set-RowState { param($Row,[string]$Status,[string]$Tp=$null)
    $Row.Cells['Status'].Value=$Status; if($Tp){$Row.Cells['Tp'].Value=$Tp}; $script:Grid.Refresh(); [Windows.Forms.Application]::DoEvents() }

# -- actions ---------------------------------------------------------------
function Format-Err { param($ErrRec)
    $ex=$ErrRec.Exception; $s=$ex.ToString()
    if([string]::IsNullOrWhiteSpace($s)){ $s="$($ErrRec)" }
    while($ex.InnerException){ $ex=$ex.InnerException; $s+=" --> $($ex.Message)" }
    $s }

function Do-Load {
    # Manual recorders are added unconditionally; only the optional MilestonePSTools discovery
    # can fail, and it must NOT block the rest of the load. This GUI has no Management Server
    # row - every row loaded here is a recording server.
    try {
        $script:Grid.Rows.Clear()
        $domain = Get-DomainSuffix $script:DomainBox.Text
    } catch { Write-Log "Load (base) failed: $(Format-Err $_)" 'Err'; return }

    if($script:DiscoverChk.Checked){
        try {
            if(-not (Get-Module -ListAvailable MilestonePSTools)){ throw 'MilestonePSTools is not installed on this machine. Use "Load list..." (a .txt/.csv of hosts), or install MilestonePSTools.' }
            Import-Module MilestonePSTools -ErrorAction Stop
            $domain = Get-DomainSuffix $script:DomainBox.Text
            $rawHost = try { ([uri]$script:MsAddrBox.Text.Trim()).Host } catch { $script:MsAddrBox.Text.Trim() }
            if([string]::IsNullOrWhiteSpace($rawHost)){ $rawHost=$script:MsAddrBox.Text.Trim() }
            # An ENCRYPTED management server's SDK endpoint answers ONLY on its real server FQDN (the cert CN)
            # over https, NOT on a bare IP or localhost (Connect-Vms -> ServerNotFoundMIPException). An
            # UNENCRYPTED management server answers on http only (https candidates all fail there). So build
            # candidate HOSTS first, then try every host as https:// and again as http://; use the first URL
            # that connects. If the user typed an explicit scheme in the Management Server box, that exact
            # URL is tried first. The GUI usually runs ON the MS, so COMPUTERNAME.<domain> is the cert CN.
            $hosts=[System.Collections.Generic.List[string]]::new()
            $addh={ param($h) if($h -and ($hosts -notcontains $h)){ [void]$hosts.Add($h) } }
            & $addh ("{0}.{1}" -f $env:COMPUTERNAME,$domain)
            if($rawHost -match '^\d{1,3}(\.\d{1,3}){3}$'){
                try { $rev=[System.Net.Dns]::GetHostEntry($rawHost).HostName; & $addh $rev } catch {}
                & $addh $rawHost   # bare IP: useless over https (cert CN), but works fine over http
            } else {
                & $addh $rawHost
                if($rawHost -notmatch '\.'){ & $addh ("{0}.{1}" -f $rawHost,$domain) }
            }
            & $addh $env:COMPUTERNAME
            $cands=[System.Collections.Generic.List[string]]::new()
            $addc={ param($u) if($u -and ($cands -notcontains $u)){ [void]$cands.Add($u) } }
            $typedAddr=$script:MsAddrBox.Text.Trim()
            if($typedAddr -match '^https?://'){ & $addc $typedAddr }
            foreach($h in $hosts){ & $addc "https://$h" }
            foreach($h in $hosts){ & $addc "http://$h" }
            $vmsCred = if(-not [string]::IsNullOrWhiteSpace($script:MsUserBox.Text)){ Get-Cred $script:MsUserBox.Text $script:MsPwBox.Text } else { $null }
            $connected=$false
            $connectedUrl=$null
            foreach($u in $cands){
                try {
                    $cp=@{ServerAddress=[uri]$u;AcceptEula=$true;ErrorAction='Stop'}
                    if($vmsCred){ $cp.Credential=$vmsCred }
                    if($script:VmsBasicChk.Checked){ $cp.BasicUser=$true }   # only for Milestone basic users, NOT windows accounts
                    Write-Log "Connecting VMS $u to discover recorders..."
                    Connect-Vms @cp | Out-Null
                    Write-Log "Connected: $u" 'Good'; $connected=$true; $connectedUrl=$u; break
                } catch { Write-Log "  $u -> $($_.Exception.GetType().Name)" }
            }
            if(-not $connected){ throw "Could not connect to the VMS on any of: $($cands -join ', '). Put the server FQDN in the Management Server box." }
            # Identity of the management-server MACHINE (short names) - used to skip its co-located
            # recorder. COMPUTERNAME alone is wrong when the GUI runs off-box.
            $msNames = [System.Collections.Generic.List[string]]::new()
            $addMs = { param($n) if($n){ try { $s = Normalize-RecorderHostName $n; if($msNames -notcontains $s){ [void]$msNames.Add($s) } } catch {} } }
            try { $vmsMs = Get-VmsManagementServer -ErrorAction Stop; if($vmsMs -and $vmsMs.Name){ & $addMs $vmsMs.Name } } catch {}
            if($connectedUrl){ try { & $addMs (([uri]$connectedUrl).Host) } catch {} }
            if($rawHost -and $rawHost -notmatch '^\d{1,3}(\.\d{1,3}){3}$'){ & $addMs $rawHost }
            elseif($rawHost){ try { & $addMs ([System.Net.Dns]::GetHostEntry($rawHost).HostName) } catch {} }
            & $addMs $env:COMPUTERNAME
            $n=0
            foreach($rec in (Get-VmsRecordingServer | Sort-Object Name)){
                $src= if(-not [string]::IsNullOrWhiteSpace($rec.HostName)){$rec.HostName}else{$rec.Name}
                $isIp = $src -match '^\d{1,3}(\.\d{1,3}){3}$'
                $short= Normalize-RecorderHostName $(if($isIp){ $rec.Name } else { $src })
                $fqdn = if($isIp){ $src } else { Get-RecorderFqdn -HostName $short -DomainSuffix $domain }
                # Co-located recorder (same machine as the management server): its server-to-server
                # cert is applied by the Management Server GUI's own Server group - this tool never
                # touches the management server, so skip it here and say why.
                if($msNames -contains $short){
                    Write-Log "Recorder '$($rec.Name)' runs on the management server - use the Management Server GUI (Server group covers it); skipped."
                    continue
                }
                Add-Row -Target $short -Role 'Recorder' -Fqdn $fqdn -Name $rec.Name; $n++
            }
            Write-Log "Discovered $n recording server(s)." 'Good'
            Disconnect-ManagementServer -ErrorAction SilentlyContinue
        } catch { Write-Log "Discovery failed: $(Format-Err $_)" 'Err' }
    }
    Write-Log "Targets loaded: $($script:Grid.Rows.Count). Edit the FQDN/IP cell for any host that won't resolve, then select + Enable/Disable." 'Good'
}

function Do-LoadList {
    # Bulk-add recorders from a text/CSV file: one host or IP per line. Optional "host,fqdn-or-ip" per line.
    $d=[Windows.Forms.OpenFileDialog]::new(); $d.Filter='Host list (*.txt;*.csv)|*.txt;*.csv|All files (*.*)|*.*'
    if($d.ShowDialog() -ne 'OK'){ return }
    Do-LoadListFile $d.FileName
}
function Do-LoadListFile { param([string]$Path)
    if(-not (Test-Path -LiteralPath $Path)){ Write-Log "List file not found: $Path" 'Err'; return }
    $domain=$script:DomainBox.Text; $n=0
    foreach($line in (Get-Content -LiteralPath $Path)){
        $h=$line.Trim()
        if([string]::IsNullOrWhiteSpace($h) -or $h.StartsWith('#')){ continue }
        $parts=$h -split '[,;\t]'
        $hn=$parts[0].Trim()
        $isIp = $hn -match '^\d{1,3}(\.\d{1,3}){3}$'
        $short= if($isIp){ $hn } else { Normalize-RecorderHostName $hn }
        $fqdn = if($parts.Count -gt 1 -and $parts[1].Trim()){ $parts[1].Trim() }
                elseif($isIp){ $hn }
                else { try { Get-RecorderFqdn -HostName $short -DomainSuffix $domain } catch { $hn } }
        Add-Row -Target $short -Role 'Recorder' -Fqdn $fqdn; $n++
    }
    Write-Log "Loaded $n recorder(s) from $Path" 'Good'
}

function Do-AddRecorder {
    $h=$script:AddRecBox.Text.Trim()
    if([string]::IsNullOrWhiteSpace($h)){ return }
    $short=Normalize-RecorderHostName $h
    # if they typed an IP, keep it as the FQDN; otherwise build host.domain
    $fqdn= if($h -match '^\d{1,3}(\.\d{1,3}){3}$'){ $h } else { try { Get-RecorderFqdn -HostName $short -DomainSuffix $script:DomainBox.Text } catch { $h } }
    Add-Row -Target $short -Role 'Recorder' -Fqdn $fqdn
    $script:AddRecBox.Clear(); Write-Log "Added recorder $short ($fqdn)" 'Good'
}

# Certificate groups applied to every recorder: the Server group (84430eb7) is mandatory, plus the
# Streaming media group (549df21d) when the checkbox is ticked. $script:HostWorker applies each
# returned group in its own ServerConfigurator run (SC only reliably applies one group per
# invocation - passing several GUIDs in one /certificategroup= arg silently skips the extras).
function Get-RecGroups {
    $g=@()
    $g+=[pscustomobject]@{Name='Server (recorder)';Guid=$script:CertGroupServer}
    if($script:AlsoStreamChk.Checked){ $g+=[pscustomobject]@{Name='Streaming media';Guid=$script:CertGroupStream} }
    $g
}

# Per-host enable/disable worker. Pure (no UI calls) so it runs identically on the
# main thread (MS, serial) or inside a runspace (recorders, parallel). Returns
# @{Target;Ok;Status;Tp;Logs}. Engine functions + $LauncherCSharp are provided by
# the caller's scope (inlined on the main thread; via InitialSessionState in runspaces).
$script:HostWorker = {
    param($P)
    $t0=Get-Date
    $logs=[System.Collections.Generic.List[string]]::new()
    $res=[pscustomobject]@{Target=$P.Target;Fqdn=$P.Fqdn;Ok=$false;Status='';Tp='';Error='';Groups=$P.Names;Action=$P.Action;Started=$t0;Ended=$null;DurationSec=0.0;Logs=$logs}
    try {
        Import-Module PKI -ErrorAction SilentlyContinue   # New-SelfSignedCertificate / Import-PfxCertificate (not always auto-loaded in a runspace)
        # ServerConfigurator only reliably applies ONE certificate group per invocation - passing several GUIDs
        # in one /certificategroup= arg silently skips the extra groups. So apply EACH group in its own SC run.
        $names=@($P.Names -split ', ' | Where-Object { $_ })
        $guids=@($P.Guids -split ' '  | Where-Object { $_ })
        if($P.Action -eq 'enable'){
            $signer = Get-ChildItem Cert:\LocalMachine\My,Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $P.SignerTp -and $_.HasPrivateKey } | Select-Object -First 1
            if(-not $signer){ throw "signer $($P.SignerTp) not found in cert store" }
            $pfxPw=[securestring]::new(); foreach($ch in ([guid]::NewGuid().ToString('N')).ToCharArray()){$pfxPw.AppendChar($ch)}; $pfxPw.MakeReadOnly()
            $certFqdn=Resolve-CertFqdn -Target $P.Target -Fqdn $P.Fqdn -DomainSuffix $P.Domain
            $sans=@(ConvertTo-SanList ([string]$P.ExtraSans))
            if($sans.Count){ $logs.Add("extra SANs: $($sans -join ', ')") }
            $pkg=New-RecorderCertificatePackage -HostName $certFqdn -DomainSuffix $P.Domain -Signer $signer -PfxPassword $pfxPw -OutputDir $P.OutputDir -ExtraDnsNames $sans
            $logs.Add("issued $($pkg.Fqdn) tp=$($pkg.Thumbprint)"); $res.Tp=$pkg.Thumbprint
            $r=Invoke-RemoteRecorderInstall -ComputerName $P.Fqdn -Credential $P.Cred -UseSsl:$false `
                 -PfxPath $pkg.PfxPath -PfxPassword $pfxPw -SignerCerPath $P.CaCer `
                 -InstallSignerToRoot $true -InstallSignerToIntermediate $false `
                 -EnableEncryption $false -ServerConfiguratorPath '' -ScCredential $P.Cred -CertificateGroup ''
            foreach($l in $r.Logs){ $logs.Add($l) }
            $okG=@(); $failG=@()
            for($i=0;$i -lt $guids.Count;$i++){
                $g=$guids[$i]; $gn= if($i -lt $names.Count){ $names[$i] } else { $g }
                $e=Invoke-ScWithWedgeRetry -ComputerName $P.Fqdn -Credential $P.Cred `
                     -Thumbprint $pkg.Thumbprint -CertificateGroup $g -Action enableencryption -WorkLog $logs -GroupName $gn -ScPaths ([string]$P.ScPaths)
                foreach($l in $e.Logs){ $logs.Add("[$gn] $l") }
                if($e.ExitCode -in 0,200000){ $okG+=$gn }
                elseif($e.ExitCode -eq 100){ $failG+="$gn=exit100(not authorized)" }
                elseif($e.ExitCode -eq 300000){ $failG+="$gn=exit300000(cert bound but registration failed - cert CN does not match server address; server may not start)" }
                elseif($e.ExitCode -eq 100000){ $failG+="$gn=exit100000(IDP 403 VmsAdminCredentialsNeeded - mgmt reconfig forbidden; cert may be half-applied)" }
                elseif($e.CertApplied){ $okG+=$gn }   # SC exit -4/267009 etc. with success markers in the SC log - tolerated (rule: 0 and -4 ok when markers present)
                else { $failG+="$gn=exit $($e.ExitCode)" }
            }
            $conf=Confirm-ServerEncryption -ComputerName $P.Fqdn -Credential $P.Cred -UseSsl:$false -Thumbprint $pkg.Thumbprint
            foreach($l in $conf.Logs){ $logs.Add($l) }
            # W5: the certificate/registration verdict is not enough - the Milestone services must also be
            # back up. A cert applied but services not running is a FAILURE (offers rollback), never a green row.
            $certOk = ($failG.Count -eq 0) -and ((-not $P.BindExpected) -or $conf.Bound)
            $res.Ok = $certOk -and $conf.AllServicesRunning
            $res.Status = if($res.Ok){ "Encrypted: $($okG -join '+') (svc up)" }
                          elseif($certOk){ "certificate applied but the Milestone services did not start again on $($P.Target)" }
                          else { "FAILED ok=[$($okG -join '+')] fail=[$($failG -join '+')] bound=$($conf.Bound)" }
        } else {
            $okG=@(); $failG=@()
            for($i=0;$i -lt $guids.Count;$i++){
                $g=$guids[$i]; $gn= if($i -lt $names.Count){ $names[$i] } else { $g }
                $r=Invoke-ScWithWedgeRetry -ComputerName $P.Fqdn -Credential $P.Cred `
                     -Thumbprint '' -CertificateGroup $g -Action disableencryption -WorkLog $logs -GroupName $gn -ScPaths ([string]$P.ScPaths)
                foreach($l in $r.Logs){ $logs.Add($l) }
                if($r.CertApplied -or ($r.ExitCode -in 0,100,200000)){ $okG+=$gn } else { $failG+="$gn=exit $($r.ExitCode)" }
            }
            $conf=Confirm-ServerEncryption -ComputerName $P.Fqdn -Credential $P.Cred -UseSsl:$false -Thumbprint '0'
            foreach($l in $conf.Logs){ $logs.Add($l) }
            $certOk = ($failG.Count -eq 0)
            $res.Ok = $certOk -and $conf.AllServicesRunning
            $res.Status = if($res.Ok){ "Disabled: $($okG -join '+') (svc up)" }
                          elseif($certOk){ "certificate applied but the Milestone services did not start again on $($P.Target)" }
                          else { "FAILED fail=[$($failG -join '+')]" }
        }
    } catch { $res.Status='FAILED'; $logs.Add("ERROR: $($_.Exception.Message)"); $res.Error=$_.Exception.Message }
    $res.Ended=Get-Date; $res.DurationSec=[math]::Round((New-TimeSpan -Start $t0 -End $res.Ended).TotalSeconds,1)
    $res
}

function Add-RunResult { param($R)
    [void]$script:RunResults.Add([pscustomobject]@{
        HostKey=$R.Target; Fqdn=$R.Fqdn; Success=[bool]$R.Ok; Status=$R.Status; Thumbprint=$R.Tp
        Error=$R.Error; CertificateGroup=$R.Groups; Action=$R.Action
        Started=$R.Started; Ended=$R.Ended; DurationSec=$R.DurationSec }) }
function Export-RunResults {
    if(-not $script:RunResults.Count){ return }
    try {
        if(-not (Test-Path -LiteralPath $script:RunsDir)){ [void](New-Item -ItemType Directory -Path $script:RunsDir -Force) }
        $stamp = '{0:yyyyMMdd-HHmmss}' -f (Get-Date)
        $csv = Join-Path $script:RunsDir "run-$stamp-results.csv"
        $txt = Join-Path $script:RunsDir "run-$stamp-results.txt"
        $script:RunResults | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
        $script:RunResults | Format-Table HostKey,Fqdn,Success,Status,Thumbprint,DurationSec,Error -AutoSize | Out-String -Width 300 | Set-Content -LiteralPath $txt -Encoding UTF8
        Write-Log "Run results exported: $csv" 'Good'
    } catch { Write-Log "Run results export FAILED: $($_.Exception.Message)" 'Err' }
    $script:RunResults.Clear() }

function Get-MaxParallel {
    $n=0; [void][int]::TryParse(([string]$script:MaxParBox.Text).Trim(),[ref]$n)
    if($n -lt 1){ $n=32 }; if($n -gt 256){ $n=256 }; $n
}

# Run the per-host worker over many recorder rows IN PARALLEL via a throttled runspace pool.
function Invoke-RecordersParallel { param([object[]]$Rows,[string]$Action,[hashtable]$Common,[int]$Throttle)
    $funcNames='Normalize-RecorderHostName','Get-DomainSuffix','Get-RecorderFqdn','ConvertTo-SanList','Resolve-CertFqdn','Test-SigningCertificate','Import-SignerCertificate','New-RecorderCertificatePackage','Invoke-RemoteRecorderInstall','Invoke-RemoteServerEncryption','Repair-WedgedService','Invoke-ScWithWedgeRetry','Confirm-ServerEncryption','Test-LocalTarget'
    $iss=[System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    foreach($fn in $funcNames){ $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry $fn,((Get-Command $fn).Definition))) }
    $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry 'LauncherCSharp',$script:LauncherCSharp,''))
    $pool=[runspacefactory]::CreateRunspacePool(1,[Math]::Max(1,$Throttle),$iss,$Host); $pool.Open()
    Write-Log "Parallel $Action of $($Rows.Count) recorder(s), max $Throttle at once..."
    $jobs=@()
    foreach($row in $Rows){
        $tgt=[string]$row.Cells['Target'].Value; $fqdn=[string]$row.Cells['Fqdn'].Value
        $P=@{Target=$tgt;Fqdn=$fqdn;Cred=$Common.Cred;SignerTp=$Common.SignerTp;CaCer=$Common.CaCer;Domain=$Common.Domain;OutputDir=$Common.OutputDir;Guids=$Common.Guids;Names=$Common.Names;Action=$Action;BindExpected=$true;ExtraSans=[string]$row.Cells['Sans'].Value}
        $ps=[powershell]::Create(); $ps.RunspacePool=$pool
        [void]$ps.AddScript($script:HostWorker).AddArgument($P)
        Set-RowState $row $(if($Action -eq 'enable'){'Queued (enable)'}else{'Queued (disable)'})
        $jobs += [pscustomobject]@{Row=$row;PS=$ps;Handle=$ps.BeginInvoke();Done=$false}
    }
    $remaining=$jobs.Count
    while($remaining -gt 0){
        foreach($j in @($jobs | Where-Object { -not $_.Done -and $_.Handle.IsCompleted })){
            try { $r=@($j.PS.EndInvoke($j.Handle))[0] } catch { $r=[pscustomobject]@{Target=[string]$j.Row.Cells['Target'].Value;Fqdn=[string]$j.Row.Cells['Fqdn'].Value;Ok=$false;Status="FAILED ($($_.Exception.Message))";Tp='';Error=$_.Exception.Message;Groups='';Action=$Action;Started=Get-Date;Ended=Get-Date;DurationSec=0.0;Logs=@()} }
            $j.PS.Dispose(); $j.Done=$true; $remaining--
            if($r){ Add-RunResult $r; foreach($l in $r.Logs){ Write-Log "[$($r.Target)] $l" }; Set-RowState $j.Row $r.Status $r.Tp; Write-Log "[$($r.Target)] $(if($r.Ok){'OK'}else{'FAILED'}): $($r.Status)" $(if($r.Ok){'Good'}else{'Err'}) }
        }
        Start-Sleep -Milliseconds 250; [Windows.Forms.Application]::DoEvents()
    }
    $pool.Close(); $pool.Dispose()
}

# -- Role-order gate (lab finding 2026-09-23) -------------------------------------------------
# Recorders must follow the management server: enable only while the MS is encrypted, disable only
# while it is unencrypted - otherwise ServerConfigurator exits 1 and changes nothing. Full verified
# order: encrypt = Event Server, then MS, then recorders; decrypt = MS, then recorders, then Event
# Server. MS state is read with a TLS handshake to the MS on port 9000 (TLS-bound only while the MS
# is encrypted). Returns $true (encrypted), $false (plain), $null (no answer).
function Test-MsServerEncrypted {
    param([string]$MsHost,[int]$Port=9000,[int]$TimeoutMs=6000)
    # 1) TLS handshake, synchronous: an async handshake runs the validation scriptblock on a
    #    thread-pool thread with no runspace, which throws and makes every handshake "fail".
    $open = {
        $c = New-Object System.Net.Sockets.TcpClient
        $ar = $c.BeginConnect($MsHost,$Port,$null,$null)
        if(-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs) -or -not $c.Connected){ $c.Close(); return $null }
        $c.EndConnect($ar); $c.ReceiveTimeout = $TimeoutMs; $c.SendTimeout = $TimeoutMs; $c
    }
    $tcp = $null
    try {
        $tcp = & $open; if(-not $tcp){ return $null }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(),$false,([System.Net.Security.RemoteCertificateValidationCallback]{ $true }))
        try { $ssl.AuthenticateAsClient($MsHost); return $true } catch { } finally { $ssl.Dispose() }
    } catch { } finally { if($tcp){ $tcp.Close() } }
    # 2) TLS failed: does the port answer plain HTTP? (locale-independent, no error-text matching)
    $tcp = $null
    try {
        $tcp = & $open; if(-not $tcp){ return $null }
        $ns = $tcp.GetStream(); $req = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`nHost: $MsHost`r`n`r`n")
        $ns.Write($req,0,$req.Length); $buf = New-Object byte[] 16; $n = $ns.Read($buf,0,16)
        if($n -ge 5 -and [Text.Encoding]::ASCII.GetString($buf,0,5) -eq 'HTTP/'){ return $false }
        return $null
    } catch { return $null } finally { if($tcp){ $tcp.Close() } }
}
function Test-RecOrderGate { param([ValidateSet('enable','disable')][string]$Action)
    $addr = [string]$script:MsAddrBox.Text
    if([string]::IsNullOrWhiteSpace($addr) -or $addr -match '^<'){ $addr = [string]$MsAddr }
    if(([string]::IsNullOrWhiteSpace($addr) -or $addr -match '^<') -and (Get-Service -DisplayName 'Milestone XProtect Management Server' -ErrorAction SilentlyContinue)){ $addr = $env:COMPUTERNAME }
    $msHost = if($addr -and $addr -notmatch '^<'){ if($addr -match '://'){ try { ([uri]$addr).Host } catch { $addr } } else { $addr.Trim() } } else { '' }
    $enc = $null
    if($msHost){ for($i=0; $i -lt 5; $i++){ $enc = Test-MsServerEncrypted -MsHost $msHost; if($null -ne $enc){ break }; Start-Sleep -Seconds 10 } }   # MS may be mid-restart right after its own enable/disable
    $want = ($Action -eq 'enable')
    if($null -ne $enc -and $enc -eq $want){ Write-Log "ORDER CHECK: management server $msHost is $(if($enc){'encrypted'}else{'unencrypted'}) - OK to $Action recorders" 'Good'; return $true }
    $why = if($null -eq $enc){ "could not determine the management server's encryption state (VMS address '$addr', TLS probe to port 9000 got no answer)." }
           elseif($want){ "the management server ($msHost) is NOT encrypted. Recorders can only be encrypted after the MS (ServerConfigurator exits 1 and changes nothing). Order: encrypt = Event Server, then MS, then recorders. Encrypt the management server first." }
           else { "the management server ($msHost) is still ENCRYPTED. Recorders can only be decrypted after the MS (ServerConfigurator exits 1 and changes nothing). Order: decrypt = MS, then recorders, then Event Server. Decrypt the management server first." }
    if($SkipOrderCheck){ Write-Log "ORDER CHECK overridden (-SkipOrderCheck): $why" 'Err'; return $true }
    if($script:Headless){ Write-Log "ORDER CHECK BLOCKED: $why Use -SkipOrderCheck to override." 'Err'; return $false }
    $ans = [Windows.Forms.MessageBox]::Show("Role order check: $why`r`n`r`nProceed anyway?",'Role order',[Windows.Forms.MessageBoxButtons]::YesNo,[Windows.Forms.MessageBoxIcon]::Warning,[Windows.Forms.MessageBoxDefaultButton]::Button2)
    if($ans -eq 'Yes'){ Write-Log "ORDER CHECK overridden by operator: $why" 'Err'; return $true }
    Write-Log "ORDER CHECK BLOCKED: $why" 'Err'; return $false
}

function Do-Enable {
    $rows=Get-SelectedRows; if(-not $rows){ Write-Log 'Select at least one target.' 'Err'; return }
    if(-not (Test-RecOrderGate -Action 'enable')){ return }
    Set-Busy $true
    try {
        $domain=Get-DomainSuffix $script:DomainBox.Text
        $signer=Resolve-Signer; Write-Log "Signer: $($signer.Subject) [$($signer.Thumbprint)]"
        $caCer=Join-Path $script:OutputDir 'MilestoneCA.cer'; Export-Certificate -Cert $signer -FilePath $caCer -Type CERT -Force | Out-Null
        Ensure-TrustedHosts -Hosts (@($rows | ForEach-Object { [string]$_.Cells['Fqdn'].Value }))
        $recGroups=@(Get-RecGroups)
        $common=@{ Cred=(Get-Cred $script:RecUserBox.Text $script:RecPwBox.Text); SignerTp=$signer.Thumbprint; CaCer=$caCer; Domain=$domain; OutputDir=$script:OutputDir
                  Guids=(($recGroups|ForEach-Object{$_.Guid}) -join ' '); Names=(($recGroups|ForEach-Object{$_.Name}) -join ', ') }
        Invoke-RecordersParallel -Rows $rows -Action 'enable' -Common $common -Throttle (Get-MaxParallel)
        Write-Log 'Enable run complete.' 'Good'
    } catch { Write-Log "Enable failed: $(Format-Err $_)" 'Err' } finally { Export-RunResults; Set-Busy $false }
}

function Do-Disable {
    $rows=Get-SelectedRows; if(-not $rows){ Write-Log 'Select at least one target.' 'Err'; return }
    if(-not $script:Headless){ if([Windows.Forms.MessageBox]::Show('Disable encryption on the selected target(s)?','Confirm',4,'Warning') -ne 'Yes'){ return } }
    if(-not (Test-RecOrderGate -Action 'disable')){ return }
    Set-Busy $true
    try {
        $domain=Get-DomainSuffix $script:DomainBox.Text
        Ensure-TrustedHosts -Hosts (@($rows | ForEach-Object { [string]$_.Cells['Fqdn'].Value }))
        $recGroups=@(Get-RecGroups); [array]::Reverse($recGroups)
        $common=@{ Cred=(Get-Cred $script:RecUserBox.Text $script:RecPwBox.Text); SignerTp=''; CaCer=''; Domain=$domain; OutputDir=$script:OutputDir
                  Guids=(($recGroups|ForEach-Object{$_.Guid}) -join ' '); Names=(($recGroups|ForEach-Object{$_.Name}) -join ', ') }
        Invoke-RecordersParallel -Rows $rows -Action 'disable' -Common $common -Throttle (Get-MaxParallel)
        Write-Log 'Disable run complete.' 'Good'
    } catch { Write-Log "Disable failed: $(Format-Err $_)" 'Err' } finally { Export-RunResults; Set-Busy $false }
}

function Set-Busy { param([bool]$Busy)
    foreach($c in $script:BusyCtrls){ $c.Enabled = -not $Busy }
    $script:Form.UseWaitCursor=$Busy; [Windows.Forms.Application]::DoEvents() }

# Headless -CreateRoot cannot prompt: refuse placeholders and duplicate CA names loudly.
function New-RootCaHeadless { param([string]$Subject)
    if ($Subject -match '<[^>]+>') { throw "RootSubject '$Subject' is a placeholder. Pass -RootSubject 'CN=Your CA' or set SignerSubject in mrc.defaults.psd1." }
    $dup = @(Find-ExistingCa $Subject)   # @(): function return unwraps; null otherwise (StrictMode Count crash)
    if ($dup.Count) { throw "A CA with CN '$(Get-CaSubjectCn $Subject)' and a private key already exists (thumb $($dup[0].Thumbprint)). A second root with the same name changes the trust anchor and can BREAK an already-encrypted server. Omit -CreateRoot to sign with the existing CA, or use a different -RootSubject." }
    New-RootCa -Subject $Subject -OutputDir $script:OutputDir }

# -- build UI --------------------------------------------------------------
$script:Form=[Windows.Forms.Form]::new()
$script:Form.Text='Milestone Encryption - Recording Servers (remote)'
$script:Form.StartPosition='CenterScreen'; $script:Form.ClientSize=[Drawing.Size]::new(940,920); $script:Form.MinimumSize=[Drawing.Size]::new(916,700)
$script:Tip=[Windows.Forms.ToolTip]::new(); $script:Tip.AutoPopDelay=20000; $script:Tip.InitialDelay=300; $script:Tip.ReshowDelay=100

$y=14
$script:Form.Controls.Add((New-Label 'Management Server' 12 $y 130))
$script:MsAddrBox=New-Tb 150 $y 250 ([string]$script:Defaults.MsAddr); $script:Form.Controls.Add($script:MsAddrBox)
$script:Tip.SetToolTip($script:MsAddrBox,'Address used only to connect for recorder discovery (Connect-Vms). Not itself a target of this tool.')
$script:Form.Controls.Add((New-Label 'Domain suffix' 415 $y 90))
$script:DomainBox=New-Tb 505 $y 140 ([string]$script:Defaults.Domain); $script:Form.Controls.Add($script:DomainBox)

$y+=30
$script:Form.Controls.Add((New-Label 'VMS user' 12 $y 130))
$script:MsUserBox=New-Tb 150 $y 250 ([string]$script:Defaults.MsUser); $script:Form.Controls.Add($script:MsUserBox)
$script:Tip.SetToolTip($script:MsUserBox,'Credential used only to connect to the VMS for recorder discovery (Connect-Vms). Never applied to a recorder - see Recorder admin user below for that.')
$script:Form.Controls.Add((New-Label 'VMS password' 415 $y 90))
$script:MsPwBox=New-Tb 505 $y 140 '' $true; $script:Form.Controls.Add($script:MsPwBox)
$script:Tip.SetToolTip($script:MsPwBox,'Password for the VMS discovery credential above.')

$y+=30
$script:Form.Controls.Add((New-Label 'Recorder admin user' 12 $y 130))
$script:RecUserBox=New-Tb 150 $y 250 ([string]$script:Defaults.RecUser); $script:Form.Controls.Add($script:RecUserBox)
$script:Form.Controls.Add((New-Label 'Rec admin pw' 415 $y 90))
$script:RecPwBox=New-Tb 505 $y 140 '' $true; $script:Form.Controls.Add($script:RecPwBox)

$y+=30
$script:SignerStoreRadio=[Windows.Forms.RadioButton]::new(); $script:SignerStoreRadio.Text='Sign with MilestoneCA from cert store'; $script:SignerStoreRadio.Location=[Drawing.Point]::new(12,$y); $script:SignerStoreRadio.Size=[Drawing.Size]::new(280,22); $script:SignerStoreRadio.Checked=$true; $script:Form.Controls.Add($script:SignerStoreRadio)
$script:SignerPfxRadio=[Windows.Forms.RadioButton]::new(); $script:SignerPfxRadio.Text='Signer PFX:'; $script:SignerPfxRadio.Location=[Drawing.Point]::new(300,$y); $script:SignerPfxRadio.Size=[Drawing.Size]::new(95,22); $script:Form.Controls.Add($script:SignerPfxRadio)
$script:SignerPfxBox=New-Tb 395 $y 200; $script:Form.Controls.Add($script:SignerPfxBox)
$script:Form.Controls.Add((New-Label 'pw' 600 $y 24))
$script:SignerPwBox=New-Tb 626 $y 120 '' $true; $script:Form.Controls.Add($script:SignerPwBox)
$browse=New-Btn '...' 750 ($y-2) 40; $script:Form.Controls.Add($browse)
$browse.Add_Click({ $d=[Windows.Forms.OpenFileDialog]::new(); $d.Filter='PFX|*.pfx'; if($d.ShowDialog() -eq 'OK'){ $script:SignerPfxBox.Text=$d.FileName; $script:SignerPfxRadio.Checked=$true } })

$y+=28
$script:Form.Controls.Add((New-Label 'Root CA subject' 12 $y 100))
$script:SignerSubjectBox=New-Tb 115 $y 235 ([string]$script:Defaults.SignerSubject); $script:Form.Controls.Add($script:SignerSubjectBox)
$createRootBtn=New-Btn 'Create root CA' 360 ($y-3) 130; $script:Form.Controls.Add($createRootBtn)
$createRootBtn.Add_Click({
    try {
        $subj=$script:SignerSubjectBox.Text.Trim(); if(-not $subj){ throw 'Enter a Root CA subject, e.g. CN=MilestoneCA, O=YourOrg' }
        $cn=Get-CaSubjectCn $subj
        $dup=@(Find-ExistingCa $subj)   # @(): function return unwraps; null otherwise (StrictMode Count crash)
        if($dup.Count){
            $msg="A CA named 'CN=$cn' with a private key already EXISTS (thumb $($dup[0].Thumbprint.Substring(0,8))...).`n`nCreating ANOTHER root with the same name and applying it will CHANGE the trust anchor recorders validate the management server against, and can BREAK a recorder that is already configured/encrypted (IDP returns 403 -> services stop).`n`nIf you just want to sign with the existing CA, click No and leave store-mode as-is.`nUse a DIFFERENT subject (e.g. CN=MilestoneRootCA) for a genuinely new root.`n`nCreate a duplicate anyway?"
            if([Windows.Forms.MessageBox]::Show($msg,'Duplicate CA name',4,'Warning') -ne 'Yes'){ Write-Log "Create root CA cancelled (CN=$cn already exists; using existing)." 'Err'; return }
        }
        $ca=New-RootCa -Subject $subj -OutputDir $script:OutputDir
        $script:SignerStoreRadio.Checked=$true
        Write-Log "Created self-signed root CA $($ca.Subject) [$($ca.Thumbprint)] in CurrentUser\My; public cert exported to $script:OutputDir" 'Good'
        [Windows.Forms.MessageBox]::Show("Root CA created and selected for store-mode signing:`n`n$($ca.Subject)`nThumbprint: $($ca.Thumbprint)",'Root CA',0,'Information')|Out-Null
    } catch { Write-Log "Create root CA failed: $(Format-Err $_)" 'Err'; [Windows.Forms.MessageBox]::Show("Create root CA failed:`n$($_.Exception.Message)",'Error',0,'Error')|Out-Null }
})
$storeHint=New-Label '(store-mode signs with the CA matching this CN)' 500 $y 430; $script:Form.Controls.Add($storeHint)
$script:Tip.SetToolTip($storeHint,'Store-mode signs with the CA in the cert store whose CN matches this box. Create root CA makes a fresh self-signed root with this subject. Must be the SAME CA that signed the management server certificate.')

# Per-recorder certificate group selector: the Server group (84430eb7) is mandatory (it IS the
# recorder cert group); Streaming media (549df21d) is optional, for recorders with an image
# server component.
function New-Chk { param([string]$Text,[int]$X,[int]$Y,[int]$W,[bool]$On)
    $c=[Windows.Forms.CheckBox]::new(); $c.Text=$Text; $c.Location=[Drawing.Point]::new($X,$Y); $c.Size=[Drawing.Size]::new($W,22); $c.Checked=$On; $c }
$y+=30
$script:Form.Controls.Add((New-Label 'Certificate group:' 12 $y 120))
$script:AlsoStreamChk=New-Chk 'Also Streaming media group' 138 $y 220 $false; $script:Form.Controls.Add($script:AlsoStreamChk)
$script:Tip.SetToolTip($script:AlsoStreamChk,"Certificate group 549df21d - Streaming media / image server.`r`nEvery recorder always gets the Server group (84430eb7). Tick this ONLY if the recorder also runs a Streaming media (image server) component.")
$script:Form.Controls.Add((New-Label 'Max ||' 770 $y 48))
$script:MaxParBox   =New-Tb 818 $y 60 '32'; $script:Form.Controls.Add($script:MaxParBox)

$y+=30
$script:DiscoverChk=[Windows.Forms.CheckBox]::new(); $script:DiscoverChk.Text='Discover recorders (MilestonePSTools)'; $script:DiscoverChk.Location=[Drawing.Point]::new(12,$y); $script:DiscoverChk.Size=[Drawing.Size]::new(270,22); $script:Form.Controls.Add($script:DiscoverChk)
$script:VmsBasicChk=[Windows.Forms.CheckBox]::new(); $script:VmsBasicChk.Text='VMS Basic-user auth (NOT Windows accts)'; $script:VmsBasicChk.Location=[Drawing.Point]::new(290,$y); $script:VmsBasicChk.Size=[Drawing.Size]::new(310,22); $script:VmsBasicChk.Checked=$false; $script:Form.Controls.Add($script:VmsBasicChk)
$loadBtn=New-Btn 'Load Targets' 760 ($y-3) 150; $script:Form.Controls.Add($loadBtn); $loadBtn.Add_Click({ Do-Load })

$y+=28
$script:Form.Controls.Add((New-Label 'Add recorder (host/IP)' 12 $y 140))
$script:AddRecBox=New-Tb 155 $y 200; $script:Form.Controls.Add($script:AddRecBox)
$addRecBtn=New-Btn 'Add' 362 ($y-3) 70; $script:Form.Controls.Add($addRecBtn); $addRecBtn.Add_Click({ Do-AddRecorder })
$loadListBtn=New-Btn 'Load list...' 440 ($y-3) 110; $script:Form.Controls.Add($loadListBtn); $loadListBtn.Add_Click({ Do-LoadList })
$importHint=New-Label 'or import .txt/.csv, one host per line (appends)' 560 $y 370; $script:Form.Controls.Add($importHint)
$script:Tip.SetToolTip($importHint,'Import a .txt or .csv of hosts/IPs, one per line. Discovery and list import both APPEND to the grid.')

$y+=32
$script:Grid=[Windows.Forms.DataGridView]::new()
$script:Grid.Location=[Drawing.Point]::new(12,$y); $script:Grid.Size=[Drawing.Size]::new(916,250); $script:Grid.Anchor='Top,Left,Right'
$script:Grid.AllowUserToAddRows=$false; $script:Grid.RowHeadersVisible=$false; $script:Grid.SelectionMode='FullRowSelect'
$colSel=[Windows.Forms.DataGridViewCheckBoxColumn]::new(); $colSel.Name='Sel'; $colSel.HeaderText='Sel'; $colSel.Width=40
$script:Grid.Columns.Add($colSel)|Out-Null
foreach($c in @(@('Name','Name (VMS)',100),@('Target','Target (host)',120),@('Role','Role',60),@('Fqdn','FQDN / IP (editable)',180),@('Sans','Extra SANs (editable)',130),@('Status','Status',150),@('Tp','Thumbprint',100))){
    $col=[Windows.Forms.DataGridViewTextBoxColumn]::new(); $col.Name=$c[0]; $col.HeaderText=$c[1]; $col.Width=$c[2]
    if($c[0] -ne 'Fqdn' -and $c[0] -ne 'Sans'){ $col.ReadOnly=$true }
    $script:Grid.Columns.Add($col)|Out-Null }
$script:Form.Controls.Add($script:Grid)

$y+=258
$enableBtn=New-Btn 'Enable Selected' 12 $y 150; $script:Form.Controls.Add($enableBtn); $enableBtn.Add_Click({ Do-Enable })
$disableBtn=New-Btn 'Disable Selected' 170 $y 150; $script:Form.Controls.Add($disableBtn); $disableBtn.Add_Click({ Do-Disable })
$selAll=New-Btn 'Select All' 700 $y 100; $selAll.Anchor='Top,Right'; $script:Form.Controls.Add($selAll); $selAll.Add_Click({ foreach($r in $script:Grid.Rows){ if(-not $r.IsNewRow){$r.Cells['Sel'].Value=$true} }; $script:Grid.Refresh() })
$selNone=New-Btn 'Select None' 808 $y 100; $selNone.Anchor='Top,Right'; $script:Form.Controls.Add($selNone); $selNone.Add_Click({ foreach($r in $script:Grid.Rows){ if(-not $r.IsNewRow){$r.Cells['Sel'].Value=$false} }; $script:Grid.Refresh() })

$y+=36
$script:Log=[Windows.Forms.RichTextBox]::new(); $script:Log.Location=[Drawing.Point]::new(12,$y); $script:Log.Size=[Drawing.Size]::new(916,360); $script:Log.ReadOnly=$true; $script:Log.Anchor='Top,Bottom,Left,Right'
$script:Form.Controls.Add($script:Log)

$script:BusyCtrls=@($loadBtn,$enableBtn,$disableBtn,$selAll,$selNone,$addRecBtn,$loadListBtn,$script:MsAddrBox,$script:DomainBox,$createRootBtn)

# DPI autoscale, set AFTER all controls exist (designer order): first layout compares the actual
# DPI to this 96-dpi baseline and scales every control uniformly, so fixed-width labels stop
# wrapping/clipping on 125%/150% displays. The layout itself stays authored in 96-dpi pixels.
$script:Form.AutoScaleDimensions=[Drawing.SizeF]::new(96,96); $script:Form.AutoScaleMode='Dpi'

# Screen clamp + MinimumSize at Shown time - only then are DPI scaling and anchor distances final.
# MinimumSize width = full laid-out width: the layout is fixed-width, so shrinking narrower only
# clips the grid and the right-hand buttons (verified: 916 min width cut Select None + Thumbprint).
$script:Form.Add_Shown({
    $wa=[Windows.Forms.Screen]::FromControl($script:Form).WorkingArea
    if($script:Form.Height -gt $wa.Height){ $script:Form.Height=$wa.Height }
    $minH=$script:Form.Height - $script:Log.Height + 120   # keep >= 120px of log visible
    $script:Form.MinimumSize=[Drawing.Size]::new($script:Form.Width,$minH)
    # DataGridView columns are NOT covered by WinForms autoscaling - scale them by the same factor.
    $f=$script:Form.CurrentAutoScaleDimensions.Width/96
    if($f -gt 1.01){ foreach($c in $script:Grid.Columns){ $c.Width=[int]($c.Width*$f) } }
})

Write-Log "Output dir: $script:OutputDir" 'Good'
if($script:DefaultsLoadError){ Write-Log "WARNING: mrc.defaults.psd1 failed to parse: $script:DefaultsLoadError - using built-in placeholders" 'Err' }
elseif($script:DefaultsLoaded.Count){ Write-Log "Loaded defaults from mrc.defaults.psd1: $($script:DefaultsLoaded -join ', ')" }
Write-Log 'Recorders run in parallel (throttled). Each recorder self-confirms (certificate binding + Milestone services) after apply.'

if($RecTargets){
    try {
        if($RecPwFile -and (Test-Path -LiteralPath $RecPwFile)){ $script:RecPwBox.Text=(Get-Content -Raw -LiteralPath $RecPwFile).Trim() }
        $script:RecUserBox.Text=$RecUser; $script:DomainBox.Text=$SelfTestDomain; $script:SignerStoreRadio.Checked=$true
        $script:SignerSubjectBox.Text=$RootSubject; $script:RootSubjectForRun=$RootSubject
        if($CreateRoot){ Write-Log "Creating self-signed root CA: $RootSubject"; $rca=New-RootCaHeadless -Subject $RootSubject; Write-Log "Root CA created [$($rca.Thumbprint)]" 'Good' }
        $script:MaxParBox.Text="$MaxParallel"
        $script:AlsoStreamChk.Checked=$false
        $script:Grid.Rows.Clear()
        foreach($h in ($RecTargets -split '[;,] *' | Where-Object { $_ })){
            $parts=$h.Trim() -split '='
            if($parts.Count -ge 2){ Add-Row -Target (Normalize-RecorderHostName $parts[0]) -Role 'Recorder' -Fqdn $parts[1].Trim() -Sans $ExtraSans }
            else { $hh=$h.Trim(); $isIp = $hh -match '^\d{1,3}(\.\d{1,3}){3}$'; Add-Row -Target $(if($isIp){$hh}else{Normalize-RecorderHostName $hh}) -Role 'Recorder' -Fqdn $hh -Sans $ExtraSans }
        }
        foreach($r in $script:Grid.Rows){ if(-not $r.IsNewRow){ $r.Cells['Sel'].Value=$true } }
        Write-Log "RECORDER TEST ($RecAction): $($script:Grid.Rows.Count) recorder(s), max $MaxParallel parallel" 'Good'
        $acts = if($RecAction -eq 'cycle'){ 'disable','enable' } else { ,$RecAction }
        foreach($a in $acts){ Write-Log "########## RECORDERS: $($a.ToUpper()) ##########"; if($a -eq 'enable'){ Do-Enable } else { Do-Disable } }
        Write-Log '----- FINAL RECORDER ROWS -----'
        $bad=0
        foreach($r in $script:Grid.Rows){ if($r.IsNewRow){continue}
            $st=[string]$r.Cells['Status'].Value
            $want = if($RecAction -eq 'disable'){ $st -like 'Disabled*' } else { $st -like 'Encrypted*' }
            if(-not $want){ $bad++ }
            Write-Log (" {0,-20} {1}" -f $r.Cells['Target'].Value,$st) $(if($want){'Good'}else{'Err'})
        }
        Write-Log "OVERALL: $(if($bad -eq 0){'ALL RECORDERS OK'}else{"$bad recorder(s) NOT in expected state"})" $(if($bad -eq 0){'Good'}else{'Err'})
        exit ([int]($bad -ne 0))
    } catch { Write-Log "RECORDER-TEST FATAL: $(Format-Err $_)" 'Err'; exit 2 }
} elseif($TestDiscover){
    try {
        if($MsPwFile -and (Test-Path -LiteralPath $MsPwFile)){ $script:MsPwBox.Text=(Get-Content -Raw -LiteralPath $MsPwFile).Trim() }
        $script:MsUserBox.Text=$MsUser; $script:DomainBox.Text=$SelfTestDomain; $script:MsAddrBox.Text=$MsAddr
        $script:DiscoverChk.Checked=$true; $script:VmsBasicChk.Checked=$false
        Do-Load
        Write-Log '----- GRID ROWS -----'
        foreach($r in $script:Grid.Rows){ if(-not $r.IsNewRow){ Write-Log (" {0,-20} {1,-9} {2}" -f $r.Cells['Target'].Value,$r.Cells['Role'].Value,$r.Cells['Fqdn'].Value) } }
        exit 0
    } catch { Write-Log "TEST-DISCOVER FATAL: $(Format-Err $_)" 'Err'; exit 2 }
} else {
    [void]$script:Form.ShowDialog()
}
