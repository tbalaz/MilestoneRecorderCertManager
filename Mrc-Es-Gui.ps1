#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone XProtect Event Server local encryption console (GUI).

.DESCRIPTION
    Point-and-click front end to enable / disable Milestone XProtect server encryption for the
    Event Server component on THIS machine only. Run it ON a standalone Event Server box (a
    machine that hosts the Event Server role but is not itself the Management Server).

    Fixed target, fixed certificate group: this GUI never connects anywhere - it always operates
    on the local machine (in-process, no WinRM), and always applies ONE certificate group, Event
    Server (7e02e0f5-549d-4113-b8de-bda2c1f38dbf). There is no target grid and no group picker.

    Enable issues a fresh CA-signed certificate for this host (CN = its own DNS name), imports it
    (+ trusts the CA, grants NETWORK SERVICE on the key) and runs ServerConfigurator
    /enableencryption /certificategroup=7e02e0f5-... . Disable runs ServerConfigurator
    /disableencryption for the same group. Minted certificates carry CN = the resolved local FQDN,
    with SANs = FQDN + short name + any Extra SANs.

    IMPORTANT: the Management Server must be reachable from this machine for the Event Server's
    IDP re-registration to succeed, and trust must run BOTH ways - the CA that signed the
    Management Server's certificate should be trusted here (installed to LocalMachine\Root), and
    the CA used here (via 'Sign with MilestoneCA from cert store' or a signer PFX) should be
    trusted on the Management Server, or IDP registration fails even though the local cert applies.

    All site-specific defaults ship CLEARED to placeholders. Fill them in the GUI for your
    environment. For convenient repeat use in one environment, drop a 'mrc.defaults.psd1' next to
    this script (same format/keys used by the other Mrc-*.ps1 tools; unused keys are ignored); it
    is gitignored and must never be shipped to a client.
.NOTES
    Interactive (operator on the Event Server console, run elevated):
        powershell -ExecutionPolicy Bypass -STA -File .\Mrc-Es-Gui.ps1

    Headless (same Do-Disable/Do-Enable code paths the buttons call - no clicks); supply your own
    values, password read from a file (never on the command line):
        powershell -ExecutionPolicy Bypass -File .\Mrc-Es-Gui.ps1 -EsAction enable `
            -EsUser '.\Administrator' -EsPwFile <path-to-pw-file> `
            -SelfTestDomain <domain-suffix> -LogFile <path-to-log> -ExtraSans '<alias-fqdn>'
    Runs one enable (or disable) against this machine's Event Server group, exits 0 only on success.
    -ExtraSans adds extra SAN DNS names (e.g. alias addresses) to the minted certificate.
#>
[CmdletBinding()]
param(
    [ValidateSet('','enable','disable')][string]$EsAction = '',   # headless: one-shot enable or disable (no GUI window)
    [string]$EsPwFile,                                  # file holding the ES admin password (headless only)
    [string]$EsUser = '',                                # account ServerConfigurator runs as (Milestone Administrators role); resolves via mrc.defaults.psd1 EsUser, default .\Administrator
    [string]$SelfTestDomain = '<domain-suffix>',        # headless: overrides the Domain suffix box
    [string]$ExtraSans = '',                            # extra SAN DNS names for the minted cert (comma/space/semicolon/newline separated)
    [string]$LogFile,                                   # optional: tee the log here
    [switch]$CreateRoot,                                # headless: generate a fresh self-signed root CA before the run
    [string]$RootSubject = '<signer-subject>',          # subject for -CreateRoot AND for store-mode signer lookup (matched by CN)
    [switch]$SkipOrderCheck                             # headless: bypass the role-order gate (MS must be unencrypted while the Event Server changes)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Deployment defaults (client-ready) ------------------------------------------------------
# This tool ships with NEUTRAL placeholders so nothing site-specific is baked into the file.
# Fill the real values in the GUI for your environment. For convenient repeat use in ONE known
# environment, drop a 'mrc.defaults.psd1' next to this script containing any subset of the keys
# below (the same file used by the other Mrc-*.ps1 tools in this suite - unrelated keys in it are
# ignored here), e.g.:
#     @{ Domain='contoso.local'; EsUser='CONTOSO\svc-mrc'; SignerSubject='CN=Contoso VMS CA' }
# That file is gitignored and must NEVER be shipped to a client - it is operator convenience only.
$script:Defaults = @{
    Domain        = '<domain-suffix>'                # GUI 'Domain suffix' box fallback (machine DNS suffix is tried first)
    EsUser        = '.\Administrator'                 # GUI 'ES admin user' box
    SignerSubject = 'CN=<Your Organization> CA'       # GUI 'Root CA subject' (store-mode signer match / Create root CA)
    ExtraSans     = ''                                # extra cert SAN names (aliases)
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
$EsUser         = Resolve-Default $EsUser         'EsUser'
$SelfTestDomain = Resolve-Default $SelfTestDomain 'Domain'
$RootSubject    = Resolve-Default $RootSubject    'SignerSubject'
$ExtraSans      = Resolve-Default $ExtraSans      'ExtraSans'

# ===================== INLINED ENGINE (curated subset of MrcEngine, from Mrc-Gui.ps1) =====================
<#
.SYNOPSIS
    Shared engine for Milestone recorder/management-server certificate + encryption automation,
    trimmed to exactly what the Event Server local-only GUI reaches.
.DESCRIPTION
    Everything below (through END INLINED ENGINE) is carried over VERBATIM from the lab-verified
    Mrc-Gui.ps1 (2026-05-29), with exactly two functional deviations, each commented in place:
      1. Repair-WedgedService: the :8080 settle probe is a Management-Server-specific readiness
         signal; it now only runs when the wedged service is the Management Server.
      2. Confirm-ServerEncryption is replaced by Confirm-EventServerEncryption: the Event Server
         certificate group does not create a netsh sslcert binding, so the base's binding check is
         not a valid success signal here; a service-running check is used instead.
    Invoke-ScWithWedgeRetry's wedge-restart condition is also extended to cover the Event Server
    (see the DEVIATION comment at its $want assignment) - this is required wiring for deviation 1,
    not a separate behavior change.
    Do NOT "improve" or DRY-refactor anything below beyond those marked spots; the exact form is
    what was proven end-to-end.
.NOTES
    ServerConfigurator /enableencryption exit codes:
       0    success
       100  local cert applied BUT MS registration failed ("not authorized") => run-as account
            is not in the Milestone Administrators role on the management server
       -4   silent failure: cert chains to an untrusted root (install signer CA into
            LocalMachine\Root) OR a stuck ServerConfigurator instance holds the singleton lock
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Milestone Event Server certificate-group GUID (constant across XProtect installs).
# Copied verbatim from Mrc-Gui.ps1's $script:CertGroupEvent.
$script:CertGroupEvent = '7e02e0f5-549d-4113-b8de-bda2c1f38dbf'   # Event Server
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
# Then WinRM is skipped entirely and scriptblocks run in-process: this GUI always runs ON the
# Event Server, where loopback WinRM is often not enabled and remoting to self fails.
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
# (before an enable retry) it is restarted and given the settle window before the SC retry.
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
                # DEVIATION 1 (see file header): the :8080 TCP probe is a Management-Server readiness
                # signal (IIS/IDP). Only require it when bouncing the Management Server itself; other
                # services (e.g. Event Server) settle on process uptime alone - same threshold, same deadline.
                $needPort = ($Dn -like '*Management Server*')
                while((Get-Date) -lt $deadline){
                    Start-Sleep -Seconds 10
                    $age=0
                    $svcPid=(Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'").ProcessId
                    if($svcPid){ try { $age=((Get-Date)-(Get-Process -Id $svcPid -ErrorAction Stop).StartTime).TotalSeconds } catch {} }
                    $port=$true
                    if($needPort){ $port=$false; try { $tc=[System.Net.Sockets.TcpClient]::new(); $tc.Connect('127.0.0.1',8080); $port=$tc.Connected; $tc.Close() } catch {} }
                    if($age -ge 240 -and $port){ $out.Add("settled (uptime $([int]$age)s$(if($needPort){', :8080 up'}))"); $settled=$true; break }
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
        # DEVIATION (required wiring for Repair-WedgedService's DEVIATION 1 above): the base only
        # restarted a wedged Management Server before the retry; a wedged Event Server must also be
        # restarted here, or Repair-WedgedService leaves it stopped and the SC retry has nothing to apply to.
        $want=($Action -eq 'enableencryption') -and (($dn -like '*Management Server*') -or ($dn -like '*Event Server*'))
        foreach($l in @(Repair-WedgedService -ComputerName $ComputerName -Credential $Credential -UseSsl:$false -DisplayName $dn -WantRunning $want)){ $WorkLog.Add("[$GroupName] $l") }
        $script:WedgeDepth++
        try { Invoke-ScWithWedgeRetry @PSBoundParameters } finally { $script:WedgeDepth-- }
    }
}

# -- Post-apply confirmation (reconnect-tolerant), Event Server variant -----
# DEVIATION 2 (see file header): this REPLACES the base Confirm-ServerEncryption for this GUI. The
# Event Server certificate group does not create a netsh http sslcert binding - ServerConfigurator
# instead flips the Event Server's SecureCommunicationEnabled flag and re-registers it to https. So
# the base's netsh-binding check is not a valid success signal here. Success is judged by (a) the SC
# CertApplied/exit-code verdict the caller already captured from Invoke-RemoteServerEncryption, plus
# (b) confirming the Event Server service (and W3SVC/WAS if present) is Running - same
# start-if-stopped + retry structure as the base Confirm. Bound is reported as the literal string
# 'n/a' (never a boolean) so it can never be mistaken for a real binding check downstream. If the
# Event Server service itself cannot be found, this is an explicit FAILURE, not a vacuous pass.
function Confirm-EventServerEncryption {
    param([string]$ComputerName, [pscredential]$Credential, [bool]$UseSsl, [int]$TimeoutSeconds = 180)
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
        if ($null -eq $session) { return [pscustomobject]@{ Bound = 'n/a'; AllServicesRunning = $false; Logs = @("Confirm: could not reconnect to $ComputerName within ${TimeoutSeconds}s") } }
        $icm = @{ Session = $session }
    }
    try {
        $res = Invoke-Command @icm -ScriptBlock {
            $rlog = [System.Collections.Generic.List[string]]::new()
            # Verified service Name (the base's own IIS/Milestone selector regex already matches this
            # short name) checked first; DisplayName as a fallback for older/localized builds.
            $esSvc = Get-Service | Where-Object { $_.Name -eq 'MilestoneEventServer' -or $_.DisplayName -eq 'Milestone XProtect Event Server' } | Select-Object -First 1
            if (-not $esSvc) {
                $rlog.Add("[$env:COMPUTERNAME] Event Server service NOT FOUND (Name=MilestoneEventServer / DisplayName='Milestone XProtect Event Server') - cannot confirm, treating as FAILURE")
                return [pscustomobject]@{ Bound = 'n/a'; AllServicesRunning = $false; Stopped = @('Milestone XProtect Event Server (service not found)'); Logs = $rlog.ToArray() }
            }
            # IIS (W3SVC/WAS) hosts the IDP web the Event Server re-registers against - start it first.
            foreach ($iis in 'WAS','W3SVC') {
                $sv = Get-Service $iis -ErrorAction SilentlyContinue
                if ($sv -and $sv.Status -ne 'Running') {
                    try { Start-Service $iis -ErrorAction Stop; $rlog.Add("[$env:COMPUTERNAME] started service: $iis") } catch { $rlog.Add("[$env:COMPUTERNAME] FAILED to start ${iis}: $($_.Exception.Message)") }
                }
            }
            $esSel = { $_.Name -eq 'MilestoneEventServer' -or $_.DisplayName -eq 'Milestone XProtect Event Server' -or $_.Name -match '^W3SVC$|^WAS$' }
            # A Disabled service is a valid, intentional state (e.g. on an MS cluster node, by design) -
            # never a start attempt, never counted as "stopped".
            $svcAll = @(Get-Service | Where-Object $esSel)
            $disabled = @($svcAll | Where-Object { [string]$_.StartType -eq 'Disabled' } | ForEach-Object { $_.Name })
            if ($disabled.Count) { $rlog.Add("[$env:COMPUTERNAME] skipped (Disabled): $($disabled -join ',')") }
            $svc = @($svcAll | Where-Object { [string]$_.StartType -ne 'Disabled' })
            foreach ($s in ($svc | Where-Object { $_.Status -ne 'Running' })) {
                try { Start-Service $s.Name -ErrorAction Stop; $rlog.Add("[$env:COMPUTERNAME] started service: $($s.Name)") }
                catch { $rlog.Add("[$env:COMPUTERNAME] FAILED to start $($s.Name): $($_.Exception.Message)") }
            }
            Start-Sleep -Seconds 3
            $svc = @(Get-Service | Where-Object $esSel | Where-Object { [string]$_.StartType -ne 'Disabled' })
            $stopped = @($svc | Where-Object { $_.Status -ne 'Running' } | Select-Object -ExpandProperty Name)
            $rlog.Add("[$env:COMPUTERNAME] services running: $(@($svc | Where-Object Status -eq Running).Count)/$($svc.Count)$(if ($stopped) { ' STILL STOPPED: ' + ($stopped -join ',') })")
            [pscustomobject]@{ Bound = 'n/a'; AllServicesRunning = ($stopped.Count -eq 0); Stopped = $stopped; Logs = $rlog.ToArray() }
        }
        foreach ($l in $res.Logs) { $log.Add($l) }
        [pscustomobject]@{ Bound = $res.Bound; AllServicesRunning = $res.AllServicesRunning; Stopped = $res.Stopped; Logs = $log.ToArray() }
    } finally { if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue } }
}

# =================== END INLINED ENGINE ===================


$script:Headless    = [bool]$EsAction
$script:LogFilePath = $LogFile

# 'Run with PowerShell' (and a normal double-click) starts NON-elevated, but the GUI path needs
# admin: the SYSTEM-jump scheduled task and LocalMachine cert import both require it. So relaunch
# ourselves elevated (+ -STA for WinForms) when interactive and not already admin. Headless
# automation callers manage their own elevation, so skip them.
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

$script:OutputDir = Join-Path ([IO.Path]::GetTempPath()) ("MrcEsGui-{0:yyyyMMdd-HHmmss}" -f (Get-Date))
[void](New-Item -ItemType Directory -Path $script:OutputDir -Force)
$script:RunResults = [System.Collections.Generic.List[object]]::new()
$script:RunsDir    = Join-Path ([IO.Path]::GetTempPath()) 'MilestoneRecorderCertManager-runs'
$script:RootSubjectForRun = $null   # set by -RootSubject in headless; else GUI subject box drives store-mode signer lookup
$script:LastResult = $null          # last Do-Enable/Do-Disable result; headless dispatch reads this, not a function return value

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

function Format-Err { param($ErrRec)
    $ex=$ErrRec.Exception; $s=$ex.ToString()
    if([string]::IsNullOrWhiteSpace($s)){ $s="$($ErrRec)" }
    while($ex.InnerException){ $ex=$ex.InnerException; $s+=" --> $($ex.Message)" }
    $s }

# -- Honest ES verdicts (lab finding 2026-09-23) ------------------------------------------------
# ServerConfigurator can flip the Event Server's LOCAL encryption setting and then fail to register
# the change with the management server (SC exit 20, log 'Error occurred in RegisterThisService').
# The local config then says encrypted/decrypted while the management server still has the old
# registration - Management Client and every client disagree with the box. That is a FAILURE, never
# a green row. Separately, SC exit 1 on this role means SC refused before applying anything.
$script:EsExit1Msg = 'exit1(ServerConfigurator refused before applying - NOTHING changed. SC quits with 1 after reaching the management server and rejecting the request; it logs no reason even at debug level. Run ServerConfigurator interactively on this server to see the message)'
function Test-EsRegistrationFailed { param([string[]]$ScLogs)
    $txt = ($ScLogs -join ' || ')
    return ($txt -match 'Error occurred in RegisterThisService' -or $txt -match "RegisterThisService'? Status = (?!Success)")
}
function Get-EsNotRegisteredMsg { param([int64]$ExitCode,[string]$What)
    "exit$ExitCode($What APPLIED LOCALLY but NOT REGISTERED with the management server - the MS still has the previous state; check this server resolves/reaches the MS address and re-run)"
}

# -- Role-order gate (lab finding 2026-09-23) -------------------------------------------------
# Verified order: encrypt = Event Server, then management server, then recorders; decrypt = management
# server, then recorders, then Event Server. While the MS enforces encryption, ServerConfigurator on
# the Event Server exits 1 in BOTH directions and changes nothing (no reason logged, even at debug).
# MS encryption state is read with a TLS handshake to the MS on port 9000: that port is TLS-bound
# only while the MS is encrypted. Returns $true (encrypted), $false (plain), $null (no answer).
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
function Test-EsOrderGate { param([ValidateSet('enable','disable')][string]$Action)
    $addr = $null
    foreach($k in 'HKLM:\SOFTWARE\WOW6432Node\Milestone\XProtect Event Server','HKLM:\SOFTWARE\Milestone\XProtect Event Server'){
        $v = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).ManagementServerAddress; if($v){ $addr = [string]$v; break }
    }
    $msHost = if($addr){ try { ([uri]$addr).Host } catch { $addr } } else { '' }
    $enc = $null
    if($msHost){ for($i=0; $i -lt 5; $i++){ $enc = Test-MsServerEncrypted -MsHost $msHost; if($null -ne $enc){ break }; Start-Sleep -Seconds 10 } }   # MS may be mid-restart right after its own enable/disable
    if($enc -eq $false){ Write-Log "ORDER CHECK: management server $msHost is unencrypted - OK to $Action the Event Server" 'Good'; return $true }
    $why = if($enc){ "the management server ($msHost) is ENCRYPTED. ServerConfigurator cannot change the Event Server while the MS enforces encryption (it exits 1 and changes nothing). Order: encrypt = Event Server, then MS, then recorders; decrypt = MS, then recorders, then Event Server. Decrypt the management server first." }
           else { "could not determine the management server's encryption state (address '$addr', TLS probe to port 9000 got no answer)." }
    if($SkipOrderCheck){ Write-Log "ORDER CHECK overridden (-SkipOrderCheck): $why" 'Err'; return $true }
    if($script:Headless){ Write-Log "ORDER CHECK BLOCKED: $why Use -SkipOrderCheck to override." 'Err'; return $false }
    $ans = [Windows.Forms.MessageBox]::Show("Role order check: $why`r`n`r`nProceed anyway?",'Role order',[Windows.Forms.MessageBoxButtons]::YesNo,[Windows.Forms.MessageBoxIcon]::Warning,[Windows.Forms.MessageBoxDefaultButton]::Button2)
    if($ans -eq 'Yes'){ Write-Log "ORDER CHECK overridden by operator: $why" 'Err'; return $true }
    Write-Log "ORDER CHECK BLOCKED: $why" 'Err'; return $false
}
function Set-OrderBlocked {
    $script:LastResult = [pscustomobject]@{ Ok=$false; Status='BLOCKED by role-order check (see log)' }
    $script:StatusLabel.Text = $script:LastResult.Status; $script:StatusLabel.ForeColor = [Drawing.Color]::DarkRed
}

# Local-only, single-group worker: mint+import+enable, or disable, the Event Server group on THIS
# machine. Adapted from Mrc-Gui.ps1's $script:HostWorker, trimmed to exactly one target and exactly
# one fixed certificate group (no role branching, no per-group loop, no parallel runspace pool -
# there is only ever one host and one group here). Returns @{Target;Fqdn;Ok;Status;Tp;Error;Groups;
# Action;Started;Ended;DurationSec;Logs}.
$script:EsHostWorker = {
    param($P)
    $t0=Get-Date
    $logs=[System.Collections.Generic.List[string]]::new()
    $res=[pscustomobject]@{Target=$P.Target;Fqdn=$P.Fqdn;Ok=$false;Status='';Tp='';Error='';Groups=$P.GroupName;Action=$P.Action;Started=$t0;Ended=$null;DurationSec=0.0;Logs=$logs}
    try {
        Import-Module PKI -ErrorAction SilentlyContinue   # New-SelfSignedCertificate / Import-PfxCertificate (not always auto-loaded)
        if($P.Action -eq 'enable'){
            $signer = Get-ChildItem Cert:\LocalMachine\My,Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $P.SignerTp -and $_.HasPrivateKey } | Select-Object -First 1
            if(-not $signer){ throw "signer $($P.SignerTp) not found in cert store" }
            $pfxPw=[securestring]::new(); foreach($ch in ([guid]::NewGuid().ToString('N')).ToCharArray()){$pfxPw.AppendChar($ch)}; $pfxPw.MakeReadOnly()
            $certFqdn=Resolve-CertFqdn -Target $P.Target -Fqdn $P.Fqdn -DomainSuffix $P.Domain
            $sans=@(ConvertTo-SanList ([string]$P.ExtraSans))
            if($sans.Count){ $logs.Add("extra SANs: $($sans -join ', ')") }
            $pkg=New-RecorderCertificatePackage -HostName $certFqdn -DomainSuffix $P.Domain -Signer $signer -PfxPassword $pfxPw -OutputDir $P.OutputDir -ExtraDnsNames $sans
            $logs.Add("issued $($pkg.Fqdn) tp=$($pkg.Thumbprint)"); $res.Tp=$pkg.Thumbprint
            # Invoke-RemoteRecorderInstall is reused verbatim: despite its name it is not
            # role-specific - it imports the PFX to LocalMachine\My and (optionally) trusts the
            # signer CA, and is exactly what Mrc-Gui.ps1's MS-role rows call too.
            $r=Invoke-RemoteRecorderInstall -ComputerName $P.Fqdn -Credential $P.Cred -UseSsl:$false `
                 -PfxPath $pkg.PfxPath -PfxPassword $pfxPw -SignerCerPath $P.CaCer `
                 -InstallSignerToRoot $true -InstallSignerToIntermediate $false `
                 -EnableEncryption $false -ServerConfiguratorPath '' -ScCredential $P.Cred -CertificateGroup ''
            foreach($l in $r.Logs){ $logs.Add($l) }
            $e=Invoke-ScWithWedgeRetry -ComputerName $P.Fqdn -Credential $P.Cred `
                 -Thumbprint $pkg.Thumbprint -CertificateGroup $P.Guid -Action enableencryption -WorkLog $logs -GroupName $P.GroupName -ScPaths ([string]$P.ScPaths)
            foreach($l in $e.Logs){ $logs.Add("[$($P.GroupName)] $l") }
            $failMsg=''
            $regFail = Test-EsRegistrationFailed -ScLogs $e.Logs
            if($regFail -and ($e.CertApplied -or $e.ExitCode -ne 0)){ $failMsg=(Get-EsNotRegisteredMsg -ExitCode $e.ExitCode -What 'encryption'); $logs.Add("[$($P.GroupName)] $failMsg") }
            elseif($e.ExitCode -in 0,200000 -or $e.CertApplied){ }   # SC exit -4/267009 etc. with success markers in the SC log - tolerated (rule: 0 and -4 ok when markers present)
            elseif($e.ExitCode -eq 1){ $failMsg=$script:EsExit1Msg; $logs.Add("[$($P.GroupName)] $failMsg") }
            elseif($e.ExitCode -eq 100){ $failMsg='exit100(not authorized)' }
            elseif($e.ExitCode -eq 300000){ $failMsg='exit300000(cert bound but registration failed - cert CN does not match server address; server may not start)' }
            elseif($e.ExitCode -eq 100000){ $failMsg='exit100000(IDP 403 VmsAdminCredentialsNeeded - mgmt reconfig forbidden; cert may be half-applied)' }
            else { $failMsg="exit $($e.ExitCode)" }
            $conf=Confirm-EventServerEncryption -ComputerName $P.Fqdn -Credential $P.Cred -UseSsl:$false
            foreach($l in $conf.Logs){ $logs.Add($l) }
            $res.Ok = (-not $failMsg) -and $conf.AllServicesRunning
            $res.Status = if($res.Ok){ "Encrypted: $($P.GroupName) (svc $(if($conf.AllServicesRunning){'up'}else{'CHECK'}))" }
                          else { "FAILED $failMsg svc=$(if($conf.AllServicesRunning){'up'}else{'CHECK: ' + ($conf.Stopped -join ',')})" }
        } else {
            $r=Invoke-ScWithWedgeRetry -ComputerName $P.Fqdn -Credential $P.Cred `
                 -Thumbprint '' -CertificateGroup $P.Guid -Action disableencryption -WorkLog $logs -GroupName $P.GroupName -ScPaths ([string]$P.ScPaths)
            foreach($l in $r.Logs){ $logs.Add("[$($P.GroupName)] $l") }
            $failMsg=''
            if((Test-EsRegistrationFailed -ScLogs $r.Logs) -and ($r.CertApplied -or $r.ExitCode -ne 0)){ $failMsg=(Get-EsNotRegisteredMsg -ExitCode $r.ExitCode -What 'decryption') }
            elseif($r.CertApplied -or ($r.ExitCode -in 0,100,200000)){ }
            elseif($r.ExitCode -eq 1){ $failMsg=$script:EsExit1Msg }
            else { $failMsg="exit $($r.ExitCode)" }
            if($failMsg){ $logs.Add("[$($P.GroupName)] $failMsg") }
            $conf=Confirm-EventServerEncryption -ComputerName $P.Fqdn -Credential $P.Cred -UseSsl:$false
            foreach($l in $conf.Logs){ $logs.Add($l) }
            $res.Ok = (-not $failMsg) -and $conf.AllServicesRunning
            $res.Status = if($res.Ok){ "Disabled: $($P.GroupName) (svc $(if($conf.AllServicesRunning){'up'}else{'CHECK'}))" }
                          else { "FAILED $failMsg svc=$(if($conf.AllServicesRunning){'up'}else{'CHECK: ' + ($conf.Stopped -join ',')})" }
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

function Set-Busy { param([bool]$Busy)
    foreach($c in $script:BusyCtrls){ $c.Enabled = -not $Busy }
    $script:Form.UseWaitCursor=$Busy; [Windows.Forms.Application]::DoEvents() }

# -- actions -----------------------------------------------------------------
function Do-Enable {
    if(-not (Test-EsOrderGate -Action 'enable')){ Set-OrderBlocked; return }
    Set-Busy $true
    try {
        $domain=Get-DomainSuffix $script:DomainBox.Text
        # Real local FQDN (not the literal string 'localhost'): Resolve-CertFqdn's 'localhost'
        # shortcut bypasses DNS-name validation entirely, which would let a still-placeholder
        # domain box silently mint an invalid CN. Passing the real FQDN routes it through the same
        # validation every other candidate gets, so a bad domain box throws loudly instead.
        $localFqdn = ("{0}.{1}" -f $env:COMPUTERNAME, $domain).ToLowerInvariant()
        $signer=Resolve-Signer; Write-Log "Signer: $($signer.Subject) [$($signer.Thumbprint)]"
        $caCer=Join-Path $script:OutputDir 'MilestoneCA.cer'; Export-Certificate -Cert $signer -FilePath $caCer -Type CERT -Force | Out-Null
        $P=@{ Target=$env:COMPUTERNAME; Fqdn=$localFqdn; Cred=(Get-Cred $script:EsUserBox.Text $script:EsPwBox.Text)
              SignerTp=$signer.Thumbprint; CaCer=$caCer; Domain=$domain; OutputDir=$script:OutputDir
              Guid=$script:CertGroupEvent; GroupName='Event Server'; Action='enable'; ExtraSans=$script:SansBox.Text }
        $r = & $script:EsHostWorker $P
        Add-RunResult $r
        foreach($l in $r.Logs){ Write-Log "[$($r.Target)] $l" }
        $script:StatusLabel.Text = $r.Status
        $script:StatusLabel.ForeColor = if($r.Ok){[Drawing.Color]::DarkGreen}else{[Drawing.Color]::DarkRed}
        Write-Log "[$($r.Target)] $(if($r.Ok){'OK'}else{'FAILED'}): $($r.Status)" $(if($r.Ok){'Good'}else{'Err'})
        Write-Log 'Enable run complete.' 'Good'
        $script:LastResult = $r
    } catch {
        Write-Log "Enable failed: $(Format-Err $_)" 'Err'
        $script:LastResult = [pscustomobject]@{ Ok=$false; Status="FAILED: $(Format-Err $_)" }
    } finally { Export-RunResults; Set-Busy $false }
}

function Do-Disable {
    if(-not $script:Headless){ if([Windows.Forms.MessageBox]::Show('Disable encryption for the Event Server on this machine?','Confirm',4,'Warning') -ne 'Yes'){ $script:LastResult = $null; return } }
    if(-not (Test-EsOrderGate -Action 'disable')){ Set-OrderBlocked; return }
    Set-Busy $true
    try {
        $domain=Get-DomainSuffix $script:DomainBox.Text
        $localFqdn = ("{0}.{1}" -f $env:COMPUTERNAME, $domain).ToLowerInvariant()
        $P=@{ Target=$env:COMPUTERNAME; Fqdn=$localFqdn; Cred=(Get-Cred $script:EsUserBox.Text $script:EsPwBox.Text)
              SignerTp=''; CaCer=''; Domain=$domain; OutputDir=$script:OutputDir
              Guid=$script:CertGroupEvent; GroupName='Event Server'; Action='disable'; ExtraSans=$script:SansBox.Text }
        $r = & $script:EsHostWorker $P
        Add-RunResult $r
        foreach($l in $r.Logs){ Write-Log "[$($r.Target)] $l" }
        $script:StatusLabel.Text = $r.Status
        $script:StatusLabel.ForeColor = if($r.Ok){[Drawing.Color]::DarkGreen}else{[Drawing.Color]::DarkRed}
        Write-Log "[$($r.Target)] $(if($r.Ok){'OK'}else{'FAILED'}): $($r.Status)" $(if($r.Ok){'Good'}else{'Err'})
        Write-Log 'Disable run complete.' 'Good'
        $script:LastResult = $r
    } catch {
        Write-Log "Disable failed: $(Format-Err $_)" 'Err'
        $script:LastResult = [pscustomobject]@{ Ok=$false; Status="FAILED: $(Format-Err $_)" }
    } finally { Export-RunResults; Set-Busy $false }
}

# -- headless one-shot ES action (symmetric to Mrc-Gui.ps1's -MsAction) ------
function Invoke-EsAction {
    param([ValidateSet('enable','disable')][string]$Action,[string]$EsUser,[string]$EsPwFile,[string]$Domain,[string]$Sans)
    if([string]::IsNullOrWhiteSpace($EsPwFile) -or -not (Test-Path -LiteralPath $EsPwFile)){ throw "EsPwFile not found: $EsPwFile" }
    $script:EsPwBox.Text   = (Get-Content -Raw -LiteralPath $EsPwFile).Trim()
    $script:EsUserBox.Text = $EsUser
    $script:DomainBox.Text = $Domain
    $script:SansBox.Text   = $Sans
    $script:SignerStoreRadio.Checked = $true
    Write-Log "ES ONE-SHOT: $Action on $env:COMPUTERNAME (Event Server group)" 'Good'
    if($Action -eq 'enable'){ Do-Enable } else { Do-Disable }
    $r = $script:LastResult
    $ok = [bool]($r -and $r.Ok)
    $st = if($r){ $r.Status } else { '(no result - run cancelled)' }
    Write-Log "ES $Action result: $st" $(if($ok){'Good'}else{'Err'})
    return $ok
}

# Headless -CreateRoot cannot prompt: refuse placeholders and duplicate CA names loudly.
function New-RootCaHeadless { param([string]$Subject)
    if ($Subject -match '<[^>]+>') { throw "RootSubject '$Subject' is a placeholder. Pass -RootSubject 'CN=Your CA' or set SignerSubject in mrc.defaults.psd1." }
    $dup = @(Find-ExistingCa $Subject)   # @(): function return unwraps; null otherwise (StrictMode Count crash)
    if ($dup.Count) { throw "A CA with CN '$(Get-CaSubjectCn $Subject)' and a private key already exists (thumb $($dup[0].Thumbprint)). A second root with the same name changes the trust anchor and can BREAK an already-encrypted server. Omit -CreateRoot to sign with the existing CA, or use a different -RootSubject." }
    New-RootCa -Subject $Subject -OutputDir $script:OutputDir }

# -- build UI --------------------------------------------------------------
$script:Form=[Windows.Forms.Form]::new()
$script:Form.Text='Milestone Encryption - Event Server (local)'
$script:Form.StartPosition='CenterScreen'; $script:Form.ClientSize=[Drawing.Size]::new(820,560); $script:Form.MinimumSize=[Drawing.Size]::new(800,420)
$script:Tip=[Windows.Forms.ToolTip]::new(); $script:Tip.AutoPopDelay=20000; $script:Tip.InitialDelay=300; $script:Tip.ReshowDelay=100

# Domain suffix prefill: try this machine's primary DNS suffix first (works out of the box on a
# domain-joined Event Server); fall back to the deployment default / placeholder.
$ipDomain = ''
try { $ipDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName } catch {}
$domainPrefill = if ($ipDomain) { $ipDomain } else { [string]$script:Defaults.Domain }

$y=14
$script:Form.Controls.Add((New-Label 'Domain suffix' 12 $y 100))
$script:DomainBox=New-Tb 115 $y 170 $domainPrefill; $script:Form.Controls.Add($script:DomainBox)
$script:Form.Controls.Add((New-Label 'Extra SANs' 300 $y 80))
$script:SansBox=New-Tb 385 $y 420 ([string]$script:Defaults.ExtraSans); $script:Form.Controls.Add($script:SansBox)
$script:Tip.SetToolTip($script:SansBox,'Extra SAN DNS names for the minted certificate (alias addresses), comma/space/semicolon/newline separated.')

$y+=30
$script:SignerStoreRadio=[Windows.Forms.RadioButton]::new(); $script:SignerStoreRadio.Text='Sign with MilestoneCA from cert store'; $script:SignerStoreRadio.Location=[Drawing.Point]::new(12,$y); $script:SignerStoreRadio.Size=[Drawing.Size]::new(280,22); $script:SignerStoreRadio.Checked=$true; $script:Form.Controls.Add($script:SignerStoreRadio)
$script:SignerPfxRadio=[Windows.Forms.RadioButton]::new(); $script:SignerPfxRadio.Text='Signer PFX:'; $script:SignerPfxRadio.Location=[Drawing.Point]::new(300,$y); $script:SignerPfxRadio.Size=[Drawing.Size]::new(95,22); $script:Form.Controls.Add($script:SignerPfxRadio)
$script:SignerPfxBox=New-Tb 395 $y 190; $script:Form.Controls.Add($script:SignerPfxBox)
$script:Form.Controls.Add((New-Label 'pw' 592 $y 24))
$script:SignerPwBox=New-Tb 618 $y 110 '' $true; $script:Form.Controls.Add($script:SignerPwBox)
$browse=New-Btn '...' 736 ($y-2) 40; $script:Form.Controls.Add($browse)
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
            $msg="A CA named 'CN=$cn' with a private key already EXISTS (thumb $($dup[0].Thumbprint.Substring(0,8))...).`n`nCreating ANOTHER root with the same name and applying it will CHANGE the management server's trust anchor and can BREAK a server that is already configured/encrypted (IDP returns 403 -> services stop).`n`nIf you just want to sign with the existing CA, click No and leave store-mode as-is.`nUse a DIFFERENT subject (e.g. CN=MilestoneRootCA) for a genuinely new root.`n`nCreate a duplicate anyway?"
            if([Windows.Forms.MessageBox]::Show($msg,'Duplicate CA name',4,'Warning') -ne 'Yes'){ Write-Log "Create root CA cancelled (CN=$cn already exists; using existing)." 'Err'; return }
        }
        $ca=New-RootCa -Subject $subj -OutputDir $script:OutputDir
        $script:SignerStoreRadio.Checked=$true
        Write-Log "Created self-signed root CA $($ca.Subject) [$($ca.Thumbprint)] in CurrentUser\My; public cert exported to $script:OutputDir" 'Good'
        [Windows.Forms.MessageBox]::Show("Root CA created and selected for store-mode signing:`n`n$($ca.Subject)`nThumbprint: $($ca.Thumbprint)",'Root CA',0,'Information')|Out-Null
    } catch { Write-Log "Create root CA failed: $(Format-Err $_)" 'Err'; [Windows.Forms.MessageBox]::Show("Create root CA failed:`n$($_.Exception.Message)",'Error',0,'Error')|Out-Null }
})
$storeHint=New-Label '(store-mode signs with the CA matching this CN)' 500 $y 300; $script:Form.Controls.Add($storeHint)
$script:Tip.SetToolTip($storeHint,'Store-mode signs with the CA in the cert store whose CN matches this box. Create root CA makes a fresh self-signed root with this subject.')

$y+=32
$groupLbl=New-Label 'Fixed certificate group: Event Server (7e02e0f5-549d-4113-b8de-bda2c1f38dbf)' 12 $y 700
$script:Form.Controls.Add($groupLbl)
$script:Tip.SetToolTip($groupLbl,"Sets the Event Server's 'SecureCommunicationEnabled' flag and re-registers it to https. This is NOT a netsh binding - confirmation checks the Event Server service instead.")

$y+=28
$script:Form.Controls.Add((New-Label 'ES admin user' 12 $y 110))
$script:EsUserBox=New-Tb 130 $y 200 ([string]$script:Defaults.EsUser); $script:Form.Controls.Add($script:EsUserBox)
$script:Form.Controls.Add((New-Label 'ES admin pw' 345 $y 90))
$script:EsPwBox=New-Tb 440 $y 150 '' $true; $script:Form.Controls.Add($script:EsPwBox)
$credTip='Account ServerConfigurator runs as on this machine (via LogonUser/CreateProcessAsUser). Must be a member of the Milestone Administrators role on the management server, or the IDP re-registration step fails (SC exit 100).'
$script:Tip.SetToolTip($script:EsUserBox,$credTip); $script:Tip.SetToolTip($script:EsPwBox,$credTip)

$y+=34
$enableBtn=New-Btn 'Enable' 12 $y 120; $script:Form.Controls.Add($enableBtn); $enableBtn.Add_Click({ Do-Enable })
$disableBtn=New-Btn 'Disable' 140 $y 120; $script:Form.Controls.Add($disableBtn); $disableBtn.Add_Click({ Do-Disable })
$script:StatusLabel=New-Label '(no run yet)' 275 $y 530; $script:StatusLabel.Anchor='Top,Left,Right'; $script:Form.Controls.Add($script:StatusLabel)

$y+=40
$script:Log=[Windows.Forms.RichTextBox]::new(); $script:Log.Location=[Drawing.Point]::new(12,$y); $script:Log.Size=[Drawing.Size]::new(796,320); $script:Log.ReadOnly=$true; $script:Log.Anchor='Top,Bottom,Left,Right'
$script:Form.Controls.Add($script:Log)

$script:BusyCtrls=@($enableBtn,$disableBtn,$createRootBtn,$browse)

# DPI autoscale, set AFTER all controls exist (designer order): first layout compares the actual
# DPI to this 96-dpi baseline and scales every control uniformly, so fixed-width labels stop
# wrapping/clipping on 125%/150% displays. The layout itself stays authored in 96-dpi pixels.
$script:Form.AutoScaleDimensions=[Drawing.SizeF]::new(96,96); $script:Form.AutoScaleMode='Dpi'

# Screen clamp + MinimumSize at Shown time - only then are DPI scaling and anchor distances final.
$script:Form.Add_Shown({
    $wa=[Windows.Forms.Screen]::FromControl($script:Form).WorkingArea
    if($script:Form.Height -gt $wa.Height){ $script:Form.Height=$wa.Height }
    $minH=$script:Form.Height - $script:Log.Height + 120   # keep >= 120px of log visible
    $script:Form.MinimumSize=[Drawing.Size]::new($script:Form.Width,$minH)
})

Write-Log "Output dir: $script:OutputDir" 'Good'
if($script:DefaultsLoadError){ Write-Log "WARNING: mrc.defaults.psd1 failed to parse: $script:DefaultsLoadError - using built-in placeholders" 'Err' }
elseif($script:DefaultsLoaded.Count){ Write-Log "Loaded defaults from mrc.defaults.psd1: $($script:DefaultsLoaded -join ', ')" }
Write-Log 'Target is always this machine. Fixed group: Event Server. Confirmation checks the Event Server service, not a netsh binding.'

if($EsAction){
    try {
        $script:SignerSubjectBox.Text=$RootSubject; $script:RootSubjectForRun=$RootSubject
        if($CreateRoot){ Write-Log "Creating self-signed root CA: $RootSubject"; $rca=New-RootCaHeadless -Subject $RootSubject; Write-Log "Root CA created [$($rca.Thumbprint)]" 'Good' }
        $ok = Invoke-EsAction -Action $EsAction -EsUser $EsUser -EsPwFile $EsPwFile -Domain $SelfTestDomain -Sans $ExtraSans
        exit ([int](-not $ok))
    } catch { Write-Log "ES-ACTION FATAL: $(Format-Err $_)" 'Err'; exit 2 }
} else {
    [void]$script:Form.ShowDialog()
}
