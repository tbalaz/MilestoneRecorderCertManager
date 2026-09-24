#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone XProtect encryption - guided wizard for the whole system (one file, run on the
    Management Server).

.DESCRIPTION
    A step-by-step wizard that turns Milestone XProtect server encryption ON or OFF for the whole
    system in the one order that works:
        Turn encryption ON : Event Server, then Management Server, then recording servers
        Turn encryption OFF: Management Server, then recording servers, then Event Server
    ServerConfigurator on a standalone Event Server refuses (exit 1, nothing changed) while the
    Management Server is encrypted, and recording servers refuse to move against the Management
    Server's state - so this order is enforced by construction: before every step the real state
    of the prerequisite machine is read, and the sequence stops if it is wrong.

    WHERE TO RUN IT: on the Management Server itself, as Administrator. The Management Server step
    runs locally (in-process). The Event Server and the recording servers are reached over WinRM
    (PowerShell remoting) with the account you enter. If this computer is not a Management Server
    (no 'Milestone XProtect Management Server' service), the tool refuses to start.

    The four wizard pages:
        1 Connect - this computer, the Event Server name (or 'No separate Event Server'), the admin
                    account, an optional separate recording-server account, the signing CA.
                    Recording servers are found automatically from the VMS (the recording server
                    that runs on this Management Server is covered by the Management Server step).
        2 Check   - every computer: reachable or not, and its REAL encryption state.
        3 Action  - 'Turn encryption ON' / 'Turn encryption OFF', with live progress per step and a
                    'Show details' technical log.
        4 Result  - the final real state of every computer and the path of the report file.

    Real state (never taken from ServerConfigurator's own verdict):
        Management Server : netsh http sslcert has a binding on port 9000 or 9001 (local)
        Event Server      : <CertificateEnabled> in
                            %ProgramData%\Milestone\XProtect Event Server\config\ServiceEndpoints.xml
        Recording server  : netsh http sslcert has any binding other than port 443 and 5986
    A computer that cannot be reached is 'Unknown'. Computers already in the wanted state are
    skipped. After every step the real state is read again; if it is not what was asked for, the
    sequence STOPS and a plain-language message says what failed and what to do next.

    Every run writes a report (CSV + TXT, one row per computer and step) to
    %TEMP%\MilestoneRecorderCertManager-runs\ and shows its path.

    All site-specific defaults ship CLEARED to placeholders. For convenient repeat use in one
    environment, drop a 'mrc.defaults.psd1' next to this script (same file and keys as the other
    Mrc-*.ps1 tools, plus EsHost; unused keys are ignored). It is operator convenience only and must
    never be shipped to a client.
.NOTES
    Interactive (on the Management Server console):
        powershell -ExecutionPolicy Bypass -STA -File .\Mrc-Guided.ps1

    Headless (no window, for automated testing). Passwords are read from files, never from the
    command line:
        powershell -ExecutionPolicy Bypass -File .\Mrc-Guided.ps1 -Action on `
            -EsHost <event-server-fqdn> -AdminUser '<DOMAIN>\Administrator' -AdminPwFile <path-to-pw-file> `
            -RecTargets '<rec1-fqdn>,<REC2>=<rec2-ip>' -RecUser Administrator -RecPwFile <path-to-pw-file> `
            -RootSubject 'CN=<Your Organization> CA' -ExtraSans '<ms-alias-fqdn>' -LogFile <path-to-log>
    -Action on|off|status. -NoEventServer instead of -EsHost when there is no standalone Event
    Server. Without -RecTargets the recording servers are discovered from the VMS (-MsAddr, default
    this machine; needs MilestonePSTools). Exit code: on/off -> 0 only if every computer's real
    state equals the target; status -> 0 only if every computer was reachable. 1 = not complete,
    2 = fatal error, 3 = refused (not a Management Server / not elevated / missing input).
#>
[CmdletBinding()]
param(
    [ValidateSet('','on','off','status')][string]$Action = '',   # headless: on | off | status (no window). Empty = wizard.
    [string]$EsHost = '',                               # standalone Event Server host (FQDN, short name or IP)
    [switch]$NoEventServer,                             # there is no standalone Event Server
    [string]$RecTargets = '',                           # comma list of recorders ('host' or 'name=ip'); empty = discover from the VMS
    [string]$AdminUser = '',                            # admin account (Management Server + Event Server + default for recorders)
    [string]$AdminPwFile,                               # file holding the admin password (headless only)
    [string]$RecUser = '',                              # optional separate recording-server account
    [string]$RecPwFile,                                 # file holding the recording-server password (headless only)
    [string]$RootSubject = '<signer-subject>',          # signing CA subject (store lookup by CN)
    [string]$ExtraSans = '',                            # extra SAN DNS names for the Management Server certificate
    [string]$LogFile,                                   # optional: tee the log here
    [string]$MsAddr = '',                               # VMS address for recorder discovery (default: this machine)
    [string]$Domain = ''                                # DNS domain suffix (default: this machine's primary DNS suffix)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Deployment defaults (client-ready) ------------------------------------------------------
# NEUTRAL placeholders only - nothing site-specific is baked into this file. For repeat use in ONE
# known environment, drop a 'mrc.defaults.psd1' next to this script with any subset of these keys
# (the same file the other Mrc-*.ps1 tools read; keys not used here are ignored), e.g.:
#     @{ Domain='contoso.local'; MsUser='CONTOSO\Administrator'; RecUser='Administrator'
#        SignerSubject='CN=Contoso VMS CA'; EsHost='events.contoso.local'; ExtraSans='vms.contoso.local' }
# That file is gitignored and must NEVER be shipped to a client - it is operator convenience only.
$script:Defaults = @{
    MsAddr        = '<management-server-address>'    # VMS address for recorder discovery (default: this machine)
    Domain        = '<domain-suffix>'                # DNS domain suffix (machine DNS suffix is tried first)
    MsUser        = '<DOMAIN>\Administrator'          # admin account (wizard 'Admin account')
    RecUser       = ''                                # optional separate recording-server account
    SignerSubject = 'CN=<Your Organization> CA'       # signing CA subject (store lookup by CN / Create signing CA)
    MsFqdn        = '<mgmt-fqdn>'                     # this Management Server's certificate name (default: COMPUTERNAME.<domain>)
    EsHost        = '<event-server-host>'             # standalone Event Server host
    ExtraSans     = ''                                # extra SAN names for the Management Server certificate
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
$AdminUser   = Resolve-Default $AdminUser   'MsUser'
$RecUser     = Resolve-Default $RecUser     'RecUser'
$RootSubject = Resolve-Default $RootSubject 'SignerSubject'
$ExtraSans   = Resolve-Default $ExtraSans   'ExtraSans'
$MsAddr      = Resolve-Default $MsAddr      'MsAddr'
if (-not $NoEventServer) { $EsHost = Resolve-Default $EsHost 'EsHost' }

# ===================== INLINED ENGINE (verbatim from Mrc-Es-Gui.ps1 / Mrc-Ms-Gui.ps1) =====================
# Everything from here to END INLINED ENGINE is copied VERBATIM from the lab-verified role GUIs:
# the SYSTEM-jump launcher, certificate helpers, Invoke-RemoteRecorderInstall,
# Invoke-RemoteServerEncryption, the Event Server SUPERSET variants of Repair-WedgedService and
# Invoke-ScWithWedgeRetry (they also restart a wedged Event Server), Confirm-ServerEncryption
# (Mrc-Ms-Gui.ps1) and Confirm-EventServerEncryption (Mrc-Es-Gui.ps1). Do NOT "improve" or
# DRY-refactor anything in this block - a fix must be made in every Mrc-*.ps1 that carries it.
#
# ServerConfigurator /enableencryption exit codes:
#    0    success
#    100  local cert applied BUT MS registration failed ("not authorized") => run-as account is not
#         in the Milestone Administrators role on the management server
#    -4   silent failure: cert chains to an untrusted root (install signer CA into LocalMachine\Root)
#         OR a stuck ServerConfigurator instance holds the singleton lock

# Milestone certificate-group GUIDs (constant across XProtect installs).
$script:CertGroupServer = '84430eb7-847c-422d-aa00-7915cd0d7a65'   # Management server / co-located recorder / recording servers
$script:CertGroupEvent  = '7e02e0f5-549d-4113-b8de-bda2c1f38dbf'   # Event Server
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
                $scExe = if ([string]::IsNullOrWhiteSpace($ConfPath)) {
                    'C:\Program Files\Milestone\Server Configurator\ServerConfigurator.exe'
                } else { $ConfPath }
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
                $scLog = Get-ChildItem -Path 'C:\ProgramData\Milestone' -Recurse -Filter '*.log' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match 'erver.?onfigurator' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
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
            $scExe = if ([string]::IsNullOrWhiteSpace($ConfPath)) {
                'C:\Program Files\Milestone\Server Configurator\ServerConfigurator.exe'
            } else { $ConfPath }
            if (-not (Test-Path -LiteralPath $scExe)) { throw "ServerConfigurator not found: $scExe | $($elog.ToArray() -join ' | ')" }
            $scDir   = [System.IO.Path]::GetDirectoryName($scExe)
            # Kill any stale ServerConfigurator first: its singleton lock makes the next run exit -4/1 silently.
            Get-Process -Name ServerConfigurator -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 800
            $work    = Join-Path $env:windir ("Temp\MRC-{0}" -f [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $work -Force | Out-Null
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
            }
            $stdout = (Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue)
            $stderr = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
            Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
            $elog.Add("[$env:COMPUTERNAME] SC stdout: $(if ($stdout -and $stdout.Trim()) { $stdout.Trim() } else { '(empty)' })")
            $elog.Add("[$env:COMPUTERNAME] SC stderr: $(if ($stderr -and $stderr.Trim()) { $stderr.Trim() } else { '(empty)' })")
            $elog.Add("[$env:COMPUTERNAME] SC exit code: $scExit")
            $scLog = Get-ChildItem -Path 'C:\ProgramData\Milestone' -Recurse -Filter '*.log' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match 'erver.?onfigurator' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
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
          [System.Collections.Generic.List[string]]$WorkLog,[string]$GroupName)
    try {
        Invoke-RemoteServerEncryption -ComputerName $ComputerName -Credential $Credential -UseSsl:$false `
            -Thumbprint $Thumbprint -ServerConfiguratorPath '' -ScCredential $Credential -CertificateGroup $CertificateGroup -Action $Action
    } catch {
        $m=$_.Exception.Message
        if($m -notmatch 'cannot accept control messages|Unable to (?:stop|restart) the service|Could not stop service'){ throw }
        if(-not (Test-Path variable:script:WedgeDepth)){ $script:WedgeDepth = 0 }   # StrictMode-safe init (runspaces too)
        if($script:WedgeDepth -ge 3){ $WorkLog.Add("[$GroupName] WEDGE: giving up after 3 recovery attempts"); throw }   # bounded: SC + up to 3 recoveries
        $dn=if($m -match 'Unable to (?:stop|restart) the service (.+?)\.'){ $Matches[1].Trim() }
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
            $svc = Get-Service | Where-Object $iisSel
            foreach ($s in ($svc | Where-Object { $_.Status -ne 'Running' })) {
                try { Start-Service $s.Name -ErrorAction Stop; $rlog.Add("[$env:COMPUTERNAME] started service: $($s.Name)") }
                catch { $rlog.Add("[$env:COMPUTERNAME] FAILED to start $($s.Name): $($_.Exception.Message)") }
            }
            Start-Sleep -Seconds 3
            $svc = Get-Service | Where-Object $iisSel
            $stopped = @($svc | Where-Object { $_.Status -ne 'Running' } | Select-Object -ExpandProperty Name)
            $binds = (netsh http show sslcert) -join "`n"
            $bound = $binds -match $Tp
            $rlog.Add("[$env:COMPUTERNAME] cert $Tp bound: $bound")
            $rlog.Add("[$env:COMPUTERNAME] services running: $(($svc | Where-Object Status -eq Running).Count)/$($svc.Count)$(if ($stopped) { ' STILL STOPPED: ' + ($stopped -join ',') })")
            [pscustomobject]@{ Bound = [bool]$bound; AllServicesRunning = ($stopped.Count -eq 0); Stopped = $stopped; Logs = $rlog.ToArray() }
        } -ArgumentList $tp
        foreach ($l in $res.Logs) { $log.Add($l) }
        [pscustomobject]@{ Bound = $res.Bound; AllServicesRunning = $res.AllServicesRunning; Stopped = $res.Stopped; Logs = $log.ToArray() }
    } finally { if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue } }
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
            $svc = Get-Service | Where-Object $esSel
            foreach ($s in ($svc | Where-Object { $_.Status -ne 'Running' })) {
                try { Start-Service $s.Name -ErrorAction Stop; $rlog.Add("[$env:COMPUTERNAME] started service: $($s.Name)") }
                catch { $rlog.Add("[$env:COMPUTERNAME] FAILED to start $($s.Name): $($_.Exception.Message)") }
            }
            Start-Sleep -Seconds 3
            $svc = Get-Service | Where-Object $esSel
            $stopped = @($svc | Where-Object { $_.Status -ne 'Running' } | Select-Object -ExpandProperty Name)
            $rlog.Add("[$env:COMPUTERNAME] services running: $(($svc | Where-Object Status -eq Running).Count)/$($svc.Count)$(if ($stopped) { ' STILL STOPPED: ' + ($stopped -join ',') })")
            [pscustomobject]@{ Bound = 'n/a'; AllServicesRunning = ($stopped.Count -eq 0); Stopped = $stopped; Logs = $rlog.ToArray() }
        }
        foreach ($l in $res.Logs) { $log.Add($l) }
        [pscustomobject]@{ Bound = $res.Bound; AllServicesRunning = $res.AllServicesRunning; Stopped = $res.Stopped; Logs = $log.ToArray() }
    } finally { if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue } }
}


# =================== END INLINED ENGINE ===================


$script:Headless    = [bool]$Action
$script:LogFilePath = $LogFile

# Plain-language refusal before any window exists (Write-Log needs the form's log box).
function Stop-Refused { param([string]$Msg)
    if($script:Headless){
        Write-Host "REFUSED: $Msg"
        if($script:LogFilePath){ try { Add-Content -LiteralPath $script:LogFilePath -Value "REFUSED: $Msg" -Encoding UTF8 } catch {} }
        exit 3
    }
    [System.Windows.Forms.MessageBox]::Show($Msg,'Milestone Encryption',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    exit 3
}

# This tool must run ON the Management Server: the Management Server step runs locally, in-process.
$script:MsServiceName = 'Milestone XProtect Management Server'
if(-not (Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $script:MsServiceName })){
    Stop-Refused ("This computer ($env:COMPUTERNAME) is not a Milestone Management Server - the service '$($script:MsServiceName)' was not found here.`r`n`r`n" +
                  "Copy this file to the Management Server and run it there, as Administrator.")
}

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

if ($script:Headless) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) { Stop-Refused 'This tool must run elevated (as Administrator).' }
}

$script:OutputDir = Join-Path ([IO.Path]::GetTempPath()) ("MrcGuided-{0:yyyyMMdd-HHmmss}" -f (Get-Date))
[void](New-Item -ItemType Directory -Path $script:OutputDir -Force)
$script:RunResults = [System.Collections.Generic.List[object]]::new()
$script:RunsDir    = Join-Path ([IO.Path]::GetTempPath()) 'MilestoneRecorderCertManager-runs'
$script:RootSubjectForRun = $null   # set from -RootSubject in headless; else the wizard's CA box drives store-mode signer lookup
$script:LastReportPath = ''

# ===================== HELPERS (verbatim from the role GUIs) =====================
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

# Per-host enable/disable worker for the Management Server (serial, this thread) and the recording
# servers (parallel, runspaces). VERBATIM $script:HostWorker from Mrc-Rec-Gui.ps1 / Mrc-Ms-Gui.ps1.
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
                     -Thumbprint $pkg.Thumbprint -CertificateGroup $g -Action enableencryption -WorkLog $logs -GroupName $gn
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
            $res.Ok = ($failG.Count -eq 0) -and ((-not $P.BindExpected) -or $conf.Bound)
            $res.Status = if($res.Ok){ "Encrypted: $($okG -join '+') (svc $(if($conf.AllServicesRunning){'up'}else{'CHECK'}))" } else { "FAILED ok=[$($okG -join '+')] fail=[$($failG -join '+')] bound=$($conf.Bound)" }
        } else {
            $okG=@(); $failG=@()
            for($i=0;$i -lt $guids.Count;$i++){
                $g=$guids[$i]; $gn= if($i -lt $names.Count){ $names[$i] } else { $g }
                $r=Invoke-ScWithWedgeRetry -ComputerName $P.Fqdn -Credential $P.Cred `
                     -Thumbprint '' -CertificateGroup $g -Action disableencryption -WorkLog $logs -GroupName $gn
                foreach($l in $r.Logs){ $logs.Add($l) }
                if($r.CertApplied -or ($r.ExitCode -in 0,100,200000)){ $okG+=$gn } else { $failG+="$gn=exit $($r.ExitCode)" }
            }
            $conf=Confirm-ServerEncryption -ComputerName $P.Fqdn -Credential $P.Cred -UseSsl:$false -Thumbprint '0'
            foreach($l in $conf.Logs){ $logs.Add($l) }
            $res.Ok = ($failG.Count -eq 0)
            $res.Status = if($res.Ok){ "Disabled: $($okG -join '+') (svc $(if($conf.AllServicesRunning){'up'}else{'CHECK'}))" } else { "FAILED fail=[$($failG -join '+')]" }
        }
    } catch { $res.Status='FAILED'; $logs.Add("ERROR: $($_.Exception.Message)"); $res.Error=$_.Exception.Message }
    $res.Ended=Get-Date; $res.DurationSec=[math]::Round((New-TimeSpan -Start $t0 -End $res.Ended).TotalSeconds,1)
    $res
}

# Event Server enable/disable worker. VERBATIM $script:EsHostWorker from Mrc-Es-Gui.ps1; its engine
# calls are remote-capable, so here it runs against the standalone Event Server over WinRM.
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
                 -Thumbprint $pkg.Thumbprint -CertificateGroup $P.Guid -Action enableencryption -WorkLog $logs -GroupName $P.GroupName
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
                 -Thumbprint '' -CertificateGroup $P.Guid -Action disableencryption -WorkLog $logs -GroupName $P.GroupName
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

# Management Server settle gate (VERBATIM from Mrc-Ms-Gui.ps1): run before the local SC apply.
# ServerConfigurator stops/restarts EVERY Server-group component service during an apply; any
# sibling (Log Server, Data Collector) whose VideoOS control handler has wedged (error 1061
# 'cannot accept control messages' while still running) aborts the whole SC run in
# PreApplyCertificate. Ensure each is stoppable: try a stop, kill on refusal - a STOPPED
# sibling is a valid SC input (it starts them again after the apply).
function Clear-WedgedMilestoneSiblings {
    foreach($sb in (Get-Service | Where-Object { $_.DisplayName -in 'Milestone XProtect Log Server','Milestone XProtect Data Collector Server' -and $_.Status -eq 'Running' })){
        try { Stop-Service $sb.Name -Force -ErrorAction Stop; Write-Log "readiness gate stopped $($sb.DisplayName) (ServerConfigurator restarts it)" }
        catch {
            $ci = Get-CimInstance Win32_Service -Filter "DisplayName='$($sb.DisplayName)'"
            if($ci -and $ci.ProcessId -gt 0){
                Write-Log "$($sb.DisplayName) control handler wedged - killing pid $($ci.ProcessId)" 'Err'
                Stop-Process -Id $ci.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# ServerConfigurator restarts the Management Server service as part of every apply; against a
# service that is mid-startup it fails with SC exit 10000/20000 ('The service cannot accept
# control messages at this time') and back-to-back self-test cycles cascade. No passive probe
# works: 'sc.exe interrogate' returns 1061 on VideoOS services even when fully operational, and
# HTTP probes lie (IDP is IIS-hosted, :8080 lingers across restarts). The only deterministic
# gate is to STOP the service ourselves before the SC run - a stopped Management Server is a
# proven-valid input state for ServerConfigurator (it starts the service itself), and
# Stop-Service either succeeds or tells us the service is still initializing (retry until it
# accepts). Local self-test only; off-box runs fall back to HTTP probes as a best effort.
function Wait-MsIdpReady { param([string]$MsFqdn,[int]$TimeoutSec=600,[switch]$WantRunning)
    $deadline=(Get-Date).AddSeconds($TimeoutSec)
    $killAfter=(Get-Date).AddSeconds(90)
    $svc = Get-Service | Where-Object { $_.DisplayName -eq 'Milestone XProtect Management Server' } | Select-Object -First 1
    do {
        if($svc -and $WantRunning){
            # ENABLE needs a SETTLED, RUNNING Management Server: with a stopped one ServerConfigurator
            # skips the IIS 443 rebind entirely, and against a freshly-started one its own service
            # restart step fails (control handler not accepting yet; :8080 http.sys registration can
            # linger from the previous instance, so the port alone is not proof). Require real process
            # uptime on top of the port before letting SC at it.
            $svc.Refresh()
            if($svc.Status -eq 'Stopped'){ try { Start-Service $svc.Name -ErrorAction Stop; Write-Log 'MS service started by readiness gate' } catch {} }
            $ws=$false
            try { $tc=[System.Net.Sockets.TcpClient]::new(); $tc.Connect('127.0.0.1',8080); $ws=$tc.Connected; $tc.Close() } catch {}
            $upSec=-1
            $ci = Get-CimInstance Win32_Service -Filter "DisplayName='Milestone XProtect Management Server'"
            if($ci -and $ci.ProcessId -gt 0){
                $p = Get-Process -Id $ci.ProcessId -ErrorAction SilentlyContinue
                if($p){ $upSec = [int](New-TimeSpan -Start $p.StartTime -End (Get-Date)).TotalSeconds }
            }
            if($ws -and $svc.Status -eq 'Running' -and $upSec -ge 240){
                Clear-WedgedMilestoneSiblings
                Write-Log "MS service settled (uptime ${upSec}s, :8080 up) - ready for enable"; return $true
            }
        } elseif($svc){
            $svc.Refresh()
            if($svc.Status -eq 'Stopped'){ Clear-WedgedMilestoneSiblings; Write-Log 'MS service stopped - ready for ServerConfigurator (it will start it)'; return $true }
            if($svc.Status -eq 'Running'){
                try { Stop-Service $svc.Name -Force -ErrorAction Stop; Clear-WedgedMilestoneSiblings; Write-Log 'MS service stopped by readiness gate - ServerConfigurator will start it'; return $true }
                catch {
                    Write-Log "MS service not stoppable yet ($($_.Exception.Message.Split([char]10)[0])) - waiting"
                    # The VideoOS service control handler can wedge permanently (error 1061 while the
                    # service still serves traffic and SCM reports STOPPABLE). No control ever succeeds
                    # again; the operator remedy is killing the process. Do that after a short grace.
                    if((Get-Date) -gt $killAfter){
                        $ci = Get-CimInstance Win32_Service -Filter "DisplayName='Milestone XProtect Management Server'"
                        if($ci -and $ci.ProcessId -gt 0){
                            Write-Log "MS service control handler wedged (1061 for 90s+) - killing pid $($ci.ProcessId) so ServerConfigurator can proceed" 'Err'
                            Stop-Process -Id $ci.ProcessId -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 5
                        }
                    }
                }
            }
        } else {
            $idpOk=$false; $wsOk=$false
            try { $r=Invoke-WebRequest -Uri ("http://{0}/IDP/.well-known/openid-configuration" -f $MsFqdn) -UseBasicParsing -TimeoutSec 15; $idpOk=($r.StatusCode -eq 200) } catch {}
            if($idpOk){ $tc=$null; try { $tc=[System.Net.Sockets.TcpClient]::new(); $tc.Connect($MsFqdn,8080); $wsOk=$tc.Connected } catch {} finally { if($tc){$tc.Close()} } }
            if($idpOk -and $wsOk){ Write-Log "MS ready on $MsFqdn (IDP 200 + :8080 up)"; return $true }
        }
        Start-Sleep -Seconds 10
    } while((Get-Date) -lt $deadline)
    Write-Log "MS NOT ready after ${TimeoutSec}s - proceeding anyway" 'Err'
    $false }


# ===================== GUIDED ORCHESTRATION (new in this file) =====================

# Run the per-host worker over many recorders IN PARALLEL via a throttled runspace pool.
# ADAPTED from Mrc-Rec-Gui.ps1 Invoke-RecordersParallel: identical runspace setup (same engine
# function list, same launcher variable, same worker), but the targets are guided-run box objects
# instead of grid rows, and progress goes to the step list instead of a grid cell. Returns one
# [pscustomobject]@{Box;Result} per recorder that produced a result.
function Invoke-RecordersParallel { param([object[]]$Boxes,[string]$Action,[hashtable]$Common,[int]$Throttle)
    $funcNames='Normalize-RecorderHostName','Get-DomainSuffix','Get-RecorderFqdn','ConvertTo-SanList','Resolve-CertFqdn','Test-SigningCertificate','Import-SignerCertificate','New-RecorderCertificatePackage','Invoke-RemoteRecorderInstall','Invoke-RemoteServerEncryption','Repair-WedgedService','Invoke-ScWithWedgeRetry','Confirm-ServerEncryption','Test-LocalTarget'
    $iss=[System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    foreach($fn in $funcNames){ $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry $fn,((Get-Command $fn).Definition))) }
    $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry 'LauncherCSharp',$script:LauncherCSharp,''))
    $pool=[runspacefactory]::CreateRunspacePool(1,[Math]::Max(1,$Throttle),$iss,$Host); $pool.Open()
    Write-Log "Parallel $Action of $(@($Boxes).Count) recorder(s), max $Throttle at once..."
    $jobs=@()
    foreach($box in @($Boxes)){
        $P=@{Target=$box.Target;Fqdn=$box.Addr;Cred=$Common.Cred;SignerTp=$Common.SignerTp;CaCer=$Common.CaCer;Domain=$Common.Domain;OutputDir=$Common.OutputDir;Guids=$Common.Guids;Names=$Common.Names;Action=$Action;BindExpected=$true;ExtraSans=''}
        $ps=[powershell]::Create(); $ps.RunspacePool=$pool
        [void]$ps.AddScript($script:HostWorker).AddArgument($P)
        $jobs += [pscustomobject]@{Box=$box;PS=$ps;Handle=$ps.BeginInvoke();Done=$false}
    }
    $out=[System.Collections.Generic.List[object]]::new()
    $remaining=$jobs.Count; $done=0
    while($remaining -gt 0){
        foreach($j in @($jobs | Where-Object { -not $_.Done -and $_.Handle.IsCompleted })){
            try { $r=@($j.PS.EndInvoke($j.Handle))[0] } catch { $r=[pscustomobject]@{Target=[string]$j.Box.Target;Fqdn=[string]$j.Box.Addr;Ok=$false;Status="FAILED ($($_.Exception.Message))";Tp='';Error=$_.Exception.Message;Groups='';Action=$Action;Started=Get-Date;Ended=Get-Date;DurationSec=0.0;Logs=@()} }
            $j.PS.Dispose(); $j.Done=$true; $remaining--; $done++
            if($r){
                Add-RunResult $r; foreach($l in $r.Logs){ Write-Log "[$($r.Target)] $l" }
                Write-Log "[$($r.Target)] $(if($r.Ok){'OK'}else{'FAILED'}): $($r.Status)" $(if($r.Ok){'Good'}else{'Err'})
                [void]$out.Add([pscustomobject]@{Box=$j.Box;Result=$r})
            }
            Set-StageStatus 'REC' "Working... $done of $($jobs.Count) finished" 'Work'
        }
        Start-Sleep -Milliseconds 250; [Windows.Forms.Application]::DoEvents()
    }
    $pool.Close(); $pool.Dispose()
    $out.ToArray()
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
    $connected=$false
    $connectedUrl=$null
    foreach($u in $cands){
        try {
            $cp=@{ServerAddress=[uri]$u;AcceptEula=$true;ErrorAction='Stop'}
            if($VmsCred){ $cp.Credential=$VmsCred }
            Write-Log "Connecting VMS $u to discover recorders..."
            Connect-Vms @cp | Out-Null
            Write-Log "Connected: $u" 'Good'; $connected=$true; $connectedUrl=$u; break
        } catch { Write-Log "  $u -> $($_.Exception.GetType().Name)" }
    }
    if(-not $connected){ throw "Could not connect to the VMS on any of: $($cands -join ', ')." }
    $msNames = [System.Collections.Generic.List[string]]::new()
    $addMs = { param($n) if($n){ try { $s = Normalize-RecorderHostName $n; if($msNames -notcontains $s){ [void]$msNames.Add($s) } } catch {} } }
    try { $vmsMs = Get-VmsManagementServer -ErrorAction Stop; if($vmsMs -and $vmsMs.Name){ & $addMs $vmsMs.Name } } catch {}
    if($connectedUrl){ try { & $addMs (([uri]$connectedUrl).Host) } catch {} }
    if($rawHost -and $rawHost -notmatch '^\d{1,3}(\.\d{1,3}){3}$'){ & $addMs $rawHost }
    elseif($rawHost){ try { & $addMs ([System.Net.Dns]::GetHostEntry($rawHost).HostName) } catch {} }
    & $addMs $env:COMPUTERNAME
    $found=[System.Collections.Generic.List[object]]::new()
    foreach($rec in (Get-VmsRecordingServer | Sort-Object Name)){
        $src= if(-not [string]::IsNullOrWhiteSpace($rec.HostName)){$rec.HostName}else{$rec.Name}
        $isIp = $src -match '^\d{1,3}(\.\d{1,3}){3}$'
        $short= Normalize-RecorderHostName $(if($isIp){ $rec.Name } else { $src })
        $fqdn = if($isIp){ $src } else { Get-RecorderFqdn -HostName $short -DomainSuffix $Domain }
        if($msNames -contains $short){
            Write-Log "Recording server '$($rec.Name)' runs on this Management Server - it is covered by the Management Server step, not handled separately."
            continue
        }
        [void]$found.Add([pscustomobject]@{ Name=[string]$rec.Name; Target=$short; Fqdn=$fqdn })
    }
    Write-Log "Discovered $($found.Count) recording server(s)." 'Good'
    Disconnect-ManagementServer -ErrorAction SilentlyContinue
    $found.ToArray()
}

# -- boxes (one per computer) and their REAL encryption state -------------------------------
$script:MsBox = $null; $script:EsBox = $null; $script:RecBoxes = @()
$script:RunFailure = $null; $script:SignerTp = ''; $script:CaCer = ''; $script:HasResult = $false
$script:RunStart = Get-Date; $script:StageRows = @{}; $script:LastOutcome = $null
$script:SessOpt = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 180000

function New-Box { param([string]$Role,[string]$Name,[string]$Target,[string]$Addr,[pscredential]$Cred)
    [pscustomobject]@{ Role=$Role; Name=$Name; Target=$Target; Addr=$Addr; Cred=$Cred; Reachable=$false; Encrypted=$null; Detail='not checked yet'; Excluded=$false } }
function Get-AllBoxes {
    $a=@(); if($script:MsBox){ $a+=$script:MsBox }; if($script:EsBox){ $a+=$script:EsBox }; $a+=@($script:RecBoxes); $a }
function Get-FirstLine { param([string]$Text) if(-not $Text){ return '' }; ($Text -split "`r?`n")[0].Trim() }
function Test-IpAddress { param([string]$Value) $ip=$null; [System.Net.IPAddress]::TryParse(([string]$Value).Trim(),[ref]$ip) }
function Get-StateText { param($Box)
    if(-not $Box.Reachable){ 'Unknown (cannot connect)' } elseif($null -eq $Box.Encrypted){ 'Unknown' } elseif($Box.Encrypted){ 'Encrypted' } else { 'Not encrypted' } }

# Ground truth readers. Management Server / recording server: netsh http sslcert bindings (443 = IIS
# and 5986 = WinRM HTTPS are ignored); MS encrypted iff port 9000 or 9001 is bound. Event Server:
# <CertificateEnabled> in its ServiceEndpoints.xml.
$script:BindingsSb = {
    $b = @(netsh http show sslcert | Select-String 'IP:port\s*:\s*(\S+)' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Where-Object { $_ -notmatch ':(443|5986)$' })
    [pscustomobject]@{ Bindings = ($b -join ','); Count = $b.Count }
}
$script:EsStateSb = {
    $p = Join-Path $env:ProgramData 'Milestone\XProtect Event Server\config\ServiceEndpoints.xml'
    if(-not (Test-Path -LiteralPath $p)){ return [pscustomobject]@{ Found=$false; Value=''; Path=$p } }
    $x = [xml](Get-Content -LiteralPath $p -Raw)
    $n = $x.SelectSingleNode('/eventserverconfig/CertificateEnabled')
    [pscustomobject]@{ Found=$true; Value=$(if($n){ ([string]$n.InnerText).Trim() } else { '(element missing)' }); Path=$p }
}
function Invoke-OnBox { param([string]$Computer,[pscredential]$Cred,[scriptblock]$Sb)
    if(Test-LocalTarget $Computer){ return (& $Sb) }
    $p=@{ ComputerName=$Computer; ScriptBlock=$Sb; ErrorAction='Stop'; SessionOption=$script:SessOpt }
    if($Cred){ $p.Credential=$Cred }
    Invoke-Command @p
}
function Set-RecBoxState { param($Box,$R)
    $Box.Reachable=$true; $Box.Encrypted=([int]$R.Count -gt 0); $Box.Detail="bindings: $(if($R.Bindings){$R.Bindings}else{'none'})" }
function Update-RecorderStates { param([object[]]$Boxes)
    $remote=@()
    foreach($b in @($Boxes)){
        if(Test-LocalTarget $b.Addr){
            try { Set-RecBoxState $b (& $script:BindingsSb) } catch { $b.Reachable=$true; $b.Encrypted=$null; $b.Detail="netsh failed: $(Get-FirstLine $_.Exception.Message)" }
        } else { $remote+=$b }
    }
    if(-not $remote.Count){ return }
    # One fan-out Invoke-Command for all recorders (WinRM runs them in parallel).
    $addrs=@($remote | ForEach-Object { [string]$_.Addr } | Select-Object -Unique)
    $ev=$null
    $p=@{ ComputerName=$addrs; ScriptBlock=$script:BindingsSb; SessionOption=$script:SessOpt; ThrottleLimit=32; ErrorAction='SilentlyContinue'; ErrorVariable='ev' }
    if($remote[0].Cred){ $p.Credential=$remote[0].Cred }
    $out=@(Invoke-Command @p)
    $res=@{}; foreach($o in $out){ $res[[string]$o.PSComputerName]=$o }
    $errs=@{}
    foreach($e in @($ev)){
        $k=$null
        try { if($e.TargetObject -is [string]){ $k=[string]$e.TargetObject } } catch {}
        if(-not $k){ try { $k=[string]$e.OriginInfo.PSComputerName } catch {} }
        if($k -and -not $errs.ContainsKey($k)){ $errs[$k]=Get-FirstLine $e.Exception.Message }
    }
    foreach($b in $remote){
        if($res.ContainsKey([string]$b.Addr)){ Set-RecBoxState $b $res[[string]$b.Addr] }
        else { $b.Reachable=$false; $b.Encrypted=$null; $b.Detail="cannot connect: $(if($errs.ContainsKey([string]$b.Addr)){$errs[[string]$b.Addr]}else{'no answer'})" }
    }
}
function Update-BoxStates { param([object[]]$Boxes)
    $recs=@()
    foreach($b in @($Boxes)){
        if($b.Role -eq 'Management Server'){
            try {
                $r = & $script:BindingsSb
                $ms=@(([string]$r.Bindings) -split ',' | Where-Object { $_ -match ':900[01]$' })
                $b.Reachable=$true; $b.Encrypted=($ms.Count -gt 0); $b.Detail="bindings: $(if($r.Bindings){$r.Bindings}else{'none'})"
            } catch { $b.Reachable=$true; $b.Encrypted=$null; $b.Detail="netsh failed: $(Get-FirstLine $_.Exception.Message)" }
        } elseif($b.Role -eq 'Event Server'){
            try {
                $r = @(Invoke-OnBox -Computer $b.Addr -Cred $b.Cred -Sb $script:EsStateSb)[0]
                $b.Reachable=$true
                if(-not $r.Found){ $b.Encrypted=$null; $b.Detail="Event Server settings file not found ($($r.Path)) - is the Event Server installed on that computer?" }
                else { $b.Encrypted=($r.Value -eq 'true'); $b.Detail="CertificateEnabled=$($r.Value)" }
            } catch { $b.Reachable=$false; $b.Encrypted=$null; $b.Detail="cannot connect: $(Get-FirstLine $_.Exception.Message)" }
        } else { $recs+=$b }
    }
    if($recs.Count){ Update-RecorderStates $recs }
}
function Wait-Ui { param([int]$Seconds)
    $end=(Get-Date).AddSeconds($Seconds)
    while((Get-Date) -lt $end){ Start-Sleep -Milliseconds 250; [Windows.Forms.Application]::DoEvents() } }
# Re-read the real state until every box matches (services may still be restarting right after an apply).
function Confirm-BoxStates { param([object[]]$Boxes,[bool]$Want,[int]$Tries=4,[int]$DelaySec=15)
    for($i=1; $i -le $Tries; $i++){
        Update-BoxStates $Boxes
        foreach($b in @($Boxes)){ Write-Log "  real state [$($b.Role)] $($b.Name): $(Get-StateText $b) ($($b.Detail))" }
        $bad=@($Boxes | Where-Object { $_.Encrypted -ne $Want })
        if(-not $bad.Count){ return $true }
        if($i -lt $Tries){ Write-Log "  $($bad.Count) computer(s) not yet in the wanted state - checking again in ${DelaySec}s (attempt $i of $Tries)"; Wait-Ui $DelaySec }
    }
    $false
}
function Write-StateLog { param([string]$Title,[object[]]$Boxes)
    Write-Log "----- $Title -----"
    foreach($b in @($Boxes)){
        Write-Log (" {0,-18} {1,-30} {2,-26} {3}" -f $b.Role,$b.Name,(Get-StateText $b),$b.Detail) $(if(-not $b.Reachable -or $null -eq $b.Encrypted){'Err'}else{'Info'})
    }
}

# -- targets ----------------------------------------------------------------------------
# Validate the Connect page and derive credentials / names. Throws a plain-language message.
function Read-Inputs {
    $d=$script:DomainBox.Text.Trim()
    if(-not $d -or $d -match '<[^>]+>'){ throw 'Enter the DNS domain of these computers (for example company.local).' }
    $script:DomainName=Get-DomainSuffix $d
    $script:NoEs=[bool]$script:NoEsChk.Checked
    $e=$script:EsHostBox.Text.Trim()
    if(-not $script:NoEs -and (-not $e -or $e -match '<[^>]+>')){ throw "Enter the name of the Event Server computer, or tick 'There is no separate Event Server'." }
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
    [void](ConvertTo-SanList $script:MsExtraSans)   # validate early: an invalid SAN would only fail mid-run
}
# Build the box list: this Management Server, the Event Server (unless none), and the recorders
# (discovered from the VMS and/or listed by hand; 'name=address' allowed). Returns the discovery
# error text ('' when discovery worked or was not asked for).
function Initialize-Targets { param([string]$ManualList,[bool]$Discover)
    $script:MsBox = New-Box 'Management Server' $env:COMPUTERNAME $env:COMPUTERNAME $script:MsFqdn $script:AdminCred
    $script:EsBox = $null
    if(-not $script:NoEs){ $script:EsBox = New-Box 'Event Server' $script:EsAddr $script:EsAddr $script:EsAddr $script:AdminCred }
    $list=[System.Collections.Generic.List[object]]::new(); $seen=@{}
    $add={ param([string]$Name,[string]$Target,[string]$Addr)
        if((Test-LocalTarget $Addr) -or (Test-LocalTarget $Target)){ Write-Log "Recording server '$Name' runs on this Management Server - it is covered by the Management Server step, not handled separately."; return }
        $k=$Target.ToUpperInvariant(); if($seen.ContainsKey($k)){ return }; $seen[$k]=$true
        [void]$list.Add((New-Box 'Recording server' $Name $Target $Addr $script:RecCred)) }
    $discErr=''
    if($Discover){
        try { foreach($r in @(Get-VmsRecorderList -Domain $script:DomainName -VmsCred $script:AdminCred -MsAddrText $script:MsAddrValue)){ & $add $r.Name $r.Target $r.Fqdn } }
        catch { $discErr=Get-FirstLine $_.Exception.Message; Write-Log "Recording server discovery failed: $(Format-Err $_)" 'Err' }
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
    Write-Log "Computers: Management Server $env:COMPUTERNAME ($($script:MsFqdn)); Event Server $(if($script:EsBox){$script:EsAddr}else{'(none)'}); $($script:RecBoxes.Count) recording server(s)" 'Good'
    $discErr
}

# -- run bookkeeping ----------------------------------------------------------------------
function Add-GuidedRow { param($Box,[string]$Act,[bool]$Ok,[string]$Status,[string]$Err='')
    $now=Get-Date
    [void]$script:RunResults.Add([pscustomobject]@{
        HostKey=$Box.Target; Fqdn=$Box.Addr; Success=$Ok; Status="$($Box.Role): $Status"; Thumbprint=''
        Error=$Err; CertificateGroup=$(if($Box.Role -eq 'Event Server'){'Event Server'}else{'Server'}); Action=$Act
        Started=$now; Ended=$now; DurationSec=0.0 }) }
function Save-Report {
    Export-RunResults
    $txt = Get-ChildItem -LiteralPath $script:RunsDir -Filter 'run-*-results.txt' -ErrorAction SilentlyContinue |
           Where-Object { $_.LastWriteTime -ge $script:RunStart } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if($txt){
        $script:LastReportPath=$txt.FullName
        $logPath = $txt.FullName -replace '-results\.txt$','-log.txt'
        try { Set-Content -LiteralPath $logPath -Value $script:Log.Text -Encoding UTF8 } catch {}
    }
}
function Set-RunFailure { param([string]$Step,[string]$Who,[string]$Reason,[string]$Tech='',[string]$Next='')
    $script:RunFailure=[pscustomobject]@{ Step=$Step; Who=$Who; Reason=$Reason; Tech=$Tech; Next=$Next }
    Write-Log "STOPPED at step '$Step' ($Who): $Reason$(if($Tech){' | ' + $Tech})" 'Err'
}
# Map an engine status/error text to a sentence an operator can act on.
function Get-PlainReason { param([string]$Text)
    $t=[string]$Text
    if($t -match 'NOT REGISTERED'){ return 'The Event Server changed its own setting but could not register the change with the Management Server, so the two now disagree.' }
    if($t -match 'exit1\(|refused before applying'){ return 'ServerConfigurator on that computer refused the change, so nothing was changed there.' }
    if($t -match 'exit100\(|not authorized'){ return 'The account is not allowed to change Milestone settings. It must be a member of the Milestone Administrators role.' }
    if($t -match 'exit300000|exit100000'){ return 'The certificate was applied, but the server could not register with it (the certificate name may not match the server address).' }
    if($t -match 'WEDGE|cannot accept control messages|Unable to (?:stop|restart)'){ return 'A Milestone service on that computer was stuck and could not be restarted.' }
    if($t -match 'Access is denied|logon failure|user name or password|LogonUser failed'){ return 'The account or password was not accepted by that computer.' }
    if($t -match 'WinRM|cannot connect|Connecting to remote server|network path|could not reconnect'){ return 'Could not connect to that computer (it may be switched off, WinRM may be disabled, or a firewall blocks it).' }
    if($t -match 'No root CA|signer'){ return 'The signing CA (certificate authority) was not found on this computer.' }
    'The change did not take effect.'
}

# -- step list (page 3) ------------------------------------------------------------------
function Get-StageName { param([string]$Key) switch($Key){ 'ES' { 'Event Server' } 'MS' { 'Management Server' } default { 'Recording servers' } } }
function Reset-Stages { param([string[]]$Keys)
    $script:StageGrid.Rows.Clear(); $script:StageRows=@{}
    $n=1
    foreach($k in $Keys){
        $who = switch($k){ 'ES' { $script:EsAddr } 'MS' { "$env:COMPUTERNAME (this computer)" } default { "$(@($script:RecBoxes).Count) computer(s)" } }
        $idx=$script:StageGrid.Rows.Add("Step ${n}: $(Get-StageName $k)",$who,'Waiting')
        $script:StageRows[$k]=$script:StageGrid.Rows[$idx]; $n++
    }
    $script:StageGrid.ClearSelection(); $script:StageGrid.Refresh(); [Windows.Forms.Application]::DoEvents()
}
function Set-StageStatus { param([string]$Key,[string]$Text,[string]$Kind='Info')
    Write-Log "STEP $(Get-StageName $Key): $Text" $(if($Kind -eq 'Good'){'Good'}elseif($Kind -eq 'Bad'){'Err'}else{'Info'})
    if($script:StageRows.ContainsKey($Key)){
        $row=$script:StageRows[$Key]; $row.Cells['Status'].Value=$Text
        $row.DefaultCellStyle.BackColor = switch($Kind){ 'Good' { $script:ColGood } 'Bad' { $script:ColBad } 'Work' { $script:ColWork } 'Skip' { $script:ColOff } default { [Drawing.Color]::White } }
        $script:StageGrid.Refresh(); [Windows.Forms.Application]::DoEvents()
    }
}

# -- the three steps -----------------------------------------------------------------------
function Invoke-EsStage { param([bool]$Want)
    $es=$script:EsBox; $wt=$(if($Want){'ON'}else{'OFF'}); $act=$(if($Want){'on'}else{'off'})
    Set-StageStatus 'ES' 'Checking...' 'Work'
    Update-BoxStates @($es)
    if(-not $es.Reachable -or $null -eq $es.Encrypted){
        Set-StageStatus 'ES' 'FAILED - cannot read its state' 'Bad'; Add-GuidedRow $es $act $false 'cannot read state' $es.Detail
        Set-RunFailure 'Event Server' $es.Name "Could not read the Event Server's encryption state." $es.Detail; return $false }
    if($es.Encrypted -eq $Want){
        Write-Log "[$($es.Name)] Event Server already $wt - skipped" 'Good'; Add-GuidedRow $es $act $true "already $wt - skipped"
        Set-StageStatus 'ES' "Already $wt - skipped" 'Skip'; return $true }
    # Prerequisite (both directions): ServerConfigurator on the Event Server refuses while the MS is encrypted.
    Update-BoxStates @($script:MsBox)
    if($script:MsBox.Encrypted -ne $false){
        $why = if($script:MsBox.Encrypted){ 'The Management Server is encrypted. The Event Server can only be changed while the Management Server is NOT encrypted.' } else { "Could not read the Management Server's encryption state." }
        $next = if($Want -and $script:MsBox.Encrypted){ "Click 'Turn encryption OFF' and let it finish, then click 'Turn encryption ON'." } else { '' }
        Set-StageStatus 'ES' 'BLOCKED - wrong order' 'Bad'; Add-GuidedRow $es $act $false 'blocked by order check' $why
        Set-RunFailure 'Event Server' $es.Name $why $script:MsBox.Detail $next; return $false }
    Write-Log "ORDER CHECK: the Management Server is not encrypted - OK to turn the Event Server $wt" 'Good'
    if(Test-IpAddress $es.Addr){ Ensure-TrustedHosts -Hosts @($es.Addr) }
    Set-StageStatus 'ES' 'Working...' 'Work'
    $P=@{ Target=$es.Target; Fqdn=$es.Addr; Cred=$es.Cred; SignerTp=$script:SignerTp; CaCer=$script:CaCer; Domain=$script:DomainName; OutputDir=$script:OutputDir
          Guid=$script:CertGroupEvent; GroupName='Event Server'; Action=$(if($Want){'enable'}else{'disable'}); ExtraSans='' }
    $r = & $script:EsHostWorker $P
    Add-RunResult $r
    foreach($l in $r.Logs){ Write-Log "[$($r.Target)] $l" }
    Write-Log "[$($r.Target)] $(if($r.Ok){'OK'}else{'FAILED'}): $($r.Status)" $(if($r.Ok){'Good'}else{'Err'})
    $gt = Confirm-BoxStates @($es) $Want
    if($r.Ok -and $gt){ Set-StageStatus 'ES' "Done - encryption $wt" 'Good'; return $true }
    $reason = if($r.Ok){ "ServerConfigurator reported success, but the Event Server still reports: $(Get-StateText $es)." } else { Get-PlainReason "$($r.Status) $($r.Error)" }
    Set-StageStatus 'ES' 'FAILED' 'Bad'; Set-RunFailure 'Event Server' $es.Name $reason "$($r.Status) $($r.Error)"
    $false
}
function Invoke-MsStage { param([bool]$Want)
    $ms=$script:MsBox; $wt=$(if($Want){'ON'}else{'OFF'}); $act=$(if($Want){'on'}else{'off'})
    Set-StageStatus 'MS' 'Checking...' 'Work'
    Update-BoxStates @($ms)
    if($null -eq $ms.Encrypted){
        Set-StageStatus 'MS' 'FAILED - cannot read its state' 'Bad'; Add-GuidedRow $ms $act $false 'cannot read state' $ms.Detail
        Set-RunFailure 'Management Server' $ms.Name "Could not read this Management Server's encryption state." $ms.Detail; return $false }
    if($ms.Encrypted -eq $Want){
        Write-Log "[$($ms.Name)] Management Server already $wt - skipped" 'Good'; Add-GuidedRow $ms $act $true "already $wt - skipped"
        Set-StageStatus 'MS' "Already $wt - skipped" 'Skip'; return $true }
    if($Want -and $script:EsBox){
        Update-BoxStates @($script:EsBox)
        if($script:EsBox.Encrypted -ne $true){
            $why='The Event Server is not encrypted yet. It must be encrypted BEFORE the Management Server (afterwards it can no longer be changed).'
            Set-StageStatus 'MS' 'BLOCKED - wrong order' 'Bad'; Add-GuidedRow $ms $act $false 'blocked by order check' $why
            Set-RunFailure 'Management Server' $ms.Name $why $script:EsBox.Detail; return $false }
        Write-Log 'ORDER CHECK: the Event Server is encrypted - OK to encrypt the Management Server' 'Good'
    }
    Set-StageStatus 'MS' 'Preparing - waiting for the Management Server service to settle...' 'Work'
    [void](Wait-MsIdpReady -MsFqdn $script:MsFqdn -WantRunning:$Want)
    Set-StageStatus 'MS' 'Working...' 'Work'
    $P=@{ Target=$env:COMPUTERNAME; Fqdn=$script:MsFqdn; Cred=$script:AdminCred; SignerTp=$script:SignerTp; CaCer=$script:CaCer; Domain=$script:DomainName; OutputDir=$script:OutputDir
          Guids=$script:CertGroupServer; Names='Server (mgmt+recorder)'; Action=$(if($Want){'enable'}else{'disable'}); BindExpected=$true; GroupCount=1
          ExtraSans=$script:MsExtraSans }
    $r = & $script:HostWorker $P
    Add-RunResult $r
    foreach($l in $r.Logs){ Write-Log "[$($r.Target)] $l" }
    Write-Log "[$($r.Target)] $(if($r.Ok){'OK'}else{'FAILED'}): $($r.Status)" $(if($r.Ok){'Good'}else{'Err'})
    $gt = Confirm-BoxStates @($ms) $Want
    if($r.Ok -and $gt){ Set-StageStatus 'MS' "Done - encryption $wt" 'Good'; return $true }
    $reason = if($r.Ok){ "ServerConfigurator reported success, but this Management Server still reports: $(Get-StateText $ms)." } else { Get-PlainReason "$($r.Status) $($r.Error)" }
    Set-StageStatus 'MS' 'FAILED' 'Bad'; Set-RunFailure 'Management Server' $ms.Name $reason "$($r.Status) $($r.Error)"
    $false
}
function Invoke-RecStage { param([bool]$Want)
    $wt=$(if($Want){'ON'}else{'OFF'}); $act=$(if($Want){'on'}else{'off'})
    Set-StageStatus 'REC' 'Checking...' 'Work'
    $recs=@($script:RecBoxes | Where-Object { -not $_.Excluded })
    if(-not $recs.Count){ Set-StageStatus 'REC' $(if(@($script:RecBoxes).Count){'None reachable - left as they are'}else{'No recording servers to handle'}) 'Skip'; return $true }
    Update-BoxStates $recs
    $todo=@()
    foreach($b in $recs){
        if($b.Reachable -and $b.Encrypted -eq $Want){ Write-Log "[$($b.Name)] recording server already $wt - skipped" 'Good'; Add-GuidedRow $b $act $true "already $wt - skipped" }
        else { $todo+=$b }
    }
    if(-not $todo.Count){ Set-StageStatus 'REC' "All already $wt - skipped" 'Skip'; return $true }
    # Prerequisite: recorders only move to the state the Management Server is already in.
    Update-BoxStates @($script:MsBox)
    if($script:MsBox.Encrypted -ne $Want){
        $why = if($null -eq $script:MsBox.Encrypted){ "Could not read the Management Server's encryption state." }
               elseif($Want){ 'The Management Server is not encrypted. Recording servers can only be encrypted after the Management Server.' }
               else { 'The Management Server is still encrypted. Recording servers can only be decrypted after the Management Server.' }
        Set-StageStatus 'REC' 'BLOCKED - wrong order' 'Bad'
        foreach($b in $todo){ Add-GuidedRow $b $act $false 'blocked by order check' $why }
        Set-RunFailure 'Recording servers' "$($todo.Count) computer(s)" $why $script:MsBox.Detail; return $false }
    Write-Log "ORDER CHECK: the Management Server is $(if($Want){'encrypted'}else{'not encrypted'}) - OK to turn the recording servers $wt" 'Good'
    $ips=@($todo | Where-Object { Test-IpAddress $_.Addr } | ForEach-Object { [string]$_.Addr })
    if($ips.Count){ Ensure-TrustedHosts -Hosts $ips }
    Set-StageStatus 'REC' "Working on $($todo.Count) recording server(s)..." 'Work'
    $common=@{ Cred=$script:RecCred; SignerTp=$script:SignerTp; CaCer=$script:CaCer; Domain=$script:DomainName; OutputDir=$script:OutputDir
               Guids=$script:CertGroupServer; Names='Server (recorder)' }
    $results=@(Invoke-RecordersParallel -Boxes $todo -Action $(if($Want){'enable'}else{'disable'}) -Common $common -Throttle 32)
    [void](Confirm-BoxStates $todo $Want)
    $failed=@()
    foreach($b in $todo){
        $rr=@($results | Where-Object { [string]$_.Box.Addr -eq [string]$b.Addr } | Select-Object -First 1)
        $wok=($rr.Count -gt 0) -and [bool]$rr[0].Result.Ok
        if(-not ($wok -and $b.Encrypted -eq $Want)){
            $txt = if($rr.Count){ "$($rr[0].Result.Status) $($rr[0].Result.Error)" } else { 'no result' }
            $why = if($wok){ "ServerConfigurator reported success, but it still reports: $(Get-StateText $b)." } else { Get-PlainReason "$txt $($b.Detail)" }
            $failed += [pscustomobject]@{ Name=$b.Name; Why=$why; Tech=$txt }
        }
    }
    if(-not $failed.Count){ Set-StageStatus 'REC' "Done - $($todo.Count) recording server(s) $wt" 'Good'; return $true }
    Set-StageStatus 'REC' "FAILED on $($failed.Count) of $($todo.Count)" 'Bad'
    Set-RunFailure 'Recording servers' (($failed | ForEach-Object { $_.Name }) -join ', ') (($failed | ForEach-Object { "$($_.Name): $($_.Why)" }) -join "`r`n") (($failed | ForEach-Object { "$($_.Name): $($_.Tech)" }) -join ' || ')
    $false
}

# Full ON/OFF sequence in the lab-verified order, stopping at the first step whose real state is wrong.
function Invoke-GuidedRun { param([ValidateSet('on','off')][string]$Act)
    $want=($Act -eq 'on'); $wt=$Act.ToUpper()
    $script:RunFailure=$null; $script:SignerTp=''; $script:CaCer=''; $script:RunStart=Get-Date; $script:LastReportPath=''
    $keys = if($want){ @('ES','MS','REC') } else { @('MS','REC','ES') }
    if(-not $script:EsBox){ $keys=@($keys | Where-Object { $_ -ne 'ES' }) }
    Reset-Stages $keys
    Write-Log "========== TURN ENCRYPTION $wt ==========" 'Good'
    Write-Log "Order: $(@($keys | ForEach-Object { Get-StageName $_ }) -join ', then ')"
    $all=@(Get-AllBoxes)
    foreach($b in $all){ $b.Excluded=$false }
    Update-BoxStates $all
    Write-StateLog 'STATE BEFORE' $all
    $ok=$true
    try {
        if($script:EsBox -and (-not $script:EsBox.Reachable -or $null -eq $script:EsBox.Encrypted)){
            $ok=$false
            Add-GuidedRow $script:EsBox $Act $false 'cannot read state - nothing changed' $script:EsBox.Detail
            Set-RunFailure 'Before starting' $script:EsBox.Name "Could not read the Event Server's state, so nothing was changed. The Event Server must be reachable because it has to be handled in the right order." $script:EsBox.Detail 'Make sure the Event Server is switched on and reachable from this computer (WinRM), then try again.'
        } else {
            foreach($b in @($script:RecBoxes | Where-Object { -not $_.Reachable })){
                $b.Excluded=$true
                Write-Log "[$($b.Name)] cannot be reached - it will be left as it is" 'Err'
                Add-GuidedRow $b $Act $false 'not reachable - left as it is' $b.Detail
            }
            if($want -and @($all | Where-Object { -not $_.Excluded -and $_.Encrypted -ne $true }).Count){
                $script:SignerStoreRadio.Checked=$true
                try {
                    $signer=Resolve-Signer; Write-Log "Signer: $($signer.Subject) [$($signer.Thumbprint)]"
                    $script:SignerTp=$signer.Thumbprint
                    $script:CaCer=Join-Path $script:OutputDir 'MilestoneCA.cer'; Export-Certificate -Cert $signer -FilePath $script:CaCer -Type CERT -Force | Out-Null
                } catch {
                    $ok=$false
                    Set-RunFailure 'Before starting' 'Signing CA' "The signing CA '$($script:SignerSubjectBox.Text)' was not found on this computer, so nothing was changed." (Format-Err $_) 'Go back to step 1 and check the name of the signing CA. Create a new one only if encryption was never set up in this system.'
                }
            }
            foreach($k in $keys){
                if(-not $ok){ break }
                $res=@(switch($k){ 'ES' { Invoke-EsStage $want } 'MS' { Invoke-MsStage $want } default { Invoke-RecStage $want } })
                if(-not ($res.Count -and $res[-1] -eq $true)){ $ok=$false; break }
            }
        }
    } catch {
        $ok=$false
        Set-RunFailure 'Unexpected error' $env:COMPUTERNAME (Get-PlainReason (Format-Err $_)) (Format-Err $_)
    }
    $all=@(Get-AllBoxes); Update-BoxStates $all
    Write-StateLog "STATE AFTER (target: encryption $wt)" $all
    foreach($b in $all){ Add-GuidedRow $b 'final-state' ($b.Encrypted -eq $want) "final state $(Get-StateText $b) (target $wt)" $(if($b.Encrypted -ne $want){$b.Detail}else{''}) }
    $allMatch = (@($all | Where-Object { $_.Encrypted -ne $want }).Count -eq 0)
    if($ok -and -not $allMatch){
        $bad=@($all | Where-Object { $_.Encrypted -ne $want } | ForEach-Object { $_.Name })
        Set-RunFailure 'Final check' ($bad -join ', ') 'These computers are not in the wanted state (for example they could not be reached).' '' 'Make sure every computer is switched on and reachable, then run the same action again.'
    }
    $success = $ok -and $allMatch
    Write-Log "OVERALL: $(if($success){"encryption is $wt on every computer"}else{'NOT COMPLETE - see the message above'})" $(if($success){'Good'}else{'Err'})
    Save-Report
    $script:HasResult=$true
    [pscustomobject]@{ Success=$success; Want=$want; Failure=$script:RunFailure; Report=$script:LastReportPath }
}

# Plain-language outcome: what failed, the state of every computer, what to do next, report path.
function Get-OutcomeText { param($Res)
    $wt = if($Res.Want){'ON'}else{'OFF'}
    $lines = (@(Get-AllBoxes) | ForEach-Object { " - $($_.Role) $($_.Name): $(Get-StateText $_)" }) -join "`r`n"
    $rep = if($Res.Report){ $Res.Report } else { '(the report could not be written - see the details log)' }
    if($Res.Success){ return "Encryption is now $wt on every computer.`r`n`r`nCurrent state:`r`n$lines`r`n`r`nReport file:`r`n$rep" }
    $f=$Res.Failure
    $step = if($f){ "$($f.Step) ($($f.Who))" } else { '(unknown step)' }
    $why  = if($f){ $f.Reason } else { '' }
    $next = if($f -and $f.Next){ $f.Next } else { "Click 'Turn encryption $wt' again. If it fails again, send the report file to support." }
    "Encryption was NOT completed.`r`n`r`nWhat failed: $step`r`n$why`r`n`r`nCurrent state:`r`n$lines`r`n`r`nWhat to do next: $next`r`n`r`nReport file:`r`n$rep"
}

# -- wizard UI -------------------------------------------------------------------------------
$script:ColGood = [Drawing.Color]::FromArgb(198,239,206)
$script:ColOff  = [Drawing.Color]::FromArgb(226,232,240)
$script:ColBad  = [Drawing.Color]::FromArgb(255,199,206)
$script:ColWork = [Drawing.Color]::FromArgb(255,235,156)
$script:UiFont  = [Drawing.Font]::new('Segoe UI',11)
$script:UiBold  = [Drawing.Font]::new('Segoe UI',11,[Drawing.FontStyle]::Bold)

function New-UiLabel { param([string]$Text,[int]$X,[int]$Y,[int]$W=290,[int]$H=30)
    $l=[Windows.Forms.Label]::new(); $l.Text=$Text; $l.Location=[Drawing.Point]::new($X,$Y); $l.Size=[Drawing.Size]::new($W,$H); $l.TextAlign='MiddleLeft'; $l }
function New-UiText { param([int]$X,[int]$Y,[int]$W=320,[string]$Text='',[bool]$Pw=$false)
    $b=[Windows.Forms.TextBox]::new(); $b.Location=[Drawing.Point]::new($X,$Y); $b.Width=$W; $b.Text=$Text; if($Pw){$b.UseSystemPasswordChar=$true}; $b }
function New-UiButton { param([string]$Text,[int]$X,[int]$Y,[int]$W=180,[int]$H=36)
    $b=[Windows.Forms.Button]::new(); $b.Text=$Text; $b.Location=[Drawing.Point]::new($X,$Y); $b.Size=[Drawing.Size]::new($W,$H); $b }
function New-UiCheck { param([string]$Text,[int]$X,[int]$Y,[int]$W=560)
    $c=[Windows.Forms.CheckBox]::new(); $c.Text=$Text; $c.Location=[Drawing.Point]::new($X,$Y); $c.Size=[Drawing.Size]::new($W,30); $c }
function New-StateGrid { param([int]$X,[int]$Y,[int]$W,[int]$H)
    $g=[Windows.Forms.DataGridView]::new(); $g.Location=[Drawing.Point]::new($X,$Y); $g.Size=[Drawing.Size]::new($W,$H); $g.Anchor='Top,Bottom,Left,Right'
    $g.AllowUserToAddRows=$false; $g.AllowUserToDeleteRows=$false; $g.RowHeadersVisible=$false; $g.ReadOnly=$true; $g.SelectionMode='FullRowSelect'
    $g.BackgroundColor=[Drawing.Color]::White; $g.RowTemplate.Height=30; $g.ColumnHeadersHeight=34
    foreach($c in @(@('Name','Computer',210),@('Role','Role',170),@('Reach','Reachable',100),@('State','Encryption',190),@('Detail','Details',400))){
        $col=[Windows.Forms.DataGridViewTextBoxColumn]::new(); $col.Name=$c[0]; $col.HeaderText=$c[1]; $col.Width=$c[2]; $col.SortMode='NotSortable'
        [void]$g.Columns.Add($col) }
    $g.Columns['Detail'].AutoSizeMode='Fill'
    $g }
function Show-StateGrid { param($Grid,[object[]]$Boxes)
    $Grid.Rows.Clear()
    foreach($b in @($Boxes)){
        $idx=$Grid.Rows.Add($b.Name,$b.Role,$(if($b.Reachable){'Yes'}else{'No'}),(Get-StateText $b),$b.Detail)
        $row=$Grid.Rows[$idx]
        $row.Cells['Reach'].Style.BackColor = if($b.Reachable){ $script:ColGood } else { $script:ColBad }
        $row.Cells['State'].Style.BackColor = if(-not $b.Reachable -or $null -eq $b.Encrypted){ $script:ColBad } elseif($b.Encrypted){ $script:ColGood } else { $script:ColOff }
    }
    $Grid.ClearSelection()
}
function Get-StateSummary { param([object[]]$Boxes)
    $a=@($Boxes)
    $on=@($a | Where-Object { $_.Encrypted -eq $true }).Count; $off=@($a | Where-Object { $_.Encrypted -eq $false }).Count
    "$($a.Count) computer(s): $on encrypted, $off not encrypted, $($a.Count - $on - $off) unknown." }

function Update-CaStatus {
    $s=$script:SignerSubjectBox.Text.Trim()
    if(-not $s -or $s -match '<[^>]+>'){ $script:CaStatus.Text='Type the name (subject) of your signing CA, for example: CN=Company VMS CA'; $script:CaStatus.ForeColor=[Drawing.Color]::DarkRed; return $null }
    try { $ca=@(Find-ExistingCa $s) } catch { $script:CaStatus.Text="Not a valid CA name: $($_.Exception.Message)"; $script:CaStatus.ForeColor=[Drawing.Color]::DarkRed; return $null }
    if($ca.Count){ $script:CaStatus.Text="Found on this computer: $($ca[0].Subject)  (valid until $($ca[0].NotAfter.ToString('yyyy-MM-dd')))"; $script:CaStatus.ForeColor=[Drawing.Color]::DarkGreen; return $ca[0] }
    $script:CaStatus.Text="Not found on this computer. It is needed only to turn encryption ON. If encryption was never set up, click 'Create signing CA'."
    $script:CaStatus.ForeColor=[Drawing.Color]::DarkOrange
    $null
}
# Adapted from the role GUIs' 'Create root CA' button (same duplicate-name guard, same New-RootCa).
function New-SigningCaInteractive {
    try {
        $subj=$script:SignerSubjectBox.Text.Trim(); if(-not $subj -or $subj -match '<[^>]+>'){ throw 'Type a name for the new CA first, for example: CN=Company VMS CA, O=Company' }
        $cn=Get-CaSubjectCn $subj
        $dup=@(Find-ExistingCa $subj)   # @(): function return unwraps; null otherwise (StrictMode Count crash)
        if($dup.Count){
            $msg="A CA named 'CN=$cn' already exists on this computer (thumbprint $($dup[0].Thumbprint.Substring(0,8))...). It will be used - there is no need to create another one.`n`nCreating ANOTHER CA with the same name changes the trust anchor and can BREAK servers that are already encrypted (IDP returns 403 -> services stop).`n`nCreate a duplicate anyway?"
            if([Windows.Forms.MessageBox]::Show($msg,'CA already exists',4,'Warning') -ne 'Yes'){ Write-Log "Create signing CA cancelled (CN=$cn already exists; using existing)."; [void](Update-CaStatus); return }
        } elseif([Windows.Forms.MessageBox]::Show("Create a new signing CA '$subj' on this computer?`n`nDo this only if encryption has never been set up in this system. If the servers were encrypted before, use the CA that was used then.",'Create signing CA',4,'Question') -ne 'Yes'){ return }
        $ca=New-RootCa -Subject $subj -OutputDir $script:OutputDir
        Write-Log "Created self-signed root CA $($ca.Subject) [$($ca.Thumbprint)] in CurrentUser\My; public cert exported to $script:OutputDir" 'Good'
        [void](Update-CaStatus)
        [Windows.Forms.MessageBox]::Show("Signing CA created:`n`n$($ca.Subject)`nThumbprint: $($ca.Thumbprint)",'Signing CA',0,'Information')|Out-Null
    } catch { Write-Log "Create signing CA failed: $(Format-Err $_)" 'Err'; [Windows.Forms.MessageBox]::Show("Could not create the signing CA:`n$($_.Exception.Message)",'Error',0,'Error')|Out-Null }
}

$script:PageTitles = @('Connect','Check','Action','Result')
function Show-Page { param([int]$N)
    $script:Page=$N
    for($i=0; $i -lt $script:Pages.Count; $i++){ $script:Pages[$i].Visible = (($i+1) -eq $N) }
    $script:StepLabel.Text = "Step $N of 4:  $($script:PageTitles[$N-1])"
    $script:BackBtn.Enabled = ($N -gt 1)
    $script:NextBtn.Text = if($N -eq 4){ 'Close' } else { 'Next >' }
    $script:NextBtn.Enabled = if($N -eq 3){ $script:HasResult } else { $true }
}
function Do-Connect {
    try { Read-Inputs } catch { [Windows.Forms.MessageBox]::Show($_.Exception.Message,'Missing information',0,'Warning')|Out-Null; return }
    Set-Busy $true
    try {
        $script:ConnectStatus.Text='Looking for the recording servers and checking every computer. Please wait...'; [Windows.Forms.Application]::DoEvents()
        $err = Initialize-Targets -ManualList $script:ManualRecBox.Text -Discover $true
        if($err -and -not $script:ManualRecBox.Text.Trim()){
            $q="The recording servers could not be found automatically:`r`n$err`r`n`r`nYou can type them in the 'Extra recording servers' box instead.`r`n`r`nContinue WITHOUT recording servers?"
            if([Windows.Forms.MessageBox]::Show($q,'Recording servers not found',4,'Warning') -ne 'Yes'){ return }
        }
        $all=@(Get-AllBoxes); Update-BoxStates $all
        Show-StateGrid $script:CheckGrid $all; $script:CheckSummary.Text=Get-StateSummary $all
        Write-StateLog 'CURRENT STATE' $all
        $script:Page=2
    } catch {
        Write-Log "Check failed: $(Format-Err $_)" 'Err'
        [Windows.Forms.MessageBox]::Show("Could not check the computers:`r`n$(Get-FirstLine $_.Exception.Message)",'Error',0,'Error')|Out-Null
    } finally { $script:ConnectStatus.Text=''; Set-Busy $false; Show-Page $script:Page }
}
function Do-Recheck {
    Set-Busy $true
    try { $all=@(Get-AllBoxes); Update-BoxStates $all; Show-StateGrid $script:CheckGrid $all; $script:CheckSummary.Text=Get-StateSummary $all; Write-StateLog 'CURRENT STATE' $all }
    catch { Write-Log "Check failed: $(Format-Err $_)" 'Err' }
    finally { Set-Busy $false; Show-Page $script:Page }
}
function Start-GuidedAction { param([ValidateSet('on','off')][string]$Act)
    $wt=$Act.ToUpper()
    $q="Turn encryption $wt for the whole system?`r`n`r`nMilestone services on the servers will restart. Video and clients can be interrupted for several minutes - use a maintenance window."
    if([Windows.Forms.MessageBox]::Show($q,'Please confirm',4,'Question') -ne 'Yes'){ return }
    Set-Busy $true
    try {
        Update-RecorderStates @($script:RecBoxes)
        $un=@($script:RecBoxes | Where-Object { -not $_.Reachable })
        if($un.Count){
            $q2="These recording servers cannot be reached:`r`n$((@($un | ForEach-Object { ' - ' + $_.Name }) -join "`r`n"))`r`n`r`nThey will be left as they are, and the result will show 'not complete'. Continue anyway?"
            if([Windows.Forms.MessageBox]::Show($q2,'Some computers cannot be reached',4,'Warning',[Windows.Forms.MessageBoxDefaultButton]::Button2) -ne 'Yes'){ return }
        }
        $script:BusyLabel.Visible=$true; [Windows.Forms.Application]::DoEvents()
        $res=@(Invoke-GuidedRun $Act)[-1]
        $script:LastOutcome=$res
        $all=@(Get-AllBoxes)
        Show-StateGrid $script:FinalGrid $all; Show-StateGrid $script:CheckGrid $all; $script:CheckSummary.Text=Get-StateSummary $all
        $script:ResultLabel.Text = if($res.Success){ "Done. Encryption is $wt on every computer." } else { "NOT complete. Encryption could not be turned $wt everywhere - see the message and the table below." }
        $script:ResultLabel.ForeColor = if($res.Success){ [Drawing.Color]::DarkGreen } else { [Drawing.Color]::DarkRed }
        $script:ReportBox.Text = $res.Report
        $script:BusyLabel.Visible=$false
        [Windows.Forms.MessageBox]::Show((Get-OutcomeText $res),$(if($res.Success){'Finished'}else{'Encryption NOT completed'}),0,$(if($res.Success){'Information'}else{'Error'}))|Out-Null
        $script:Page=4
    } catch {
        Write-Log "Run failed: $(Format-Err $_)" 'Err'
        [Windows.Forms.MessageBox]::Show("Unexpected error:`r`n$(Get-FirstLine $_.Exception.Message)`r`n`r`nSee 'Show details' on this page.",'Error',0,'Error')|Out-Null
    } finally { $script:BusyLabel.Visible=$false; Set-Busy $false; Show-Page $script:Page }
}

$script:Form=[Windows.Forms.Form]::new()
$script:Form.Text='Milestone Encryption - Guided'
$script:Form.StartPosition='CenterScreen'; $script:Form.Font=$script:UiFont
$script:Form.ClientSize=[Drawing.Size]::new(1000,760); $script:Form.MinimumSize=[Drawing.Size]::new(900,640)

# Layout: Fill child FIRST, then Top and Bottom (WinForms docks in reverse z-order).
$script:Content=[Windows.Forms.Panel]::new(); $script:Content.Size=[Drawing.Size]::new(1000,622); $script:Content.Dock='Fill'
$script:Header=[Windows.Forms.Panel]::new(); $script:Header.Size=[Drawing.Size]::new(1000,74); $script:Header.Dock='Top'; $script:Header.BackColor=[Drawing.Color]::FromArgb(32,56,100)
$script:Nav=[Windows.Forms.Panel]::new(); $script:Nav.Size=[Drawing.Size]::new(1000,64); $script:Nav.Dock='Bottom'
$script:Form.Controls.Add($script:Content); $script:Form.Controls.Add($script:Header); $script:Form.Controls.Add($script:Nav)

$hdrTitle=New-UiLabel 'Milestone XProtect - turn encryption ON or OFF' 20 6 900 34; $hdrTitle.Font=[Drawing.Font]::new('Segoe UI',15,[Drawing.FontStyle]::Bold); $hdrTitle.ForeColor=[Drawing.Color]::White
$script:StepLabel=New-UiLabel '' 22 40 900 28; $script:StepLabel.ForeColor=[Drawing.Color]::White
$script:Header.Controls.Add($hdrTitle); $script:Header.Controls.Add($script:StepLabel)

$script:BackBtn=New-UiButton '< Back' 610 12 170 40; $script:BackBtn.Anchor='Top,Right'
$script:NextBtn=New-UiButton 'Next >' 800 12 170 40; $script:NextBtn.Anchor='Top,Right'; $script:NextBtn.Font=$script:UiBold
$script:Nav.Controls.Add($script:BackBtn); $script:Nav.Controls.Add($script:NextBtn)

$script:Pages=@()
for($i=0; $i -lt 4; $i++){
    $pg=[Windows.Forms.Panel]::new(); $pg.Size=[Drawing.Size]::new(1000,622); $pg.Dock='Fill'; $pg.AutoScroll=$true; $pg.Visible=($i -eq 0)
    $script:Content.Controls.Add($pg); $script:Pages+=$pg
}

# ---- page 1: Connect ----
$p1=$script:Pages[0]
$domainPrefill = if($Domain){ $Domain } else { '' }
if(-not $domainPrefill){ try { $domainPrefill = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName } catch {} }
if(-not $domainPrefill -and [string]$script:Defaults.Domain -notmatch '<[^>]+>'){ $domainPrefill=[string]$script:Defaults.Domain }
$clearPh = { param([string]$v) if([string]$v -match '<[^>]+>'){ '' } else { [string]$v } }
$intro1=New-UiLabel 'Fill in the details and click Next. Nothing is changed until you choose an action in step 3.' 24 10 950 36
$p1.Controls.Add($intro1)
$p1.Controls.Add((New-UiLabel 'This computer (Management Server):' 24 56))
$msShow=New-UiText 320 58 320 $env:COMPUTERNAME; $msShow.ReadOnly=$true; $msShow.TabStop=$false; $p1.Controls.Add($msShow)
$p1.Controls.Add((New-UiLabel 'DNS domain of these computers:' 24 94))
$script:DomainBox=New-UiText 320 96 320 $domainPrefill; $p1.Controls.Add($script:DomainBox)
$p1.Controls.Add((New-UiLabel 'for example company.local' 656 94 320))
$p1.Controls.Add((New-UiLabel 'Event Server computer:' 24 132))
$script:EsHostBox=New-UiText 320 134 320 (& $clearPh $EsHost); $p1.Controls.Add($script:EsHostBox)
$p1.Controls.Add((New-UiLabel 'its name or IP address' 656 132 320))
$script:NoEsChk=New-UiCheck 'There is no separate Event Server' 320 168; $script:NoEsChk.Checked=[bool]$NoEventServer; $p1.Controls.Add($script:NoEsChk)
$script:NoEsChk.Add_CheckedChanged({ $script:EsHostBox.Enabled = -not $script:NoEsChk.Checked })
$script:EsHostBox.Enabled = -not $script:NoEsChk.Checked
$p1.Controls.Add((New-UiLabel 'Admin account:' 24 204))
$script:AdminUserBox=New-UiText 320 206 320 (& $clearPh $AdminUser); $p1.Controls.Add($script:AdminUserBox)
$p1.Controls.Add((New-UiLabel 'for example COMPANY\Administrator' 656 204 320))
$p1.Controls.Add((New-UiLabel 'Admin password:' 24 242))
$script:AdminPwBox=New-UiText 320 244 320 '' $true; $p1.Controls.Add($script:AdminPwBox)
$script:RecSepChk=New-UiCheck 'Recording servers use a different account' 320 278; $p1.Controls.Add($script:RecSepChk)
$p1.Controls.Add((New-UiLabel 'Recording server account:' 24 314))
$script:RecUserBox=New-UiText 320 316 320 (& $clearPh $RecUser); $p1.Controls.Add($script:RecUserBox)
$p1.Controls.Add((New-UiLabel 'Recording server password:' 24 352))
$script:RecPwBox=New-UiText 320 354 320 '' $true; $p1.Controls.Add($script:RecPwBox)
$script:RecUserBox.Enabled=$false; $script:RecPwBox.Enabled=$false
$script:RecSepChk.Add_CheckedChanged({ $script:RecUserBox.Enabled=$script:RecSepChk.Checked; $script:RecPwBox.Enabled=$script:RecSepChk.Checked })
$p1.Controls.Add((New-UiLabel 'Signing CA (certificate authority):' 24 392))
$script:SignerSubjectBox=New-UiText 320 394 320 (& $clearPh $RootSubject); $p1.Controls.Add($script:SignerSubjectBox)
$findCaBtn=New-UiButton 'Look again' 656 390 130; $p1.Controls.Add($findCaBtn); $findCaBtn.Add_Click({ [void](Update-CaStatus) })
$createCaBtn=New-UiButton 'Create signing CA' 796 390 180; $p1.Controls.Add($createCaBtn); $createCaBtn.Add_Click({ New-SigningCaInteractive })
$script:CaStatus=New-UiLabel '' 320 428 656 30; $p1.Controls.Add($script:CaStatus)
$recLbl=New-UiLabel 'Extra recording servers (optional, one per line):' 24 466 290 56; $recLbl.TextAlign='TopLeft'; $p1.Controls.Add($recLbl)
$script:ManualRecBox=[Windows.Forms.TextBox]::new(); $script:ManualRecBox.Multiline=$true; $script:ManualRecBox.ScrollBars='Vertical'
$script:ManualRecBox.Location=[Drawing.Point]::new(320,466); $script:ManualRecBox.Size=[Drawing.Size]::new(320,60); $p1.Controls.Add($script:ManualRecBox)
$recHint=New-UiLabel 'Recording servers are found automatically. Add them here only if they are missing.' 656 466 320 60; $recHint.TextAlign='TopLeft'; $p1.Controls.Add($recHint)
$script:ConnectStatus=New-UiLabel '' 24 540 950 30; $script:ConnectStatus.Font=$script:UiBold; $script:ConnectStatus.ForeColor=[Drawing.Color]::DarkOrange; $p1.Controls.Add($script:ConnectStatus)
# Resolve-Signer (verbatim) reads these: store mode only in the wizard; the PFX controls are never shown.
$script:SignerStoreRadio=[Windows.Forms.RadioButton]::new(); $script:SignerStoreRadio.Checked=$true
$script:SignerPfxRadio=[Windows.Forms.RadioButton]::new()
$script:SignerPfxBox=[Windows.Forms.TextBox]::new(); $script:SignerPwBox=[Windows.Forms.TextBox]::new()

# ---- page 2: Check ----
$p2=$script:Pages[1]
$p2.Controls.Add((New-UiLabel 'This is the current state of every computer. Nothing has been changed yet.' 24 10 950 34))
$script:CheckGrid=New-StateGrid 24 50 950 440; $p2.Controls.Add($script:CheckGrid)
$script:CheckSummary=New-UiLabel '' 24 500 720 30; $script:CheckSummary.Anchor='Bottom,Left'; $script:CheckSummary.Font=$script:UiBold; $p2.Controls.Add($script:CheckSummary)
$recheckBtn=New-UiButton 'Check again' 794 498 180; $recheckBtn.Anchor='Bottom,Right'; $p2.Controls.Add($recheckBtn); $recheckBtn.Add_Click({ Do-Recheck })
$legend=New-UiLabel 'Green = encrypted.   Grey = not encrypted.   Red = unknown (cannot connect).' 24 540 950 30; $legend.Anchor='Bottom,Left'; $p2.Controls.Add($legend)

# ---- page 3: Action ----
$p3=$script:Pages[2]
$intro3=New-UiLabel 'Choose what to do. The steps run automatically in the safe order, and each step is checked before the next one starts.' 24 8 950 44; $intro3.TextAlign='TopLeft'; $p3.Controls.Add($intro3)
$onBtn=New-UiButton 'Turn encryption ON' 24 56 460 64; $onBtn.Font=[Drawing.Font]::new('Segoe UI',14,[Drawing.FontStyle]::Bold); $onBtn.BackColor=[Drawing.Color]::FromArgb(46,125,50); $onBtn.ForeColor=[Drawing.Color]::White; $onBtn.FlatStyle='Flat'
$offBtn=New-UiButton 'Turn encryption OFF' 514 56 460 64; $offBtn.Font=[Drawing.Font]::new('Segoe UI',14,[Drawing.FontStyle]::Bold); $offBtn.BackColor=[Drawing.Color]::FromArgb(84,110,122); $offBtn.ForeColor=[Drawing.Color]::White; $offBtn.FlatStyle='Flat'
$p3.Controls.Add($onBtn); $p3.Controls.Add($offBtn)
$onBtn.Add_Click({ Start-GuidedAction 'on' }); $offBtn.Add_Click({ Start-GuidedAction 'off' })
$order3=New-UiLabel "ON order: Event Server, then Management Server, then recording servers.`r`nOFF order: Management Server, then recording servers, then Event Server." 24 128 950 50; $order3.TextAlign='TopLeft'; $p3.Controls.Add($order3)
$script:StageGrid=[Windows.Forms.DataGridView]::new(); $script:StageGrid.Location=[Drawing.Point]::new(24,182); $script:StageGrid.Size=[Drawing.Size]::new(950,130); $script:StageGrid.Anchor='Top,Left,Right'
$script:StageGrid.AllowUserToAddRows=$false; $script:StageGrid.AllowUserToDeleteRows=$false; $script:StageGrid.RowHeadersVisible=$false; $script:StageGrid.ReadOnly=$true
$script:StageGrid.BackgroundColor=[Drawing.Color]::White; $script:StageGrid.RowTemplate.Height=30; $script:StageGrid.ColumnHeadersHeight=34
foreach($c in @(@('Step','Step',260),@('Who','Computers',280),@('Status','Status',400))){
    $col=[Windows.Forms.DataGridViewTextBoxColumn]::new(); $col.Name=$c[0]; $col.HeaderText=$c[1]; $col.Width=$c[2]; $col.SortMode='NotSortable'; [void]$script:StageGrid.Columns.Add($col) }
$script:StageGrid.Columns['Status'].AutoSizeMode='Fill'
$p3.Controls.Add($script:StageGrid)
$script:BusyLabel=New-UiLabel 'Working - this can take several minutes. The window may stop responding while a server restarts. Please wait and do not close it.' 24 318 950 50
$script:BusyLabel.TextAlign='TopLeft'; $script:BusyLabel.Font=$script:UiBold; $script:BusyLabel.ForeColor=[Drawing.Color]::DarkOrange; $script:BusyLabel.Visible=$false; $p3.Controls.Add($script:BusyLabel)
$detailsBtn=New-UiButton 'Show details' 24 372 180 34; $p3.Controls.Add($detailsBtn)
$script:Log=[Windows.Forms.RichTextBox]::new(); $script:Log.Location=[Drawing.Point]::new(24,412); $script:Log.Size=[Drawing.Size]::new(950,200); $script:Log.ReadOnly=$true
$script:Log.Anchor='Top,Bottom,Left,Right'; $script:Log.Font=[Drawing.Font]::new('Consolas',9); $script:Log.Visible=$false; $p3.Controls.Add($script:Log)
$detailsBtn.Add_Click({ $script:Log.Visible = -not $script:Log.Visible; $this.Text = if($script:Log.Visible){'Hide details'}else{'Show details'} })

# ---- page 4: Result ----
$p4=$script:Pages[3]
$script:ResultLabel=New-UiLabel '' 24 10 950 60; $script:ResultLabel.Font=[Drawing.Font]::new('Segoe UI',14,[Drawing.FontStyle]::Bold); $script:ResultLabel.TextAlign='TopLeft'; $p4.Controls.Add($script:ResultLabel)
$script:FinalGrid=New-StateGrid 24 76 950 380; $p4.Controls.Add($script:FinalGrid)
$repLbl=New-UiLabel 'Report file:' 24 468 120; $repLbl.Anchor='Bottom,Left'; $p4.Controls.Add($repLbl)
$script:ReportBox=New-UiText 150 470 620 ''; $script:ReportBox.ReadOnly=$true; $script:ReportBox.Anchor='Bottom,Left,Right'; $p4.Controls.Add($script:ReportBox)
$openBtn=New-UiButton 'Open report folder' 780 466 194; $openBtn.Anchor='Bottom,Right'; $p4.Controls.Add($openBtn)
$openBtn.Add_Click({ if($script:ReportBox.Text -and (Test-Path -LiteralPath $script:ReportBox.Text)){ Start-Process explorer.exe -ArgumentList "/select,`"$($script:ReportBox.Text)`"" } elseif(Test-Path -LiteralPath $script:RunsDir){ Start-Process explorer.exe -ArgumentList "`"$($script:RunsDir)`"" } })
$repHint=New-UiLabel 'Keep this file. If something failed, send it (and the -log.txt file next to it) to support.' 24 508 950 30; $repHint.Anchor='Bottom,Left'; $p4.Controls.Add($repHint)

$script:BackBtn.Add_Click({ if($script:Page -gt 1){ Show-Page ($script:Page - 1) } })
$script:NextBtn.Add_Click({ switch($script:Page){ 1 { Do-Connect } 2 { Show-Page 3 } 3 { Show-Page 4 } default { $script:Form.Close() } } })

$script:BusyCtrls=@($script:BackBtn,$script:NextBtn,$onBtn,$offBtn,$recheckBtn,$findCaBtn,$createCaBtn)

# DPI autoscale, set AFTER all controls exist: the layout is authored at 96 dpi and scaled uniformly.
$script:Form.AutoScaleDimensions=[Drawing.SizeF]::new(96,96); $script:Form.AutoScaleMode='Dpi'
$script:Form.Add_Shown({
    $wa=[Windows.Forms.Screen]::FromControl($script:Form).WorkingArea
    if($script:Form.Height -gt $wa.Height){ $script:Form.Height=$wa.Height }
    # DataGridView columns are NOT covered by WinForms autoscaling - scale them by the same factor.
    $f=$script:Form.CurrentAutoScaleDimensions.Width/96
    if($f -gt 1.01){ foreach($g in @($script:CheckGrid,$script:FinalGrid,$script:StageGrid)){ foreach($c in $g.Columns){ $c.Width=[int]($c.Width*$f) } } }
})

$script:MsExtraSans = [string]$ExtraSans
$script:MsAddrValue = [string]$MsAddr
$script:Page = 1
Show-Page 1
Write-Log "Output dir: $script:OutputDir" 'Good'
if($script:DefaultsLoadError){ Write-Log "WARNING: mrc.defaults.psd1 failed to parse: $script:DefaultsLoadError - using built-in placeholders" 'Err' }
elseif($script:DefaultsLoaded.Count){ Write-Log "Loaded defaults from mrc.defaults.psd1: $($script:DefaultsLoaded -join ', ')" }
Write-Log "Management Server: $env:COMPUTERNAME (local). Order ON = Event Server, MS, recorders; OFF = MS, recorders, Event Server."

if($script:Headless){
    try {
        if([string]::IsNullOrWhiteSpace($AdminPwFile) -or -not (Test-Path -LiteralPath $AdminPwFile)){ Write-Log "REFUSED: -AdminPwFile not found: $AdminPwFile" 'Err'; exit 3 }
        $script:AdminPwBox.Text   = (Get-Content -Raw -LiteralPath $AdminPwFile).Trim()
        $script:AdminUserBox.Text = $AdminUser
        $script:NoEsChk.Checked   = [bool]$NoEventServer
        $script:EsHostBox.Text    = $(if($NoEventServer){ '' } else { $EsHost })
        if($RecPwFile){
            if(-not (Test-Path -LiteralPath $RecPwFile)){ Write-Log "REFUSED: -RecPwFile not found: $RecPwFile" 'Err'; exit 3 }
            if([string]::IsNullOrWhiteSpace($RecUser)){ Write-Log 'REFUSED: -RecPwFile given without -RecUser' 'Err'; exit 3 }
            $script:RecSepChk.Checked=$true; $script:RecUserBox.Text=$RecUser; $script:RecPwBox.Text=(Get-Content -Raw -LiteralPath $RecPwFile).Trim()
        }
        $script:SignerSubjectBox.Text=$RootSubject; $script:RootSubjectForRun=$RootSubject
        try { Read-Inputs } catch { Write-Log "REFUSED: $($_.Exception.Message)" 'Err'; exit 3 }
        $discover = [string]::IsNullOrWhiteSpace($RecTargets)
        $err = Initialize-Targets -ManualList $RecTargets -Discover $discover
        if($err -and $discover){ Write-Log "REFUSED: the recording servers could not be discovered ($err). Pass -RecTargets to list them." 'Err'; exit 3 }
        if($Action -eq 'status'){
            $script:RunStart=Get-Date
            $all=@(Get-AllBoxes); Update-BoxStates $all
            Write-StateLog 'CURRENT STATE' $all
            foreach($b in $all){ Add-GuidedRow $b 'status' ([bool]$b.Reachable -and $null -ne $b.Encrypted) "state $(Get-StateText $b)" $b.Detail }
            $allOk = (@($all | Where-Object { -not $_.Reachable -or $null -eq $_.Encrypted }).Count -eq 0)
            Write-Log "OVERALL: $(if($allOk){'every computer reachable'}else{'some computers could not be read'})" $(if($allOk){'Good'}else{'Err'})
            Save-Report
            if($script:LastReportPath){ Write-Log "Report: $script:LastReportPath" 'Good' }
            exit ([int](-not $allOk))
        }
        $res=@(Invoke-GuidedRun $Action)[-1]
        foreach($l in ((Get-OutcomeText $res) -split "`r`n")){ Write-Log $l $(if($res.Success){'Good'}else{'Err'}) }
        exit ([int](-not $res.Success))
    } catch { Write-Log "GUIDED FATAL: $(Format-Err $_)" 'Err'; exit 2 }
} else {
    [void](Update-CaStatus)
    [void]$script:Form.ShowDialog()
}
