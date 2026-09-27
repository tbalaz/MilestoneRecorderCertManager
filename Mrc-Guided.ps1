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

    WINDOWS FAILOVER CLUSTERS (WSFC, plain 'Generic Service' roles - not the Milestone Failover add-on):
    If the Management Server service (on this computer) or the Event Server service (on the Event
    Server host, over WinRM) is a Generic Service resource of a cluster role, that role is handled
    node by node. Without the FailoverClusters module or the cluster service the computer is treated
    as a single server, exactly as before.
        - One certificate per clustered role: CN = the address the component is registered under
          (Management Server: the cluster Network Name; Event Server: the host entered in step 1),
          SANs = cluster name (FQDN + short) + every node (FQDN + short) (+ ExtraSans for the MS).
          The same PFX is imported on every node; the account the Milestone service runs as gets
          Read on the private key when it is not NETWORK SERVICE / LocalSystem.
        - Per node, the node that owns the role now LAST (only nodes that may own the role):
          Event Server: move the role to the node, pause the nodes, run ServerConfigurator, resume.
          Management Server: stop the role's services, move only the cluster address to the node,
          pause the nodes, run ServerConfigurator against the stopped service (it starts it
          again), resume, start the role's resources. The MS role is only ever moved onto the node
          registered last, and every move is awaited until the cluster reports it finished.
          Then wait for the service (MS :9000 or :80, ES :22331) and read that node's real state.
          The role ends on the node that had it.
        - Real state is read per node; the Check and Result tables show one row per node.
        - Known Milestone limitation (reported, not fixed): each ServerConfigurator run on a
          Management Server node leaves the OTHER MS nodes unable to start the Management Server
          after a failover (IDP 'invalid_client') until they are registered again. The wizard's
          'Re-register this node' action (headless -Action register) does that on the node it runs on.
        - Optional failover self-test after a change (move each role to every other node and back).
    Before every on/off run a JSON snapshot of the real state is written next to the report; a failed
    run offers 'Undo this run (roll back)' (headless -Action rollback -Snapshot <file>).
    Every change (on/off/register/rollback) is preceded by a pre-flight check; if it fails, nothing
    is changed.

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
    -Action on|off|status|register|rollback. -NoEventServer instead of -EsHost when there is no
    standalone Event Server. Without -RecTargets the recording servers are discovered from the VMS
    (-MsAddr, default this machine; needs MilestonePSTools). -TestFailover runs the failover
    self-test after an on/off run on clustered roles. -FixRegistration lets the pre-flight check
    register computers that point to a different management-server address (Server Configurator
    /register); without it such a computer fails the pre-flight check (status only reports it).
        -Action register                      re-register THIS Management Server cluster node
                                              (it must own the role now; needs -AdminUser/-AdminPwFile)
        -Action rollback -Snapshot <file>     undo what the run that wrote <file> changed
                                              (recorders and Event Server are taken from the file)
    Exit code: on/off -> 0 only if every computer's real state equals the target; status -> 0 only
    if every computer was reachable; register -> 0 if the node registered and the Management
    Server came up; rollback -> 0 if every computer is back to the snapshot state. 1 = not
    complete, 2 = fatal error, 3 = refused (not a Management Server / not elevated / missing input),
    4 = on/off only: encryption itself succeeded everywhere but the -TestFailover self-test failed.
#>
[CmdletBinding()]
param(
    [ValidateSet('','on','off','status','register','rollback')][string]$Action = '',   # headless action (no window). Empty = wizard.
    [string]$Snapshot = '',                             # -Action rollback: the run-<stamp>-snapshot.json to roll back to
    [switch]$TestFailover,                              # headless on/off: failover self-test of clustered roles afterwards
    [switch]$FixRegistration,                           # headless: register computers that point to a different management server
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


$script:Headless    = [bool]$Action
$script:SelfPath    = $PSCommandPath
$script:ChangeInProgress = $false   # a change / rollback / re-register is running (window close guard)
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
                     -Thumbprint '' -CertificateGroup $g -Action disableencryption -WorkLog $logs -GroupName $gn
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
        # W14: resolve the connection address here (main thread, Kerberos-to-IP fallback) BEFORE handing
        # the box off to the runspace - the engine calls inside HostWorker have no concept of Get-ConnAddr,
        # so a workgroup recorder addressed by name must already be resolved by the time it gets there.
        $conn = try { Get-ConnAddr $box.Addr $Common.Cred } catch { $box.Addr }
        $P=@{Target=$box.Target;Fqdn=$conn;Cred=$Common.Cred;SignerTp=$Common.SignerTp;CaCer=$Common.CaCer;Domain=$Common.Domain;OutputDir=$Common.OutputDir;Guids=$Common.Guids;Names=$Common.Names;Action=$Action;BindExpected=$true;ExtraSans=''}
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

# -- boxes (one per computer) and their REAL encryption state -------------------------------
$script:MsBox = $null; $script:EsBox = $null; $script:RecBoxes = @()
$script:RunFailure = $null; $script:SignerTp = ''; $script:CaCer = ''; $script:HasResult = $false
$script:RunStart = Get-Date; $script:StageRows = @{}; $script:LastOutcome = $null
$script:SessOpt = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 180000

function New-Box { param([string]$Role,[string]$Name,[string]$Target,[string]$Addr,[pscredential]$Cred)
    [pscustomobject]@{ Role=$Role; Name=$Name; Target=$Target; Addr=$Addr; Cred=$Cred; Reachable=$false; Encrypted=$null; Detail='not checked yet'; Excluded=$false
                       IsNode=$false; ClusterKey=''; Active=$false } }
# Cluster state (WSFC). $script:MsCluster / $script:EsCluster are $null for a single (standalone) server.
$script:MsCluster = $null; $script:MsNodeBoxes = @(); $script:MsDetectError = ''
$script:EsCluster = $null; $script:EsNodeBoxes = @(); $script:EsDetectError = ''
$script:MsStaleNodes = @(); $script:MsLastRegistered = ''; $script:FailoverResults = @()
$script:Scope = $null; $script:FinalOwners = @{}; $script:LastSnapshotPath = ''; $script:TestFailoverOn = $false
function Get-First { param($Items) $a=@($Items); if($a.Count){ $a[0] } else { $null } }
function Get-ClusterObj { param([string]$Key) if($Key -eq 'MS'){ $script:MsCluster } elseif($Key -eq 'ES'){ $script:EsCluster } else { $null } }
function Get-NodeBoxes { param([string]$Key) if($Key -eq 'MS'){ @($script:MsNodeBoxes) } elseif($Key -eq 'ES'){ @($script:EsNodeBoxes) } else { @() } }
function Get-NodeBox { param([string]$Key,[string]$Name) Get-First -Items @(Get-NodeBoxes $Key | Where-Object { [string]$_.Target -eq $Name }) }
function Get-MsBoxes { if($script:MsCluster){ @($script:MsNodeBoxes) } elseif($script:MsBox){ @($script:MsBox) } else { @() } }
function Get-EsBoxes { if($script:EsCluster){ @($script:EsNodeBoxes) } elseif($script:EsBox){ @($script:EsBox) } else { @() } }
function Get-AllBoxes {
    $a=@(); $a+=@(Get-MsBoxes); $a+=@(Get-EsBoxes); $a+=@($script:RecBoxes); $a }
function Get-BoxKind { param($Box) if($Box.Role -eq 'Management Server'){ 'MS' } elseif($Box.Role -eq 'Event Server'){ 'ES' } else { 'REC' } }
function Get-RoleText { param($Box)
    if(-not $Box.IsNode){ return [string]$Box.Role }
    "$($Box.Role) - cluster node, $(if($Box.Active){'active (runs the role now)'}else{'passive (standby)'})" }
# W8: scope/snapshot lookup key is KIND + a canonical host, never an address alone - MS by node (Target:
# the node's own identity, stable across cluster address/FQDN changes), ES/REC by host (Addr: what the
# wizard connects to). Two different-kind boxes must never collide just because they share an address.
function Get-BoxScopeKey { param($Box)
    $kind = Get-BoxKind $Box
    $hostKey = if($kind -eq 'MS'){ [string]$Box.Target } else { [string]$Box.Addr }
    "$kind|$($hostKey.ToLowerInvariant())"
}
function Find-Box { param([string]$Kind,[string]$HostName)
    $key = "$Kind|$(([string]$HostName).ToLowerInvariant())"
    Get-First -Items @(Get-AllBoxes | Where-Object { (Get-BoxScopeKey $_) -eq $key }) }
# Rollback limits a run to the boxes the earlier run changed ($script:Scope = set of kind+host keys).
function Test-InScope { param($Box)
    if($null -eq $script:Scope){ return $true }
    $script:Scope.ContainsKey((Get-BoxScopeKey $Box)) }
function Get-FirstLine { param([string]$Text) if(-not $Text){ return '' }; ($Text -split "`r?`n")[0].Trim() }
function Test-IpAddress { param([string]$Value) $ip=$null; [System.Net.IPAddress]::TryParse(([string]$Value).Trim(),[ref]$ip) }
function Get-StateText { param($Box)
    if(-not $Box.Reachable){ 'Unknown (cannot connect)' } elseif($null -eq $Box.Encrypted){ 'Unknown' } elseif($Box.Encrypted){ 'Encrypted' } else { 'Not encrypted' } }

# Ground truth readers. Management Server: netsh http sslcert bindings (443 = IIS and 5986 = WinRM
# HTTPS are ignored); MS encrypted iff port 9000 or 9001 is bound. Recording server: RecorderConfig.xml
# first, bindings only as a fallback (see $script:RecorderStateSb below). Event Server: <CertificateEnabled>
# in its ServiceEndpoints.xml.
#
# W4: netsh's own "IP:port" column label is LOCALIZED (a non-English Windows does not say "IP:port"), so
# matching that literal label silently reads nothing on such a box. Instead this parses the ADDRESS:PORT
# VALUE token itself (IPv4:port, or [IPv6]:port) wherever it appears in the output - that shape is
# invariant across languages and never collides with the other netsh fields (hash, GUID, store name).
# If netsh itself fails (non-zero exit / nothing could be read), Ok=$false: the caller must treat the
# state as Unknown ($null), never as "not encrypted". Both scriptblocks below inline this same parsing
# (never a shared named function) because they run remotely over WinRM, where only the scriptblock's own
# text travels to the target - a call to an outside function would fail there with "not recognized".
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
# W4: recorder ground truth is RecorderConfig.xml's <serverEncryption enabled="true|false"> element
# (present on a 2025 R3 recorder at this path); the bindings are used ONLY when that element is missing
# or unreadable. Source=xml/bindings tells the caller which one produced the answer.
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
# -- connection helpers (lab findings: cluster names break Kerberos AND can point at the wrong node) ---
# Two strictly separate paths:
#  HOST connections (the Event Server name typed in step 1, a standalone Event Server): cached by the
#    typed name in $script:ConnCache; on a Kerberos refusal (0x80090322 / 0x8009030e / 0x80090311) the
#    name's DNS address is used instead (NTLM via TrustedHosts). Whatever computer answers is accepted -
#    fine for detection, NEVER used for anything that targets one cluster node.
#  NODE connections (every node-scoped action): keyed by the cluster NODE NAME in $script:NodeConn.
#    Resolved only via (a) the node's own FQDN, and only when that name does NOT resolve to a cluster /
#    role IP address or to this computer, or (b) the node's own IPv4 addresses as reported by the cluster,
#    minus every 'IP Address' resource of the cluster. Every candidate must answer as that node.
#    Before EVERY node action the answering computer is checked again over the exact address used:
#    Invoke-OnNode checks it inside the same PowerShell session that runs the action; Get-VerifiedNodeAddr
#    checks it right before an engine call. A mismatch stops with a plain message, nothing is changed.
#    A node is local only if its NAME is this computer (then everything runs in-process).
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
# W14: the "belongs to a cluster" wording is kept ONLY when $Computer is actually a known cluster name
# (the standalone Event Server address IS often a WSFC role Network Name); a plain host with no Kerberos
# realm (a workgroup recorder, for instance) gets the accurate, generic reason instead.
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
function Set-RecBoxState { param($Box,$R)
    $Box.Reachable=$true
    if($R.Source -eq 'xml'){
        $Box.Encrypted=$R.Enabled; $Box.Detail="RecorderConfig.xml: serverEncryption enabled=$($R.Enabled)$(if($R.Hash){' hash=' + $R.Hash}else{''})"
    } elseif($R.Ok){
        $Box.Encrypted=$R.Enabled; $Box.Detail="bindings: $(if($R.Bindings){$R.Bindings}else{'none'}) (RecorderConfig.xml not usable - fallback)"
    } else {
        # W4/W9: netsh could not be read or parsed - Unknown ($null), never "not encrypted".
        $Box.Encrypted=$null; $Box.Detail="state unknown: $(if($R.Error){$R.Error}else{'RecorderConfig.xml and netsh both unusable'})"
    }
}
function Update-RecorderStates { param([object[]]$Boxes)
    $remote=@()
    foreach($b in @($Boxes)){
        if(Test-LocalTarget $b.Addr){
            try { Set-RecBoxState $b (& $script:RecorderStateSb) } catch { $b.Reachable=$true; $b.Encrypted=$null; $b.Detail="netsh failed: $(Get-FirstLine $_.Exception.Message)" }
        } else { $remote+=$b }
    }
    if(-not $remote.Count){ return }
    # W14: resolve each box's connection address first (Kerberos-to-IP fallback) - same host path every
    # other recorder connection goes through, so a workgroup recorder addressed by name is not silently
    # reported Unknown just because Kerberos refused the bare name.
    $connOf=@{}
    foreach($b in $remote){
        try { $connOf[[string]$b.Addr] = Get-ConnAddr $b.Addr $b.Cred }
        catch { $b.Reachable=$false; $b.Encrypted=$null; $b.Detail="cannot connect: $(Get-FirstLine $_.Exception.Message)" }
    }
    $stillRemote=@($remote | Where-Object { $connOf.ContainsKey([string]$_.Addr) })
    if(-not $stillRemote.Count){ return }
    # One fan-out Invoke-Command for all recorders (WinRM runs them in parallel), by RESOLVED address.
    $addrs=@($stillRemote | ForEach-Object { $connOf[[string]$_.Addr] } | Select-Object -Unique)
    $ev=$null
    $p=@{ ComputerName=$addrs; ScriptBlock=$script:RecorderStateSb; SessionOption=$script:SessOpt; ThrottleLimit=32; ErrorAction='SilentlyContinue'; ErrorVariable='ev' }
    if($stillRemote[0].Cred){ $p.Credential=$stillRemote[0].Cred }
    $out=@(Invoke-Command @p)
    $res=@{}; foreach($o in $out){ $res[[string]$o.PSComputerName]=$o }
    $errs=@{}
    foreach($e in @($ev)){
        $k=$null
        try { if($e.TargetObject -is [string]){ $k=[string]$e.TargetObject } } catch {}
        if(-not $k){ try { $k=[string]$e.OriginInfo.PSComputerName } catch {} }
        if($k -and -not $errs.ContainsKey($k)){ $errs[$k]=Get-FirstLine $e.Exception.Message }
    }
    foreach($b in $stillRemote){
        $conn=$connOf[[string]$b.Addr]
        if($res.ContainsKey($conn)){ Set-RecBoxState $b $res[$conn] }
        else { $b.Reachable=$false; $b.Encrypted=$null; $b.Detail="cannot connect: $(if($errs.ContainsKey($conn)){$errs[$conn]}else{'no answer'})" }
    }
}
function Update-BoxStates { param([object[]]$Boxes)
    $recs=@()
    foreach($b in @($Boxes)){
        if($b.Role -eq 'Management Server' -and $b.IsNode){
            # Cluster node: that node's own netsh bindings (local in-process, or over WinRM).
            try {
                $r = Get-First -Items @(Invoke-OnNode -Node $b.Target -Cred $b.Cred -Sb $script:BindingsSb)
                if(-not $r.Ok){ $b.Reachable=$true; $b.Encrypted=$null; $b.Detail="state unknown: $(if($r.Error){$r.Error}else{'netsh could not be read'})" }
                else {
                    $ms=@(([string]$r.Bindings) -split ',' | Where-Object { $_ -match ':900[01]$' })
                    $b.Reachable=$true; $b.Encrypted=($ms.Count -gt 0); $b.Detail="bindings: $(if($r.Bindings){$r.Bindings}else{'none'})"
                }
            } catch { $b.Reachable=$false; $b.Encrypted=$null; $b.Detail="cannot connect: $(Get-FirstLine $_.Exception.Message)" }
        } elseif($b.Role -eq 'Management Server'){
            try {
                $r = & $script:BindingsSb
                if(-not $r.Ok){ $b.Reachable=$true; $b.Encrypted=$null; $b.Detail="state unknown: $(if($r.Error){$r.Error}else{'netsh could not be read'})" }
                else {
                    $ms=@(([string]$r.Bindings) -split ',' | Where-Object { $_ -match ':900[01]$' })
                    $b.Reachable=$true; $b.Encrypted=($ms.Count -gt 0); $b.Detail="bindings: $(if($r.Bindings){$r.Bindings}else{'none'})"
                }
            } catch { $b.Reachable=$true; $b.Encrypted=$null; $b.Detail="netsh failed: $(Get-FirstLine $_.Exception.Message)" }
        } elseif($b.Role -eq 'Event Server'){
            try {
                $r = if($b.IsNode){ Get-First -Items @(Invoke-OnNode -Node $b.Target -Cred $b.Cred -Sb $script:EsStateSb) }
                     else { Get-First -Items @(Invoke-OnBox -Computer $b.Addr -Cred $b.Cred -Sb $script:EsStateSb) }
                if(-not $r){ throw 'no answer from the Event Server' }
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
# The window matches the service waits (MS/recorders 5 min, Event Server 3 min): a slow but successful
# change is not reported as a failure. Returns as soon as every box is in the wanted state.
function Confirm-BoxStates { param([object[]]$Boxes,[bool]$Want,[int]$TotalSec=300,[int]$DelaySec=20)
    $deadline=(Get-Date).AddSeconds($TotalSec); $i=0
    while($true){
        $i++
        Update-BoxStates $Boxes
        foreach($b in @($Boxes)){ Write-Log "  real state [$(Get-RoleText $b)] $($b.Name): $(Get-StateText $b) ($($b.Detail))" }
        $bad=@($Boxes | Where-Object { $_.Encrypted -ne $Want })
        if(-not $bad.Count){ return $true }
        if((Get-Date).AddSeconds($DelaySec) -gt $deadline){ break }
        Write-Log "  $($bad.Count) computer(s) not yet in the wanted state - checking again in ${DelaySec}s (check $i, up to $([int]($TotalSec/60)) min in total)"; Wait-Ui $DelaySec
    }
    $false
}
function Write-StateLog { param([string]$Title,[object[]]$Boxes)
    Write-Log "----- $Title -----"
    foreach($b in @($Boxes)){
        Write-Log (" {0,-18} {1,-30} {2,-26} {3}" -f (Get-RoleText $b),$b.Name,(Get-StateText $b),$b.Detail) $(if(-not $b.Reachable -or $null -eq $b.Encrypted){'Err'}else{'Info'})
    }
}

# ===================== WINDOWS FAILOVER CLUSTER (WSFC) SUPPORT =====================
# Everything below is new in this file and stays OUTSIDE the inlined engine: the engine functions are
# called unchanged, per node. Scriptblocks run on the target through Invoke-OnBox (in-process when the
# target is this computer, else WinRM) and must be StrictMode-safe (they inherit it when run locally).

$script:MsSvcDisplay = 'Milestone XProtect Management Server'
$script:EsSvcDisplay = 'Milestone XProtect Event Server'

# Detect whether the Milestone service of one kind ('MS' / 'ES') is a Generic Service resource of a
# WSFC role on the computer this runs on. Returns Clustered=$false (with a Note) for a single server.
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

# One cluster operation on the computer this runs on: move | suspend | resume | start.
# 'start' brings offline resources of the role online again, but NEVER the Event Server resource of
# the Management Server role (offline by design) and never a resource whose service is Disabled here.
$script:ClusterOpSb = {
    param([string]$Op,[string]$Group,[string]$Node,[int]$WaitSec,[string]$Kind)
    $ErrorActionPreference = 'Stop'
    Import-Module FailoverClusters -ErrorAction Stop
    $nm = { param($o) if($null -eq $o){ return '' }; if($o -is [string]){ return $o }; $pp=$o.PSObject.Properties['Name']; if($pp){ return [string]$pp.Value }; [string]$o }
    $first = { param($t) (([string]$t) -split "`n")[0].Trim() }
    $log = [System.Collections.Generic.List[string]]::new(); $ok = $true; $paused = @(); $resumed = @()
    if($Op -eq 'move'){
        $cur = & $nm (Get-ClusterGroup -Name $Group).OwnerNode
        if($cur -eq $Node){ $log.Add("role '$Group' is already on $Node") }
        else {
            try { Move-ClusterGroup -Name $Group -Node $Node -Wait $WaitSec -ErrorAction Stop | Out-Null; $log.Add("moved role '$Group' from $cur to $Node") }
            catch { $log.Add("moving role '$Group' to $Node reported: $(& $first $_.Exception.Message)") }
        }
    } elseif($Op -eq 'suspend'){
        # W3: $Node carries the caller's possible-owner list (comma-separated); a node of this cluster
        # that is NOT a possible owner of role $Group is left exactly as it is (another role may need it).
        $only = @(([string]$Node) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        foreach($n in @(Get-ClusterNode)){
            if($only.Count -and $only -notcontains [string]$n.Name){ $log.Add("node $($n.Name) left as it is (not a possible owner of role '$Group')"); continue }
            $st = [string]$n.State
            if($st -eq 'Up'){
                try { Suspend-ClusterNode -Name $n.Name -ErrorAction Stop | Out-Null; $log.Add("paused node $($n.Name)"); $paused += [string]$n.Name }
                catch { $ok = $false; $log.Add("could NOT pause node $($n.Name): $(& $first $_.Exception.Message)") }
            } elseif($st -eq 'Paused'){ $log.Add("node $($n.Name) was already paused - left as it is") }
            elseif($st -eq 'Down'){ $log.Add("node $($n.Name) is Down - skipped (it cannot take the role over anyway)") }
            else { $ok = $false; $log.Add("node $($n.Name) is $st - it cannot be paused") }
        }
    } elseif($Op -eq 'resume'){
        # Resume ONLY the nodes this run paused ($Node = comma list); a node paused before the run stays paused.
        $only = @(([string]$Node) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        foreach($n in @(Get-ClusterNode)){
            if([string]$n.State -ne 'Paused'){ continue }
            if($only -notcontains [string]$n.Name){ $log.Add("node $($n.Name) left paused (this run did not pause it)"); continue }
            try { Resume-ClusterNode -Name $n.Name -ErrorAction Stop | Out-Null; $log.Add("resumed node $($n.Name)"); $resumed += [string]$n.Name }
            catch { $ok = $false; $log.Add("could NOT resume node $($n.Name): $(& $first $_.Exception.Message)") }
        }
    } elseif($Op -eq 'start'){
        $esNames = @('MilestoneEventServerService','MilestoneEventServer')
        foreach($s in @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Milestone XProtect Event Server' })){ if($esNames -notcontains $s.Name){ $esNames += $s.Name } }
        foreach($r in @(Get-ClusterResource | Where-Object { (& $nm $_.OwnerGroup) -eq $Group })){
            if([string]$r.State -eq 'Online'){ continue }
            $rt = & $nm $r.ResourceType; $sn = ''
            if($rt -eq 'Generic Service'){ try { $sn = [string](($r | Get-ClusterParameter -Name ServiceName -ErrorAction Stop).Value) } catch {} }
            if($Kind -eq 'MS' -and (($esNames -contains $sn) -or ($rt -eq 'Generic Service' -and [string]$r.Name -match 'Event Server'))){
                $log.Add("left '$($r.Name)' offline (the Event Server resource of the Management Server role stays offline by design)"); continue }
            if($sn){
                $ls = Get-Service -Name $sn -ErrorAction SilentlyContinue
                if($ls -and [string]$ls.StartType -eq 'Disabled'){ $log.Add("left '$($r.Name)' offline (its service is Disabled on $env:COMPUTERNAME)"); continue }
            }
            # A resource can fail once while its service is still settling: 3 tries, 20 s apart.
            $started = $false; $lastErr = ''
            for($try = 1; $try -le 3 -and -not $started; $try++){
                try { Start-ClusterResource -Name $r.Name -Wait 180 -ErrorAction Stop | Out-Null; $started = $true; $log.Add("started cluster resource '$($r.Name)'$(if($try -gt 1){" (try $try)"})") }
                catch { $lastErr = & $first $_.Exception.Message; if($try -lt 3){ Start-Sleep -Seconds 20 } }
            }
            if(-not $started){ $log.Add("could not start cluster resource '$($r.Name)' after 3 tries: $lastErr") }
        }
    } elseif($Op -eq 'stopsvc'){
        # Take the role's Milestone services offline; the IP Address / Network Name stay online, so the
        # cluster address keeps answering (ServerConfigurator registers against it).
        foreach($r in @(Get-ClusterResource | Where-Object { (& $nm $_.OwnerGroup) -eq $Group -and (& $nm $_.ResourceType) -eq 'Generic Service' })){
            if([string]$r.State -eq 'Offline'){ continue }
            try { Stop-ClusterResource -Name $r.Name -Wait 180 -ErrorAction Stop | Out-Null; $log.Add("stopped cluster resource '$($r.Name)'") }
            catch { $ok = $false; $log.Add("could NOT stop cluster resource '$($r.Name)': $(& $first $_.Exception.Message)") }
        }
    }
    $g = Get-ClusterGroup -Name $Group
    $owner = & $nm $g.OwnerNode
    if($Op -eq 'move' -and $owner -ne $Node){ $ok = $false }
    [pscustomobject]@{ Ok=[bool]$ok; Owner=$owner; State=[string]$g.State; Logs=$log.ToArray(); Paused=$paused; Resumed=$resumed }
}

# Is the role's service up on this computer: service Running and its port answering on loopback.
$script:ServiceProbeSb = {
    param([string]$Dn,[int]$Port)
    $s = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $Dn } | Select-Object -First 1
    $open = $false
    try { $tc = [System.Net.Sockets.TcpClient]::new(); $tc.Connect('127.0.0.1',$Port); $open = $tc.Connected; $tc.Close() } catch {}
    [pscustomobject]@{ Status=$(if($s){ [string]$s.Status } else { 'not installed' }); Port=[bool]$open }
}

# W1: does ServerConfigurator.exe exist at the engine's fixed install path on this computer? The engine
# (Invoke-RemoteServerEncryption / ScRegisterSb) always uses this same hardcoded path - this wizard
# supports the default Milestone install folder only, so a missing exe must be caught before anything
# is attempted, not discovered as an opaque SC failure mid-run.
$script:ScExePath = 'C:\Program Files\Milestone\Server Configurator\ServerConfigurator.exe'
$script:ScExistsSb = { param([string]$Path) [pscustomobject]@{ Exists=[bool](Test-Path -LiteralPath $Path) } }
function Get-ScMissingProblem { param([object[]]$Boxes)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach($b in @($Boxes)){
        try {
            $r = if($b.IsNode){ Get-First -Items @(Invoke-OnNode -Node $b.Target -Cred $b.Cred -Sb $script:ScExistsSb -ArgumentList @($script:ScExePath)) }
                 else { Get-First -Items @(Invoke-OnBox -Computer $b.Addr -Cred $b.Cred -Sb $script:ScExistsSb -ArgumentList @($script:ScExePath)) }
            if(-not $r -or -not $r.Exists){ $out.Add("$($b.Name): ServerConfigurator was not found at $($script:ScExePath). This wizard supports the default Milestone install folder only.") }
        } catch { $out.Add("$($b.Name): could not check for ServerConfigurator ($(Get-FirstLine $_.Exception.Message)).") }
    }
    $out.ToArray()
}

# ONE pass of the Management Server settle gate on a REMOTE node - the same checks as the local
# Wait-MsIdpReady + Clear-WedgedMilestoneSiblings (verbatim engine helpers, which only work in-process).
# The caller loops it until Ready or the deadline.
$script:MsSettleProbeSb = {
    param([bool]$WantRun,[bool]$KillIfStuck)
    $log = [System.Collections.Generic.List[string]]::new(); $ready = $false
    $clear = {
        foreach($sb in @(Get-Service | Where-Object { $_.DisplayName -in 'Milestone XProtect Log Server','Milestone XProtect Data Collector Server' -and $_.Status -eq 'Running' })){
            try { Stop-Service $sb.Name -Force -ErrorAction Stop; $log.Add("readiness gate stopped $($sb.DisplayName) (ServerConfigurator restarts it)") }
            catch {
                $ci = Get-CimInstance Win32_Service -Filter "Name='$($sb.Name)'"
                if($ci -and $ci.ProcessId -gt 0){ Stop-Process -Id $ci.ProcessId -Force -ErrorAction SilentlyContinue; $log.Add("$($sb.DisplayName) control handler wedged - killed pid $($ci.ProcessId)") }
            }
        }
    }
    $svc = Get-Service | Where-Object { $_.DisplayName -eq 'Milestone XProtect Management Server' } | Select-Object -First 1
    if(-not $svc){ return [pscustomobject]@{ Ready=$true; Logs=@("[$env:COMPUTERNAME] Management Server service not found") } }
    if($WantRun){
        if($svc.Status -eq 'Stopped'){ try { Start-Service $svc.Name -ErrorAction Stop; $log.Add('MS service started by readiness gate') } catch {} }
        $ws = $false
        try { $tc = [System.Net.Sockets.TcpClient]::new(); $tc.Connect('127.0.0.1',8080); $ws = $tc.Connected; $tc.Close() } catch {}
        $up = -1
        $ci = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'"
        if($ci -and $ci.ProcessId -gt 0){ $p = Get-Process -Id $ci.ProcessId -ErrorAction SilentlyContinue; if($p){ $up = [int]((Get-Date) - $p.StartTime).TotalSeconds } }
        $svc.Refresh()
        if($ws -and $svc.Status -eq 'Running' -and $up -ge 240){ & $clear; $log.Add("MS service settled (uptime ${up}s, :8080 up) - ready for enable"); $ready = $true }
        else { $log.Add("MS service not settled yet (status $($svc.Status), uptime ${up}s, :8080 $(if($ws){'up'}else{'down'}))") }
    } else {
        $svc.Refresh()
        if($svc.Status -eq 'Stopped'){ & $clear; $log.Add('MS service stopped - ready for ServerConfigurator (it will start it)'); $ready = $true }
        elseif($svc.Status -eq 'Running'){
            try { Stop-Service $svc.Name -Force -ErrorAction Stop; & $clear; $log.Add('MS service stopped by readiness gate - ServerConfigurator will start it'); $ready = $true }
            catch {
                $log.Add("MS service not stoppable yet ($((([string]$_.Exception.Message) -split "`n")[0].Trim())) - waiting")
                if($KillIfStuck){
                    $ci = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'"
                    if($ci -and $ci.ProcessId -gt 0){ Stop-Process -Id $ci.ProcessId -Force -ErrorAction SilentlyContinue; $log.Add("MS service control handler wedged (90s+) - killed pid $($ci.ProcessId)") }
                }
            }
        } else { $log.Add("MS service is $($svc.Status) - waiting") }
    }
    [pscustomobject]@{ Ready=[bool]$ready; Logs=@($log.ToArray() | ForEach-Object { "[$env:COMPUTERNAME] $_" }) }
}

# Give the account the Milestone service runs as (StartName) Read on the new certificate's private
# key - Invoke-RemoteRecorderInstall (engine) grants NETWORK SERVICE only.
$script:KeyGrantSb = {
    param([string]$Tp,[string]$Dn)
    $svc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $Dn } | Select-Object -First 1
    if(-not $svc){ return "[$env:COMPUTERNAME] service '$Dn' not found - private key permissions left as they are" }
    $acct = [string]$svc.StartName
    if(-not $acct -or $acct -match '^(NT AUTHORITY\\)?Network ?Service$' -or $acct -match '^(LocalSystem|NT AUTHORITY\\SYSTEM)$'){
        return "[$env:COMPUTERNAME] '$Dn' runs as $(if($acct){$acct}else{'(unknown)'}) - no extra private key permission needed" }
    if($acct.StartsWith('.\')){ $acct = "$env:COMPUTERNAME\$($acct.Substring(2))" }
    try {
        $c = Get-Item -LiteralPath "Cert:\LocalMachine\My\$Tp" -ErrorAction Stop
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
        $keyName = $null
        if($rsa -and $rsa.PSObject.Properties['Key'] -and $rsa.Key){ $keyName = $rsa.Key.UniqueName }
        elseif($c.PrivateKey){ $keyName = $c.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName }
        if(-not $keyName){ return "[$env:COMPUTERNAME] WARNING: private key of $Tp not found - $acct was NOT given access" }
        $keyFile = $null
        foreach($d in @("$env:ProgramData\Microsoft\Crypto\Keys", "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys")){
            $p = Join-Path $d $keyName
            if(Test-Path -LiteralPath $p){ $keyFile = $p; break }
        }
        if(-not $keyFile){ return "[$env:COMPUTERNAME] WARNING: private key file not located for $Tp - $acct was NOT given access" }
        $kAcl = Get-Acl -Path $keyFile
        $kAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($acct,'Read','Allow')))
        Set-Acl -Path $keyFile -AclObject $kAcl
        "[$env:COMPUTERNAME] granted $acct Read on the private key ($keyName) - '$Dn' runs as that account"
    } catch { "[$env:COMPUTERNAME] WARNING: could not give $acct Read on the private key: $($_.Exception.Message)" }
}

# ServerConfigurator /register /managementserveraddress=<addr> /quiet on the computer this runs on,
# through the same SYSTEM-jump launcher pattern as the engine (scheduled task as SYSTEM -> LogonUser +
# CreateProcessAsUser as the admin). The engine's Invoke-RemoteServerEncryption only knows
# enable/disable, so this is a separate, non-engine copy of that pattern for the register verb.
$script:ScRegisterSb = {
    param([string]$MsAddress,[pscredential]$RunCred,[string]$LauncherSource)
    $ErrorActionPreference = 'Stop'
    $elog = [System.Collections.Generic.List[string]]::new()
    $scExe = 'C:\Program Files\Milestone\Server Configurator\ServerConfigurator.exe'
    if(-not (Test-Path -LiteralPath $scExe)){ throw "ServerConfigurator not found: $scExe" }
    $scDir = [System.IO.Path]::GetDirectoryName($scExe)
    Get-Process -Name ServerConfigurator -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800
    $work = Join-Path $env:windir ("Temp\MRC-{0}" -f [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    # E1: protect the work folder itself (SYSTEM + Administrators, no inheritance) before ANY file is
    # written into it - pw.txt must never land in a folder any authenticated user can read.
    $aclWork = Get-Acl -Path $work
    $aclWork.SetAccessRuleProtection($true, $false)
    foreach($idName in @('NT AUTHORITY\SYSTEM','BUILTIN\Administrators')){ $aclWork.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($idName, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }
    Set-Acl -Path $work -AclObject $aclWork
    $outFile = Join-Path $work 'out.txt'; $errFile = Join-Path $work 'err.txt'; $cmdFile = Join-Path $work 'run.cmd'
    $scArgs = "/register /managementserveraddress=$MsAddress /quiet"
    Set-Content -LiteralPath $cmdFile -Encoding ASCII -Value @('@echo off', "cd /d ""$scDir""", """$scExe"" $scArgs 1> ""$outFile"" 2> ""$errFile""", 'exit /b %ERRORLEVEL%')
    $nc = $RunCred.GetNetworkCredential()
    $launchUser = $nc.UserName
    $launchDom  = if([string]::IsNullOrWhiteSpace($nc.Domain)){ '.' } else { $nc.Domain }
    $cmdSpec = '"{0}" /c "{1}"' -f "$env:windir\System32\cmd.exe", $cmdFile
    $pwFile = Join-Path $work 'pw.txt'
    $taskName = "MRC-SCReg-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    $taskRegistered = $false
    $launcherPs1 = $null
    $state = $null; $scExit = $null
    try {
        # E1: everything from the pw.txt write to the end of the task is ONE try/finally - a failure
        # anywhere in here still cleans up the secret file and the launcher, and unregisters the task
        # only if it was registered.
        [IO.File]::WriteAllText($pwFile, $nc.Password)
        $aclPw = Get-Acl -Path $pwFile
        $aclPw.SetAccessRuleProtection($true, $false)
        foreach($idName in @('NT AUTHORITY\SYSTEM','BUILTIN\Administrators')){ $aclPw.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($idName, 'FullControl', 'Allow'))) }
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
        Remove-Item -LiteralPath $pwFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $launcherPs1 -Force -ErrorAction SilentlyContinue
    }
    $stdout = (Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue)
    $stderr = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    $elog.Add("[$env:COMPUTERNAME] SC stdout: $(if($stdout -and $stdout.Trim()){ $stdout.Trim() } else { '(empty)' })")
    $elog.Add("[$env:COMPUTERNAME] SC stderr: $(if($stderr -and $stderr.Trim()){ $stderr.Trim() } else { '(empty)' })")
    $elog.Add("[$env:COMPUTERNAME] SC exit code: $scExit")
    $scLog = Get-ChildItem -Path 'C:\ProgramData\Milestone' -Recurse -Filter '*.log' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match 'erver.?onfigurator' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $runLines = @()
    if($scLog){
        $allLog = @(Get-Content -LiteralPath $scLog.FullName -ErrorAction SilentlyContinue)
        $argIdx = -1
        for($i = $allLog.Count - 1; $i -ge 0; $i--){ if($allLog[$i] -match 'Arguments:.*register'){ $argIdx = $i; break } }
        $runLines = @(if($argIdx -ge 0){ @($allLog[$argIdx..($allLog.Count - 1)]) } else { @($allLog | Select-Object -Last 120) })
        $elog.Add("[$env:COMPUTERNAME] SC log [$($scLog.Name)] (this run): $(($runLines | Select-Object -Last 80) -join ' || ')")
    } else { $elog.Add("[$env:COMPUTERNAME] SC log: none found") }
    $marker = (@($runLines -match 'Registration done with result = Success').Count -gt 0)
    $ok = ($scExit -eq 0) -or $marker
    [pscustomobject]@{ ExitCode=$(if($null -ne $scExit){ [int64]$scExit } else { [int64]-1 }); Ok=[bool]$ok; Logs=$elog.ToArray() }
}

function New-ClusterObj { param([string]$Key,$Info,[string]$Via)
    [pscustomobject]@{ Key=$Key; Group=[string]$Info.Group; Address=[string]$Info.Address; NetName=[string]$Info.NetName; Domain=[string]$Info.Domain
                       Owner=[string]$Info.Owner; State=[string]$Info.State; Nodes=@($Info.Nodes); Offline=@($Info.Offline)
                       ClusterIps=@(if($Info.PSObject.Properties['ClusterIps']){ @($Info.ClusterIps) })
                       Excluded=@(if($Info.PSObject.Properties['Excluded']){ @($Info.Excluded) })
                       Via=$Via; Error='' } }   # Via = the NODE NAME cluster commands are sent to (Invoke-OnNode); Excluded = nodes that are not possible owners of this role (W3)
# Log every node excluded from a role because it is not a possible owner (Get-ClusterOwnerNode, W3).
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
# Re-read owner, role state, node states and offline resources of one clustered role.
function Update-ClusterInfo { param([string]$Key)
    $cl = Get-ClusterObj $Key; if(-not $cl){ return $null }
    try {
        $i = Get-First -Items @(Invoke-OnNode -Node $cl.Via -Cred $script:AdminCred -Sb $script:ClusterInfoSb -ArgumentList @($Key))
        if(-not $i -or -not $i.Clustered){ throw "the Milestone service is no longer a cluster resource on $($cl.Via)" }
        $cl.Owner=[string]$i.Owner; $cl.State=[string]$i.State; $cl.Nodes=@($i.Nodes); $cl.Offline=@($i.Offline); $cl.Error=''
        if($i.PSObject.Properties['ClusterIps']){ $cl.ClusterIps=@($i.ClusterIps) }
        if($i.PSObject.Properties['Excluded']){ $cl.Excluded=@($i.Excluded) }
        Register-NodeAddresses $cl
    } catch { $cl.Error = Get-FirstLine $_.Exception.Message; Write-Log "Cluster role '$($cl.Group)': state could not be read: $($cl.Error)" 'Err' }
    Set-ActiveFlags $Key
    $cl
}
# '' when the role is healthy: Online, or PartialOnline where the ONLY offline resource is the Event
# Server resource of the Management Server role (its service is Disabled on MS nodes by design).
function Get-ClusterHealthProblem { param($Cl)
    $st = [string]$Cl.State
    if($st -eq 'Online'){ return '' }
    if($st -eq 'PartialOnline'){
        $other = @(@($Cl.Offline) | Where-Object { -not ($Cl.Key -eq 'MS' -and $_.IsEs) })
        if(-not $other.Count){ return '' }
        return "The cluster role '$($Cl.Group)' ($(Get-StageName $Cl.Key)) is only partly running. Not running: $((@($other | ForEach-Object { "$($_.Name) ($($_.State))" })) -join ', '). Start them in Failover Cluster Manager (Roles > '$($Cl.Group)' > Resources), then try again."
    }
    "The cluster role '$($Cl.Group)' ($(Get-StageName $Cl.Key)) is '$st', not 'Online'. It must be running before anything is changed. In Failover Cluster Manager > Roles, right-click '$($Cl.Group)' > Start Role, then try again."
}
# In-run pause tracking: 'resume' resumes only the nodes THIS run paused; a node that was paused (or
# Down) before the run is left exactly as it is.
$script:PausedByRun = @{}
function Test-PausedByRun { param([string]$Key,[string]$Node) $script:PausedByRun.ContainsKey($Key) -and (@($script:PausedByRun[$Key]) -contains $Node) }
function Get-ResumeList { param([string]$Key) if($script:PausedByRun.ContainsKey($Key)){ (@($script:PausedByRun[$Key]) -join ',') } else { '' } }
function Update-PauseTracker { param([string]$Key,[string]$Op,$R)
    if(-not $R){ return }
    if(-not $script:PausedByRun.ContainsKey($Key)){ $script:PausedByRun[$Key] = @() }
    if($Op -eq 'suspend' -and $R.PSObject.Properties['Paused']){
        foreach($n in @($R.Paused)){ if($n -and @($script:PausedByRun[$Key]) -notcontains [string]$n){ $script:PausedByRun[$Key] = @(@($script:PausedByRun[$Key]) + [string]$n) } } }
    if($Op -eq 'resume' -and $R.PSObject.Properties['Resumed']){
        $done = @($R.Resumed); $script:PausedByRun[$Key] = @(@($script:PausedByRun[$Key]) | Where-Object { $done -notcontains $_ }) }
}
function Invoke-ClusterOp { param([string]$Key,[string]$Op,[string]$Node='',[int]$WaitSec=300)
    $cl = Get-ClusterObj $Key
    if($Op -eq 'resume' -and -not $Node){ $Node = Get-ResumeList $Key }
    # W3: suspend/resume touch only this role's possible-owner nodes (already filtered into $cl.Nodes by
    # ClusterInfoSb) - never every node of a bigger cluster that also hosts unrelated roles.
    if($Op -eq 'suspend' -and -not $Node){ $Node = ((@($cl.Nodes) | ForEach-Object { [string]$_.Name }) -join ',') }
    try {
        $r = Get-First -Items @(Invoke-OnNode -Node $cl.Via -Cred $script:AdminCred -Sb $script:ClusterOpSb -ArgumentList @($Op,$cl.Group,$Node,$WaitSec,$Key))
        foreach($l in @($r.Logs)){ Write-Log "  [cluster $($cl.Group)] $l" $(if($l -match 'NOT|cannot|could not'){'Err'}else{'Info'}) }
        Update-PauseTracker $Key $Op $r
        $cl.Owner=[string]$r.Owner; $cl.State=[string]$r.State; Set-ActiveFlags $Key
        [pscustomobject]@{ Ok=[bool]$r.Ok; Owner=[string]$r.Owner; State=[string]$r.State; Detail=(@($r.Logs) -join '; ') }
    } catch {
        $m = Get-FirstLine $_.Exception.Message
        Write-Log "  [cluster $($cl.Group)] $Op FAILED: $m" 'Err'
        [pscustomobject]@{ Ok=$false; Owner=''; State=''; Detail=$m }
    }
}
function Move-ClusterRole { param([string]$Key,[string]$Node)
    $cl = Get-ClusterObj $Key
    if($Key -eq 'MS'){ $script:MsTouched = $true }
    Write-Log "Cluster: moving role '$($cl.Group)' to $Node (the $(Get-StageName $Key) stops where it runs now and starts on $Node)."
    $r = Invoke-ClusterOp $Key 'move' $Node 300
    if(-not $r.Ok){
        # A timed-out move can still be completing (or failing back): wait until the role is no longer
        # Pending, then decide on what the cluster really did.
        Write-Log "Cluster: the move of '$($cl.Group)' to $Node did not finish in time ($($r.Detail)). Waiting up to 5 minutes for the cluster to finish it before deciding..." 'Err'
        $s = Wait-ClusterGroupSettled $Key 300 0
        $r = [pscustomobject]@{ Ok=([string]$cl.Owner -eq $Node -and $s.Settled); Owner=[string]$cl.Owner; State=[string]$cl.State; Detail="$($r.Detail); after waiting: role on $($cl.Owner), state $($cl.State)" }
        if($r.Ok){ Write-Log "Cluster: the move to $Node completed late - role '$($cl.Group)' is on $Node (state $($cl.State))." 'Good' }
    }
    if($r.Ok){ Write-Log "Cluster: role '$($cl.Group)' is on $Node (state $($r.State))." 'Good' }
    else { Write-Log "Cluster: role '$($cl.Group)' could NOT be moved to $Node - it is on $(if($r.Owner){$r.Owner}else{'(unknown)'}) ($($r.Detail))" 'Err' }
    $r
}
# Poll the role until it is no longer Pending (and stays so for $StableSec). 10-second polls.
function Wait-ClusterGroupSettled { param([string]$Key,[int]$TimeoutSec=300,[int]$StableSec=0)
    $cl = Get-ClusterObj $Key
    $polls = [int][math]::Ceiling($TimeoutSec / 10); $need = [int][math]::Ceiling($StableSec / 10); $stable = 0; $said = $false
    for($i = 0; $i -le $polls; $i++){
        [void](Update-ClusterInfo $Key)
        if([string]$cl.State -eq 'Pending' -or $cl.Error){
            $stable = 0
            if(-not $said){ Write-Log "Cluster: role '$($cl.Group)' is still changing (state $(if($cl.Error){'unknown'}else{$cl.State})) - waiting..."; $said = $true }
        } else {
            if($stable -ge $need){ return [pscustomobject]@{ Settled=$true; Owner=[string]$cl.Owner; State=[string]$cl.State } }
            $stable++
        }
        Wait-Ui 10
    }
    Write-Log "Cluster: role '$($cl.Group)' did not settle within $([int]($TimeoutSec/60)) min (state $($cl.State), on $($cl.Owner))." 'Err'
    [pscustomobject]@{ Settled=$false; Owner=[string]$cl.Owner; State=[string]$cl.State }
}

# -- Management Server cluster: last-registered node tracking + safe takeover --------------------
# Only the MS node registered LAST can start the Management Server (Milestone limitation). The wizard
# tracks that node for the run ($script:MsLastRegistered, starting with the role owner at run start) and
# never plainly moves the MS role to any other node: to run ServerConfigurator on a node it first takes
# the role's Milestone services offline (IP + name stay online), then moves only the address there.
$script:MsTouched = $false; $script:MsLive = $null
function Initialize-MsTracking {
    $script:MsTouched = $false; $script:MsLive = $null
    if(-not $script:MsCluster){ return }
    [void](Update-ClusterInfo 'MS')
    $script:MsLastRegistered = [string]$script:MsCluster.Owner
}
function Set-MsRegistered { param([string]$Node)
    $script:MsLastRegistered = $Node
    $script:MsStaleNodes = @(@($script:MsNodeBoxes) | Where-Object { [string]$_.Target -ne $Node } | ForEach-Object { [string]$_.Name })
}
# Fix-1 takeover: stop the MS role's Generic Service resources, then move the role (only IP and name
# move, so this no longer depends on the Management Server starting on a node that is not registered).
function Enter-MsNode { param($Box)
    $script:MsTouched = $true
    [void](Update-ClusterInfo 'MS')
    Write-Log "Stopping the Milestone services of the Management Server cluster role before $($Box.Name) is configured. The cluster address stays online, so ServerConfigurator can still reach it. The Management Server is unavailable until the node is configured." 'Good'
    $st = Invoke-ClusterOp 'MS' 'stopsvc'
    if(-not $st.Ok){ return [pscustomobject]@{ Ok=$false; Detail="The Management Server services could not be stopped in the cluster ($($st.Detail))." } }
    if([string]$script:MsCluster.Owner -ne [string]$Box.Target){
        $mv = Move-ClusterRole 'MS' $Box.Target
        if(-not $mv.Ok){ return [pscustomobject]@{ Ok=$false; Detail=$mv.Detail } }
    }
    [pscustomobject]@{ Ok=$true; Detail='' }
}
# Put the MS role on the last-registered node (plain move is safe there), start it, wait for it.
function Move-MsToWorkingNode {
    $t = [string]$script:MsLastRegistered
    if(-not $script:MsCluster -or -not $t){ return }
    [void](Wait-ClusterGroupSettled 'MS' 300 0)
    if([string]$script:MsCluster.Owner -ne $t){
        Write-Log "Moving the Management Server role to $t, the node registered last - the only node that can start the Management Server." 'Err'
        [void](Move-ClusterRole 'MS' $t)
    }
    [void](Invoke-ClusterOp 'MS' 'start')
    $b = Get-NodeBox 'MS' $t
    if($b){ Update-BoxStates @($b); [void](Wait-NodeService 'MS' $b) }
}
# Live check of the MS role: after the role has left Pending for 30 s, the owner must run the MS
# service with its port answering. This (not bookkeeping) is what the result page reports.
# W5: also covers a standalone (non-clustered) Management Server - the same service+port check, in-process.
function Test-MsLive {
    if(-not $script:MsCluster){
        $box = $script:MsBox
        $out = [pscustomobject]@{ Up=$false; Owner=$env:COMPUTERNAME; Detail=''; At=(Get-Date) }
        if(-not $box){ $out.Detail = 'the Management Server box is not known'; return $out }
        Update-BoxStates @($box)
        $port = if($box.Encrypted -eq $false){ 80 } else { 9000 }
        try {
            $pr = & $script:ServiceProbeSb $script:MsSvcDisplay $port
            $out.Up = ([string]$pr.Status -eq 'Running' -and [bool]$pr.Port)
            $out.Detail = "service $($pr.Status), port $port $(if($pr.Port){'answering'}else{'not answering'})"
        } catch { $out.Detail = "cannot check: $(Get-FirstLine $_.Exception.Message)" }
        return $out
    }
    $cl = $script:MsCluster
    $s = Wait-ClusterGroupSettled 'MS' 300 30
    $owner = [string]$cl.Owner; $box = Get-NodeBox 'MS' $owner
    $out = [pscustomobject]@{ Up=$false; Owner=$owner; Detail=''; At=(Get-Date) }
    if(-not $box){ $out.Detail = "the role is on '$owner', which is not a known node"; return $out }
    Update-BoxStates @($box)
    $port = if($box.Encrypted -eq $false){ 80 } else { 9000 }
    try {
        $pr = Get-First -Items @(Invoke-OnNode -Node $box.Target -Cred $box.Cred -Sb $script:ServiceProbeSb -ArgumentList @($script:MsSvcDisplay,$port))
        $out.Up = ($s.Settled -and [string]$pr.Status -eq 'Running' -and [bool]$pr.Port)
        $out.Detail = "role state $($cl.State), service $($pr.Status), port $port $(if($pr.Port){'answering'}else{'not answering'})"
    } catch { $out.Detail = "role state $($cl.State), cannot connect: $(Get-FirstLine $_.Exception.Message)" }
    $out
}
# End-of-run guard (on/off/rollback/register, only when the MS was touched). W5: no longer skipped for a
# standalone MS - Test-MsLive itself now covers both the clustered and the standalone case.
function Test-FinalMsLiveGuard { param([string]$Act)
    if(-not $script:MsTouched){ return $true }
    $lv = Test-MsLive
    if($script:MsCluster -and -not $lv.Up -and $script:MsLastRegistered -and $lv.Owner -ne $script:MsLastRegistered){
        Write-Log "The Management Server is NOT running on $($lv.Owner) ($($lv.Detail))." 'Err'
        Move-MsToWorkingNode
        $lv = Test-MsLive
    }
    $script:MsLive = $lv
    if($lv.Up){ Write-Log "Checked live: the Management Server works on $($lv.Owner) ($($lv.Detail))." 'Good'; return $true }
    $t = "The Management Server is NOT running after the run: the role is on $($lv.Owner) ($($lv.Detail)). On $($lv.Owner), start this wizard and click 'Re-register this node', or undo the run."
    Write-Log $t 'Err'
    Add-NoteRow $Act $false 'Management Server not running after the run' $t
    if($script:RunFailure){ $script:RunFailure.Reason = "$($script:RunFailure.Reason)`r`n`r`nALSO: $t" }
    else { Set-RunFailure 'Management Server check after the run' $lv.Owner $t }
    $false
}
# Wait until the role's service answers on the node: MS = service Running + :9000, ES = + :22331.
# MS port: 9000 when encrypted, 80 when not (-Port overrides; else from $Box.Encrypted).
function Wait-NodeService { param([string]$Key,$Box,[int]$TimeoutSec=0,[int]$Port=0)
    $isMs = ($Key -eq 'MS')
    $dn = if($isMs){ $script:MsSvcDisplay } else { $script:EsSvcDisplay }
    $port = if($Port -gt 0){ $Port } elseif($isMs){ $(if($Box.Encrypted -eq $false){ 80 } else { 9000 }) } else { 22331 }
    if($TimeoutSec -le 0){ $TimeoutSec = if($isMs){ 300 } else { 180 } }
    $t0 = Get-Date; $deadline = $t0.AddSeconds($TimeoutSec); $last = 'not checked'
    Write-Log "[$($Box.Name)] waiting up to $([int]($TimeoutSec/60)) min for the $(Get-StageName $Key) service (port $port)..."
    do {
        try {
            $p = Get-First -Items @(Invoke-OnNode -Node $Box.Target -Cred $Box.Cred -Sb $script:ServiceProbeSb -ArgumentList @($dn,$port))
            $last = "service $($p.Status), port $port $(if($p.Port){'open'}else{'closed'})"
            if($p.Status -eq 'Running' -and $p.Port){
                $sec = [int]((Get-Date) - $t0).TotalSeconds
                Write-Log "[$($Box.Name)] $(Get-StageName $Key) is up ($last) after ${sec}s" 'Good'
                return [pscustomobject]@{ Up=$true; Detail="up after ${sec}s"; Seconds=$sec }
            }
        } catch {
            if(Test-IdentityError $_.Exception.Message){
                $im = Get-IdentityMessage $_.Exception.Message
                Write-Log "[$($Box.Name)] $im" 'Err'
                return [pscustomobject]@{ Up=$false; Detail=$im; Seconds=[int]((Get-Date) - $t0).TotalSeconds } }
            $last = "cannot connect: $(Get-FirstLine $_.Exception.Message)" }
        Wait-Ui 10
    } while((Get-Date) -lt $deadline)
    Write-Log "[$($Box.Name)] $(Get-StageName $Key) did NOT come up within $([int]($TimeoutSec/60)) min ($last)" 'Err'
    [pscustomobject]@{ Up=$false; Detail="the service did not come up within $([int]($TimeoutSec/60)) minutes ($last)"; Seconds=$TimeoutSec }
}
# Remote-node version of the Management Server settle gate (the local node uses Wait-MsIdpReady).
function Wait-NodeMsSettled { param($Box,[bool]$WantRunning,[int]$TimeoutSec=600)
    $t0 = Get-Date; $deadline = $t0.AddSeconds($TimeoutSec)
    do {
        try {
            $p = Get-First -Items @(Invoke-OnNode -Node $Box.Target -Cred $Box.Cred -Sb $script:MsSettleProbeSb -ArgumentList @($WantRunning, (((Get-Date) - $t0).TotalSeconds -gt 90)))
            foreach($l in @($p.Logs)){ Write-Log $l }
            if($p.Ready){ return $true }
        } catch {
            if(Test-IdentityError $_.Exception.Message){ throw (Get-IdentityMessage $_.Exception.Message) }   # wrong computer: stop
            Write-Log "[$($Box.Name)] settle check failed: $(Get-FirstLine $_.Exception.Message)" 'Err' }
        Wait-Ui 10
    } while((Get-Date) -lt $deadline)
    Write-Log "[$($Box.Name)] MS NOT ready after ${TimeoutSec}s - proceeding anyway" 'Err'
    $false
}

# The engine's Confirm-ServerEncryption tries to start every stopped Milestone service. On a clustered MS
# node the Event Server service is Disabled by design (its cluster resource stays offline), so that one
# 'FAILED to start' line is reworded here (the engine itself stays verbatim) and ignored for 'svc up'.
function Get-MsNodeConfirmLogs { param([object[]]$Lines)
    foreach($l in @($Lines)){
        $s = [string]$l
        if($s -match '^\[([^\]]+)\] FAILED to start (MilestoneEventServer\S*)'){ "[$($Matches[1])] Event Server service on this Management Server node stays off (by design in this cluster role)" }
        else { $s }
    } }
function Test-MsNodeServicesUp { param($Conf)
    if($Conf.AllServicesRunning){ return $true }
    (@(@($Conf.Stopped) | Where-Object { [string]$_ -and [string]$_ -notmatch 'EventServer' }).Count -eq 0) }
# ServerConfigurator on ONE cluster node with an already imported certificate. ADAPTED from
# $script:HostWorker (MS) / $script:EsHostWorker (ES): the same engine calls and the same verdict
# mapping, minus the per-host certificate issue/import (a clustered role shares one certificate).
function Invoke-NodeSc { param([string]$Key,$Box,[bool]$Want,[string]$Thumbprint)
    $t0 = Get-Date; $logs = [System.Collections.Generic.List[string]]::new()
    $isMs = ($Key -eq 'MS')
    $gn = if($isMs){ 'Server (mgmt+recorder)' } else { 'Event Server' }
    $guid = if($isMs){ $script:CertGroupServer } else { $script:CertGroupEvent }
    $res = [pscustomobject]@{Target=$Box.Target;Fqdn=$Box.Addr;Ok=$false;Status='';Tp=$(if($Want){$Thumbprint}else{''});Error='';Groups=$gn;Action=$(if($Want){'enable'}else{'disable'});Started=$t0;Ended=$null;DurationSec=0.0;Logs=$logs}
    try {
        $conn = Get-VerifiedNodeAddr $Box   # identity-checked: this address answers as $Box.Target right now
        if($conn -ne $Box.Addr){ $logs.Add("connecting to $($Box.Name) by its own address $conn (verified: it answers as $($Box.Target))") }
        $e = Invoke-ScWithWedgeRetry -ComputerName $conn -Credential $Box.Cred -Thumbprint $(if($Want){$Thumbprint}else{''}) `
                 -CertificateGroup $guid -Action $(if($Want){'enableencryption'}else{'disableencryption'}) -WorkLog $logs -GroupName $gn
        foreach($l in $e.Logs){ $logs.Add("[$gn] $l") }
        $failMsg = ''
        if($isMs){
            if($Want){
                if($e.ExitCode -in 0,200000){ }
                elseif($e.ExitCode -eq 100){ $failMsg='exit100(not authorized)' }
                elseif($e.ExitCode -eq 300000){ $failMsg='exit300000(cert bound but registration failed - cert CN does not match server address; server may not start)' }
                elseif($e.ExitCode -eq 100000){ $failMsg='exit100000(IDP 403 VmsAdminCredentialsNeeded - mgmt reconfig forbidden; cert may be half-applied)' }
                elseif($e.CertApplied){ }
                else { $failMsg="exit $($e.ExitCode)" }
                $conf = Confirm-ServerEncryption -ComputerName (Get-VerifiedNodeAddr $Box) -Credential $Box.Cred -UseSsl:$false -Thumbprint $Thumbprint
                foreach($l in @(Get-MsNodeConfirmLogs $conf.Logs)){ $logs.Add($l) }
                $res.Ok = (-not $failMsg) -and $conf.Bound
                $res.Status = if($res.Ok){ "Encrypted: $gn (svc $(if(Test-MsNodeServicesUp $conf){'up'}else{'CHECK'}))" } else { "FAILED $failMsg bound=$($conf.Bound)" }
            } else {
                if(-not ($e.CertApplied -or ($e.ExitCode -in 0,100,200000))){ $failMsg="exit $($e.ExitCode)" }
                $conf = Confirm-ServerEncryption -ComputerName (Get-VerifiedNodeAddr $Box) -Credential $Box.Cred -UseSsl:$false -Thumbprint '0'
                foreach($l in @(Get-MsNodeConfirmLogs $conf.Logs)){ $logs.Add($l) }
                $res.Ok = (-not $failMsg)
                $res.Status = if($res.Ok){ "Disabled: $gn (svc $(if(Test-MsNodeServicesUp $conf){'up'}else{'CHECK'}))" } else { "FAILED fail=[$gn=$failMsg]" }
            }
        } else {
            $what = if($Want){ 'encryption' } else { 'decryption' }
            if((Test-EsRegistrationFailed -ScLogs $e.Logs) -and ($e.CertApplied -or $e.ExitCode -ne 0)){ $failMsg = Get-EsNotRegisteredMsg -ExitCode $e.ExitCode -What $what }
            elseif($Want -and ($e.ExitCode -in 0,200000 -or $e.CertApplied)){ }
            elseif(-not $Want -and ($e.CertApplied -or ($e.ExitCode -in 0,100,200000))){ }
            elseif($e.ExitCode -eq 1){ $failMsg = $script:EsExit1Msg }
            elseif($Want -and $e.ExitCode -eq 100){ $failMsg = 'exit100(not authorized)' }
            elseif($Want -and $e.ExitCode -eq 300000){ $failMsg = 'exit300000(cert bound but registration failed - cert CN does not match server address; server may not start)' }
            elseif($Want -and $e.ExitCode -eq 100000){ $failMsg = 'exit100000(IDP 403 VmsAdminCredentialsNeeded - mgmt reconfig forbidden; cert may be half-applied)' }
            else { $failMsg = "exit $($e.ExitCode)" }
            if($failMsg){ $logs.Add("[$gn] $failMsg") }
            $conf = Confirm-EventServerEncryption -ComputerName (Get-VerifiedNodeAddr $Box) -Credential $Box.Cred -UseSsl:$false
            foreach($l in $conf.Logs){ $logs.Add($l) }
            $res.Ok = (-not $failMsg) -and $conf.AllServicesRunning
            $res.Status = if($res.Ok){ "$(if($Want){'Encrypted'}else{'Disabled'}): $gn (svc up)" }
                          else { "FAILED $failMsg svc=$(if($conf.AllServicesRunning){'up'}else{'CHECK: ' + (@($conf.Stopped) -join ',')})" }
        }
    } catch { $res.Status='FAILED'; $logs.Add("ERROR: $($_.Exception.Message)"); $res.Error=$_.Exception.Message }
    $res.Ended = Get-Date; $res.DurationSec = [math]::Round((New-TimeSpan -Start $t0 -End $res.Ended).TotalSeconds,1)
    $res
}

# ONE certificate for a clustered role, imported on the given nodes. Returns the thumbprint.
function New-ClusterCertificate { param([string]$Key,[object[]]$Nodes)
    $cl = Get-ClusterObj $Key; $isMs = ($Key -eq 'MS')
    $signer = Get-First -Items @(Get-ChildItem Cert:\LocalMachine\My,Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $script:SignerTp -and $_.HasPrivateKey })
    if(-not $signer){ throw "signer $($script:SignerTp) not found in cert store" }
    $cn = if($isMs){
        if(-not $cl.Address){ throw "The cluster role '$($cl.Group)' has no network name (cluster address), so the certificate name is unknown." }
        [string]$cl.Address
    } else { Resolve-CertFqdn -Target $script:EsAddr -Fqdn '' -DomainSuffix $script:DomainName }
    $cnShort = ($cn -split '\.')[0].ToLowerInvariant()
    $sans = [System.Collections.Generic.List[string]]::new()
    $addSan = { param($n) $v = ([string]$n).Trim().TrimEnd('.').ToLowerInvariant(); if($v -and $v -ne $cn -and $v -ne $cnShort -and -not $sans.Contains($v)){ [void]$sans.Add($v) } }
    & $addSan $cl.Address; & $addSan $cl.NetName
    foreach($n in @($cl.Nodes)){ & $addSan $n.Fqdn; & $addSan $n.Name }
    if($isMs){ foreach($x in @(ConvertTo-SanList $script:MsExtraSans)){ & $addSan $x } }
    $pfxPw = [securestring]::new(); foreach($ch in ([guid]::NewGuid().ToString('N')).ToCharArray()){ $pfxPw.AppendChar($ch) }; $pfxPw.MakeReadOnly()
    $pkg = New-RecorderCertificatePackage -HostName $cn -DomainSuffix $script:DomainName -Signer $signer -PfxPassword $pfxPw -OutputDir $script:OutputDir -ExtraDnsNames $sans.ToArray()
    Write-Log "Cluster certificate for '$($cl.Group)': CN=$($pkg.Fqdn), also valid for: $($sans -join ', ') [tp $($pkg.Thumbprint)]" 'Good'
    $dn = if($isMs){ $script:MsSvcDisplay } else { $script:EsSvcDisplay }
    foreach($n in @($Nodes)){
        Write-Log "[$($n.Name)] installing the cluster certificate (and trusting the signing CA)..."
        $nAddr = Get-VerifiedNodeAddr $n   # identity-checked right before the import
        if($nAddr -ne $n.Addr){ Write-Log "[$($n.Name)] importing on its own address $nAddr (verified: it answers as $($n.Target))" }
        $r = Invoke-RemoteRecorderInstall -ComputerName $nAddr -Credential $n.Cred -UseSsl:$false `
                 -PfxPath $pkg.PfxPath -PfxPassword $pfxPw -SignerCerPath $script:CaCer `
                 -InstallSignerToRoot $true -InstallSignerToIntermediate $false `
                 -EnableEncryption $false -ServerConfiguratorPath '' -ScCredential $n.Cred -CertificateGroup ''
        foreach($l in $r.Logs){ Write-Log "[$($n.Name)] $l" }
        foreach($l in @(Invoke-OnNode -Node $n.Target -Cred $n.Cred -Sb $script:KeyGrantSb -ArgumentList @($pkg.Thumbprint,$dn))){ Write-Log ([string]$l) $(if([string]$l -match 'WARNING'){'Err'}else{'Info'}) }
    }
    $pkg.Thumbprint
}

# ServerConfigurator /register on a Management Server cluster node that owns the role now:
# pause all nodes, register, resume, bring the role's resources up, wait for :9000.
function Get-MsRegisterAddress { param([bool]$Encrypted)
    $a = [string]$script:MsCluster.Address
    if(-not $a){ throw "The Management Server cluster role '$($script:MsCluster.Group)' has no network name (cluster address), so the address to register with is unknown." }
    '{0}://{1}/' -f $(if($Encrypted){'https'}else{'http'}), $a }
# ServerConfigurator /register on ONE box, as that box's credential (the admin account the wizard holds;
# the recording-server account for recorders, as for their encryption runs), through the SYSTEM-jump
# launcher in $script:ScRegisterSb. Cluster node -> node path (identity-guarded); the standalone
# Management Server -> this computer, in-process; anything else -> host path.
function Invoke-ScRegisterOn { param($Box,[string]$Address)
    $scArgs = @($Address,$Box.Cred,$script:LauncherCSharp)
    if($Box.IsNode){ return (Get-First -Items @(Invoke-OnNode -Node $Box.Target -Cred $Box.Cred -Sb $script:ScRegisterSb -ArgumentList $scArgs)) }
    if((Get-BoxKind $Box) -eq 'MS'){ return (Get-First -Items @(& $script:ScRegisterSb @scArgs)) }
    Get-First -Items @(Invoke-OnBox -Computer $Box.Addr -Cred $Box.Cred -Sb $script:ScRegisterSb -ArgumentList $scArgs)
}
# Register a cluster node of role $Key ('MS' / 'ES') that owns the role now: pause all nodes, register,
# resume, bring the role's resources up, wait for the service (MS :9000, ES :22331).
function Invoke-NodeRegister { param($Box,[string]$Address,[string]$Key='MS')
    $out = [pscustomobject]@{ Ok=$false; Detail=''; Ran=$false }
    $role = Get-StageName $Key
    Write-Log "[$($Box.Name)] Register: ServerConfigurator /register with the management server address $Address (cluster paused meanwhile)" 'Good'
    # Take the role over first: MS = services offline, then move only the address (never a plain move
    # to a node that is not registered last); ES = a plain move.
    if($Key -eq 'MS'){
        $tk = Enter-MsNode $Box
        if(-not $tk.Ok){ $out.Detail = "The Management Server role could not be taken over by $($Box.Name): $($tk.Detail)"; Write-Log $out.Detail 'Err'; [void](Invoke-ClusterOp 'MS' 'start'); Add-GuidedRow $Box 'register' $false 'register FAILED - role not taken over' $out.Detail; return $out }
    } elseif([string](Get-ClusterObj $Key).Owner -ne [string]$Box.Target){
        $mv = Move-ClusterRole $Key $Box.Target
        if(-not $mv.Ok){ $out.Detail = "The cluster role could not be moved to $($Box.Name): $($mv.Detail)"; Add-GuidedRow $Box 'register' $false 'register FAILED - role not moved' $out.Detail; return $out }
    }
    $r = $null
    $sus = Invoke-ClusterOp $Key 'suspend'
    try {
        if(-not $sus.Ok){ throw "Not every cluster node could be paused ($($sus.Detail))." }
        if($Key -eq 'MS'){
            # Settle gate, stopped path (the Management Server must not run while it is registered).
            if(Test-NodeIsLocal $Box.Target){ [void](Wait-MsIdpReady -MsFqdn $Box.Addr) } else { [void](Wait-NodeMsSettled -Box $Box -WantRunning $false) }
        }
        $out.Ran = $true
        $r = Invoke-ScRegisterOn $Box $Address
        foreach($l in @($r.Logs)){ Write-Log "[$($Box.Name)] $l" }
    } catch { $out.Detail = $(if(Test-IdentityError $_.Exception.Message){ Get-IdentityMessage $_.Exception.Message } else { Format-Err $_ }); Write-Log "[$($Box.Name)] register FAILED: $($out.Detail)" 'Err' }
    finally {
        $rs = Invoke-ClusterOp $Key 'resume'
        $resumeFail = ''
        if(-not $rs.Ok){
            $resumeFail = Get-PausedNodeText @($Key)
            if(-not $resumeFail){ $resumeFail = "Not every cluster node could be resumed ($($rs.Detail)). Open Failover Cluster Manager, right-click each paused node, Resume > Do not fail roles back." }
            Write-Log $resumeFail 'Err'
        }
        [void](Invoke-ClusterOp $Key 'start')
    }
    if($Key -eq 'MS' -and $r -and $r.Ok){ Set-MsRegistered ([string]$Box.Target) }   # registered, even if it does not come up
    if($Key -eq 'MS'){ Update-BoxStates @($Box) }
    $up = Wait-NodeService $Key $Box
    $out.Ok = ($null -ne $r) -and [bool]$r.Ok -and $up.Up -and -not $resumeFail
    if($resumeFail){ $out.Detail = $resumeFail }
    if(-not $out.Detail){ $out.Detail = "ServerConfigurator exit $(if($r){$r.ExitCode}else{'(not run)'}); $($up.Detail)" }
    Add-GuidedRow $Box 'register' $out.Ok $(if($out.Ok){"registered with $Address, $role up"}else{'register FAILED'}) $(if($out.Ok){''}else{$out.Detail})
    $out
}

# -- registration-address check (lab finding 2026-09-27) -------------------------------------------
# A Milestone server registered to a different management-server address (for example to one MS cluster
# NODE instead of the cluster address) fails every ServerConfigurator change ('Error getting management
# server uris', SC 20000 then exit 20). Source of truth on every Milestone server box: ManagementServerAddress
# in <Data Collector install dir>\appsettings.json (folder of the ImagePath of 'Milestone XProtect Data
# Collector Server'); on Event Servers also the registry value HKLM:\SOFTWARE\WOW6432Node\Milestone\XProtect
# Event Server\ManagementServerAddress. A missing file or value is skipped silently. Read over the same node
# (identity-guarded) and host paths as everything else. The fix is Milestone's documented
# 'ServerConfigurator /register /managementserveraddress=<target> /quiet'.
$script:RegFindings = @(); $script:LastRegFindings = @(); $script:FixRegistrationOn = $false
$script:RegAddrSb = {
    param([bool]$IsEs)
    $dir = 'C:\Program Files\Milestone\XProtect Data Collector Server'
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
# The management server this wizard works with: the MS cluster address, else this Management Server.
function Get-TargetMsHost { if($script:MsCluster -and $script:MsCluster.Address){ [string]$script:MsCluster.Address } else { [string]$script:MsFqdn } }
function Get-TargetMsUrl { $gb = Get-MsGateBox; '{0}://{1}/' -f $(if($gb.Encrypted -eq $true){'https'}else{'http'}), (Get-TargetMsHost) }
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
function Read-BoxRegistration { param($Box)
    $isEs = ((Get-BoxKind $Box) -eq 'ES')
    if($Box.IsNode){ return (Get-First -Items @(Invoke-OnNode -Node $Box.Target -Cred $Box.Cred -Sb $script:RegAddrSb -ArgumentList @($isEs))) }
    if((Get-BoxKind $Box) -eq 'MS'){ return (Get-First -Items @(& $script:RegAddrSb $false)) }   # the standalone MS is this computer
    Get-First -Items @(Invoke-OnBox -Computer $Box.Addr -Cred $Box.Cred -Sb $script:RegAddrSb -ArgumentList @($isEs)) }
# Loopback / own-name exemption: on a box with the Management Server service installed locally (MS node,
# standalone or all-in-one MS, or a recorder / Event Server on the MS box itself), localhost, 127.0.0.0/8,
# ::1 and the box's own computer name (short or FQDN) point to that Management Server - a match.
# EXCEPTION: a CLUSTERED Management Server node registered to its own node name stays a mismatch - that is
# exactly the bug class (the other nodes and every client work with the cluster address).
function Test-OwnBoxAddress { param([string]$Addr,$R,$Box)
    if(-not $R -or -not $R.PSObject.Properties['HasMs'] -or -not $R.HasMs){ return $false }
    $h = (Get-UrlHost $Addr).Trim('[',']')
    if(-not $h){ return $false }
    $ipObj = $null
    if($h -eq 'localhost' -or ([System.Net.IPAddress]::TryParse($h,[ref]$ipObj) -and [System.Net.IPAddress]::IsLoopback($ipObj))){ return $true }   # localhost, 127.0.0.0/8, ::1 (any notation)
    $cn = if($R.PSObject.Properties['Computer']){ ([string]$R.Computer).ToLowerInvariant() } else { '' }
    $fq = if($R.PSObject.Properties['Fqdn']){ ([string]$R.Fqdn).ToLowerInvariant() } else { '' }
    $own = $cn -and (($h -eq $cn) -or ($fq -and $h -eq $fq) -or ($h.Split('.')[0] -eq $cn))
    if(-not $own){ return $false }
    if($Box -and $Box.IsNode -and [string]$Box.ClusterKey -eq 'MS'){ return $false }
    $true }
function Get-RegFinding { param($Box,$R,[string]$TargetHost,[string]$TargetUrl)
    if(-not $R){ return $null }
    $pairs = @(@([string]$R.Address, [string]$R.Source), @([string]$R.EsAddress, 'HKLM:\SOFTWARE\WOW6432Node\Milestone\XProtect Event Server\ManagementServerAddress'))
    foreach($pair in $pairs){
        $a = [string]$pair[0]; if(-not $a){ continue }
        if(-not (Test-MsAddressMatch $a $TargetHost) -and -not (Test-OwnBoxAddress $a $R $Box)){ return [pscustomobject]@{ Box=$Box; Address=$a; Source=[string]$pair[1]; Target=$TargetUrl } }
    }
    $null }
function Get-RegFindingText { param($F) "$($F.Box.Name) is registered to management server $($F.Address), but this wizard works with $($F.Target). Changes on $($F.Box.Name) can fail, and $($F.Box.Name) loses the management server when the role runs on another node." }
# Read-only check of the given (reachable) boxes. Returns the findings; logs each one.
function Get-RegistrationMismatches { param([object[]]$Boxes)
    $out = [System.Collections.Generic.List[object]]::new()
    $th = Get-TargetMsHost
    if(-not $th){ Write-Log 'Registration check skipped: the management server address is not known.'; return }
    $tu = try { Get-TargetMsUrl } catch { "http://$th/" }
    $recs = @()
    foreach($b in @($Boxes)){
        if(-not $b.Reachable){ continue }
        if((Get-BoxKind $b) -eq 'REC'){ $recs += $b; continue }
        try { $f = Get-RegFinding $b (Read-BoxRegistration $b) $th $tu; if($f){ [void]$out.Add($f) } }
        catch { Write-Log "[$($b.Name)] registration address not read: $(Get-FirstLine $_.Exception.Message)" }
    }
    if($recs.Count){
        $res = @{}
        try { $res = Invoke-RecorderFanOut $recs $script:RegAddrSb @($false) } catch { Write-Log "Recording servers: registration addresses not read: $(Get-FirstLine $_.Exception.Message)" }
        foreach($b in $recs){ if($res.ContainsKey([string]$b.Addr)){ $f = Get-RegFinding $b $res[[string]$b.Addr] $th $tu; if($f){ [void]$out.Add($f) } } }
    }
    foreach($f in $out){ Write-Log "REGISTRATION: $(Get-RegFindingText $f) (read from $($f.Source))" 'Err' }
    if(-not $out.Count){ Write-Log "Registration check: every checked computer is registered to $tu (or records no address)." 'Good' }
    $out.ToArray()
}
# After a fix: read the box's address again until it matches (services restart meanwhile).
function Test-BoxRegistration { param($Box,[string]$TargetHost,[int]$TotalSec=90)
    $deadline = (Get-Date).AddSeconds($TotalSec); $last = 'not read'
    do {
        try {
            $r = Read-BoxRegistration $Box
            $f = Get-RegFinding $Box $r $TargetHost ''
            if(-not $f){ Write-Log "[$($Box.Name)] registration address now: $(if($r -and $r.Address){$r.Address}else{'(none recorded)'}) - OK" 'Good'; return $true }
            $last = [string]$f.Address
        } catch { $last = Get-FirstLine $_.Exception.Message }
        Wait-Ui 10
    } while((Get-Date) -lt $deadline)
    Write-Log "[$($Box.Name)] still registered to $last after the fix" 'Err'
    $false }
# Fix one box that is not a cluster node (recording server, standalone Event Server, standalone MS).
function Repair-HostRegistration { param($F)
    $b = $F.Box; $url = [string]$F.Target; $r = $null; $det = ''
    Write-Log "[$($b.Name)] registering with $url (Server Configurator /register)" 'Good'
    try { $r = Invoke-ScRegisterOn $b $url; foreach($l in @($r.Logs)){ Write-Log "[$($b.Name)] $l" } }
    catch { $det = Get-PlainReason (Format-Err $_); Write-Log "[$($b.Name)] register FAILED: $(Format-Err $_)" 'Err' }
    $ok = ($null -ne $r) -and [bool]$r.Ok
    if($ok){ $ok = Test-BoxRegistration $b (Get-UrlHost $url) }
    Add-GuidedRow $b 'fix-registration' $ok $(if($ok){"registered with $url"}else{'registration fix FAILED'}) $(if($ok){''}elseif($det){$det}else{"ServerConfigurator exit $(if($r){$r.ExitCode}else{'(not run)'}), or the address did not change"})
    $ok }
# Fix nodes of one clustered role, following the per-node pattern: role to the node, pause, register,
# resume, start, then the role goes back to the node that had it. The node that owns the role now goes
# last. Management Server: only the node registered LAST can start it (Milestone limitation), so when
# another node was registered, the original owner is registered again at the end.
function Repair-ClusterRegistrations { param([string]$Key,[object[]]$Findings)
    $cl = Get-ClusterObj $Key; [void](Update-ClusterInfo $Key)
    $orig = [string]$cl.Owner; $isMs = ($Key -eq 'MS')
    $url = [string](Get-First -Items @(@($Findings) | ForEach-Object { $_.Target })); $th = Get-UrlHost $url
    $boxes = @(@($Findings) | ForEach-Object { $_.Box })
    $order = @(@($boxes | Where-Object { [string]$_.Target -ne $orig }) + @($boxes | Where-Object { [string]$_.Target -eq $orig }))
    $ok = $true
    foreach($b in $order){
        # Invoke-NodeRegister takes the role over itself (MS: services offline first, then the move).
        $rg = Invoke-NodeRegister $b $url $Key
        if(-not $rg.Ok){ $ok = $false; Add-GuidedRow $b 'fix-registration' $false 'registration fix FAILED' $rg.Detail; break }
        if(-not (Test-BoxRegistration $b $th)){ $ok = $false; Add-GuidedRow $b 'fix-registration' $false 'still registered to a different address after Server Configurator ran'; break }
        Add-GuidedRow $b 'fix-registration' $true "registered with $url"
    }
    [void](Wait-ClusterGroupSettled $Key 300 0)
    $ob = Get-NodeBox $Key $orig
    if($isMs){
        if($ob -and [string]$script:MsLastRegistered -ne $orig){
            # Only the node registered last can start the MS: register the original owner again (fix-1 takeover).
            Write-Log "Registering $orig again so the Management Server can run there (only the node registered last can start it)." 'Good'
            $rg = Invoke-NodeRegister $ob $url 'MS'
            if(-not $rg.Ok){ $ok = $false; Move-MsToWorkingNode }
        } elseif([string]$cl.Owner -ne [string]$script:MsLastRegistered){ Move-MsToWorkingNode }
    } elseif([string]$cl.Owner -ne $orig){
        $mv = Move-ClusterRole $Key $orig
        if(-not $mv.Ok -or -not $ob){ $ok = $false; Write-Log "The cluster role '$($cl.Group)' could not be moved back to $orig. Move it in Failover Cluster Manager (Roles > right-click '$($cl.Group)' > Move > Select Node)." 'Err' }
        else { $up = Wait-NodeService $Key $ob; if(-not $up.Up){ $ok = $false } }
    }
    $ok }
function Repair-Registrations { param([object[]]$Findings)
    $f = @($Findings); $ok = $true
    foreach($x in @($f | Where-Object { -not $_.Box.IsNode })){ if(-not (Repair-HostRegistration $x)){ $ok = $false } }
    $es = @($f | Where-Object { $_.Box.IsNode -and $_.Box.ClusterKey -eq 'ES' })
    if($es.Count){ if(-not (Repair-ClusterRegistrations 'ES' $es)){ $ok = $false } }
    $ms = @($f | Where-Object { $_.Box.IsNode -and $_.Box.ClusterKey -eq 'MS' })
    if($ms.Count){ if(-not (Repair-ClusterRegistrations 'MS' $ms)){ $ok = $false } }
    $ok }
# GUI: offer the fix. Returns $true for Yes.
function Confirm-RegistrationFix { param([object[]]$Findings)
    $f = @($Findings); $tu = [string]$f[0].Target
    $l = @(); foreach($x in $f){ $l += (Get-RegFindingText $x) }
    $l += ''; $l += "Fix it now - register $((@($f | ForEach-Object { $_.Box.Name })) -join ', ') with $tu using Milestone's Server Configurator?"
    $l += ''; $l += 'What will happen:'
    foreach($k in @('ES','MS')){
        $cl = Get-ClusterObj $k
        if($cl -and @($f | Where-Object { $_.Box.IsNode -and $_.Box.ClusterKey -eq $k }).Count){
            $l += " - $(Get-StageName $k) cluster '$($cl.Group)': the role is moved to that node, all nodes are paused while Server Configurator registers it, then the nodes are resumed and the role goes back to $($cl.Owner)." }
    }
    if(@($f | Where-Object { $_.Box.IsNode -and $_.Box.ClusterKey -eq 'MS' }).Count){ $l += " - Afterwards $($script:MsCluster.Owner) is registered again too: only the Management Server node registered last can start the Management Server." }
    if(@($f | Where-Object { -not $_.Box.IsNode }).Count){ $l += ' - Other computers: Server Configurator registers them; their Milestone services restart briefly.' }
    $l += ' - The address is read again afterwards, then every check runs again. Encryption is not changed by this step.'
    $l += ''; $l += 'No = nothing is changed and the run stops here.'
    ([Windows.Forms.MessageBox]::Show(($l -join "`r`n"),'Registered to a different management server',4,'Warning')) -eq 'Yes' }
# Pre-flight with the registration fix: problems -> (offer / -FixRegistration) fix -> pre-flight again.
function Invoke-PreFlight { param([ValidateSet('on','off','register','rollback')][string]$Mode,[bool]$Want)
    $probs = @(Get-PreFlightProblems $Mode $Want)
    $f = @($script:RegFindings)
    if(-not $f.Count){ return $probs }
    $fix = if($script:Headless){ [bool]$script:FixRegistrationOn } else { [bool](Confirm-RegistrationFix $f) }
    if(-not $fix){
        if($script:Headless){ Write-Log 'Pass -FixRegistration to let the wizard register these computers with the right management server address (Server Configurator /register).' 'Err' }
        return $probs }
    Write-Log "Fixing the registration of $((@($f | ForEach-Object { $_.Box.Name })) -join ', ') ..." 'Good'
    $fixOk = Repair-Registrations $f
    Write-Log "Registration fix $(if($fixOk){'done'}else{'did NOT fully work'}) - running the pre-flight check again." $(if($fixOk){'Good'}else{'Err'})
    @(Get-PreFlightProblems $Mode $Want)
}

# One node of a clustered role: take the role over, pause the cluster, ServerConfigurator, resume,
# wait for the service, read the node's real state.
function Invoke-ClusterNodeStep { param([string]$Key,$Box,[bool]$Want,[string]$Thumbprint)
    $out = [pscustomobject]@{ Ok=$false; ScRan=$false; Why=''; Tech='' }
    $isMs = ($Key -eq 'MS'); $act = $(if($Want){'on'}else{'off'}); $role = Get-StageName $Key
    $mv = if($isMs){ Enter-MsNode $Box } else { Move-ClusterRole $Key $Box.Target }
    if(-not $mv.Ok){
        $out.Why = "The cluster role could not be moved to $($Box.Name), so nothing was changed on that node."; $out.Tech = $mv.Detail
        Add-GuidedRow $Box $act $false 'the cluster role could not be moved here - nothing changed' $mv.Detail; return $out }
    $r = $null
    $sus = Invoke-ClusterOp $Key 'suspend'
    try {
        if(-not $sus.Ok){ throw "Not every cluster node could be paused, so ServerConfigurator was NOT run on $($Box.Name). $($sus.Detail)" }
        if($isMs){
            # Settle gate, ALWAYS the stopped path (enable and disable): ServerConfigurator runs with the
            # Management Server stopped - proven safe on a cluster node (the IIS-hosted IDP answers).
            Set-StageStatus 'MS' "$($Box.Name): making sure the Management Server service is stopped..." 'Work'
            if(Test-NodeIsLocal $Box.Target){ [void](Wait-MsIdpReady -MsFqdn $Box.Addr) }
            else { [void](Wait-NodeMsSettled -Box $Box -WantRunning $false) }
        }
        Set-StageStatus $Key "$($Box.Name): ServerConfigurator is running (turn encryption $($act.ToUpper()))..." 'Work'
        $r = Invoke-NodeSc -Key $Key -Box $Box -Want $Want -Thumbprint $Thumbprint
        $out.ScRan = $true
        # Registered? (SC success, or its 'Registration done' log marker) -> this node is now the one that can start the MS.
        if($isMs -and ($r.Ok -or @(@($r.Logs) | Where-Object { [string]$_ -match 'Registration done with result = Success' }).Count)){ Set-MsRegistered ([string]$Box.Target) }
    } catch { $out.Why = Get-PlainReason (Format-Err $_); $out.Tech = Format-Err $_ }
    finally {
        $rs = Invoke-ClusterOp $Key 'resume'
        $resumeFail = ''
        if(-not $rs.Ok){
            $resumeFail = Get-PausedNodeText @($Key)
            if(-not $resumeFail){ $resumeFail = "Not every cluster node could be resumed ($($rs.Detail)). Open Failover Cluster Manager, right-click each paused node, Resume > Do not fail roles back." }
            Write-Log $resumeFail 'Err'
        }
        [void](Invoke-ClusterOp $Key 'start')
    }
    if($resumeFail){
        if($r){ Add-RunResult $r; foreach($l in $r.Logs){ Write-Log "[$($r.Target)] $l" } }
        Add-GuidedRow $Box $act $false 'cluster node(s) still paused - stopped' $resumeFail
        $out.Why = $resumeFail; $out.Tech = $rs.Detail; return $out }
    if(-not $r){
        if(-not $out.Why){ $out.Why = "ServerConfigurator could not be run on $($Box.Name)." }
        Add-GuidedRow $Box $act $false 'ServerConfigurator not run' $out.Tech; return $out }
    Add-RunResult $r
    foreach($l in $r.Logs){ Write-Log "[$($r.Target)] $l" }
    Write-Log "[$($r.Target)] $(if($r.Ok){'OK'}else{'FAILED'}): $($r.Status)" $(if($r.Ok){'Good'}else{'Err'})
    Set-StageStatus $Key "$($Box.Name): waiting for the $role service to come back..." 'Work'
    $up = if($isMs){ Wait-NodeService $Key $Box -Port $(if($Want){ 9000 } else { 80 }) } else { Wait-NodeService $Key $Box }
    $gt = Confirm-BoxStates @($Box) $Want -TotalSec $(if($isMs){300}else{180})
    if($r.Ok -and $gt -and $up.Up){ $out.Ok = $true; return $out }
    $out.Why = if(-not $r.Ok){ Get-PlainReason "$($r.Status) $($r.Error)" }
               elseif(-not $gt){ "ServerConfigurator reported success, but $($Box.Name) still reports: $(Get-StateText $Box)." }
               elseif(Test-IdentityError $up.Detail){ $up.Detail }
               else { "The $role service did not come back up on $($Box.Name): $($up.Detail)." }
    $out.Tech = "$($r.Status) $($r.Error) | $($up.Detail)"
    $out
}

# The per-node loop for a clustered role. $Todo = the node boxes to change. The node that should own
# the role at the end (the owner now, or the snapshot owner during a rollback) goes LAST.
function Invoke-ClusterStage { param([string]$Key,[bool]$Want,[object[]]$Todo)
    $cl = Get-ClusterObj $Key; $isMs = ($Key -eq 'MS'); $role = Get-StageName $Key
    $wt = $(if($Want){'ON'}else{'OFF'}); $act = $(if($Want){'on'}else{'off'})
    [void](Update-ClusterInfo $Key)
    $final = if($script:FinalOwners.ContainsKey($Key) -and $script:FinalOwners[$Key]){ [string]$script:FinalOwners[$Key] } else { [string]$cl.Owner }
    $order = @(@($Todo | Where-Object { [string]$_.Target -ne $final }) + @($Todo | Where-Object { [string]$_.Target -eq $final }))
    Write-Log "Cluster role '$($cl.Group)': $($order.Count) node(s) are configured one by one: $((@($order | ForEach-Object { $_.Name })) -join ', then '). Each node briefly takes over the role while it is configured. The role ends on $final."
    $tp = ''
    if($Want){
        Set-StageStatus $Key 'Creating and installing the cluster certificate...' 'Work'
        try { $tp = New-ClusterCertificate $Key $Todo }
        catch {
            foreach($b in $Todo){ Add-GuidedRow $b $act $false 'cluster certificate could not be installed - nothing changed' (Format-Err $_) }
            Set-StageStatus $Key 'FAILED - certificate' 'Bad'
            $certWhy = if(Test-IdentityError $_.Exception.Message){ "$(Get-IdentityMessage $_.Exception.Message) The certificate was not installed there and ServerConfigurator was not run, so encryption was not changed." }
                       else { 'The certificate for the cluster could not be created or installed on every node. ServerConfigurator was not run, so encryption was not changed.' }
            Set-RunFailure $role $cl.Group $certWhy (Format-Err $_) 'Check that every cluster node is reachable by its own name or its own IP address and that the signing CA is on this computer, then try again.'
            return $false
        }
    }
    $failed = $null; $i = 0
    foreach($n in $order){
        $i++
        if(-not $isMs){
            # Order check again, right before THIS Event Server node: the Management Server must still be unencrypted.
            $gb = Get-MsGateBox
            if($gb.Encrypted -ne $false){
                $why = "Stopped before Event Server node $($n.Name): the Management Server is $(if($gb.Encrypted){'encrypted now'}else{'in an unknown state now'}) (checked on $($gb.Name)). The Event Server can only be changed while the Management Server is NOT encrypted."
                Add-GuidedRow $n $act $false 'blocked by order check' $why
                $failed = [pscustomobject]@{ Box=$n; Why=$why; Tech=$gb.Detail }; break }
        }
        Set-StageStatus $Key "Node $i of $($order.Count): $($n.Name) - taking over the role..." 'Work'
        $st = Invoke-ClusterNodeStep -Key $Key -Box $n -Want $Want -Thumbprint $tp
        if(-not $st.Ok){ $failed = [pscustomobject]@{ Box=$n; Why=$st.Why; Tech=$st.Tech }; break }
    }
    if(-not $failed -and -not @($Todo | Where-Object { [string]$_.Target -eq $final }).Count){
        # The node that should own the role was already in the wanted state: the role goes back there.
        $fb = Get-NodeBox $Key $final
        if(-not $fb){ $failed = [pscustomobject]@{ Box=$order[-1]; Why="The node $final is not known, so the role could not be moved back."; Tech='' } }
        elseif($isMs -and [string]$script:MsLastRegistered -ne $final){
            # Only the Management Server node registered LAST can start (Milestone limitation): register the
            # final owner again - takeover with the services offline, then ServerConfigurator /register.
            Set-StageStatus $Key "Registering $final again so the Management Server can run there..." 'Work'
            Update-BoxStates @($fb)
            try { $rg = Invoke-NodeRegister $fb (Get-MsRegisterAddress ($fb.Encrypted -eq $true)) }
            catch { $rg = [pscustomobject]@{ Ok=$false; Detail=(Format-Err $_) } }
            if(-not $rg.Ok){ $failed = [pscustomobject]@{ Box=$fb; Why="The Management Server could not be registered again on $final after the other node(s) were configured."; Tech=$rg.Detail } }
        } else {
            Set-StageStatus $Key "Moving the role back to $final..." 'Work'
            $mv = Move-ClusterRole $Key $final
            if(-not $mv.Ok){ $failed = [pscustomobject]@{ Box=$fb; Why="The cluster role could not be moved back to $final."; Tech=$mv.Detail } }
            else {
                if($isMs){ [void](Invoke-ClusterOp 'MS' 'start'); Update-BoxStates @($fb) }
                $up = Wait-NodeService $Key $fb
                if(-not $up.Up){ $failed = [pscustomobject]@{ Box=$fb; Why="The $role did not come back up on $final."; Tech=$up.Detail } }
            }
        }
    }
    if($failed){
        if($isMs){
            # Never leave (or put) the MS role on a node that cannot start it: go to the node registered last.
            Move-MsToWorkingNode
        } else {
            [void](Wait-ClusterGroupSettled $Key 300 0)
            if([string]$cl.Owner -ne $final){
                Write-Log "Trying to leave the role '$($cl.Group)' on $final, where it was before..." 'Err'
                $mv = Move-ClusterRole $Key $final
                $fb = Get-NodeBox $Key $final
                if($mv.Ok -and $fb){ [void](Wait-NodeService $Key $fb) }
            }
        }
        Set-StageStatus $Key "FAILED on $($failed.Box.Name)" 'Bad'
        $next = if($null -ne $script:Scope){ 'Fix the problem above and start the rollback again (it only changes what still differs).' }
                else { "Click 'Undo this run (roll back)' to undo what this run changed, or fix the problem and click 'Turn encryption $wt' again." }
        if($isMs){ $next += " If the Management Server does not start on the node that has the role now, run 'Re-register this node' on that node." }
        Set-RunFailure $role $failed.Box.Name $failed.Why $failed.Tech $next
        return $false
    }
    [void](Update-ClusterInfo $Key)
    Set-StageStatus $Key "Done - encryption $wt on $(@($Todo).Count) cluster node(s); the role is on $($cl.Owner)" 'Good'
    $true
}

# -- Milestone Administrators role check (pre-flight, needs MilestonePSTools) ---------------------
# ServerConfigurator stops with exit 100 'not authorized' when the run-as account is not in the
# Milestone Administrators role. Best effort: blocks ONLY when the role members were read and neither
# the account nor any group it is in (domain groups, and the local Administrators group when the role
# contains it) is a member. Anything that cannot be checked is logged and does not block.
$script:HasPsTools = $null
function Test-HasPsTools { if($null -eq $script:HasPsTools){ $script:HasPsTools = [bool](Get-Module -ListAvailable -Name MilestonePSTools) }; $script:HasPsTools }
$script:PsToolsConfirmLine = " - The admin account must be in the Milestone Administrators role - otherwise the change stops with 'not authorized' on the first server. (MilestonePSTools is not installed here, so this cannot be checked in advance.)"
function Get-MilestoneAdminProblem {
    if(-not (Test-HasPsTools)){ Write-Log 'Milestone Administrators role: not checked (MilestonePSTools is not installed on this computer).'; return '' }
    $user = [string]$script:AdminCred.UserName
    $sids = @()
    try { $sids += (New-Object Security.Principal.NTAccount($user)).Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { Write-Log "Milestone Administrators role: not checked ($user could not be resolved to a SID)." 'Err'; return '' }
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $nc = $script:AdminCred.GetNetworkCredential()
        $ct = if($nc.Domain -and $nc.Domain -ne '.' -and $nc.Domain -ne $env:COMPUTERNAME){ [System.DirectoryServices.AccountManagement.ContextType]::Domain } else { [System.DirectoryServices.AccountManagement.ContextType]::Machine }
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ct)
        $up = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, $user)
        if($up){ foreach($g in @($up.GetAuthorizationGroups())){ try { $sids += [string]$g.Sid.Value } catch {} } }
    } catch { Write-Log "Milestone Administrators role: the groups of $user could not be read ($(Get-FirstLine $_.Exception.Message)) - checking direct membership only." }
    try { Import-Module MilestonePSTools -ErrorAction Stop } catch { Write-Log "Milestone Administrators role: not checked (MilestonePSTools did not load: $(Get-FirstLine $_.Exception.Message))." 'Err'; return '' }
    $hosts = @()
    if($script:MsCluster -and $script:MsCluster.Address){ $hosts += [string]$script:MsCluster.Address }
    if($script:MsFqdn){ $hosts += [string]$script:MsFqdn }
    $hosts += $env:COMPUTERNAME
    $cands = @(); foreach($h in ($hosts | Select-Object -Unique)){ $cands += "https://$h" }; foreach($h in ($hosts | Select-Object -Unique)){ $cands += "http://$h" }
    $connected = $false
    foreach($u in $cands){
        try { Connect-Vms -ServerAddress ([uri]$u) -Credential $script:AdminCred -AcceptEula -ErrorAction Stop | Out-Null; $connected = $true; break } catch {}
    }
    if(-not $connected){ Write-Log 'Milestone Administrators role: not checked (could not connect to the VMS with the admin account).' 'Err'; return '' }
    $memSids = @()
    try {
        $roles = @(Get-VmsRole -ErrorAction Stop | Where-Object { [string]$_.Name -eq 'Administrators' -or ([string]$_.PSObject.Properties['RoleType'].Value) -match 'Adm' })
        foreach($r in $roles){ foreach($m in @(Get-VmsRoleMember -Role $r -ErrorAction Stop)){ if($m.PSObject.Properties['Sid'] -and $m.Sid){ $memSids += [string]$m.Sid } } }
    } catch { Write-Log "Milestone Administrators role: members could not be read ($(Get-FirstLine $_.Exception.Message)) - not checked." 'Err'; return '' }
    finally { Disconnect-ManagementServer -ErrorAction SilentlyContinue }
    if(-not $memSids.Count){ Write-Log 'Milestone Administrators role: no members could be read - not checked.' 'Err'; return '' }
    if(@($sids | Where-Object { $memSids -contains $_ }).Count){ Write-Log "Milestone Administrators role: $user is a member (directly or through a group)." 'Good'; return '' }
    if($memSids -contains 'S-1-5-32-544'){
        try {
            $loc = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.SID.Value })
            if(@($sids | Where-Object { $loc -contains $_ }).Count){ Write-Log "Milestone Administrators role: $user is a member through the local Administrators group." 'Good'; return '' }
        } catch { Write-Log "Milestone Administrators role: the local Administrators group could not be read - not checked." 'Err'; return '' }
    }
    "The admin account $user is not in the Milestone Administrators role. ServerConfigurator would stop with 'not authorized' on the first server. Add the account (or a group it is in) in Management Client > Security > Roles > Administrators, then try again."
}

# -- pre-flight: before ANY change. Returns plain-language problems; empty = OK to go. -------------
function Get-PreFlightProblems { param([ValidateSet('on','off','register','rollback')][string]$Mode,[bool]$Want)
    $p = [System.Collections.Generic.List[string]]::new()
    Write-Log "PRE-FLIGHT CHECK ($Mode) - nothing is changed until it passes" 'Good'
    if($script:MsDetectError){ $p.Add("Could not check whether this Management Server is part of a Windows failover cluster: $($script:MsDetectError)") }
    if($Mode -ne 'register' -and $script:EsBox -and $script:EsDetectError){ $p.Add("Could not check whether the Event Server ($($script:EsAddr)) is part of a Windows failover cluster (a cluster = several computers that take turns running the same server): $($script:EsDetectError)") }
    foreach($k in @('MS','ES')){
        if($Mode -eq 'register' -and $k -eq 'ES'){ continue }
        $cl = Get-ClusterObj $k; if(-not $cl){ continue }
        [void](Update-ClusterInfo $k)
        if($cl.Error){ $p.Add("The state of cluster role '$($cl.Group)' ($(Get-StageName $k)) could not be read: $($cl.Error)"); continue }
        foreach($n in @($cl.Nodes)){
            $st = [string]$n.State
            if($st -ne 'Up' -and $Mode -eq 'register' -and -not (Test-NodeIsLocal ([string]$n.Name))){
                # Register is the repair path after a failover: a Paused / Down peer must not block it.
                Write-Log "$($n.Name) is $st - it is left as it is; it cannot take over until it is registered again."
                continue }
            if($st -ne 'Up'){
                $how = if($st -eq 'Paused'){ "In Failover Cluster Manager > Nodes, right-click $($n.Name) > Resume > Do Not Fail Roles Back." } else { "Start that computer (or its cluster service) so it shows 'Up' in Failover Cluster Manager > Nodes." }
                $p.Add("Cluster node $($n.Name) ($(Get-StageName $k)) is '$st'. Every node must be 'Up' (a 'Paused' node is on hold and cannot take over). $how")
            }
        }
        # W10: register and rollback are both RECOVERY paths, so the role-health check (Failed / Offline /
        # PartialOnline) is skipped for them on purpose - a role that needs recovering is expected to be
        # unhealthy. Register still refuses when this node does not own the role (Invoke-RegisterActionCore),
        # rollback still requires every node Up (above), and a clustered MS takeover (Enter-MsNode) does not
        # need the Management Server itself to be running.
        if($Mode -ne 'register' -and $Mode -ne 'rollback'){ $h = Get-ClusterHealthProblem $cl; if($h){ $p.Add($h) } }
    }
    if($Mode -ne 'register'){ $a = Get-MilestoneAdminProblem; if($a){ $p.Add($a) } }
    # Register touches THIS node only (a peer may be Paused or Down); every other mode checks all boxes.
    $boxes = @(if($Mode -eq 'register'){ @(Get-MsBoxes | Where-Object { -not $_.IsNode -or (Test-NodeIsLocal ([string]$_.Target)) }) } else { @(Get-MsBoxes) })
    if($Mode -ne 'register'){ $boxes += @(Get-EsBoxes); $boxes += @($script:RecBoxes | Where-Object { -not $_.Excluded -and (Test-InScope $_) }) }
    Update-BoxStates $boxes
    foreach($b in $boxes){
        # W9/W4: an Unknown state (netsh unreadable, or RecorderConfig.xml AND the bindings both unusable)
        # is a pre-flight problem on EVERY box kind, including recorders - never silently treated as "not
        # encrypted". Before the first change, every box the action may change must be Reachable with a
        # known state.
        if(-not $b.Reachable){ $p.Add("Cannot connect to $($b.Name) ($(Get-RoleText $b)): $($b.Detail). Make sure it is switched on and WinRM (PowerShell remoting) is enabled.") }
        elseif($null -eq $b.Encrypted){ $p.Add("Could not read the encryption state of $($b.Name) ($(Get-RoleText $b)): $($b.Detail)") }
    }
    # W1: ServerConfigurator.exe must exist at the engine's fixed install path on every target that would
    # actually run it in this action (register always runs it on the local node; on/off/rollback run it on
    # every reachable box that still needs to change). Otherwise refuse and change nothing.
    $scTargets = if($Mode -eq 'register'){ @($boxes | Where-Object { $_.Reachable }) }
                 else { @($boxes | Where-Object { $_.Reachable -and (Test-InScope $_) -and $_.Encrypted -ne $Want }) }
    foreach($m in @(Get-ScMissingProblem $scTargets)){ $p.Add($m) }
    # Registered to a different management server? Read-only here; Invoke-PreFlight offers the fix.
    $script:RegFindings = @(Get-RegistrationMismatches @($boxes | Where-Object { $_.Reachable }))
    if($Mode -eq 'register'){
        # This node is registered by the register action itself, with the right address.
        foreach($x in @($script:RegFindings | Where-Object { $_.Box.IsNode -and (Test-NodeIsLocal $_.Box.Target) })){ Write-Log "$($x.Box.Name): the register action itself registers this node with the right address." }
        $script:RegFindings = @($script:RegFindings | Where-Object { -not ($_.Box.IsNode -and (Test-NodeIsLocal $_.Box.Target)) })
    }
    foreach($x in @($script:RegFindings)){ $p.Add((Get-RegFindingText $x)) }
    if($Want -and $Mode -ne 'register'){
        $needs = @($boxes | Where-Object { (Test-InScope $_) -and $_.Encrypted -ne $true })
        if($needs.Count){
            $script:SignerStoreRadio.Checked = $true
            try {
                $signer = Resolve-Signer; Write-Log "Signer: $($signer.Subject) [$($signer.Thumbprint)]"
                $script:SignerTp = $signer.Thumbprint
                $script:CaCer = Join-Path $script:OutputDir 'MilestoneCA.cer'; Export-Certificate -Cert $signer -FilePath $script:CaCer -Type CERT -Force | Out-Null
            } catch {
                Write-Log "Signer lookup failed: $(Format-Err $_)" 'Err'
                $p.Add("The signing CA '$($script:SignerSubjectBox.Text)' (the certificate authority that signs the new certificates) was not found on this computer. Go back to step 1 and check its name. Create a new one only if encryption was never set up in this system.")
            }
        }
    }
    foreach($x in $p){ Write-Log "PRE-FLIGHT PROBLEM: $x" 'Err' }
    if(-not $p.Count){ Write-Log 'PRE-FLIGHT CHECK passed' 'Good' }
    $p.ToArray()   # unrolled on purpose: callers wrap in @()
}
function Add-NoteRow { param([string]$Act,[bool]$Ok,[string]$Status,[string]$Err='')
    $now = Get-Date
    [void]$script:RunResults.Add([pscustomobject]@{
        HostKey='(run)'; Fqdn=''; Success=$Ok; Status=$Status; Thumbprint=''; Error=$Err; CertificateGroup=''; Action=$Act
        Started=$now; Ended=$now; DurationSec=0.0 }) }

# Paused cluster nodes left behind are a failure: a paused node can never take the role over.
function Get-PausedNodeInfo { param([string[]]$Keys=@('MS','ES'))
    $ours=@(); $before=@()
    foreach($k in $Keys){
        $cl=Get-ClusterObj $k; if(-not $cl){ continue }
        [void](Update-ClusterInfo $k)
        foreach($n in @($cl.Nodes)){
            if([string]$n.State -ne 'Paused'){ continue }
            if(Test-PausedByRun $k ([string]$n.Name)){ $ours += "Node $($n.Name) is still paused. Open Failover Cluster Manager, right-click the node, Resume > Do not fail roles back." }
            else { $before += "Node $($n.Name) is paused (it was already paused before this run - resume it when you are ready: Resume > Do not fail roles back)." }
        }
    }
    [pscustomobject]@{ Ours=((@($ours | Select-Object -Unique)) -join "`r`n"); Before=((@($before | Select-Object -Unique)) -join "`r`n") } }
# Nodes THIS run paused and could not resume (a failure). Nodes paused before the run do not count.
function Get-PausedNodeText { param([string[]]$Keys=@('MS','ES')) [string](Get-PausedNodeInfo $Keys).Ours }
$script:PausedBeforeNote = ''
function Test-FinalPausedGuard { param([string]$Act)
    $pi = Get-PausedNodeInfo
    $script:PausedBeforeNote = [string]$pi.Before
    if($pi.Before){ Write-Log $pi.Before; Add-NoteRow $Act $true 'cluster node(s) paused before the run - left as they are' $pi.Before }
    $t = [string]$pi.Ours
    if(-not $t){ return $true }
    Write-Log "PAUSED CLUSTER NODE(S) after the run: $t" 'Err'
    Add-NoteRow $Act $false 'cluster node(s) still paused after the run' $t
    if($script:RunFailure){ $script:RunFailure.Reason = "$($script:RunFailure.Reason)`r`n`r`nALSO: $t" }
    else { Set-RunFailure 'Cluster check after the run' 'cluster nodes' $t '' 'Resume the paused node(s) as described above, then click Check again.' }
    $false }

# Support detail for an unexpected error: goes to the LOG only (never to the operator's message).
function Write-ErrorTrace { param($ErrRec)
    try {
        $st = [string]$ErrRec.ScriptStackTrace
        if($st){ Write-Log "  script stack: $(($st -split "`r?`n" | Where-Object { $_ }) -join ' <- ')" 'Err' }
        $pm = if($ErrRec.InvocationInfo){ [string]$ErrRec.InvocationInfo.PositionMessage } else { '' }
        if($pm){ Write-Log "  position: $(($pm -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' | ')" 'Err' }
    } catch {}
}

# -- snapshot + rollback ------------------------------------------------------------------------
function Save-Snapshot { param([string]$Act)
    try {
        if(-not (Test-Path -LiteralPath $script:RunsDir)){ [void](New-Item -ItemType Directory -Path $script:RunsDir -Force) }
        $path = Join-Path $script:RunsDir ("run-{0:yyyyMMdd-HHmmss}-snapshot.json" -f (Get-Date))
        $roles = @(foreach($k in @('MS','ES')){ $cl = Get-ClusterObj $k; if($cl){ [ordered]@{ Key=$k; Group=$cl.Group; Owner=$cl.Owner; Address=$cl.Address } } })
        $boxes = @(foreach($b in @(Get-AllBoxes)){
            [ordered]@{ Kind=(Get-BoxKind $b); Role=$b.Role; Name=$b.Name; Target=$b.Target; Addr=$b.Addr; IsNode=[bool]$b.IsNode; ClusterKey=$b.ClusterKey
                        Active=[bool]$b.Active; Encrypted=$b.Encrypted; State=(Get-StateText $b); Excluded=[bool]$b.Excluded } })
        $o = [ordered]@{ Tool='Mrc-Guided'; Version=1; Created=(Get-Date).ToString('s'); Action=$Act; Computer=$env:COMPUTERNAME; Domain=$script:DomainName
                         EsHost=$(if($script:EsBox){ $script:EsAddr } else { '' }); NoEventServer=[bool](-not $script:EsBox); Roles=$roles; Boxes=$boxes }
        ($o | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $path -Encoding UTF8
        $script:LastSnapshotPath = $path
        Write-Log "State before the run saved (for rollback): $path" 'Good'
        return $true
    } catch { $script:LastSnapshotPath = ''; Write-Log "The state file for rollback could not be written: $($_.Exception.Message)" 'Err'; return $false }
}
function Read-Snapshot { param([string]$Path)
    if([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)){ throw "The snapshot file was not found: $Path" }
    $bad = "This state file is from a different version or damaged; rollback cannot use it: $Path"
    try { $s = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } catch { throw $bad }
    # Every property the rollback reads must exist (a value may be null), on the file and on each entry.
    $has = { param($o,[string[]]$Names) if($null -eq $o){ return $false }; foreach($n in $Names){ if(-not $o.PSObject.Properties[$n]){ return $false } }; $true }
    if(-not (& $has $s @('Tool','Version','Created','Action','Domain','EsHost','NoEventServer','Roles','Boxes'))){ throw $bad }
    if([string]$s.Tool -ne 'Mrc-Guided' -or [string]$s.Version -ne '1' -or [string]$s.Action -notin 'on','off'){ throw $bad }
    foreach($b in @($s.Boxes)){
        if(-not (& $has $b @('Kind','Role','Name','Target','Addr','IsNode','ClusterKey','Encrypted'))){ throw $bad }
        if([string]$b.Kind -notin 'MS','ES','REC' -or -not [string]$b.Addr){ throw $bad }
        if($null -ne $b.Encrypted -and $b.Encrypted -isnot [bool]){ throw $bad }
    }
    foreach($r in @($s.Roles)){
        if(-not (& $has $r @('Key','Group','Owner','Address'))){ throw $bad }
        if([string]$r.Key -notin 'MS','ES' -or -not [string]$r.Owner){ throw $bad }
    }
    $s
}
# What a rollback would change NOW: boxes this run moved away from the snapshot state (in the run's
# direction only), and cluster roles no longer on their snapshot owner.
function Get-RollbackPlan { param($Snap)
    $want = ([string]$Snap.Action -ne 'on')
    $changed = @(); $missing = @(); $moves = @()
    foreach($sb in @($Snap.Boxes)){
        if($null -eq $sb.Encrypted -or [bool]$sb.Encrypted -ne $want){ continue }
        # W8: MS is matched by node (Target), ES/REC by host (Addr) - same canonical key Get-BoxScopeKey uses.
        $hostKey = if([string]$sb.Kind -eq 'MS'){ [string]$sb.Target } else { [string]$sb.Addr }
        $cur = Find-Box ([string]$sb.Kind) $hostKey
        if(-not $cur){ $missing += [string]$sb.Name; continue }
        if($cur.Encrypted -eq (-not $want)){ $changed += $cur }
    }
    foreach($r in @($Snap.Roles)){ $cl = Get-ClusterObj ([string]$r.Key); if($cl -and [string]$cl.Owner -ne [string]$r.Owner){ $moves += $r } }
    [pscustomobject]@{ Want=$want; Changed=$changed; Missing=$missing; Moves=$moves }
}
function Test-RollbackUseful {
    if(-not $script:LastSnapshotPath -or -not (Test-Path -LiteralPath $script:LastSnapshotPath)){ return $false }
    try { $p = Get-RollbackPlan (Read-Snapshot $script:LastSnapshotPath); return ((@($p.Changed).Count -gt 0) -or (@($p.Moves).Count -gt 0)) } catch { return $false }
}
# Move each cluster role back to its snapshot owner. A Management Server that does not come up there
# (the known registration limitation) is registered again on that node.
function Restore-RoleOwners { param($Snap)
    $ok = $true
    Set-StageStatus 'ROLE' 'Checking...' 'Work'
    foreach($r in @($Snap.Roles)){
        $k = [string]$r.Key; $cl = Get-ClusterObj $k
        if(-not $cl){ $ok = $false; Set-RunFailure 'Move cluster roles back' ([string]$r.Group) "The snapshot has cluster role '$($r.Group)', but it is not detected as a cluster now." '' 'Go back to step 1 and check the computers.'; continue }
        [void](Update-ClusterInfo $k)
        if([string]$cl.Owner -eq [string]$r.Owner){ Write-Log "Cluster role '$($cl.Group)' is already on $($r.Owner), as before the run." 'Good'; continue }
        Set-StageStatus 'ROLE' "Moving '$($cl.Group)' back to $($r.Owner)..." 'Work'
        $box = Get-NodeBox $k ([string]$r.Owner)
        if(-not $box){ $ok = $false; Set-RunFailure 'Move cluster roles back' ([string]$r.Owner) "The node $($r.Owner) of cluster role '$($cl.Group)' is not known now." '' 'Go back to step 1 and check the computers.'; continue }
        if($k -eq 'MS' -and [string]$script:MsLastRegistered -ne [string]$r.Owner){
            # The original owner is not the node registered last, so it cannot start the Management Server:
            # register it (takeover with the services offline first), which makes it the working node.
            Write-Log "$($r.Owner) is not the Management Server node registered last ($($script:MsLastRegistered) is). Registering $($r.Owner) again so it can run the Management Server..." 'Good'
            Update-BoxStates @($box)
            try { $rg = Invoke-NodeRegister $box (Get-MsRegisterAddress ($box.Encrypted -eq $true)); $up = [pscustomobject]@{ Up=[bool]$rg.Ok; Detail=$rg.Detail } }
            catch { $up = [pscustomobject]@{ Up=$false; Detail=(Format-Err $_) } }
            if(-not $up.Up){ Move-MsToWorkingNode }
        } else {
            $mv = Move-ClusterRole $k ([string]$r.Owner)
            if(-not $mv.Ok){ $ok = $false; Set-RunFailure 'Move cluster roles back' ([string]$r.Owner) "The cluster role '$($cl.Group)' could not be moved back to $($r.Owner)." $mv.Detail "Move it in Failover Cluster Manager (Roles > right-click '$($cl.Group)' > Move > Select Node)."; if($k -eq 'MS'){ Move-MsToWorkingNode }; continue }
            if($k -eq 'MS'){ [void](Invoke-ClusterOp 'MS' 'start'); Update-BoxStates @($box) }
            $up = Wait-NodeService $k $box
        }
        if(-not $up.Up){ $ok = $false; Set-RunFailure 'Move cluster roles back' ([string]$r.Owner) "The role '$($cl.Group)' is back on $($r.Owner), but the $(Get-StageName $k) did not come up there." $up.Detail $(if($k -eq 'MS'){"On $($r.Owner), run this wizard and click 'Re-register this node'."}else{"Check the Event Server service on $($r.Owner)."}) }
    }
    Set-StageStatus 'ROLE' $(if($ok){'Done - roles are where they were before'}else{'FAILED'}) $(if($ok){'Good'}else{'Bad'})
    $ok
}

# -- failover self-test: move each clustered role to every other node and back ---------------------
function Invoke-FailoverTest {
    $res = [System.Collections.Generic.List[object]]::new()
    Set-StageStatus 'FT' 'Working...' 'Work'
    foreach($k in @('MS','ES')){
        $cl = Get-ClusterObj $k; if(-not $cl){ continue }
        [void](Update-ClusterInfo $k)
        $orig = [string]$cl.Owner; $role = Get-StageName $k; $moved = $false
        # Management Server: the node registered last must end up owning the role.
        if($k -eq 'MS' -and $script:MsLastRegistered){ $orig = [string]$script:MsLastRegistered }
        foreach($n in @(Get-NodeBoxes $k | Where-Object { [string]$_.Target -ne $orig })){
            if($k -eq 'MS' -and [string]$n.Target -ne [string]$script:MsLastRegistered){
                # Known to fail AND it takes the Management Server down: not tested.
                $det = "skipped - $($n.Name) cannot take over until it is re-registered (known Milestone limitation, see IMPORTANT)"
                [void]$res.Add([pscustomobject]@{ Key=$k; Role=$role; Node=[string]$n.Name; Ok=$true; Skipped=$true; Detail=$det; Back=$false })
                Add-GuidedRow $n 'failover-test' $true "failover test: $det"; continue }
            Set-StageStatus 'FT' "$($role): moving the role to $($n.Name) and waiting for the service..." 'Work'
            $mv = Move-ClusterRole $k $n.Target; $moved = $true
            if($mv.Ok){ $up = Wait-NodeService $k $n; $okN = [bool]$up.Up; $det = $up.Detail } else { $okN = $false; $det = "the role could not be moved there: $($mv.Detail)" }
            [void]$res.Add([pscustomobject]@{ Key=$k; Role=$role; Node=[string]$n.Name; Ok=$okN; Skipped=$false; Detail=$det; Back=$false })
            Add-GuidedRow $n 'failover-test' $okN $(if($okN){'failover test: took over the role, service up'}else{"failover test: FAILED - $det"})
        }
        if(-not $moved -and [string]$cl.Owner -eq $orig){ continue }
        $ob = Get-NodeBox $k $orig
        Set-StageStatus 'FT' "$($role): moving the role back to $orig..." 'Work'
        $mv = Move-ClusterRole $k $orig
        if($mv.Ok -and $ob){ $up = Wait-NodeService $k $ob; $okB = [bool]$up.Up; $det = $up.Detail } else { $okB = $false; $det = "the role could not be moved back: $($mv.Detail)" }
        # W7: each tested role must end up back on its original owner and live; if it is not, try the move
        # back ONCE more before reporting - bounded, not an infinite retry loop.
        if(-not $okB){
            Write-Log "$($role): not back and live on $orig after the failover test - trying the move back once more..." 'Err'
            $mv2 = Move-ClusterRole $k $orig
            if($mv2.Ok -and $ob){ $up2 = Wait-NodeService $k $ob; $okB = [bool]$up2.Up; $det = $up2.Detail } else { $det = "the role could not be moved back (retry): $($mv2.Detail)" }
        }
        [void]$res.Add([pscustomobject]@{ Key=$k; Role=$role; Node=$orig; Ok=$okB; Skipped=$false; Detail=$det; Back=$true })
        if($ob){ Add-GuidedRow $ob 'failover-test' $okB $(if($okB){'failover test: role back on the original node, service up'}else{"failover test: FAILED after moving back - $det"}) }
    }
    $script:FailoverResults = $res.ToArray()
    $bad = @($res | Where-Object { -not $_.Ok })
    $skip = @($res | Where-Object { $_.Skipped })
    Set-StageStatus 'FT' $(if($bad.Count){"Done - $($bad.Count) node(s) did not take over (see the result page)"}elseif($skip.Count){"Done - tested nodes took over; $($skip.Count) skipped (see the result page)"}else{'Done - every node took over'}) $(if($bad.Count){'Bad'}else{'Good'})
}

# Plain-language cluster lines for the Check page.
function Get-ClusterSummary {
    $l = @()
    if($script:MsCluster){ $c=$script:MsCluster; $l += "Management Server: cluster role '$($c.Group)' at $($c.Address) ($(@($c.Nodes).Count) nodes: $(Format-NodeList $c))." }
    elseif($script:MsDetectError){ $l += "Management Server: could not check for a cluster - $($script:MsDetectError)" }
    else { $l += "Management Server: a single server ($env:COMPUTERNAME), not a cluster." }
    if($script:EsCluster){ $c=$script:EsCluster; $l += "Event Server: cluster role '$($c.Group)' at $($c.Address) ($(@($c.Nodes).Count) nodes: $(Format-NodeList $c))." }
    elseif($script:EsBox -and $script:EsDetectError){ $l += "Event Server: could not check for a cluster - $($script:EsDetectError)" }
    elseif($script:EsBox){ $l += "Event Server: a single server ($($script:EsAddr)), not a cluster." }
    if($script:MsCluster -or $script:EsCluster){ $l += 'Cluster = several computers (nodes) that take turns running one server. Active = runs it now; passive = on standby.' }
    $l -join "`r`n"
}
# Plain-language cluster notes for the Result page and the outcome message.
function Get-ClusterNotes {
    $n = [System.Collections.Generic.List[string]]::new()
    foreach($k in @('MS','ES')){ $cl = Get-ClusterObj $k; if($cl){ $n.Add("$(Get-StageName $k) cluster role '$($cl.Group)' ($($cl.Address)): the role is on $($cl.Owner) now.") } }
    if(@($script:MsStaleNodes).Count -and $script:MsCluster){
        $g = $script:MsCluster.Group
        $n.Add('')
        $n.Add("IMPORTANT - known Milestone limitation (not an error of this run): the Management Server node registered last is $($script:MsLastRegistered). Only that node can start the Management Server now. These node(s) CANNOT take over until they are registered again: $($script:MsStaleNodes -join ', ').")
        if($script:MsLive){
            $lv = $script:MsLive
            if($lv.Up){ $n.Add("The Management Server works now, on $($lv.Owner) (checked live at $($lv.At.ToString('HH:mm:ss')): $($lv.Detail)).") }
            else { $n.Add("The Management Server does NOT work now: the role is on $($lv.Owner) ($($lv.Detail)).") }
        }
        $n.Add("If the role '$g' moves to one of those nodes (a failover), the Management Server will not start there. Fix: make sure the role is on that node (Failover Cluster Manager > Roles > right-click '$g' > Move > Select Node), then on THAT node start this wizard and click 'Re-register this node'. Afterwards that node works and the others need the same step after their next failover.")
    }
    if($script:PausedBeforeNote){ $n.Add(''); foreach($x in ($script:PausedBeforeNote -split "`r`n")){ $n.Add($x) } }
    if(@($script:FailoverResults).Count){
        $n.Add('')
        $n.Add('Failover test (each role was moved to every other node and back):')
        foreach($f in @($script:FailoverResults)){
            $sk = ($f.PSObject.Properties['Skipped'] -and $f.Skipped)
            $n.Add(" - $($f.Role) on $($f.Node)$(if($f.Back){' (back on the original node)'}): $(if($sk){$f.Detail}elseif($f.Ok){"OK - $($f.Detail)"}else{"FAILED - $($f.Detail)"})")
        }
        $msBad = @(@($script:FailoverResults) | Where-Object { $_.Key -eq 'MS' -and -not $_.Ok -and -not $_.Back })
        $otherBad = @(@($script:FailoverResults) | Where-Object { -not $_.Ok -and ($_.Key -ne 'MS' -or $_.Back) })
        if($msBad.Count){ $n.Add("The Management Server failing on $((@($msBad | ForEach-Object { $_.Node })) -join ', ') is the Milestone limitation described above - expected, not a certificate problem. 'Re-register this node' on that node after a failover fixes it.") }
        if($otherBad.Count){ $n.Add("NOT expected: $((@($otherBad | ForEach-Object { "$($_.Role) on $($_.Node)" })) -join ', '). Check the Milestone services and the Windows event log on that node, or roll back.") }
    }
    $n.ToArray()   # unrolled on purpose: callers wrap in @()
}

# -- targets ----------------------------------------------------------------------------
# Validate the Connect page and derive credentials / names. Throws a plain-language message.
function Read-Inputs {
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
    [void](ConvertTo-SanList $script:MsExtraSans)   # validate early: an invalid SAN would only fail mid-run
}
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
    Initialize-EsCluster
    $msTxt = if($script:MsCluster){ "cluster '$($script:MsCluster.Group)' ($(@($script:MsCluster.Nodes).Count) nodes)" } else { "$env:COMPUTERNAME ($($script:MsFqdn))" }
    $esTxt = if($script:EsCluster){ "cluster '$($script:EsCluster.Group)' ($(@($script:EsCluster.Nodes).Count) nodes)" } elseif($script:EsBox){ $script:EsAddr } else { '(none)' }
    Write-Log "Computers: Management Server $msTxt; Event Server $esTxt; $(@($script:RecBoxes).Count) recording server(s)" 'Good'
    $discErr
}

# -- run bookkeeping ----------------------------------------------------------------------
function Add-GuidedRow { param($Box,[string]$Act,[bool]$Ok,[string]$Status,[string]$Err='')
    $now=Get-Date
    [void]$script:RunResults.Add([pscustomobject]@{
        HostKey=$Box.Target; Fqdn=$Box.Addr; Success=$Ok; Status="$(Get-RoleText $Box): $Status"; Thumbprint=''
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
    if(Test-IdentityError $t){ return (Get-IdentityMessage $t) }
    if($t -match '(Cannot reach cluster node .+? Nothing was changed on [^.\s]+\.)'){ return $Matches[1] }
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
function Get-StageName { param([string]$Key) switch($Key){ 'ES' { 'Event Server' } 'MS' { 'Management Server' } 'FT' { 'Failover test' } 'REG' { 'Re-register this node' } 'ROLE' { 'Move cluster roles back' } default { 'Recording servers' } } }
function Reset-Stages { param([string[]]$Keys)
    $script:StageGrid.Rows.Clear(); $script:StageRows=@{}
    $n=1
    foreach($k in $Keys){
        $who = switch($k){
            'ES'   { if($script:EsCluster){ "cluster '$($script:EsCluster.Group)': $(@($script:EsCluster.Nodes).Count) nodes" } else { $script:EsAddr } }
            'MS'   { if($script:MsCluster){ "cluster '$($script:MsCluster.Group)': $(@($script:MsCluster.Nodes).Count) nodes" } else { "$env:COMPUTERNAME (this computer)" } }
            'FT'   { 'every cluster node' }
            'REG'  { "$env:COMPUTERNAME (this computer)" }
            'ROLE' { 'cluster roles' }
            default { "$(@($script:RecBoxes).Count) computer(s)" } }
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
# Skip rows for the boxes of one role that are not changed in this stage.
function Add-SkipRows { param([object[]]$Boxes,[object[]]$Todo,[string]$Act,[string]$Wt,[string]$What)
    foreach($b in @($Boxes)){
        if(@($Todo | Where-Object { [object]::ReferenceEquals($_,$b) }).Count){ continue }
        if(Test-InScope $b){ Write-Log "[$($b.Name)] $What already $Wt - skipped" 'Good'; Add-GuidedRow $b $Act $true "already $Wt - skipped" }
        else { Add-GuidedRow $b $Act $true 'not changed by the run - left as it is' }
    } }
# The Management Server state the order checks use: the standalone MS, or the CURRENT owner of the
# Management Server cluster role.
function Get-MsGateBox {
    if(-not $script:MsCluster){ Update-BoxStates @($script:MsBox); return $script:MsBox }
    [void](Update-ClusterInfo 'MS')
    $o = Get-First -Items @(@($script:MsNodeBoxes) | Where-Object { $_.Active })
    if(-not $o){
        $x = New-Box 'Management Server' '(cluster owner unknown)' '' '' $null
        $x.Detail = "the node that runs the Management Server role could not be determined ($($script:MsCluster.Error))"; return $x }
    Update-BoxStates @($o); $o
}
function Invoke-EsStage { param([bool]$Want)
    $wt=$(if($Want){'ON'}else{'OFF'}); $act=$(if($Want){'on'}else{'off'})
    Set-StageStatus 'ES' 'Checking...' 'Work'
    if($script:EsCluster){ [void](Update-ClusterInfo 'ES') }
    $esBoxes=@(Get-EsBoxes)
    Update-BoxStates $esBoxes
    $unk=@($esBoxes | Where-Object { (Test-InScope $_) -and (-not $_.Reachable -or $null -eq $_.Encrypted) })
    if($unk.Count){ $u=$unk[0]
        Set-StageStatus 'ES' 'FAILED - cannot read its state' 'Bad'; Add-GuidedRow $u $act $false 'cannot read state' $u.Detail
        Set-RunFailure 'Event Server' $u.Name "Could not read the Event Server's encryption state on $($u.Name)." $u.Detail; return $false }
    $todo=@($esBoxes | Where-Object { (Test-InScope $_) -and $_.Encrypted -ne $Want })
    Add-SkipRows $esBoxes $todo $act $wt 'Event Server'
    if(-not $todo.Count){ Set-StageStatus 'ES' $(if($null -ne $script:Scope){'Nothing to change back'}else{"Already $wt - skipped"}) 'Skip'; return $true }
    # Prerequisite (both directions): ServerConfigurator on the Event Server refuses while the MS is encrypted.
    $gb = Get-MsGateBox
    if($gb.Encrypted -ne $false){
        $why = if($gb.Encrypted){ "The Management Server is encrypted (checked on $($gb.Name)). The Event Server can only be changed while the Management Server is NOT encrypted." } else { "Could not read the Management Server's encryption state ($($gb.Name))." }
        $next = if($Want -and $gb.Encrypted){ "Click 'Turn encryption OFF' and let it finish, then click 'Turn encryption ON'." } else { '' }
        Set-StageStatus 'ES' 'BLOCKED - wrong order' 'Bad'; foreach($b in $todo){ Add-GuidedRow $b $act $false 'blocked by order check' $why }
        Set-RunFailure 'Event Server' $todo[0].Name $why $gb.Detail $next; return $false }
    Write-Log "ORDER CHECK: the Management Server is not encrypted - OK to turn the Event Server $wt" 'Good'
    if($script:EsCluster){ return (Invoke-ClusterStage 'ES' $Want $todo) }
    $es=$script:EsBox
    if(Test-IpAddress $es.Addr){ Ensure-TrustedHosts -Hosts @($es.Addr) }
    Set-StageStatus 'ES' 'Working...' 'Work'
    # Kerberos can refuse an Event Server name that belongs to a cluster: then its IP is used for WinRM
    # (the certificate name still comes from Target, the name entered in step 1).
    $esConn = try { Get-ConnAddr $es.Addr $es.Cred } catch { $es.Addr }
    $P=@{ Target=$es.Target; Fqdn=$esConn; Cred=$es.Cred; SignerTp=$script:SignerTp; CaCer=$script:CaCer; Domain=$script:DomainName; OutputDir=$script:OutputDir
          Guid=$script:CertGroupEvent; GroupName='Event Server'; Action=$(if($Want){'enable'}else{'disable'}); ExtraSans='' }
    $r = & $script:EsHostWorker $P
    Add-RunResult $r
    foreach($l in $r.Logs){ Write-Log "[$($r.Target)] $l" }
    Write-Log "[$($r.Target)] $(if($r.Ok){'OK'}else{'FAILED'}): $($r.Status)" $(if($r.Ok){'Good'}else{'Err'})
    $gt = Confirm-BoxStates @($es) $Want -TotalSec 180
    if($r.Ok -and $gt){ Set-StageStatus 'ES' "Done - encryption $wt" 'Good'; return $true }
    $reason = if($r.Ok){ "ServerConfigurator reported success, but the Event Server still reports: $(Get-StateText $es)." } else { Get-PlainReason "$($r.Status) $($r.Error)" }
    Set-StageStatus 'ES' 'FAILED' 'Bad'; Set-RunFailure 'Event Server' $es.Name $reason "$($r.Status) $($r.Error)"
    $false
}
function Invoke-MsStage { param([bool]$Want)
    $wt=$(if($Want){'ON'}else{'OFF'}); $act=$(if($Want){'on'}else{'off'})
    Set-StageStatus 'MS' 'Checking...' 'Work'
    if($script:MsCluster){ [void](Update-ClusterInfo 'MS') }
    $msBoxes=@(Get-MsBoxes)
    Update-BoxStates $msBoxes
    $unk=@($msBoxes | Where-Object { (Test-InScope $_) -and (-not $_.Reachable -or $null -eq $_.Encrypted) })
    if($unk.Count){ $u=$unk[0]
        Set-StageStatus 'MS' 'FAILED - cannot read its state' 'Bad'; Add-GuidedRow $u $act $false 'cannot read state' $u.Detail
        Set-RunFailure 'Management Server' $u.Name "Could not read the Management Server's encryption state on $($u.Name)." $u.Detail; return $false }
    $todo=@($msBoxes | Where-Object { (Test-InScope $_) -and $_.Encrypted -ne $Want })
    Add-SkipRows $msBoxes $todo $act $wt 'Management Server'
    if(-not $todo.Count){ Set-StageStatus 'MS' $(if($null -ne $script:Scope){'Nothing to change back'}else{"Already $wt - skipped"}) 'Skip'; return $true }
    $esBoxes=@(Get-EsBoxes)
    if($Want -and $esBoxes.Count){
        Update-BoxStates $esBoxes
        $notEnc=@($esBoxes | Where-Object { $_.Encrypted -ne $true })
        if($notEnc.Count){
            $why="The Event Server is not encrypted yet ($((@($notEnc | ForEach-Object { $_.Name })) -join ', ')). It must be encrypted BEFORE the Management Server (afterwards it can no longer be changed)."
            Set-StageStatus 'MS' 'BLOCKED - wrong order' 'Bad'; foreach($b in $todo){ Add-GuidedRow $b $act $false 'blocked by order check' $why }
            Set-RunFailure 'Management Server' $todo[0].Name $why $notEnc[0].Detail; return $false }
        Write-Log 'ORDER CHECK: the Event Server is encrypted - OK to encrypt the Management Server' 'Good'
    }
    if($script:MsCluster){ return (Invoke-ClusterStage 'MS' $Want $todo) }
    $ms=$script:MsBox
    # W5: the final live guard now also covers a standalone MS - mark it touched so Test-FinalMsLiveGuard runs.
    $script:MsTouched = $true
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
    $gt = Confirm-BoxStates @($ms) $Want -TotalSec 300
    if($r.Ok -and $gt){ Set-StageStatus 'MS' "Done - encryption $wt" 'Good'; return $true }
    $reason = if($r.Ok){ "ServerConfigurator reported success, but this Management Server still reports: $(Get-StateText $ms)." } else { Get-PlainReason "$($r.Status) $($r.Error)" }
    Set-StageStatus 'MS' 'FAILED' 'Bad'; Set-RunFailure 'Management Server' $ms.Name $reason "$($r.Status) $($r.Error)"
    $false
}
function Invoke-RecStage { param([bool]$Want)
    $wt=$(if($Want){'ON'}else{'OFF'}); $act=$(if($Want){'on'}else{'off'})
    Set-StageStatus 'REC' 'Checking...' 'Work'
    $recs=@($script:RecBoxes | Where-Object { -not $_.Excluded -and (Test-InScope $_) })
    if(-not $recs.Count){ Set-StageStatus 'REC' $(if($null -ne $script:Scope){'Nothing to change back'}elseif(@($script:RecBoxes).Count){'None reachable - left as they are'}else{'No recording servers to handle'}) 'Skip'; return $true }
    Update-BoxStates $recs
    $todo=@()
    foreach($b in $recs){
        if($b.Reachable -and $b.Encrypted -eq $Want){ Write-Log "[$($b.Name)] recording server already $wt - skipped" 'Good'; Add-GuidedRow $b $act $true "already $wt - skipped" }
        else { $todo+=$b }
    }
    if(-not $todo.Count){ Set-StageStatus 'REC' "All already $wt - skipped" 'Skip'; return $true }
    # Prerequisite: recorders only move to the state the Management Server is already in (on a
    # cluster: the node that runs the Management Server role now).
    $gb = Get-MsGateBox
    if($gb.Encrypted -ne $Want){
        # W12: during ROLLBACK ($script:Scope set), a recorder whose pre-run state cannot coexist with the
        # MS's state after rollback is skipped - not a rollback failure. Milestone requires recording
        # servers to match the management server, and rollback recovers what it can rather than blocking
        # everything else because one box's target does not fit.
        if($null -ne $script:Scope){
            $state = Get-StateText $gb
            foreach($b in $todo){
                Write-Log "[$($b.Name)] stays $(Get-StateText $b): Milestone requires recording servers to match the management server" 'Good'
                Add-GuidedRow $b $act $true "stays $(Get-StateText $b): Milestone requires recording servers to match the management server"
            }
            Set-StageStatus 'REC' "Skipped - the Management Server is not $wt ($state)" 'Skip'
            return $true
        }
        $why = if($null -eq $gb.Encrypted){ "Could not read the Management Server's encryption state ($($gb.Name))." }
               elseif($Want){ 'The Management Server is not encrypted. Recording servers can only be encrypted after the Management Server.' }
               else { 'The Management Server is still encrypted. Recording servers can only be decrypted after the Management Server.' }
        Set-StageStatus 'REC' 'BLOCKED - wrong order' 'Bad'
        foreach($b in $todo){ Add-GuidedRow $b $act $false 'blocked by order check' $why }
        Set-RunFailure 'Recording servers' "$($todo.Count) computer(s)" $why $gb.Detail; return $false }
    Write-Log "ORDER CHECK: the Management Server is $(if($Want){'encrypted'}else{'not encrypted'}) - OK to turn the recording servers $wt" 'Good'
    $ips=@($todo | Where-Object { Test-IpAddress $_.Addr } | ForEach-Object { [string]$_.Addr })
    if($ips.Count){ Ensure-TrustedHosts -Hosts $ips }
    Set-StageStatus 'REC' "Working on $($todo.Count) recording server(s)..." 'Work'
    $common=@{ Cred=$script:RecCred; SignerTp=$script:SignerTp; CaCer=$script:CaCer; Domain=$script:DomainName; OutputDir=$script:OutputDir
               Guids=$script:CertGroupServer; Names='Server (recorder)' }
    # Order check again, right before the batch starts (the MS role may have moved or changed meanwhile).
    $gb2 = Get-MsGateBox
    if($gb2.Encrypted -ne $Want){
        $why = "The Management Server state changed just before the recording servers were started: it is now $(Get-StateText $gb2) (checked on $($gb2.Name)). Nothing was changed on the recording servers."
        Set-StageStatus 'REC' 'BLOCKED - Management Server state changed' 'Bad'
        foreach($b in $todo){ Add-GuidedRow $b $act $false 'blocked by order check' $why }
        Set-RunFailure 'Recording servers' "$($todo.Count) computer(s)" $why $gb2.Detail 'Click Check again to see the current state, then run the same action again.'; return $false }
    $results=@(Invoke-RecordersParallel -Boxes $todo -Action $(if($Want){'enable'}else{'disable'}) -Common $common -Throttle 32)
    [void](Confirm-BoxStates $todo $Want -TotalSec 300)
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

# Run the ON/OFF stages in the given order, stopping at the first stage that does not return $true.
function Invoke-StageSequence { param([string[]]$Keys,[bool]$Want)
    foreach($k in $Keys){
        $res=@(switch($k){ 'ES' { Invoke-EsStage $Want } 'MS' { Invoke-MsStage $Want } default { Invoke-RecStage $Want } })
        if(-not ($res.Count -and $res[-1] -eq $true)){ return $false }
    }
    $true
}
function Reset-RunState {
    $script:RunFailure=$null; $script:SignerTp=''; $script:CaCer=''; $script:RunStart=Get-Date; $script:LastReportPath=''
    $script:FailoverResults=@(); $script:Scope=$null; $script:FinalOwners=@{}
    $script:MsTouched=$false; $script:MsLive=$null; $script:PausedByRun=@{}; $script:PausedBeforeNote=''
}

# Full ON/OFF sequence in the lab-verified order, stopping at the first step whose real state is wrong.
# -- single-run lock: only one state-changing run per system ------------------------------------
# A named mutex (all sessions of this computer) keyed by the cluster address or this MS host, plus a
# lock file next to the reports that says who holds it. NOTE: a mutex is per computer - a second run
# started on ANOTHER cluster node is not seen by it.
$script:RunMutex = $null
function Get-RunLockFile { Join-Path $script:RunsDir 'run.lock' }
function Enter-RunLock {
    $key = if($script:MsCluster -and $script:MsCluster.Address){ [string]$script:MsCluster.Address } else { $env:COMPUTERNAME }
    $name = 'Global\MrcGuided-' + ($key.ToLowerInvariant() -replace '[^a-z0-9.-]','_')
    $m = New-Object System.Threading.Mutex($false, $name)
    $got = $false
    try { $got = $m.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $got = $true }
    if(-not $got){
        $m.Dispose()
        $who = 'another session'; $when = 'an unknown time'
        try {
            $t = Get-Content -LiteralPath (Get-RunLockFile) -Raw -ErrorAction Stop
            if($t -match 'computer=([^;]+)'){ $who = $Matches[1].Trim() }
            if($t -match 'started=([^;]+)'){ $when = $Matches[1].Trim() }
        } catch {}
        return "Another run of this wizard is already changing this system (started on $who at $when). Wait for it to finish."
    }
    $script:RunMutex = $m
    try {
        if(-not (Test-Path -LiteralPath $script:RunsDir)){ [void](New-Item -ItemType Directory -Path $script:RunsDir -Force) }
        Set-Content -LiteralPath (Get-RunLockFile) -Value ("computer=$env:COMPUTERNAME; started=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')); user=$env:USERDOMAIN\$env:USERNAME; pid=$PID") -Encoding ASCII
    } catch {}
    ''
}
function Exit-RunLock {
    if(-not $script:RunMutex){ return }
    try { $script:RunMutex.ReleaseMutex() } catch {}
    try { $script:RunMutex.Dispose() } catch {}
    $script:RunMutex = $null
    Remove-Item -LiteralPath (Get-RunLockFile) -Force -ErrorAction SilentlyContinue
}
function Invoke-WithRunLock { param([string]$Kind,$Want,[scriptblock]$Body)
    $err = Enter-RunLock
    if($err){
        Reset-RunState
        Write-Log "REFUSED: $err" 'Err'
        Set-RunFailure 'Before starting' $env:COMPUTERNAME $err '' 'Wait for the other run to finish, then try again.'
        $script:HasResult = $true
        return [pscustomobject]@{ Kind=$Kind; Success=$false; Want=$Want; Failure=$script:RunFailure; Report='' }
    }
    try { & $Body } finally { Exit-RunLock }
}
function Invoke-GuidedRun { param([ValidateSet('on','off')][string]$Act) Invoke-WithRunLock $Act ($Act -eq 'on') { Invoke-GuidedRunCore $Act } }
function Invoke-GuidedRollback { param([string]$Path) Invoke-WithRunLock 'rollback' $null { Invoke-GuidedRollbackCore $Path } }
function Invoke-RegisterAction { Invoke-WithRunLock 'register' $null { Invoke-RegisterActionCore } }

function Invoke-GuidedRunCore { param([ValidateSet('on','off')][string]$Act)
    $want=($Act -eq 'on'); $wt=$Act.ToUpper()
    Reset-RunState
    $keys = @(if($want){ @('ES','MS','REC') } else { @('MS','REC','ES') })
    if(-not $script:EsBox){ $keys=@($keys | Where-Object { $_ -ne 'ES' }) }
    $doFt = [bool]$script:TestFailoverOn -and [bool]($script:MsCluster -or $script:EsCluster)
    Reset-Stages ($keys + @(if($doFt){ 'FT' }))
    Write-Log "========== TURN ENCRYPTION $wt ==========" 'Good'
    Write-Log "Order: $(@($keys | ForEach-Object { Get-StageName $_ }) -join ', then ')"
    foreach($k in @('MS','ES')){ if(Get-ClusterObj $k){ [void](Update-ClusterInfo $k) } }
    Initialize-MsTracking
    $all=@(Get-AllBoxes)
    foreach($b in $all){ $b.Excluded=$false }
    Update-BoxStates $all
    Write-StateLog 'STATE BEFORE' $all
    $ok=$true
    try {
        foreach($b in @($script:RecBoxes | Where-Object { -not $_.Reachable })){
            $b.Excluded=$true
            Write-Log "[$($b.Name)] cannot be reached - it will be left as it is" 'Err'
            Add-GuidedRow $b $Act $false 'not reachable - left as it is' $b.Detail
        }
        # No state file = no rollback: then nothing may be changed (counts as a failed pre-flight check).
        $snapOk = [bool](@(Save-Snapshot $Act)[-1])
        # @() around the WHOLE if: an if-statement unrolls its output, so a bare 'if' gives $null (no
        # problem) or a string (one problem), and .Count on those throws under StrictMode.
        $probs = @(if($snapOk){ @(Invoke-PreFlight $Act $want) }
                   else { @("Could not save the state file needed for rollback, so nothing was changed. Check that this folder exists and can be written, and that the disk is not full: $($script:RunsDir)") })
        if($probs.Count){
            $ok=$false
            foreach($x in $probs){ Add-NoteRow $Act $false 'pre-flight check failed - nothing changed' $x }
            foreach($k in $keys){ Set-StageStatus $k 'Not started - the pre-flight check failed' 'Bad' }
            Set-RunFailure 'Pre-flight check (before any change)' 'see the list' ("Nothing was changed. These problems must be fixed first:`r`n" + ((@($probs | ForEach-Object { " - $_" })) -join "`r`n")) '' 'Fix the problems listed above, then click the same button again.'
        } else {
            $ok = Invoke-StageSequence $keys $want
        }
    } catch {
        $ok=$false
        Write-ErrorTrace $_
        Set-RunFailure 'Unexpected error' $env:COMPUTERNAME (Get-PlainReason (Format-Err $_)) (Format-Err $_) "Click 'Undo this run (roll back)' on the Result page to undo what was changed, or send the report file to support."
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
    # Failover self-test only after a change that worked (a failed run is rolled back or fixed first).
    # W7: a test failure does NOT undo the (already successful) encryption change - it is reported as its
    # own distinct outcome ("encryption done, but the failover test FAILED"), never silently folded into
    # $success or hidden as just a stage-status line.
    $ftFailed = $false
    if($doFt){
        if($success){
            try { Invoke-FailoverTest; $ftFailed = (@(@($script:FailoverResults) | Where-Object { -not $_.Ok -and -not $_.Skipped }).Count -gt 0) }
            catch { Write-Log "Failover test error: $(Format-Err $_)" 'Err'; Set-StageStatus 'FT' 'FAILED - see the details' 'Bad'; $ftFailed = $true }
        } else { Set-StageStatus 'FT' 'Not run - the change did not complete' 'Skip' }
    }
    try { if(-not (Test-FinalMsLiveGuard $Act)){ $success=$false } } catch { Write-ErrorTrace $_; $success=$false }
    if(-not (Test-FinalPausedGuard $Act)){ $success=$false }
    Write-Log "OVERALL: $(if($success){"encryption is $wt on every computer"}else{'NOT COMPLETE - see the message above'})" $(if($success){'Good'}else{'Err'})
    foreach($l in @(Get-ClusterNotes)){ if($l){ Write-Log $l } }
    Save-Report
    $script:HasResult=$true
    [pscustomobject]@{ Kind=$Act; Success=$success; Want=$want; Failure=$script:RunFailure; Report=$script:LastReportPath; FailoverFailed=$ftFailed }
}

# Undo what the run that wrote the snapshot changed: the opposite action, only on the boxes whose state
# that run changed, in the safe order for that direction (order checks included), then the cluster
# roles go back to their snapshot owners, then the real state is compared with the snapshot.
function Invoke-GuidedRollbackCore { param([string]$Path)
    Reset-RunState
    $snap=$null
    try { $snap=Read-Snapshot $Path } catch {
        Reset-Stages @('ROLE')
        Set-RunFailure 'Rollback' 'snapshot file' $_.Exception.Message '' 'Choose the snapshot file (run-...-snapshot.json) that was written before the run.'
        Save-Report; $script:HasResult=$true
        return [pscustomobject]@{ Kind='rollback'; Success=$false; Want=$false; Failure=$script:RunFailure; Report=$script:LastReportPath } }
    $want=([string]$snap.Action -ne 'on'); $wt=$(if($want){'ON'}else{'OFF'}); $act="rollback-$($wt.ToLower())"
    $keys = @(if($want){ @('ES','MS','REC') } else { @('MS','REC','ES') })
    if(-not $script:EsBox){ $keys=@($keys | Where-Object { $_ -ne 'ES' }) }
    Reset-Stages ($keys + @('ROLE'))
    Write-Log "========== ROLLBACK: turn encryption $wt again where the run of $($snap.Created) changed it ==========" 'Good'
    Write-Log "Snapshot: $Path"
    $ok=$true
    try {
        # The recording servers of that run come from the snapshot.
        $list=[System.Collections.Generic.List[object]]::new()
        foreach($sb in @(@($snap.Boxes) | Where-Object { [string]$_.Kind -eq 'REC' })){ [void]$list.Add((New-Box 'Recording server' ([string]$sb.Name) ([string]$sb.Target) ([string]$sb.Addr) $script:RecCred)) }
        $script:RecBoxes=@($list.ToArray())
        $ips=@($script:RecBoxes | Where-Object { Test-IpAddress $_.Addr } | ForEach-Object { [string]$_.Addr })
        if($ips.Count){ Ensure-TrustedHosts -Hosts $ips }
        $snapEs=[string]$snap.EsHost
        if($snapEs -and (-not $script:EsBox -or $snapEs -ne [string]$script:EsAddr)){
            $ok=$false
            Set-RunFailure 'Rollback' 'Event Server' "The snapshot was taken with Event Server '$snapEs', but this wizard is set to '$(if($script:EsBox){$script:EsAddr}else{'no Event Server'})'. Nothing was changed." '' "Go back to step 1, enter '$snapEs' as the Event Server, and start the rollback again."
        } else {
            foreach($k in @('MS','ES')){ if(Get-ClusterObj $k){ [void](Update-ClusterInfo $k) } }
            Initialize-MsTracking
            $all=@(Get-AllBoxes); foreach($b in $all){ $b.Excluded=$false }
            Update-BoxStates $all
            Write-StateLog 'STATE NOW' $all
            $plan=Get-RollbackPlan $snap
            if(@($plan.Missing).Count){
                $ok=$false
                Set-RunFailure 'Rollback' ($plan.Missing -join ', ') "These computers are in the snapshot but are not known to the wizard now: $($plan.Missing -join ', '). Nothing was changed." '' 'Check that the same computers (and the same cluster nodes) are used as when the snapshot was taken.'
            } else {
                Write-Log "Changed by that run (will be turned $wt again): $(if(@($plan.Changed).Count){ (@($plan.Changed | ForEach-Object { $_.Name })) -join ', ' } else { '(none)' })"
                foreach($m in @($plan.Moves)){ Write-Log "Cluster role '$($m.Group)' will be moved back to $($m.Owner)" }
                $script:Scope=@{}; foreach($b in @($plan.Changed)){ $script:Scope[(Get-BoxScopeKey $b)]=$true }
                $script:FinalOwners=@{}; foreach($r in @($snap.Roles)){ $script:FinalOwners[[string]$r.Key]=[string]$r.Owner }
                $probs=@(Invoke-PreFlight 'rollback' $want)
                if($probs.Count){
                    $ok=$false
                    foreach($x in $probs){ Add-NoteRow $act $false 'pre-flight check failed - nothing changed' $x }
                    Set-RunFailure 'Pre-flight check (before any change)' 'see the list' ("Nothing was changed. These problems must be fixed first:`r`n" + ((@($probs | ForEach-Object { " - $_" })) -join "`r`n")) '' 'Fix the problems listed above, then start the rollback again.'
                } else {
                    if(@($plan.Changed).Count){ $ok = Invoke-StageSequence $keys $want }
                    else { foreach($k in $keys){ Set-StageStatus $k 'Nothing to change back' 'Skip' } }
                    $script:Scope=$null
                    if($ok){ $ok = Restore-RoleOwners $snap }
                }
            }
        }
    } catch {
        $ok=$false
        Write-ErrorTrace $_
        Set-RunFailure 'Unexpected error' $env:COMPUTERNAME (Get-PlainReason (Format-Err $_)) (Format-Err $_)
    } finally { $script:Scope=$null; $script:FinalOwners=@{} }
    # Ground truth against the snapshot.
    $all=@(Get-AllBoxes); Update-BoxStates $all
    Write-StateLog 'STATE AFTER ROLLBACK' $all
    $mism=@()
    foreach($sb in @($snap.Boxes)){
        if($null -eq $sb.Encrypted){ continue }
        $hostKey=if([string]$sb.Kind -eq 'MS'){ [string]$sb.Target } else { [string]$sb.Addr }
        $cur=Find-Box ([string]$sb.Kind) $hostKey
        $good = $cur -and ($cur.Encrypted -eq [bool]$sb.Encrypted)
        if(-not $good){ $mism += [string]$sb.Name }
        $target = $(if([bool]$sb.Encrypted){'Encrypted'}else{'Not encrypted'})
        if($cur){ Add-GuidedRow $cur 'rollback-final' $good "state $(Get-StateText $cur) (before the run: $target)" $(if($good){''}else{$cur.Detail}) }
    }
    foreach($r in @($snap.Roles)){ $cl=Get-ClusterObj ([string]$r.Key); if(-not $cl -or [string]$cl.Owner -ne [string]$r.Owner){ $mism += "role '$($r.Group)' (on $(if($cl){$cl.Owner}else{'?'}), was on $($r.Owner))" } }
    if($ok -and $mism.Count){ Set-RunFailure 'Final check' ($mism -join ', ') 'These are not back in the state they had before the run.' '' 'Make sure every computer is switched on and reachable, then start the rollback again (it only changes what still differs).' }
    $success = $ok -and -not $mism.Count
    try { if(-not (Test-FinalMsLiveGuard $act)){ $success=$false } } catch { Write-ErrorTrace $_; $success=$false }
    if(-not (Test-FinalPausedGuard $act)){ $success=$false }
    Write-Log "OVERALL: $(if($success){'every computer is back in the state it had before the run'}else{'ROLLBACK NOT COMPLETE - see the message above'})" $(if($success){'Good'}else{'Err'})
    foreach($l in @(Get-ClusterNotes)){ if($l){ Write-Log $l } }
    Save-Report
    $script:HasResult=$true
    [pscustomobject]@{ Kind='rollback'; Success=$success; Want=$want; Failure=$script:RunFailure; Report=$script:LastReportPath }
}

# 'Re-register this node': ServerConfigurator /register on THIS Management Server cluster node, which
# must own the role now. The documented fix for a node that cannot start the Management Server after
# a failover (IDP 'invalid_client').
function Invoke-RegisterActionCore {
    Reset-RunState
    Reset-Stages @('REG')
    Write-Log '========== RE-REGISTER THIS NODE ==========' 'Good'
    $ok=$false
    try {
        Set-StageStatus 'REG' 'Checking...' 'Work'
        $cl = $script:MsCluster
        $me = Get-First -Items @(Get-NodeBoxes 'MS' | Where-Object { [string]$_.Target -eq $env:COMPUTERNAME })
        if(-not $cl){
            Set-StageStatus 'REG' 'Not a cluster - nothing to do' 'Bad'
            Set-RunFailure 'Re-register' $env:COMPUTERNAME 'This Management Server is not part of a Windows failover cluster. Re-register is only needed on cluster nodes, so nothing was changed.' }
        elseif(-not $me){
            Set-StageStatus 'REG' 'FAILED' 'Bad'
            Set-RunFailure 'Re-register' $env:COMPUTERNAME "This computer is not listed as a node of cluster role '$($cl.Group)', so nothing was changed." }
        else {
            Initialize-MsTracking
            if($cl.Error){
                Set-StageStatus 'REG' 'FAILED - cluster state unknown' 'Bad'
                Set-RunFailure 'Re-register' $env:COMPUTERNAME "The state of cluster role '$($cl.Group)' could not be read, so nothing was changed." $cl.Error }
            elseif([string]$cl.Owner -ne [string]$me.Target){
                Set-StageStatus 'REG' 'REFUSED - this node does not run the role' 'Bad'
                Add-GuidedRow $me 'register' $false 'refused - this node does not own the role'
                Set-RunFailure 'Re-register' $me.Name "This node does not run the Management Server role now - $($cl.Owner) does. Nothing was changed." '' "Re-register only works on the node that runs the role. If THIS node should run the Management Server: in Failover Cluster Manager > Roles, right-click '$($cl.Group)' > Move > Select Node > $($me.Name). Then click 'Re-register this node' again."
            } else {
                $probs=@(Invoke-PreFlight 'register' $false)
                if($probs.Count){
                    foreach($x in $probs){ Add-NoteRow 'register' $false 'pre-flight check failed - nothing changed' $x }
                    Set-StageStatus 'REG' 'Not started - the pre-flight check failed' 'Bad'
                    Set-RunFailure 'Pre-flight check (before any change)' 'see the list' ("Nothing was changed. These problems must be fixed first:`r`n" + ((@($probs | ForEach-Object { " - $_" })) -join "`r`n")) '' 'Fix the problems listed above, then click Re-register this node again.'
                } else {
                    Set-StageStatus 'REG' 'Working - ServerConfigurator is registering this node...' 'Work'
                    $addr = Get-MsRegisterAddress ($me.Encrypted -eq $true)
                    $rg = Invoke-NodeRegister $me $addr
                    if($rg.Ok){ $ok=$true; Set-StageStatus 'REG' 'Done - registered, the Management Server is running' 'Good' }
                    else {
                        Set-StageStatus 'REG' 'FAILED' 'Bad'
                        Set-RunFailure 'Re-register' $me.Name 'ServerConfigurator could not register this node, or the Management Server did not start within 5 minutes afterwards.' $rg.Detail "Check that the admin account is a Milestone administrator and that the cluster address $($cl.Address) points to this node. Then click 'Re-register this node' again, or send the report to support."
                    }
                }
            }
        }
    } catch {
        Set-StageStatus 'REG' 'FAILED' 'Bad'
        Write-ErrorTrace $_
        Set-RunFailure 'Unexpected error' $env:COMPUTERNAME (Get-PlainReason (Format-Err $_)) (Format-Err $_)
    }
    try { if(-not (Test-FinalMsLiveGuard 'register')){ $ok=$false } } catch { Write-ErrorTrace $_; $ok=$false }
    if(-not (Test-FinalPausedGuard 'register')){ $ok=$false }
    $all=@(Get-AllBoxes); Update-BoxStates $all
    Write-StateLog 'STATE AFTER' $all
    Write-Log "OVERALL: $(if($ok){'this node is registered and the Management Server runs on it'}else{'RE-REGISTER NOT COMPLETE - see the message above'})" $(if($ok){'Good'}else{'Err'})
    foreach($l in @(Get-ClusterNotes)){ if($l){ Write-Log $l } }
    Save-Report
    $script:HasResult=$true
    [pscustomobject]@{ Kind='register'; Success=$ok; Want=$null; Failure=$script:RunFailure; Report=$script:LastReportPath }
}

# Plain-language outcome: what failed, the state of every computer, what to do next, report path.
function Get-OutcomeText { param($Res)
    $wt = if($Res.Want){'ON'}else{'OFF'}
    $lines = (@(Get-AllBoxes) | ForEach-Object { " - $(Get-RoleText $_) $($_.Name): $(Get-StateText $_)" }) -join "`r`n"
    $rep = if($Res.Report){ $Res.Report } else { '(the report could not be written - see the details log)' }
    $notes = @(Get-ClusterNotes)
    $notesTxt = if($notes.Count){ "`r`n`r`n" + ($notes -join "`r`n") } else { '' }
    $snapTxt = if($Res.Kind -in 'on','off' -and $script:LastSnapshotPath){ "`r`n`r`nState before the run (used for rollback):`r`n$($script:LastSnapshotPath)" } else { '' }
    if($Res.Success){
        $head = switch($Res.Kind){
            'register' { 'This node is registered again, and the Management Server runs on it.' }
            'rollback' { 'Rollback finished. Every computer is back in the state it had before the run.' }
            default {
                # W7: the encryption change itself succeeded, but a failover self-test failure is its own
                # distinct outcome - never silently reported as a plain success.
                if($Res.PSObject.Properties['FailoverFailed'] -and $Res.FailoverFailed){
                    $badDet = (@($script:FailoverResults) | Where-Object { -not $_.Ok -and -not $_.Skipped } | ForEach-Object { "$($_.Role) on $($_.Node): $($_.Detail)" }) -join '; '
                    "Encryption done, but the failover test FAILED: $badDet"
                } else { "Encryption is now $wt on every computer." }
            } }
        return "$head`r`n`r`nCurrent state:`r`n$lines$notesTxt$snapTxt`r`n`r`nReport file:`r`n$rep"
    }
    $f=$Res.Failure
    $head = switch($Res.Kind){ 'register' { 'Re-register was NOT completed.' } 'rollback' { 'Rollback was NOT completed.' } default { 'Encryption was NOT completed.' } }
    $step = if($f){ "$($f.Step) ($($f.Who))" } else { '(unknown step)' }
    $why  = if($f){ $f.Reason } else { '' }
    $defNext = switch($Res.Kind){
        'register' { "Fix the problem above and click 'Re-register this node' again. If it fails again, send the report file to support." }
        'rollback' { 'Fix the problem above and start the rollback again (it only changes what still differs). If it fails again, send the report file to support.' }
        default    { "Fix the problem and click 'Turn encryption $wt' again$(if($script:LastSnapshotPath){", or click 'Undo this run (roll back)' to undo what this run changed"}). If it fails again, send the report file to support." } }
    $next = if($f -and $f.Next){ $f.Next } else { $defNext }
    "$head`r`n`r`nWhat failed: $step`r`n$why`r`n`r`nCurrent state:`r`n$lines$notesTxt`r`n`r`nWhat to do next: $next$snapTxt`r`n`r`nReport file:`r`n$rep"
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
    foreach($c in @(@('Name','Computer',180),@('Role','Role',290),@('Reach','Reachable',90),@('State','Encryption',170),@('Detail','Details',400))){
        $col=[Windows.Forms.DataGridViewTextBoxColumn]::new(); $col.Name=$c[0]; $col.HeaderText=$c[1]; $col.Width=$c[2]; $col.SortMode='NotSortable'
        [void]$g.Columns.Add($col) }
    $g.Columns['Detail'].AutoSizeMode='Fill'
    $g }
function Show-StateGrid { param($Grid,[object[]]$Boxes)
    $Grid.Rows.Clear()
    foreach($b in @($Boxes)){
        $idx=$Grid.Rows.Add($b.Name,(Get-RoleText $b),$(if($b.Reachable){'Yes'}else{'No'}),(Get-StateText $b),$b.Detail)
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
        $script:LastRegFindings = @(Get-RegistrationMismatches $all)
        Update-ClusterUi
        $script:Page=2
    } catch {
        Write-Log "Check failed: $(Format-Err $_)" 'Err'
        [Windows.Forms.MessageBox]::Show("Could not check the computers:`r`n$(Get-FirstLine $_.Exception.Message)",'Error',0,'Error')|Out-Null
    } finally { $script:ConnectStatus.Text=''; Set-Busy $false; Show-Page $script:Page }
}
function Do-Recheck {
    Set-Busy $true
    try {
        # Cluster membership and owners can change between checks: detect again (states are re-read anyway).
        Initialize-MsCluster; Initialize-EsCluster
        $all=@(Get-AllBoxes); Update-BoxStates $all; Show-StateGrid $script:CheckGrid $all; $script:CheckSummary.Text=Get-StateSummary $all; Write-StateLog 'CURRENT STATE' $all
        $script:LastRegFindings = @(Get-RegistrationMismatches $all)
        Update-ClusterUi
    }
    catch { Write-Log "Check failed: $(Format-Err $_)" 'Err' }
    finally { Set-Busy $false; Show-Page $script:Page }
}
function Update-ClusterUi {
    $any = [bool]($script:MsCluster -or $script:EsCluster)
    $script:FailoverChk.Visible = $any
    $script:RegBtn.Visible = [bool]$script:MsCluster
    $t = Get-ClusterSummary
    $rf = @($script:LastRegFindings)
    if($rf.Count){
        $t += "`r`nRegistration: $($rf.Count) computer(s) point to a different management server ($((@($rf | ForEach-Object { "$($_.Box.Name) -> $($_.Address)" })) -join '; ')). Changes there would fail; the change offers to register them with $($rf[0].Target)."
    }
    $script:ClusterLabel.Text = $t
}
# Text lines describing what happens to each clustered role during a change.
function Get-ClusterConfirmLines {
    $l=@()
    foreach($k in @('MS','ES')){
        $cl=Get-ClusterObj $k; if(-not $cl){ continue }
        $l += " - $(Get-StageName $k) cluster '$($cl.Group)': each cluster node is briefly taken over while it is configured (the role moves to that node, all nodes are paused, the node is configured, then the nodes are resumed). The role ends on $($cl.Owner), where it is now."
    }
    $l
}
function Get-ConfirmText { param([string]$Act)
    $want=($Act -eq 'on'); $wt=$Act.ToUpper()
    $order = if($want){ 'Event Server, then Management Server, then recording servers' } else { 'Management Server, then recording servers, then Event Server' }
    $l=@("Turn encryption $wt for the whole system?",'','What will happen:',
         ' - The current state is saved to a file first, so this run can be rolled back.',
         ' - Every computer is checked first. If something is wrong, nothing is changed and you get a list of what to fix.',
         " - The steps run in this order: $order. Computers that are already $wt are skipped.")
    $l += @(Get-ClusterConfirmLines)
    if(-not (Test-HasPsTools)){ $l += $script:PsToolsConfirmLine }
    if($script:MsCluster){ $l += " - Known Milestone limitation: after the Management Server is changed, only the node that was configured last ($($script:MsCluster.Owner)) can run it. The other Management Server node(s) need 'Re-register this node' after a failover. The result page explains it." }
    if($script:TestFailoverOn -and ($script:MsCluster -or $script:EsCluster)){ $l += ' - Failover test afterwards: each cluster role is moved to every other node and back, to see whether each node can take over. This adds several minutes of interruption.' }
    $l += @('','Milestone services restart. Video and clients can be interrupted for several minutes - use a maintenance window.')
    $l -join "`r`n"
}
# Fill the Result page and show the outcome box.
function Show-RunOutcome { param($Res)
    $all=@(Get-AllBoxes)
    Show-StateGrid $script:FinalGrid $all; Show-StateGrid $script:CheckGrid $all; $script:CheckSummary.Text=Get-StateSummary $all
    $wt = if($Res.Want){'ON'}else{'OFF'}
    $script:ResultLabel.Text = switch($Res.Kind){
        'register' { if($Res.Success){ 'Done. This node is registered again and the Management Server runs on it.' } else { 'NOT complete. Re-register did not finish - see the message and the notes below.' } }
        'rollback' { if($Res.Success){ 'Done. Every computer is back in the state it had before the run.' } else { 'NOT complete. The rollback did not finish - see the message and the table below.' } }
        default    { if($Res.Success){ "Done. Encryption is $wt on every computer." } else { "NOT complete. Encryption could not be turned $wt everywhere - see the message and the table below." } } }
    $script:ResultLabel.ForeColor = if($Res.Success){ [Drawing.Color]::DarkGreen } else { [Drawing.Color]::DarkRed }
    $script:ReportBox.Text = $Res.Report
    $script:NotesBox.Text = (@(Get-ClusterNotes) -join "`r`n")
    $script:BusyLabel.Visible=$false
    Update-ClusterUi
    [Windows.Forms.MessageBox]::Show((Get-OutcomeText $Res),$(if($Res.Success){'Finished'}else{'NOT completed'}),0,$(if($Res.Success){'Information'}else{'Error'}))|Out-Null
}
function Start-GuidedAction { param([ValidateSet('on','off')][string]$Act)
    $wt=$Act.ToUpper()
    $script:TestFailoverOn = [bool]($script:FailoverChk.Visible -and $script:FailoverChk.Checked)
    $q=Get-ConfirmText $Act
    if([Windows.Forms.MessageBox]::Show($q,'Please confirm',4,'Question') -ne 'Yes'){ return }
    $offer=$false
    $script:ChangeInProgress=$true; $script:RollbackBtn.Enabled=$false
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
        Show-RunOutcome $res
        $offer = (-not $res.Success) -and (Test-RollbackUseful)
        $script:Page=4
    } catch {
        Write-Log "Run failed: $(Format-Err $_)" 'Err'; Write-ErrorTrace $_
        [Windows.Forms.MessageBox]::Show("Unexpected error:`r`n$(Get-FirstLine $_.Exception.Message)`r`n`r`nSee 'Show details' on this page.",'Error',0,'Error')|Out-Null
    } finally { $script:ChangeInProgress=$false; $script:BusyLabel.Visible=$false; Set-Busy $false; Update-RollbackButton; Show-Page $script:Page }
    if($offer){
        $q2 = "The run did not finish, and it already changed some computers (or moved a cluster role).`r`n`r`nRoll back to the state before this run?`r`n`r`nYes = change back only what this run changed. You will see the details and confirm first.`r`nNo = leave everything as it is now. You can still roll back later with the button on the Result page."
        if([Windows.Forms.MessageBox]::Show($q2,'Roll back to the state before this run?',4,'Question') -eq 'Yes'){ Start-RollbackAction $script:LastSnapshotPath }
    }
}
# 'Undo this run' is only offered while the last run's state file shows something to change back.
function Update-RollbackButton {
    $en = $false
    try {
        if($script:LastOutcome -and $script:LastOutcome.PSObject.Properties['Kind'] -and [string]$script:LastOutcome.Kind -in 'on','off','rollback'){ $en = [bool](Test-RollbackUseful) }
    } catch { $en = $false }
    $script:RollbackBtn.Enabled = $en }
# The exact headless command that rolls the last run back (for the log / a closed window).
function Get-RollbackCommand {
    if(-not $script:LastSnapshotPath){ return '' }
    $u = if($script:AdminCred){ [string]$script:AdminCred.UserName } else { '<DOMAIN>\<admin>' }
    $rec = if($script:RecSepChk -and $script:RecSepChk.Checked -and $script:RecCred){ " -RecUser '$($script:RecCred.UserName)' -RecPwFile <file-with-the-recording-server-password>" } else { '' }
    "powershell -ExecutionPolicy Bypass -File `"$($script:SelfPath)`" -Action rollback -Snapshot `"$($script:LastSnapshotPath)`" -AdminUser '$u' -AdminPwFile <file-with-the-admin-password>$rec"
}
# Window closed while a change runs: resume paused nodes (best effort), then say how to roll back.
function Invoke-CloseCleanup {
    $lines = @('The window was closed while a change was running.')
    try {
        foreach($k in @('MS','ES')){
            if(-not (Get-ClusterObj $k)){ continue }
            try { $r = Invoke-ClusterOp $k 'resume'; $lines += "$(Get-StageName $k) cluster: resume paused nodes - $(if($r.Ok){'done'}else{"FAILED ($($r.Detail)). Open Failover Cluster Manager, right-click each paused node, Resume > Do not fail roles back."})" }
            catch { Write-ErrorTrace $_; $lines += "$(Get-StageName $k) cluster: could not resume paused nodes ($(Get-FirstLine $_.Exception.Message)). Open Failover Cluster Manager, right-click each paused node, Resume > Do not fail roles back." }
        }
    } finally {
        if($script:LastSnapshotPath){
            $lines += "State before the run: $($script:LastSnapshotPath)"
            $lines += 'To undo what the run changed, run this as Administrator on this computer (put the password in a file first):'
            $lines += (Get-RollbackCommand)
            $lines += "Or start this wizard again and click 'Undo an earlier run...' on the Action page."
        } else { $lines += 'No state file was written yet for this run, so there is nothing to roll back. Click Check in a new window to see the current state.' }
        foreach($l in $lines){ try { Write-Log $l 'Err' } catch {} }
        try {
            if(-not (Test-Path -LiteralPath $script:RunsDir)){ [void](New-Item -ItemType Directory -Path $script:RunsDir -Force) }
            $f = Join-Path $script:RunsDir ("run-{0:yyyyMMdd-HHmmss}-closed-during-run.txt" -f (Get-Date))
            Set-Content -LiteralPath $f -Value (@($lines) + @('','--- log ---', $script:Log.Text)) -Encoding UTF8
        } catch {}
        Exit-RunLock
        try { [Windows.Forms.MessageBox]::Show(($lines -join "`r`n`r`n"),'Closed during a change',0,'Warning') | Out-Null } catch {}
    }
}
# 'Undo this run (roll back)' on the Result page, 'Undo an earlier run...' on the Action page, or
# offered after a failed run.
function Start-RollbackAction { param([string]$Path='')
    if(-not $Path -or -not (Test-Path -LiteralPath $Path)){
        $dlg=[Windows.Forms.OpenFileDialog]::new(); $dlg.Title='Choose the state file written before the run (run-...-snapshot.json)'
        $dlg.Filter='State before a run (*-snapshot.json)|*-snapshot.json|All files (*.*)|*.*'
        if(Test-Path -LiteralPath $script:RunsDir){ $dlg.InitialDirectory=$script:RunsDir }
        if($dlg.ShowDialog() -ne 'OK'){ return }
        $Path=$dlg.FileName
    }
    try { $s=Read-Snapshot $Path } catch { [Windows.Forms.MessageBox]::Show($_.Exception.Message,'Cannot roll back',0,'Warning')|Out-Null; return }
    $undo = if([string]$s.Action -eq 'on'){ 'OFF' } else { 'ON' }
    $order = if($undo -eq 'ON'){ 'Event Server, then Management Server, then recording servers' } else { 'Management Server, then recording servers, then Event Server' }
    $l=@()
    if($script:LastOutcome -and $script:LastOutcome.PSObject.Properties['Kind'] -and [string]$script:LastOutcome.Kind -in 'on','off' -and $script:LastOutcome.Success -and $Path -eq $script:LastSnapshotPath){
        $l += @("This UNDOES the change you just made successfully (turn encryption $(([string]$s.Action).ToUpper())).",'') }
    $l+=@("Roll back to the state saved at $($s.Created), before 'Turn encryption $(([string]$s.Action).ToUpper())'?",'','What will happen:',
         ' - Every computer is checked first. If something is wrong, nothing is changed.',
         " - Only the computers that this run changed are turned $undo again. Computers that were already in that state before the run stay as they are.",
         " - The steps run in the safe order for turning encryption ${undo}: $order.")
    $l += @(Get-ClusterConfirmLines)
    if(-not (Test-HasPsTools)){ $l += $script:PsToolsConfirmLine }
    foreach($r in @($s.Roles)){ $l += " - The cluster role '$($r.Group)' is moved back to $($r.Owner), where it was before the run." }
    $l += @('','Milestone services restart. Video and clients can be interrupted for several minutes - use a maintenance window.')
    if([Windows.Forms.MessageBox]::Show(($l -join "`r`n"),'Please confirm the rollback',4,'Question') -ne 'Yes'){ return }
    $script:ChangeInProgress=$true; $script:RollbackBtn.Enabled=$false
    Set-Busy $true
    try {
        Show-Page 3; $script:BusyLabel.Visible=$true; [Windows.Forms.Application]::DoEvents()
        $res=@(Invoke-GuidedRollback $Path)[-1]
        $script:LastOutcome=$res
        Show-RunOutcome $res
        $script:Page=4
    } catch {
        Write-Log "Rollback failed: $(Format-Err $_)" 'Err'; Write-ErrorTrace $_
        [Windows.Forms.MessageBox]::Show("Unexpected error:`r`n$(Get-FirstLine $_.Exception.Message)`r`n`r`nSee 'Show details' on the Action page.",'Error',0,'Error')|Out-Null
    } finally { $script:ChangeInProgress=$false; $script:BusyLabel.Visible=$false; Set-Busy $false; Update-RollbackButton; Show-Page $script:Page }
}
# 'Re-register this node' (Action page, visible only on a clustered Management Server).
function Start-RegisterAction {
    if(-not $script:MsCluster){ return }
    [void](Update-ClusterInfo 'MS')
    $cl=$script:MsCluster
    $q="Re-register this node ($env:COMPUTERNAME) with the Management Server cluster?`r`n`r`n" +
       "Use this when the Management Server does not start on this node after a failover (Milestone logs 'invalid_client').`r`n`r`n" +
       "What will happen:`r`n" +
       " - Checks first: this node must run the role '$($cl.Group)' now (it runs on $($cl.Owner) at the moment), and every cluster node must be Up. If not, nothing is changed.`r`n" +
       " - All cluster nodes are paused (for a moment no node can take the role over).`r`n" +
       " - ServerConfigurator registers this node again with the cluster address $($cl.Address).`r`n" +
       " - The nodes are resumed, and the wizard waits up to 5 minutes for the Management Server.`r`n`r`n" +
       "Afterwards THIS node can run the Management Server; the other Management Server node(s) need the same step after their next failover.`r`n" +
       'The Management Server is unavailable for a few minutes.'
    if([Windows.Forms.MessageBox]::Show($q,'Please confirm',4,'Question') -ne 'Yes'){ return }
    $script:ChangeInProgress=$true; $script:RollbackBtn.Enabled=$false
    Set-Busy $true
    try {
        Show-Page 3; $script:BusyLabel.Visible=$true; [Windows.Forms.Application]::DoEvents()
        $res=@(Invoke-RegisterAction)[-1]
        $script:LastOutcome=$res
        Show-RunOutcome $res
        $script:Page=4
    } catch {
        Write-Log "Re-register failed: $(Format-Err $_)" 'Err'; Write-ErrorTrace $_
        [Windows.Forms.MessageBox]::Show("Unexpected error:`r`n$(Get-FirstLine $_.Exception.Message)`r`n`r`nSee 'Show details' on this page.",'Error',0,'Error')|Out-Null
    } finally { $script:ChangeInProgress=$false; $script:BusyLabel.Visible=$false; Set-Busy $false; Update-RollbackButton; Show-Page $script:Page }
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
$script:NoEsChk=New-UiCheck 'The Event Server is on this computer, or not installed' 320 168; $script:NoEsChk.Checked=[bool]$NoEventServer; $p1.Controls.Add($script:NoEsChk)
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
$script:CheckGrid=New-StateGrid 24 50 950 320; $p2.Controls.Add($script:CheckGrid)
$script:ClusterLabel=New-UiLabel '' 24 376 950 120; $script:ClusterLabel.TextAlign='TopLeft'; $script:ClusterLabel.Anchor='Bottom,Left,Right'; $p2.Controls.Add($script:ClusterLabel)
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
$script:FailoverChk=New-UiCheck 'Test failover after the change (move each cluster role to every other node and back)' 24 178 950; $script:FailoverChk.Checked=$true; $script:FailoverChk.Visible=$false; $p3.Controls.Add($script:FailoverChk)
$script:StageGrid=[Windows.Forms.DataGridView]::new(); $script:StageGrid.Location=[Drawing.Point]::new(24,212); $script:StageGrid.Size=[Drawing.Size]::new(950,160); $script:StageGrid.Anchor='Top,Left,Right'
$script:StageGrid.AllowUserToAddRows=$false; $script:StageGrid.AllowUserToDeleteRows=$false; $script:StageGrid.RowHeadersVisible=$false; $script:StageGrid.ReadOnly=$true
$script:StageGrid.BackgroundColor=[Drawing.Color]::White; $script:StageGrid.RowTemplate.Height=30; $script:StageGrid.ColumnHeadersHeight=34
foreach($c in @(@('Step','Step',260),@('Who','Computers',280),@('Status','Status',400))){
    $col=[Windows.Forms.DataGridViewTextBoxColumn]::new(); $col.Name=$c[0]; $col.HeaderText=$c[1]; $col.Width=$c[2]; $col.SortMode='NotSortable'; [void]$script:StageGrid.Columns.Add($col) }
$script:StageGrid.Columns['Status'].AutoSizeMode='Fill'
$p3.Controls.Add($script:StageGrid)
$script:BusyLabel=New-UiLabel 'Working - this can take several minutes (on a cluster: longer). The window may stop responding while a server restarts. Please wait and do not close it.' 24 376 950 50
$script:BusyLabel.TextAlign='TopLeft'; $script:BusyLabel.Font=$script:UiBold; $script:BusyLabel.ForeColor=[Drawing.Color]::DarkOrange; $script:BusyLabel.Visible=$false; $p3.Controls.Add($script:BusyLabel)
$detailsBtn=New-UiButton 'Show details' 24 430 180 34; $p3.Controls.Add($detailsBtn)
$undoOldBtn=New-UiButton 'Undo an earlier run...' 214 430 260 34; $p3.Controls.Add($undoOldBtn)
$undoOldBtn.Add_Click({ Start-RollbackAction '' })   # asks for the run-...-snapshot.json of that run
$script:RegBtn=New-UiButton 'Re-register this node' 594 430 380 34; $script:RegBtn.Anchor='Top,Right'; $script:RegBtn.Visible=$false; $p3.Controls.Add($script:RegBtn)
$script:RegBtn.Add_Click({ Start-RegisterAction })
$script:Log=[Windows.Forms.RichTextBox]::new(); $script:Log.Location=[Drawing.Point]::new(24,470); $script:Log.Size=[Drawing.Size]::new(950,142); $script:Log.ReadOnly=$true
$script:Log.Anchor='Top,Bottom,Left,Right'; $script:Log.Font=[Drawing.Font]::new('Consolas',9); $script:Log.Visible=$false; $p3.Controls.Add($script:Log)
$detailsBtn.Add_Click({ $script:Log.Visible = -not $script:Log.Visible; $this.Text = if($script:Log.Visible){'Hide details'}else{'Show details'} })

# ---- page 4: Result ----
$p4=$script:Pages[3]
$script:ResultLabel=New-UiLabel '' 24 10 950 60; $script:ResultLabel.Font=[Drawing.Font]::new('Segoe UI',14,[Drawing.FontStyle]::Bold); $script:ResultLabel.TextAlign='TopLeft'; $p4.Controls.Add($script:ResultLabel)
$script:FinalGrid=New-StateGrid 24 76 950 250; $script:FinalGrid.Anchor='Top,Left,Right'; $p4.Controls.Add($script:FinalGrid)
$script:NotesBox=[Windows.Forms.TextBox]::new(); $script:NotesBox.Multiline=$true; $script:NotesBox.ReadOnly=$true; $script:NotesBox.ScrollBars='Vertical'
$script:NotesBox.Location=[Drawing.Point]::new(24,332); $script:NotesBox.Size=[Drawing.Size]::new(950,128); $script:NotesBox.Anchor='Top,Bottom,Left,Right'; $p4.Controls.Add($script:NotesBox)
$repLbl=New-UiLabel 'Report file:' 24 468 120; $repLbl.Anchor='Bottom,Left'; $p4.Controls.Add($repLbl)
$script:ReportBox=New-UiText 150 470 620 ''; $script:ReportBox.ReadOnly=$true; $script:ReportBox.Anchor='Bottom,Left,Right'; $p4.Controls.Add($script:ReportBox)
$openBtn=New-UiButton 'Open report folder' 780 466 194; $openBtn.Anchor='Bottom,Right'; $p4.Controls.Add($openBtn)
$openBtn.Add_Click({ if($script:ReportBox.Text -and (Test-Path -LiteralPath $script:ReportBox.Text)){ Start-Process explorer.exe -ArgumentList "/select,`"$($script:ReportBox.Text)`"" } elseif(Test-Path -LiteralPath $script:RunsDir){ Start-Process explorer.exe -ArgumentList "`"$($script:RunsDir)`"" } })
$repHint=New-UiLabel 'Keep this file. If something failed, send it (and the -log.txt file next to it) to support.' 24 508 950 30; $repHint.Anchor='Bottom,Left'; $p4.Controls.Add($repHint)
$script:RollbackBtn=New-UiButton 'Undo this run (roll back)' 24 544 320 40; $script:RollbackBtn.Anchor='Bottom,Left'; $script:RollbackBtn.Enabled=$false; $p4.Controls.Add($script:RollbackBtn)
$script:RollbackBtn.Add_Click({ Start-RollbackAction $script:LastSnapshotPath })
$rbHint=New-UiLabel 'Changes back only what the last run changed. Available only while there is something to undo.' 354 544 620 40; $rbHint.Anchor='Bottom,Left,Right'; $rbHint.TextAlign='MiddleLeft'; $p4.Controls.Add($rbHint)

$script:BackBtn.Add_Click({ if($script:Page -gt 1){ Show-Page ($script:Page - 1) } })
$script:NextBtn.Add_Click({ switch($script:Page){ 1 { Do-Connect } 2 { Show-Page 3 } 3 { Show-Page 4 } default { $script:Form.Close() } } })

$script:BusyCtrls=@($script:BackBtn,$script:NextBtn,$onBtn,$offBtn,$recheckBtn,$findCaBtn,$createCaBtn,$script:RegBtn,$undoOldBtn,$script:FailoverChk)   # RollbackBtn: Update-RollbackButton decides

# Closing the window in the middle of a change can leave cluster nodes paused or a role elsewhere.
$script:Form.Add_FormClosing({
    param($sender,$e)
    if(-not $script:ChangeInProgress){ return }
    $q = 'A change is in progress. Closing now can leave cluster nodes paused or a role on another node. Close anyway?'
    if([Windows.Forms.MessageBox]::Show($q,'A change is in progress',4,'Warning',[Windows.Forms.MessageBoxDefaultButton]::Button2) -ne 'Yes'){ $e.Cancel = $true; return }
    Invoke-CloseCleanup
})

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
        $script:FixRegistrationOn = [bool]$FixRegistration   # on / off / register / rollback pre-flight
        $snapObj = $null
        if($Action -eq 'rollback'){
            # The Event Server (and the recording servers) of the rolled-back run come from the snapshot.
            try { $snapObj = Read-Snapshot $Snapshot } catch { Write-Log "REFUSED: $($_.Exception.Message) (pass -Snapshot <run-...-snapshot.json>)" 'Err'; exit 3 }
            $NoEventServer = [switch]([bool]$snapObj.NoEventServer)
            $EsHost = [string]$snapObj.EsHost
            if(-not $script:DomainBox.Text.Trim() -and $snapObj.PSObject.Properties['Domain'] -and $snapObj.Domain){ $script:DomainBox.Text = [string]$snapObj.Domain }
        }
        if($Action -eq 'register' -and ([string]::IsNullOrWhiteSpace($EsHost) -or $EsHost -match '<[^>]+>')){ $NoEventServer = [switch]$true }   # register touches this node only
        $script:NoEsChk.Checked   = [bool]$NoEventServer
        $script:EsHostBox.Text    = $(if($NoEventServer){ '' } else { $EsHost })
        if($RecPwFile){
            if(-not (Test-Path -LiteralPath $RecPwFile)){ Write-Log "REFUSED: -RecPwFile not found: $RecPwFile" 'Err'; exit 3 }
            if([string]::IsNullOrWhiteSpace($RecUser)){ Write-Log 'REFUSED: -RecPwFile given without -RecUser' 'Err'; exit 3 }
            $script:RecSepChk.Checked=$true; $script:RecUserBox.Text=$RecUser; $script:RecPwBox.Text=(Get-Content -Raw -LiteralPath $RecPwFile).Trim()
        }
        $script:SignerSubjectBox.Text=$RootSubject; $script:RootSubjectForRun=$RootSubject
        try { Read-Inputs } catch { Write-Log "REFUSED: $($_.Exception.Message)" 'Err'; exit 3 }
        $discover = [string]::IsNullOrWhiteSpace($RecTargets) -and ($Action -in 'on','off','status')
        $err = Initialize-Targets -ManualList $RecTargets -Discover $discover
        if($err -and $discover){ Write-Log "REFUSED: the recording servers could not be discovered ($err). Pass -RecTargets to list them." 'Err'; exit 3 }
        foreach($l in ((Get-ClusterSummary) -split "`r`n")){ Write-Log $l }
        if($Action -eq 'register'){
            $res=@(Invoke-RegisterAction)[-1]
            foreach($l in ((Get-OutcomeText $res) -split "`r`n")){ Write-Log $l $(if($res.Success){'Good'}else{'Err'}) }
            exit ([int](-not $res.Success))
        }
        if($Action -eq 'rollback'){
            $res=@(Invoke-GuidedRollback $Snapshot)[-1]
            foreach($l in ((Get-OutcomeText $res) -split "`r`n")){ Write-Log $l $(if($res.Success){'Good'}else{'Err'}) }
            exit ([int](-not $res.Success))
        }
        if($Action -eq 'status'){
            $script:RunStart=Get-Date
            $all=@(Get-AllBoxes); Update-BoxStates $all
            Write-StateLog 'CURRENT STATE' $all
            # Registration check: reported only (a status run changes nothing).
            foreach($x in @(Get-RegistrationMismatches $all)){ Add-GuidedRow $x.Box 'registration-check' $false (Get-RegFindingText $x) "read from $($x.Source)" }
            foreach($b in $all){ Add-GuidedRow $b 'status' ([bool]$b.Reachable -and $null -ne $b.Encrypted) "state $(Get-StateText $b)" $b.Detail }
            $allOk = (@($all | Where-Object { -not $_.Reachable -or $null -eq $_.Encrypted }).Count -eq 0)
            Write-Log "OVERALL: $(if($allOk){'every computer reachable'}else{'some computers could not be read'})" $(if($allOk){'Good'}else{'Err'})
            Save-Report
            if($script:LastReportPath){ Write-Log "Report: $script:LastReportPath" 'Good' }
            exit ([int](-not $allOk))
        }
        $script:TestFailoverOn = [bool]$TestFailover
        $res=@(Invoke-GuidedRun $Action)[-1]
        foreach($l in ((Get-OutcomeText $res) -split "`r`n")){ Write-Log $l $(if($res.Success){'Good'}else{'Err'}) }
        if(-not $res.Success -and $script:LastSnapshotPath -and (Test-RollbackUseful)){
            Write-Log "To undo what this run changed: $(Get-RollbackCommand)" 'Err' }
        # W7: encryption succeeded but the failover self-test failed -> exit 4, distinct from a plain 0/1.
        if($res.Success -and $res.PSObject.Properties['FailoverFailed'] -and $res.FailoverFailed){ exit 4 }
        exit ([int](-not $res.Success))
    } catch { Write-Log "GUIDED FATAL: $(Format-Err $_)" 'Err'; Write-ErrorTrace $_; exit 2 }
} else {
    [void](Update-CaStatus)
    [void]$script:Form.ShowDialog()
}
