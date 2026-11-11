<#
.SYNOPSIS
    Restart IIS once on the node that has just taken over the Management Server role (WSFC Generic Application).
.DESCRIPTION
    For a clustered Milestone XProtect Management Server: after a failover the Management Server service can be
    running while logins fail (field report: only an iisreset on the new node fixed it). This script is a cluster
    resource in the Management Server role. Every time the role comes online on a node, the cluster starts it;
    it runs iisreset /restart once and then stays running so the resource stays Online.

    What it does NOT fix: a node whose Management Server service does not start, or crash-loops with
    'invalid_client' in its log (stale IDP secret on that node). iisreset does not help there; use "Re-register
    this node" in Mrc-Guided.ps1.

    -Watch (the only mode that does anything; the cluster uses it, as SYSTEM):
      1. iisreset.exe /restart (once, at start).
      2. Application event log, source 'MRC IIS restart' (created if missing): event 101 Information on success,
         event 100 Error on failure (text names the exit code). Also written to Mrc-ClusterIisReset.log next to
         this file.
      3. Sleeps for ever. It never exits on an error: an exit is a resource failure, the cluster would restart the
         resource and run iisreset again and again.
    Without -Watch it prints this usage and changes nothing.

    Cluster setup (WSFC Generic Application, runs as SYSTEM; administrator, Windows PowerShell 5.1):
      1. On EVERY Management Server cluster node copy this file to the same local folder that only administrators
         can write (a local disk, not a cluster disk), for example
         C:\Program Files\MilestoneRecorderCertManager\Mrc-ClusterIisReset.ps1
      2. If an older 'MRC IIS restart' resource of type Generic Script exists (the former .js version), remove it first:
           Remove-ClusterResource 'MRC IIS restart'
      3. On one node (names from Failover Cluster Manager):
           $role = '<Management Server role name>'; $ms = '<Management Server service resource name>'
           Add-ClusterResource -Name 'MRC IIS restart' -ResourceType 'Generic Application' -Group $role
           Get-ClusterResource 'MRC IIS restart' | Set-ClusterParameter -Multiple @{
               CommandLine = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\Program Files\MilestoneRecorderCertManager\Mrc-ClusterIisReset.ps1" -Watch'
               CurrentDirectory = 'C:\Program Files\MilestoneRecorderCertManager'; UseNetworkName = 0 }
           Add-ClusterResourceDependency -Resource 'MRC IIS restart' -Provider $ms
           Start-ClusterResource 'MRC IIS restart'   # restarts IIS once on the node that runs the role now
    Check: the resource is Online; Application log has event 101 from 'MRC IIS restart' after each online.
    Remove: Stop-ClusterResource 'MRC IIS restart'; Remove-ClusterResource 'MRC IIS restart'; delete the file on
    every node.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Mrc-ClusterIisReset.ps1
    Prints the usage. Nothing is changed.
.EXAMPLE
    powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Mrc-ClusterIisReset.ps1 -Watch
    What the cluster runs: one iisreset /restart, then stays running.
#>
[CmdletBinding()]
param(
    [switch]$Watch,
    [string]$LogFile = ''   # empty: Mrc-ClusterIisReset.log next to this file
)
$ErrorActionPreference = 'Continue'
if(-not $Watch){
    Write-Output 'Mrc-ClusterIisReset.ps1 - restarts IIS once when the clustered Management Server role comes online on this node.'
    Write-Output 'Usage: powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File Mrc-ClusterIisReset.ps1 -Watch'
    Write-Output 'It is run by the cluster as a Generic Application resource (as SYSTEM). Without -Watch nothing is changed.'
    Write-Output 'Install and remove steps: see the header of this file.'
    exit 0
}
$eventSource = 'MRC IIS restart'
# Resolved here at script level: inside a function $MyInvocation describes the function and has no Path.
$script:IisLogPath = if($LogFile){ $LogFile } else { Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Mrc-ClusterIisReset.log' }
function Write-IisLog { param([string]$Text)
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME, $Text
    try {
        $lf = $script:IisLogPath
        Add-Content -LiteralPath $lf -Value $line -Encoding ASCII
    } catch {}
    Write-Output $line
}
# Application event log entry: 101 Information on success, 100 Error on failure. Never throws.
function Write-IisEvent { param([int]$Id,[string]$Type,[string]$Text)
    try {
        if(-not [System.Diagnostics.EventLog]::SourceExists($eventSource)){ New-EventLog -LogName Application -Source $eventSource -ErrorAction Stop }
        Write-EventLog -LogName Application -Source $eventSource -EventId $Id -EntryType $Type -Message $Text -ErrorAction Stop
    } catch { Write-IisLog "could not write the event log entry ($($_.Exception.Message))" }
}
try {
    $exe = Join-Path $env:windir 'System32\iisreset.exe'
    Write-IisLog "iisreset /restart starting"
    $rc = -1
    try { $p = Start-Process -FilePath $exe -ArgumentList '/restart' -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop; $rc = [int]$p.ExitCode }
    catch { Write-IisLog "iisreset could not be started: $($_.Exception.Message)" }
    if($rc -eq 0){
        Write-IisLog 'iisreset /restart exit code 0'
        Write-IisEvent 101 'Information' 'MRC IIS restart: iisreset /restart finished with exit code 0 after the Management Server role came online on this node.'
    } else {
        Write-IisLog "iisreset /restart exit code $rc - the Management Server role stays online"
        Write-IisEvent 100 'Error' "MRC IIS restart: iisreset /restart exit code $rc - the Management Server role stays online; restart IIS on this node by hand."
    }
} catch {
    Write-IisLog "FAILED: $($_.Exception.Message) - the Management Server role stays online"
    Write-IisEvent 100 'Error' "MRC IIS restart: FAILED: $($_.Exception.Message) - the Management Server role stays online; restart IIS on this node by hand."
}
# Stay running for as long as the cluster keeps the resource Online (an exit would be a resource failure).
while($true){ try { Start-Sleep -Seconds 3600 } catch { Start-Sleep -Seconds 60 } }
