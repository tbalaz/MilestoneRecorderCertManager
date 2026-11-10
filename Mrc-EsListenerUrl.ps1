<#
.SYNOPSIS
    Keep the Event Server's registered services on the Event Server cluster listener instead of a node name.
.DESCRIPTION
    ServerConfigurator registers a clustered Event Server's services ('Event Server service', 'Alarms Service') with
    the Management Server under the FQDN of the node it ran on. After a role move the Smart Client and the API Gateway
    still go to that node (alarms API 504). This script sets the host of those registered URLs to the Event Server
    cluster listener (scheme, port and path stay) - the same change as Management Client > Tools > Registered
    Services > Edit. MilestonePSTools Update-RegisteredService cannot do it ('Bad request: Duplicate id'), so the
    entry is removed and added again with the same name, type, instance id and description (lab 2026-11-10: Trusted
    stays, the API Gateway route follows within seconds, alarms API 200 with the role on either node).

    It logs in to the Management Server as the CURRENT Windows account. Run by the cluster that is SYSTEM, so the
    Management Server sees the node's computer account (DOMAIN\NODE$). Milestone servers running as NETWORK SERVICE
    already have their computer accounts in the Milestone Administrators role; if not, add them.

    -Watch (for the cluster): never exits; checks every -IntervalSec seconds and fixes the URLs again, so a
    ServerConfigurator "Event server and add-ons" run, which writes the node name back, is corrected within a minute.

    Cluster setup (WSFC Generic Application, runs as SYSTEM; on EVERY Event Server node first):
      1. Copy this file to the same local folder that only administrators can write, for example
         C:\Program Files\MilestoneRecorderCertManager\Mrc-EsListenerUrl.ps1, and fill in -MsAddress / -Listener below.
      2. MilestonePSTools installed for all users (C:\Program Files\WindowsPowerShell\Modules).
      3. Test once by hand: powershell -ExecutionPolicy Bypass -File "<path>\Mrc-EsListenerUrl.ps1"
      4. On one node (names from Failover Cluster Manager):
           $role = '<Event Server role name>'; $es = '<Event Server service resource name>'
           Add-ClusterResource -Name 'MRC ES listener URL' -ResourceType 'Generic Application' -Group $role
           Get-ClusterResource 'MRC ES listener URL' | Set-ClusterParameter -Multiple @{
               CommandLine = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\Program Files\MilestoneRecorderCertManager\Mrc-EsListenerUrl.ps1" -Watch'
               CurrentDirectory = 'C:\Program Files\MilestoneRecorderCertManager'; UseNetworkName = 0 }
           Add-ClusterResourceDependency -Resource 'MRC ES listener URL' -Provider $es
           Start-ClusterResource 'MRC ES listener URL'
      Remove: Remove-ClusterResource 'MRC ES listener URL', then delete the file on every node.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Mrc-EsListenerUrl.ps1
    powershell -ExecutionPolicy Bypass -File .\Mrc-EsListenerUrl.ps1 -MsAddress https://ms-listener.example.local -Listener es-listener.example.local
    One pass: exit 0 = the registered services point at the listener (changed or already right), 1 = failed (see the log).
#>
[CmdletBinding()]
param(
    [string]$MsAddress = '<management-server-address, e.g. https://ms-listener.example.local>',
    [string]$Listener  = '<event-server-listener-fqdn, e.g. es-listener.example.local>',
    [string[]]$Names   = @('Event Server service','Alarms Service'),
    [string]$LogFile   = '',   # empty: Mrc-EsListenerUrl.log next to this file
    [switch]$Watch,
    [int]$IntervalSec  = 60
)
$ErrorActionPreference = 'Stop'
# PS 5.1 leaves $PSScriptRoot empty in parameter defaults; resolve the log path in the body.
if(-not $LogFile){ $LogFile = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Mrc-EsListenerUrl.log' }
function Write-UrlLog { param([string]$Text)
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME, $Text
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding ASCII } catch {}
    Write-Output $line
}
# The same URL with its host replaced by $NewHost (scheme, port, path, query kept). Pure.
function Get-ListenerUri { param([string]$Uri,[string]$NewHost)
    $b = New-Object System.UriBuilder($Uri)
    if($b.Host -ieq $NewHost){ return $Uri }
    $b.Host = $NewHost
    $b.Uri.AbsoluteUri
}
# One pass over the named registered services. Returns $true when all of them point at the listener.
function Set-ListenerUrls {
    $found = 0
    foreach($n in $Names){
        foreach($svc in @(Get-RegisteredService -Name $n)){
            $found++
            $old = @($svc.UriArray | ForEach-Object { [string]$_ })
            if($old.Count -ne 1){ Write-UrlLog "'$($svc.Name)' has $($old.Count) URLs ($($old -join ', ')) - left as it is"; continue }
            $new = Get-ListenerUri $old[0] $Listener
            if($new -eq $old[0]){ continue }
            Remove-RegisteredService -RegisteredService $svc -ErrorAction Stop
            try { Add-RegisteredService -Name $svc.Name -Uri $new -ServiceType $svc.Type -InstanceId $svc.Instance -Description $svc.Description -ErrorAction Stop | Out-Null
                  Write-UrlLog "'$($svc.Name)': $($old[0]) -> $new" }
            catch { Write-UrlLog "'$($svc.Name)': re-add with $new FAILED ($($_.Exception.Message)) - putting $($old[0]) back"
                    Add-RegisteredService -Name $svc.Name -Uri $old[0] -ServiceType $svc.Type -InstanceId $svc.Instance -Description $svc.Description -ErrorAction Stop | Out-Null
                    throw }
        }
    }
    if($found -eq 0){ throw "no registered service named $($Names -join ' / ') found" }
    $true
}
if($MsAddress -match '^<' -or $Listener -match '^<'){ Write-UrlLog 'NOT CONFIGURED: set -MsAddress and -Listener (top of this file or as parameters).'; if($Watch){ while($true){ Start-Sleep 3600 } }; exit 1 }
Import-Module MilestonePSTools -ErrorAction Stop
$connected = $false; $lastOk = $null
do {
    try {
        if(-not $connected){ Connect-Vms -ServerAddress $MsAddress -AcceptEula -ErrorAction Stop | Out-Null; $connected = $true
            Write-UrlLog "connected to $MsAddress as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)$(if($Watch){", watching every $IntervalSec s"})" }
        [void](Set-ListenerUrls)
        if($lastOk -ne $true){ Write-UrlLog "registered services $($Names -join ' / ') point at $Listener" }
        $lastOk = $true
        if(-not $Watch){ Disconnect-Vms -ErrorAction SilentlyContinue; exit 0 }
    } catch {
        Write-UrlLog "FAILED: $($_.Exception.Message)"
        $lastOk = $false
        try { Disconnect-Vms -ErrorAction SilentlyContinue } catch {}
        $connected = $false
        if(-not $Watch){ exit 1 }
    }
    Start-Sleep -Seconds $IntervalSec
} while($Watch)
