# helper.ps1 - commands for Management Server / IDP token problems on a clustered MS
# (Event Server 'token validation failed', recorders 'Unauthorized during ValidatePublicAddress',
#  Management Server not starting after an IDP address change or a re-register).
#
# Copy-paste only the block for the computer you are on, in Windows PowerShell started
# "as Administrator". Fill in the values below first. Blocks 1-3 only read; the actions in
# block 4 are commented out.

$MsName    = '<ms-dnsname>'                  # the MS cluster name every server must use
$MsRole    = '<ms-cluster-role>'             # the Management Server cluster role
$EsRole    = '<event-server-cluster-role>'   # the Event Server cluster role
$Recorders = @('<recorder1>','<recorder2>')  # recording servers to restart (block 4)


# --- 1. On a Management Server node -------------------------------------------------------------
# Where the MS role runs, the IDP address on every node, the last ServerConfigurator result,
# the MS self-call that fails at startup, recent errors, the IDP issuer.
"=== $env:COMPUTERNAME  $(Get-Date)"
Get-ClusterGroup | Select-Object Name,OwnerNode,State | Out-String
Get-ClusterNode | ForEach-Object { Invoke-Command -ComputerName $_.Name { "$env:COMPUTERNAME " + ([xml](Get-Content 'C:\ProgramData\Milestone\XProtect Management Server\ServerConfig.xml')).SelectSingleNode('//AuthorizationServerUri').InnerText + '  MS service: ' + (Get-Service -DisplayName 'Milestone XProtect Management Server' -ErrorAction SilentlyContinue).Status } }
$sc = 'C:\ProgramData\Milestone\Server Configurator\Logs\ServerConfiguratorApplication.log'
"SC log written: $((Get-Item $sc -ErrorAction SilentlyContinue).LastWriteTime)"
Select-String -LiteralPath $sc -Pattern 'Registration done with result|managementserveraddress|Status = (?!Success)' -ErrorAction SilentlyContinue | Select-Object -Last 6 | ForEach-Object { $_.Line } | Out-String -Width 300
try { $null = Invoke-WebRequest 'http://localhost/ManagementServer/ServerService.svc' -UseBasicParsing; 'ServerService.svc: OK' } catch { 'ServerService.svc: ' + $_.Exception.Message; $r = $_.Exception.Response; if($r){ $s = (New-Object IO.StreamReader($r.GetResponseStream())).ReadToEnd(); $s.Substring(0,[Math]::Min(1500,$s.Length)) } }
Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=(Get-Date).AddMinutes(-30)} -MaxEvents 5 -ErrorAction SilentlyContinue | Format-List TimeCreated,ProviderName,Message | Out-String -Width 250
try { 'IDP issuer: ' + (Invoke-RestMethod "http://$MsName/IDP/.well-known/openid-configuration").issuer } catch { 'IDP issuer: ' + $_.Exception.Message }
Import-Module WebAdministration -ErrorAction SilentlyContinue; Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue | Select-Object Name,State | Out-String


# --- 2. On an Event Server node -----------------------------------------------------------------
# Where the ES role runs, each ES node's MS address, the LAST 'validation failed' entries
# (their time shows whether it still happens).
"=== $env:COMPUTERNAME  $(Get-Date)"
Get-ClusterGroup | Select-Object Name,OwnerNode,State | Out-String
Get-ClusterNode | ForEach-Object { Invoke-Command -ComputerName $_.Name { "$env:COMPUTERNAME " + (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Milestone\XProtect Event Server' -ErrorAction SilentlyContinue).ManagementServerAddress } }
$log = Get-ChildItem 'C:\ProgramData\Milestone\XProtect Event Server\logs' -Recurse -Filter *.log -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
"ES log: $($log.FullName)"
Select-String -LiteralPath $log.FullName -Pattern 'validation failed' -ErrorAction SilentlyContinue | Select-Object -Last 3 | ForEach-Object { $_.Line } | Out-String -Width 300


# --- 3. On one recording server -----------------------------------------------------------------
# Its MS address and the last token / unauthorized / 401 lines of the last hour.
"=== $env:COMPUTERNAME  $(Get-Date)"
Get-ChildItem 'C:\Program Files\Milestone\XProtect Data Collector Server\appsettings.json','D:\Programs\Milestone\XProtect Data Collector Server\appsettings.json' -ErrorAction SilentlyContinue | ForEach-Object { "$($_.FullName): " + (Get-Content $_.FullName -Raw | ConvertFrom-Json).ManagementServerAddress }
$recLogs = Get-ChildItem 'C:\ProgramData\Milestone\XProtect Recording Server\Logs' -Recurse -Filter *.log -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt (Get-Date).AddHours(-1)
$recLogs | Select-String -Pattern 'token|unauthori|401' | Select-Object -Last 8 | ForEach-Object { "$($_.Filename): $($_.Line)" } | Out-String -Width 300


# --- 4. ACTIONS - uncomment only the line you need ----------------------------------------------
# Move the MS role to the node that ran ServerConfigurator LAST (only that node can start the MS):
# Move-ClusterGroup -Name $MsRole -Node '<node>'
# After the MS runs again: restart the recorders (from the MS) so they load the current IDP issuer:
# Invoke-Command -ComputerName $Recorders { Restart-Service -DisplayName 'Milestone XProtect Recording Server' }
# ...and the Event Server role (on an ES node):
# Stop-ClusterGroup -Name $EsRole; Start-ClusterGroup -Name $EsRole


# --- 5. RECOVERY: the MS cannot start because the recorders flood it with requests -------------
# A temporary firewall rule on every MS node blocks the recorders' addresses while the MS starts.
# Recorders keep recording while the MS is unreachable (stopping their service would stop recording).
# On the MS node that ran ServerConfigurator LAST. $Recorders (top) must list EVERY recording server.
# Pasting this file only DEFINES the functions below; nothing runs until you type a command:
#   Block-MrcRecorders                   block all recorder addresses on every MS node
#   iisreset                             restart IIS on this node (the crashed ManagementServer app,
#                                        and app pools IIS may have stopped after repeated crashes)
#   Start-ClusterGroup -Name $MsRole     start the MS; wait until the Management Client connects
#   Release-MrcRecorders 10              unblock 10 recorders + restart their Recording Server service;
#                                        repeat while the MS stays healthy
#   Remove-MrcRecorderBlock              at the end, or to undo: delete the rule on every MS node
$RuleName = 'MRC TEMP block recorders'
function Get-MrcRecorderIps { param([string[]]$Names)
    foreach($n in $Names){ foreach($ip in @((Resolve-DnsName $n -Type A -ErrorAction Stop).IPAddress)){ [pscustomobject]@{ Name=$n; Ip=[string]$ip } } } }
function Block-MrcRecorders {
    $map = @(Get-MrcRecorderIps $Recorders)
    $protect = @(Get-ClusterNode | ForEach-Object { @((Resolve-DnsName $_.Name -Type A).IPAddress) })
    $protect += @(Get-ClusterResource | Where-Object ResourceType -eq 'IP Address' | Get-ClusterParameter -Name Address | ForEach-Object { [string]$_.Value })
    $bad = @($map | Where-Object { $protect -contains $_.Ip })
    if($bad.Count){ "STOP - these are MS cluster addresses, not recorders: " + (($bad | ForEach-Object { "$($_.Name)=$($_.Ip)" }) -join ', '); return }
    $ips = @($map | ForEach-Object Ip | Sort-Object -Unique)
    "Blocking $($ips.Count) addresses of $(@($Recorders).Count) recorders"
    Get-ClusterNode | ForEach-Object { Invoke-Command -ComputerName $_.Name -ArgumentList $RuleName,$ips { param($rn,$ips)
        Remove-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $rn -Direction Inbound -Action Block -RemoteAddress $ips | Out-Null
        "$env:COMPUTERNAME : rule '$rn' blocks $(@($ips).Count) addresses" } } }
function Release-MrcRecorders { param([int]$Count = 10)
    $blocked = @((Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Get-NetFirewallAddressFilter).RemoteAddress)
    if(-not $blocked.Count){ 'No recorder address is blocked any more.'; return }
    $map = @(Get-MrcRecorderIps $Recorders | Where-Object { $blocked -contains $_.Ip })
    $names = @($map | ForEach-Object Name | Select-Object -Unique | Select-Object -First $Count)
    $free = @($map | Where-Object { $names -contains $_.Name } | ForEach-Object Ip)
    $left = @($blocked | Where-Object { $free -notcontains $_ })
    Get-ClusterNode | ForEach-Object { Invoke-Command -ComputerName $_.Name -ArgumentList $RuleName,$left { param($rn,$left)
        if(@($left).Count){ Set-NetFirewallRule -DisplayName $rn -RemoteAddress $left } else { Remove-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue }
        "$env:COMPUTERNAME : $(@($left).Count) addresses still blocked" } }
    "Restarting the Recording Server service on: $($names -join ', ')"
    Invoke-Command -ComputerName $names { Restart-Service -DisplayName 'Milestone XProtect Recording Server'; "$env:COMPUTERNAME : Recording Server restarted" } }
function Remove-MrcRecorderBlock {
    Get-ClusterNode | ForEach-Object { Invoke-Command -ComputerName $_.Name -ArgumentList $RuleName { param($rn)
        Remove-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue; "$env:COMPUTERNAME : rule '$rn' removed" } } }
