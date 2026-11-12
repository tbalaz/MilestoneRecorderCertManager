# helper.ps1 - commands for 'token validation failed' in the Event Server log.
#
# Copy-paste only the block for the computer you are on, in Windows PowerShell started
# "as Administrator". Fill in the values below first. Blocks 1-4 only read; the fix in
# block 5 is commented out and changes one Event Server node's registration.

$MsName = '<ms-dnsname>'                  # the management server address every server must use
$EsRole = '<event-server-cluster-role>'   # the Event Server cluster role (block 5 only)


# --- 1. On a Management Server node: which node runs the role, and the IDP address per node -
# ServerConfig.xml is per node, so the nodes can differ.
Get-ClusterGroup | Select-Object Name,OwnerNode,State | Out-String
Get-ClusterNode | ForEach-Object { Invoke-Command -ComputerName $_.Name { "$env:COMPUTERNAME " + ([xml](Get-Content 'C:\ProgramData\Milestone\XProtect Management Server\ServerConfig.xml')).SelectSingleNode('//AuthorizationServerUri').InnerText } }


# --- 2. On a Management Server node: the cluster IP addresses and what the MS name resolves to
Get-ClusterResource | Where-Object ResourceType -eq 'IP Address' | Get-ClusterParameter -Name Address | Select-Object ClusterObject,Value | Out-String
Resolve-DnsName $MsName -Type A | Select-Object Name,IPAddress | Out-String


# --- 3. On an Event Server node: which node runs the ES role, each ES node's MS address and
#        what it resolves to, the IDP issuer, the clock
# Every ES node must point to $MsName (or a name with the same IP). Another address = that
# node talks to a different management server whenever it runs the role.
Get-ClusterGroup | Select-Object Name,OwnerNode,State | Out-String
Get-ClusterNode | ForEach-Object { Invoke-Command -ComputerName $_.Name { $a = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Milestone\XProtect Event Server').ManagementServerAddress; "$env:COMPUTERNAME $a -> " + (@((Resolve-DnsName ([uri]$a).Host -Type A -ErrorAction SilentlyContinue).IPAddress) -join ',') } }
"MS name $MsName -> " + (@((Resolve-DnsName $MsName -Type A).IPAddress) -join ',')
(Invoke-RestMethod "http://$MsName/IDP/.well-known/openid-configuration").issuer
net time \\$MsName
Get-Date
# The two times must be within a few minutes of each other.


# --- 4. On the Event Server node that runs the role: the first 'validation failed' entries ----
$log = Get-ChildItem 'C:\ProgramData\Milestone\XProtect Event Server\logs' -Recurse -Filter *.log -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
"$env:COMPUTERNAME $($log.FullName)"
Select-String -LiteralPath $log.FullName -Pattern 'validation failed' -Context 1,8 | Select-Object -First 2 | Out-String -Width 300


# --- 5. FIX, on the Event Server node that block 3 shows with a different MS address ---------
# Moves the ES role to this node, stops the role's services, registers this node with $MsName,
# starts the role again. The Event Server is down for about 1-2 minutes.
# Move-ClusterGroup -Name $EsRole -Node $env:COMPUTERNAME
# Get-ClusterGroup $EsRole | Get-ClusterResource | Where-Object ResourceType -eq 'Generic Service' | Stop-ClusterResource
# & "$env:ProgramFiles\Milestone\Server Configurator\ServerConfigurator.exe" /register /managementserveraddress=http://$MsName/ /quiet | Out-Null
# (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Milestone\XProtect Event Server').ManagementServerAddress
# Start-ClusterGroup -Name $EsRole
# Get-ClusterGroup $EsRole | Get-ClusterResource | Select-Object Name,State,OwnerNode | Out-String
