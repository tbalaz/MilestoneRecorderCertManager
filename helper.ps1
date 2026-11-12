# helper.ps1 - commands for 'token validation failed' in the Event Server log
# (the Management Server and the Event Server use different management server addresses).
#
# Copy-paste only the block for the computer you are on, in Windows PowerShell started
# "as Administrator". Fill in the two values below first. Blocks 1-3 only read; the fix
# in block 4 is commented out and changes the Event Server registration.

$MsIp   = '<ms-ip>'          # the address in the MS ServerConfig.xml AuthorizationServerUri
$MsName = '<ms-dnsname>'     # the address the Event Server is registered to


# --- 1. On a Management Server node: the IDP address each MS node publishes -----------------
# ServerConfig.xml is per node, so the nodes can differ.
([xml](Get-Content 'C:\ProgramData\Milestone\XProtect Management Server\ServerConfig.xml')).SelectSingleNode('//AuthorizationServerUri').InnerText
Get-ClusterNode | ForEach-Object { Invoke-Command -ComputerName $_.Name { "$env:COMPUTERNAME " + ([xml](Get-Content 'C:\ProgramData\Milestone\XProtect Management Server\ServerConfig.xml')).SelectSingleNode('//AuthorizationServerUri').InnerText } }


# --- 2. On a Management Server node: is that IP the cluster role's address or a node's own? ---
Get-ClusterResource | Where-Object ResourceType -eq 'IP Address' | Get-ClusterParameter -Name Address | Select-Object ClusterObject,Value


# --- 3. On the Event Server: its MS address, the IDP issuer through both addresses, clock -----
(Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Milestone\XProtect Event Server').ManagementServerAddress
foreach($h in $MsIp,$MsName){ "$h -> " + (Invoke-RestMethod "http://$h/IDP/.well-known/openid-configuration").issuer }
w32tm /stripchart /computer:$MsName /samples:3 /dataonly
# Different issuers on the two lines = the cause. Clock offset over ~300 s = a second problem.


# --- 4. FIX, on the Event Server: register it to the same address the MS publishes -----------
# Only when block 2 shows $MsIp is the cluster ROLE's IP. The Event Server restarts (~30 s).
# If $MsIp is one node's own IP, do not use this: both MS nodes must be re-registered to the
# cluster name instead (maintenance window).
# & "$env:ProgramFiles\Milestone\Server Configurator\ServerConfigurator.exe" /register /managementserveraddress=http://$MsIp/ /quiet | Out-Null
# (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Milestone\XProtect Event Server').ManagementServerAddress
