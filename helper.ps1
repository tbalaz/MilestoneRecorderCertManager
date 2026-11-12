# helper.ps1 - commands for 'token validation failed' in the Event Server log.
#
# Copy-paste only the block for the computer you are on, in Windows PowerShell started
# "as Administrator". Fill in the value below first. Every block only reads; nothing changes.

$MsName = '<ms-dnsname>'     # the management server address the Event Server is registered to


# --- 1. On a Management Server node: which node runs the role, and the IDP address per node -
# ServerConfig.xml is per node, so the nodes can differ.
Get-ClusterGroup | Select-Object Name,OwnerNode,State
Get-ClusterNode | ForEach-Object { Invoke-Command -ComputerName $_.Name { "$env:COMPUTERNAME " + ([xml](Get-Content 'C:\ProgramData\Milestone\XProtect Management Server\ServerConfig.xml')).SelectSingleNode('//AuthorizationServerUri').InnerText } }


# --- 2. On a Management Server node: the cluster IP addresses and what the MS name resolves to
Get-ClusterResource | Where-Object ResourceType -eq 'IP Address' | Get-ClusterParameter -Name Address | Select-Object ClusterObject,Value
Resolve-DnsName $MsName -Type A | Select-Object Name,IPAddress


# --- 3. On the Event Server: its MS address (every ES node), the IDP issuer, the clock --------
Get-ClusterNode | ForEach-Object { Invoke-Command -ComputerName $_.Name { "$env:COMPUTERNAME " + (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Milestone\XProtect Event Server').ManagementServerAddress } }
(Invoke-RestMethod "http://$MsName/IDP/.well-known/openid-configuration").issuer
net time \\$MsName
Get-Date
# The two times must be within a few minutes of each other.


# --- 4. On the Event Server: the first 'token' errors in the newest Event Server log ---------
$log = Get-ChildItem 'C:\ProgramData\Milestone\XProtect Event Server' -Recurse -Filter *.log -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
$log.FullName
Select-String -LiteralPath $log.FullName -Pattern 'token' -Context 2,10 | Select-Object -First 3
