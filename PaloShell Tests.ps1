$ErrorActionPreference = 'Stop'
$firewallHostname = '<insert Firewall IP address or hostname here>'
$paloshellModulePath = '<insert path to firewall module here>'
$userIDTestUsername1 = 'test1'
$userIDTestUsername2 = 'test2'
$userIDTestIp1 = '1.1.1.1'
$userIDTestIp2 = '5::6'
$testFQDNAddressObjectName = 'testing5678'
$testIpRangeAddressObjectName = 'testing56789'
$testIpNetmaskAddressObjectName = 'testing567890'
$testFQDNAddressObjectValue = 'woot.com'
$testIpRangeAddressObjectValue = '192.168.1.0-192.168.1.5'
$testIpNetmaskAddressObjectValue = '10.5.6.0/20'
$testAddressGroupName = 'testing123'
$testAddressGroupValue = ($testFQDNAddressObjectName + ',' + $testIpRangeAddressObjectName + ',' + $testIpNetmaskAddressObjectName)

if ($firewallHostname -eq '<insert Firewall IP address or hostname here>')
{
	throw 'You need to edit this script and replace the "<insert Firewall IP address or hostname here>" text at the top with the correct address for your device.'
}
if ($paloshellModulePath -eq '<insert path to firewall module here>')
{
	throw 'You need to edit this script and replace the "<insert path to firewall module here>" text at the top with the correct file path to your PaloShell Module file.'
}
#Prompt the user for credentials.
$cred = Get-Credential -Message 'Please input your log in information for the firewall.'
Import-Module $paloshellModulePath

$result = Add-PaloAltoManagementSession -Hostname $firewallHostname -DisableSSLCertificateCheck -PSCredential $cred
$sessionID = $result.MgmtSessionID

Show-PaRoutingTable -ID $sessionID

Show-PaActiveSessions -ID $sessionID 

Show-PaArpEntries -ID $sessionID 

Show-PaHAStatus -ID $sessionID 

Show-PaInfo -ID $sessionID 

$test = Show-PaInterface -ID $sessionID
$test.InterfaceNetworkStats
$test.InterfacePhysicalStats

Show-PaIpsecSa -ID $sessionID 

Show-PaJobs -ID $sessionID -All

Show-PaRuleHitCount -ID $sessionID -AllRuleTypes


$test = Show-PaRunningConfig -ID $sessionID 
$test.config

Add-PaUserIDMapping -ID $sessionID -Username $userIDTestUsername -IpAddress $userIDTestIp1 -Timeout 5
Add-PaUserIDMapping -ID $sessionID -Username $userIDTestUsername -IpAddress $userIDTestIp2 -Timeout 5

sleep 5

Show-PaUserIDMapping -ID $sessionID

Get-PaAddressGroups -ID $sessionID #needs an update for panos 8.1, doesn't pull uncommitted changes apropriately.###################################################

Get-PaAddressObjects -ID $sessionID 

Get-PaAvailableSoftwareVersions -ID $sessionID 

Request-PaAvailableSoftwareVersions -ID $sessionID 

Get-PaloAltoManagementSession 

Get-PaNATRules -ID $sessionID 

Get-PaPolicyRoutingRules -ID $sessionID 

Get-PaSecurityRules -ID $sessionID 

Get-PaServiceGroups -ID $sessionID 

Get-PaServices -ID $sessionID 

Get-PaSessionInformation -ID $sessionID 

$test = Get-PaThreatLogs -ID $sessionID 
$test.Logs.Logs

$test = Get-PaTrafficLogs -ID $sessionID 
$test.Logs.Logs

$test = Get-PaURLLogs -ID $sessionID 
$test.Logs.Logs

Get-PaVirtualRouters -ID $sessionID 

Add-PaAddressObject -ID $sessionID -AddressName $testFQDNAddressObjectName -FQDN $testFQDNAddressObjectValue
Add-PaAddressObject -ID $sessionID -AddressName $testIpRangeAddressObjectName -IpRange $testIpRangeAddressObjectValue
Add-PaAddressObject -ID $sessionID -AddressName $testIpNetmaskAddressObjectName -IpNetmask $testIpNetmaskAddressObjectValue

Add-PaAddressGroup -ID $sessionID -AddressGroupName $testAddressGroupName -Members $testAddressGroupValue

Remove-PaAddressGroup -ID $sessionID -AddressGroupName $testAddressGroupName

Remove-PaAddressObject -ID $sessionID -AddressName $testFQDNAddressObjectName 
Remove-PaAddressObject -ID $sessionID -AddressName $testIpRangeAddressObjectName 
Remove-PaAddressObject -ID $sessionID -AddressName $testIpNetmaskAddressObjectName 


Add-PaServiceObject -ID $sessionID -ServiceName test123 -TCP -port 78

Add-PaNATRule -ID $sessionID -RuleName test123 -Service test123 -SourceAddress 0.0.0.0/0 -DestinationAddress '1.1.1.1' -SourceZone Trust -DestinationZone Trust -Description woot -NATDestinationPort 60 -NATDestinationAddress 2.2.2.2

Add-PaSecurityRule -ID $sessionID -RuleName test123 -Service test123 -SourceAddress 0.0.0.0/0 -DestinationAddress '1.1.1.1' -SourceZone Trust -DestinationZone Trust -Description woot -Application web-browsing -NegateDestinationAddress -Action allow -NoIPS 

Move-PaNATRule -ID $sessionID -RuleToMove test123 -MoveToTop

Move-PaSecurityRule -ID $sessionID -RuleToMove test123 -MoveToTop


Remove-PaNATRule -ID $sessionID -RuleName test123

Remove-PaSecurityRule -ID $sessionID -RuleName test123


Add-PaServiceGroup -ID $sessionID -ServiceGroupName test456 -Members test123

Remove-PaServiceGroup -ID $sessionID -ServiceGroupName test456

Remove-PaServiceObject -ID $sessionID -ServiceName test123

#Reboot-PaloAlto -ID $sessionID 
#Reboot-PaloAlto -ID 2 

Check-PaLogsForBlockedTraffic -ID $sessionID -returnLogs -ReturnRawLogs

#Commit-PaloAltoConfiguration -ID $sessionID
#Commit-PaloAltoConfiguration -ID 2 

#Download-PaPANOSVersion -ID $sessionID 
#Download-PaPANOSVersion -ID 2 -SoftwareVersion 8.0.8





<#

Get-PaLogsFromJob -ID $sessionID 
Get-PaLogsFromJob -ID 2 

Install-PaPANOSVersion -ID $sessionID 
Install-PaPANOSVersion -ID 2 




Remove-PaloAltoManagementSession -ID $sessionID 
Remove-PaloAltoManagementSession -ID 2 


Request-PaLogs -ID $sessionID 
Request-PaLogs -ID 2 

Revert-PaloAltoConfiguration -ID $sessionID 
Revert-PaloAltoConfiguration -ID 2 

Set-PaPreviousContentPackage -ID $sessionID 
Set-PaPreviousContentPackage -ID 2 

Update-PaAddressObject -ID $sessionID 
Update-PaAddressObject -ID 2 

Update-PaServiceObject -ID $sessionID 
Update-PaServiceObject -ID 2 







foreach ($entry in (Get-Content "F:\Powershell\Github\PaloShell\PaloShell.psm1" | where {$_ -match 'Function' -and $_ -match '[a-zA-Z]-[a-zA-Z]' -and $_ -notmatch ('<|/|"|#|\(|\.|\)' + "|'")} | %{$_.trim('{')} | select -Unique | Sort-Object | %{$_.split(' ')[1]}))
{
    Write-Host ($entry + ' -ID $sessionID ')
    Write-Host ($entry + ' -ID 2 ')
    Write-Host
}
#>