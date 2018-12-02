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
$testTCPServiceObjectName = 'test123'
$testTCPServiceObjectValue = '78'
$testUDPServiceObjectName = 'test456'
$testUDPServiceObjectValue = '78'
$testServiceGroupName = 'test456'
$testServiceGroupValue = ($testTCPServiceObjectName + ',' + $testUDPServiceObjectName)
$testNatRuleName1 = 'test123'
$testNatRuleName2 = 'test456'
$testSecurityRuleName1 = 'test123'
$testSecurityRuleName2 = 'test456'

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

Show-PaRoutingTable -ID $sessionID #This should either complete successfully or throw an error on it's own.

Show-PaActiveSessions -ID $sessionID  #This should either complete successfully or throw an error on it's own.

Show-PaArpEntries -ID $sessionID  #This should either complete successfully or throw an error on it's own.

Show-PaHAStatus -ID $sessionID  #This should either complete successfully or throw an error on it's own.

Show-PaInfo -ID $sessionID  #This should either complete successfully or throw an error on it's own.

Show-PaInterface -ID $sessionID #This should either complete successfully or throw an error on it's own.

Show-PaIpsecSa -ID $sessionID  #This should either complete successfully or throw an error on it's own.

$jobs = Show-PaJobs -ID $sessionID -All #This should either complete successfully or throw an error on it's own.
#Next check that we can pull back data on just one job.
Show-PaJobs -ID $sessionID -jobID $jobs[0].id

Show-PaJobs -ID $sessionID -Processed #This should either complete successfully or throw an error on it's own.
Show-PaJobs -ID $sessionID -Pending #This should either complete successfully or throw an error on it's own.

Show-PaRuleHitCount -ID $sessionID -AllRuleTypes #This should either complete successfully or throw an error on it's own. Due to the way this functions is written it is throoughly tested with this flag given to it.

Show-PaRunningConfig -ID $sessionID #This should either complete successfully or throw an error on it's own.


Add-PaUserIDMapping -ID $sessionID -Username $userIDTestUsername1 -IpAddress $userIDTestIp1 -Timeout 5
Add-PaUserIDMapping -ID $sessionID -Username $userIDTestUsername2 -IpAddress $userIDTestIp2 -Timeout 5

sleep 5

$users = Show-PaUserIDMapping -ID $sessionID #test this command but get the results to ensure that the Add-PaUserIDMapping function worked as expected.
$userIDTestUser1Found = $false
$userIDTestUser2Found = $false
foreach ($user in $users)
{
	if ($user.User -eq $userIDTestUsername1 -and -$user.IPAddress -eq $userIDTestIp1)
	{
		$userIDTestUser1Found = $true
		continue
	}
	if ($user.User -eq $userIDTestUsername2 -and -$user.IPAddress -eq $userIDTestIp2)
	{
		$userIDTestUser2Found = $true
	}
	if ($userIDTestUser1Found -and $userIDTestUser2Found)
	{
		break
	}
}

if (!($userIDTestUser1Found -and $userIDTestUser2Found))
{
	throw 'At least one UserID mapping for the test users was not seen in the Show-PaUserIDMapping results.'
}

Get-PaAvailableSoftwareVersions -ID $sessionID 

Request-PaAvailableSoftwareVersions -ID $sessionID 

$managementSessions = Get-PaloAltoManagementSession 
#Check that the management session populated correctly. It should have if we got to this point but double check.
$managementSessionCheckPassed = $false
foreach ($managementSession in $managementSessions)
{
	if ($managementSession.SessionID -eq $sessionID -and $managementSession.Hostname -eq $firewallHostname)
	{
		$managementSessionCheckPassed = $true
	}
}
if (!$managementSessionCheckPassed)
{
	throw 'Did not find a management session that matched the specified management session.' #Need to update this message
}

Get-PaSessionInformation -ID $sessionID 

#resume check the script from this point (12-1-18)
$test = Get-PaThreatLogs -ID $sessionID 
#$test.Logs.Logs

$test = Get-PaTrafficLogs -ID $sessionID 
#$test.Logs.Logs

$test = Get-PaURLLogs -ID $sessionID 
#$test.Logs.Logs

Check-PaLogsForBlockedTraffic -ID $sessionID 

Get-PaVirtualRouters -ID $sessionID 

Add-PaAddressObject -ID $sessionID -AddressName $testFQDNAddressObjectName -FQDN $testFQDNAddressObjectValue
Add-PaAddressObject -ID $sessionID -AddressName $testIpRangeAddressObjectName -IpRange $testIpRangeAddressObjectValue
Add-PaAddressObject -ID $sessionID -AddressName $testIpNetmaskAddressObjectName -IpNetmask $testIpNetmaskAddressObjectValue

Add-PaAddressGroup -ID $sessionID -AddressGroupName $testAddressGroupName -Members $testAddressGroupValue

Add-PaServiceObject -ID $sessionID -ServiceName $testTCPServiceObjectName -TCP -port $testTCPServiceObjectValue
Add-PaServiceObject -ID $sessionID -ServiceName $testUDPServiceObjectName -UDP -port $testUDPServiceObjectValue

Add-PaServiceGroup -ID $sessionID -ServiceGroupName $testServiceGroupName -Members $testServiceGroupValue 

Add-PaNATRule -ID $sessionID -RuleName $testNatRuleName1 -Service $testTCPServiceObjectName -SourceAddress 0.0.0.0/0 -DestinationAddress '1.1.1.1' -SourceZone Trust -DestinationZone Trust -Description woot -NATDestinationPort 60 -NATDestinationAddress 2.2.2.2
Add-PaNATRule -ID $sessionID -RuleName $testNatRuleName2 -Service $testUDPServiceObjectName -SourceAddress 0.0.0.0/0 -DestinationAddress '1.1.1.1' -SourceZone Trust -DestinationZone Trust -Description woot -NATDestinationPort 60 -NATDestinationAddress 2.2.2.2

Add-PaSecurityRule -ID $sessionID -RuleName $testSecurityRuleName1 -Service $testTCPServiceObjectName -SourceAddress 0.0.0.0/0 -DestinationAddress '1.1.1.1' -SourceZone Trust -DestinationZone Trust -Description woot -Application web-browsing -NegateDestinationAddress -Action allow -NoIPS 
Add-PaSecurityRule -ID $sessionID -RuleName $testSecurityRuleName2 -Service $testUDPServiceObjectName -SourceAddress 0.0.0.0/0 -DestinationAddress '1.1.1.1' -SourceZone Trust -DestinationZone Trust -Description woot -Application web-browsing -NegateDestinationAddress -Action allow -NoIPS 

Get-PaAddressGroups -ID $sessionID #needs an update for panos 8.1, doesn't pull uncommitted changes apropriately.###################################################

Get-PaAddressObjects -ID $sessionID 

Get-PaNATRules -ID $sessionID 

Get-PaPolicyRoutingRules -ID $sessionID 

Get-PaSecurityRules -ID $sessionID 

Get-PaServiceGroups -ID $sessionID 

Get-PaServices -ID $sessionID 

Move-PaNATRule -ID $sessionID -RuleToMove $testNatRuleName1 -MoveToTop
Move-PaNATRule -ID $sessionID -RuleToMove $testNatRuleName2 -MoveAfterRule $testNatRuleName1

Move-PaSecurityRule -ID $sessionID -RuleToMove $testSecurityRuleName1 -MoveToTop
Move-PaSecurityRule -ID $sessionID -RuleToMove $testSecurityRuleName2 -MoveAfterRule $testSecurityRuleName1

Remove-PaNATRule -ID $sessionID -RuleName $testNatRuleName1
Remove-PaNATRule -ID $sessionID -RuleName $testNatRuleName2

Remove-PaSecurityRule -ID $sessionID -RuleName $testSecurityRuleName1
Remove-PaSecurityRule -ID $sessionID -RuleName $testSecurityRuleName2

Remove-PaAddressGroup -ID $sessionID -AddressGroupName $testAddressGroupName

Remove-PaAddressObject -ID $sessionID -AddressName $testFQDNAddressObjectName 
Remove-PaAddressObject -ID $sessionID -AddressName $testIpRangeAddressObjectName 
Remove-PaAddressObject -ID $sessionID -AddressName $testIpNetmaskAddressObjectName 



Remove-PaServiceGroup -ID $sessionID -ServiceGroupName $testServiceGroupName

Remove-PaServiceObject -ID $sessionID -ServiceName $testTCPServiceObjectName
Remove-PaServiceObject -ID $sessionID -ServiceName $testUDPServiceObjectName

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