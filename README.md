About This Module
====

I wrote this module as I was looking for an easy way to programmatically interact with Palo Alto firewalls. At the time I was not very familiar with development practices and the Python library that seems to be the golden standard “PanDevice” seemed too clunky to easily pick up and run with. Add to this that in many organizations installing another scripting language to your machine can be a headache and I decided to embark on writing this in PowerShell so any sysadmin with Windows 8.1 or newer can programmatically interact with Palo Alto firewalls without the need to install any additional software. This module also supports PowerShell6 (Core).

This module I’m sure is rough around the edges and there is probably a lot of code that can be cleaned up but I have endeavored to keep the code as PowerShell native as I possibly could. I did this to make the code easier to maintain for persons who do not spend most of their time on development. I’ve found PowerShell’s style to be quite accessible to the lay sysadmin with little experience with writing code and thought it fitting to lower the bar to be able to contribute to project such as this one. I hope you will find this module easy to use and if you so choose I would appreciate any contributions you see fit to make. Please note this is a hobby project and though I make every effort to ensure it is error free there may be some bugs lurking. Since Palo Alto firewalls use a commit based architecture for configuration changes I recommend you test making changes using this module but do not commit. You can then log in to the firewall to see if the changes made are desired. If they are then you should be able to use those commands without the need to double check in the future.



How to use this module
====

All you need to do to use this module is download the single PaloShell.psm1 file. (Please ensure you are downloading it from the "master" Branch.) All of the code you need is in there. Once you have downloaded this file open PowerShell and run the command “Import-Module <path to module>”. There are some unapproved verbs in there and PowerShell will tell you that, it is safe to ignore these warnings.

At this time I haven’t fully flushed out the help output but to get the help for the commands you can run “get-help \<commandName\> -detail”. That will print out the help for the command if it exists. I am working to update the help as I can.

The next command to run is “Add-PaloAltoManagementSession”. This command creates the Palo Alto firewall object the module will reference for future commands. You can run get-help on this command but I’ll include an example here as well. The command is run like this:
“Add-PaloAltoManagementSession -hostname \<hostname or IP address of firewall\>”. That’s all you need. You will then be prompted to enter your username and password. (If you don’t have a valid SSL certificate on your firewall then shame on you but I’ve accounted for this. You can add the “-DisableSSLCertificateCheck” switch to the command and it will ignore the SSL certificate validity of the firewall. This is insecure!) If there is no error the output of this command is a PowerShell object. PowerShell should display something like this:

MgmtSessionID

\-\-\-\-\-\-\-\-\-\-\-\-\-

            1


The “MgmtSessionID” is the number you need to pass any other command you use in this module. Every command will have a mandatory -ID switch. You must use the “MgmtSessionID” of the firewall you want to make changes to. You can add as many management sessions as you want and if you forget which ID goes with which firewall you can use the “Get-PaloAltoManagementSession” command to give you the list of firewalls you have added.



List of All Available commands
====

Add-PaAddressGroup

Add-PaAddressObject

Add-PaloAltoManagementSession

Add-PaNATRule

Add-PaSecurityRule

Add-PaServiceGroup

Add-PaServiceObject

Add-PaUserIDMapping

Check-PaLogsForBlockedTraffic

Commit-PaloAltoConfiguration

Download-PaPANOSVersion

Get-PaAddressGroups

Get-PaAddressObjects

Get-PaAvailableSoftwareVersions

Get-PaloAltoManagementSession

Get-PaLogsFromJob

Get-PaNATRules

Get-PaPolicyRoutingRules

Get-PaSecurityRules

Get-PaServiceGroups

Get-PaServices

Get-PaSessionInformation

Get-PaThreatLogs

Get-PaTrafficLogs

Get-PaURLLogs

Get-PaVirtualRouters

Install-PaPANOSVersion

Move-PaNATRule

Move-PaSecurityRule

Reboot-PaloAlto

Remove-PaAddressGroup

Remove-PaAddressObject

Remove-PaloAltoManagementSession

Remove-PaNATRule

Remove-PaSecurityRule

Remove-PaServiceGroup

Remove-PaServiceObject

Request-PaAvailableSoftwareVersions

Request-PaLogs

Revert-PaloAltoConfiguration

Set-PaPreviousContentPackage

Show-PaActiveSessions

Show-PaArpEntries

Show-PaHAStatus

Show-PaInfo

Show-PaInterface

Show-PaIpsecSa

Show-PaJobs

Show-PaRoutingTable

Show-PaRuleHitCount

Show-PaRunningConfig

Show-PaUserIDMapping

Update-PaAddressObject

Update-PaServiceObject



More Information
====
Please see the Wiki for more information.