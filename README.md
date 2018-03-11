#About This Module

I wrote this module as I was looking for an easy way to programmatically interact with Palo Alto firewalls. At the time I was not very familiar with development practices and the Python library that seems to be the golden standard “PanDevice” seemed to clunky to easily pick up and run with. Add to this that in many organizations installing another scripting language to your machine can be a headache and I decided to embark on writing this in PowerShell so any sysadmin with Windows 7 or newer can programmatically interact with Palo Alto firewalls without the need to install any additional software.
This module I’m sure is rough around the edges and there is probably a lot of code that can be cleaned up but I endeavored to keep the code as PowerShell native as I possible could. I did this to make the code easier to maintain for persons who do not spend most of their time on development. I’ve found PowerShell’s style to be quite accessible to the lay sysadmin with little experience with writing code and thought it fitting to lower the bar to be able to contribute to project such as this one. I hope you will find this module easy to use and if you so choose I would appreciate any contributions you see fit to make. Please note this is a hobby project and though I make every effort to ensure it is error free there may be some bugs lurking. Since Palo Alto’s use a commit based architecture for configuration changes I recommend you test making changes using this module but do not commit. You can then log in to the firewall to see if the changes made are desired. If they are then you should b e able to use those commands without the need to double check in the future.

#How to use this module

All you need to do to use this module is download the single .psm1 file. All of the code you need is in there. Once you have downloaded this file open PowerShell and run the command “Import-Module <path to module”. There are some unapproved verbs in there and PowerShell will tell you that, it is safe to ignore these warnings.
At this time I haven’t fully flushed out the help output but to get the help for the commands you can run “get-help <commandName> -detail”. That will print out the help for the command if it exists. I am working to update the help as I can.
The next command to run is “Add-PaloAltoManagementSession”. This command created the Palo Alto firewall object the module will reference for future commands. You can run get-help on this command but I’ll include an example here as well. The command is run like this:
“Add-PaloAltoManagementSession -hostname <hostname or IP address of firewall>”. That’s all you need. You will then be prompted to enter your username and password. (If you don’t have a valid SSL certificate on your firewall then shame on you but I’ve accounted for this. You can add the “-DisableSSLCertificateCheck” switch to the command and it will ignore the SSL certificate validity of the firewall. This is insecure!) If there is no error the output of this command is a PowerShell object. PowerShell should display something like this:
Status  MgmtSessionID
------  -------------
Success             3 
The “MgmtSessionID” is the number you need to pass any other command you use in this module. Every command will have a mandatory -ID switch. You must use the “MgmtSessionID” of the firewall you want to make changes to. You can add as many management sessions as you want and if you forget which ID goes with which firewall you can use the “Get-PaloAltoManagementSession” command to give you the list of firewalls you have added.

#List of All Available commands

Function Add-PaloAltoManagementSession
Function Get-PaloAltoManagementSession
Function Remove-PaloAltoManagementSession
Function Show-PaRunningConfig 
Function Show-PaRoutingTable 
Function Show-PaRuleHitCount 
Function Get-PaPolicyRoutingRules 
Function Show-PaIpsecSa 
Function Show-PaInfo 
Function Show-PaInterface 
Function Get-PaSessionInformation 
Function Get-PaSecurityRules 
Function Get-PaNATRules 
Function Show-PaActiveSessions 
Function Get-PaServices 
Function Get-PaServiceGroups 
Function Get-PaAddressObjects 
Function Get-PaAddressGroups 
Function Show-PaJobs
Function Request-PaAvailableSoftwareVersions
Function Get-PaAvailableSoftwareVersions
Function Show-PaArpEntries 
Function Check-PaLogsForBlockedTraffic 
Function Request-PaLogs 
Function Get-PaLogsFromJob 
Function Get-PaTrafficLogs 
Function Get-PaThreatLogs 
Function Get-PaURLLogs 
Function Show-PaUserIDMapping 
Function Get-PaVirtualRouters 
Function Show-PaHAStatus
Function Set-PaPreviousContentPackage 
Function Add-PaSecurityRule 
Function Remove-PaSecurityRule 
function Reboot-PaloAlto
function Commit-PaloAltoConfiguration
Function Move-PaSecurityRule
Function Add-PaNATRule 
Function Remove-PaNATRule 
Function Move-PaNATRule
Function Revert-PaloAltoConfiguration
Function Add-PaAddressObject
Function Update-PaAddressObject
Function Remove-PaAddressObject
Function Add-PaServiceObject
Function Update-PaServiceObject
Function Remove-PaServiceObject
Function Add-PaAddressGroup
Function Remove-PaAddressGroup
Function Add-PaServiceGroup
Function Remove-PaServiceGroup
Function Download-PaPANOSVersion
Function Install-PaPANOSVersion
Function Add-PaUserIDMapping 

