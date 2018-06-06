#Maintained by David Isaacs.
#This is open source but please do not distribute without attribution.
#This code is written to Support Powershell standard v3 and higher as well as Powershell Core/6. This is deliberate as I want this script to be run with default software installed on Windows if possible while also supporting Linux and MacOS.



#####################################################################################################################################################
#The following code is run on module import.
#Variables create here are scoped globally for the module only. These variables are only accessable by functions in this module. (Unless there's a bug I suppose)
#####################################################################################################################################################
#Halt on all errors.
$ErrorActionPreference = 'Stop'

#Check to see if the script is executing in powershell 6.
if ($PSVersionTable.PSVersion.Major -eq 6)
{
	$RunningPowershell6 = $true
}
else
{
	$RunningPowershell6 = $false
}
#The following Try Catch resolves an issue where $PaloAltoModuleWebClient.downloadstring will fail if a registry key is not set. Only do this for Windows PowerShell.
if(!$RunningPowershell6)
{
	try
	{
		#Check for the registry key.
		Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -Name 'IE10RunOncePerInstallCompleted' | Out-Null
	}
	Catch
	{
		#Try this next command in a try in case IE isn't installed on the target system.
		try
		{
			#Create the Registry entry if needed.
			Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -Name 'IE10RunOncePerInstallCompleted' -Value '1' | Out-Null
		}
		Catch
		{
			#Do nothing if we got here. Silently swallow the error.
		}
	}
}

#Create an array to contain the Palo Alto Management sessions. This was a datatable but has been changed to an array for PowerShell 6 support.
New-Variable -Name  managementSessions -Value (New-Object System.Collections.ArrayList) -Scope Script

#For ease of migration from datatables to an ArrayList I've created an object that is named $PaloAltoManagementSessionTable but is really just a psobject with a method to somewhat mimick the old way of doing things.
New-Variable -Name PaloAltoManagementSessionTable -Value (New-Object -TypeName PSObject) -Scope Script
#The following function is used to find required information to work with the firewall.
Add-Member -InputObject $PaloAltoManagementSessionTable -MemberType ScriptMethod -Name findSessionByID -Value {
	param
	(
		[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
	)
    $managementSessions | where {$_.'SessionID' -eq $ID} #I hate to have to pipe this but it was the simplest solution for now and performance will likely not be hampered by searching through this list.
}
#The following method is used to give a count of the current entries in the PaloAltoManagementSessionTable .
Add-Member -InputObject $PaloAltoManagementSessionTable -MemberType ScriptMethod -Name count -Value {
    $managmentSessions.Count
}

#The following powershell object works for abstracting web calls so they will work with Linux or Windows.
New-Variable -Name PaloAltoModuleWebClient -Value (New-Object -TypeName PSObject) -Scope Script
Add-Member -InputObject $PaloAltoModuleWebClient -MemberType ScriptMethod -Name downloadstring -Value {
	param
	(
		[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$url
	)
	if (!$RunningPowershell6) #This check is needed because Powershell standard doesn't support using "Invoke-WebRequest" with the  "-SkipCertificateCheck" flag.
	{
		#Check if invalid SSL certificates should be ignored.
		if (($PaloAltoManagementSessionTable.findSessionByID($ID).'DisableSSLCertCheck') -or $DisableSSLCertificateCheck)
		{
			#The following line makes it such that invalid ssl certificates are ignored. (There is probably a better way to do this.)
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} #This line needs to be here so the API call will work properly if there is not a valid SSL certificate.
		}
		#Define web client object. Do this every time to ensure it picks up ignore SSL cert setting.
		New-Variable -Name webclient -Value (New-Object System.Net.WebClient)
		#Run the requested command 
		Try
		{
			#Write-Host $url
			$response = [xml]($webclient.downloadstring($url))
		}
		Catch
		{
			$CaughtError = $_
		}
		Finally
		{
			Remove-Variable -Name webclient

			# If we disabled SSL certificate checking turn it back on. This should be the most secure as I'm not sure if turning off certificate checking the way I do does it for all programs.
			if (($PaloAltoManagementSessionTable.findSessionByID($ID).'DisableSSLCertCheck') -or $DisableSSLCertificateCheck)
			{
				[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$false}
			}
			
		}
		if ($CaughtError)
		{
			throw $CaughtError
		}
		else
		{
			return $response
		}
	}
	else
	{
		#If we got here we are using Powershell6.
		#Check if invalid SSL certificates should be ignored.
		if (($PaloAltoManagementSessionTable.findSessionByID($ID).'DisableSSLCertCheck')  -or $DisableSSLCertificateCheck)
		{
			$response = [xml]((Invoke-WebRequest -SkipCertificateCheck ([string]$url)).Content)
		}else
		{
			$response = [xml]((Invoke-WebRequest ([string]$url)).Content)
		}
		return $response
	}
	
}
Add-Member -InputObject $PaloAltoModuleWebClient -MemberType ScriptMethod -Name uploadstring -Value {
	param
	(
		[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$url,
        [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$uploadString
	)
	if (!$RunningPowershell6) #This check is needed because Powershell standard doesn't support using "Invoke-WebRequest" with the  "-SkipCertificateCheck" flag.
	{
		#Check if invalid SSL certificates should be ignored.
		if (($PaloAltoManagementSessionTable.findSessionByID($ID).'DisableSSLCertCheck') -or $DisableSSLCertificateCheck)
		{
			#The following line makes it such that invalid ssl certificates are ignored. (There is probably a better way to do this.)
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} #This line needs to be here so the API call will work properly if there is not a valid SSL certificate.
		}
		#Define web client object. Do this every time to ensure it picks up ignore SSL cert setting.
		New-Variable -Name webclient -Value (New-Object System.Net.WebClient)
		#Run the requested command 
		Try
		{
			$response = [xml]($webclient.uploadstring($url, $uploadString))
		}
		Catch
		{
			$CaughtError = $_
		}
		Finally
		{
			Remove-Variable -Name webclient

			# If we disabled SSL certificate checking turn it back on. This should be the most secure as I'm not sure if turning off certificate checking the way I do does it for all programs.
			if (($PaloAltoManagementSessionTable.findSessionByID($ID).'DisableSSLCertCheck') -or $DisableSSLCertificateCheck)
			{
				[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$false}
			}
			
		}
		if ($CaughtError)
		{
			throw $CaughtError
		}
		else
		{
			return $response
		}
	}
	else
	{
		#If we got here we are using Linux.
		#Check if invalid SSL certificates should be ignored.
		if (($PaloAltoManagementSessionTable.findSessionByID($ID).'DisableSSLCertCheck')  -or $DisableSSLCertificateCheck)
		{
			$response = [xml]((Invoke-WebRequest -SkipCertificateCheck ([string]$url) -Method Post -Body $uploadString).Content)
		}else
		{
			$response = [xml]((Invoke-WebRequest ([string]$url) -Method Post -Body $uploadString).Content)
		}
		return $response
	}
}

#####################################################################################################################################################
#Below this line are all of the module functions. Any code loaded on module import should be above this line.
#####################################################################################################################################################

 <#
.SYNOPSIS
This function is used to create the "Palo Alto Management Session" that you will reference when accessing a firewall. This is designed to make it easy to manage multiple firewalls in the same powershell instance. 
The output of this function is a session ID number that you will reference when running any other functions against the firewall you specified.
.Parameter Hostname
Required.
The Hostname/IP address of the firewall you wish to work with.
.Parameter  DeviceName
Optional.
I'm unsure how to change this in a firewall and if you are not familiar with the firewall's device name then do not specify this parameter.
.Parameter VirtualSystemNumber
Optional.
This Parameter is used to specify a Virtual System to work with when you specify this session. If you are unsure of what this is then do not specify this parameter. The Default setting is: 'vsys1'.
.Parameter Username
Optional.
Use this parameter if you want to pass a username as an argument to this function. If this parameter is specified you must also specify a password in plain text as an argument for this command. Note that this is considered insecure but the function will not store your password in cleartext.
If you do not specify and username and password or a PSCredential object you will be interactively prompted to input your credentials.
.Parameter Password
Optional.
Use this parameter if you want to specify a password (In plain text) as an argument to this function. If this parameter is specified you must also specify a username. Note that this is considered insecure but the function will not store your password in cleartext.
If you do not specify and username and password or a PSCredential object you will be interactively prompted to input your credentials.
.Parameter PSCredential
Optional.
Use this parameter if you want to specify a PSCredential object(different from a dotnet Credential object) for authentication. This would be more secure as you can have your own code get the credential object and pass it to this function.
If you do not specify and username and password or a PSCredential object you will be interactively prompted to input your credentials.
.Parameter PANOSVersion
Optional.
This parameter was added for the event where a user has access to any API functionality aside from operational commands. This is a required where the user does not have access to operational commands as there is not other way to tell what PANOS version the firewall is running.
.Parameter DisableSSLCertificateCheck
Optional.
If this switch is specified no validation of the Firewall SSL certificate will be performed. Only use this if you know what you are doing.

#>
Function Add-PaloAltoManagementSession
{
	param 
	(
        [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$Hostname,
		[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DeviceName,
		[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$VirtualSystemNumber,
		[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Username,
		[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Password,
		[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$PANOSVersion,
		[Parameter(Mandatory=$false,valueFromPipeline=$true)]$PSCredential,
		[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$DisableSSLCertificateCheck
	)
	try
	{
		#Add the Data to the table.
		#Create an object to hold the session.
		$session = New-Object psobject

		#Get the current session count.
		$sessionCount = $managementSessions.Count
		#The following if checks for the instance where there are not configured managment sessions.
		if (!$sessionCount)
		{
			$sessionCount = 0
		}
		Write-Debug ('Rows in Session Management Array: ' + $sessionCount)
		if ($sessionCount -eq 0)
		{
			#If there are no sessions set the $highestSessionID to zero and $nextSessionID to 1. This is a requirment for how this functions continues.
			$highestSessionID = 0
			Write-Debug ('Highest Session ID:' + $highestSessionID)
			$nextSessionID = 1
			Write-Debug ('Next session ID:' + $nextSessionID)
		}
		else
		{
			#If there are existing sessions get the highest sessionID. It will always be the last session in the list.
			$highestSessionID = ($managementSessions[([int]$sessionCount - [int]1)]).SessionID
			Write-Debug ('Highest Session ID:' + $highestSessionID)
			$nextSessionID = [int]$highestSessionID + 1
			Write-Debug ('Next session ID:' + $nextSessionID)
		}
		Add-Member -InputObject $session -MemberType NoteProperty -Name 'SessionID' -Value $nextSessionID
		Add-Member -InputObject $session -MemberType NoteProperty -Name 'Hostname' -Value $Hostname
		if (!$DisableSSLCertificateCheck)
		{
			Add-Member -InputObject $session -MemberType NoteProperty -Name 'DisableSSLCertCheck' -Value $false
		}else
		{
			Add-Member -InputObject $session -MemberType NoteProperty -Name 'DisableSSLCertCheck'  -Value $true
		}
		if (!$DeviceName)
		{
			Add-Member -InputObject $session -MemberType NoteProperty -Name 'DeviceName' -Value 'localhost.localdomain' #Set the value to default if not specified.
		}else
		{
			Add-Member -InputObject $session -MemberType NoteProperty -Name 'DeviceName' -Value $DeviceName
		}
		if (!$VirtualSystemNumber)
		{
			Add-Member -InputObject $session -MemberType NoteProperty -Name 'VirtualSystem' -Value 'vsys1' #Set the value to default if not specified.
		}else
		{
			Add-Member -InputObject $session -MemberType NoteProperty -Name 'VirtualSystem' -Value ('vsys' + [string]$VirtualSystemNumber)
		}
		#Add what information we do have the $managementSessions array. We actually don't have to remove it from the array later, powershell links the variable to its entry in the array so future updates to the object apply anyway.
		[void]$managementSessions.Add($session)
		#Check to see if an old ID variable exists. If so remove it. This resolves an issue that is not properly caught when this function unexpectedly terminates and the ID variable is left in memory. This seems like a hack but it should resolve the issue with little work.
		if ($ID)
		{
			Remove-Variable -Name ID -Scope Script
		}
		#Temporarily set a global ID variable to get through setup of the new session. Scope it as script to ensure any other functions in this module that are called can access it.
		New-Variable -name ID -Value $nextSessionID -Scope Script


		#Determine if we are sending credentials to getpaapikey or if it will have to interactively ask for them.
		if ($Username -and $Password)
		{
			#Set the API Key. The API Key must be a variable as for some reason it cannot be saved in the data table. (Since we are no longer using Datatables maybe there is a better way to handle this.) Turns out you can store a PScredential object as a member of another object and get the data from it. Doing that now.
			#Get the API key and username from the function.
			#Pass the username and password to the function.
			$result = getpaapikey -UsernameFromArgument $Username -PasswordFromArgument $Password
		}
		elseif ($PSCredential)
		{
			#Check that the correct object was passed.
			$variableType = $PSCredential.GetType()
			if ($variableType.Name -eq 'PSCredential')
			{
				#Set the API Key. The API Key must be a variable as for some reason it cannot be save in the data table. (Since we are no longer using Datatables maybe there is a better way to handle this.) Turns out you can store a PScredential object as a member of another object and get the data from it. Doing that now.
				#Get the API key and username from the function.
				#Pass a "System.Management.Automation.PSCredential" object to the function.
				$result = getpaapikey -PSCredential $PSCredential
			}
			else
			{
				throw 'The PSCredential supplied was not a "PSCredential" object.'
			}
		}
		elseif ($Username -or $Password)
		{
			#Error because you cannot just have a username and no password.
			throw 'You must specify both a Username and Password.'
		}
		else
		{
			#Set the API Key. The API Key must be a variable as for some reason it cannot be save in the data table. (Since we are no longer using Datatables maybe there is a better way to handle this.) Turns out you can store a PScredential object as a member of another object and get the data from it. Doing that now.
			#Get the API key and username from the function.
			try
			{
				$result = getpaapikey
			}
			Catch
			{
				$CaughtException = $_
				if ((findPaWebCallErrorCode($CaughtException.Exception)) -eq 403) #Check if the error was a 403. Throw an apropriate error.
				{
					throw "The username or password entered is incorrect."
				}
				else
				{
					throw $CaughtException
				}
			}
		}
		#Store username and password together in a PScredential, because why not? Turns out formatting reasons is why not. For a better UX I'm leaving username as its own field so a user can figure out who is loggedin on a firewall session.
		Add-Member -InputObject $session -MemberType NoteProperty -Name Credential -Value (New-Object System.Management.Automation.PSCredential ($result[1], $result[0])) 
		
		Add-Member -InputObject $session -MemberType NoteProperty -Name Username -Value $result[1]

		#Get the current version of the firewall software. Handle the error if the web call fails for some reason. For now this won't be a reason to terminate execution.
		#Put this in a try, a user may not have access to operational commands but could do other things. If the user does not have access to operational commands a 403 will be thrown.
		if ($PANOSVersion)
		{
			$version = $PANOSVersion.split('.')
			if ($verson.count -eq 1)
			{
				throw 'Please spcify the PANOSVersion in the format "<Major Version>.<Minor Version>"'
			}
			$panOSMajorVersion = $Version.Split('.')[0]
			$panOSMinorVersion = $Version.Split('.')[1]
			try
			{
				[void][int]$panOSMajorVersion
				[void][int]$panOSMinorVersion
			}
			Catch
			{
				throw 'Please spcify the PANOSVersion in the format "<Major Version>.<Minor Version>" with the quotation marks.'
			}
		}
		else
		{
			try
			{
				$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><system><info></info></system></show>&key=" + (GetPaAPIKeyClearText)))
			}
			Catch
			{
				$CaughtException = $_
				if ((findPaWebCallErrorCode($CaughtException.Exception)) -eq 403) #Check if the error was a 403. Throw an apropriate error.
				{
					throw "This user does not have permissions to populate the version information for this firewall. Firewall version cannot be determined. Please ask your administrator for your firewall's PANOS version and specify it with the -PANOSVersion parameter."
				}
				else
				{
					throw $CaughtException
				}
			}
			ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
			$version = $response.response.result.system.'sw-version'
			$panOSMajorVersion = $version.Split('.')[0]
			$panOSMinorVersion = $version.Split('.')[1]
			Remove-Variable -Name response
			Remove-Variable -Name version 
		}
		Add-Member -InputObject $session -MemberType NoteProperty -Name 'PANOSMajorVersion' -Value $panOSMajorVersion
		Add-Member -InputObject $session -MemberType NoteProperty -Name 'PANOSMinorVersion' -Value $panOSMinorVersion

		Write-Debug 'Successfully added the management session to the management session table.'
		$returnObject = New-Object PSObject
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name Status -Value 'Success'
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name MgmtSessionID -Value $session.SessionID
		Write-Debug ('The session ID is ' + $session.SessionID)
		#Remove all Variables before returning.
		Remove-Variable -Name ID -Scope Script
		Remove-Variable -Name Hostname
		Remove-Variable -Name DeviceName
		Remove-Variable -Name VirtualSystemNumber
		Remove-Variable -Name session
		Remove-Variable -Name result
		return $returnObject
	}
	Catch
	{
		$CaughtException = $_
		$errorObject = New-Object PSObject
		$ErrorMessage = $CaughtException.Exception.Message
		$FailedItem = $CaughtException.Exception.ItemName
		Add-Member -InputObject $errorObject -MemberType NoteProperty -Name 'Message' -Value 'The session was not added.'
		Add-Member -InputObject $errorObject -MemberType NoteProperty -Name 'Error' -Value $CaughtException
		#Write-Host 'The script encountered an error. The error was:'
		#$ErrorMessage
		#$FailedItem
		#Remove any data if it was added.
		if ($ID)
		{
			#Due to the one off nature of this I'm using the following code to remove any outstanding object from the $managementSessions array on a failure.
			$index = 0
			foreach ($item in $managementSessions)
			{
				if ($item.'SessionID' -eq $ID)
				{
					$managementSessions.RemoveAt($index)
					#Break so we don't needlessly run through the entire array.
					break
				}
				$index ++
			}
			Remove-Variable -Name index
			Remove-Variable -Name ID -Scope Script
		}
		throw $CaughtException
	}
}

<#
.SYNOPSIS
Lists all configured Palo Alto Management Sessions. This command is useful for looking up the session ID associated with a particular firewall.
#>
Function Get-PaloAltoManagementSession
{
	if($managementSessions -eq '0') #I'm not sure this if does anything....
	{
		throw ('There are no defined sessions. Create them using "Add-PaloAltoSession"')
	}
	elseif(!$managementSessions)
	{
		#If the array list is empty then we ended up here. Throw an error that there are not defined management sessions.
		throw ('There are no defined sessions. Create them using "Add-PaloAltoSession"')
	}
	#Nicely output the ManagementSessions.
	$managementSessions | select SessionID,Hostname,DisableSSLCertCheck,DeviceName,VirtualSystem,Username,PANOSMajorVersion,PANOSMinorVersion | ft
}

<#
.SYNOPSIS
Removes the specified management session.
.Parameter ID
The management session ID to remove.
#>
Function Remove-PaloAltoManagementSession
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
	)

	if(!$managementSessions)
	{
		throw ('There are no defined sessions.')
	}
	elseif($managementSessions.Count -eq 0)
	{
		throw ('There are no defined sessions.')
	}
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist. Nothing was deleted.')
	}
	$sessionToRemove = $PaloAltoManagementSessionTable.findSessionByID($ID)
	[void]$managementSessions.remove($sessionToRemove)
	Remove-Variable -Name sessionToRemove
	Write-Host 'The session was successfully removed.'
}

 <#
.SYNOPSIS
#Get the variable that stores the API key as the password part of a PSCredential Object. Return the password of that object in clear text.
.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
Function GetPaAPIKeyClearText
{
	return ($PaloAltoManagementSessionTable.findSessionByID($ID).Credential.GetNetworkCredential().Password)
}


 <#
.SYNOPSIS

.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
Function getPaApiKey {
	param(
		[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$UsernameFromArgument,
		[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$PasswordFromArgument,
		[Parameter(Mandatory=$false,valueFromPipeline=$true)]$PSCredential
	)
	if ($UsernameFromArgument)
	{
		$Username = $UsernameFromArgument
		$password = $PasswordFromArgument
	}
	elseif ($PSCredential)
	{
		$Username = $PSCredential.UserName
		$password = $PSCredential.GetNetworkCredential().Password
	}
	else
	{
		#Interactively get the credentials for the session.
		#Get the user's username and password to get the new API Key.
		$Username = Read-Host 'Enter your username'
		#I use secure password so the user's password isn't visible on the command line.
		$secPassword = Read-Host 'Enter your password' -AsSecureString
		#A PSCredential is a cross platform object that can accept a secure string and will allow my to programatically acces it as plain text if needed. In order to make the script work and prompt the user with a secure string prompt I need to use this type to store and retrieve the information.
		$tempCredential = New-Object System.Management.Automation.PSCredential ($Username, $secPassword)
		#Since you can't pass a secure sting to a web service the following line turns a secure string stored in the password location of a PSCredential object in to a normal string.
		$password = $tempCredential.GetNetworkCredential().Password
	}
	#Get only the XML from the web request
   try
	{
		$xml = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=keygen&user=" + $username + "&password=" + $password))
	}
	Catch
	{
		#If we get a 403 here it means the username and password combination is incorrect.
		throw $_
		#throw ('The web request failed with the following error: ' + $_.Exception.Message)
    }
	#Check that the request completed successfully.
	ReturnPaAPIErrorIfError($xml) #This function checks for an error from the firewall and throws it if there is one.
	#Get the API key as a secure string. This is then stored in memory as a secure string and not on the filesystem.
	$apiKey = ConvertTo-SecureString -Force -AsPlainText ($xml.response.result.key)

	#Return the api key to the main function.
	return $apiKey,$Username
	#Clean up variables
	Remove-Variable -Name apiKey
	Remove-Variable -Name xml
	Remove-Variable -Name username
	Remove-Variable -Name secPassword
	Remove-Variable -Name password
	Remove-Variable -Name tempCredential
}

 <#
.SYNOPSIS

.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

.PARAMETER 
	
.PARAMETER 
	 
#>
Function Show-PaRunningConfig {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$result = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><config><running></running></config></show>&key=" + (GetPaAPIKeyClearText))

	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.	
	return $result.response.result
}
 <#
.SYNOPSIS

.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

.PARAMETER 
	
.PARAMETER 
	


#>
Function Show-PaRoutingTable {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Get the Routing Table
    $route = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><routing><route></route></routing></show>&key=" + (GetPaAPIKeyClearText)))

    ReturnPaAPIErrorIfError($route) #This function checks for an error from the firewall and throws it if there is one.
	#Print the route flags so the User knows what types are what.
	$route.response.result.flags
	$route.response.result.entry | ft
}

 <#
.SYNOPSIS
Returns a list of the specified rule types and their hitcounts.
.Description
Other:
Timestamp values returned for the rule hitcounts are in UTC time. If a timestamp has the value "1/1/1970 12:00:00 AM" this means that this timestamp has never been updated. This is not a bug, it has been designed this way so dates are always returned as datetime objects.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter ApplicationOverride
Optional.
Specify this switch to return hitcounts for ApplicationOverride rules.
.Parameter Authentication
Optional.
Specify this switch to return hitcounts for Authentication rules.
.Parameter Decryption
Optional.
Specify this switch to return hitcounts for Decryption rules.
.Parameter Dos
Optional.
Specify this switch to return hitcounts for Dos rules.
.Parameter Nat
Optional.
Specify this switch to return hitcounts for Nat rules.
.Parameter Pbf
Optional.
Specify this switch to return hitcounts for Pbf rules.
.Parameter Qos
Optional.
Specify this switch to return hitcounts for Qos rules.
.Parameter Security
Optional.
Specify this switch to return hitcounts for Security rules.
.Parameter TunnelInspect
Optional.
Specify this switch to return hitcounts for TunnelInspect rules.
.Parameter AllRuleTypes
Optional.
Specify this switch to return hitcounts for all rules of all types.
#>
Function Show-PaRuleHitCount {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$ApplicationOverride,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$Authentication,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$Decryption,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$Dos,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$Nat,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$Pbf,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$Qos,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$Security,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$TunnelInspect,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$AllRuleTypes
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Check that the firewall we are running this command on is on at least PANOS version 8.1
	if (!(($PaloAltoManagementSessionTable.findSessionByID($ID).PANOSMajorVersion -eq 8 -and $PaloAltoManagementSessionTable.findSessionByID($ID).PANOSMinorVersion -ge 1) -or $PaloAltoManagementSessionTable.findSessionByID($ID).PANOSMajorVersion -gt 8))
	{
		throw "The firewall must be running at least PANOS 8.1 to use this command."
	}
	if (!$ApplicationOverride -and !$Authentication -and !$Decryption -and !$Dos -and !$Nat -and !$Pbf -and !$Qos -and !$Security -and !$TunnelInspect-and !$AllRuleTypes)
	{
		#If we got here the user didn't specify any rules to return hitcounts for.
		throw "You must specify at least one rule type or use the -AllRuleTypes switch to get rule hitcount information."
	}
	#Since timestamp values are returned in unix time format from UTC time the following is run so math can be performed to return the timestamp to the user as a powershell datetime object.
	$unixEpoch = (get-date "1/1/1970")
	#Define the object to be returned at the end of this function. Append the rules to it as we proceed.
	$result = New-Object psobject
	#Define a function to make the web call and return the results.
	function getPaRuleHitCounts	{
		param (
		[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ruleType
		)
		$ruleHitCounts = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><rule-hit-count><vsys><vsys-name><entry name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "'><rule-base><entry name='" + $ruleType + "'><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>&key=" + (GetPaAPIKeyClearText)))
		ReturnPaAPIErrorIfError($ruleHitCounts) #This function checks for an error from the firewall and throws it if there is one.
		$hitCountsList = New-Object System.Collections.ArrayList
		foreach ($entry in $ruleHitCounts.response.result.'rule-hit-count'.vsys.entry.'rule-base'.entry.rules.entry)
		{
			$rule = New-Object psobject
			Add-Member -InputObject $rule -MemberType NoteProperty -Name 'RuleName' -Value $entry.name
			Add-Member -InputObject $rule -MemberType NoteProperty -Name 'Latest' -Value $entry.latest
			Add-Member -InputObject $rule -MemberType NoteProperty -Name 'HitCount' -Value $entry.'hit-count'
			Add-Member -InputObject $rule -MemberType NoteProperty -Name 'LastHitTimestamp' -Value $unixEpoch.AddSeconds($entry.'last-hit-timestamp')
			Add-Member -InputObject $rule -MemberType NoteProperty -Name 'LastCounterResetTimestamp' -Value $unixEpoch.AddSeconds($entry.'last-reset-timestamp')
			Add-Member -InputObject $rule -MemberType NoteProperty -Name 'FirstHitTimestamp' -Value $unixEpoch.AddSeconds($entry.'first-hit-timestamp')
			[void]$hitCountsList.add($rule)
		}
		return $hitCountsList
	}
	#Get the requested rule hitcounts.
	if ($ApplicationOverride -or $AllRuleTypes)
	{
		Add-Member -InputObject $result -MemberType NoteProperty -Name 'ApplicationOverrideRuleHitCounts' -Value (getPaRuleHitCounts -ruleType 'application-override')
	}
	if ($Authentication -or $AllRuleTypes)
	{
		Add-Member -InputObject $result -MemberType NoteProperty -Name 'AuthenticationRuleHitCounts' -Value (getPaRuleHitCounts -ruleType 'authentication')
	}
	if ($Decryption -or $AllRuleTypes)
	{
		Add-Member -InputObject $result -MemberType NoteProperty -Name 'DecryptionRuleHitCounts' -Value (getPaRuleHitCounts -ruleType 'decryption')
	}
	if ($Dos -or $AllRuleTypes)
	{
		Add-Member -InputObject $result -MemberType NoteProperty -Name 'DosRuleHitCounts' -Value (getPaRuleHitCounts -ruleType 'dos')
	}
	if ($Nat -or $AllRuleTypes)
	{
		Add-Member -InputObject $result -MemberType NoteProperty -Name 'NatRuleHitCounts' -Value (getPaRuleHitCounts -ruleType 'nat')
	}
	if ($Pbf -or $AllRuleTypes)
	{
		Add-Member -InputObject $result -MemberType NoteProperty -Name 'PbfRuleHitCounts' -Value (getPaRuleHitCounts -ruleType 'pbf')
	}
	if ($Qos -or $AllRuleTypes)
	{
		Add-Member -InputObject $result -MemberType NoteProperty -Name 'QosRuleHitCounts' -Value (getPaRuleHitCounts -ruleType 'qos')
	}
	if ($Security -or $AllRuleTypes)
	{
		Add-Member -InputObject $result -MemberType NoteProperty -Name 'SecurityRuleHitCounts' -Value (getPaRuleHitCounts -ruleType 'security')
	}
	if ($TunnelInspect -or $AllRuleTypes)
	{
		Add-Member -InputObject $result -MemberType NoteProperty -Name 'TunnelInspectRuleHitCounts' -Value (getPaRuleHitCounts -ruleType 'tunnel-inspect')
	}
	return $result
}


 <#
.SYNOPSIS
Returns a list of the Configured PBF rules from the candidate configuration.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command. 

.PARAMETER 
	
.PARAMETER 
	


#>
Function Get-PaPolicyRoutingRules {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Get the PBF rules
    $response = $PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/pbf&key=" + (GetPaAPIKeyClearText))

    ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	$rules = $response.response.result.pbf.rules.entry
	$result = New-Object System.Collections.ArrayList
	foreach ($rule in $rules)
	{
		$parsedRule = New-Object PSObject
		#Check if a rule has been edited but not committed, if it has then it needs to be processed slightly differently.
		if ($rule.dirtyId)
		{
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'RuleName' -Value ($rule.name) #rulename
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Description' -Value ($rule.description.'#text') #description
			if ($rule.action.forward)
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Action' -Value ('forward') #Action the PBF rule specifies
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Egress-Interface' -Value ($rule.action.forward.'egress-interface') 
				if ($rule.action.forward.monitor)
				{
					Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'IsMonitored' -Value $true
					Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'MonitorProfile' -Value ($rule.action.forward.monitor.profile.'#text') #If the rule is monitored a monitor profile must be specified.
					if ($rule.action.forward.monitor.'ip-address')
					{
						Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'MonitoredAddress' -Value ($rule.action.forward.monitor.'ip-address'.'#text')
					}
					if ($rules.action.forward.monitor.'disable-if-unreachable'.'#text' -eq 'yes')
					{
						Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'DisableIfMonitoredAddressUnreachable' -Value $true
					}
					else
					{
						Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'DisableIfMonitoredAddressUnreachable' -Value $false
					}
				}
				else
				{
					Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'IsMonitored' -Value $false
				}
				if ($rule.action.forward.nexthop.'ip-address')
				{
					Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'NextHopAddress' -Value ($rule.action.forward.nexthop.'ip-address'.'#text')
				}
			}
			if ($rule.action.discard)
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Action' -Value ('discard') #Action the PBF rule specifies
			}
			if ($rule.action.'no-pbf')
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Action' -Value ('no-pbf') #Action the PBF rule specifies
			}
			if ($rule.'enforce-symmetric-return'.enabled.'#text' -eq 'yes')
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'EnforceSymmetricReturn' -Value $true
			}
			else
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'EnforceSymmetricReturn' -Value $false
			}
			if ($rule.from.zone)
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'FromZones' -Value ($rule.from.zone.member.'#text' -join ';' -join ';')
			}
			else
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'FromInterfaces' -Value ($rule.from.interface.member.'#text' -join ';')
			}
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'SourceAddresses' -Value ($rule.source.member.'#text' -join ';')
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'SourceUsers' -Value ($rule.'source-user'.member.'#text' -join ';')
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'DestinationAddress' -Value ($rule.destination.member.'#text' -join ';')
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Applications' -Value ($rule.application.member.'#text' -join ';')
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Service' -Value ($rule.service.member.'#text' -join ';')
			if ($rule.disabled.'#text' -eq 'yes')
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Disabled' -Value $true
			}
			else
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Disabled' -Value $false
			}
			[void]$result.add($parsedRule)
		}
		else
		{
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'RuleName' -Value ($rule.name) #rulename
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Description' -Value ($rule.description) #description
			if ($rule.action.forward)
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Action' -Value ('forward') #Action the PBF rule specifies
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Egress-Interface' -Value ($rule.action.forward.'egress-interface') 
				if ($rule.action.forward.monitor)
				{
					Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'IsMonitored' -Value $true
					Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'MonitorProfile' -Value ($rule.action.forward.monitor.profile) #If the rule is monitored a monitor profile must be specified.
					if ($rule.action.forward.monitor.'ip-address')
					{
						Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'MonitoredAddress' -Value ($rule.action.forward.monitor.'ip-address')
					}
					if ($rules.action.forward.monitor.'disable-if-unreachable' -eq 'yes')
					{
						Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'DisableIfMonitoredAddressUnreachable' -Value $true
					}
					else
					{
						Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'DisableIfMonitoredAddressUnreachable' -Value $false
					}
				}
				else
				{
					Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'IsMonitored' -Value $false
				}
				if ($rule.action.forward.nexthop.'ip-address')
				{
					Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'NextHopAddress' -Value ($rule.action.forward.nexthop.'ip-address')
				}
			}
			if ($rule.action.discard)
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Action' -Value ('discard') #Action the PBF rule specifies
			}
			if ($rule.action.'no-pbf')
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Action' -Value ('no-pbf') #Action the PBF rule specifies
			}
			if ($rule.'enforce-symmetric-return'.enabled -eq 'yes')
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'EnforceSymmetricReturn' -Value $true
			}
			else
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'EnforceSymmetricReturn' -Value $false
			}
			if ($rule.from.zone)
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'FromZones' -Value ($rule.from.zone.member -join ';' -join ';')
			}
			else
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'FromInterfaces' -Value ($rule.from.interface.member -join ';')
			}
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'SourceAddresses' -Value ($rule.source.member -join ';')
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'SourceUsers' -Value ($rule.'source-user'.member -join ';')
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'DestinationAddress' -Value ($rule.destination.member -join ';')
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Applications' -Value ($rule.application.member -join ';')
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Service' -Value ($rule.service.member -join ';')
			if ($rule.disabled -eq 'yes')
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Disabled' -Value $true
			}
			else
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Disabled' -Value $false
			}
			[void]$result.add($parsedRule)
		}
	}
	return $result
}
 <#
.SYNOPSIS
Returns a list of IPsec SA's and their status. Currently returns raw XML. The output of this command will change soon.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

.PARAMETER 
	
.PARAMETER 
	


#>
Function Show-PaIpsecSa {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}

    $ipsecSa = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><vpn><ipsec-sa></ipsec-sa></vpn></show>&key=" + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($ipsecSa) #This function checks for an error from the firewall and throws it if there is one.

	#return $ipsecSa.response.result.entry  #this works in PANOS 5.0
	return $ipsecSa.response.result.entries.entry #this works with PANOS 7

}
 <#
.SYNOPSIS
Shows information about the Palo Alto firewall. This is the equivalent to the output of the "show system info" command on the cli.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

.PARAMETER 
	
.PARAMETER 
	


#>
Function Show-PaInfo {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}

    $paInfo = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><system><info></info></system></show>&key=" + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($paInfo) #This function checks for an error from the firewall and throws it if there is one.

	return $paInfo.response.result.system
}

<#
.SYNOPSIS
Shows Palo Alto firewall interfaces and their logical and physical status.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

.Parameter Interface
Optional.
If not specified, stats for all interfaces will be returned. If specified, stats only for the interface specified will be returned.


#>
Function Show-PaInterface {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Interface = 'all'
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
    $paInfo = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><interface>" + $Interface + "</interface></show>&key=" + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($paInfo) #This function checks for an error from the firewall and throws it if there is one.

	#Define the variable to hold the results of the interface network config.
	$intNetResult = New-Object System.Collections.ArrayList
	#Loop through the interface current settings.
	foreach ($entry in ($paInfo.response.result.ifnet.entry))
	{
		#Create the object to store in the array.
		$object = New-Object PSObject

		Add-Member -InputObject $object -MemberType NoteProperty -Name 'Name' -Value $entry.name
		Add-Member -InputObject $object -MemberType NoteProperty -Name 'Zone' -Value $entry.zone
		Add-Member -InputObject $object -MemberType NoteProperty -Name 'VirtualRouter' -Value $entry.fwd
		Add-Member -InputObject $object -MemberType NoteProperty -Name 'VSYS' -Value $entry.vsys
		Add-Member -InputObject $object -MemberType NoteProperty -Name 'VlanTag' -Value $entry.tag
		Add-Member -InputObject $object -MemberType NoteProperty -Name 'InterfaceID' -Value $entry.id
		if ($entry.ip)
		{
			Add-Member -InputObject $object -MemberType NoteProperty -Name 'IPv4Addresses' -Value (($entry.ip.trim(' ')) -join ';') #Remove whitespace from output and join multiple addresses with a semicolon.
		}
		else
		{
			Add-Member -InputObject $object -MemberType NoteProperty -Name 'IPv4Addresses' -Value ''
		}
		if ($entry.addr6.member)
		{
			Add-Member -InputObject $object -MemberType NoteProperty -Name 'IPv6Addresses' -Value (($entry.addr6.member.trim(' ')) -join ';') #Remove whitespace from output and join multiple addresses with a semicolon.
		}
		else
		{
			Add-Member -InputObject $object -MemberType NoteProperty -Name 'IPv6Addresses' -Value ''
		}
		[void]$intNetResult.Add($object)
	}

	#Define the variable to hold the results of the interface hardware config.
	$intHardwareResult = New-Object System.Collections.ArrayList
	#Loop through the interface current settings.
	foreach ($entry in ($paInfo.response.result.hw.entry))
	{
		#Create the object to store in the array.
		$object = New-Object PSObject

		Add-Member -InputObject $object -MemberType NoteProperty -Name 'Name' -Value $entry.name
		Add-Member -InputObject $object -MemberType NoteProperty -Name 'Duplex' -Value $entry.duplex
		Add-Member -InputObject $object -MemberType NoteProperty -Name 'Type' -Value $entry.type
		Add-Member -InputObject $object -MemberType NoteProperty -Name 'State' -Value $entry.state
		Add-Member -InputObject $object -MemberType NoteProperty -Name 'MACAddress' -Value $entry.mac
		Add-Member -InputObject $object -MemberType NoteProperty -Name 'Mode' -Value $entry.mode
		Add-Member -InputObject $object -MemberType NoteProperty -Name 'Speed' -Value $entry.speed #Remove whitespace from output and join multiple addresses with a semicolon.
		Add-Member -InputObject $object -MemberType NoteProperty -Name 'InterfaceID' -Value $entry.id
		[void]$intHardwareResult.Add($object)
	}
	$result = New-Object PSObject
	Add-Member -InputObject $result -MemberType NoteProperty -Name 'InterfaceNetworkStats' -Value $intNetResult
	Add-Member -InputObject $result -MemberType NoteProperty -Name 'InterfacePhysicalStats' -Value $intHardwareResult

	return $result
}

 <#
.SYNOPSIS
Returns information about Maximum supported sessions and active session counts on the Palo Alto firewall.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command. 


#>
Function Get-PaSessionInformation {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
    $paInfo = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><session><info></info></session></show>&key=" + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($paInfo) #This function checks for an error from the firewall and throws it if there is one.

	$sessionOutput = New-Object PSObject
	Add-Member -InputObject $sessionOutput -MemberType NoteProperty -Name 'Platform Max Sessions' -Value $paInfo.response.result.'num-max'
	Add-Member -InputObject $sessionOutput -MemberType NoteProperty -Name 'Total Active Sessions' -Value $paInfo.response.result.'num-active'
	Add-Member -InputObject $sessionOutput -MemberType NoteProperty -Name 'Total TCP Sessions' -Value $paInfo.response.result.'num-tcp'
	Add-Member -InputObject $sessionOutput -MemberType NoteProperty -Name 'Total UDP Session' -Value $paInfo.response.result.'num-udp'
	Add-Member -InputObject $sessionOutput -MemberType NoteProperty -Name 'Total ICMP Sessions' -Value $paInfo.response.result.'num-icmp'
	Add-Member -InputObject $sessionOutput -MemberType NoteProperty -Name 'New Connection Establish Rate' -Value $paInfo.response.result.'cps'
	Add-Member -InputObject $sessionOutput -MemberType NoteProperty -Name 'Packet Per Second' -Value $paInfo.response.result.'pps'
	Add-Member -InputObject $sessionOutput -MemberType NoteProperty -Name 'Kilobits per Second' -Value $paInfo.response.result.'kbps'
	return $sessionOutput
}
<#
.SYNOPSIS
Returns a list of Security rules configured in the candidate configuration on the Palo Alto firewall.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

#>
Function Get-PaSecurityRules 
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}

    $paConfig = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($paConfig) #This function checks for an error from the firewall and throws it if there is one.

	#Define the variable to hold the results of this command.
	$result = New-Object System.Collections.ArrayList
	$paSecurityRules = $paConfig.response.result.rules.entry
	foreach ($rule in $paSecurityRules)
	{
		$parsedRule = New-Object PSObject
		#Check if a rule has been edited but not committed, if it has then it needs to be processed slightly differently.
		if ($rule.to.member.'#text')
		{
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Rule Name' -Value ($rule.name) #rulename
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Description' -Value ($rule.description.'#text') #description
			if ($rule.'profile-setting'.group.member.'#text')
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'IPS Setting' -Value ($rule.'profile-setting'.group.member.'#text' -join ";") #IPS group setting
			}elseif ($rule.'profile-setting'.profiles.'#text')
			{
				$IPSProfiles = ''
				if ($rule.'profile-setting'.profiles.'url-filtering'.member.'#text')
				{
					$IPSProfiles += ('URL:' + ($rule.'profile-setting'.profiles.'url-filtering'.member.'#text') + ';')
				}
				if ($rule.'profile-setting'.profiles.'data-filtering'.member.'#text')
				{
					$IPSProfiles += ('DataFiltering:' + ($rule.'profile-setting'.profiles.'data-filtering'.member.'#text') + ';')
				}
				if ($rule.'profile-setting'.profiles.'file-blocking'.member.'#text')
				{
					$IPSProfiles += ('FileBlocking:' + ($rule.'profile-setting'.profiles.'file-blocking'.member.'#text') + ';')
				}
				if ($rule.'profile-setting'.profiles.'virus'.member.'#text')
				{
					$IPSProfiles += ('Virus:' + ($rule.'profile-setting'.profiles.'virus'.member.'#text') + ';')
				}
				if ($rule.'profile-setting'.profiles.'spyware'.member.'#text')
				{
					$IPSProfiles += ('Spyware:' + ($rule.'profile-setting'.profiles.'spyware'.member.'#text') + ';')
				}
				if ($rule.'profile-setting'.profiles.'vulnerability'.member.'#text')
				{
					$IPSProfiles += ('Vulnerability:' + ($rule.'profile-setting'.profiles.'vulnerability'.member.'#text') + ';')
				}
				if ($rule.'profile-setting'.profiles.'wildfire-analysis'.member.'#text')
				{
					$IPSProfiles += ('WildFire:' + ($rule.'profile-setting'.profiles.'wildfire-analysis'.member.'#text'))
				}
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'IPS Setting' -Value ($IPSProfiles) #IPS group setting
				Remove-Variable -Name IPSProfiles
			}else
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'IPS Setting' -Value ('')
			}
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source Zone' -Value ($rule.from.member.'#text' -join ";") #from zone
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source Address' -Value ($rule.source.member.'#text' -join ";") #Source addresses
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source User' -Value ($rule.'source-user'.member.'#text' -join ";") #Source Users
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Zone' -Value ($rule.to.member.'#text' -join ";") #destination Zone
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Address' -Value ($rule.destination.member.'#text' -join ";") #Destination addresses
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'URL Category' -Value ($rule.category.member.'#text' -join ";") # URL Category
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Applications' -Value ($rule.application.member.'#text' -join ";") #Applications
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Services' -Value ($rule.service.member.'#text' -join ";") #ports
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'HIP Profile' -Value ($rule.'hip-profiles'.member.'#text' -join ";") #hip profile
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Action' -Value ($rule.action.'#text') #action
			if ($rule.disabled -ne 'yes')
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Disabled' -Value ('no') #Is rule disabled.
			}else{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Disabled' -Value ($rule.disabled.'#text') #Is rule disabled.
			}
			#Add the object to the result array list.
			[void]$result.Add($parsedRule)
			Remove-Variable -Name parsedRule
		}else
		{
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Rule Name' -Value ($rule.name) #rulename
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Description' -Value ($rule.description) #description
			if ($rule.'profile-setting'.group.member)
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'IPS Setting' -Value ($rule.'profile-setting'.group.member -join ";") #IPS group setting
			}elseif ($rule.'profile-setting'.profiles)
			{
				$IPSProfiles = ''
				if ($rule.'profile-setting'.profiles.'url-filtering'.member)
				{
					$IPSProfiles += ('URL:' + ($rule.'profile-setting'.profiles.'url-filtering'.member) + ';')
				}
				if ($rule.'profile-setting'.profiles.'data-filtering'.member)
				{
					$IPSProfiles += ('DataFiltering:' + ($rule.'profile-setting'.profiles.'data-filtering'.member) + ';')
				}
				if ($rule.'profile-setting'.profiles.'file-blocking'.member)
				{
					$IPSProfiles += ('FileBlocking:' + ($rule.'profile-setting'.profiles.'file-blocking'.member) + ';')
				}
				if ($rule.'profile-setting'.profiles.'virus'.member)
				{
					$IPSProfiles += ('Virus:' + ($rule.'profile-setting'.profiles.'virus'.member) + ';')
				}
				if ($rule.'profile-setting'.profiles.'spyware'.member)
				{
					$IPSProfiles += ('Spyware:' + ($rule.'profile-setting'.profiles.'spyware'.member) + ';')
				}
				if ($rule.'profile-setting'.profiles.'vulnerability'.member)
				{
					$IPSProfiles += ('Vulnerability:' + ($rule.'profile-setting'.profiles.'vulnerability'.member) + ';')
				}
				if ($rule.'profile-setting'.profiles.'wildfire-analysis'.member)
				{
					$IPSProfiles += ('WildFire:' + ($rule.'profile-setting'.profiles.'wildfire-analysis'.member))
				}
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'IPS Setting' -Value ($IPSProfiles) #IPS group setting
				Remove-Variable -Name IPSProfiles
			}else
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'IPS Setting' -Value ('')
			}
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source Zone' -Value ($rule.from.member -join ";") #from zone
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source Address' -Value ($rule.source.member -join ";") #Source addresses
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source User' -Value ($rule.'source-user'.member -join ";") #Source Users
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Zone' -Value ($rule.to.member -join ";") #destination Zone
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Address' -Value ($rule.destination.member -join ";") #Destination addresses
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'URL Category' -Value ($rule.category.member -join ";") # URL Category
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Applications' -Value ($rule.application.member -join ";") #Applications
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Services' -Value ($rule.service.member -join ";") #ports
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'HIP Profile' -Value ($rule.'hip-profiles'.member -join ";") #hip profile
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Action' -Value ($rule.action) #action
			if ($rule.disabled -ne 'yes')
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Disabled' -Value ('no') #Is rule disabled.
			}else{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Disabled' -Value ($rule.disabled) #Is rule disabled.
			}
			#Add the object to the result array list.
			[void]$result.Add($parsedRule)
			Remove-Variable -Name parsedRule
		}
	}
	Remove-Variable -Name rule
	Remove-Variable -Name paSecurityRules
	return $result
}
<#
.SYNOPSIS
Returns a list of NAT rules configured in the candidate configuration on the firewall.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

#>
Function Get-PaNATRules {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}

	$paConfig = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules&key=" + (GetPaAPIKeyClearText)) 
	ReturnPaAPIErrorIfError($paConfig) #This function checks for an error from the firewall and throws it if there is one.

	$paNATRules = $paConfig.response.result.rules.entry
	#Define the variable to hold the results of this command.
	$result = New-Object System.Collections.ArrayList

	foreach ($rule in $paNATRules)
	{
		$parsedRule = New-Object PSObject
		#Check if a rule has been edited but not committed, if it has then it needs to be processed slightly differently.
		if ($rule.to.member.'#text')
		{
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Rule Name' -Value ($rule.name) #rulename
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Description' -Value ($rule.description.'#text') #description
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Address' -Value ($rule.destination.member.'#text' -join ";") #Destination Address
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Zone' -Value ($rule.to.member.'#text' -join ";") #Destination Zone
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Interface' -Value ($rule.'to-interface'.'#text' -join ";") #Destination Interface
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Translation' -Value ($rule.'destination-translation'.'translated-address'.'#text' -join ";") #Source Users
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Port Translation' -Value ($rule.'destination-translation'.'translated-port'.'#text' -join ";") # URL Category
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source Zone' -Value ($rule.from.member.'#text' -join ";") #from zone
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source Address' -Value ($rule.source.member.'#text' -join ";") #Source addresses
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Services' -Value ($rule.service.'#text' -join ";") #ports
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source Translation IP address' -Value ($rule.'source-translation'.'dynamic-ip-and-port'.'interface-address'.ip.'#text') #Source Translation IP address
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source Translation Interface' -Value ($rule.'source-translation'.'dynamic-ip-and-port'.'interface-address'.interface.'#text') #Source Translation Interface
			if ($rule.disabled.'#text' -ne 'yes')
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Disabled' -Value ('no') #Is rule disabled.
			}else{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Disabled' -Value ($rule.disabled.'#text') #Is rule disabled.
			}
			#Add the object to the result array list.
			[void]$result.Add($parsedRule)
			Remove-Variable -Name parsedRule
		}else
		{
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Rule Name' -Value ($rule.name) #rulename
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Description' -Value ($rule.description) #description
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Address' -Value ($rule.destination.member -join ";") #Destination Address
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Zone' -Value ($rule.to.member -join ";") #Destination Zone
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Interface' -Value ($rule.'to-interface' -join ";") #Destination Interface
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Translation' -Value ($rule.'destination-translation'.'translated-address' -join ";") #Source Users
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Destination Port Translation' -Value ($rule.'destination-translation'.'translated-port' -join ";") # URL Category
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source Zone' -Value ($rule.from.member -join ";") #from zone
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source Address' -Value ($rule.source.member -join ";") #Source addresses
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Services' -Value ($rule.service -join ";") #ports
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source Translation IP address' -Value ($rule.'source-translation'.'dynamic-ip-and-port'.'interface-address'.ip) #Source Translation IP address
			Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Source Translation Interface' -Value ($rule.'source-translation'.'dynamic-ip-and-port'.'interface-address'.interface) #Source Translation Interface
			if ($rule.disabled -ne 'yes')
			{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Disabled' -Value ('no') #Is rule disabled.
			}else{
				Add-Member -InputObject $parsedRule -MemberType NoteProperty -Name 'Disabled' -Value ($rule.disabled) #Is rule disabled.
			}
			#Add the object to the result array list.
			[void]$result.Add($parsedRule)
			Remove-Variable -Name parsedRule
		}
	}
	return $result
}

<#
.SYNOPSIS
Returns a list of all active sessions on the firewall. This is the equivalent to running "show session all" on the command line. This function will iterate through all sessions beyond the 1024 default. Some sessions may be duplicated.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

#>
Function Show-PaActiveSessions {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$paConfig = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/service&key=" + (GetPaAPIKeyClearText))

	$sessionCount = 1
	$paInfo = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><session><all><start-at>" + $sessionCount + "</start-at></all></session></show>&key=" + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($paInfo) #This function checks for an error from the firewall and throws it if there is one.

	$sessions = $paInfo.response.result.entry
	#The firewall will only send a max of 1024 sessions back at one time. If we get 1024 sessions back there are likely more sessions to be retrieved. 
	while (($paInfo.response.result.entry | Measure-Object).count -eq 1024)
	{
		$sessionCount += 1024
		$paInfo = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><session><all><start-at>" + $sessionCount + "</start-at></all></session></show>&key=" + (GetPaAPIKeyClearText)))
		$sessions += $paInfo.response.result.entry
	}
	return $sessions
}

<#
.SYNOPSIS
Returns a list of configured PA services from the candidate configuration.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

#>
Function Get-PaServices {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$paConfig = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/service&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($paConfig) #This function checks for an error from the firewall and throws it if there is one.

	#Define the variable to hold the results of this command.
	$result = New-Object System.Collections.ArrayList

	#Get the relevant information from the result of the web request.
	$paServices = $paConfig.response.result.service.entry

	foreach ($service in $paServices)
	{
		$parsedService = New-Object PSObject
		Add-Member -InputObject $parsedService -MemberType NoteProperty -Name 'Service Name' -Value ($service.name) #Service Name
		if ($service.protocol.tcp.port.'#text')
		{
			Add-Member -InputObject $parsedService -MemberType NoteProperty -Name 'Protocol' -Value ('tcp') #Protocol
			Add-Member -InputObject $parsedService -MemberType NoteProperty -Name 'Port' -Value ($service.protocol.tcp.port.'#text') #Port
		}
		elseif ($service.protocol.udp.port.'#text')
		{
			Add-Member -InputObject $parsedService -MemberType NoteProperty -Name 'Protocol' -Value ('udp') #Protocol
			Add-Member -InputObject $parsedService -MemberType NoteProperty -Name 'Port' -Value ($service.protocol.udp.port.'#text' -join ";") #Port
		}
		else
		{
			Add-Member -InputObject $parsedService -MemberType NoteProperty -Name 'Protocol' -Value ($service.protocol.childnodes -join ";") #Protocol
			Add-Member -InputObject $parsedService -MemberType NoteProperty -Name 'Port' -Value ($service.protocol.($service.protocol.childnodes).port -join ";") #Port
		}

		#Add the object to the result array list.
		[void]$result.Add($parsedService)
		Remove-Variable -Name parsedService
	}
	return $result
}

<#
.SYNOPSIS
Returns a list of configure service groups from the candidate configuration.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

#>
Function Get-PaServiceGroups {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$paConfig = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/service-group&key=" + (GetPaAPIKeyClearText))  
	ReturnPaAPIErrorIfError($paConfig) #This function checks for an error from the firewall and throws it if there is one.

	$paServiceGroups = $paConfig.response.result.'service-group'.entry #Set paServiceGroups to the root of the Service groups in the config for easier processing.
	$paServices = (Get-PaServices -ID $ID) #Get the list of all Services by running the handily already written commandlet. This is so we can loop through them later in memory without getting the list every time.
	#Define the variable to hold the results of this command.
	$result = New-Object System.Collections.ArrayList

	Function getServicesForGroup ($group) 
	{
		$ports = ''
		if ($group.members.member.'#text')
		{
			$members = ($group.members.member.'#text')
		}
		else
		{
			$members = ($group.members.member)
		}
		foreach ($member in $members) #This loops through all of the service members of the service group. Since I joined the members with semicolons I split them so I can loop through them like an array.
		{
			if($paServices.'Service Name' -contains $member){
				$service = ($paServices | where {$_.'Service Name' -eq $member})
				$ports += [string]($service.Protocol + '-' + $service.Port + ';')
				continue
			}
			if ($member -like 'service-https')#This must be hard coded because the service-http and service https rules are predefined and not in the configuration.
			{
				$ports += 'tcp-443;'
				continue #Break because otherwise ports can be erroneously filled in, also because it could be more effcient.
			}
			if ($member -like 'service-http') #This must be hard coded because the service-http and service https rules are predefined and not in the configuration.
			{
				$ports += 'tcp-80;tcp-8080;'
				continue #Break because otherwise ports can be erroneously filled in, also because it could be more effcient.
			}
			$ports += getServicesForGroup($paServiceGroups | where {$_.name -eq $member})
		}
		return $ports
		Remove-Variable -Name ports
	}
	foreach ($serviceGroup in $paServiceGroups) #Loop through each service group one by one to get the relevant information.
	{
		$resultPorts = getServicesForGroup($serviceGroup) #gets list of all ports for the group.
		#Create the result object to be stored in the result array.
		$ServiceGroupResult = New-Object PSObject

		Add-Member -InputObject $ServiceGroupResult -MemberType NoteProperty -Name 'Service Group Name' -Value $serviceGroup.name #Service Name
		if ($serviceGroup.members.member.'#text')
		{
			Add-Member -InputObject $ServiceGroupResult -MemberType NoteProperty -Name 'Members' -Value ($serviceGroup.members.member.'#text' -join ";") #Members
		}
		else
		{
			Add-Member -InputObject $ServiceGroupResult -MemberType NoteProperty -Name 'Members' -Value ($serviceGroup.members.member -join ";") #Members
		}
		Add-Member -InputObject $ServiceGroupResult -MemberType NoteProperty -Name 'Ports' -Value ($resultPorts.Substring(0,$resultPorts.Length-1)) #The ports that make up the service group. #The last weird bit strips the last charachter from the string, which is a semi-colon, which shouldn't be there because the string is ended.
		#Add the object to the result array list.
		[void]$result.Add($ServiceGroupResult)
		Remove-Variable -Name ServiceGroupResult
	}
	Remove-Variable -Name serviceGroup
	Remove-Variable -Name paServiceGroups
	Remove-Variable -Name paServices
	Remove-Variable -Name resultPorts
	return $result

}

<#
.SYNOPSIS
Returns a list of configured address objects from the candidate configuration.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
#>
Function Get-PaAddressObjects {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	Write-Debug 'Making the firewall call.'
	$paConfig = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/address&key=" + (GetPaAPIKeyClearText))
	Write-Debug 'After making the call.'
	ReturnPaAPIErrorIfError($paConfig) #This function checks for an error from the firewall and throws it if there is one.

	#Define the variable to hold the results of this command.
	Write-Debug 'Creating the result array.'
	$result = New-Object System.Collections.ArrayList

	Write-Debug 'Creating paAddresses variable.'
	$paAddresses = $paConfig.response.result.address.entry
	Write-Debug 'Created paAddress variable.'
	foreach ($address in $paAddresses)
	{
		$parsedAddress = New-Object PSObject

		#Create the address object.
		Add-Member -InputObject $parsedAddress -MemberType NoteProperty -Name 'Address Name' -Value $address.name #Service Name
		if ($address.fqdn)
		{
			if ($address.fqdn.'#text')
			{
				Add-Member -InputObject $parsedAddress -MemberType NoteProperty -Name 'fqdn' -Value $address.fqdn.'#text' #Add fqdn Information
			}
			else
			{
				Add-Member -InputObject $parsedAddress -MemberType NoteProperty -Name 'fqdn' -Value $address.fqdn #Add fqdn Information
			}
		}
		if ($address.'ip-netmask')
		{
			if ($address.'ip-netmask'.'#text')
			{
				Add-Member -InputObject $parsedAddress -MemberType NoteProperty -Name 'ip-netmask' -Value $address.'ip-netmask'.'#text' #Add ip-netmask information
			}
			else
			{
				Add-Member -InputObject $parsedAddress -MemberType NoteProperty -Name 'ip-netmask' -Value $address.'ip-netmask' #Add ip-netmask information
			}
		}
		if ($address.'ip-range')
		{
			if ($address.'ip-range'.'#text')
			{
				Add-Member -InputObject $parsedAddress -MemberType NoteProperty -Name 'ip-range' -Value $address.'ip-range'.'#text' #Add ip range information
			}
			else
			{
				Write-Debug 'Adding IP-Range.'
				Add-Member -InputObject $parsedAddress -MemberType NoteProperty -Name 'ip-range' -Value $address.'ip-range' #Add ip range information
			}
		}
		#Add the object to the result array list.
		[void]$result.Add($parsedAddress)
		Remove-Variable -Name parsedAddress
	}
	return $result
}

<#
.SYNOPSIS
Returns a list of configured address groups from the candidate configuration. (This only works for static groups at this time.)
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
#>
Function Get-PaAddressGroups {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$paConfig = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/address-group&key=" + (GetPaAPIKeyClearText))  
	ReturnPaAPIErrorIfError($paConfig) #This function checks for an error from the firewall and throws it if there is one.

	$paAddressGroups = $paConfig.response.result.'address-group'.entry #Set paAddressGroups to the root of the Service groups in the config for easier processing.
	$paAddressObjects = (Get-PaAddressObjects -ID $ID) #Get the list of all Addresses by running the handily already written commandlet. This is so we can loop through them later in memory without getting the list every time.
		
	#Define the variable to hold the results of this command.
	$result = New-Object System.Collections.ArrayList

	Function getAddressesForGroup ($group) 
	{
		[string]$ipAddresses = ''
		if ($group.static.member.'#text')
		{
			foreach ($member in $group.static.member.'#text') #This loops through all of the members of the address group. Since I joined the members with semicolons I split them so I can loop through them like an array.
			{
				if($paAddressObjects.'Address Name' -contains $member)
				{
					$address = ($paAddressObjects | where {$_.'Address Name' -eq $member})
					if ($address.'fqdn')
					{
						$ipAddresses += ($address.'fqdn')
					}
					if ($address.'ip-netmask')
					{
						$ipAddresses += ($address.'ip-netmask')
					}
					if ($address.'ip-range')
					{
						Write-Debug ('Adding IP range for address' + $address.'Address Name' )
						$ipAddresses += ($address.'ip-range')
					}
					$ipAddresses += ';'
					continue #Break because otherwise addresses can be erroneously filled in, also because it could be more effcient.
				}
				$ipAddresses += (getAddressesForGroup($paAddressGroups | where {$_.'name' -eq $member}))
			}
		}
		else
		{
			foreach ($member in $group.static.member) #This loops through all of the members of the address group. Since I joined the members with semicolons I split them so I can loop through them like an array.
			{
				if($paAddressObjects.'Address Name' -contains $member)
				{
					$address = ($paAddressObjects | where {$_.'Address Name' -eq $member})
					if ($address.'fqdn')
					{
						$ipAddresses += ($address.'fqdn')
					}
					if ($address.'ip-netmask')
					{
						$ipAddresses += ($address.'ip-netmask')
					}
					if ($address.'ip-range')
					{
						Write-Debug ('Adding IP range for address' + $address.'Address Name' )
						$ipAddresses += ($address.'ip-range')
					}
					$ipAddresses += ';'
					continue #Break because otherwise addresses can be erroneously filled in, also because it could be more effcient.
				}
				$ipAddresses += (getAddressesForGroup($paAddressGroups | where {$_.'name' -eq $member}))
			}
		}
		return $ipAddresses
		Remove-Variable -Name ipAddresses
	}
	foreach ($AddressGroup in $paAddressGroups) #Loop through each service group one by one to get the relevant information.
	{
		$resultAddresses = getAddressesForGroup($AddressGroup) #gets list of all addresses for the group.

		#Create the result object to be stored in the result array.
		$AddressGroupResult = New-Object PSObject

		Add-Member -InputObject $AddressGroupResult -MemberType NoteProperty -Name 'Address Group Name' -Value $AddressGroup.name #Address group Name
		if ($AddressGroup.static.member.'#text')
		{
			Add-Member -InputObject $AddressGroupResult -MemberType NoteProperty -Name 'Members' -Value ($AddressGroup.static.member.'#text' -join ";") #Address group members
		}else
		{
			Add-Member -InputObject $AddressGroupResult -MemberType NoteProperty -Name 'Members' -Value ($AddressGroup.static.member -join ";") #Address group members
		}
		Add-Member -InputObject $AddressGroupResult -MemberType NoteProperty -Name 'Addresses' -Value ($resultAddresses.Substring(0,$resultAddresses.Length-1)) #The addresses that make up the address group. #The last weird bit strips the last charachter from the string, which is a semi-colon, which shouldn't be there because the string is ended.
		#Add the object to the result array list.
		[void]$result.Add($AddressGroupResult)
		Remove-Variable -Name AddressGroupResult
	}
	return $result
}

<#
.SYNOPSIS
Show jobs the firewall is running or has run, or just the requested job by ID.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter All
Optional.
Returns a list of all jobs in the firewall task list. Pending, Active, or completed.
.Parameter Pending
Optional.
Returns a list of pending jobs in the firewall.
.Parameter Processed
Returns a list of Completed jobs in the firewall

#>
Function Show-PaJobs{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$All,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$JobID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$Pending,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$Processed
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	if (($All -and $JobID) -or ($All -and $Pending) -or ($All -and $Processed) -or ($JobID -and $Pending) -or ($JobID -and $Processed) -or ($Pending -and $Processed))
	{
		throw 'You may only select one method to retrieve the jobs.'
	}
	if ($All)
	{
		$query = '<show><jobs><all></all></jobs></show>'
	}
	elseif($JobID)
	{
		$query = ('<show><jobs><id>' + $JobID + '</id></jobs></show>')
	}
	elseif ($Pending)
	{
		$query = '<show><jobs><pending></pending></jobs></show>'
	}
	elseif ($Processed)
	{
		$query = '<show><jobs><processed></processed></jobs></show>'
	}
	else
	{
		throw ("No option to retrieve logs was specified.")
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=" + $query + "&key=" + (GetPaAPIKeyClearText))  
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	#Just return the XML that the firewall gives us. All requests for jobs store the job data in the same node.
	$response.response.result.job
}

<#
.SYNOPSIS
This function tells the firewall to refresh it's PANOS version list from the Palo Alto networks server and returns all available software versions. If you only want a list of software versions the firewall is currently aware of please use the "Get-PaAvailableSoftwareVersions" command.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
#>
Function Request-PaAvailableSoftwareVersions
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<request><system><software><check></check></software></system></request>&key=" + (GetPaAPIKeyClearText))  
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	#Define the variable to hold the results of this command.
	$result = New-Object System.Collections.ArrayList
	foreach ($entry in ($response.response.result.'sw-updates'.versions.entry))
	{
		#Create the result object to be stored in the result array.
		$osEntry = New-Object PSObject
		Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'Version' -Value $entry.version
		Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'Filename' -Value $entry.filename
		Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'SizeMB' -Value $entry.size
		Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'SizeKB' -Value $entry.'size-kb'
		Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'ReleasedOn' -Value $entry.'released-on'
		Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'ReleaseNotesURL' -Value $entry.'release-notes'.'#cdata-section'
		if ($entry.downloaded -eq 'yes')
		{
			Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'IsDownloaded' -Value $true
		}
		else
		{
			Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'IsDownloaded' -Value $false
		}
		if ($entry.current -eq 'yes')
		{
			Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'CurrentlyInstalled' -Value $true
		}
		else
		{
			Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'CurrentlyInstalled' -Value $false
		}
		#Add-Member -InputObject $osEntry-MemberType NoteProperty -Name 'Latest' -Value $entry.latest 
		#Add-Member -InputObject $osEntry-MemberType NoteProperty -Name 'Uploaded' -Value $entry.uploaded 
		[void]$result.Add($osEntry)
	}
	return $result
}

<#
.SYNOPSIS
This function retrieves the list of PANOS versions the firewall is currently aware of. This function does not check for updates from Palo Alto servers. To do that please run the "Request-PaAvailableSoftwareVersions" command.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

#>
Function Get-PaAvailableSoftwareVersions
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$ReturnRawResult = $false
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<request><system><software><info></info></software></system></request>&key=" + (GetPaAPIKeyClearText))  
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	if ($ReturnRawResult)
	{
		return $response
	}
	#Define the variable to hold the results of this command.
	$result = New-Object System.Collections.ArrayList
	foreach ($entry in ($response.response.result.'sw-updates'.versions.entry))
	{
		#Create the result object to be stored in the result array.
		$osEntry = New-Object PSObject
		Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'Version' -Value $entry.version
		Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'Filename' -Value $entry.filename
		Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'SizeMB' -Value $entry.size
		Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'SizeKB' -Value $entry.'size-kb'
		Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'ReleasedOn' -Value $entry.'released-on'
		Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'ReleaseNotesURL' -Value $entry.'release-notes'.'#cdata-section'
		if ($entry.downloaded -eq 'yes')
		{
			Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'IsDownloaded' -Value $true
		}
		else
		{
			Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'IsDownloaded' -Value $false
		}
		if ($entry.current -eq 'yes')
		{
			Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'CurrentlyInstalled' -Value $true
		}
		else
		{
			Add-Member -InputObject $osEntry -MemberType NoteProperty -Name 'CurrentlyInstalled' -Value $false
		}
		#Add-Member -InputObject $osEntry-MemberType NoteProperty -Name 'Latest' -Value $entry.latest 
		#Add-Member -InputObject $osEntry-MemberType NoteProperty -Name 'Uploaded' -Value $entry.uploaded 
		[void]$result.Add($osEntry)
	}
	return $result
}

<#
.SYNOPSIS
This function will output all of the ARP enties the Palo Alto firewall has learned.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
#>
Function Show-PaArpEntries {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><arp><entry name = 'all'/></arp></show>&key=" + (GetPaAPIKeyClearText))  
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.

	#Define the variable to hold the results of this command.
	$result = New-Object System.Collections.ArrayList
	foreach ($entry in ($response.response.result.entries.entry))
	{
		#Create the result object to be stored in the result array.
		$arpEntry = New-Object PSObject

		Add-Member -InputObject $arpEntry -MemberType NoteProperty -Name 'Status' -Value ($entry.status).Trim(' ') #PA echoes white space for formatting, remove it.
		Add-Member -InputObject $arpEntry -MemberType NoteProperty -Name 'IPAddress' -Value $entry.ip
		Add-Member -InputObject $arpEntry -MemberType NoteProperty -Name 'MACAddress' -Value $entry.mac
		Add-Member -InputObject $arpEntry -MemberType NoteProperty -Name 'TTL' -Value $entry.ttl
		Add-Member -InputObject $arpEntry -MemberType NoteProperty -Name 'Interface' -Value $entry.interface
		Add-Member -InputObject $arpEntry -MemberType NoteProperty -Name 'Port' -Value $entry.port
		[void]$result.Add($arpEntry)
		Remove-Variable -Name arpEntry
	}
	return $result
}


<#
.SYNOPSIS
This function is used to check Palo Alto traffic, threat, and URL logs for blocked traffic. It can also return some logs so the user can get a better idea of why the traffic was blocked it desired.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter SearchAfterDate
Optional.
Specify a date that "Get-Date" command can interpret. This script will look for logs that date from the present time back until the time specified by this parameter.
.Parameter SourceAddress
Optional.
Specify the source address to look for in the logs. This can be an IP address or hostname, it can also be a full URL (example: https://www.google.com:443/mainpage/test.html). The latter functionality was added to make it easier for people who don't know to resolve DNS names.
If you want to specify a source port include it in standard URL format. Examples of this are: 192.168.1.50:80 , www.google.com:443 ,  [1fff:0:a88:85a3::ac1f]:8001
.Parameter DestinationAddress
Optional.
Specify the destination address to look for in the logs. This can be an IP address or hostname, it can also be a full URL (example: https://www.google.com:443/mainpage/test.html). The latter functionality was added to make it easier for people who don't know to resolve DNS names.
If you want to specify a source port include it in standard URL format. Examples of this are: 192.168.1.50:80 , www.google.com:443 ,  [1fff:0:a88:85a3::ac1f]:8001
.Parameter NumberOfLogsToReturn
Optional.
By default this value is 1. You can increase this number to a maximum of 5000. This command is only useful if you use either or both of the returnLogs or ReturnRawLogs switches.
.Parameter returnLogs
Optional.
Use this parameter to append formatted logs to the output of this command for review.
.Parameter ReturnRawLogs
Optional.
Use this parameter to append the raw logs to the output of this command for review. These may change from time to time as PANOS versions change.
.Description
The basic output of this command just lets the user know whether or not there is blocked traffic in either the traffic, threat, and/or URL logs.
#>
Function Check-PaLogsForBlockedTraffic
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SearchAfterDate = (get-date (Get-Date).AddDays('-1') -Format 'yyyy/MM/dd HH:mm:ss'), #Only search the past day unless sotherwise specified.
	[Parameter(Mandatory=$false,valueFromPipeline=$true)]$SourceAddress, #Can be multiple DNS names and/or IP addresses
	[Parameter(Mandatory=$false,valueFromPipeline=$true)]$DestinationAddress, #Can be multiple DNS names and/or IP addresses
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$NumberOfLogsToReturn = 1, #Defines how many logs to return. Max 5000
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$returnLogs = $false,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][switch]$ReturnRawLogs = $false
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	if ($ReturnRawLogs)
	{
		$returnLogs = $true #Set that to true so we get logs back.
	}
	if ($SearchAfterDate)
	{
		Try
		{
			$SearchAfterDate = (get-date $SearchAfterDate -Format 'yyyy/MM/dd HH:mm:ss')
		}
		Catch
		{
			throw "Please specify the date in a format Get-Date can interpret."
		}
	}
	if ($SourceAddress)
	{
		$SourceAddresses = New-Object System.Collections.ArrayList
		foreach($entry in $SourceAddress)
		{
			$addressObject = New-Object psobject
			Add-Member -InputObject $addressObject  -MemberType NoteProperty -Name 'address' -Value $address
			Add-Member -InputObject $addressObject  -MemberType NoteProperty -Name 'port' -Value $port 
			try
			{
				$result = ParseURL -userInput $entry
				foreach ($item in $result)
				{
					[void]$SourceAddresses.Add($item)
				}
			}
			Catch
			{
				throw $_
			}
		}
	}
	if ($DestinationAddress)
	{
		$DestinationAddresses = New-Object System.Collections.ArrayList
		foreach($entry in $DestinationAddress)
		{
			$addressObject = New-Object psobject
			Add-Member -InputObject $addressObject  -MemberType NoteProperty -Name 'address' -Value $address
			Add-Member -InputObject $addressObject  -MemberType NoteProperty -Name 'port' -Value $port 
			try
			{
				$result = ParseURL -userInput $entry
				foreach ($item in $result)
				{
					[void]$DestinationAddresses.Add($item)
				}
			}
			Catch
			{
				throw $_
			}
		}
	}
	#Build the query.
	$query = "(receive_time geq '" + $SearchAfterDate + "')"
	if ($SourceAddresses)
	{
		$query += " and (" 
		foreach ($SourceAddress in $SourceAddresses)
		{
			if ($SourceAddress.port -ne $null) #Check if a port was included for this address
			{
				$query += "((addr.src eq '" + $SourceAddress.IpAddress + "') and (port.src eq " + $SourceAddress.port + ")) or "
			}
			else
			{
							$query += "(addr.src eq '" + $SourceAddress.IpAddress  + "') or "
			}
		}
		$query = $query.Substring(0,($query.Length -4)) #Once the loop is complete remove the trailing ' or '
		$query += ")"
	}
	if ($DestinationAddresses)
	{
		$query += " and (" 
		foreach ($DestinationAddress in $DestinationAddresses)
		{
			if ($DestinationAddress.port -ne $null) #Check if a port was included for this address
			{
				$query += "((addr.dst eq '" + $DestinationAddress.IpAddress + "') and (port.dst eq " + $DestinationAddress.port + ")) or "
			}
			else
			{
				$query += "(addr.dst eq '" + $DestinationAddress.IpAddress  + "') or "
			}
		}
		$query = $query.Substring(0,($query.Length -4)) #Once the loop is complete remove the trailing ' or '
		$query += ")"
	}
	$trafficQuery = ($query + " and (action neq allow)")
	$threatQuery = ($query + " and (action neq alert)")
	$urlQuery = ($query + " and (action neq alert)")
	#return $query
	Write-Debug ("The query for the rules is: " + $query)
	if ($ReturnRawLogs)
	{
		$trafficLogResponse = Get-PaTrafficLogs -ID $ID -query $trafficQuery -NumberOfLogsToReturn $NumberOfLogsToReturn -ReturnRawLogs
		$threatLogsResponse = Get-PaThreatLogs -ID $ID -query $threatQuery -NumberOfLogsToReturn $NumberOfLogsToReturn -ReturnRawLogs
		$urlLogsResponse = Get-PaURLLogs -ID $ID -query $urlQuery -NumberOfLogsToReturn $NumberOfLogsToReturn -ReturnRawLogs
	}
	else
	{
		$trafficLogResponse = Get-PaTrafficLogs -ID $ID -query $trafficQuery -NumberOfLogsToReturn $NumberOfLogsToReturn
		$threatLogsResponse = Get-PaThreatLogs -ID $ID -query $threatQuery -NumberOfLogsToReturn $NumberOfLogsToReturn
		$urlLogsResponse = Get-PaURLLogs -ID $ID -query $urlQuery -NumberOfLogsToReturn $NumberOfLogsToReturn
	}
	
	$trafficLogs = $trafficLogResponse.logs.logs
	$threatLogs = $threatLogsResponse.logs.logs
	$urlLogs = $urlLogsResponse.logs.logs

	$returnObject = New-Object PSObject

	if ($trafficLogs.count -gt 0)
	{
		Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'TrafficBlockedDueToFirewallRules' -Value $true
	}
	else
	{
		Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'TrafficBlockedDueToFirewallRules' -Value $false
	}
	if ($threatLogs.count -gt 0)
	{
		Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'TrafficBlockedDueToDetectedThreats' -Value $true
	}
	else
	{
		Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'TrafficBlockedDueToDetectedThreats' -Value $false
	}
	if ($urlLogs.count -gt 0)
	{
		Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'TrafficBlockedDueToURLFiltering' -Value $true
	}
	else
	{
		Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'TrafficBlockedDueToURLFiltering' -Value $false
	}
	if ($returnLogs)
	{
		Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'TrafficLogEntries' -Value $trafficLogs
		Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'ThreatLogEntries' -Value $threatLogs
		Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'URLLogEntries' -Value $urlLogs
	}
	if ($ReturnRawLogs)
	{
		Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'RawTrafficLogEntries' -Value $trafficLogResponse.logs.RawLogs
		Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'RawThreatLogEntries' -Value $threatLogsResponse.logs.RawLogs
		Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'RawURLLogEntries' -Value $urlLogsResponse.logs.RawLogs
	}
	Add-Member -InputObject $returnObject  -MemberType NoteProperty -Name 'SearchAfterDate' -Value $SearchAfterDate
	return $returnObject
}

<#
.SYNOPSIS
This is a generic function used to request a job to get PA logs.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

.Description
Other:
Relevant documentation.
https://www.paloaltonetworks.com/documentation/71/pan-os/xml-api/pan-os-xml-api-request-types/retrieve-logs-api
#>
Function Request-PaLogs {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$traffic,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$threat,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$url,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$system,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$query,
    [Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$NumberOfLogsToReturn=1000 #Max 5000
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	if ([int]$NumberOfLogsToReturn -gt 5000)
	{
		throw "You cannot return more than 5000 logs."
	}
	if ($traffic)
	{
		$logType = 'traffic'
	}
	if ($threat)
	{
		$logType = 'threat'
	}
	if ($url)
	{
		$logType = 'url'
	}
	if ($system)
	{
		$logType = 'system'
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=log&log-type=" + $logType + "&query=" + $query + "&nlogs = "+ $NumberOfLogsToReturn + "&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	$returnObject = New-Object PSObject
	Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'status' -Value $response.response.status
	Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'code' -Value $response.response.code
	Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'message' -Value $response.response.result.msg.line
	Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'job' -Value $response.response.result.job
	return $returnObject
}

<#
.SYNOPSIS
This is a generic function used to get PA logs from a job.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Description
Other:
Relevant documentation.
https://www.paloaltonetworks.com/documentation/71/pan-os/xml-api/pan-os-xml-api-request-types/retrieve-logs-api
#>
Function Get-PaLogsFromJob {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][int]$jobID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][int]$TimesToRetry = 60
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$requestAttemps = 0
	while ($requestAttemps -lt $TimesToRetry)
	{
		$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=log&action=get&job-id=" + $jobID+ "&key=" + (GetPaAPIKeyClearText))
		ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
		if ($response.response.result.job.status -eq 'ACT') #Check that the job is still active.
		{
			Write-Debug ("Sleeping for 2 seconds since log collection is not complete.") #This line is for debugging.
			sleep(2) # Wait 2 seconds then poll the firewall again to see if all logs have been retrived.
			$requestAttemps += 1
		}
		else
		{
			#If the job is finished leave the loop.
			break
		}
	}
	return $response
}
<#
.SYNOPSIS
Returns a list of Traffic Logs from the firewall. Maximum of 5000 entries can be returned.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter Query
Optional:
A query you supply, in the format you would used for a query for traffic logs in the web interface, to be used to filter log responses returned. If no query is specified the default query will only return logs from the last hour.
.Parameter NumberOfLogsToReturn
Optional:
Use this to specify how many log entries you want returned (Maximum of 5000).
.Paramter ReturnRawLogs
Optional:
Specify to have logs returned as an extra property in the output of this script. These logs will be output in the XML format they were recieved and not the standardized output this functions would normally return them in.
#>
Function Get-PaTrafficLogs {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Query = ("(receive_time geq '" + (get-date (Get-Date).AddHours('-1') -Format 'yyyy/MM/dd HH:mm:ss') + "')"),# don't get an infinite number of logs, if the script is called without the query parameter only get the last hour.
    [Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$NumberOfLogsToReturn = 5000, #Defines how many logs to return. Max 5000
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][switch]$ReturnRawLogs = $false
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = Request-PaLogs -ID $ID -Query $Query -NumberOfLogsToReturn $NumberOfLogsToReturn -traffic
	$jobID = $response.job
	sleep(1) # don't immediately poll for the results, chances are really good they aren't ready yet.
	$response = Get-PaLogsFromJob -ID $ID -jobID $jobID

	if ($response.response.result.job.status -eq 'FIN')
	{	
		#If the job completed, format and  return the results.
		$logs = New-Object System.Collections.ArrayList
		foreach ($entry in $response.response.result.log.logs.entry)
		{
			$log = New-Object PSObject
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'SourceAddress' -Value $entry.src
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'DestinationAddress' -Value $entry.dst
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'SourceZone' -Value $entry.from
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'DestinationZone' -Value $entry.to
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Rule' -Value $entry.rule
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'NATSourceAddress' -Value $entry.natsrc
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'NATDestinationAddress' -Value $entry.natdst
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'SourcePort' -Value $entry.sport
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'DestinationPort' -Value $entry.dport
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'NATSourcePort' -Value $entry.natsport
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'NATDestinationPort' -Value $entry.natdport
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Protocol' -Value $entry.proto
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'TimeReceived' -Value $entry.'receive_time'
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'StartTime' -Value $entry.start
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'SessionEndReason' -Value $entry.'session_end_reason'
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'ElapsedTime' -Value $entry.elapsed
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'InboundInterface' -Value $entry.inbound_if
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'OutboundInterface' -Value $entry.outbound_if 
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Action' -Value $entry.action
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Application' -Value $entry.app
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'VSYS' -Value $entry.vsys
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'PacketsSent' -Value $entry.'pkts_sent'
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'PacketsReceived' -Value $entry.'pkts_received'
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'BytesSent' -Value $entry.'bytes_sent'
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'BytesReceived' -Value $entry.'bytes_received'
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Type' -Value $entry.type
			[void]$logs.add($log)
		}
		$logInfo = New-Object PSObject
		Add-Member -InputObject $logInfo -MemberType NoteProperty -Name 'Count' -Value $response.response.result.log.logs.count
		Add-Member -InputObject $logInfo -MemberType NoteProperty -Name 'Progress' -Value $response.response.result.log.logs.progress
		Add-Member -InputObject $logInfo -MemberType NoteProperty -Name 'Logs' -Value $logs
		if ($ReturnRawLogs)
		{
			Add-Member -InputObject $logInfo -MemberType NoteProperty -Name 'RawLogs' -Value $response.response.result.log.logs.entry
		}
		$jobInfo = New-Object PSObject
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'TimeEnqeued' -Value $response.response.result.job.tenq
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'TimeDequeued' -Value $response.response.result.job.tdeq
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'TimeLastRun' -Value $response.response.result.job.tlast
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'Status' -Value $response.response.result.job.status
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'Job' -Value $response.response.result.job.id
		$returnObject = New-Object PSObject
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Status' -Value $response.response.status
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Logs' -Value $logInfo
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Job' -Value $jobInfo
		return $returnObject
	}else
	{
		#If the job did not complete give back the raw response. (Will clean this up later, not sure how to make it error.) 
		return $response
	}
}

<#
.SYNOPSIS
Returns a list of Threat Logs from the firewall. Maximum of 5000 entries can be returned.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter Query
Optional:
A query you supply, in the format you would used for a query for threat logs in the web interface, to be used to filter log responses returned. If no query is specified the default query will only return logs from the last hour.
.Parameter NumberOfLogsToReturn
Optional:
Use this to specify how many log entries you want returned (Maximum of 5000).
.Paramter ReturnRawLogs
Optional:
Specify to have logs returned as an extra property in the output of this script. These logs will be output in the XML format they were recieved and not the standardized output this functions would normally return them in.
#>
Function Get-PaThreatLogs {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$query = ("(receive_time geq '" + (get-date (Get-Date).AddHours('-1') -Format 'yyyy/MM/dd HH:mm:ss') + "')"),# don't get an infinite number of logs, if the script is called without the query parameter only get the last hour.
    [Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$NumberOfLogsToReturn = 5000, #Defines how many logs to return. Max 5000
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][switch]$ReturnRawLogs = $false
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = Request-PaLogs -ID $ID -query $query -NumberOfLogsToReturn $NumberOfLogsToReturn -threat
	$jobID = $response.job
	sleep(1) # don't immediately poll for the results, chances are really good they aren't ready yet.
	$response = Get-PaLogsFromJob -ID $ID -jobID $jobID

	if ($response.response.result.job.status -eq 'FIN')
	{	
		#If the job completed return the results.
		$logs = New-Object System.Collections.ArrayList
		foreach ($entry in $response.response.result.log.logs.entry)
		{
			$log = New-Object PSObject
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'SourceAddress' -Value $entry.src
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'DestinationAddress' -Value $entry.dst
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'SourceZone' -Value $entry.from
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'DestinationZone' -Value $entry.to
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Rule' -Value $entry.rule
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'NATSourceAddress' -Value $entry.natsrc
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'NATDestinationAddress' -Value $entry.natdst
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'SourcePort' -Value $entry.sport
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'DestinationPort' -Value $entry.dport
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'NATSourcePort' -Value $entry.natsport
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'NATDestinationPort' -Value $entry.natdport
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Protocol' -Value $entry.proto
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'TimeReceived' -Value $entry.'receive_time'
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'StartTime' -Value $entry.start
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'ThreatID' -Value $entry.threatid
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Direction' -Value $entry.direction
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'InboundInterface' -Value $entry.inbound_if
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'OutboundInterface' -Value $entry.outbound_if 
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Action' -Value $entry.action
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Application' -Value $entry.app
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'VSYS' -Value $entry.vsys
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'ThreatCategory' -Value $entry.'thr_category'
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Misc' -Value $entry.misc
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Subtype' -Value $entry.subtype
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Type' -Value $entry.type
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Severity' -Value $entry.severity
			[void]$logs.add($log)
		}
		$logInfo = New-Object PSObject
		Add-Member -InputObject $logInfo -MemberType NoteProperty -Name 'Count' -Value $response.response.result.log.logs.count
		Add-Member -InputObject $logInfo -MemberType NoteProperty -Name 'Progress' -Value $response.response.result.log.logs.progress
		Add-Member -InputObject $logInfo -MemberType NoteProperty -Name 'Logs' -Value $logs
		if ($ReturnRawLogs)
		{
			Add-Member -InputObject $logInfo -MemberType NoteProperty -Name 'RawLogs' -Value $response.response.result.log.logs.entry
		}
		$jobInfo = New-Object PSObject
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'TimeEnqeued' -Value $response.response.result.job.tenq
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'TimeDequeued' -Value $response.response.result.job.tdeq
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'TimeLastRun' -Value $response.response.result.job.tlast
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'Status' -Value $response.response.result.job.status
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'Job' -Value $response.response.result.job.id
		$returnObject = New-Object PSObject
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Status' -Value $response.response.status
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Logs' -Value $logInfo
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Job' -Value $jobInfo
		return $returnObject
	}else
	{
		#If the job did not complete give back the raw response. (Will clean this up later, not sure how to make it error.) 
		return $response
	}
}

<#
.SYNOPSIS
Returns a list of URL Logs from the firewall. Maximum of 5000 entries can be returned.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter Query
Optional:
A query you supply, in the format you would used for a query for URL logs in the web interface, to be used to filter log responses returned. If no query is specified the default query will only return logs from the last hour.
.Parameter NumberOfLogsToReturn
Optional:
Use this to specify how many log entries you want returned (Maximum of 5000).
.Paramter ReturnRawLogs
Optional:
Specify to have logs returned as an extra property in the output of this script. These logs will be output in the XML format they were recieved and not the standardized output this functions would normally return them in.
#>
Function Get-PaURLLogs {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$query = ("(receive_time geq '" + (get-date (Get-Date).AddHours('-1') -Format 'yyyy/MM/dd HH:mm:ss') + "')"),# don't get an infinite number of logs, if the script is called without the query parameter only get the last hour.
    [Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$NumberOfLogsToReturn = 5000, #Defines how many logs to return. Max 5000
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][switch]$ReturnRawLogs = $false
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = Request-PaLogs -ID $ID -query $query -NumberOfLogsToReturn $NumberOfLogsToReturn -url
	$jobID = $response.job
	sleep(1) # don't immediately poll for the results, chances are really good they aren't ready yet.
	$response = Get-PaLogsFromJob -ID $ID -jobID $jobID

	if ($response.response.result.job.status -eq 'FIN')
	{	
		#If the job completed return the results.
		$logs = New-Object System.Collections.ArrayList
		foreach ($entry in $response.response.result.log.logs.entry)
		{
			$log = New-Object PSObject
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'SourceAddress' -Value $entry.src
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'DestinationAddress' -Value $entry.dst
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'SourceZone' -Value $entry.from
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'DestinationZone' -Value $entry.to
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Rule' -Value $entry.rule
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'NATSourceAddress' -Value $entry.natsrc
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'NATDestinationAddress' -Value $entry.natdst
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'SourcePort' -Value $entry.sport
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'DestinationPort' -Value $entry.dport
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'NATSourcePort' -Value $entry.natsport
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'NATDestinationPort' -Value $entry.natdport
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'protocol' -Value $entry.proto
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'TimeReceived' -Value $entry.'time_received'
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'StartTime' -Value $entry.start
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'SessionEndReason' -Value $entry.'session_end_reason'
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'InboundInterface' -Value $entry.inbound_if
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'OutboundInterface' -Value $entry.outbound_if 
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Action' -Value $entry.action
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Application' -Value $entry.app
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'VSYS' -Value $entry.vsys
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Category' -Value $entry.category
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'URL' -Value $entry.misc
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Type' -Value $entry.type
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Severity' -Value $entry.severity
			Add-Member -InputObject $log -MemberType NoteProperty -Name 'Subtype' -Value $entry.subtype
			[void]$logs.add($log)
		}
		$logInfo = New-Object PSObject
		Add-Member -InputObject $logInfo -MemberType NoteProperty -Name 'Count' -Value $response.response.result.log.logs.count
		Add-Member -InputObject $logInfo -MemberType NoteProperty -Name 'Progress' -Value $response.response.result.log.logs.progress
		Add-Member -InputObject $logInfo -MemberType NoteProperty -Name 'Logs' -Value $logs
		if ($ReturnRawLogs)
		{
			Add-Member -InputObject $logInfo -MemberType NoteProperty -Name 'RawLogs' -Value $response.response.result.log.logs.entry
		}
		$jobInfo = New-Object PSObject
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'TimeEnqeued' -Value $response.response.result.job.tenq
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'TimeDequeued' -Value $response.response.result.job.tdeq
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'TimeLastRun' -Value $response.response.result.job.tlast
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'Status' -Value $response.response.result.job.status
		Add-Member -InputObject $jobInfo -MemberType NoteProperty -Name 'Job' -Value $response.response.result.job.id
		$returnObject = New-Object PSObject
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Status' -Value $response.response.status
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Logs' -Value $logInfo
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Job' -Value $jobInfo
		return $returnObject
	}else
	{
		#If the job did not complete give back the raw response. (Will clean this up later, not sure how to make it error.) 
		return $response
	}
}

<#
.SYNOPSIS
Retrieves a list of users and their IP mappings the firewall is aware of.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
#>
Function Show-PaUserIDMapping {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}

	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><user><ip-user-mapping-mp><all></all></ip-user-mapping-mp></user></show>&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	$results = New-Object System.Collections.ArrayList
	foreach ($entry in $response.response.result.entry)
	{
		$userIDMapping = New-Object PSObject
		Add-Member -InputObject $userIDMapping -MemberType NoteProperty -Name 'User' -Value $entry.user
		Add-Member -InputObject $userIDMapping -MemberType NoteProperty -Name 'IPAddress' -Value $entry.ip
		Add-Member -InputObject $userIDMapping -MemberType NoteProperty -Name 'Vsys' -Value $entry.vsys
		Add-Member -InputObject $userIDMapping -MemberType NoteProperty -Name 'Type' -Value $entry.type
		Add-Member -InputObject $userIDMapping -MemberType NoteProperty -Name 'Timeout' -Value $entry.timeout

		[void]$results.add($userIDMapping)
	}
	return $results
}

<#
.SYNOPSIS
Retrieves the candidate configuration for virtual routers configured oin the Palo Alto.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
#>
Function Get-PaVirtualRouters {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/network/virtual-router&key=" + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	return $response.response.result.'virtual-router'.entry
}

 <#
.SYNOPSIS
This function returns the High Availability status of the firewall.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
#>
Function Show-PaHAStatus
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$ReturnRawData=$false
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$returnObject = New-Object psobject
	$haStatusResponse = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><high-availability><state></state></high-availability></show>&key=" + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($haStatusResponse) #This function checks for an error from the firewall and throws it if there is one.
	if ($ReturnRawData)
	{
		return $haStatusResponse
	}
	if (($haStatusResponse.response.result.enabled).tolower() -eq 'no')
	{
		#If HA is disabled then there is no more information to collect. Add the member to the returnObject and return it.
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name HAEnabled -Value $false
		return $returnObject
	}
	elseif (($haStatusResponse.response.result.enabled).tolower() -eq 'yes')
	{
		#If HA is enabled Add the member to the returnObject and continue on.
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name HAEnabled -Value $true
	}
	else
	{
		#If we got here then I'm not sure what state HA would be in. Throw an error with the HA state.
		throw('Recieved an unknown HA state. The HA state was: ' + $haStatusResponse.response.result.enabled)
	}
	Add-Member -InputObject $returnObject -MemberType NoteProperty -Name HAMode -Value $haStatusResponse.response.result.group.mode
	Add-Member -InputObject $returnObject -MemberType NoteProperty -Name HALocalState -Value $haStatusResponse.response.result.group.'local-info'.state
	Add-Member -InputObject $returnObject -MemberType NoteProperty -Name HAPeerState -Value $haStatusResponse.response.result.group.'peer-info'.state
	if (($haStatusResponse.response.result.group.'local-info'.preemptive).tolower() -eq 'no')
	{
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name HALocalPreemptt -Value $false
	}
	else
	{
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name HALocalPreempt -Value $true
	}
	if (($haStatusResponse.response.result.group.'peer-info'.preemptive).tolower() -eq 'no')
	{
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name HAPeerPreempt -Value $false
	}
	else
	{
		Add-Member -InputObject $returnObject -MemberType NoteProperty -Name HAPeerPreempt -Value $true
	}
	Add-Member -InputObject $returnObject -MemberType NoteProperty -Name HALocalStateSync -Value $haStatusResponse.response.result.group.'local-info'.'state-sync' #This variable tells us if all of the syncing is occring correctly. If it is the value will be 'Complete'
	return $returnObject
}

<#
.SYNOPSIS
This command displays the Geo location of the specified IP address.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter IP
Required.
Specifies the IP address to look up the location of.
#>
Function Show-PaGeoIpLocation {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][Switch]$IP
    )
	#This function has only been tested on PANOS8.1 6-6-18
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$returnObject = New-Object psobject
	$paResponse = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<show><location><ip>" + $IP + "</ip></location></show>&key=" + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($paResponse) #This function checks for an error from the firewall and throws it if there is one.

	Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'CountryCode' -Value $paResponse.response.result.entry.cc
	Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'IP' -Value $paResponse.response.result.entry.ip
	Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'CountryName' -Value $paResponse.response.result.entry.country

	return $returnObject
}
#####################################################################################################################################################################
#Below this line are functions that change PA functionality. Above this line are functions that get information.
#####################################################################################################################################################################
<#
.SYNOPSIS
This command rolls the firewall back to the previously installed application/threat content package.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
#>
Function Set-PaPreviousContentPackage {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<request><content><downgrade><install>previous</install></downgrade></content></request>&key=" + (GetPaAPIKeyClearText)))
    Write-Host 'The command was sent, the result was:'
    ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	$response.response.msg.line
	Remove-Variable -Name paInfo
}

<#
.SYNOPSIS
All changes are based on the candidate configuration.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

.PARAMETER 
	
.PARAMETER 
	


#>
#I've commented this out for now as I'm not sure it is 100% working anymore and it really should be re-written.
Function UpdatePaSecurityRule {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$RuleName,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Application,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Service,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SourceAddress,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DestinationAddress,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SourceZone,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DestinationZone,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$User,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$HIPProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Description,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Action,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$IPSGroup,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$IPSProfiles,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$NoIPS,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$URLFilteringIPSProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$FileBlockingIPSProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$VirusIPSProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SpywareIPSProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$VulnerabilityIPSProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$WildfireIPSProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DataFilteringIPSProfile
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	if (!$RuleName)
	{
		throw  'You must specify a rule name to edit.'
	}elseif ((!$Application -and !$Service -and !$SourceAddress -and !$DestinationAddress -and !$User -and !$HIPProfile -and !$SourceZone -and !$DestinationZone -and !$IPSProfiles -and !$IPSGroup -and !$Action -and !$Description -and !$NoIPS))
	{
		throw  "You must specify an attribute to edit."
	}elseif ($IPSGroup -and $IPSProfiles)
	{
		throw  "You cannot specify an IPS group and individual IPS profiles at the same time."
	}elseif (($IPSGroup -and $NoIPS) -or ($IPSProfiles -and $NoIPS))
	{
		throw  "You cannot specify to remove the IPS function and then enable it at the same time."
	}
	#get the configuration for the rule to edit.
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $RuleName + "']&key="  + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	$rule = $result.response.result
	Remove-Variable -Name result
	#The following if's check to see which fields in the rule need updating.
	if ($SourceZone)
	{
		($rule.entry.from).InnerXml = TurnCSVListIntoXMLString -xmlNodes "member" -list $SourceZone
	}
	if ($DestinationZone)
	{
		($rule.entry.to).InnerXml = TurnCSVListIntoXMLString -xmlNodes "member" -list $DestinationZone
	}
	if ($SourceAddress)
	{
		($rule.entry.source).InnerXml = TurnCSVListIntoXMLString -xmlNodes "member" -list $SourceAddress
	}
	if ($DestinationAddress)
	{
		($rule.entry.destination).InnerXml = TurnCSVListIntoXMLString -xmlNodes "member" -list $DestinationAddress
	}
	if ($User)
	{
		($rule.entry.'source-user').InnerXml = TurnCSVListIntoXMLString -xmlNodes "member" -list $User
	}
	if ($UrlCategory)
	{
		($rule.entry.category).InnerXml = TurnCSVListIntoXMLString -xmlNodes "member" -list $UrlCategory
	}
	if ($Application)
	{
		($rule.entry.application).InnerXml = TurnCSVListIntoXMLString -xmlNodes "member" -list $Application
	}
	if ($Service)
	{
		($rule.entry.service).InnerXml = TurnCSVListIntoXMLString -xmlNodes "member" -list $Service
	}
	if ($Action)
	{
		#Set the rule action.
		$rule.entry.action = $Action
	}
	if ($Description)
	{
		if ($Description -eq 'none')
		{
			#Get the XML node to delete. It must be done this way, not sure why. Use the X-Path syntax to pick the node.
			$node = $rule.entry.SelectSingleNode('//description')
			#Remove the child node.
			($rule.entry).RemoveChild($node)
		}else
		{
			#Set the rule description.
			$rule.entry.description = $Description
		}
	}
	if ($IPSGroup)
	{
		#Check if an IPS setting already exists. If it does, delete it.
		if ($rule.entry.'profile-setting')
		{
			#Get the XML node to delete. It must be done this way, not sure why. Use the X-Path syntax to pick the node.
			$node = $rule.entry.SelectSingleNode('//profile-setting')
			#Remove the child node.
			($rule.entry).RemoveChild($node)
		}
			#Set the IPS group.
			($rule.entry).InnerXML += TurnCSVListIntoXMLString -xmlNodes 'profile-setting,group,member' -list $IPSGroup
	}
	if ($IPSProfiles)
	{
		if (!$URLFilteringIPSProfile -and !$FileBlockingIPSProfile -and !$VirusIPSProfile -and !$SpywareIPSProfile -and !$VulnerabilityIPSProfile -and !$WildfireIPSProfile -and !$DataFilteringIPSProfile)
		{
			Write-Host "The script was requested to configure IPS profiles but there were no profiles specified."
		}else
		{
			#Check if an IPS setting already exists. If it does, delete it.
			if ($rule.entry.'profile-setting')
			{
				#Get the XML node to delete. It must be done this way, not sure why. Use the X-Path syntax to pick the node.
				$node = $rule.entry.SelectSingleNode('//profile-setting')
				#Remove the child node.
				($rule.entry).RemoveChild($node)
			}
			$xmlString = '<profile-setting><profiles>'
			if ($URLFilteringIPSProfile)
			{
				$xmlString += TurnCSVListIntoXMLString -xmlNodes "url-filtering,member" -list $URLFilteringIPSProfile
			}
			if ($FileBlockingIPSProfile)
			{
				$xmlString += TurnCSVListIntoXMLString -xmlNodes "file-blocking,member" -list $FileBlockingIPSProfile
			}
			if ($VirusIPSProfile)
			{
				$xmlString += TurnCSVListIntoXMLString -xmlNodes "virus,member" -list $VirusIPSProfile
			}
			if ($SpywareIPSProfile)
			{
				$xmlString += TurnCSVListIntoXMLString -xmlNodes "spyware,member" -list $SpywareIPSProfile
			}
			if ($VulnerabilityIPSProfile)
			{
				$xmlString += TurnCSVListIntoXMLString -xmlNodes "vulnerability,member" -list $VulnerabilityIPSProfile
			}
			if ($WildfireIPSProfile)
			{
				$xmlString += TurnCSVListIntoXMLString -xmlNodes "wildfire-analysis,member" -list $WildfireIPSProfile
			}
			if ($DataFilteringIPSProfile)
			{
				$xmlString += TurnCSVListIntoXMLString -xmlNodes "data-filtering,member" -list $DataFilteringIPSProfile
			}
			$xmlString += '</profiles></profile-setting>'
			($rule.entry).InnerXML += $xmlString
		}
	}

	if ($NoIPS)
	{
		#Get the XML node to delete. It must be done this way, not sure why. Use the X-Path syntax to pick the node.
		$node = $rule.entry.SelectSingleNode('//profile-setting')
		#Remove the child node.
		($rule.entry).RemoveChild($node)
	}

	#Once all of the edits to the XML object have been made send the change to the firewall.
	$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=edit&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $RuleName + "']&element=" + $rule.InnerXml + "&key="  + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.

	Write-Host "The rule was modified successfully."
	Remove-Variable -Name rule
	Remove-Variable -Name response
	if ($xmlString)
	{
		Remove-Variable -Name xmlString
	}
	if ($entry)
	{
		Remove-Variable -Name entry
	}	
}


<#
.SYNOPSIS
Adds the specified security rule to the firewall.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter RuleName
Required.
The name of the rule you wish to add.
.Parameter Application
Required.
Specify the applications to allow. This can be a single application, a comma seperated list of applications, or the work 'any' for all applications.
.Parameter Service
Required.
Specify the service object(s) or service group(s) for this rule. To match multiple services use a comma seperated list of service objects and service groups. To match any service you may use the word 'any'.
.Parameter SourceAddress
Required.
Specify the source address for this rule. To allow multiple source addresses use a comma seperated list of addresses and/or address/netmask entries. To match any source address you may use the word 'any'.
.Parameter DestinationAddress
Required.
Specify the destination address for this rule. To allow multiple destination addresses use a comma seperated list of addresses and/or address/netmask entries. To match any destination address you may use the word 'any'.
.Parameter SourceZone
Required.
Specify the source zone for this rule. To allow multiple source zones use a comma seperated list of zone names. To match any source zone you may use the word 'any'.
.Parameter DestinationZone
Required.
Specify the destination zone for this rule. To allow multiple destination zones use a comma seperated list of zone names. To match any destination zone you may use the word 'any'.
.Parameter NegateSourceAddress
Optional.
Specify this switch to make this rule match traffic sourced from addresses that were not specified in the SourceAddress parameter.
.Parameter NegateDestinationAddress
Specify this switch to make this rule match traffic destined to addresses that were not specified in the DestinationAddress parameter.
.Parameter User
Optional.
Specify a source user or comma seperated list of users for this rule to match.
.Parameter Description
Optional.
Specify a description for this rule.
.Parameter Action
Required.
Specify the action to be applied for traffic that matches this rule. examples of some actions are: "allow" , "deny", and "drop". The supported actions depend on your PANOS version.
.Parameter IPSGroup
Optional.
Specifies the IPS (Security Profile Group) group that will be applied for this rule
.Parameter NoIPS
Optional.
Specifies that you no IPS profiles of IPS groups (Securit Profiles or Security Groups) will be applied to the rule.
.Parameter IPSProfiles
Optional.
Specifies that you will use at least one of the IPSProfile arguments to specify at least one IPS Profile (Security Profile) to be applied to this rule.
.Parameter URLFilteringIPSProfile
Optional.
Specifies the URL Filtering IPS Profile (Security Profile) to be applied to this rule. This must be used with the -IPSProfiles switch.
.Parameter FileBlockingIPSProfile
Optional.
Specifies the FileBlocking IPS Profile (Security Profile) to be applied to this rule. This must be used with the -IPSProfiles switch.
.Parameter VirusIPSProfile
Optional.
Specifies the Virus IPS Profile (Security Profile) to be applied to this rule. This must be used with the -IPSProfiles switch.
.Parameter SpywareIPSProfile
Optional.
Specifies the Spyware IPS Profile (Security Profile) to be applied to this rule. This must be used with the -IPSProfiles switch.
.Parameter VulnerabilityIPSProfile
Optional.
Specifies the Vulnerability IPS Profile (Security Profile) to be applied to this rule. This must be used with the -IPSProfiles switch.
.Parameter WildfireIPSProfile
Optional.
Specifies the URL Filtering IPS Profile (Security Profile) to be applied to this rule. This must be used with the -IPSProfiles switch.
.Parameter DataFilteringIPSProfile
Optional.
Specifies the Data Filtering IPS Profile (Security Profile) to be applied to this rule. This must be used with the -IPSProfiles switch.
#>
Function Add-PaSecurityRule {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$RuleName,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Application,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Service,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SourceAddress,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DestinationAddress,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$NegateSourceAddress,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$NegateDestinationAddress,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SourceZone,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DestinationZone,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$User,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$HIPProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Description,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Action,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$IPSGroup,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$IPSProfiles,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$NoIPS,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$URLFilteringIPSProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$FileBlockingIPSProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$VirusIPSProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SpywareIPSProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$VulnerabilityIPSProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$WildfireIPSProfile,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DataFilteringIPSProfile
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Do some sanity checks before calling the firewall.
	if (!$RuleName)
	{
		throw 'You must specify a rule name to create. The rule was not added.'
	}
	elseif ((!$Application -and !$Service -and !$SourceAddress -and !$DestinationAddress -and !$User -and !$HIPProfile -and !$SourceZone -and !$DestinationZone -and !$IPSProfiles -and !$IPSGroup -and !$Action -and !$Description -and !$NoIPS))
	{
		throw "You must specify at least one attribute to add the rule. The rule was not added."
	}
	elseif ($IPSGroup -and $IPSProfiles)
	{
		throw "You cannot specify an IPS group and individual IPS profiles at the same time. The rule was not added."
	}
	elseif (($IPSGroup -and $NoIPS) -or ($IPSProfiles -and $NoIPS))
	{
		throw "You cannot specify to have no IPS function and then to use the IPS at the same time. The rule was not added."
	}
	elseif (!$SourceAddress -or !$SourceZone -or !$DestinationAddress -or !$DestinationZone)
	{
		throw "You must specify a source address and zone and a destination address and zone. The rule was not added."
	}
	elseif (!$Application -or !$Service)
	{
		throw "You must specify and Application and a Service. The rule was not added."
	}
	elseif (!$IPSGroup -and !$IPSProfiles -and !$NoIPS)
	{
		throw 'You must specify an IPSgroup, IPSProfiles, or the NoIPS flag. The rule was not added.'
	}
	elseif ($IPSProfiles -and (!$URLFilteringIPSProfile -and !$FileBlockingIPSProfile -and !$VirusIPSProfile -and !$SpywareIPSProfile -and !$VulnerabilityIPSProfile -and !$WildfireIPSProfile -and !$DataFilteringIPSProfile))
	{
		#Let the user know this and then don't do anything.
		throw "The script was requested to configure IPS profiles but there were no profiles specified. The rule was not added."
	}
	elseif(!$IPSProfiles -and ($URLFilteringIPSProfile -or $FileBlockingIPSProfile -or $VirusIPSProfile -or $SpywareIPSProfile -or $VulnerabilityIPSProfile -or $WildfireIPSProfile -or $DataFilteringIPSProfile))
	{
		throw 'You must use the -IPSProfiles switch when specifying an IPS profile to use for the rule.'
	}
	elseif (!$Action)
	{
		throw "You must specify an action (allow,deny,drop, etc...)for this rule. The rule was not added."
	}
	#Check if a rule by this name already exists. We have to do this because the firewall will update an existing rule by the same name even when using the set command instead of edit.
	#This is undesireable because a user likely won't want to modify an existing rule if they are calling the add function of this script.
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $RuleName + "']&key="  + (GetPaAPIKeyClearText)))
	if ($result.response.result)
	{
		throw 'A rule by this name already exists. Please specify another name to add a rule or use the "Update-PaSecurityRule" function to modify an existing rule.'
	}
	#Build the rule configuration.
	$xmlString = '' #Set this to empty to ensure we start the build clean.
	#Set negate source if specified.
	if ($NegateSourceAddress)
	{
		$xmlString += TurnCSVListIntoXMLString -xmlNodes "negate-source" -list 'yes'
	}
	#Set negate destination if specified.
	if ($NegateDestinationAddress)
	{
		$xmlString += TurnCSVListIntoXMLString -xmlNodes "negate-destination" -list 'yes'
	}
	#Build the source zone config.
	$xmlString += '<from>'
	$xmlString += TurnCSVListIntoXMLString -xmlNodes "member" -list $SourceZone
	$xmlString += '</from>'
	#Build the Destination zone config.
	$xmlString += '<to>'
	$xmlString += TurnCSVListIntoXMLString -xmlNodes "member" -list $DestinationZone
	$xmlString += '</to>'
	#Build the Source address config.
	$xmlString += '<source>'
	$xmlString += TurnCSVListIntoXMLString -xmlNodes "member" -list $SourceAddress
	$xmlString += '</source>'
	#Build the Destination address config.
	$xmlString += '<destination>'
	$xmlString += TurnCSVListIntoXMLString -xmlNodes "member" -list $DestinationAddress
	$xmlString += '</destination>'
	#Build the user config. If none is specified leave it out.
	if ($User)
	{
		$xmlString += '<source-user>'
		$xmlString += TurnCSVListIntoXMLString -xmlNodes "member" -list $User
		$xmlString += '</source-user>'
	}
	#Build the URL category config.
	$xmlString += '<category>'
	if ($UrlCategory)
	{
		$xmlString += TurnCSVListIntoXMLString -xmlNodes "member" -list $UrlCategory
	}else
	{
		$xmlString += TurnCSVListIntoXMLString -xmlNodes "member" -list 'any'
	}
	$xmlString += '</category>'
	#Build the Application config.
	$xmlString += '<application>'
	$xmlString += TurnCSVListIntoXMLString -xmlNodes "member" -list $Application
	$xmlString += '</application>'
	#Build the Service (ports) config.
	$xmlString += '<service>'
	$xmlString += TurnCSVListIntoXMLString -xmlNodes "member" -list $Service
	$xmlString += '</service>'
	#Build the rule Action.
	$xmlString += TurnCSVListIntoXMLString -xmlNodes "action" -list $Action
	#Build the rule description, leave empty if not specified.
	if ($Description)
	{
		#Set the rule description.
		$xmlString += TurnCSVListIntoXMLString -xmlNodes "description" -list $Description
	}
	#Build the IPS configuration. If non is specified then don't create any XML.
	if ($IPSGroup)
	{
			$xmlString += TurnCSVListIntoXMLString -xmlNodes "profile-settinggroupmember" -list $IPSGroup
	}
	if ($IPSProfiles)
	{
		$xmlString += '<profile-setting><profiles>'
		if ($URLFilteringIPSProfile)
		{
			$xmlString += TurnCSVListIntoXMLString -xmlNodes "url-filtering,member" -list $URLFilteringIPSProfile
		}
		if ($FileBlockingIPSProfile)
		{
			$xmlString += TurnCSVListIntoXMLString -xmlNodes "file-blocking,member" -list $FileBlockingIPSProfile
		}
		if ($VirusIPSProfile)
		{
			$xmlString += TurnCSVListIntoXMLString -xmlNodes "virus,member" -list $VirusIPSProfile
		}
		if ($SpywareIPSProfile)
		{
			$xmlString += TurnCSVListIntoXMLString -xmlNodes "spyware,member" -list $SpywareIPSProfile
		}
		if ($VulnerabilityIPSProfile)
		{
			$xmlString += TurnCSVListIntoXMLString -xmlNodes "vulnerability,member" -list $VulnerabilityIPSProfile
		}
		if ($WildfireIPSProfile)
		{
			$xmlString += TurnCSVListIntoXMLString -xmlNodes "wildfire-analysis,member" -list $WildfireIPSProfile
		}
		if ($DataFilteringIPSProfile)
		{
			$xmlString += TurnCSVListIntoXMLString -xmlNodes "data-filtering,member" -list $DataFilteringIPSProfile
		}
		$xmlString += '</profiles></profile-setting>'
	}
	if ($NoIPS)
	{
		#Do nothing. This flag only exists since I largely copied this from the edit function. I may remove it later.
	}
	#Once all of the all of the configuration has been built send the new rule to the firewall.
	$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $RuleName + "']&element=" + $xmlString + "&key="  + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The rule was added successfully."
	Remove-Variable -Name response
	if ($xmlString)
	{
		Remove-Variable -Name xmlString
	}
	if ($entry)
	{
		Remove-Variable -Name entry
	}
}

<#
.SYNOPSIS
Remove the specified security rule from the candidate configuration.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter RuleName
Required.
The name of the Security rule to remove.
#>
Function Remove-PaSecurityRule {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$RuleName
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $RuleName + "']&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.

	Write-Host "The rule was removed successfully."
	Remove-Variable -Name response
	
}

<#
.SYNOPSIS
#All changes are based on the candidate configuration.
.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
<#Function Update-PaPolicyRoutingRule {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$RuleName,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Application,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Service,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SourceAddress,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DestinationAddress,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SourceZone,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DestinationZone,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SourceUser,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$HIPProfile,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Description,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Action,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$EnforceSymmetricReturn,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$NoSymmetricReturn,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$NextHopAddress,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$MonitorAddress
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$FileBlockingIPSProfile,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$VirusIPSProfile,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SpywareIPSProfile,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$VulnerabilityIPSProfile,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$WildfireIPSProfile,
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DataFilteringIPSProfile
    )
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	if (!$RuleName)
	{
		throw  'You must specify a rule name to edit.'
	}
	#get the configuration for the rule to edit.
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/pbf/rules/entry[@name='" + $RuleName + "']&key="  + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	#return $result
	$rule = $result.response.result.entry
	return $rule
	Remove-Variable -Name result

	$xmlstring = ''
	if ($EnforceSymmetricReturn)
	{
		$xmlstring += '	<enabled>yes</enabled>'
		$rule.'enforce-symmetric-return'.InnerXml = $xmlstring
	}
	if ($NoSymmetricReturn)
	{
		$xmlstring += '<enabled>no</enabled>'
		$rule.'enforce-symmetric-return'.InnerXml = $xmlstring
	}
	$xmlstring = ''

	if ($MonitorAddress)
	{
		$rule.action.forward.monitor.'ip-address'.InnerXml = $MonitorAddress
	}
	if ($NextHopAddress)
	{
		if (!$rule.action.forward.nexthop)
		{
			$xmlstring = ('<nexthop><ip-address>' + $NextHopAddress + '</ip-address></nexthop>')
			$rule.action.forward.InnerXml += $xmlstring
		}
		else
		{
			$rule.action.forward.nexthop.'ip-address'.InnerXml = $NextHopAddress
		}
	}
	return $rule
	#Once all of the edits to the XML object have been made send the change to the firewall.
	$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=edit&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/pbf/rules/entry[@name='" + $RuleName + "']&element=" + $rule.InnerXml + "&key="  + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The rule was modified successfully."
}#>
<#
.SYNOPSIS
Reboot the specified firewall.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter Force
Optional.
USE THIS PARAMETER WITH EXTREME CAUTION! Specify this parameter to bypass the prompt for the user to confirm the reboot. 
#>
function Reboot-PaloAlto
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$Force
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	if (!$Force)
	{
		Write-Output ('This command will reboot the firewall "' + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + '". Are you sure you wish to continue? Enter Y or Yes for yes.')
		$input = Read-Host
		if (!([string]$input.ToLower() -eq 'y' -or [string]$input.ToLower() -eq 'yes'))
		{
			throw 'The user did not confirm the firewall reboot request.'
		}
	}
	#Reboot the firewwall.
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<request><restart><system></system></restart></request>&key=" + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	Write-Output "Reboot command was sent successfully."	
}

<#
.SYNOPSIS
Commit pending changes on the firewall.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter Force
Optional.
USE THIS PARAMETER WITH EXTREME CAUTION! Specify this parameter to bypass the prompt for the user to confirm the commit. 
#>
function Commit-PaloAltoConfiguration
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$Force
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	if (!$Force)
	{
		Write-Output ('This command will commit pending changes to the running configuration on "' + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + '". Are you sure you wish to continue? Enter Y or Yes for yes.')
		$input = Read-Host
		if (!([string]$input.ToLower() -eq 'y' -or [string]$input.ToLower() -eq 'yes'))
		{
			throw 'The user did not confirm the commit request.'
		}
	}
	#Commit the configuration.
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=commit&cmd=<commit></commit>&key=" + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	$output = New-Object psobject
	Add-Member -InputObject $output -MemberType NoteProperty -Name JobID -Value $result.response.result.job
	Add-Member -InputObject $output -MemberType NoteProperty -Name Message -Value $result.response.result.msg.Line
	Add-Member -InputObject $output -MemberType NoteProperty -Name Status -Value $result.response.status
	Add-Member -InputObject $output -MemberType NoteProperty -Name Code -Value $result.response.code
	return $output
}

<#
.SYNOPSIS
This code is no longer needed. It was buggy and has been replaced by the function Move-PaSecurityRule. Leaving it for now for code reference.
.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
<#Function Sort-PaSecurityRules
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][string]$SortList #passing this a comma seperate string will work. If you have an array use this to send the data: ($array -join ',')
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$paConfig = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules&key=" + (GetPaAPIKeyClearText)) 
	$oldSecurityRules = $paConfig.response.result.rules.entry
	Remove-Variable -Name paConfig
	#$oldSecurityRules = getpaSecurityRules #I'd like to use the existing function if possible but it may never be.
	$sorted = ($oldSecurityRules | sort -Property @{Expression={$SortList.IndexOf(($_.name))}; Ascending = $true})
	#Delete all rules but don't delete the security rulebase.
	foreach ($rule in $oldSecurityRules)
	{
		$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $rule.name + "']" + "&key="  + (GetPaAPIKeyClearText)))
	}
	#Add the rules.
	foreach ($rule in $sorted)
	{
		$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $rule.name + "']&element=" + $rule.InnerXml + "&key="  + (GetPaAPIKeyClearText)))
	}
	Remove-Variable -Name oldSecurityRules
	Remove-Variable -Name sorted
	Remove-Variable -Name rule
	Remove-Variable -Name response
	Remove-Variable -Name SortList
	
}#>

<#
.SYNOPSIS
Move the specified security rule up or down in the rule list.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter RuleToMove
Required.
The rule that you wish to move.
.Parameter MoveToTop
Optional.
Move the rule to the top of the rule list.
.Parameter MoveToBottom
Optional.
Move the rule to the bottom of the rule list.
.Parameter MoveAfterRule
Optional.
Use this parameter to specify the rule name to move the "RuleToMove" below.
.Parameter MoveBeforeRule
Optional.
Use this parameter to specify the rule name to move the "RuleToMove" above.
#>
Function Move-PaSecurityRule
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][string]$RuleToMove,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][switch]$MoveToTop,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][switch]$MoveToBottom,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][string]$MoveAfterRule,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][string]$MoveBeforeRule
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	if (($MoveToTop -and $MoveToBottom) -or ($MoveToTop -and $MoveAfterRule) -or ($MoveToTop -and $MoveBeforeRule) -or ($MoveToBottom -and $MoveAfterRule) -or ($MoveToBottom -and $MoveBeforeRule) -or ($MoveAfterRule -and $MoveBeforeRule))
	{
		throw "You may only chose one action to do to a rule."
	}
	if ($MoveToTop)
	{
		$result = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=move&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $RuleToMove + "']&where=top&key=" + (GetPaAPIKeyClearText)) 
	}
	elseif($MoveToBottom)
	{
		$result = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=move&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $RuleToMove + "']&where=bottom&key=" + (GetPaAPIKeyClearText)) 
	}
	elseif($MoveAfterRule)
	{
		$result = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=move&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $RuleToMove + "']&where=after&dst=" + $MoveAfterRule + "&key=" + (GetPaAPIKeyClearText)) 
	}
	elseif($MoveBeforeRule)
	{
		$result = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=move&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $RuleToMove + "']&where=before&dst=" + $MoveBeforeRule + "&key=" + (GetPaAPIKeyClearText)) 
	}
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	#return $result.response	
	#Return nothing if successfull.
}

<#
.SYNOPSIS

.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

.PARAMETER 
	
.PARAMETER 
	


#>
Function RenamePaSecurityRule #This function needs re-written, it relies on a deprecated and buggy old function. Need to find a better way to rename the rule.
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$RuleName,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$NewRuleName
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Get the current list of security rules
	$paConfig = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules&key=" + (GetPaAPIKeyClearText)) 
	#Get only the security rules from the output.
	$oldSecurityRules = $paConfig.response.result.rules.entry
	#Remove the larger result variable that we no longer need.
	Remove-Variable -Name paConfig
	#Put the rule names in an array
	$ruleNames = $oldSecurityRules.name
	#Remove the now unneeded variable.
	Remove-Variable -Name oldSecurityRules
	#Get the index number in the array of the rule to be renamed.
	$ruleIndex = $ruleNames.IndexOf($RuleName)
	#Rename the rule in the array.
	$ruleNames[$ruleIndex] = $NewRuleName
	#Get the current rule configuration.
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $RuleName + "']&key="  + (GetPaAPIKeyClearText)))
	$rule = $result.response.result.entry
	Remove-Variable -Name result
	#Remove the existing rule.
	Remove-PaSecurityRule -ID $ID -RuleName $RuleName
	#Add the new rule with the same configuration.
	$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/security/rules/entry[@name='" + $NewRuleName + "']&element=" + $rule.InnerXml + "&key="  + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.

	Write-Host "The rule was added successfully."
	#Sort the Rules.
	Sort-PaSecurityRules -ID $ID -SortList ($ruleNames -join ',')
	Remove-Variable -Name rule
	Remove-Variable -Name response
	Remove-Variable -Name ruleNames
	Remove-Variable -Name RuleName
	Remove-Variable -Name NewRuleName
	
}


<#
.SYNOPSIS
Add the specified NAT rule.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter RuleName
Required.
The name of the rule you wish to add.
.Parameter BiDirectional
Optional.
Specify this switch if the rule should be bi-directional.
.Parameter Service
Required.
Specify the service object or service group for this rule. To match any service you may use the word 'any'.
.Parameter SourceAddress
Required.
Specify the source address for this rule. To match any source address you may use the word 'any'.
.Parameter DestinationAddress
Required.
Specify the destination address for this rule. To match any destination address you may use the word 'any'.
.Parameter SourceZone
Required.
Specify the source zone for this rule. To match any source zone you may use the word 'any'.
.Parameter DestinationZone
Required.
Specify the destination zone for this rule. This must be a specific zone. The use of 'any' for this parameter is not supported.
.Parameter Description
Optional.
Specify a description for this rule.
.Parameter NATDestinationAddress
Optional.
Specify the NAT destination address for traffic that matches this rule. Currently this module only supports a static destination address.
.Parameter NATStaticSourceAddress
Optional.
Specify the NAT source address for traffic that matches this rule. Currently this module only supports a static source address.
.Parameter NATDestinationPort
Optional.
Specify the NAT destination port. This must be a number not a service group or service object.
.Parameter DestinationInterface
Optional.
Specify the destination interface to match of the original packet for this NAT rule.
.Parameter Disabled
Optional.
Specify that this rule is to be disabled.
#>
Function Add-PaNATRule 
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$RuleName,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$BiDirectional,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Service,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SourceAddress,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DestinationAddress,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$SourceZone,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DestinationZone,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Description,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$NATDestinationAddress,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$NATStaticSourceAddress,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$NATDestinationPort,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$DestinationInterface,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$Disabled
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Do some sanity checks before calling the firewall.
	if (!$RuleName)
	{
		throw 'You must specify a rule name to create. The rule was not added.'
	}
	elseif($BiDirectional -and !$NATStaticSourceAddress)
	{
		throw "You must specify a NAT source address when using bi-directional NAT. The rule was not added."
	}
	elseif($NATDestinationPort -and (!$NATDestinationAddress))
	{
		throw 'You must specify a destination address when specifying NATDestinationPort. The rule was not added.'
	}
	elseif(!$SourceAddress)
	{
		throw 'You must specify a source address. The word "any" can be used to mean all addresses. The rule was not added.'
	}
	elseif(!$DestinationAddress)
	{
		throw 'You must specify a destination address. The word "any" can be used to mean all addresses. The rule was not added.'
	}
	elseif(!$Service)
	{
		throw 'You must specify a service object or service group address. The word "any" can be used to mean any service. The rule was not added.'
	}
	elseif(!$SourceZone)
	{
		throw 'You must specify a source zone. You may define one or multiple zones seperated by commas. The "any" keyword can also  be used to specify all zones. The rule was not added.'
	}
	elseif(!$DestinationZone)
	{
		throw 'You must specify a destination zone. Only one zone may be defined. The rule was not added.'
	}
	#Check if a rule by this name already exists. We have to do this because the firewall will update an existing rule by the same name even when using the set command instead of edit.
	#This is undesireable because a user likely won't want to modify an existing rule if they are calling the add function of this script.
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules/entry[@name='" + $RuleName + "']&key="  + (GetPaAPIKeyClearText)))
	if ($result.response.result)
	{
		throw 'A rule by this name already exists. Please specify another name to add a rule or use the "Edit-PaNatRule" function to modify an existing rule.'
	}
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	#Build the rule configuration.
	$xmlString = '' #Set this to empty to ensure we start the build clean.

	#Set the configuration for bi-directional NAT
	if($BiDirectional)
	{
		$xmlString += '<source-translation><static-ip><bi-directional>yes</bi-directional>'
		$xmlString += ('<translated-address>' + $NATStaticSourceAddress + '</translated-address></static-ip></source-translation>')
	}
				#Build the destination Zone configuration. There can only be one destination zone entry.
	if($NATStaticSourceAddress)
	{
		$xmlString += ('<source-translation><static-ip><translated-address>' + $NATStaticSourceAddress + '</translated-address></static-ip></source-translation>')
	}
	#Build the destination Zone configuration. There can only be one destination zone entry.
	if($DestinationZone)
	{
		$xmlString += ('<to><member>' + $DestinationZone + '</member></to>')
	}
	#Build the Source zone configuration.
	if($SourceZone)
	{
		$xmlString += '<from>'
		foreach ($entry in $SourceZone.Split(','))
		{
			$xmlString += "<member>"
			$xmlString += $entry
			$xmlString += "</member>"
		}
		$xmlString += '</from>'
	}
	#Build the Source address configuration.
	if($SourceAddress)
	{
		$xmlString += '<source>'
		foreach ($entry in $SourceAddress.Split(','))
		{
			$xmlString += "<member>"
			$xmlString += $entry
			$xmlString += "</member>"
		}
		$xmlString += '</source>'
	}
	#Build the Destination address configuration.
	if($DestinationAddress)
	{
		$xmlString += '<destination>'
		foreach ($entry in $DestinationAddress.Split(','))
		{
			$xmlString += "<member>"
			$xmlString += $entry
			$xmlString += "</member>"
		}
		$xmlString += '</destination>'
	}
	#Build the Service configuration. There can only be one service entry.
	if($Service)
	{
		$xmlString += ('<service>' + $Service + '</service>')
	}
	#The following few items fall under destination-translation, do them all at the same time.
	#Build the NATTranslatedPort configuration. There can only be one NATTranslatedPort entry.
	if($NATDestinationPort)
	{
		$xmlString += ('<destination-translation><translated-port>' + $NATDestinationPort + '</translated-port></destination-translation>')
	}
	#Build the NATDestinationAddress configuration. There can only be one NATDestinationAddress entry.
	if($NATDestinationAddress)
	{
		$xmlString += ('<destination-translation><translated-address>' + $NATDestinationAddress + '</translated-address></destination-translation>')
	}
	#Build the DestinationInterface configuration. There can only be one DestinationInterface entry.
	if($DestinationInterface)
	{
		$xmlString += ('<to-interface>' + $DestinationInterface + '</to-interface>')
	}
	#Build the Rule disabled configuration.
	if($Disabled)
	{
		$xmlString += ('<disabled>yes</disabled>')
	}else
	{
		$xmlString += ('<disabled>no</disabled>')
	}
	#Once all of the all of the configuration has been built send the new rule to the firewall.
	$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules/entry[@name='" + $RuleName + "']&element=" + $xmlString + "&key="  + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.

	Write-Host "The rule was added successfully."
}


<#
.SYNOPSIS
Remove the specified NAT rule from the candidate configuration.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter RuleName
Required.
The name of the NAT rule to remove.
#>
Function Remove-PaNATRule {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$RuleName
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules/entry[@name='" + $RuleName + "']&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Output "The rule was removed successfully."
	Remove-Variable -Name response
	
}


<#
.SYNOPSIS
This code is no longer needed. It was buggy and has been replaced by the function Move-PaNATRule. Leaving it for now for code reference.
.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
<#Function Sort-PaNATRules
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][string]$SortList #passing this a comma seperate string will work. If you have an array use this to send the data: ($array -join ',')
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$paConfig = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules&key=" + (GetPaAPIKeyClearText)) 
	$oldNatRules = $paConfig.response.result.rules.entry
	Remove-Variable -Name paConfig
	#$oldNatRules = getpaNatRules #I'd like to use the existing function if possible but it may never be.
	$sorted = ($oldNatRules | sort -Property @{Expression={$SortList.IndexOf(($_.name))}; Ascending = $true})
	#Delete all rules but don't delete the Nat rulebase.
	foreach ($rule in $oldNatRules)
	{
		$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules/entry[@name='" + $rule.name + "']" + "&key="  + (GetPaAPIKeyClearText)))
	}
	#Add the rules.
	foreach ($rule in $sorted)
	{
		$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules/entry[@name='" + $rule.name + "']&element=" + $rule.InnerXml + "&key="  + (GetPaAPIKeyClearText)))
	}
	Remove-Variable -Name oldNatRules
	Remove-Variable -Name sorted
	Remove-Variable -Name rule
	Remove-Variable -Name response
	Remove-Variable -Name SortList
	
}#>

<#
.SYNOPSIS
Move the specified NAT rule up or down in the rule list.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter RuleToMove
Required.
The rule that you wish to move.
.Parameter MoveToTop
Optional.
Move the rule to the top of the rule list.
.Parameter MoveToBottom
Optional.
Move the rule to the bottom of the rule list.
.Parameter MoveAfterRule
Optional.
Use this parameter to specify the rule name to move the "RuleToMove" below.
.Parameter MoveBeforeRule
Optional.
Use this parameter to specify the rule name to move the "RuleToMove" above.
#>
Function Move-PaNATRule
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][string]$RuleToMove,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][switch]$MoveToTop,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][switch]$MoveToBottom,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][string]$MoveAfterRule,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][string]$MoveBeforeRule
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	if (($MoveToTop -and $MoveToBottom) -or ($MoveToTop -and $MoveAfterRule) -or ($MoveToTop -and $MoveBeforeRule) -or ($MoveToBottom -and $MoveAfterRule) -or ($MoveToBottom -and $MoveBeforeRule) -or ($MoveAfterRule -and $MoveBeforeRule))
	{
		throw "You may only chose one action to do to a rule."
	}
	if ($MoveToTop)
	{
		$result = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=move&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules/entry[@name='" + $RuleToMove + "']&where=top&key=" + (GetPaAPIKeyClearText)) 
	}
	elseif($MoveToBottom)
	{
		$result = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=move&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules/entry[@name='" + $RuleToMove + "']&where=bottom&key=" + (GetPaAPIKeyClearText)) 
	}
	elseif($MoveAfterRule)
	{
		$result = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=move&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules/entry[@name='" + $RuleToMove + "']&where=after&dst=" + $MoveAfterRule + "&key=" + (GetPaAPIKeyClearText)) 
	}
	elseif($MoveBeforeRule)
	{
		$result = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=move&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules/entry[@name='" + $RuleToMove + "']&where=before&dst=" + $MoveBeforeRule + "&key=" + (GetPaAPIKeyClearText)) 
	}
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	return $result.response	
}
<#
.SYNOPSIS

.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

.PARAMETER 
	
.PARAMETER 
	


#>
Function RenamePaNatRule #This function needs re-written, it relies on a deprecated and buggy old function. Need to find a betteer way to rename the rule.
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$RuleName,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$NewRuleName
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Get the current list of NAT rules
	$paConfig = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules&key=" + (GetPaAPIKeyClearText)) 
	$oldNatRules = $paConfig.response.result.rules.entry
	Remove-Variable -Name paConfig
	#Put the rule names in an array
	$ruleNames = $oldNatRules.name
	Remove-Variable -Name oldNatRules
	#Get the index number in the array of the rule to be renamed.
	$ruleIndex = $ruleNames.IndexOf($RuleName)
	#Rename the rule in the array.
	$ruleNames[$ruleIndex] = $NewRuleName
	#Get the current rule configuration.
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules/entry[@name='" + $RuleName + "']&key="  + (GetPaAPIKeyClearText)))
	$rule = $result.response.result.entry
	Remove-Variable -Name result
	#Remove the existing rule.
	Remove-PaNATRule -ID $ID -RuleName $RuleName
	#Add the new rule with the same configuration.
	$response = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/rulebase/nat/rules/entry[@name='" + $NewRuleName + "']&element=" + $rule.InnerXml + "&key="  + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Output "The rule was renamed successfully."
	#Sort the Rules.
	Sort-PaNATRules -ID $ID -SortList ($ruleNames -join ',')
	Remove-Variable -Name rule
	Remove-Variable -Name response
	Remove-Variable -Name ruleNames
	Remove-Variable -Name RuleName
	Remove-Variable -Name NewRuleName
	
}

<#
.SYNOPSIS
Roll back the candidate configuration to the specified configuration version. This function currently only supports rolling back to the running configuration. Changes are only applied to the candidate configuration.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.

#>
Function Revert-PaloAltoConfiguration
{
	param (
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$RunningConfig
	)
	if(!$PaloAltoManagementSessionTable.findSessionByID($ID))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Set RevertoConfig to be empty.
	#$RevertToConfig = ''
	#if ($RunningConfig)
	#{
		$RevertToConfig = 'running-config.xml' 
	#}
	#if ($RevertToConfig -eq '')
	#{
	#	throw  "No config to revert to, the script will do nothing. Currently this commandlet only supports reverting to the running config."
	#}
	#Revert the configuration.
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<load><config><from>" + $RevertToConfig + "</from></config></load>&key=" + (GetPaAPIKeyClearText)))
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The configuration was reverted successfully."
	Remove-Variable -Name result
	Remove-Variable -Name RevertToConfig
}

<#
.SYNOPSIS
Adds a static address object to the candidate configuration.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter AddressName
Required. 
Specifies the name of the address object.
.Parameter FQDN
Optional. 
Specify the fully qualified domain name for the address object.
.Parameter IpRange
Optional. 
Specify the IP range for this address object. Example: '192.168.0.1-192.168.0.50'
.Parameter IpNetmask
Optional. 
Specify an IP/Netmask combination for this address object. Example: '192.168.0.0/24'
.Parameter Description
Optional. 	
Specifies a description for the address object.
#>
Function Add-PaAddressObject
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$AddressName,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$FQDN,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$IpRange,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$IpNetmask,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Description
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Do some sanity checks before calling the firewall.
	if (!$AddressName)
	{
		throw 'You must specify a name for the address object. The address object was not added.'
	}
	if(($FQDN -and $IpRange) -or ($FQDN -and $IpNetmask) -or ($IpRange -and $IpNetmask))
	{
		throw "You may only specify one type (FQDN, IpRange, IpNetmask) for an address object. The address object was not added."
	}
	#Check if an address object by this name already exists. We have to do this because the firewall will update an existing address object by the same name even when using the set command instead of edit.
	#This is undesireable because a user likely won't want to modify an existing address object if they are calling the add function of this script.
	Write-Debug ('Checking to see if an address object with the requested name already exists.')
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/address/entry[@name='" + $AddressName + "' ]&key="  + (GetPaAPIKeyClearText)))
	if ($result.response.result)
	{
		throw 'An address object with this name already exists. Please specify another name to add an address object or use the "Edit-PaAddressObject" function to modify an existing Address Object.'
	}
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	#Build the XML string.
	$xmlString = ('<entry name="' + $AddressName + '">')
	if ($FQDN)
	{
		Write-Debug ('The address object will be created with a FQDN element.')
		$xmlString += ('<fqdn>' + $FQDN + '</fqdn>')
	}
	if ($IpRange)
	{
		Write-Debug ('The address object will be created with a IpRange element.')
		$xmlString += ('<ip-range>' + $IpRange + '</ip-range>')
	}
	if ($IpNetmask)
	{
		Write-Debug ('The address object will be created with a IpNetMask element.')
		$xmlString += ('<ip-netmask>' + $IpNetmask + '</ip-netmask>')
	}
	if ($Description)
	{
		Write-Debug ('The address object will be created with a Description element.')
		$xmlString += ('<description>' + $Description + '</description>')
	}
	$xmlString += '</entry>'
	Write-Debug ('The XML string that defines the address object is: ' + $xmlString)
	#Send the request to the firewall.
	#Unlike with the rulebase rule additions you cannot specify the entry to add for an address object in the URL and must build the XML string to contain it.
	$url = ("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/address&element=" + $xmlString + "&key="  + (GetPaAPIKeyClearText))
	Write-Debug ('The url called is: ' + $url)
	$response = [xml]($PaloAltoModuleWebClient.downloadstring($url))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The address object was added successfully."
}

<#
.SYNOPSIS
Updates an existing address object. More specifically it overwrites an existing address object with the parameters you specify in this command.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter AddressName
Required. 
Specifies the name of the address object.
.Parameter FQDN
Optional. 
Specify the fully qualified domain name for the address object.
.Parameter IpRange
Optional. 
Specify the IP range for this address object. Example: '192.168.0.1-192.168.0.50'
.Parameter IpNetmask
Optional. 
Specify an IP/Netmask combination for this address object. Example: '192.168.0.0/24'
.Parameter Description
Optional. 	
Specifies a description for the address object.
#>
Function Update-PaAddressObject
{
	#This is essentially the same function as Add-PaAddressObject, just don't check if an object already exists.
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$AddressName,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$FQDN,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$IpRange,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$IpNetmask,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Description
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Do some sanity checks before calling the firewall.
	if (!$AddressName)
	{
		throw 'You must specify a name for the address object. The address object was not modified.'
	}
	if(($FQDN -and $IpRange) -or ($FQDN -and $IpNetmask) -or ($IpRange -and $IpNetmask))
	{
		throw "You may only specify one type (FQDN, IpRange, IpNetmask) for an address object. The address object was not modified."
	}
	#Check if an address object by this name already exists. We do this because if the user is calling the edit function they likely do not want to create a new address object.
	Write-Debug ('Checking to see if an address object with the requested name already exists.')
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/address/entry[@name='" + $AddressName + "' ]&key="  + (GetPaAPIKeyClearText)))
	if ($result.response.result)
	{
		#This is good, this means the address object already exists.
	}
	else
	{
		throw ('An address object by the name specified does not exist. Please pick an address name that does exist or use the Add-PaAddressObject function.')
	}
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	#Build the XML string.
	$xmlString = ('<entry name="' + $AddressName + '">')
	if ($FQDN)
	{
		Write-Debug ('The address object will be modified with a FQDN element.')
		$xmlString += ('<fqdn>' + $FQDN + '</fqdn>')
	}
	if ($IpRange)
	{
		Write-Debug ('The address object will be modified with a IpRange element.')
		$xmlString += ('<ip-range>' + $IpRange + '</ip-range>')
	}
	if ($IpNetmask)
	{
		Write-Debug ('The address object will be modified with a IpNetMask element.')
		$xmlString += ('<ip-netmask>' + $IpNetmask + '</ip-netmask>')
	}
	if ($Description)
	{
		Write-Debug ('The address object will be modified with a Description element.')
		$xmlString += ('<description>' + $Description + '</description>')
	}
	$xmlString += '</entry>'
	Write-Debug ('The XML string that defines the modified address object is: ' + $xmlString)
	#Send the request to the firewall.
	#Unlike with the rulebase rule additions you cannot specify the entry to add for an address object in the URL and must build the XML string to contain it.
	#Since set can modify configuration values we use it here.
	$url = ("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/address&element=" + $xmlString + "&key="  + (GetPaAPIKeyClearText))
	Write-Debug ('The url called is: ' + $url) #This will output the apikey to the powershell window as part of the URL string.
	$response = [xml]($PaloAltoModuleWebClient.downloadstring($url))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The address object was modified successfully."
}

<#
.SYNOPSIS
Removes the specified address object.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter AddressName
Required. 
Specifies the name of the address object.
#>
Function Remove-PaAddressObject
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$AddressName
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Do some sanity checks before calling the firewall.
	if (!$AddressName)
	{
		throw 'You must specify a name for the address object. The address object was not deleted.'
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/address/entry[@name='" + $AddressName + "']&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The address object was removed successfully."
	Remove-Variable -Name response
}

<#
.SYNOPSIS

.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
Function Add-PaServiceObject
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$ServiceName,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$TCP,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$UDP,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Port,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Description
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Do some sanity checks before calling the firewall.
	if (!$ServiceName)
	{
		throw 'You must specify a name for the service object. The service object was not added.'
	}
	if($TCP -and $UDP)
	{
		throw "You may only specify one Protocol (TCP,UDP) for a service object. The service object was not added."
	}
	#Check if a service object by this name already exists. We have to do this because the firewall will update an existing service object by the same name even when using the set command instead of edit.
	#This is undesireable because a user likely won't want to modify an existing service object if they are calling the add function of this script.
	Write-Debug ('Checking to see if a service object with the requested name already exists.')
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/service/entry[@name='" + $ServiceName + "' ]&key="  + (GetPaAPIKeyClearText)))
	if ($result.response.result)
	{
		throw 'A service object with this name already exists. Please specify another name to add a service object or use the "Edit-PaServiceObject" function to modify an existing Service Object.'
	}
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	#Build the XML string.
	$xmlString = ('<entry name="' + $ServiceName + '">')
	if ($TCP)
	{
		Write-Debug ('The service object will be created as a TCP object.')
		$xmlString += ('<protocol><tcp><port>' + $port + '</port></tcp></protocol>')
		if ($Description)
		{
			$xmlString += ('<description>' + $Description + '</description>')
		}
	}
	if ($UDP)
	{
		Write-Debug ('The service object will be created as a UDP object.')
		$xmlString += ('<protocol><udp><port>' + $port + '</port></udp></protocol>')
		if ($Description)
		{
			$xmlString += ('<description>' + $Description + '</description>')
		}
	}
	$xmlString += '</entry>'
	Write-Debug ('The XML string that defines the service object is: ' + $xmlString)
	#Send the request to the firewall.
	#Unlike with the rulebase rule additions you cannot specify the entry to add for a service object in the URL and must build the XML string to contain it.
	$url = ("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/service&element=" + $xmlString + "&key="  + (GetPaAPIKeyClearText))
	Write-Debug ('The url called is: ' + $url)
	$response = [xml]($PaloAltoModuleWebClient.downloadstring($url))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The service object was added successfully."
}

<#
.SYNOPSIS
#This is essentially the same function as Add-PaServiceObject, just don't check if an object already exists.

.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
Function Update-PaServiceObject
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$ServiceName,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$TCP,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$UDP,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Port,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Description
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Do some sanity checks before calling the firewall.
	if (!$ServiceName)
	{
		throw 'You must specify a name for the service object. The service object was not modified.'
	}
	if($TCP -and $UDP)
	{
		throw "You may only specify one Protocol (TCP,UDP) for a service object. The service object was not modified."
	}
	#Check if a service object by this name already exists. We do this because if the user is calling the edit function they likely do not want to create a new service object.
	Write-Debug ('Checking to see if a service object with the requested name already exists.')
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/service/entry[@name='" + $ServiceName + "' ]&key="  + (GetPaAPIKeyClearText)))
	if ($result.response.result)
	{
		#This is good, this means the service object already exists.
	}
	else
	{
		throw ('A service object by the name specified does not exist. Please pick a service name that does exist or use the Add-PaServiceObject function.')
	}
	#Remove the existing service object to edits happen as expected. For some reason even when no description is passed a description will stay if the object being edited already exists.
	#Capture any output in case I may want to use it some day. Also this should hide the output from the remove function from the user.
	$result = (Remove-PaServiceObject -ID $ID -ServiceName $ServiceName)
	Remove-Variable -Name result
	#Build the XML string.
	$xmlString = ('<entry name="' + $ServiceName + '">')
	if ($TCP)
	{
		Write-Debug ('The service object will be modified as a TCP object.')
		$xmlString += ('<protocol><tcp><port>' + $port + '</port></tcp></protocol>')
		if ($Description)
		{
			$xmlString += ('<description>' + $Description + '</description>')
		}
	}
	if ($UDP)
	{
		Write-Debug ('The service object will be modified as a UDP object.')
		$xmlString += ('<protocol><udp><port>' + $port + '</port></udp></protocol>')
		if ($Description)
		{
			$xmlString += ('<description>' + $Description + '</description>')
		}
	}
	$xmlString += '</entry>'
	Write-Debug ('The XML string that defines the service object is: ' + $xmlString)
	#Send the request to the firewall.
	#Unlike with the rulebase rule additions you cannot specify the entry to add for a service object in the URL and must build the XML string to contain it.
	$url = ("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/service&element=" + $xmlString + "&key="  + (GetPaAPIKeyClearText))
	Write-Debug ('The url called is: ' + $url)
	$response = [xml]($PaloAltoModuleWebClient.downloadstring($url))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The service object was modified successfully."
}

<#
.SYNOPSIS
Remove a service object from the candidate configuration.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter ServiceName
Required.
The name of the service object you wish to delete.
#>
Function Remove-PaServiceObject
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$ServiceName
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Do some sanity checks before calling the firewall.
	if (!$ServiceName)
	{
		throw 'You must specify a name for the service object. The service object was not deleted.'
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/service/entry[@name='" + $ServiceName + "']&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The service object was removed successfully."
	Remove-Variable -Name response
}

<#
.SYNOPSIS
Adds the specfied address group to the candidate configuration.
Currently only works with static groups.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter AddressGroupName
Required.
Specifies the name of the address group to create.
.Parameter Members
Required. 
A comma seperated string containing the names of address objects or other address groups this group should contain.
.Description
Optional.
Specify a description for this address group.
#>
Function Add-PaAddressGroup
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$AddressGroupName,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Members,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Description
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Do some sanity checks before calling the firewall.
	if (!$AddressGroupName)
	{
		throw 'You must specify a name for the address group. The address group was not created.'
	}
	#Check if an address group by this name already exists. We do this because if the user is calling the add function they likely do not want to overwrite and existing address group.
	Write-Debug ('Checking to see if an address group with the requested name already exists.')
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/address-group/entry[@name='" + $AddressGroupName + "' ]&key="  + (GetPaAPIKeyClearText)))
	if ($result.response.result)
	{
		throw ('An address group by this name already exists. Please pick a name that does exist or use the Edit-PaAddressGroup function to modify an existing address group.')
	}
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	#Build the XML string.
	$xmlString = ('<entry name="' + $AddressGroupName + '">')
	#For now all address groups are static.
	$xmlString += '<static>'
	foreach ($entry in $Members.Split(','))
	{
		$xmlString += "<member>"
		$xmlString += $entry
		$xmlString += "</member>"
	}
	$xmlString += '</static>'
	if ($Description)
	{
		$xmlString += ('<description>' + $Description + '</description>')
	}
	$xmlString += '</entry>'
	Write-Debug ('The XML string that defines the address group is: ' + $xmlString)
	#Send the request to the firewall.
	#Unlike with the rulebase rule additions you cannot specify the entry to add for a service object in the URL and must build the XML string to contain it.
	$url = ("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/address-group&element=" + $xmlString + "&key="  + (GetPaAPIKeyClearText))
	Write-Debug ('The url called is: ' + $url)
	$response = [xml]($PaloAltoModuleWebClient.downloadstring($url))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The address group was created successfully."
}

<#
.SYNOPSIS
Remove an address group from the candidate configuration.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter AddressGroupName
Required.
The name of the address group you wish to delete.
#>
Function Remove-PaAddressGroup
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$AddressGroupName
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Do some sanity checks before calling the firewall.
	if (!$AddressGroupName)
	{
		throw 'You must specify the name of an address group to delete. No address group was deleted.'
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/address-group/entry[@name='" + $AddressGroupName + "']&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The address group was removed successfully."

	Remove-Variable -Name response
}

<#
.SYNOPSIS


.Members 
A comma seperated string containing the names of address objects or other service groups this group should contain.
.PARAMETER 
	
.PARAMETER 
	


#>
Function Add-PaServiceGroup
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$ServiceGroupName,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Members
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Do some sanity checks before calling the firewall.
	if (!$ServiceGroupName)
	{
		throw 'You must specify a name for the service group. The service group was not created.'
	}
	#Check if a service group by this name already exists. We do this because if the user is calling the add function they likely do not want to overwrite and existing service group.
	Write-Debug ('Checking to see if an service group with the requested name already exists.')
	$result = [xml]($PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/service-group/entry[@name='" + $ServiceGroupName + "' ]&key="  + (GetPaAPIKeyClearText)))
	if ($result.response.result)
	{
		throw ('An service group by this name already exists. Please pick a name that does exist or use the Edit-PaAddressGroup function to modify an existing service group.')
	}
	ReturnPaAPIErrorIfError($result) #This function checks for an error from the firewall and throws it if there is one.
	#Build the XML string.
	$xmlString = ('<entry name="' + $ServiceGroupName + '"><members>')
	foreach ($entry in $Members.Split(','))
	{
		$xmlString += "<member>"
		$xmlString += $entry
		$xmlString += "</member>"
	}
	$xmlString += '</members></entry>'
	Write-Debug ('The XML string that defines the service group is: ' + $xmlString)
	#Send the request to the firewall.
	#Unlike with the rulebase rule additions you cannot specify the entry to add for a service object in the URL and must build the XML string to contain it.
	$url = ("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/service-group&element=" + $xmlString + "&key="  + (GetPaAPIKeyClearText))
	Write-Debug ('The url called is: ' + $url)
	$response = [xml]($PaloAltoModuleWebClient.downloadstring($url))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The service group was created successfully."
}

<#
.SYNOPSIS
Remove a service group from the candidate configuration.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter AddressGroupName
Required.
The name of the service group you wish to delete.
#>
Function Remove-PaServiceGroup
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$ServiceGroupName
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Do some sanity checks before calling the firewall.
	if (!$ServiceGroupName)
	{
		throw 'You must specify the name of an service group to delete. No service group was deleted.'
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='" + $PaloAltoManagementSessionTable.findSessionByID($ID).DeviceName + "']/vsys/entry[@name='"+ $PaloAltoManagementSessionTable.findSessionByID($ID).VirtualSystem + "']/service-group/entry[@name='" + $ServiceGroupName + "']&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host "The service group was removed successfully."
	Remove-Variable -Name response
}

<#
.SYNOPSIS
Direct the firewall to download the specified PANOS version.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter SoftwareVersion
Required.
This is the PANOS version you wish to download. Specify it in the format x.y.z . Example for PANOS 7.0.15 specify "7.0.15"
#>
Function Download-PaPANOSVersion{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$SoftwareVersion
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<request><system><software><download><version>" + $SoftwareVersion + "</version></download></software></system></request>&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	$result = New-Object psobject
	Add-Member -InputObject $result -MemberType NoteProperty -Name ResultMessage -Value $response.response.result.msg.line
	Add-Member -InputObject $result -MemberType NoteProperty -Name JobID -Value $response.response.result.job
	return $result
}

<#
.SYNOPSIS
Direct the firewall to install the specified PANOS version. The output of this command contains the software download jobID so you can watch it's progress with the Get-Pajob -JobID <ID> command 
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. You can find the ID to firewall mapping by running the "Get-PaloAltoManagementSession" command.
.Parameter SoftwareVersion
Required.
This is the PANOS version you wish to install. Specify it in the format x.y.z . Example for PANOS 7.0.15 specify "7.0.15"
#>
Function Install-PaPANOSVersion{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$SoftwareVersion
	#[Parameter(Mandatory=$false,valueFromPipeline=$true)][Switch]$ReturnRawData
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<request><system><software><install><version>" + $SoftwareVersion + "</version></install></software></system></request>&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	$result = New-Object psobject
	Add-Member -InputObject $result -MemberType NoteProperty -Name ResultMessage -Value $response.response.result.msg.line
	Add-Member -InputObject $result -MemberType NoteProperty -Name JobID -Value $response.response.result.job
	return $result
}


<#
.SYNOPSIS
This function is used to add a user-id mapping to the Palo Alto firewall.
.Parameter ID
Required.
This is the session ID of the firewall you wish to run this command on. 
.Parameter Username
Required.
The username to be used for this mapping.
.Parameter IpAddress
Required.
The IPv4 or IPv6 address to be used for this mapping.
.Parameter Timeout
Optional.
Sets the time in minutes the mapping will be valid.
#>
Function Add-PaUserIDMapping{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$Username,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$IpAddress,
	[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$Timeout = 60
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	#Build the first part of the XML string.
	$xmlString = '<uid-message><version>1.0</version><type>update</type><payload><login>'
	#Parse the given username.
	$userDomain = $Username.split('\')
	if ($userDomain.Count -gt 2)
	{
		throw "The <domain>\<username> string entered was invalid."
	}
	if ($userDomain.Count -eq 1)
	{
		$domain = ''
		$user = $userDomain[0]
	}
	elseif ($userDomain.Count -eq 2)
	{
		$domain = $userDomain[0]
		$user = $userDomain[1]
	}
	$xmlString += ('<entry name="' + $domain + '\' + $user + '" ip="' + $IpAddress + '" timeout="' + $Timeout + '">')
	$xmlString += '</entry></login></payload></uid-message>'
	#$response = $PaloAltoModuleWebClient.uploadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=user-id&key=" + (GetPaAPIKeyClearText), $xmlString)
	$response = $PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=user-id&cmd=" + $xmlString + "&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	#Do not return anything if the function executed as expected.
}

<#

<uid-message>
 <version>1.0</version>
 <type>update</type>
 <payload>
 <login>
 <entry name="domain\uid1" ip="10.1.1.1" timeout="20">
 </entry>
 </login>
 <groups>
 <entry name="group1">
 <members>
 <entry name="user1"/>
 <entry name="user2"/>
 </members>
 </entry>
 <entry name="group2">
 <members>
 <entry name="user3"/>
 </members>
 </entry>
 </groups>
 </payload>
</uid-message></uid-message>

"https://firewall/api/?type=user-id

#>
<#
.SYNOPSIS


.PARAMETER  

.PARAMETER 
	
.PARAMETER 
	


#>
<#Function Disable-PaSecurityRule{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$RuleName
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<request><system><software><install><version>" + $SoftwareVersion + "</version></install></software></system></request>&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host 'The install was started with no errors. (Figure out what result is returned on software install and update this output.'
	$result = New-Object psobject
	Add-Member -InputObject $result -MemberType NoteProperty -Name ResultMessage -Value $response.response.result.msg.line
	Add-Member -InputObject $result -MemberType NoteProperty -Name JobID -Value $response.response.result.job
	return $result
}#>

<#
.SYNOPSIS


.PARAMETER  

.PARAMETER 
	
.PARAMETER 
	


#>
<#Function Disable-PaNatRule{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$ID,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$RuleName
    )
	if((!$PaloAltoManagementSessionTable.findSessionByID($ID)) -or (!$PaloAltoManagementSessionTable))
	{
		throw ('This session ID does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using "Get-PaloAltoSession".')
	}
	$response = [xml]$PaloAltoModuleWebClient.downloadstring("https://" + $PaloAltoManagementSessionTable.findSessionByID($ID).Hostname + "/api/?type=op&cmd=<request><system><software><install><version>" + $SoftwareVersion + "</version></install></software></system></request>&key=" + (GetPaAPIKeyClearText))
	ReturnPaAPIErrorIfError($response) #This function checks for an error from the firewall and throws it if there is one.
	Write-Host 'The install was started with no errors. (Figure out what result is returned on software install and update this output.'
	$result = New-Object psobject
	Add-Member -InputObject $result -MemberType NoteProperty -Name ResultMessage -Value $response.response.result.msg.line
	Add-Member -InputObject $result -MemberType NoteProperty -Name JobID -Value $response.response.result.job
	return $result
}#>


#####################################################################################################################################################################
#Below this line are functions that are helpers for the other module functions.
#####################################################################################################################################################################
<#
.SYNOPSIS
This function returns a formatted error of information retrieved from the API if there was an error. Otherwise the script returns nothing. 
.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
function ReturnPaAPIErrorIfError
{
	param 
	(
        [Parameter(Mandatory=$true,valueFromPipeline=$true)]$response
    )
	$returnObject = New-Object PSObject
	$returnString = ''
    if ($response.response.status -eq 'error')
	{
		if ($response.response.msg.line.'#cdata-section')
		{
			Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'cdata-section' -Value $response.response.msg.line.'#cdata-section'
			$returnString += $response.response.msg.line.'#cdata-section'
		}
		elseif ($response.response.msg.line)
		{
			Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'MessageLine' -Value $response.response.msg.line
			$returnString += $response.response.msg.line
		}
		elseif ($response.response.msg)
		{
			Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Message' -Value $response.response.msg
			$returnString += $response.response.msg
		}
		throw $returnString
	}
}
<#
.SYNOPSIS
This function returns the HTTP error value as an integer or nothing if it doesn't find an HTTP error code. This function is only designed to work with the palo alto module. 
This function is looking for errors from the dotnet web client object.

If you catch an exception and want this function to find the HTTP error code you must send it $Exception.Exception

.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
function findPaWebCallErrorCode
{
	param 
	(
        [Parameter(Mandatory=$true,valueFromPipeline=$true)]$exceptionObject
    )
	if ($RunningPowershell6)
	{
		if ($exceptionObject.Response.RequestMessage.Headers.UserAgent)
		{
			if ($exceptionObject.Response.RequestMessage.Headers.UserAgent.ToString() -match 'WindowsPowerShell')
			{
				if ($exceptionObject.Response.StatusCode)
				{
					return [int]$exceptionObject.Response.StatusCode #Putting [int] there is a way to access the integer value of an enumeration of StatusCode.
				}
			}
		}
		if ($exceptionObject.InnerException) #Check to see if there is another inner exception, if there is try this function again.
		{
			findPaWebCallErrorCode($exceptionObject.InnerException)
		}
	}
	else
	{
		if ($exceptionObject.StackTrace)
		{
			if ($exceptionObject.StackTrace.ToString() -match 'System.Net.WebClient.Download')
			{
				if ($exceptionObject.Response.StatusCode)
				{
					return [int]$exceptionObject.Response.StatusCode #Putting [int] there is a way to access the integer value of an enumeration of StatusCode.
				}
			}
		}
		if ($exceptionObject.InnerException) #Check to see if there is another inner exception, if there is try this function again.
		{
			findPaWebCallErrorCode($exceptionObject.InnerException)
		}
	}
}

<#
.SYNOPSIS
Converts an csv list in to an XML string.
Example1:
If the command is run like this: ConvertCSVListIntoXMLString -xmlNodes 'member' -list 'test'
The output will be <member>test</member>

Example2:
If the command is run like this: ConvertCSVListIntoXMLString -xmlNodes 'candle,member' -list 'test'
The output will be <candle><member>test</member></candle>

Example3:
If the command is run like this: ConvertCSVListIntoXMLString -xmlNodes 'member' -list 'test,test1,test2'
The output will be <member>test</member><member>test1</member><member>test2</member>

Example4:
If the command is run like this: ConvertCSVListIntoXMLString -xmlNodes 'candle,member' -list 'test,test1,test2'
The output will be <candle><member>test</member></candle><candle><member>test1</member></candle><candle><member>test2</member></candle>
#>
Function ConvertCSVListIntoXMLString
{
	param (
		[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$xmlNodes,
		[Parameter(Mandatory=$false,valueFromPipeline=$true)][String]$list
		)
	$xmlString = ''
	$nodeList = $xmlNodes.Split(',')
	foreach ($entry in $list.Split(','))
	{
		foreach ($node in $nodeList)
		{
			$xmlString += ("<" + $node + ">")
		}

		$xmlString += $entry
			
		for ($i = $nodeList.length - 1; $i -ge 0; $i--)
		{
			$xmlString += ("</" + $nodeList[$i] + ">")
		}
	}
	Return $xmlString
}


<#
.SYNOPSIS
Returns a list of addresses and ports it finds. Input can be a full URL or just an ip address or IP and port.
.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
Function ParseURL
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$userInput
	)
    #Define the object to return when complete.
    $returnList = New-Object System.Collections.ArrayList

    #Set port to null, it will be defined if it exists.
    $port = $null
	#Get the IP address or DNS name and port number if present. The following line returns the hostname/ip address and port combo always.
	$userInput -match '(.*:\/\/)?([^\/]*)(\/.*)?' | Out-Null #Don't print any output.
	$unParsedInput = $matches[2]
    #Check if the input has multiple colons, if it does then it is an IPv6 address
    if ($unParsedInput.split(':').count -gt 2)
    {
        #If there are more than two results from the split then this must be an IPv6 address
        #Check if the input contains Square Brackets. If it does then there is a port specified.
        #If there are more than 2 colons in the address, then if it is not a valid IPv6 address we can error out, hostnames cannot contain a colon.
        if ($unParsedInput -match '\]')
        {
            #If there is a square bracket than a port is specified. Split the string by the closing bracket, then split by the colon and get the port number.
            $port = $unParsedInput.split(']')[1].split(':')[1]
            #Get the value from between the square brackets. This should be the address
            $unParsedInput -match '\[(.*)\]'  | Out-Null
            $addressToTest = $matches[1]
            try
            {
                if (!([int]$port -ge 0 -and [int]$port -le 65535))
                {
                    throw ('The specified port (' + $port + ') is not valid.')
                }
            }
            Catch
            {
                throw ('Error: A port was specified but could not be parsed. The port specified was: ' + $port)
            }
        }
        else
        {
            #Set the address to the unparsedInput, a port was not specified.
            $addressToTest = $unParsedInput
        }
        if (!(isIpAddress($addressToTest)))
        {
            throw ('The specified address is not an IPv6 address. The address specified was: ' + $addressToTest)
        }
        $validAddress = $addressToTest
        $returnObject = New-Object psobject
        Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'IpAddress' -Value $validAddress 
        Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Port' -Value $port
        [void]$returnList.Add($returnObject)
        return $returnList
    }
    else
    {
        #If we are here then we are looking for a non IPv6 address.
        #Don't error out on invalid IPv4 address, we must still try to resolve the address, it may be a hostname.
        #Check if the input has a colon.
        if ($unParsedInput -match ':')
        {
            $port = $unParsedInput.split(':')[1]
            $addressToTest = $unParsedInput.split(':')[0]
            try
            {
                if (!([int]$port -ge 0 -and [int]$port -le 65535))
                {
                    throw ('The specified port (' + $port + ') is not valid.')
                }
            }
            Catch
            {
                throw ('Error: A port was specified but could not be parsed. The port specified was: ' + $port)
            }
        }
        else
        {
            #Set the address to the unparsedInput, a port was not specified.
            $addressToTest = $unParsedInput
        }
        if (isIpAddress($addressToTest))
        {
            $validAddress = $addressToTest
            $returnObject = New-Object psobject
            Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'IpAddress' -Value $validAddress 
            Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Port' -Value $port
            [void]$returnList.Add($returnObject)
            return $returnList
        }
        else
        {
            #Check if it is a valid hostname.
            try
			{
				$ResolvedAddresses = Resolve-DnsName $addressToTest -ErrorAction Stop
			}
            Catch
			{
				#If we got here DNS resolution failed and we've already ensured that the $addressToTest isn't an IP address.
				throw ("The address is not a valid DNS name or IP address. The address specified was: " + $addressToTest)
			}
			foreach($address in $ResolvedAddresses )
			{
				if ($address.type -eq 'A' -or $address.type -eq 'AAAA')
				{
                    $returnObject = New-Object psobject
                    Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'IpAddress' -Value $address.IPaddress
                    Add-Member -InputObject $returnObject -MemberType NoteProperty -Name 'Port' -Value $port
                    [void]$returnList.Add($returnObject)
				}
			}
        return $returnList
        }
    }
}

<#
.SYNOPSIS
Return true if string passed is a valid IP address.
.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
Function isIpAddress{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$address
	)
    #Determine if this is an IPv6 address.
    if ($address -match ':')
    {
        try
        {
            [void][ipaddress]([string]$address) #To the best of my knowledge this is a valid way to check ipv6 addresses. I haven't verified.
            return $true
        }
        Catch
        {
        return $false
        }
    }
    else
    {
        #check that it's a valid IPv4 address, for some reason the [ipaddress] check won't work for these. Dotnet accepts the string '1.11.32' as a valid address.
        try
        {
		    if ($address -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') #Check for 4 numbers seperate by a period.
		    {
			    #Check that each number is below 256.
			    if ([int]$matches[1] -lt 256)
			    {
				    if ([int]$matches[2] -lt 256)
				    {
					    if ([int]$matches[3] -lt 256)
					    {
						    if ([int]$matches[4] -lt 256)
						    {
							    return $true
						    }
					    }
				    }
			    }
		    }
		    else
		    {
			    return $false
		    }
	    }
	    Catch
	    {
		    return $false
	    }
    }
}




<#
.SYNOPSIS
Return true if string passed is a valid IPv4.
.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
Function isIpV4Address {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$address
	)
	try{
		if ($address -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') #Check for 4 numbers seperate by a period.
		{
			#Check that each number is below 256.
			if ([int]$matches[1] -lt 256)
			{
				if ([int]$matches[2] -lt 256)
				{
					if ([int]$matches[3] -lt 256)
					{
						if ([int]$matches[4] -lt 256)
						{
							return $true
						}
					}
				}
			}
		}
		else
		{
			return $false
		}
	}
	Catch
	{
		return $false
	}
}

<#
.SYNOPSIS
Return true if string passed is a valid IPv4.
.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
Function isIpV6Address {
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$address
	)
	try{
		[void][ipaddress]$address
		if ($address -match '\.') #Do this check because any valid number less than 4 billion or so is a valid ip address.... (Must escape the period)
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	Catch
	{
		return $false
	}
}


#####################################################################################################################################################################
#Below this line are functions that are more advanced and rely on the functions above.
#####################################################################################################################################################################
<#
.SYNOPSIS
This function is passed the ID's of the firewalls to be upgraded in the HA pair. You must also pass this function the software version to install on the firewalls.
This function performs some rudimentary checks to ensure both firewalls are in an HA configuration (though it does not yet verify that they are in the same HA group) and ensure that synchronization is working as expected before performing the upgrade.
This function will upgrade the passive HA member first, if both are active the firewall specified with $FirewallID2 will be upgraded first.
.PARAMETER 

.PARAMETER 
	
.PARAMETER 
	


#>
Function UpgradePaHaPair #This function is being actively developed but is not ready to be published at this time.
{
	param (
    [Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$FirewallID1,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$FirewallID2,
	[Parameter(Mandatory=$true,valueFromPipeline=$true)][String]$TargetPANOSVersion
	)
	if((!$PaloAltoManagementSessionTable.findSessionByID($FirewallID1)) -or (!$PaloAltoManagementSessionTable) -or (!$PaloAltoManagementSessionTable.findSessionByID($FirewallID2)))
	{
		throw ("At least one of the session ID's specified does not exist, you must create a session for this firewall or use an existing session. Check existing sessions using 'Get-PaloAltoSession'.")
	}
	#Check that each firewall has the requested OS version available. First check if the firewall is aware so we don't refresh the PANOS versions needlessly.
	$fw1Versions = Get-PaAvailableSoftwareVersions -ID $FirewallID1
	if (!$fw1Versions.Version.Contains($TargetPANOSVersion))
	{
		#If we got here we need to see if the version is available on PaloALto's servers, the firewall does not already know about the software.
		$fw1Versions = Request-PaAvailableSoftwareVersions -ID $FirewallID1
		if (!$fw1Versions.Version.Contains($TargetPANOSVersion))
		{
			throw("The requested software version is not available on the firewall with the ID of : " + $FirewallID1)
		}
	}
	$fw2Versions = Get-PaAvailableSoftwareVersions -ID $FirewallID2
	if (!$fw2Versions.Version.Contains($TargetPANOSVersion))
	{
		#If we got here we need to see if the version is available on PaloALto's servers, the firewall does not already know about the software.
		$fw2Versions = Request-PaAvailableSoftwareVersions -ID $FirewallID2
		if (!$fw2Versions.Version.Contains($TargetPANOSVersion))
		{
			throw("The requested software version is not available on the firewall with the ID of : " + $FirewallID2)
		}
	}
	#Now check if the OS is downloaded and if not, download it.
	if (!($fw1Versions | where {$_.Version -eq $TargetPANOSVersion}).isdownloaded)
	{
		#Download the software on firewall 1
		try
		{
			$fw1DownloadJob = (Download-PaPANOSVersion -ID $FirewallID1 -SoftwareVersion $TargetPANOSVersion).JobID
		}
		Catch
		{
			throw("An error occured trying to download the software for the firewall with ID " + $FirewallID1 + ". The error was: " + $_.Exception.Message)
		}
	}
	if (!($fw2Versions | where {$_.Version -eq $TargetPANOSVersion}).isdownloaded)
	{
		#Download the software on firewall 2
		try
		{
			$fw2DownloadJob = (Download-PaPANOSVersion -ID $FirewallID2 -SoftwareVersion $TargetPANOSVersion).JobID
		}
		Catch
		{
			throw("An error occured trying to download the software for the firewall with ID " + $FirewallID2 + ". The error was: " + $_.Exception.Message)
		}
	}
	#Next check if software needed to be downloaded and if it did wait for the download to finish.
	$sanityCount = 0 #This variable will be used to ensure we don't wait forever for the download to complete.
	if ($fw1DownloadJob)
	{
		while (((Show-PaJobs -ID $FirewallID1 -JobID $fw1DownloadJob).status).tolower() -ne 'fin')
		{
			if ($sanityCount -gt 60)
			{
				throw ("Timed out waiting for software to download on the firewall with ID: " + $FirewallID1)
			}
			#sleep 10 seconds before checking the status again.
			sleep(10)
			$sanityCount ++
		}
	}
	$sanityCount = 0 #This variable will be used to ensure we don't wait forever for the download to complete.
	if ($fw2DownloadJob)
	{
		while (((Show-PaJobs -ID $FirewallID2 -JobID $fw2DownloadJob).status).tolower() -ne 'fin')
		{
			if ($sanityCount -gt 60)
			{
				throw ("Timed out waiting for software to download on the firewall with ID: " + $FirewallID2)
			}
			#sleep 10 seconds before checking the status again.
			sleep(10)
			$sanityCount ++
		}
	}
	#Now install the software
	$fw1InstallJobID = (Install-PaPANOSVersion -ID $FirewallID1 -SoftwareVersion $TargetPANOSVersion).JobID
	$fw2InstallJobID = (Install-PaPANOSVersion -ID $FirewallID2 -SoftwareVersion $TargetPANOSVersion).JobID
	#Wait for software to finish downloading.
	$sanityCount = 0 #This variable will be used to ensure we don't wait forever for the download to complete.
	while (((Show-PaJobs -ID $FirewallID1 -JobID $fw1InstallJobID).status).tolower() -ne 'fin')
	{
		if ($sanityCount -gt 60)
		{
			throw ("Timed out waiting for software to install on the firewall with ID: " + $FirewallID1)
		}
		#sleep 10 seconds before checking the status again.
		sleep(10)
		$sanityCount ++
	}
	$sanityCount = 0 #This variable will be used to ensure we don't wait forever for the download to complete.
	while (((Show-PaJobs -ID $FirewallID2 -JobID $fw2InstallJobID).status).tolower() -ne 'fin')
	{
		if ($sanityCount -gt 60)
		{
			throw ("Timed out waiting for software to install on the firewall with ID: " + $FirewallID2)
		}
		#sleep 10 seconds before checking the status again.
		sleep(10)
		$sanityCount ++
	}
}


#Only export user facing functions, this must be done after the functions are defined. Functions will only be exported if they have a hyphen in their name. 
#Functions without hyphens are useable by module functions but are not available for the user to call directly.
export-modulemember *-*

#Write a message to users letting thanking them for trying this out and letting them know how to begin.
Write-Host "Thank you for using this Palo Alto automation module. Please begin by creating a management session for a firewall by using the Add-PaloAltoManagementSession commandlet."


#Other notes
<#
Run this super terrible powershell one liner to get the list of user available functions in this module.
Get-Content "<pathToModule>" | where {$_ -match 'Function' -and $_ -match '[a-zA-Z]-[a-zA-Z]' -and $_ -notmatch ('<|/|"|#|\(|\.|\)' + "|'")} | %{$_.trim('{')} | select -Unique | Sort-Object | %{$_.split(' ')[1]; Write-host}

#>