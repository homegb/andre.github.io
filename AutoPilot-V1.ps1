function Convert-Bytes-ToGB($Value) {            
     
	$Value = $Value / 1GB #$Value / 1MB
	$DecimalPlaces = 2

	return [Math]::Round($value, $DecimalPlaces, [MidPointRounding]::AwayFromZero)
}

function DateTimeString() {
	$Date = (Get-Date).ToLocalTime().ToString()
	return ([datetime]$Date).ToString("yyyy-MM-dd HH:mm:ss")
}

function ReturnElapsed() {
	return [string]($StopWatch.Elapsed -split "\." | Select-Object -First 1)
}

function RebootComputer($Reboot, $Ask) {
    
	if ($Ask) {
		#ClearPowershellHost

		$ConfirmReboot = Read-Host "Type 'Yes' to reboot the machine"
	}

	if ($Reboot) {

		Write-Host -f Green "[$(ReturnElapsed)] Your computer will be restarted soon."

		Start-Sleep 15

		Restart-Computer -Force
	}

}

Function Add-AutopilotImportedDevice() {
	[cmdletbinding()]
	param
	(
		[Parameter(Mandatory = $true)] $serialNumber,
		[Parameter(Mandatory = $true)] $hardwareIdentifier,
		[Parameter(Mandatory = $false)] [Alias("orderIdentifier")] $groupTag = "",
		[Parameter(ParameterSetName = "Prop2")][Alias("UPN")] $assignedUser = ""
	)

	$graphApiVersion = "beta"
	$Resource = "deviceManagement/importedWindowsAutopilotDeviceIdentities"
	$Uri = "$Graph/$graphApiVersion/$Resource"
	$json = @"
{
    "@odata.type": "#microsoft.graph.importedWindowsAutopilotDeviceIdentity",
    "groupTag": "$groupTag",
    "serialNumber": "$serialNumber",
    "productKey": "",
    "hardwareIdentifier": "$hardwareIdentifier",
    "assignedUserPrincipalName": "$assignedUser",
    "state": {
        "@odata.type": "microsoft.graph.importedWindowsAutopilotDeviceIdentityState",
        "deviceImportStatus": "pending",
        "deviceRegistrationId": "",
        "deviceErrorCode": 0,
        "deviceErrorName": ""
    }
}
"@

	#$1 = $serialNumber.Length
	#$2 = $hardwareIdentifier.Length
	#Write-Host -f Magenta "Graph POST $Uri // Serial:($1) | ($2)`n$json"

	try {
		Invoke-RestMethod -Uri $Uri -Method POST -Headers $authHeaders -ContentType "application/json" -Body $json
	}
	catch {
		Write-Error $_.Exception 
		break
	}

}

Function Get-AutopilotImportedDevice() {

	[cmdletbinding()] param( [Parameter(Mandatory = $false)] $id = $null )
	
	# Defining Variables
	$graphApiVersion = "beta"
	if ($id) {
		$uri = "$Graph/$graphApiVersion/deviceManagement/importedWindowsAutopilotDeviceIdentities/$id"
	}
	else {
		$uri = "$Graph/$graphApiVersion/deviceManagement/importedWindowsAutopilotDeviceIdentities"
	}
	
	Write-Host -f Magenta "Graph GET $Uri"
	
	try {
		Start-Sleep -Milliseconds 200		
		$response = Invoke-RestMethod -Uri $uri -Headers $authHeaders
		
		if ($id) {
			$response
		}
		else {
			$devices = $response.value
		
			$devicesNextLink = $response."@odata.nextLink"
		
			while ($null -ne $devicesNextLink) {
				Start-Sleep -Milliseconds 200
				$devicesResponse = (Invoke-RestMethod -Uri $devicesNextLink -Headers $authHeaders)
				$devicesNextLink = $devicesResponse."@odata.nextLink"
				$devices += $devicesResponse.value
			}
			return $devices
		}
	}
	catch {
		Write-Error $_.Exception 
		break
	}
	
}


function Get-AutoPilotDeviceBySerial($SerialNumber) {

	try {
		Start-Sleep -Milliseconds 200
		$Response = Invoke-RestMethod -Uri "$Graph/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber, '$SerialNumber')" -Method GET -Headers $authHeaders
		$Response.value
	}
	catch {
		Write-Error $_.Exception 
		break
	}
}

function Sync-AutoPilotService() {

	try {
		Invoke-RestMethod -Uri "$Graph/beta/deviceManagement/windowsAutopilotSettings/sync" -Method POST -Headers $authHeaders -ContentType "application/json" -Body "{}"
		
		#Write-Host -f Cyan "Syncing with service, check back again soon"
	}
	catch {
		Write-Error $_.Exception 
		break
	}
}

function Update-AutoPilotDevice($deviceId, $User, $GroupTag, $DeviceName) {

	try {
		Invoke-RestMethod -Uri "$Graph/beta/deviceManagement/windowsAutopilotDeviceIdentities/$deviceId/UpdateDeviceProperties" -Method POST -Headers $authHeaders -ContentType "application/json" `
			-Body @"
{
	"userPrincipalName": "$($User.userPrincipalName)",
	"addressableUserName": "$($User.displayName)",
	"groupTag": "$GroupTag",
	"displayName": "$DeviceName"
}
"@
	}
	catch {
		Write-Error $_.Exception 
		break
	}
}

function Get-DeviceHardwareInformation() {
	try {
		$CimSession = New-CimSession

		$devDetail = (Get-CimInstance -CimSession $CimSession -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'")
		$HardwareHash = $devDetail.DeviceHardwareData

		$BiosSerialNumber = (Get-CimInstance -CimSession $CimSession -Class Win32_BIOS).SerialNumber

		$cs = Get-CimInstance -CimSession $CimSession -Class Win32_ComputerSystem
		$Make = $cs.Manufacturer.Trim()
		$Model = $cs.Model.Trim()

		$global:DevInfo = [PSCustomObject]@{
			#DeviceName             = [System.Net.Dns]::GetHostName()
			'Device Serial Number' = $BiosSerialNumber
			'Windows Product ID'   = ""
			'Hardware Hash'        = $HardwareHash
			#Manufacturer           = $Make
			#Model                  = $Model
			'Group Tag'            = ""
			'Assigned User'        = ""
		}

		return $DevInfo
	}
	catch {
		Write-Host -f Red "Unable to get all hardware information"
		Write-Error $_.Exception
	}
}

function Get-LocalDiskDrives($DriveType) {

	$DiskVolumes = Get-Volume

	$VolumeFields = $DiskVolumes | Where-Object { $_.Size -gt 0 } | Select-Object DriveLetter, FriendlyName, FileSystemType, DriveType, HealthStatus, OperationalStatus, #Size,
	@{n = "TotalSizeInGB"; e = { "$(Convert-Bytes-ToGB $_.Size) GB" } },
	@{n = "DiskSpaceFree"; e = { "$(Convert-Bytes-ToGB $_.SizeRemaining) GB" } }, Size

	if ($DriveType.Length -gt 1) {
		return $VolumeFields | Where-Object { $_.DriveType -eq "$DriveType" }
	}
	else {
		return $VolumeFields
	}
}

function SetupModules($Resources) {

	try {
		$ModuleData = [PSCustomObject]@{ Names = @(); Success = $false; Paths = @() }
		$ProgressPreference = "SilentlyContinue"
		foreach ($Resource in $Resources) {
			if (-not (Test-Path "$DeployFolder\$Resource.zip")) {

				Write-Host -f Cyan "Downloading: $Resource."
				Invoke-RestMethod "$GithubMain/Modules/$Resource.zip" -OutFile "$DeployFolder\$Resource.zip"
			}

			if (Test-Path "$DeployFolder\$Resource.zip") {

				if (-not (Test-Path "$DeployFolder\$Resource")) {
					Expand-Archive -LiteralPath "$DeployFolder\$Resource.zip" -DestinationPath "$DeployFolder\$Resource" -Force
				}
			}

			if (Test-Path "$DeployFolder\$Resource\*\$Resource.psd1") {
				Import-Module -Name "$DeployFolder\$Resource\*\$Resource.psd1" -Force | Out-Null
				$ModuleData.Success = $true
				$ModuleData.Paths += "$DeployFolder\$Resource\*\$Resource.psd1"
				$ModuleData.Names += "$Resource.psd1"
			}
		}
		$ModuleNames = $Resources -join "; "
		Write-Host -f Green "Modules downloaded $ModuleNames"
	}
	catch {
		Write-Host -f Red "Unable to download or install some modules from Github"
		Write-Error $_.Exception
	}

	return $ModuleData
}

function Get-oAuth-IntuneToken() {
	$GraphScopes = @( "DeviceManagementServiceConfig.ReadWrite.All" )
	$AccessTokenExpired = (-not $MsApi.ExpiresOn) -or ( [bool]$MsApi.ExpiresOn.LocalDateTime -and ($MsApi.ExpiresOn.LocalDateTime -lt (Get-Date).ToLocalTime()) )

	if ($AccessTokenExpired) {
		Write-Host -f Cyan "[$(ReturnElapsed)] Connecting to Intune."
		try {
			$global:MsApi = Get-MsalToken -ClientId "d1ddf0e4-d672-4dae-b554-9d5bdfd93547" -TenantId "common" -RedirectUri "urn:ietf:wg:oauth:2.0:oob" -Interactive -Scopes $GraphScopes
		}
		catch {
			$global:MsApi = Get-MsalToken -ClientId "d1ddf0e4-d672-4dae-b554-9d5bdfd93547" -TenantId "common" -RedirectUri "urn:ietf:wg:oauth:2.0:oob" -Interactive -Scopes $GraphScopes
		}
	}

	if ([bool]$MsApi.AccessToken) {

		$global:authHeaders = @{ "Content-Type" = "application/json"; "Authorization" = "Bearer " + $MsApi.AccessToken; "ExpiresOn" = $MsApi.ExpiresOn }
	}

	return $global:MsApi
}

function Get-IntuneAzureAdToken {

	try {

		#$GraphScopes = @( "DeviceManagementServiceConfig.ReadWrite.All" )
		$AccessTokenExpired = (-not $MsApi.ExpiresOn) -or ( [bool]$MsApi.ExpiresOn.LocalDateTime -and ($MsApi.ExpiresOn.LocalDateTime -lt (Get-Date).ToLocalTime()) )

		if ($AccessTokenExpired) {

			$ClientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547" #Intune Powershell
			$RedirectUri = "urn:ietf:wg:oauth:2.0:oob"
			$Resource = "AzureADPreview"
          
			$FindPath = Get-ChildItem "$DeployFolder\$Resource\*\$Resource.psd1" -EA SilentlyContinue

			if ([bool]$FindPath.Directory.FullName) {

				$AzureADModulePath = $FindPath.Directory.FullName
				$Assemblies = @(
                (Join-Path -Path $AzureADModulePath -ChildPath "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"),
                (Join-Path -Path $AzureADModulePath -ChildPath "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll")
				)
				Add-Type -Path $Assemblies -ErrorAction Stop

				try {
					$Authority = "https://login.microsoftonline.com/common/oauth2/token"
					$ResourceRecipient = "https://graph.microsoft.com"

					# Construct new authentication context
					$AuthenticationContext = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $Authority

					# Construct platform parameters
					$PlatformParams = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Always" # Arguments: Auto, Always, Never, RefreshSession

					$MsApi = ($AuthenticationContext.AcquireTokenAsync($ResourceRecipient, $ClientID, $RedirectUri, $PlatformParams)).Result
                
					if ([bool]$MsApi.AccessToken) {

						$global:authHeaders = @{ "Content-Type" = "application/json"; "Authorization" = "Bearer $($MsApi.AccessToken)"; "ExpiresOn" = $MsApi.ExpiresOn }

						return $MsApi                    
					}
				}
				catch [System.Exception] {
					Write-Warning -Message "An error occurred when constructing an authentication token: $($_.Exception.Message)" ; break
				}
			}
			else {
				Write-Host -f Red "Azure AD is not installed."
			}
		}
	}
	catch [System.Exception] {
		Write-Warning -Message "Unable to load required assemblies (Azure AD PowerShell module) to construct an authentication token. Error: $($_.Exception.Message)" ; break
	}
}

function Set-ExecutionPolicySetting($Policy) {
	try {
		Set-ExecutionPolicy -ExecutionPolicy $Policy -Force -EA SilentlyContinue
	}
	catch {
	}
}

function ClearPowershellHost() {
	Clear-Host
	Write-Host -f Green "[$(DateTimeString)] AutoPilot script V1 - https://andre.github.io`n"
}

$ErrorActionPreference = "Stop"
ClearPowershellHost

$global:StopWatch = [system.diagnostics.stopwatch]::StartNew()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Set-ExecutionPolicySetting -Policy "Unrestricted"

$global:GithubMain = "https://raw.githubusercontent.com/homegb/andre.github.io/main"
$global:Graph = "https://graph.microsoft.com"
$global:PCName = [System.Net.Dns]::GetHostName()

#Get Available Drives and setup directories
$global:DeployFolder = "C:\ProgramData\Deploy\AutoPilot"
$ExportFolder = @("C:\HWID")
New-Item -Type Directory -Path "$DeployFolder" -Force | Out-Null

Write-Host -f Yellow "[$(ReturnElapsed)] Get-DeviceHardwareInformation."
$DevInfo = Get-DeviceHardwareInformation

Write-Host -f White "[$(ReturnElapsed)] Get-LocalDiskDrives."
$DiskDrives = Get-LocalDiskDrives -DriveType "Removable"

foreach ($Drive in $DiskDrives) {
	$ExportFolder += "$($Drive.DriveLetter):\HWID"
}
foreach ($Folder in $ExportFolder) {
	New-Item -Type Directory -Path "$Folder" -Force | Out-Null
	Write-Host -f Cyan "[$(ReturnElapsed)] Export hardware information to: $Folder\AutopilotHWID.csv"
	$DevInfo | Export-Csv "$Folder\AutopilotHWID.csv" -NoTypeInformation
	$DevInfo | Export-Csv "$Folder\AutopilotHWID-$PCName.csv" -NoTypeInformation
}



# ========== Connect to Intune and upload AutoPilot data ========= #
Write-Host -f Yellow "[$(ReturnElapsed)] See prompt below:"
$ContinueScript = Read-Host "Type 'Yes' continue with the script and upload the device data to Intune AutoPilot"

#Connect to Intune and upload Autopilot hardware details
$ConnectToIntune = [bool]($ContinueScript -ieq "Yes")
if ($ConnectToIntune) {

	Write-Host -f White "[$(ReturnElapsed)] Setup Intune Modules."
	$ModuleInfo = SetupModules -Resources @("JwtDetails", "MSAL.PS", "AzureADPreview")

	if ($ModuleInfo.Success) {

		$GraphScopes = @( "DeviceManagementServiceConfig.ReadWrite.All" )
		$AccessTokenExpired = (-not $MsApi.ExpiresOn) -or ( [bool]$MsApi.ExpiresOn.LocalDateTime -and ($MsApi.ExpiresOn.LocalDateTime -lt (Get-Date).ToLocalTime()) )

		#$global:MsApi = Get-oAuth-IntuneToken
		$global:MsApi = Get-IntuneAzureAdToken

		if ([bool]$MsApi.AccessToken) {

			$AccessTokenExpired = (-not $MsApi.ExpiresOn) -or ( [bool]$MsApi.ExpiresOn.LocalDateTime -and ($MsApi.ExpiresOn.LocalDateTime -lt (Get-Date).ToLocalTime()) )
	
			$TokenDetails = Get-JWTDetails -token $MsApi.AccessToken

			$Org = Invoke-RestMethod -Uri "$Graph/v1.0/organization" -Method Get -Headers $authHeaders
			$OrgName = $Org.value.displayName

			#ClearPowershellHost
			if ($AccessTokenExpired -eq $false) {
				ClearPowershellHost
				Write-Host -f Green "[$(ReturnElapsed)] Connected to Intune." -NoNewline; #Write-Host -f Green "$OrgName // $($MsApi.Account.Username) // [$($TokenDetails.ipaddr)] " -NoNewline; Write-Host -f Yellow "until ($($MsApi.ExpiresOn.LocalDateTime))"

				$ConnectionInfo = [PSCustomObject]@{ 'Azure-Tenant-Name' = $OrgName; Username = $MsApi.Account.Username; IpAddress = $TokenDetails.ipaddr; 'Session-Valid-Until' = $MsApi.ExpiresOn.LocalDateTime; 'Time-To-Expiry' = $TokenDetails.timeToExpiry }
				$ConnectionInfo | Format-Table
				Write-Host "-----------------------------------------------"

				$Computers = @()
				$Computers += $DevInfo
				$importStart = Get-Date
				$NewAutoPilotDevices = @()
				if ($OutputFile.Length -gt 3) {
					if (Test-Path $OutputFile) { $Computers += Import-CSV -Path $OutputFile }
				}


				foreach ($Comp in $Computers) {
					Write-Host -f White "[$(ReturnElapsed)] Add Device to AutoPilot: [$($Comp.'Device Serial Number') - $($env:COMPUTERNAME)]"
					$NewAutoPilotDevices += Add-AutopilotImportedDevice -serialNumber $Comp.'Device Serial Number' -hardwareIdentifier $Comp.'Hardware Hash' -groupTag $Comp.'Group Tag' -assignedUser $Comp.'Assigned User'
				}
	


				$NotInAutoPilot = $NewAutoPilotDevices | Where-Object { -not $_.AutoPilotStatus -or $_.AutoPilotStatus -notmatch "Complete|ZtdDeviceAlreadyAssigned" }

				while ([bool]$NotInAutoPilot) {

					foreach ($NewDevice in $NewAutoPilotDevices) {
                        
						
						$device = Get-AutopilotImportedDevice -id $NewDevice.id

						if ($device.state.deviceImportStatus -eq "unknown") {

							$NewDevice | Add-Member "AutoPilotStatus" $device.state.deviceImportStatus -Force
							Write-Host -f Gray "[$(ReturnElapsed)] Waiting for device to be imported: " -NoNewline; Write-Host -f White "[$($device.serialNumber) | $($env:COMPUTERNAME)]"
						}
						elseif ($device.state.deviceErrorName -eq "ZtdDeviceAlreadyAssigned") {

							$deviceExists = Get-AutoPilotDeviceBySerial -SerialNumber $NewDevice.serialNumber 

							if ($deviceExists.deploymentProfileAssignmentStatus -match "assigned") {
								$NewDevice | Add-Member "AutoPilotStatus" $deviceExists.deploymentProfileAssignmentStatus -Force
								Write-Host -f Yellow "This device is already registered with AutoPilot: " -NoNewline; Write-Host -f Green "[$($deviceExists.serialNumber) - $($env:COMPUTERNAME)]"
							}
						}
						else {
							Write-Host -f Gray "[$(ReturnElapsed)] Current device state is: " -NoNewline; Write-Host -f Magenta "[$($device.state.deviceImportStatus)]" -NoNewline; Write-Host -f White "$($device.serialNumber) | $($env:COMPUTERNAME)"
						}
					}
				}
					
				$NotInAutoPilot = $NewAutoPilotDevices | Where-Object { -not $_.AutoPilotStatus -or $_.AutoPilotStatus -notmatch "Complete|assigned|ZtdDeviceAlreadyAssigned" }
				if ([bool]$NotInAutoPilot) { 
						
					Write-Host -f White "[$(ReturnElapsed)] Wait until the devices have been imported."
					Start-Sleep -Seconds 30
				}
			}

			$RegisteredInAutoPilot = $NewAutoPilotDevices | Where-Object { -not $_.AutoPilotStatus -or $_.AutoPilotStatus -eq "Complete" }

			if ([bool]$RegisteredInAutoPilot) {

				$importDuration = (Get-Date) - $importStart
				$importSeconds = [Math]::Ceiling($importDuration.TotalSeconds)
				Write-Host "[$(ReturnElapsed)] Devices imported. Elapsed time to complete AutoPilot import: $importSeconds seconds"
        
				# Wait for assignment (if specified)

				$Assign = $true

				if ($Assign) {
					$assignStart = Get-Date
					$processingCount = 1
					while ($processingCount -gt 0) {
						$processingCount = 0
						$autopilotDevices | ForEach-Object {
							$device = Get-AutopilotDevice -id $_.id -Expand
							if (-not ($device.deploymentProfileAssignmentStatus.StartsWith("assigned"))) {
								$processingCount = $processingCount + 1
							}
						}
						$deviceCount = $autopilotDevices.Length
						Write-Host "[$(ReturnElapsed)] Waiting for $processingCount of $deviceCount to be assigned"
						if ($processingCount -gt 0) {
							Start-Sleep 30
						}    
					}
					$assignDuration = (Get-Date) - $assignStart
					$assignSeconds = [Math]::Ceiling($assignDuration.TotalSeconds)
					Write-Host "[$(ReturnElapsed)] Profiles assigned to all devices. Elapsed time to complete assignment: $assignSeconds seconds"    

					Set-ExecutionPolicySetting -Policy "Default"

					if ($Reboot) {

						RebootComputer -Reboot $true -Ask $false
					}
				}
			}
			else {
				RebootComputer -Reboot $true -Ask $true
			}
		}
		else {
			Write-Host -f Red "[$(ReturnElapsed)] Unable to connect to Intune - Hardware information can't be uploaded - information is still stored locally only."
		}

	}
}
else {
	Write-Host -f Red "[$(ReturnElapsed)] Hardware information wasn't uploaded - information is still stored locally."
}



Set-ExecutionPolicySetting -Policy "Default"