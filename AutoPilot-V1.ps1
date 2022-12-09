function Convert-Bytes-ToGB($Value) {            
     
	$Value = $Value / 1GB #$Value / 1MB
	$DecimalPlaces = 2

	return [Math]::Round($value, $DecimalPlaces, [MidPointRounding]::AwayFromZero)
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

	# Defining Variables
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

	Write-Verbose "POST $Uri`n$json"

	try {
		Invoke-RestMethod -Url $Uri Post -Content $json -Headers $authHeaders
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
	
	Write-Verbose "GET $uri"
	
	try {
		$response = Invoke-RestMethod -Url $uri -Headers $authHeaders
		if ($id) {
			$response
		}
		else {
			$devices = $response.value
		
			$devicesNextLink = $response."@odata.nextLink"
		
			while ($null -ne $devicesNextLink) {
				$devicesResponse = (Invoke-RestMethod -Url $devicesNextLink -Headers $authHeaders)
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
		Invoke-RestMethod -Uri "$Graph/beta/deviceManagement/windowsAutopilotDeviceIdentities/$deviceId/UpdateDeviceProperties" -POST -Headers $authHeaders -ContentType "application/json" `
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
				Import-Module -Name "$DeployFolder\$Resource\*\$Resource.psd1" | Out-Null
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

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$global:GithubMain = "https://raw.githubusercontent.com/homegb/andre.github.io/main"
$global:Graph = "https://graph.microsoft.com"

#Get Available Drives and setup directories
$DeployFolder = "C:\ProgramData\Deploy\AutoPilot"
$ExportFolder = @("C:\HWID")
New-Item -Type Directory -Path "$DeployFolder" -Force | Out-Null

Write-Host -f Yellow "Get-DeviceHardwareInformation."
$DevInfo = Get-DeviceHardwareInformation

Write-Host -f Yellow "Get-DeviceHardwareInformation."
$DiskDrives = Get-LocalDiskDrives -DriveType "Removable"

foreach ($Drive in $DiskDrives) {
	$ExportFolder += "$($Drive.DriveLetter):\HWID"
}
foreach ($Folder in $ExportFolder) {
	New-Item -Type Directory -Path "$Folder" -Force | Out-Null
	Write-Host -f Cyan "Export hardware information to: $Folder\AutopilotHWID.csv"
	$DevInfo | Export-Csv "$Folder\AutopilotHWID.csv" -NoTypeInformation
}



# ========== Connect to Intune and upload AutoPilot data ========= #
Write-Host -f Yellow "See prompt below:"
$ContinueScript = Read-Host "Type 'Yes' continue with the script and upload the device data to Intune AutoPilot"

#Connect to Intune and upload Autopilot hardware details
$ConnectToIntune = [bool]($ContinueScript -ieq "Yes")
if ($ConnectToIntune) {

	$ModuleInfo = SetupModules -Resources @("JwtDetails", "MSAL.PS")

	if ($ModuleInfo.Success) {

		$GraphScopes = @( "DeviceManagementServiceConfig.ReadWrite.All" )
		$AccessTokenExpired = (-not $MsApi.ExpiresOn) -or ( [bool]$MsApi.ExpiresOn.LocalDateTime -and ($MsApi.ExpiresOn.LocalDateTime -lt (Get-Date).ToLocalTime()) )

		if ($AccessTokenExpired) {
			$global:MsApi = Get-MsalToken -ClientId "d1ddf0e4-d672-4dae-b554-9d5bdfd93547" -TenantId "common" -RedirectUri "urn:ietf:wg:oauth:2.0:oob" -Interactive -Scopes $GraphScopes
		}

		if ([bool]$MsApi.AccessToken) {

			$global:authHeaders = @{ "Content-Type" = "application/json"; "Authorization" = "Bearer " + $MsApi.AccessToken; "ExpiresOn" = $MsApi.ExpiresOn }
			$AccessTokenExpired = (-not $MsApi.ExpiresOn) -or ( [bool]$MsApi.ExpiresOn.LocalDateTime -and ($MsApi.ExpiresOn.LocalDateTime -lt (Get-Date).ToLocalTime()) )
	
			$TokenDetails = Get-JWTDetails -token $MsApi.AccessToken

			$Org = Invoke-RestMethod -Uri "$Graph/v1.0/organization" -Method Get -Headers $authHeaders
			$OrgName = $Org.value.displayName

			#Clear-Host
			if ($AccessTokenExpired -eq $false) {
				Write-Host -f Yellow "Connected to Intune." -NoNewline; #Write-Host -f Green "$OrgName // $($MsApi.Account.Username) // [$($TokenDetails.ipaddr)] " -NoNewline; Write-Host -f Yellow "until ($($MsApi.ExpiresOn.LocalDateTime))"

				$ConnectionInfo = [PSCustomObject]@{ 'Azure-Tenant-Name' = $OrgName; Username = $MsApi.Account.Username; IpAddress = $TokenDetails.ipaddr; 'Session-Valid-Until' = $MsApi.ExpiresOn.LocalDateTime; 'Time-To-Expiry' = $TokenDetails.timeToExpiry }
				$ConnectionInfo | Format-Table
			}

			$Computers = @()
			$Computers += $DevInfo
			$importStart = Get-Date
			$imported = @()
			if ($OutputFile.Length -gt 3) {
				if (Test-Path $OutputFile) { $Computers += Import-CSV -Path $OutputFile }
			}

			if ($ConnectToIntune) {

				$Assign = $true

				$Computers | ForEach-Object {
					$imported += Add-AutopilotImportedDevice -serialNumber $_.'Device Serial Number' -hardwareIdentifier $_.'Hardware Hash' -groupTag $_.'Group Tag' -assignedUser $_.'Assigned User'
				}
	

				# Wait until the devices have been imported
				$processingCount = 1
				while ($processingCount -gt 0) {
					$current = @()
					$processingCount = 0
					$imported | ForEach-Object {
						$device = Get-AutopilotImportedDevice -id $_.id
						if ($device.state.deviceImportStatus -eq "unknown") {
							$processingCount = $processingCount + 1
						}
						$current += $device
					}
					$deviceCount = $imported.Length
					Write-Host "Waiting for $processingCount of $deviceCount to be imported"
					if ($processingCount -gt 0) {
						Start-Sleep 30
					}
				}
				$importDuration = (Get-Date) - $importStart
				$importSeconds = [Math]::Ceiling($importDuration.TotalSeconds)
				Write-Host "All devices imported. Elapsed time to complete import: $importSeconds seconds"
        
				# Wait until the devices can be found in Intune (should sync automatically)
				$syncStart = Get-Date
				$processingCount = 1
				while ($processingCount -gt 0) {
					$autopilotDevices = @()
					$processingCount = 0
					$current | ForEach-Object {
						$device = Get-AutopilotDevice -id $_.state.deviceRegistrationId
						if (-not $device) {
							$processingCount = $processingCount + 1
						}
						$autopilotDevices += $device                    
					}
					$deviceCount = $autopilotDevices.Length
					Write-Host "Waiting for $processingCount of $deviceCount to be synced"
					if ($processingCount -gt 0) {
						Start-Sleep 30
					}
				}
				$syncDuration = (Get-Date) - $syncStart
				$syncSeconds = [Math]::Ceiling($syncDuration.TotalSeconds)
				Write-Host "All devices synced. Elapsed time to complete sync: $syncSeconds seconds"

				# Add the device to the specified AAD group
				if ($AddToGroup) {
					$aadGroup = Get-AzureADGroup -Filter "DisplayName eq '$AddToGroup'"
					if ($aadGroup) {
						$autopilotDevices | ForEach-Object {
							$aadDevice = Get-AzureADDevice -ObjectId "deviceid_$($_.azureActiveDirectoryDeviceId)"
							if ($aadDevice) {
								Write-Host "Adding device $($_.serialNumber) to group $AddToGroup"
								Add-AzureADGroupMember -ObjectId $aadGroup.ObjectId -RefObjectId $aadDevice.ObjectId
							}
							else {
								Write-Error "Unable to find Azure AD device with ID $($_.azureActiveDirectoryDeviceId)"
							}
						}
						Write-Host "Added devices to group '$AddToGroup' ($($aadGroup.ObjectId))"
					}
					else {
						Write-Error "Unable to find group $AddToGroup"
					}
				}

				# Assign the computer name
				if ($AssignedComputerName -ne "") {
					$autopilotDevices | ForEach-Object {
						Set-AutopilotDevice -Id $_.Id -displayName $AssignedComputerName
					}
				}

				# Wait for assignment (if specified)
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
						Write-Host "Waiting for $processingCount of $deviceCount to be assigned"
						if ($processingCount -gt 0) {
							Start-Sleep 30
						}    
					}
					$assignDuration = (Get-Date) - $assignStart
					$assignSeconds = [Math]::Ceiling($assignDuration.TotalSeconds)
					Write-Host "Profiles assigned to all devices. Elapsed time to complete assignment: $assignSeconds seconds"    
					if ($Reboot) {

						Write-Host -f Green "Your computer will be restarted soon."

						Start-Sleep 15

						Restart-Computer -Force
					}
				}
			}
			else {
				Write-Host -f Cyan "Hardware information stored locally only."
			}
		}
	}
	else {
		Write-Host -f Red "Hardware information can't be uploaded - information is still stored locally only."
	}
}
