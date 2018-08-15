<#

.SYNOPSIS
    Zerto Virtual Manager Post-recovery VM Resize Script
.DESCRIPTION
    This script is intended to be run by the Zerto Virtual Manager server as a Post-recovery Script for VM Resizing.
.PARAMETER manualTestMode
    Populates enviromentals for manual testing.
.EXAMPLE
    This script is intended to be run by the Zerto Virtual Manager server as a Post-recovery Script not directly called from CLI.
.EXAMPLE
    . "C:\Support\Scripts\Zerto-DesiredConfiguration.ps1" -manualTestMode
.NOTES 
    Author: John Milner / jfrmilner
    Requires: Powershell V4
    Filename: Zerto-DesiredConfiguration.ps1
    Version: v1.0 - 2018-06 - First Version


    A CSV file is required named as the VPG in the directory C:\Support\Scripts\PostDesiredConfiguration\, for example C:\Support\Scripts\PostDesiredConfiguration\Test-VPG01.csv
    The file requires the following fields per vm
    vm_name_sourceSite – Name as it appears in source site vCenter
    numcpu_targetSite – Desired CPU Core count
    memorymb_targetSite – Desired Memory in MB
    Example
    vm_name_sourceSite,numcpu_targetSite,memorymb_targetSite
    VM03,2,6144

    Enviromental varibles ($env) are passed to the script at launch by ZVM.
    To configue a VPG: Edit VPG\Recovery
    Command to run: powershell.exe
    Params (optional): C:\Support\Scripts\Zerto-DesiredConfiguration.ps1
    Timeout: 600 (seconds)

    Additional
    #IE first run wizard needs to be completed by the user account making web requests. (NETBIOS\ZertoDR)
        & "C:\Program Files\Internet Explorer\iexplore.exe"
    #Exported Credentials need to be created by the account running the script (sa-ndc1zvmsql)

#>

    param( 
        [Switch] #Switch Param equals true when used else false
        $manualTestMode #see manualTestMode if statement
    )


# populates environmental for testing
if ($manualTestMode) {
    $env:ZertoVPGName = 'Test-VPG01'
    $env:ZertoOperation = "Test"
    $env:ZertoHypervisorManagerIP = "vcenter01"
}

# create log
$logPathName = $("C:\Support\Scripts\Logs\" + $env:ZertoVPGName + "_" + $(Get-Date -Format 'yyyy-MM-dd') + ".log")
$VerbosePreference = "continue" #Enables Write-Verbose
Start-Transcript $LogPathName

# load support functions
. C:\Support\Scripts\Import-Export-Credentials.ps1

# Log Env
Get-ChildItem env:

# configuration variables
$timeoutVmTask = 300 # timeout value in seconds for vm startup/shutdown tasks, 300 = 5 Minutes
$zertoServer = "zvm01"
$zertoPort = "9669"
$credAD = Import-Credential -Path C:\Support\Scripts\Credentials\ZertoDR.crd #Zerto requires NetBios Name prefix but vCD requires without.
$zertoUser = 'NETBIOS\' + $credAD.UserName
$zertoPassword = $credAD.GetNetworkCredential().password

# Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -DisplayDeprecationWarnings:$false -Scope User -Confirm:$false
# vCloud connection (target)
if (!$vCDsession.IsConnected) {
 $vCDsession = Connect-CIServer -Server mycloud.timico.net -Credential $credAD -ErrorAction Stop
}
# vSphere connection (target)
if (!$vSsession.IsConnected) {
 $vSsession = Connect-VIServer -Server $env:ZertoHypervisorManagerIP -User $zertoUser -Password $zertoPassword -ErrorAction Stop
}

# enable TrustAllCerts (zvm cert is self-signed)
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


# Building Zerto API strings and invoking API
$BaseURL = "https://" + $zertoServer + ":"+$zertoPort+"/v1/"
# Authenticating with Zerto API
$xZertoSessionURL = $BaseURL + "session/add"
$AuthInfo = ("{0}:{1}" -f $zertoUser,$zertoPassword)
$AuthInfo = [System.Text.Encoding]::UTF8.GetBytes($AuthInfo)
$AuthInfo = [System.Convert]::ToBase64String($AuthInfo)
$Headers = @{Authorization=("Basic {0}" -f $AuthInfo)}
$SessionBody = '{"AuthenticationMethod": "1"}'
$TypeJSON = "application/JSON"
try {
	$xZertoSessionResponse = Invoke-WebRequest -Uri $xZertoSessionURL -Headers $Headers -Method POST -Body $SessionBody -ContentType $TypeJSON -SessionVariable zertoSessionHeader
}
catch {
	Write-Warning $_.Exception.ToString() 
	$error[0] | Format-List -Force
}
#Extracting x-zerto-session from the response
$xZertoSession = $xZertoSessionResponse.headers.get_item("x-zerto-session")
$zertoSessionHeader = @{"x-zerto-session"=$xZertoSession}

## Zerto API Rest Calls
# vpgs
$vpgsURL = $BaseURL+"vpgs"
$vpgsList = Invoke-RestMethod -Uri $vpgsURL -TimeoutSec 100 -Headers $zertoSessionHeader -ContentType $TypeJSON
$vpg = $vpgsList | Where-Object { $_.vpgname -eq $env:ZertoVPGName }
# vpgSettings (needs vpg)
$vpgSettingsURL = $BaseURL+"vpgSettings"
$vpgSettingVmIdentifier = Invoke-RestMethod -Uri $vpgSettingsURL -TimeoutSec 100 -Headers $zertoSessionHeader -Method Post -ContentType $TypeJSON -Body "{`"VpgIdentifier`" : `"$($vpg.VpgIdentifier)`"}"
$vpgSettingsURLID = $BaseURL+"vpgSettings"+"/"+$vpgSettingVmIdentifier
$vpgSettings = Invoke-RestMethod -Uri $vpgSettingsURLID -TimeoutSec 100 -Headers $zertoSessionHeader -ContentType $TypeJSON
<#
	VC Instance UUID (aka serverGuid) $global:DefaultVIServer.InstanceUuid  . vSphere moRef ID ("Managed Object Reference ID")
	1a8d30b7-1840-4389-90bc-36b00c0b2fae.vm-3325
	1a8d30b7-1840-4389-90bc-36b00c0b2fae.vm-3326
#>

# Listing Protected VMs & VPGs
$VMListURL = $BaseURL+"vms"
$VMList = Invoke-RestMethod -Uri $VMListURL -TimeoutSec 100 -Headers $zertoSessionHeader -ContentType $TypeJSON
$VMListTable = $VMList | Select-Object VmName, VpgName, UsedStorageInMB, SourceSite, TargetSite, Priority
Write-Verbose "$(Get-Date):Listing Protected VMs & VPGs"
$VMListTable | format-table -AutoSize

#vCloud PowerCLI
$OrgVdcIdentifierID = $vpgSettings.Recovery.VCD.OrgVdcIdentifier -replace 'urn:vcloud:vdc:'

# import PostDesiredConfiguration csv file
$configFile = $("C:\Support\Scripts\PostDesiredConfiguration\" + $env:ZertoVPGName + ".csv" )
$configFileImport = Import-Csv $configFile
if ($configFileImport.Count -gt 1) {
	Write-Verbose "$(Get-Date): File Import Success"
	$configFileImport | Format-Table -AutoSize
}
else {
    Write-Warning "$(Get-Date):File $($configFile) Empty/Not Found"
    break
}

# process PostDesiredConfiguration
$postDesiredConfigurationReport = @()
$resourcePoolTarget = Get-ResourcePool | Where-Object { $_.Name -match $OrgVdcIdentifierID }
if ($resourcePoolTarget.count -eq 1) {
	$VMsTarget = $resourcePoolTarget | Get-VM
    Write-Verbose "$(Get-Date): Original VM Configuration"
    $VMsTarget | Select-Object Name, NumCpu, MemoryMB, @{n="Uuid";e={$_.ExtensionData.Config.Uuid}} | ConvertTo-Csv -NoTypeInformation
	if ($VMsTarget.Count -gt 0) {

		foreach ($configFileImportVm in $configFileImport) {
		
			if ($env:ZertoOperation -eq 'Test') {
                Write-Verbose "$(Get-Date): Testing Mode"
				# Zerto adds ' - testing recovery' to VM name before vCloud GUID when testing, remove both
				$Vm = $VMsTarget | Where-Object { $_.Name -replace ' - testing recovery \(.{36}\)' -eq $configFileImportVm.vm_name_sourceSite}
			}
			else {
				# live
                # remove vCloud guid
				$Vm = $VMsTarget | Where-Object { $_.Name -replace '\(.{36}\)' -eq $configFileImportVm.vm_name_sourceSite}
			}
			
			
			if ($Vm) {
                # add vm properties from target site for summary report
				$configFileImportVm | Add-Member -Name vm_found_targetSite -MemberType NoteProperty -Value $true
				$configFileImportVm | Add-Member -Name vm_name_targetSite -MemberType NoteProperty -Value $Vm.Name
				$configFileImportVm | Add-Member -Name moref_id_targetSite -MemberType NoteProperty -Value $vm.extensiondata.moref.value
                $postDesiredConfigurationReport += $configFileImportVm

				## compare for reconfiguration requirement
				# cpu
				if ($configFileImportVm.numcpu_targetSite -eq $Vm.NumCpu) {
					$resizeCpu = $false
				}
				else {
					$resizeCpu = $true
				}
				# mem
				if ($configFileImportVm.memorymb_targetSite -eq $Vm.MemoryMB) {
					$resizeMem = $false
				}
				else {
					$resizeMem = $true
				}
				Write-Verbose "$(Get-Date): Debug: name:$($configFileImportVm.vm_name_sourceSite),resizeCpu:$($resizeCpu),resizeMem:$($resizeMem)"
				if ($resizeCpu -or $resizeMem) {

                    $timeoutVmTaskCounter = 0
					do {                                                                                                                                                                                                                                                                                   
						Write-Verbose "$(Get-Date): Waiting on VMware Tools for VM: $($Vm.Name)"
						Start-Sleep -Seconds 1
                        $timeoutVmTaskCounter++
						} until((Get-VM $Vm).ExtensionData.Guest.ToolsRunningStatus -eq "guestToolsRunning" -or $timeoutVmTaskCounter -eq $timeoutVmTask)
                    if ($timeoutVmTaskCounter -ne $timeoutVmTask) {

                        Shutdown-VMGuest -VM $Vm -Confirm:$false | Out-Null
                        $timeoutVmTaskCounter = 0
					    do {
						    Write-Verbose "$(Get-Date): Waiting on shutdown for VM: $($Vm.Name)"
						    Start-Sleep -Seconds 1
                            $timeoutVmTaskCounter++
						    } until((Get-VM $Vm).Powerstate -eq "Poweredoff" -or $timeoutVmTaskCounter -eq $timeoutVmTask)
					    if ($timeoutVmTaskCounter -ne $timeoutVmTask) {
                            Write-Verbose "$(Get-Date): Resizing VM: $($Vm.Name)"
					        Set-VM -VM $Vm -NumCPU $configFileImportVm.numcpu_targetSite -MemoryMB $configFileImportVm.memorymb_targetSite -Confirm:$false | Out-Null
					        Start-VM -VM $Vm -Confirm:$false | Out-Null
                        }
                        else {
                            Write-Warning "$(Get-Date): Waiting on shutdown for VM Timeout: $($Vm.Name)"
                        }
                    }
                    else {
                        Write-Warning "$(Get-Date): Waiting on VMware Tools for VM Timeout: $($Vm.Name)"
                    }

				}
			}
			else {
                # add vm properties from target site for summary report
                $configFileImportVm | Add-Member -Name vm_found_targetSite -MemberType NoteProperty -Value $false
                $postDesiredConfigurationReport += $configFileImportVm
				Write-Warning "$(Get-Date): Debug: VM Not Found:name:$($configFileImportVm.vm_name_sourceSite)"
			}
		}
	
	}
	else {
		Write-Warning "$(Get-Date): Error No VMs Found at Target Site location"
	}
}
else {
	Write-Warning "$(Get-Date):Error Multiple Resource Pool matches found"
}

Write-Verbose "$(Get-Date): Post Desired Configuration Report"
foreach ($postDesiredConfigurationReportItem in $postDesiredConfigurationReport) {
    
    if ($postDesiredConfigurationReportItem.vm_found_targetSite) {
        $vm = Get-VM -Id $('VirtualMachine-' + $postDesiredConfigurationReportItem.moref_id_targetSite)
        if ( $postDesiredConfigurationReportItem.numcpu_targetSite -eq $Vm.NumCpu -and $postDesiredConfigurationReportItem.memorymb_targetSite -eq $Vm.MemoryMB) {
            $vmIsDesiredConfig = $true
        }
        else {
            $vmIsDesiredConfig = $false
        }
        
    }
    else {
        $vmIsDesiredConfig = $false
    }

    $postDesiredConfigurationReportItem | Add-Member -Name vmIsDesiredConfig -MemberType NoteProperty -Value $vmIsDesiredConfig
}
Write-Verbose "$(Get-Date): Post Desired Configuration Report csv"
$postDesiredConfigurationReport | ConvertTo-Csv -NoTypeInformation
Write-Verbose "$(Get-Date): Post Desired Configuration Report list"
$postDesiredConfigurationReport | Format-List

Write-Verbose "$(Get-Date): Script End"
Stop-Transcript
