# PowerShell - Zerto Virtual Manager Post Recovery VM Resize Script (vCloud Director version)

This script is intended to be run by the Zerto Virtual Manager server as a Post-recovery Script not directly called from CLI. This allows for different sized resource requirements in the DR site (typically less).
## .EXAMPLE
    . "C:\Support\Scripts\Zerto-DesiredConfiguration.ps1" -manualTestMode
## .NOTES 
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
  #Exported Credentials need to be created by the account running the script
