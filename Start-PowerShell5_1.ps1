<#
.SYNOPSIS
  The "Start-PowerShell5_1" function starts a subprocess shell of Windows Powershell 5.1 (or whatever version of PowerShell exists in the following location: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" )

.EXAMPLE
  PS C:\> $PSVersionTable.PSVersion


  Major  Minor  Patch  PreReleaseLabel BuildLabel
  -----  -----  -----  --------------- ----------
  7      2      1

  PS C:\> Start-PowerShell5.1  
  PS C:\>
  PS C:\> $PSVersionTable.PSVersion

  Major  Minor  Build  Revision
  -----  -----  -----  --------
  5      1      19041  1320  



  Here we run the function and Windows PowerShell 5.1 is started in our terminal.

.NOTES
  Name:  Start-PowerShell5_1.ps1
  Author:  Travis Logue
  Version History:  1.1 | 2022-02-07 | Initial Version
  Dependencies:  
  Notes:
  - 

  .
#>
function Start-PowerShell5_1 {
  [CmdletBinding()]
  [Alias('PowerShell5_1')]
  param ()
  
  begin {}
  
  process {
    & 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
  }
  
  end {}
}