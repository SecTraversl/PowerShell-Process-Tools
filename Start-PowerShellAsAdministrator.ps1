<#
.SYNOPSIS
  The "Start-PowerShellAsAdministrator" function spawns an Administrator PowerShell shell.

.EXAMPLE
  PS C:\> Start-PowerShellAsAdministrator


  ################################
  # A SEPARATE TERMINAL WINDOW IS CREATED
  
  Windows PowerShell
  Copyright (C) Microsoft Corporation. All rights reserved.

  Try the new cross-platform PowerShell https://aka.ms/pscore6

  PS C:\WINDOWS\system32>



  Here we run the function and another PowerShell terminal window appears in the default directory of an Administrator shell, "C:\WINDOWS\system32>".

.NOTES
  Name:  Start-PowerShellAsAdministrator.ps1
  Author:  Travis Logue
  Version History:  1.1 | 2021-12-31 | Initial Version
  Dependencies:  
  Notes:
  - This is where I retrieved the syntax:  https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-7.2#example-5--start-powershell-as-an-administrator

  .
#>
function Start-PowerShellAsAdministrator {
  [CmdletBinding()]
  [Alias('PowerShellAsAdministrator')]
  param (
    [Parameter()]
    [switch]
    $NoProfile
  )
  
  begin {}
  
  process {

    if ($NoProfile) {
      Start-Process -FilePath "powershell" -Verb RunAs -ArgumentList "-NoProfile"
    }
    else {
      Start-Process -FilePath "powershell" -Verb RunAs
    }

  }
  
  end {}
}