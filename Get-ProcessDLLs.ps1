<#
.SYNOPSIS
  The "Get-ProcessDLLs" function retrieves running processes along with the DLLs/modules that each process has loaded.

.EXAMPLE
  PS C:\> $DLLsUsedByRunningProcesses = Get-ProcessDLLs
  PS C:\> $DLLsUsedByRunningProcesses | select -f 10

  ProcessName    Id Modules
  -----------    -- -------
  Idle            0
  System          4
  Secure System  56
  Registry      108
  svchost       124 {System.Diagnostics.ProcessModule (svchost.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostic...
  OUTLOOK       128 {System.Diagnostics.ProcessModule (OUTLOOK.EXE), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostic...
  smss          424
  fontdrvhost   460 {System.Diagnostics.ProcessModule (fontdrvhost.exe), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagno...
  audiodg       504 {System.Diagnostics.ProcessModule (AUDIODG.EXE), System.Diagnostics.ProcessModule (ntdll.dll), System.Diagnostic...
  csrss         664



  Here we run the function to retrieve modules/DLLs associated with running processes. We then select the first 10 objects that were returned.

.EXAMPLE
  PS C:\> $DLLsUsedByRunningProcessesGrouped = ProcessDLLs -GroupByModule
  PS C:\> $DLLsUsedByRunningProcessesGrouped | select -f 15 | ft -AutoSize

  Count Name
  ----- ----
    224 C:\WINDOWS\SYSTEM32\ntdll.dll
    215 C:\WINDOWS\System32\ucrtbase.dll
    215 C:\WINDOWS\System32\KERNELBASE.dll
    215 C:\WINDOWS\System32\KERNEL32.DLL
    214 C:\WINDOWS\System32\msvcp_win.dll
    213 C:\WINDOWS\System32\sechost.dll
    213 C:\WINDOWS\System32\RPCRT4.dll
    213 C:\WINDOWS\System32\msvcrt.dll
    212 C:\WINDOWS\System32\combase.dll
    209 C:\WINDOWS\System32\advapi32.dll
    204 C:\WINDOWS\System32\bcryptPrimitives.dll
    200 C:\WINDOWS\System32\win32u.dll
    198 C:\WINDOWS\System32\user32.dll
    198 C:\WINDOWS\System32\gdi32full.dll
    198 C:\WINDOWS\System32\GDI32.dll



  Here we run the function by using its built-in alias 'ProcessDLLs' and by implementing the "-GroupByModule" switch parameter (which will take the the modules/DLLs loaded by each running process and group them together, thereby showing the frequency of occurrence for each DLL).  We then select the first 15 results.

.NOTES
  Name:  Get-ProcessDLLs.ps1
  Author:  Travis Logue
  Version History:  1.1 | 2022-01-06 | Initial Version
  Dependencies:  
  Notes:
  - 

  .
#>
function Get-ProcessDLLs {
  [CmdletBinding()]
  [Alias('ProcessDLLs')]
  param (
    [Parameter()]
    [switch]
    $GroupByModule
  )
  
  begin {}
  
  process {
    $Results = Get-Process | Sort-Object Id | Select-Object ProcessName, Id, Modules

    if ($GroupByModule) {
      $Results = $Results.Modules | Group-Object FileName -NoElement | Sort-Object Count,Name -Descending
    }
  }
  
  end {
    Write-Output $Results
  }
}