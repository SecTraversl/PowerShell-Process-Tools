<#
.SYNOPSIS
  The "Watch-ProcessCreationEventsSysmon" function monitors the Sysmon .evtx log (Microsoft-Windows-Sysmon%4Operational.evtx) for Event ID 1, which shows Process Creation Events and full command line invocation. The function watches for new process creation events, parses the log, and displays the pertinent information to the terminal.  Requires Sysmon to be installed (see Notes for more info).

.EXAMPLE
  PS C:\> Watch-ProcessCreationEventsSysmon
  TimeCreated: 2022-01-10 18:49:14.664 RecordID: 932651
  ProcessOwner: CORP\Jannus.Fugal
  PID: 3452 ProcessName: C:\Windows\System32\notepad.exe
  PPID: 6684 ParentProcessName: C:\Windows\explorer.exe
          CommandLine: C:\WINDOWS\Explorer.EXE



  Here we run the function and then open "notepad.exe" in order to generate events.  The function does a "watch" or a "tail" of the Sysmon log for Event ID 1, parses the output, and displays the parsed output to the terminal.

.NOTES
  Name:  Watch-ProcessCreationEventsSysmon.ps1
  Author:  Travis Logue
  Version History:  1.1 | 2022-01-08 | Initial Version
  Dependencies:  Sysmon
  Notes:
  - Sysmon information:  https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon


  .
#>
function Watch-ProcessCreationEventsSysmon {
  [CmdletBinding()]
  [Alias('ProcessCreationWatchSysmon')]
  param ()
  
  begin {

    function Invoke-LineParser {
      [CmdletBinding()]
      param (
        [Parameter(Mandatory)]
        [System.Object]
        $Line
      )
    
      $Line.Split(':',2)[-1].Trim()
    
    }
    
    function Invoke-LogParser {
      [CmdletBinding()]
      param (
        [Parameter(Mandatory)]
        [System.Object]
        $Log
      )
    
      $Message = $Log.Message.Split("`n")
    
      $dictionary = @{
        RecordID = $Log.RecordID
        PID = Invoke-LineParser $Message[4]
        ProcessName = Invoke-LineParser $Message[5]
        ProcessOwner = Invoke-LineParser $Message[13]
        Hashes = Invoke-LineParser $Message[18]
        PPID = Invoke-LineParser $Message[20]
        ParentProcessName = Invoke-LineParser $Message[21]
        TimeCreated = $Log.TimeCreated
        CommandLine = Invoke-LineParser $Message[22]
      }
    
      Write-Host -BackgroundColor Black -NoNewline "TimeCreated: "
      Write-Host -BackgroundColor Black -NoNewline "$($dictionary['TimeCreated'].ToString('yyyy-MM-dd HH:mm:ss.fff'))" -ForegroundColor Gray
      Write-Host -BackgroundColor Black -NoNewline " RecordID: "
      Write-Host -BackgroundColor Black "$($dictionary['RecordID'])" -ForegroundColor Yellow

      Write-Host -BackgroundColor Black -NoNewline "ProcessOwner: "
      Write-Host -BackgroundColor Black "$($dictionary['ProcessOwner'])" -ForegroundColor DarkCyan
    
      Write-Host -BackgroundColor Black -NoNewline "PID: "
      Write-Host -BackgroundColor Black -NoNewline "$($dictionary['PID'])" -ForegroundColor Red
      Write-Host -BackgroundColor Black -NoNewline " ProcessName: "
      Write-Host -BackgroundColor Black "$($dictionary['ProcessName'])" -ForegroundColor Green
    
      Write-Host -BackgroundColor Black -NoNewline "PPID: "
      Write-Host -BackgroundColor Black -NoNewline "$($dictionary['PPID'])" -ForegroundColor Magenta
      Write-Host -BackgroundColor Black -NoNewline " ParentProcessName: "
      Write-Host -BackgroundColor Black "$($dictionary['ParentProcessName'])" -ForegroundColor Cyan
    
      Write-Host "`tCommandLine: $($dictionary['CommandLine'])`n"    
      
    }

  }
  
  process {
    $hashtable = @{
      LogName = 'Microsoft-Windows-Sysmon/Operational'
      ID = 1
    }

    $Primer = Get-WinEvent -FilterHashtable $hashtable -MaxEvents 1
    $Compare = $null

    while ($true) {

      Start-Sleep -Seconds 1;
      $Compare = Get-WinEvent -FilterHashtable $hashtable -MaxEvents 1

      if ($Primer.RecordId -ne $Compare.RecordId) {
        $MaxEvents = $Compare.RecordId - $Primer.RecordID
        $EventLogsToDisplay = Get-WinEvent -FilterHashtable $hashtable -MaxEvents $MaxEvents | Sort-Object RecordId
        $EventLogsToDisplay | % {Invoke-LogParser $_}
        $Primer = $Compare
      }

    }


  }
  
  end {}
}