<#
.SYNOPSIS
  The "Watch-ProcessCreationEvents4688" function monitors the Security .evtx log for Event ID 4688, which shows Process Creation Events and full command line invocation (see the Notes section for information details, and the Example for a demonstration). The function watches for new 4688 events, parses the log, and displays the pertinent information to the terminal.

.EXAMPLE
  PS C:\> Watch-ProcessCreationEvents4688
  TimeCreated: 2022-01-10 18:47:25.876 RecordID: 550020
  ProcessOwner: CORP\Jannus.Fugal
  PID: 18184 ProcessName: C:\Windows\System32\notepad.exe
  PPID: 6684 ParentProcessName: C:\Windows\explorer.exe
          CommandLine: "C:\WINDOWS\system32\notepad.exe"

  TimeCreated: 2022-01-10 18:47:25.989 RecordID: 550021
  ProcessOwner: CORP\LocLaptop-PC1$
  PID: 18776 ProcessName: C:\Windows\System32\backgroundTaskHost.exe
  PPID: 1004 ParentProcessName: C:\Windows\System32\svchost.exe
          CommandLine: "C:\WINDOWS\system32\BackgroundTaskHost.exe" -ServerName:BackgroundTaskHost.WebAccountProvider

  TimeCreated: 2022-01-10 18:47:27.503 RecordID: 550022
  ProcessOwner: CORP\LocLaptop-PC1$
  PID: 6908 ProcessName: C:\Windows\System32\RuntimeBroker.exe
  PPID: 1004 ParentProcessName: C:\Windows\System32\svchost.exe
          CommandLine: C:\Windows\System32\RuntimeBroker.exe -Embedding



  Here we run the function and then open "notepad.exe" in order to generate events.  The function does a "watch" or a "tail" of the Security log for Event ID 4688, parses the output, and displays the parsed output to the terminal.

.NOTES
  Name:  Watch-ProcessCreationEvents4688.ps1
  Author:  Travis Logue
  Version History:  1.1 | 2022-01-08 | Initial Version
  Dependencies:  Command Line Process Auditing Event ID 4688 (see Notes)
  Notes:
  - Enable Audit Process Creation to see Event ID 4688:  https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
  - Event ID 4688 details:  https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688


  .
#>
function Watch-ProcessCreationEvents4688 {
  [CmdletBinding()]
  [Alias('ProcessCreationWatch4688')]
  param ()
  
  begin {

    function Convert-HexToInteger {
      [CmdletBinding()]
      param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]
        $HexString,
        [Parameter()]
        [switch]
        $Join,
        [Parameter()]
        [switch]
        $RemoveHexNotation
      )
      
      begin {}
      
      process {
    
        $array = @( $HexString )
    
      }
      
      end {
    
        if ($RemoveHexNotationFromInput) {
          $HexToInt = $array | % { [convert]::ToInt16( $_.TrimStart('0x'), 16) }
        }
        else {
          $HexToInt = $array | % { [convert]::ToInt16($_, 16) }
        }
    
        if ($Join) {
          $HexToInt -join ' '
        }
        else {
          Write-Output $HexToInt
        }
    
      }
    }

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
    
      $CreatorAccountName = Invoke-LineParser $Message[4]
      $CreatorAccountDomain = Invoke-LineParser $Message[5]
    
      $dictionary = @{
        RecordID = $Log.RecordID
        PID = Invoke-LineParser $Message[15]| Convert-HexToInteger -RemoveHexNotation
        ProcessName = Invoke-LineParser $Message[16]
        ProcessOwner = "$CreatorAccountDomain\$CreatorAccountName"
        PPID = Invoke-LineParser $Message[19] | Convert-HexToInteger -RemoveHexNotation
        ParentProcessName = Invoke-LineParser $Message[20]
        TimeCreated = $Log.TimeCreated
        CommandLine = Invoke-LineParser $Message[21]
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
      LogName = 'Security'
      ID = 4688
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