<#
.SYNOPSIS
  The "Get-ProcessHash" function retrieves the Hash values for the running processes on a given computer.  In some cases the "Path" value of the executable is not populated, and in those cases the Hash value is not calculated.  The default for the function is to use MD5, but this can be changed by using the '-Algorithm' parameter (and the valid arguments for this parameter can be viewed by pressing the 'Tab' key).

.EXAMPLE
  PS C:\> $ProcessHashes = Get-ProcessHash
  PS C:\> $ProcessHashes | select -First 15

  Name                CreationDate          MD5Hash                          Path
  ----                ------------          -------                          ----
  System Idle Process 12/23/2021 4:51:41 PM
  System              12/23/2021 4:51:41 PM
  Secure System       12/23/2021 4:51:39 PM
  Registry            12/23/2021 4:51:39 PM
  smss.exe            12/23/2021 4:51:41 PM
  csrss.exe           12/23/2021 4:51:50 PM
  wininit.exe         12/23/2021 4:51:51 PM
  csrss.exe           12/23/2021 4:51:51 PM
  services.exe        12/23/2021 4:51:51 PM
  LsaIso.exe          12/23/2021 4:51:51 PM
  lsass.exe           12/23/2021 4:51:51 PM 8EA6FE0CDAC6DD3BAE1FADC04D168A4F C:\WINDOWS\system32\lsass.exe
  svchost.exe         12/23/2021 4:51:51 PM F586835082F632DC8D9404D83BC16316 C:\WINDOWS\system32\svchost.exe
  fontdrvhost.exe     12/23/2021 4:51:51 PM 0C8E349080DA14306299593837A44792 C:\WINDOWS\system32\fontdrvhost.exe
  svchost.exe         12/23/2021 4:51:51 PM F586835082F632DC8D9404D83BC16316 C:\WINDOWS\system32\svchost.exe
  winlogon.exe        12/23/2021 4:51:51 PM DA73454469C92DD85778A2737CC09510 C:\WINDOWS\system32\winlogon.exe


  PS C:\> Get-ProcessHash -Algorithm SHA256 | Select-Object -First 10 | Format-Table -AutoSize

  Algorithm Hash                                                             Path
  --------- ----                                                             ----
  SHA256    D4ACBCCD0A1E1E0475B46A866F54F24543536A717C12133354D9840259DF3033 C:\Program Files\OpenVPN Connect\agent_ovpnconnect_1594367...
  SHA256    60336E9BB7517FF6B7D96DD5E1F935DF5705C31FD9FDACC5410.80.D49595C45 C:\Windows\system32\ApplicationFrameHost.exe
  SHA256    A98F45BC4050E9E17345D66BE726F41269CE0340C4D2F16004BD384E1164DDDE C:\Program Files (x86)\BraveSoftware\Brave-Browser\Applica...
  SHA256    1F5EBE116590726D0F601D487F26C7FC550F62144A0F9A64022E3DC2C940F17E C:\Windows\system32\BtwRSupportService.exe
  SHA256    6538A2535817F6E9E90E3AC1726655954E0D416A77AE557AEF3E400F8FBB50EB C:\Windows\CCM\CcmExec.exe
  SHA256    BB8B199F504DB7E81CF32CE3C458D2A8533BEAC8DCEFA5DF024FA79FE132648A C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
  SHA256    B07227072C4220B199A9FB25B75FA45BF8934D104315279B0A7C4F423EF30A0C C:\Windows\CCM\RemCtrl\CmRcService.exe
  SHA256    C8256C3B78FD7BEA3622A045C07BD49372537158621298DF05A505CD8EEE56FF C:\Users\Jannus.Fugal\AppData\Local\Programs\Microsoft VS ...
  SHA256    BAF97B2A629723947539CFF84E896CD29565AB4BB68B0CEC515EB5C5D6637B69 C:\Windows\system32\conhost.exe
  SHA256    A0DF21D82DAA60F8181589F4CE96441891B6E13716F353E9D71C8B303CF398D2 C:\Windows\system32\ctfmon.exe



  Here we run the function with no additional parameters, which evaluates all running processes that has a "Path" property and calculates the MD5 hash for that executable.  

.EXAMPLE
  PS C:\> $ProcessHashesSHA256 = ProcessHash -Algorithm SHA256
  PS C:\> $ProcessHashesSHA256 | select -First 15

  Name                CreationDate          SHA256Hash                                                       Path
  ----                ------------          ----------                                                       ----
  System Idle Process 12/23/2021 4:51:41 PM
  System              12/23/2021 4:51:41 PM
  Secure System       12/23/2021 4:51:39 PM
  Registry            12/23/2021 4:51:39 PM
  smss.exe            12/23/2021 4:51:41 PM
  csrss.exe           12/23/2021 4:51:50 PM
  wininit.exe         12/23/2021 4:51:51 PM
  csrss.exe           12/23/2021 4:51:51 PM
  services.exe        12/23/2021 4:51:51 PM
  LsaIso.exe          12/23/2021 4:51:51 PM
  lsass.exe           12/23/2021 4:51:51 PM B77AA726ACD44C7C89D32DD46AA07583B88FBE2C34AED394EB6E005824E40893 C:\WINDOWS\system32\lsa...
  svchost.exe         12/23/2021 4:51:51 PM 643EC58E82E0272C97C2A59F6020970D881AF19C0AD5029DB9C958C13B6558C7 C:\WINDOWS\system32\svc...
  fontdrvhost.exe     12/23/2021 4:51:51 PM 78FC107E194699C39A62373670C1F51B60C936EC1ABB79A4C638B57409BE15E9 C:\WINDOWS\system32\fon...
  svchost.exe         12/23/2021 4:51:51 PM 643EC58E82E0272C97C2A59F6020970D881AF19C0AD5029DB9C958C13B6558C7 C:\WINDOWS\system32\svc...
  winlogon.exe        12/23/2021 4:51:51 PM 26DB419399E1DF308FC195821858B322146867CA637BC717F3982F8B0DBA6DB4 C:\WINDOWS\system32\win...



  Here we run the function and change the hash algorithm using the "-Algorithm" parameter (which contains a Validate Set Attribute, allowing us to tab through the available algorithm options) and get back a similar output as we did in the first example.

.NOTES
  Name: Get-ProcessHash.ps1
  Author: Travis Logue
  Version History: 2.1 | 2022-01-04 | Total tool update
  Dependencies:  
  Notes:
  - This was a helpful example for a good Get-CimInstance syntax: https://docs.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-5.1#example-9--getting-only-a-subset-of-properties--instead-of-all-properties
  
  - NOTE: For the Get-CimInstance syntax I had to ask for the "ExecutablePath" property... the "Property" seems to be an alias property and if that is queried we receive an error
      PS C:\> Get-CimInstance -Class Win32_Process -Property Name,Path,CreationDate
      Get-CimInstance : Invalid query
      At line:1 char:1
      + Get-CimInstance -Class Win32_Process -Property Name,Path,CreationDate
      + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
          + CategoryInfo          : InvalidArgument: (:) [Get-CimInstance], CimException
          + FullyQualifiedErrorId : HRESULT 0x80041017,Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand


  .
#>
function Get-ProcessHash {
  [CmdletBinding()]
  [Alias('ProcessHash')]
  param (
    [Parameter(HelpMessage="Specifies the cryptographic hash function to use for computing the hash value of the contents of the specified file. A cryptographic hash function includes the property that it is not possible to find two distinct inputs that generate the same hash values. Hash
    functions are commonly used with digital signatures and for data integrity. The acceptable values for this parameter are:'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'MD5', 'RIPEMD160'")]
    [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'MD5', 'RIPEMD160')]
    [String]
    $Algorithm = 'MD5'
  )
  
  begin {}
  
  process {

    # The "ExecutablePath" has a property alias of "Path", however when using 'Get-CimInstance, to avoid an error always query for the 'ExecutablePath'.
    # Then, once the query is successful, you can refer to either the 'Path' property or the 'ExecutablePath' property
    $Procs = Get-CimInstance -Class Win32_Process -Property Name,ExecutablePath,CreationDate
    $Procs = $Procs | Select-Object Name,CreationDate,Path

    $Results = @()

    $AlgorithmHashPropertyName = "$($Algorithm)Hash"

    foreach ($EachProc in $Procs) {

      if ($null -like $EachProc.Path) {
        $prop = [ordered]@{
          Name = $EachProc.Name
          CreationDate = $EachProc.CreationDate
          "$($AlgorithmHashPropertyName)" = $null
          Path = $null
        }

        $obj = New-Object -TypeName psobject -Property $prop
        $Results += $obj
      }
      else {
        if ($EachProc.Path -notin $Results.Path) {
          $TempHashResults = Get-FileHash -Path $EachProc.Path -Algorithm $Algorithm

          $prop = [ordered]@{
            Name = $EachProc.Name
            CreationDate = $EachProc.CreationDate
            "$($AlgorithmHashPropertyName)" = $TempHashResults.Hash
            Path = $TempHashResults.Path
          }

          $obj = New-Object -TypeName psobject -Property $prop
          $Results += $obj
        }
        else {
          $LookupHashResults = ($Results | ? Path -eq $EachProc.Path | Select-Object -First 1 -Property "$($AlgorithmHashPropertyName)")."$($AlgorithmHashPropertyName)"

          $prop = [ordered]@{
            Name = $EachProc.Name
            CreationDate = $EachProc.CreationDate
            "$($AlgorithmHashPropertyName)" = $LookupHashResults
            Path = $EachProc.Path
          }

          $obj = New-Object -TypeName psobject -Property $prop
          $Results += $obj
        }
      }

    }

    Write-Output $Results

  }
  
  end {}
}