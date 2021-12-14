
<#
.SYNOPSIS
  The "Start-PowerShellAsDiffUser" function spawns a PowerShell prompt with the given credentials.

.EXAMPLE
  PS C:\> Start-PowerShellAsDiffUser -Username b-Jannus.Fugal
  Enter in the Password for 'b-Jannus.Fugal': ********************************

  The '-Username' supplied did not specify the associated Domain, so the default of 'corp' has been specified as the Domain.
  If you want to specify a Domain, rerun this function with the '-Domain' parameter.

  If the account is a local user account, rerun this function with the '-LocalAccount' parameter (and if the Local Account is on a remote machine,
  also use '-LocalAccountHostname').

  Since some applications will not work properly without specifying the Domain, the -Username value has been updated to:  corp\b-Jannus.Fugal


  ################################
  # A SEPARATE TERMINAL WINDOW IS CREATED
  
  Hello:
  These creds work...
  PS C:\> whoami
  corp\b-Jannus.Fugal
  PS C:\>



  Here we run the function by specifying a particular '-Username'.  We are then prompted for the password of the user, and because the credentials were valid, another PowerShell terminal window appeared where we validated the user we were running the shell with by issuing the "whoami" command.

.NOTES
  Name:  Start-PowerShellAsDiffUser.ps1
  Author:  Travis Logue
  Version History:  2.1 | 2021-12-13 | Total refactor of the tool
  Dependencies:  
  Notes:
  - This discussion on "Start-Process" saved my sanity: https://stackoverflow.com/questions/7319658/start-process-raises-an-error-when-providing-credentials-possible-bug
    * The error I was receiving was this: "Start-Process : This command cannot be run due to the error: The directory name is invalid."
    * The first fix to simply get rid of that error was actually found in a comment of:  "I've found that if you specify something like -WorkingDirectory C:\ , it fixes the problem. "
    * The second fix was to actually get a functioning PowerShell prompt... that was achieved by considering this code, and then modifying it to my purposes (which is what is used in the function below):   Start-Process $PSHOME\powershell.exe -ArgumentList "-NoExit","-Command `"&{`$outvar1 = 4+4; `"write-output `"Hello:`"`$outvar1`"}`"" -Wait  


  .
#>

function Start-PowerShellAsDiffUser {
  [CmdletBinding()]
  [Alias('StartPowerShellAsDiffUser', 'PowerShellAsDiffUser')]
  param (
    [Parameter(HelpMessage='Reference a PSCredential object.')]
    [pscredential]
    $Credential,
    [Parameter(HelpMessage="Reference the 'Username' of the credential.")]
    [string]
    $Username,
    [Parameter(HelpMessage="This parameter expects a SecureString object.  Reference the SecureString object of the password for the corresponding Username.")]
    [securestring]
    $Password,
    [Parameter(HelpMessage='Reference the Domain of the User you are testing. DEFAULT = "corp"')]
    [string]
    $Domain,
    [Parameter(HelpMessage='If the Username is a Local Account, use this Switch Parameter')]
    [switch]
    $LocalAccount,
    [Parameter(HelpMessage='If the Username is a Local Account, and the computer is a remote machine, use this parameter to specify the Computername of that remote machine.')]
    [string]
    $LocalAccountHostname
  )
  
  begin {}
  
  process {

    if ($Credential) {

      $cred = $Credential

      Start-Process -FilePath powershell.exe -Credential $cred -WorkingDirectory c:\  -Wait -ArgumentList '-noexit', "-Command `"&{`$outvar1 = `'These creds work...`'; `"write-output `"Hello: `"`$outvar1`"}`"" -LoadUserProfile
      
    }
    else {

      if (-not ($Username)) {
        $Username = Read-Host "Enter in the Username of the account" 
      }

      if (-not ($Password)) {
        $Password = Read-Host "Enter in the Password for '$Username'" -AsSecureString
      }

      if ($LocalAccount) {  

        if ($LocalAccountHostname) {
          $Username = "$LocalAccountHostname\$Username"
        }
        else {
          $Username = "$(HOSTNAME.EXE)\$Username"
        }

        Write-Host "`nUsing the identity of: " -NoNewline -BackgroundColor Black -ForegroundColor Yellow
        Write-Host "$Username`n"
    
        $cred = New-Object System.Management.Automation.PSCredential ($Username, $Password)
  
      }
      else {

        if ($Domain) {
          $Username = "$Domain\$Username"
          Write-Host "`nUsing the identity of: " -NoNewline -BackgroundColor Black -ForegroundColor Yellow
          Write-Host "$Username`n"
        }
        elseif ($Username -like "*\*") {
          $Username = $Username
          Write-Host "`nUsing the identity of: " -NoNewline -BackgroundColor Black -ForegroundColor Yellow
          Write-Host "$Username`n"
        }
        else {
          $Username = "corp\$Username"
          Write-Host "`nThe '-Username' supplied did not specify the associated Domain, so the default of 'corp' has been specified as the Domain. `nIf you want to specify a Domain, rerun this function with the '-Domain' parameter.`n`nIf the account is a local user account, rerun this function with the '-LocalAccount' parameter (and if the Local Account is on a remote machine, also use '-LocalAccountHostname').`n`nSince some applications will not work properly without specifying the Domain, the -Username value has been updated to:" -ForegroundColor Yellow -BackgroundColor Black -NoNewline
          Write-Host "  $Username`n"
        }

        $cred = New-Object System.Management.Automation.PSCredential ($Username, $Password)
          
      } 
      
      <# TEMPLATE
      $DomainName = HOSTNAME.EXE
      runas.exe /user:$DomainName\$Username "powershell.exe -noexit -command {The credentials work...}"
      #>

      Start-Process -FilePath powershell.exe -Credential $cred -WorkingDirectory c:\  -Wait -ArgumentList '-noexit', "-Command `"&{`$outvar1 = `'These creds work...`'; `"write-output `"Hello: `"`$outvar1`"}`"" -LoadUserProfile

    }


  }
  
  end {}
}