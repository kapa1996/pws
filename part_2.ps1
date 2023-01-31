#domain Settings
function domain {
    $domain = Read-Host -Prompt "Do You Want To Add This Computer To Domain? Please Answer Yes Or No"
 switch ($domain) {
     "yes" { 
         if (Get-WmiObject -Class Win32_ComputerSystem|Where-Object {$_.PartOfDomain -like "true"}) { 
 
         write-host "This Computer IS Already A Domain Joined Computer"
     }
     else {
         $domainname =Read-Host -Prompt "Please Enter The Domain Name"
         $getcre     =Get-Credential
         Add-Computer -DomainName $domainname -DomainCredential $getcre
     } }

     'no' {Write-Host "Computer Will Not Joined To Domain"}

     Default {Write-host Please Answer Yes Or No

     domain   }
 }

} 
domain

#setting up powershell execution policy to restricted

write-host  -Foregroundcolor Green "Changing Powershell Execution Policy To Restricted"
Set-ExecutionPolicy Restricted


$namee = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
$namee2 = Get-WmiObject -Class win32_product

#virus guard status

if ($namee |Where-Object {$_.Publisher -eq "Kaspersky"}) {
 Write-Host -ForegroundColor Cyan "Virus guard is installed on this device"}
else {
     Write-Host -ForegroundColor red "Virus guard is not installed on this device"
 }


#vpn status

if ($namee2 |Where-Object {$_.vendor -eq "Fortinet Technologies Inc"}) {
 Write-Host -ForegroundColor Cyan "VPN client is installed on this device"
}

else {
 Write-Host -ForegroundColor red "VPN client is not installed on this device"
}

#adobe reader status

if ($namee2 |Where-Object {$_.vendor -like "*Adobe*"}) {

Write-Host -ForegroundColor Cyan "Adobe reader is insttaled on this device"}

else { Write-Host -ForegroundColor Red "Adobe reader is not installed on this device"
}

#manageengine status

if($namee2 |Where-Object {$_.vendor -eq "ZohoCorp"}) {

Write-Host -ForegroundColor Cyan "Manageengine is installed on this device"}

else { Write-Host -ForegroundColor Red "Manageengine is installed on this device"
}

#anydesk status

if ( $namee |Where-Object {$_.Publisher -eq "philandro Software GmbH"}){

Write-Host -ForegroundColor Cyan "Anydesk is installed on this device"}

else { Write-Host -ForegroundColor red "Anydesk is not installed on this device"
}

#SAP status

if ($namee |Where-Object {$_.publisher -eq "SAP SE"}){

Write-Host -ForegroundColor Cyan "SAP is installed on this device"}

else {Write-Host -ForegroundColor Red "SAP is not installed on this device"
}

#Chrome status

if ($namee |Where-Object {$_.Publisher -eq "Google LLC"}) {

Write-Host -ForegroundColor Cyan "Google chrome is installed on this device"
}

else{Write-Host -ForegroundColor Red "Google chrome is not installed on this device"

}


#deleting the powershell script that downloaded

Remove-Item -Path -Force "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\part2.ps1"

Start-Sleep -Seconds 10

Write-host -Foregroundcolor yellow "......................................End Of Script..................................."


