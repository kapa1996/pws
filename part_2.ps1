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


#checking the installled softwares on this device

read-host -prompt "Please be sure to check all the softwares are finished installing beofre checking"

Write-Host -ForegroundColor DarkGreen "Checking the softwares that installed on this device"

$namee = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
$namee2 = Get-WmiObject -Class win32_product
$vlc = Test-Path "C:\Program Files\VideoLAN"

#virus guard status

if ($namee |Where-Object {$_.Publisher -eq "Kaspersky"}) {
    Write-Host -ForegroundColor Cyan "Virus guard is installed on this device"}
 else {
        Write-Host -ForegroundColor red "Virus guard is not installed on this device"
    }


#vpn status

if ($namee2 |Where-Object {$_.vendor -like "*Fortinet*"}) {
    Write-Host -ForegroundColor Cyan "VPN client is installed on this device"
}

else {
    Write-Host -ForegroundColor red "VPN client is not installed on this device"
}

#adobe reader status

if ($namee2 |Where-Object {$_.vendor -like "*Adobe*"}) {

Write-Host -ForegroundColor Cyan "Adobe reader is installed on this device"}

else { Write-Host -ForegroundColor Red "Adobe reader is not installed on this device"
}

#manageengine status

if($namee2 |Where-Object {$_.vendor -eq "ZohoCorp"}) {

Write-Host -ForegroundColor Cyan "Manageengine is installed on this device"}

else { Write-Host -ForegroundColor Red "Manageengine is installed on this device"
}

#anydesk status

if ( $namee |Where-Object {$_.DisplayName -like "*anyde*"}){

Write-Host -ForegroundColor Cyan "Anydesk is installed on this device"}

else { Write-Host -ForegroundColor red "Anydesk is not installed on this device"
}

#SAP status

if ($namee |Where-Object {$_.publisher -eq "SAP SE"}){

Write-Host -ForegroundColor Cyan "SAP is installed on this device"}

else {Write-Host -ForegroundColor Red "SAP is not installed on this device"
}

#Chrome status

if ($namee |Where-Object {$_.displayname -like "*Google*"}) {

Write-Host -ForegroundColor Cyan "Google chrome is installed on this device"
}

else{Write-Host -ForegroundColor Red "Google chrome is not installed on this device"

}

#vlc status 

if ($vlc -eq $true) {

    Write-Host -ForegroundColor Cyan "VLC Player is installed on this device"
}

else {
    Write-Host -ForegroundColor red "VLC Player is not installed on this device"
}

#office status 

if ($namee2 |Where-Object {$_.Name -like "*office*"}) {
    write-host -ForegroundColor Cyan "Office package is installed on this device"
}

else {
    Write-Host -ForegroundColor Red "Office package is not installed on this device"
}

#deleting the powershell script that downloaded

Remove-Item -Force -Path "$env:USERPROFILE\desktop\part2.ps1"

#setting up powershell execution policy to restricted

write-host  -Foregroundcolor Green "Changing Powershell Execution Policy To Restricted"
Set-ExecutionPolicy Restricted

Read-Host -Prompt "Press any key to continue"

Write-host -Foregroundcolor yellow "......................................End Of Script..................................."

Start-Sleep -Seconds 10

