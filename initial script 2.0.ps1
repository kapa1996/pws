#intro and instruction 

Write-Host -ForegroundColor Yellow ".............Windows Post Installation Script............"
write-host -ForegroundColor Red "Please Connect To Internet & Plug IT-HDD To PC"

#changing powershell execution policy

#Set-ExecutionPolicy Bypass

#cmd

#sc  delete sysmain 

#powershell

#changing the ip address based on user input
function Get-IpInput {
    $ipnput = read-host "Do You Want To Change Ip Address? Please Answer yes or no"

    switch ($ipnput) `
    {
        'yes' {

$ipadd   =  Read-Host -Prompt "Enter The Ip Address You Want to Put in  "

Get-NetAdapter

[Int32]$netadap = Read-Host -Prompt " Enter ifIndex Of The Network Adapter "

New-NetIPAddress -InterfaceIndex $netadap -IPAddress $ipadd -PrefixLength 24 -defaultgateway 192.168.2.253

Set-DnsClientServerAddress -InterfaceIndex $netadap -ServerAddresses ("192.168.2.13","192.168.2.12")
        }

        'no' {
            write-host 'IP Address Will Not Changed'
        }

        default {
            write-host 'Answer Must Be Yes or No, please try again.'
            Get-IpInput
        }
    }
}

Get-IpInput

#local admin account enable

if (get-localuser -name administrator|Where-Object {$_.enabled -eq $true}) {
    write-host -ForegroundColor Yellow "User Account Already Enabled" 
     
 }
 else {
    Write-Host -ForegroundColor Green "Enabling Admin Account !!!!!!!!" 
  $psswd = "ps$#ced212" |ConvertTo-SecureString -AsPlainText -Force 
 Get-LocalUser -Name administrator |Enable-LocalUser 
 Set-LocalUser -Name administrator -AccountNeverExpires -PasswordNeverExpires $true -Password $psswd
 }

 #firewall disable

 if (Get-NetFirewallProfile -Name public,private,domain |Where-Object {$_.enabled -EQ $true}) {
 
 #   Set-NetFirewallProfile  -Name public,private,domain -Enabled False ; write-host -ForegroundColor Yellow "Firewall Profile's Status Is Enabled "
 
#    ; Write-Host -ForegroundColor Red "Disabaling Them Now"

#manageengine Rules in and out 
New-NetFirewallRule -DisplayName "ManageEngine"  -Direction Inbound -Protocol TCP -LocalPort 8027,8383 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "ManageEngine"   -Direction Outbound -Protocol TCP -LocalPort 8027,8383 -Action Allow -Profile Any

#RDP Rule enable
New-NetFirewallRule -DisplayName "RDP IN" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Any

#TCP Rule IN
New-NetFirewallRule -DisplayName "Allow inbound ICMPv4 (Ping)" -Direction Inbound -Protocol ICMPv4 -Action Allow -Profile Any

#TCP Rule Out
New-NetFirewallRule -DisplayName "Allow inbound ICMPv4 (Ping)" -Direction Outbound -Protocol ICMPv4 -Action Allow -Profile Any

#winrm port
New-NetFirewallRule -DisplayName "Allow WINRM" -Direction Outbound -LocalPort 5985 -Action Allow -Profile Domain 

write-host -ForegroundColor DarkYellow "Firewall status is enabled, firewall rules has been applied (rules include manageengine,RDP,ICMP & WINRM)"

}
else {
Set-NetFirewallProfile  -Name public,private,domain -Enabled True ;write-host -ForegroundColor Green "Firewall Profiles Has Been Enabled"
}

#enable remote login 

write-host -ForegroundColor Yellow "Enabling remote login"

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0


#setting local time as default 

Write-Host -ForegroundColor  Yellow "Changing time setting to sri lanakan standard time"

Set-TimeZone -Id "Sri Lanka Standard Time"

#creating a checkpoint in computer

Enable-ComputerRestore  -Drive "c:\"

Checkpoint-Computer -Description "fresh windows" -RestorePointType MODIFY_SETTINGS

#software installation section
$softinstall = Read-Host "Do You Want To Install Software? Please Answer Yes Or No"

if ($softinstall |Where-Object {$_.Length -ge '3'}) {
    
    function HDD {
        
        Get-Volume |Format-List FileSystemLabel,DriveLetter
        $hdri = Read-Host -Prompt "Enter The Drive Letter Of IT-HDD (EG -'D')"
    
        switch ($hdri) {
            'D' { $hdri = Set-Location "D:\PC instrall software"}
            'E' { $hdri = Set-Location "E:\PC instrall software"}
            'F' { $hdri = Set-Location "F:\PC instrall software"}
            'G' { $hdri = Set-Location "G:\PC instrall software"}
            'H' { $hdri = Set-Location "H:\PC instrall software"}
            'I' { $hdri = Set-Location "I:\PC instrall software"}
            Default {Write-Output Please Enter A Valid Drive Letter 
            
                       HDD     }
        
        }
    }
    HDD
    
    #winrar
    .\winrar.exe /s 
    
    #vlc
    .\media_player.exe
    
    #adobe-reader
    Copy-Item .\adobe\adobereader.exe.exe ".\"
    .\adobereader.exe -wait
    
    #chrome
    .\ChromeSetup.exe
    
    #ManageEngine agent
    .\LocalOffice_Agent.exe /silent

#special Software list

#Crowdstrike virus guard
$vgurad = Read-Host "Do You Want To Install Virus Guard? Please Answer Yes Or No"
if ($vgurad |Where-Object {$_.Length -ge "3"}) {
   .\crowdstrike.exe
Write-Host -ForegroundColor Green "Please copy the organization id to the runnig crowd strike apllication = 'DB7D123102454BE68E4DB0F782DB497B-4A' " 
}
else {
    Write-Host "Virus Guard Will Be Not Installed On This Device"
}

#anydesk
$anydesk = Read-Host "Do You Want To Install ANYDESK? Please Answer Yes Or No"
if ($anydesk |Where-Object {$_.Length -ge "3"}) {
   .\AnyDesk.exe
}
else {
    Write-Host "Anydesk Will Be Not Installed On This Device"
}
#forti
$forti = Read-Host "Do You Want To Install Forticlient? Please Answer Yes Or No"
if ($forti |Where-Object {$_.Length -ge "3"}) {
    .\FortiClient.msi
}
else {
    Write-Host "Forticlient Will Be Not Installed On This Device"
}

#SAP GUI
$sap = Read-Host "Do You Want To Install SAP GUI? Please Answer Yes Or No"
if ($sap |Where-Object {$_.Length -ge "3"}) {
    .\Win64\SapGui64Setup.exe
}
else {
    Write-Host "SAP GUI Will Be Not Installed On This Device"
}

#office version install
$officeinput = Read-Host "Do You Want To Install Office On This Device? Please Answer Yes Or No"
if ($officeinput |Where-Object {$_.Length -ge "3"}) {
    function install-office {
        $office = read-host -Prompt "What version Of Office Package You Need To install? (Please Answer 0365,10,13)"
    switch ($office) {
        '0365'   {.\OfficeSetup.exe}
        '10'     {.\Office_2010w_SP1_W32_English_CORE_MLF_X17-82110_2\setup.exe /adminfile test.msp}
        '13'     {.\SW_DVD5_Office_2013w_SP1_32-BIT_X64_English_MLF_X19-34823\x64\setup.exe}
        Default  { write-host "Please Input The Correct Answer (0365,10,13)"
    
        install-office 
        }
    } 
    }
    install-office 
}
else {
    Write-Host "Office Will Be Not Installed On This Device"
}

}

else {
Write-Host "Softwares Will Be Not Installed On This Device"
}

#computer rename with serialnumber

#write-host -foregroundcolor red "renaming the computer will restart the device so make sure all softwars are finished installing"

#$cnameinput = Read-Host "Do You Want To Rename The Computer? Please Answer Yes Or No"

#if ($cnameinput |Where-Object {$_.Length -ge "3"}) {
#    wmic bios get serialnumber
#    $cname =Read-Host "Please Enter The Computername's SerialNumber (see Above)"
#    Invoke-RestMethod -Uri https://raw.githubusercontent.com/kapa1996/pws/main/part_2.ps1 | out-file -FilePath `
#    "$env:USERPROFILE\desktop\part2.ps1" 
#    Start-Sleep -Seconds 10 
#Rename-Computer -NewName $cname -Restart -Force

  
#}

#else {
#    Write-Host "Computer Name Will Not Changed"
#}

#domain Settings
#function domain {
#    $domain = Read-Host -Prompt "Do You Want To Add This Computer To Domain? Please Answer Yes Or No"
# switch ($domain) {
#     "yes" { 
#         if (Get-WmiObject -Class Win32_ComputerSystem|Where-Object {$_.PartOfDomain -like "true"}) { 
 
#         write-host "This Computer IS Already A Domain Joined Computer"
#     }
#     else {
#         $domainname =Read-Host -Prompt "Please Enter The Domain Name"
#         $getcre     =Get-Credential
#         Add-Computer -DomainName $domainname -DomainCredential $getcre
#     } }

#     'no' {Write-Host "Computer Will Not Joined To Domain"}

#     Default {Write-host Please Answer Yes Or No

#     domain   }
# }

#} 
#domain


#ckecking installed softwares on this device

read-host -prompt "Please be sure to check all the softwares are finished installing beofre checking (press ENTER to continue) "

Write-Host -ForegroundColor DarkGreen "Checking the softwares that installed on this device"

$namee = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
$namee2 = Get-WmiObject -Class win32_product
$vlc = Test-Path "C:\Program Files\VideoLAN"

#virus guard status

if ($namee2 |Where-Object {$_.vendor -eq "CrowdStrike, Inc."}) {
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

if($namee2 |Where-Object {$_.vendor -eq "Zoho Corporation Pvt. Ltd."}) {

Write-Host -ForegroundColor Cyan "Manageengine is installed on this device"}

else { Write-Host -ForegroundColor Red "Manageengine is not installed on this device"
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


#setting up powershell execution policy to restricted

#write-host  -Foregroundcolor Green "Changing Powershell Execution Policy To Restricted"
#Set-ExecutionPolicy Restricted



Read-Host -Prompt "Press ENTER key to continue"


write-host -foregroundcolor red "renaming the computer will restart the device so make sure all softwars are finished installing"

$cnameinput = Read-Host "Do You Want To Rename The Computer? Please Answer Yes Or No"

if ($cnameinput |Where-Object {$_.Length -ge "3"}) {
    wmic bios get serialnumber
    $cname =Read-Host "Please Enter The Computername's SerialNumber (see Above)"
#    Invoke-RestMethod -Uri https://raw.githubusercontent.com/kapa1996/pws/main/part_2.ps1 | out-file -FilePath `
#    "$env:USERPROFILE\desktop\part2.ps1" 
Write-Host -ForegroundColor Red "Computer will Restart in 10 Seconds !!!!!!!!!"
Write-host -Foregroundcolor yellow "......................................End Of Script..................................."
Start-Sleep -Seconds 10 
Rename-Computer -NewName $cname -Restart -Force

}

