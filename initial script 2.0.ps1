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
    Write-Host -ForegroundColor Green "Enabling Admin Account !!!!" 
  $psswd = Read-Host -Prompt "Enter Administrator Password" -AsSecureString 
 Get-LocalUser -Name administrator |Enable-LocalUser 
 Set-LocalUser -Name administrator -AccountNeverExpires -PasswordNeverExpires $true -Password $psswd
 }

 #firewall disable

 if (Get-NetFirewallProfile -Name public,private,domain |Where-Object {$_.enabled -EQ $true}) {
 
    Set-NetFirewallProfile  -Name public,private,domain -Enabled False ; write-host -ForegroundColor Yellow "Firewall Profile's Status Is Enabled "
 
    ; Write-Host -ForegroundColor Red "Disabaling Them Now"
}
else {
    write-host -ForegroundColor Green "Firewall Profiles Has Been Already Disabled"
}

#enable remote login 

write-host -ForegroundColor Yellow "Enabling remote login"

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0


#setting local time as default 

Write-Host -ForegroundColor  Yellow "Changing time setting to sri lanakan standard time"

Set-TimeZone -Id "Sri Lanka Standard Time"

#software installation section
$softinstall = Read-Host "Do You Want To Install Software? Please Answer Yes Or No"
Get-volume |Format-List DriveLetter,Size,SizeRemaining,FileSystem,friendlyname

if ($softinstall |Where-Object {$_.Length -ge '3'}) {
    
    function HDD {
    
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
    .\vlc.exe
    
    #adobe-reader
    Copy-Item .\adobe\adobereader.exe.exe ".\"
    .\adobereader.exe -wait
    
    #chrome
    .\ChromeSetup.exe
    
    #ManageEngine agent
    .\LocalOffice_Agent.exe

#special Software list

#kaspersky virus guard
$vgurad = Read-Host "Do You Want To Install Virus Guard? Please Answer Yes Or No"
if ($vgurad |Where-Object {$_.Length -ge "3"}) {
   .\installer_Workstation.exe
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
    '.\SAP 7.6 Win32\SapGuiSetup.exe'
}
else {
    Write-Host "SAP GUI Will Be Not Installed On This Device"
}

#office 2010
$office10 = Read-Host "Do You Want To Install Office 10? Please Answer Yes Or No"
if ($office10 |Where-Object {$_.Length -ge "3"}) {
    .\Office_2010w_SP1_W32_English_CORE_MLF_X17-82110_2\setup.exe /adminfile test.msp
}
else {
    Write-Host "Office 10 Will Be Not Installed On This Device"
}

#office 365
$365 = Read-Host "Do You Want To Install Office 365? Please Answer Yes Or No"
if ($365 |Where-Object {$_.Length -ge "3"}) {
    .\OfficeSetup.exe
}
else {
    Write-Host "Office 365 Will Be Not Installed On This Device"
}

}

else {
Write-Host "Softwares Will Be Not Installed On This Device"
}

#computer rename with serialnumber

$cnameinput = Read-Host "Do You Want To Rename The Computer? Please Answer Yes Or No"
if ($cnameinput |Where-Object {$_.Length -ge "3"}) {
    wmic bios get serialnumber
    $cname =Read-Host "Please Enter The Computername's SerialNumber (see Above)" 
    #Rename-Computer -NewName $cname
    $ComputerName = "$cname"
   
Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Hostname" 
Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "NV Hostname" 

Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Computername\Computername" -name "Computername" -value $ComputerName
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Computername\ActiveComputername" -name "Computername" -value $ComputerName
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Hostname" -value $ComputerName
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "NV Hostname" -value  $ComputerName
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AltDefaultDomainName" -value $ComputerName
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultDomainName" -value $ComputerName

}
else {
    Write-Host "Computer Name Will Not Changed"
}

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

Write-host -Foregroundcolor yellow "......................................End Of Script..................................."
