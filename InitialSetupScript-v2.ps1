#Warp Function for Account Creation
function AccountCreation {
    #Looping for Create new Account
    $Ans = 'Y'
    while($Ans -eq 'Y')
    {
    #Function for Creating User with Checking
        #Account Parameters
        $staffname = Read-Host("Input Staff Username")
        $Password = Read-Host("Input Password") | ConvertTo-SecureString -AsPlainText -Force
        $userCheck = (Get-LocalUser).Name -Contains $staffname
        if ($userCheck -eq $false) {
        New-LocalUser -Name $staffname -FullName $staffname -Password $Password
        }
        elseif ($userCheck -eq $true) {
        Write-Host("User already exists")
        Return
        }
    
    #Function for checking localgroup members
    function GroupMemberChecker {
           #checks if staff is admin
          (Get-LocalGroupMember Administrators).Name -contains "$env:COMPUTERNAME\$staffname"
           #checkes if staff is user
           (Get-LocalGroupMember Users).Name -contains "$env:COMPUTERNAME\$staffname"
    }
    #Adds the user to a localgroup
    $answer = Read-Host("Is the user admin? (Y/N)")
    #Adds the user to a localgroup based oqn user input
    if (($answer -eq "Y") -and ($answer -eq "y")){
        Add-LocalGroupMember -Group Administrators -Member $staffname -Verbose
    }
    elseif (($answer -eq "N") -and ($answer -eq "n")) {
        Add-LocalGroupMember -Group Users -Member $staffname -Verbose
    }
    else {
        Write-Host("Invalid input")
        Return
    }
    $Ans = Read-Host "Create another user?(Y/N)"
    }
}
#Function to rename local computer
function ChangeHostname {
$HostName = Read-Host "Input the computer hostname"
Rename-Computer $HostName
$OSWMI=Get-WmiObject -class Win32_OperatingSystem
$OSWMI.Description=$HostName
}  
#Function for Activating License Key
function ActivateProductKey {
$ProductKey = (Get-WmiObject -query ‘select * from SoftwareLicensingService’).OA3xOriginalProductKey
Write-Host $ProductKey
slmgr /upk
slmgr /ipk $ProductKey
}


#Function to Remove Fast Startup
function RemoveFastStartup {
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -Value 0
Write-Host "Hiberboot Disabled"
}
#Function to DisableIPV6
function DisableIPV6 {
Write-Host "This script will disable the IPV6 of the Selected Network Adapter."
$Answer = Read-Host "Kindly input the Name of the Network Adapter you want to Disable IPV6. (You can check the name in ncpa.cpl)"
Disable-NetAdapterBinding -Name $Answer -ComponentID 'ms_tcpip6'
Get-NetAdapterBinding -Name $Answer -ComponentID 'ms_tcpip6'
Write-Host "IPV6 of $Answer Disabled"
}
#Function to Install EXE and MSI Files in the same directory of script.
function InstallApp {
#Detects all exe and msi files in a folder
foreach($_installerFiles in 
($_installerFiles = Get-ChildItem $_Source -Recurse | Where{$_.Extension -eq ".exe" -or $_.Extension -eq ".msi"}|
 Where-Object {!($_.psiscontainter)} | Select-Object -ExpandProperty FullName)) 
{
    Write-Host $_installerFiles    
}
#Installation can only be done one at a time
$appName = Read-Host "Input full file path and name with extension"
Start-Process -FilePath $appName -ArgumentList /qn #-ArgumentList "/v /s /qn /passive" -NoNewWindow
}
#Function to Uninstall EXE and MSI Files in the same directory of script.
function UninstallApp {
Get-WmiObject -Class Win32_InstalledWin32Program | Select-Object -Property Name
Get-WmiObject -Class Win32_Product | Select-Object -Property Name
$App = Read-Host "Select the program you want to uninstall"
Uninstall-Package $App
#Write-Host "The application you selected is now uninstalled."
}
#Main Menu of Program
DO
{
Write-Host "MENU"
Write-Host "1 - Create user accounts"
Write-Host "2 - Change Computer Hostname (Reboot Required)"
Write-Host "3 - Activate Product Key"
Write-Host "4 - Disable Fast startup (Reboot Required)"
Write-Host "5 - Disable IPV6"
Write-Host "6 - Install an app in the same directory (.exe and .msi files only)"
Write-Host "7 - Uninstall an app"

$userInput = Read-Host "Select the function you want to do"
Switch ($userInput)
{
    1 {AccountCreation}
    2 {ChangeHostname}
    3 {ActivateProductKey}
    4 {RemoveFastStartup}
    5 {DisableIPV6}
    6 {InstallApp}
    7 {UninstallApp}
}
$userContinue = Read-Host "Return to menu?(Y/N)"
} While ($userContinue -eq "Y")
Write-Host "End of program"
