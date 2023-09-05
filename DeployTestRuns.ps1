﻿<#
1- make more hw test automated, ask Sean if we can test such as partner window and other.
2- check application that been installed but shouldn't be there. 
3- check if xml or txt is prefered
#>
$fileversion = "DeployTestRuns_v1.1.ps1"
#Forces powershell to run as an admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{ Start-Process powershell.exe "-NoProfile -Windowstyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

#Imports Windowsforms and Drawing from system
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

#Allows the use of wshell for confirmation popups
$wshell = New-Object -ComObject Wscript.Shell
$PSScriptRoot

$fpathscript = Get-ChildItem -Path $PSScriptRoot -Filter "$fileversion" -Recurse -erroraction SilentlyContinue | Select-Object -expand Fullname | Split-Path
$date = get-date -f "yyyy-MM-dd hh:mm:ss"
$date1 = get-date -f "yyyy-MM-dd"
$getSN = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation").Model

#Application versions
$SnapPath = "C:\Program Files\WindowsApps\TobiiDynavox.Snap_1.27.0.3385_x64__626b2w651dr5w\Snap.Windows.WinUI.OEM.exe" 
$EyeFXPath = "C:\Program Files\Sensory Guru\SensoryEyeFXDemo\Sensory Eye FX Demo.exe"

$AccessibleLiteracyLearning = "1.4.0.832"
$TobiiExperienceSoftwareForWindows = "4.180.0.29190"
$TobiiDynavoxBrowse = "1.16.0.64410"
$TobiiDynavoxControl = "1.79.1.837"
$TobiiDynavoxCommunicator5 = "5.6.0.65093"
$TobiiDynavoxConfigurationManager = "2.3.3.0"
$TobiiDynavoxEyeTracking = "3.1.6.64863"
$TobiiDynavoxGazeViewer = "1.2.0.63881"
$TobiiDynavoxHardwareListener = "1.8.0.0"
$TobiiDynavoxHardwareLicensingService = "2.2.3.0"
$TobiiDynavoxHardwareSettings = "1.8.0.0"
$TobiiDynavoxHardwareService = "1.0.8.0"
$TobiiDynavoxHardwareTestUtility = "1.4.0.0"
$TobiiDynavoxPhone = "1.5.1.1189"
$TobiiDynavoxSnapScene = "1.2.5.185"
$TobiiDynavoxStartupWizard = "1.2.1.46"
$TobiiDynavoxSwitcher = "2.1.0.62303"
$TobiiDynavoxTalk = "1.14.2.1783"
$TobiiDynavoxUpdateNotifier = "1.8.1.62923"
$JoinIn = "2.3.0.0"
$JoinInPageSets = "2.1.0.6"
$MirrorforAndroid = "1.19.1.11"
$ISeriesUserManual = "1.0.3.0"
$ISeriesScreenRotationListener = "1.1.1.0"

#B1 Function listapps - outputs all installed apps with the publisher Tobii
Function OEMSetup {
    $results = $wshell.Popup("Verify that device starts to screen to start OEM Setup.`r`nVerify remaining OEM Setup runs and continues.`r`nVerify that the QR Scanner opens through the TD Config Mgr.`r`nFinish Tobii Dynavox Configuration Steps.`r`nVerify the Windows is in the Language that was selected.`r`n", 0, "OEM Setup test", 4+48)

    if ($results -eq 6) {
         $outputBox.appendtext( "PASS: OEM Setup Test`r`n")
         Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: OEM Setup test"
    }
    elseif ($results -eq 7) {
         $outputBox.appendtext( "FAIL: OEM Setup Test `r`n")
         Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: OEM Setup test"
    } 
}

#B2
Function StartupWizard {
    $results = $wshell.Popup("Once the Configuration Manager completes, the device should restart and open the Startup Wizard.`r`nSelect 'Help Me Choose'.`r`nSelect 'Go Back'.`r`nSelect one of the two applications, then select the 'Select' button.`r`nFollow the Steps to complete the setup for the application you had selected. Then restart the device.`r`n", 0, "Startup Wizard test", 4+48)
    
    if ($results -eq 6) {
         $outputBox.appendtext( "PASS: Startup Wizard Test`r`n")
         Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Startup Wizard test"
    }
    elseif ($results -eq 7) {
         $outputBox.appendtext( "FAIL: Startup Wizard Test`r`n")
         Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL:  Startup Wizard test"
    } 
}

#B3
Function ConfigurationVerification {
    $wshell = New-Object -ComObject WScript.Shell
    $results = $wshell.Popup("Each Configuration will deploy specific Applications based on the licensing and by the Language in which it is configured to.`r`n", 0, "Configuration Verification", 0x0)

    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $languageID = [convert]::ToInt32($osInfo.Locale, 16)
    $outputBox.appendtext( "Windows language: $languageID`r`n")

    #https://www.autoitscript.com/autoit3/docs/appendix/OSLangCodes.htm
    #US English
    if ($languageID -eq 1033) {
    $reqSW = @( "Accessible Literacy Learning (ALL)",
                "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Board Maker",
                "Tobii Dynavox Snap Scene")
    }
    #UK English
    elseif ($languageID -eq 2057) { 
    $reqSW = @( "Accessible Literacy Learning (ALL)",
                "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Board Maker",
                "Tobii Dynavox Snap Scene")
    }
    #German
    elseif ($languageID -eq 1031) {
    $reqSW = @( "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Board Maker",
                "Tobii Dynavox Snap Scene")
    }
    #Norwegian
    elseif ($languageID -eq 1044) {
    $reqSW = @( "Accessible Literacy Learning (ALL)",
                "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Board Maker",
                "Tobii Dynavox Snap Scene")
    }
    #Swedish
    elseif ($languageID -eq 1053) {
    $reqSW = @( "Accessible Literacy Learning (ALL)",
                "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Board Maker",
                "Tobii Dynavox Snap Scene")
    }
    #Dutch
    elseif ($languageID -eq 1043) {
    $reqSW = @( "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Snap Scene")
    }
    #Danish
    elseif ($languageID -eq 1030) {
    $reqSW = @( "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Board Maker",
                "Tobii Dynavox Snap Scene")
    }
    #French
    elseif ($languageID -eq 1036) {
    $reqSW = @( "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Board Maker",
                "Tobii Dynavox Snap Scene")
    }
    #Spanish
    elseif ($languageID -eq 3082) {
    $reqSW = @( "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Board Maker",
                "Tobii Dynavox Snap Scene")
    }
    #Italian
    elseif ($languageID -eq 1040) {
    $reqSW = @( "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Board Maker",
                "Tobii Dynavox Snap Scene")
    }
    #Portugu(Br)
    elseif ($languageID -eq 1046) {
    $reqSW = @( "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Board Maker",
                "Tobii Dynavox Snap Scene")
    }
    #Finnish
    elseif ($languageID -eq 1035) {
    $reqSW = @( "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Board Maker",
                "Tobii Dynavox Snap Scene")
    }
    #Japanese
    elseif ($languageID -eq 1041) {
    $reqSW = @( "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Snap Scene")
    }
    #Chinese
    elseif ($languageID -eq 1028) {
    $reqSW = @( "Tobii Dynavox Control",
                "Tobii Dynavox Communicator 5",
                "Tobii Dynavox Talk",
                "Tobii Dynavox Update Notifier",
                "Tobii Dynavox Browse",
                "Tobii Dynavox Phone",
                "Tobii Dynavox Snap Scene")
    }

    $TobiiVer = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { 
        ($_.Displayname -eq "Accessible Literacy Learning (ALL)")-or
        ($_.Displayname -eq "Tobii Dynavox Browse") -or
        ($_.Displayname -eq "Tobii Dynavox Control") -or
        ($_.Displayname -eq "Tobii Dynavox Communicator 5") -or
        ($_.Displayname -eq "Tobii Dynavox Board Maker")-or
        ($_.Displayname -eq "Tobii Dynavox Phone") -or
        ($_.Displayname -eq "Tobii Dynavox Snap Scene")-or
        ($_.Displayname -eq "Tobii Dynavox Talk") -or
        ($_.Displayname -eq "Tobii Dynavox Update Notifier")
                 
    } | Select-Object Displayname, UninstallString

    $installedSW = $TobiiVer.DisplayName | Select-Object -Unique

    $Uninstnames = (Compare-Object -DifferenceObject $reqSW -ReferenceObject $installedSW -CaseSensitive  | Select-Object InputObject).InputObject
    if ($Uninstnames -gt $null){
        foreach ($Uninstname in $Uninstnames){
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Configuration Verification: $Uninstname is missing"
            $outputBox.appendtext( "FAIL: $Uninstname is not installed`r`n")
        }

    } elseif ($Uninstnames -eq $null){
        $outputBox.appendtext( "PASS: all required SW are installed.`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Configuration Verification"
        
    }

    #Snap verification
    if (Test-path $SnapPath) {
        $outputBox.appendtext( "PASS: Snap is installed.`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Snap Verification"
    } else {
        $outputBox.appendtext( "FAIL:  Snap is not installed.`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Snap Verification"
    }
}

# Function to check the version of a software
function Verify-SoftwareVersion {
    param (
        [string]$displayName,
        [string]$expectedVersion
    )

    $software = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
                Where-Object { $_.DisplayName -eq $displayName }

    if ($software) {
        $installedVersion = $software.DisplayVersion
        if ($installedVersion -eq $expectedVersion) {
            #$outputBox.appendtext("PASS: $displayName version is correct.`r`n")
            #Add-Content -Path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: $displayName version Verification"
        } else {
            $outputBox.appendtext("FAIL: $displayName version is wrong.`r`n")
            Add-Content -Path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: $displayName version Verification"
        }
    } else {
        $outputBox.appendtext("FAIL: $displayName is not installed.`r`n")
        Add-Content -Path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: $displayName is not installed."
    }
}

#B4
Function ApplicationV {
    $wshell = New-Object -ComObject WScript.Shell
    $results = $wshell.Popup("Verifying that necessary Applications are deployed in the correct version.`r`n", 0, "Application Version test", 0x0)

    #Get Windows version
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $osName = $osInfo.Caption
    $osVersion = $osInfo.Version
    $versionMappings = @{ '10.0.19044' = '21H2'}

    if ($versionMappings.ContainsKey($osVersion)) {
        $windowsVersion = $versionMappings[$osVersion]
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Windows version is $windowsVersion"
    } 
    else {
        $windowsVersion = "Unknown"
    }

    # Call the function for each software you want to verify
    Verify-SoftwareVersion -displayName "Accessible Literacy Learning (ALL)" -expectedVersion "$AccessibleLiteracyLearning"
    Verify-SoftwareVersion -displayName "Tobii Experience Software For Windows (I-SeriesLarge)" -expectedVersion "$TobiiExperienceSoftwareForWindows"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Browse" -expectedVersion "$TobiiDynavoxBrowse"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Control" -expectedVersion "$TobiiDynavoxControl"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Communicator 5" -expectedVersion "$TobiiDynavoxCommunicator5"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Configuration Manager" -expectedVersion "$TobiiDynavoxConfigurationManager"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Eye Tracking" -expectedVersion "$TobiiDynavoxEyeTracking"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Gaze Viewer" -expectedVersion "$TobiiDynavoxGazeViewer"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Hardware Listener" -expectedVersion "$TobiiDynavoxHardwareListener"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Hardware Licensing Service" -expectedVersion "$TobiiDynavoxHardwareLicensingService"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Hardware Settings" -expectedVersion "$TobiiDynavoxHardwareSettings"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Hardware Service" -expectedVersion "$TobiiDynavoxHardwareService"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Hardware Test Utility" -expectedVersion "$TobiiDynavoxHardwareTestUtility"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Phone" -expectedVersion "$TobiiDynavoxPhone"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Snap Scene" -expectedVersion "$TobiiDynavoxSnapScene"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Startup Wizard" -expectedVersion "$TobiiDynavoxStartupWizard"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Switcher" -expectedVersion "$TobiiDynavoxSwitcher"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Talk" -expectedVersion "$TobiiDynavoxTalk"
    Verify-SoftwareVersion -displayName "Tobii Dynavox Update Notifier" -expectedVersion "$TobiiDynavoxUpdateNotifier"
    Verify-SoftwareVersion -displayName "Join-In" -expectedVersion "$JoinIn"
    Verify-SoftwareVersion -displayName "Join-In Page Sets" -expectedVersion "$JoinInPageSets"
    Verify-SoftwareVersion -displayName "Mirror for Android" -expectedVersion "$MirrorforAndroid"
    Verify-SoftwareVersion -displayName "I-Series User's Manual" -expectedVersion "$ISeriesUserManual"
    Verify-SoftwareVersion -displayName "I-Series Screen Rotation Listener" -expectedVersion "$ISeriesScreenRotationListener"

    #Snap version
    $SnapVersion = (Get-Item $SnapPath).VersionInfo.FileVersion

    if ($SnapVersion -eq "1.27.0.0") {
        $outputBox.appendtext( "PASS: Snap version is correct.$SnapVersion`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Snap Version $SnapVersion"
    } else {
        $outputBox.appendtext( "FAIL: Snap version is not correct.$SnapVersion`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Snap Version $SnapVersion"
    }

    #EyeFX version
    $EyeFXVersion = (Get-Item $EyeFXPath).VersionInfo.FileVersion

    if ($EyeFXVersion -eq "2.0.0") {
        $outputBox.appendtext( "PASS: EyeFX version is correct.$EyeFXVersion`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: EyeFX Version $EyeFXVersion"
    } else {
        $outputBox.appendtext( "FAIL: Snap version is not correct.$EyeFXVersion`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: EyeFX Version $EyeFXVersion"
    }
}

#B5
Function C5Content {
    $wshell = New-Object -ComObject WScript.Shell
    $results = $wshell.Popup("Verifying that the proper content is available for Communicator.`r`n", 0, "C5 Content test", 0x0)
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $languageID = [convert]::ToInt32($osInfo.Locale, 16)
    $outputBox.appendtext( "Windows language: $languageID`r`n")

    #https://www.autoitscript.com/autoit3/docs/appendix/OSLangCodes.htm
    #US English #UK English
    if (($languageID -eq 1033) -or ($languageID -eq 2057)) {
    $reqC5SW = @( 
                "Tobii Dynavox Communicator 5",
                "Sono Flex",
                "Sono Key",
                "LiterAACy - US English",
                "Sono Lexis",
                "Sono Primo for Communicator",
                "SymbolStix 2", 
                "PCS for Communicator 5"
                )
    }
    
    #Dutch Norwegian Swedish
    elseif (($languageID -eq 1043) -or ($languageID -eq 1044) -or ($languageID -eq 1053)) {
    $reqC5SW = @( 
                "Tobii Dynavox Communicator 5",
                "Sono Key",
                "Sono Primo for Communicator",
                "Sono Flex",
                "SymbolStix 2", 
                "PCS for Communicator 5"
                )
    }
    # Spanish Finnish French
    elseif (($languageID -eq 3082) -or ($languageID -eq 1035) -or ($languageID -eq 1036)) {
    $reqC5SW = @( 
                "Tobii Dynavox Communicator 5",
                "Sono Key",
                "SymbolStix 2", 
                "PCS for Communicator 5"
                )
    }    
    
    
    #German
    elseif ($languageID -eq 1031) {
    $reqC5SW = @( 
                "Tobii Dynavox Communicator 5",
                "Sono Key",
                "Sono Lexis",
                "Sono Primo for Communicator",
                "Sono Flex",
                "LiterAACy - US English",
                "SymbolStix 2", 
                "METACOM", 
                "PCS for Communicator 5"
                )
    }

    #Portugu(Br)
    elseif ($languageID -eq 1046) {
    $reqC5SW = @( 
                "Tobii Dynavox Communicator 5",
                "Sono Key",
                "Sono Flex",
                "SymbolStix 2", 
                "PCS for Communicator 5"
                )
    }   
    
    #Danish
    elseif ($languageID -eq 1030) {
    $reqC5SW = @( 
                "Tobii Dynavox Communicator 5",
                "Sono Key",
                "Sono Lexis",
                "SymbolStix 2", 
                "PCS for Communicator 5"
                )
    }
    
    #Italian
    elseif ($languageID -eq 1040) {
    $reqC5SW = @( 
                "Tobii Dynavox Communicator 5",
                "SymbolStix 2", 
                "PCS for Communicator 5"
                )
    }
    
   
    #Japanese
    elseif ($languageID -eq 1041) {
    $reqC5SW = @( 
                "Tobii Dynavox Communicator 5",
                "Sono Key",
                "SymbolStix 2", 
                "PCS for Communicator 5"
                )
    }
    #Chinese
    elseif ($languageID -eq 1028) {
    $reqC5SW = @( 
                "Tobii Dynavox Communicator 5",
                "Sono Key",
                "PCS for Communicator 5"
                )
    }

    $TobiiC5Ver = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { 
        ($_.Displayname -eq "Tobii Dynavox Communicator 5")-or
        ($_.Displayname -eq "Sono Flex")-or
        ($_.Displayname -eq "Sono Key") -or
        ($_.Displayname -eq "LiterAACy - US English") -or
        ($_.Displayname -eq "Sono Lexis") -or
        ($_.Displayname -eq "Sono Primo for Communicator") -or
        ($_.Displayname -eq "SymbolStix 2")-or
        ($_.Displayname -eq "PCS for Communicator 5") 
                 
    } | Select-Object DisplayName, DisplayVersion

    $installedC5SW = $TobiiC5Ver.DisplayName

    $UninstnamesC5 = (Compare-Object -DifferenceObject $reqC5SW -ReferenceObject $installedC5SW -CaseSensitive  | Select-Object InputObject).InputObject
    
    if ($UninstnamesC5 -eq $null){
       $outputBox.appendtext( "PASS: all required SW are installed.`r`n")
        foreach ($UninstnameC5 in $UninstnamesC5){
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Configuration Verification"
            $outputBox.appendtext( "$UninstnameC5 is not installed`r`n")
        }

    } else{
        $outputBox.appendtext( "FAIL: following sw are missing: $UninstnamesC5`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Configuration Verification"
        
    }
    
}

#B6
Function C5Voices {
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $languageID = [convert]::ToInt32($osInfo.Locale, 16)
    $outputBox.appendtext( "Windows language: $languageID`r`n")

    #https://www.autoitscript.com/autoit3/docs/appendix/OSLangCodes.htm
    #US English
    if ($languageID -eq 1033) {
        $C5Voice = "Heather, Kenny, Laura, Micah, Nelly, Ryan, Saul, Tracy, Will, Ella, Josh, Emilio (Spanish), Emilio (English), Valeria (Spanish), Valeria (English)"
    }
    #UK English
    elseif ($languageID -eq 2057) { 
        $C5Voice =  "$Lucy, Graham, Peter, Queen Elizabeth, Rachel, Harry, Rosie"
    }
    #German
    elseif ($languageID -eq 1031) {
        $C5Voice = "Klaus, Andreas, Jonas, Julia, Lea, Sarah"
    }
    #Norwegian
    elseif ($languageID -eq 1044) {
        $C5Voice = "Kari, Bente, Olav, Emilie, Elias"
    }
    #Swedish
    elseif ($languageID -eq 1053) {
        $C5Voice = "Emma, Elin, Emil, Erik, Filip, Freja"
    }
    #Dutch
    elseif ($languageID -eq 1043) {
        $C5Voice = "Femke, Daan, Jasmijn, Jeroe, Max, Sofie (Belgium), Zoe (Belgium), Merel, Thijs"
    }
    #Danish
    elseif ($languageID -eq 1030) {
        $C5Voice = "Mette, Rasmus"
    }
    #French
    elseif ($languageID -eq 1036) {
        $C5Voice = "Julie, Alice, Antoine, Bruno, Claire,Louise, Margaux, Anais, Elise, Manon, Valentin"
    }
    #Spanish
    elseif ($languageID -eq 3082) {
        $C5Voice = "Rosa , Antonio, Javier,Ines, Maria, Emilio (spantsh), Emilio (English), Valeria (spantsh), Valeria (English)"
    }
    #Italian
    elseif ($languageID -eq 1040) {
        $C5Voice = "Chiara, Fabiana"
    }
    #Portugu(Br)
    elseif ($languageID -eq 1046) {
        $C5Voice = "Marcia, Carlos, Paola, Celia (Portugal), Elia, Ester"
    }
    #Finnish
    elseif ($languageID -eq 1035) {
        $C5Voice = "Sanna"
    }
    #Japanese
    elseif ($languageID -eq 1041) {
        $C5Voice = "Misaki, Show"
    }
    #Chinese
    elseif ($languageID -eq 1028) {
        $C5Voice = "Hui, Liang"
    }

    $wshell = New-Object -ComObject WScript.Shell
    $results = $wshell.Popup("Verifying that the proper voices are available.`r`n$C5Voice`r`n Press YES or NO`r`n", 0, "C5 Voices test", 4+48)
    if ($results -eq 6) {
         $outputBox.appendtext( "PASS: C5 Voices Test`r`n")
         Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: C5 Voices test"
    }
    elseif ($results -eq 7) {
         $outputBox.appendtext( "FAIL: C5 Voices Test`r`n")
         Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: C5 Voices test"
    } 
}

#B7
Function ApplicationVerification {
    Add-Type -AssemblyName System.Windows.Forms    
    Add-Type -AssemblyName System.Drawing

    # Build Form
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Application Verification"
    $Form.Size = New-Object System.Drawing.Size(400, 600)
    $Form.StartPosition = "CenterScreen"
    #$Form.Topmost = $True

    # Add Button1
    $Button1 = New-Object System.Windows.Forms.Button
    $Button1.Location = New-Object System.Drawing.Size(40, 40)
    $Button1.Size = New-Object System.Drawing.Size(150, 50)
    $Button1.Text = "Snap Wizard"
    $Form.Controls.Add($Button1)
    
    # Add Button2
    $Button2 = New-Object System.Windows.Forms.Button
    $Button2.Location = New-Object System.Drawing.Size(190, 40)
    $Button2.Size = New-Object System.Drawing.Size(150, 50)
    $Button2.Text = "Snap"
    $Form.Controls.Add($Button2)
    
    # Add Button3
    $Button3 = New-Object System.Windows.Forms.Button
    $Button3.Location = New-Object System.Drawing.Size(40, 90)
    $Button3.Size = New-Object System.Drawing.Size(150, 50)
    $Button3.Text = "C5"
    $Form.Controls.Add($Button3)    
    
    # Add Button4
    $Button4 = New-Object System.Windows.Forms.Button
    $Button4.Location = New-Object System.Drawing.Size(190, 90)
    $Button4.Size = New-Object System.Drawing.Size(150, 50)
    $Button4.Text = "TD Talk"
    $Form.Controls.Add($Button4)

    # Add Button5
    $Button5 = New-Object System.Windows.Forms.Button
    $Button5.Location = New-Object System.Drawing.Size(40, 140)
    $Button5.Size = New-Object System.Drawing.Size(150, 50)
    $Button5.Text = "ETS"
    $Form.Controls.Add($Button5)

    # Add Button6
    $Button6 = New-Object System.Windows.Forms.Button
    $Button6.Location = New-Object System.Drawing.Size(190, 140)
    $Button6.Size = New-Object System.Drawing.Size(150, 50)
    $Button6.Text = "TD Control"
    $Form.Controls.Add($Button6)

    # Add Button7
    $Button7 = New-Object System.Windows.Forms.Button
    $Button7.Location = New-Object System.Drawing.Size(40, 190)
    $Button7.Size = New-Object System.Drawing.Size(150, 50)
    $Button7.Text = "Switcher"
    $Form.Controls.Add($Button7)
    
    # Add Button8
    $Button8 = New-Object System.Windows.Forms.Button
    $Button8.Location = New-Object System.Drawing.Size(190, 190)
    $Button8.Size = New-Object System.Drawing.Size(150, 50)
    $Button8.Text = "HS"
    $Form.Controls.Add($Button8)

    # Add Button9
    $Button9 = New-Object System.Windows.Forms.Button
    $Button9.Location = New-Object System.Drawing.Size(40, 240)
    $Button9.Size = New-Object System.Drawing.Size(150, 50)
    $Button9.Text = "ALL"
    $Form.Controls.Add($Button9)

    # Add Button10
    $Button10 = New-Object System.Windows.Forms.Button
    $Button10.Location = New-Object System.Drawing.Size(190, 240)
    $Button10.Size = New-Object System.Drawing.Size(150, 50)
    $Button10.Text = "BM7"
    $Form.Controls.Add($Button10)

    # Add Button11
    $Button11 = New-Object System.Windows.Forms.Button
    $Button11.Location = New-Object System.Drawing.Size(40, 290)
    $Button11.Size = New-Object System.Drawing.Size(150, 50)
    $Button11.Text = "Snap Scene"
    $Form.Controls.Add($Button11)

    # Add Button12
    $Button12 = New-Object System.Windows.Forms.Button
    $Button12.Location = New-Object System.Drawing.Size(190, 290)
    $Button12.Size = New-Object System.Drawing.Size(150, 50)
    $Button12.Text = "UN"
    $Form.Controls.Add($Button12)

    # Add Button13
    $Button13 = New-Object System.Windows.Forms.Button
    $Button13.Location = New-Object System.Drawing.Size(40, 340)
    $Button13.Size = New-Object System.Drawing.Size(150, 50)
    $Button13.Text = "User Manual"
    $Form.Controls.Add($Button13)

    # Add Button14
    $Button14 = New-Object System.Windows.Forms.Button
    $Button14.Location = New-Object System.Drawing.Size(190, 340)
    $Button14.Size = New-Object System.Drawing.Size(150, 50)
    $Button14.Text = "TD Browse"
    $Form.Controls.Add($Button14)
    
    # Add Button15
    $Button15 = New-Object System.Windows.Forms.Button
    $Button15.Location = New-Object System.Drawing.Size(40, 390)
    $Button15.Size = New-Object System.Drawing.Size(150, 50)
    $Button15.Text = "TD Phone"
    $Form.Controls.Add($Button15)

    # Add Button16
    $Button16 = New-Object System.Windows.Forms.Button
    $Button16.Location = New-Object System.Drawing.Size(190, 390)
    $Button16.Size = New-Object System.Drawing.Size(150, 50)
    $Button16.Text = "EyeFX2"
    $Form.Controls.Add($Button16)

    $wshell = New-Object -ComObject WScript.Shell
    
    $Button1.Add_Click({
        $results = $wshell.Popup("Verifying that the Setup Wizard can be completed successfully, as well as having the correct content and voices available.`r`n", 0, "Snap Wizard test", 0x0)
    })
    $Button2.Add_Click({
        $results = $wshell.Popup("A quick Sanity Check of Snap should be run to make sure all major components are working as expected. This is just a quick test.`r`n", 0, "Snap Sanity Check test", 0x0)
    })
    $Button3.Add_Click({
        $results = $wshell.Popup("A quick Sanity Check of Communicator should be run to make sure all major components are working as expected. This is just a quick test.`r`n", 0, "C5 Sanity Check test", 0x0)
    })
    $Button4.Add_Click({
        $results = $wshell.Popup("Verifying that TD Talk is deployed properly and is working as expected.`r`n", 0, "TD Talk Sanity Check test", 0x0)
    })
    $Button5.Add_Click({
        $results = $wshell.Popup("Verifying that the Eye Tracking Settings Application is working as expected.`r`n", 0, "ETS Sanity Check test", 0x0)
   })
    $Button6.Add_Click({
        $results = $wshell.Popup("Verifying that Control works as expected.`r`n", 0, "TD Control Sanity Check test", 0x0)
    })
    $Button7.Add_Click({
        $results = $wshell.Popup("Verifying that TD Switcher works as expected.`r`n", 0, "Switcher Sanity Check test", 0x0)
    })
    $Button8.Add_Click({
        $results = $wshell.Popup("Verifying the the Hardware Settings Application works as expected.`r`n", 0, "Hardware Settings Sanity Check test", 0x0)
   })
    $Button9.Add_Click({
        $results = $wshell.Popup("Running a quick Sanity Check for ALL. ALL will be installed on a Locked device, however it is blocked by In-Touch Lock.`r`n", 0, "ALL Sanity Check test", 0x0)
    })
    $Button10.Add_Click({
        $results = $wshell.Popup("Running a quick Sanity Check on Student Center.`r`n", 0, "BM7 Sanity Check test", 0x0)
    })
    $Button11.Add_Click({
        $results = $wshell.Popup("Running a quick Sanity Check on Snap Scene.`r`n", 0, "Snap Scene Sanity Check test", 0x0)
    })
    $Button12.Add_Click({
        $results = $wshell.Popup("Running a quick Sanity Check for Update Notifier.`r`n", 0, "UN Sanity Check test", 0x0)
    })
    $Button13.Add_Click({
        $results = $wshell.Popup("Verifying that the I-Series User's Manual App has been installed and opens as expected.`r`n", 0, "User Manual Sanity Check test", 0x0)
    })
    $Button14.Add_Click({
        $results = $wshell.Popup("Verifying that TD Browse is deployed and working as expected.`r`n", 0, "TD Browse Sanity Check test", 0x0)
    })
    $Button15.Add_Click({
        $results = $wshell.Popup("Verifying the TD Phone is installed and working as expected.`r`n", 0, "TD Phone Sanity Check test", 0x0)
    })
    $Button16.Add_Click({
        $results = $wshell.Popup("Verifying that the Sensory Eye FX 2 Demo launches and Eye Tracking can be used.`r`n", 0, "Eye FX Sanity Check test", 0x0)
    })
    $form.ShowDialog() | Out-Null 
}

#B8
Function HWVerification {
    Add-Type -AssemblyName System.Windows.Forms    
    Add-Type -AssemblyName System.Drawing

    # Build Form
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "HW Verification"
    $Form.Size = New-Object System.Drawing.Size(400, 600)
    $Form.StartPosition = "CenterScreen"
    #$Form.Topmost = $True

    # Add Button1
    $Button1 = New-Object System.Windows.Forms.Button
    $Button1.Location = New-Object System.Drawing.Size(40, 40)
    $Button1.Size = New-Object System.Drawing.Size(150, 50)
    $Button1.Text = "Adaptive Volume Buttons"
    $Form.Controls.Add($Button1)
    
    # Add Button2
    $Button2 = New-Object System.Windows.Forms.Button
    $Button2.Location = New-Object System.Drawing.Size(190, 40)
    $Button2.Size = New-Object System.Drawing.Size(150, 50)
    $Button2.Text = "Partner Window"
    $Form.Controls.Add($Button2)
    
    # Add Button3
    $Button3 = New-Object System.Windows.Forms.Button
    $Button3.Location = New-Object System.Drawing.Size(40, 90)
    $Button3.Size = New-Object System.Drawing.Size(150, 50)
    $Button3.Text = "Switch Ports"
    $Form.Controls.Add($Button3)    
    
    # Add Button4
    $Button4 = New-Object System.Windows.Forms.Button
    $Button4.Location = New-Object System.Drawing.Size(190, 90)
    $Button4.Size = New-Object System.Drawing.Size(150, 50)
    $Button4.Text = "IR"
    $Form.Controls.Add($Button4)

    # Add Button5
    $Button5 = New-Object System.Windows.Forms.Button
    $Button5.Location = New-Object System.Drawing.Size(40, 140)
    $Button5.Size = New-Object System.Drawing.Size(150, 50)
    $Button5.Text = "Bluetooth"
    $Form.Controls.Add($Button5)

    # Add Button6
    $Button6 = New-Object System.Windows.Forms.Button
    $Button6.Location = New-Object System.Drawing.Size(190, 140)
    $Button6.Size = New-Object System.Drawing.Size(150, 50)
    $Button6.Text = "Camera"
    $Form.Controls.Add($Button6)

    # Add Button7
    $Button7 = New-Object System.Windows.Forms.Button
    $Button7.Location = New-Object System.Drawing.Size(40, 190)
    $Button7.Size = New-Object System.Drawing.Size(150, 50)
    $Button7.Text = "Microphone"
    $Form.Controls.Add($Button7)
    
    # Add Button8
    $Button8 = New-Object System.Windows.Forms.Button
    $Button8.Location = New-Object System.Drawing.Size(190, 190)
    $Button8.Size = New-Object System.Drawing.Size(150, 50)
    $Button8.Text = "Headphones Port"
    $Form.Controls.Add($Button8)

    # Add Button9
    $Button9 = New-Object System.Windows.Forms.Button
    $Button9.Location = New-Object System.Drawing.Size(40, 240)
    $Button9.Size = New-Object System.Drawing.Size(150, 50)
    $Button9.Text = "Charging Port"
    $Form.Controls.Add($Button9)

    # Add Button10
    $Button10 = New-Object System.Windows.Forms.Button
    $Button10.Location = New-Object System.Drawing.Size(190, 240)
    $Button10.Size = New-Object System.Drawing.Size(150, 50)
    $Button10.Text = "USB Port"
    $Form.Controls.Add($Button10)

    # Add Button11 New
    $Button11 = New-Object System.Windows.Forms.Button
    $Button11.Location = New-Object System.Drawing.Size(40, 290)
    $Button11.Size = New-Object System.Drawing.Size(150, 50)
    $Button11.Text = "WiFi"
    $Form.Controls.Add($Button11)

    $wshell = New-Object -ComObject WScript.Shell
    
    <#0: cancels any running test
    1: executes eye tracker tests
    2: executes IR tests
    3: executes tests of physical buttons
    4: executes tests of low-level hardware features (SDK)
    8: executes tests of switches
    9: executes tests of the audio system
    10: displays the log file populated by previous test executions
    11: clears the log file
    12: executes secondary display tests
    #>
    $HWUtilityPath = "C:\Program Files (x86)\Tobii Dynavox\Hardware Test Utility"
    if (Test-Path $HWUtilityPath) { Set-Location $HWUtilityPath }

    #Adaptive Buttons
    $Button1.Add_Click({
        $results = $wshell.Popup("Verifying that the Adaptive Buttons on the front of the device work as expected.", 0, "Adaptive Buttons test", 0x0)
        
        if (Test-Path -Path $HWUtilityPath) {
            # 3: executes tests of physical buttons
            Start-Process -FilePath "TobiiDynavox.Hardware.Tests.TestRunner.exe" -ArgumentList 3
            Start-Sleep -s 2
            $ProcessID = (Get-Process Platforms.GibbonGaze.TesterUI).Id
            Wait-Process -ID $ProcessID
        } else {
            $outputBox.appendtext( "The specified path does not exist.`r`n")
        }

        $results = $wshell.Popup("Press Yes if Pass or No if Fail", 0, "Adaptive Buttons test", 4+48)
    
        if ($results -eq 6) {
             $outputBox.appendtext( "PASS: Adaptive Button Test`r`n")
             Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Adaptive Button Test"
        }
        elseif ($results -eq 7) {
             $outputBox.appendtext( "FAIL: Adaptive Button Test`r`n")
             Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Adaptive Button Test"
        }
    })
    
    #Partner Window
    $Button2.Add_Click({
        $results = $wshell.Popup("Verifying that the Partner Window on the back of the device is working as expected.`r`n", 0, "Partner Window test", 0x0)
        if (Test-Path -Path $HWUtilityPath) {
            # 12: executes secondary display tests
            Start-Process -FilePath "TobiiDynavox.Hardware.Tests.TestRunner.exe" -ArgumentList 12
            Start-Sleep -s 5
            $ProcessID = (Get-Process Platforms.GibbonGaze.TesterUI).Id
            Wait-Process -ID $ProcessID
        } else {
            $outputBox.appendtext( "The specified path does not exist.`r`n")
        }
        $results = $wshell.Popup("Press Yes if Pass or No if Fail", 0, "Partner Window test", 4+48)

        if ($results -eq 6) {
            $outputBox.appendtext( "PASS: Partner Window Test`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Partner Window Test"
        }
        elseif ($results -eq 7) {
            $outputBox.appendtext( "FAIL: Partner Window Test`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Partner Window Test"
        }

    })
    
    #Switch Port
    $Button3.Add_Click({
        $results = $wshell.Popup("Switch functionallity Test result.", 0, "Switch Port test", 0X0)
        if (Test-Path -Path $HWUtilityPath) {
            # 8: executes tests of switches
            Start-Process -FilePath "TobiiDynavox.Hardware.Tests.TestRunner.exe" -ArgumentList 8
            Start-Sleep -s 2
            $ProcessID = (Get-Process Platforms.GibbonGaze.TesterUI).Id
            Wait-Process -ID $ProcessID
        } else {
            $outputBox.appendtext( "The specified path does not exist.`r`n")
        }
        
        $results = $wshell.Popup("Press Yes if Pass or No if Fail", 0, "Switch Port test", 4+48)
        
        if ($results -eq 6) {
                $outputBox.appendtext( "PASS: Switch Test`r`n")
                Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Switch Test"
        }
        elseif ($results -eq 7) {
                $outputBox.appendtext( "FAIL: Switch Test`r`n")
                Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Switch Test"
        }
    })
    
    #IR Port   
    $Button4.Add_Click({
        $results = $wshell.Popup("Verify that IR is working as expected.`r`n", 0, "IR test", 0x0)
        if (Test-Path -Path $HWUtilityPath) {
            # 2: executes IR tests
            Start-Process -FilePath "TobiiDynavox.Hardware.Tests.TestRunner.exe" -ArgumentList 2
            Start-Sleep -s 2
            $ProcessID = (Get-Process Platforms.GibbonGaze.TesterUI).Id
            Wait-Process -ID $ProcessID
        } else {
            $outputBox.appendtext( "The specified path does not exist.`r`n")
        }
        
        $results = $wshell.Popup("Press Yes if Pass or No if Fail", 0, "IR test", 4+48)
    
        if ($results -eq 6) {
             $outputBox.appendtext( "PASS: IR Test`r`n")
             Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: IR Test"
        }
        elseif ($results -eq 7) {
             $outputBox.appendtext( "FAIL: IR Test`r`n")
             Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: IR Test"
        }
    })
    
    $Button5.Add_Click({
        $results1 = $wshell.Popup("Verifying that the I-13/I-16 can be connected to a Bluetooth device and used, especially with Scanning or Audio for the Communication Applications.`r`n", 0, "Bluetooth test",  0x0)
        start-process devicepairingwizard.exe
        $ProcessID = (Get-Process devicepairingwizard).Id
        Wait-Process -ID $ProcessID
        $results = $wshell.Popup("Press Yes if Pass or No if Fail", 0, "Bluetooth test",  4+48)

        if ($results -eq 6) {
            $outputBox.appendtext( "PASS: Bluetooth Test`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Bluetooth Test"
        }
        elseif ($results -eq 7) {
            $outputBox.appendtext( "FAIL: Bluetooth Test`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Bluetooth Test"
        }

   })
    
    $Button6.Add_Click({
        $results = $wshell.Popup("Verifying that the cameras on the I-13/I-16 work as expected.`r`n", 0, "Camera test", 0x0)
        $proc = start microsoft.windows.camera:
        Start-Sleep -s 2
        $ProcessID = (Get-Process windowscamera).Id
        Wait-Process -ID $ProcessID

        $results = $wshell.Popup("Camera front and rear camera zoom funktion for the rear camera`r`nPress Yes if Pass or No if Fail", 0, "Display test", 4+48)
    
        if ($results -eq 6) {
             $outputBox.appendtext( "PASS: Camera Test`r`n")
             Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Camera Test"
        }
        elseif ($results -eq 7) {
             $outputBox.appendtext( "FAIL: Camera Test`r`n")
             Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Camera Test"
        }

    })
    
    $Button7.Add_Click({
        $results = $wshell.Popup("Verify that the microphone is working as expected.`r`n", 0, "Mic test", 0x0)
        explorer.exe shell:appsFolder\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe!App
        Start-Sleep -s 2
        $ProcessID = (Get-Process SoundRec).Id
        Wait-Process -ID $ProcessID

        $results = $wshell.Popup("Verify voice recorde capture your sound test Mic test 1 2 3...`r`nPress Yes if Pass or No if Fail", 0, "Display test", 4+48)

        if ($results -eq 6) {
             $outputBox.appendtext( "PASS: Mic Test`r`n")
             Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Mic Test"
        }
        elseif ($results -eq 7) {
             $outputBox.appendtext( "FAIL: Mic Test`r`n")
             Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Mic Test"
        }
    })
    
    $Button8.Add_Click({
        $results = $wshell.Popup("Verifying that the Headphones Port is working as expected.`r`n", 0, "Headphones port test", 0x0)
   })
    
    $Button9.Add_Click({
        $results = $wshell.Popup("Verifying that the Charging Port works as expected.`r`n", 0, "Charging port test", 0x0)
        $battery = Get-WmiObject Win32_Battery

        if ($battery.BatteryStatus -eq 2) {
            $outputBox.appendtext( "PASS: Charging port Test. The device is charging, `r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Charging port Test. The device is charging"
        } elseif ($battery.BatteryStatus -eq 1) {
            $outputBox.appendtext( "FAIL: Charging port Test. The device is not charging`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Charging port Test. The device is not charging"
        } else {
            $outputBox.appendtext( "FAIL: Charging port Test. The device is not charging`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date The device is charging, Charging port Test: Fail"
        }

    })
    
    $Button10.Add_Click({
        $results = $wshell.Popup("Verify that the USB Port is working as expected, plugin kb mouse/Hub or a USB and find connection`r`nPress Yes if Pass or No if Fail", 0, "Display test", 4+48)
    
        if ($results -eq 6) {
             $outputBox.appendtext( "PASS: USB Test`r`n")
             Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: USB"
        }
        elseif ($results -eq 7) {
             $outputBox.appendtext( "FAIL: USB Test`r`n")
             Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: USB"
        }

    })
    
    $Button11.Add_Click({
        $results = $wshell.Popup("Verify that the WiFi is working as expected.`r`n", 0, "WiFi test", 0x0)
        $pingCount = 5
        $server = '192.168.0.1' #'192.168.50.1'
        $pingStatus = Test-Connection $server -Count $pingCount -ErrorAction SilentlyContinue
        $pingsLost = $pingCount - ($pingStatus).Count
        $Messagerecived = ($pingStatus).count 
        $outputBox.appendtext( "Message sent:$pingCount  Message recived: $Messagerecived  Message lost: $pingsLost")

        if ($pingsLost -eq 0) {
            $outputBox.appendtext( "PASS: WiFi Test`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date Message sent:$pingCount  Message recived: $Messagerecived   Message lost: $pingsLost"
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: WiFi Test"
        }
        else {
            $outputBox.appendtext( "FAIL: WiFi Test`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date Message sent:$pingCount  Message recived: ($pingStatus).count  Message lost: $pingsLost"
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: WiFi Test"
        }
    })    
    
    $form.ShowDialog() | Out-Null   

}

#B9
Function WindowsSettings {
    $wshell = New-Object -ComObject WScript.Shell
    $results = $wshell.Popup("Verifying that the correct general Windows Settings are set during Deployment.`r`n", 0, "Windows Settings Verification", 0x0)

    # Get the display scale (DPI scaling level) from the Registry
    $dpiValue = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name AppliedDPI -ErrorAction SilentlyContinue
    $key = 'HKLM:\SOFTWARE\WOW6432Node\Tobii Dynavox\Device' 
    $SerialNumber = (Get-ItemProperty -Path $key)."Serial Number"

    if ($dpiValue) {
        # Calculate the DPI scaling percentage
        $dpiPercentage = [math]::Round($dpiValue.AppliedDPI / 96 * 100)

        if (($SerialNumber -match "TD16L") -or ($SerialNumber -match "TDG16")) {
            if ($dpiPercentage -eq "125") {
                $outputBox.appendtext( "PASS: Display Scale: ${dpiPercentage}%`r`n")
                Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Display scale $dpiPercentage%"
           } else {
                $outputBox.appendtext( "FAIL: Display Scale: ${dpiPercentage}% and it should be 125%`r`n")
                Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Display scale $dpiPercentage%"
            }
        } elseif (($SerialNumber -match "TD13L") -or ($SerialNumber -match "TDG13") -or ($SerialNumber -match "TDH10") -or ($SerialNumber -match "TD110") -or ($SerialNumber -match "TDG10") -or ($SerialNumber -match "TDI12") -or ($SerialNumber -match "TDI15")) {
            if ($dpiPercentage -eq "150") {
                $outputBox.appendtext( "PASS: Display Scale: ${dpiPercentage}%`r`n")
                Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Display scale $dpiPercentage%"
            } else {
                $outputBox.appendtext( "FAIL: Display Scale: ${dpiPercentage}% and it should be 150%`r`n")
                Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Display scale $dpiPercentage%"
            }
        } elseif (($SerialNumber -match "TDTW7") -or ($SerialNumber -match "TEM12")) {
            if ($dpiPercentage -eq "200") {
                $outputBox.appendtext( "PASS: Display Scale: ${dpiPercentage}%`r`n")
                Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Display scale $dpiPercentage%"
            } else {
                $outputBox.appendtext( "FAIL: Display Scale: ${dpiPercentage}% and it should be 200%`r`n")
                Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Display scale $dpiPercentage%"
            }
        }
        
    }
  
    # Get Display Resolution
    $screen = Get-WmiObject Win32_VideoController | Select-Object CurrentHorizontalResolution, CurrentVerticalResolution
    $horizontalResolution = $screen.CurrentHorizontalResolution
    $verticalResolution = $screen.CurrentVerticalResolution
    #$outputBox.appendtext( "Display Resolution: $horizontalResolution x $verticalResolution`r`n")
    if (($SerialNumber -match "TD16L") -or ($SerialNumber -match "TDG16") -or ($SerialNumber -match "TD13L") -or ($SerialNumber -match "TDG13")) {
        if (($horizontalResolution -eq "1920") -and ($verticalResolution -eq "1080")) {
            $outputBox.appendtext( "PASS: Display Resolution: $horizontalResolution x $verticalResolution`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Display Resolution $horizontalResolution x $verticalResolution"
        } else {
            $outputBox.appendtext( "FAIL: Display Resolution $horizontalResolution x $verticalResolution and it should be 1920x1080`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Display Resolution $horizontalResolution x $verticalResolution"
        }
    } elseif (($SerialNumber -match "TDH10") -or ($SerialNumber -match "TD110") -or ($SerialNumber -match "TDG10") -or ($SerialNumber -match "TDTW7")) {
        if (($horizontalResolution -eq "1920") -and ($verticalResolution -eq "1200")) {
            $outputBox.appendtext( "PASS: Display Resolution: $horizontalResolution x $verticalResolution`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Display Resolution $horizontalResolution x $verticalResolution"
        } else {
            $outputBox.appendtext( "FAIL: Display Resolution $horizontalResolution x $verticalResolution and it should be 1920x1200`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Display Resolution $horizontalResolution x $verticalResolution"
        }
    } elseif ($SerialNumber -match "TEM12") {
        if (($horizontalResolution -eq "2736") -and ($verticalResolution -eq "1824")) {
            $outputBox.appendtext( "PASS: Display Resolution: $horizontalResolution x $verticalResolution`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Display Resolution $horizontalResolution x $verticalResolution"
        } else {
            $outputBox.appendtext( "FAIL: Display Resolution $horizontalResolution x $verticalResolution and it should be 2736x1824`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Display Resolution $horizontalResolution x $verticalResolution"
        }
    } elseif (($SerialNumber -match "TDI12") -or ($SerialNumber -match "TDI15")) {
        if (($horizontalResolution -eq "1024") -and ($verticalResolution -eq "768")) {
            $outputBox.appendtext( "PASS: Display Resolution: $horizontalResolution x $verticalResolution`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Display Resolution $horizontalResolution x $verticalResolution"
        } else {
            $outputBox.appendtext( "FAIL: Display Resolution $horizontalResolution x $verticalResolution and it should be 1024x768`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Display Resolution $horizontalResolution x $verticalResolution"
        }
    }
    #Display Orientation
    # Specify the registry key path
    $registryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration\AUO30ED0_1A_07E2_BB^582F9294ABD418FDFA7F91BCA7A32401\00\00"

    # Get the current display orientation from the registry
    $displayOrientation = (Get-ItemProperty -Path $registryKeyPath -Name Rotation).Rotation

    # Interpret the display orientation value
    if ($displayOrientation -eq 0) {
        $orientationText = "Portrait"
    } elseif ($displayOrientation -eq 1) {
        $orientationText = "Landscape"
    } elseif ($displayOrientation -eq 2) {
        $orientationText = "Landscape (flipped)"
    } elseif ($displayOrientation -eq 3) {
        $orientationText = "Portrait (flipped)"
    } else {
        $orientationText = "Unknown"
    }
    
    if ($orientationText -eq "Landscape") {
        $outputBox.appendtext( "PASS: Display orientation: $orientationText`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Display orientation: $orientationText"
    } else {
        $outputBox.appendtext( "FAIL: Display orientation: $orientationText`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Display orientation: $orientationText"
    }

    #Device Mode
    # Check if Tablet Mode is enabled or disabled
    $tabletModeValue = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "TabletMode" -ErrorAction SilentlyContinue
    if ($tabletModeValue.TabletMode -eq 1) {
        if ($SerialNumber -match "TDTW7") {
            $outputBox.appendtext( "PASS: Device Mode: Enabled`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Device Mode: Enabled"
        } else { 
            $outputBox.appendtext( "FAIL: Device Mode: Enabled`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Device Mode: Enabled"
        }
    } elseif ($tabletModeValue.TabletMode -eq 0) {
         if (($SerialNumber -match "TDG16") -or ($SerialNumber -match "TDG13") -or ($SerialNumber -match "TD13L")-or ($SerialNumber -match "TD16L")-or ($SerialNumber -match "TDH10")-or ($SerialNumber -match "TD110")-or ($SerialNumber -match "TDG10")-or ($SerialNumber -match "TEM12")-or ($SerialNumber -match "TDI12")){
            $outputBox.appendtext( "PASS: Device Mode: Disabled`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Device Mode: Disabled"
        } else { 
           $outputBox.appendtext( "FAIL: Device Mode: Disabled`r`n")
            Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Device Mode: Disabled"
        }
       
    } else {
        $outputBox.appendtext( "FAIL: Tablet Mode status: Disabled")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Device Mode: Disabled"
    }

}

#B10
Function PowerSettings {
    $key = 'HKLM:\SOFTWARE\WOW6432Node\Tobii Dynavox\Device' 
    $SerialNumber = (Get-ItemProperty -Path $key)."Serial Number"
    # Verify power settings
    if (($SerialNumber -match "TD16L") -or ($SerialNumber -match "TDG16") -or ($SerialNumber -match "TD13L") -or ($SerialNumber -match "TDG13") -or ($SerialNumber -match "TDH10") -or ($SerialNumber -match "TD110") -or ($SerialNumber -match "TDG10") -or ($SerialNumber -match "TDTW7")) {
        Start-Process control.exe -ArgumentList "/name Microsoft.PowerOptions"
        $results = $wshell.Popup("Verifying that the current Windows power settings is set to:`r`nTurn off the display 10 minutes(on battery) and never(plugged in)`r`nPut the computer to sleep after 10 minutes(on battery) and never(plugged in)`r`n", 0, "Windows power settings Verification", 4+48)
    } elseif (($SerialNumber -match "TDI12") -or ($SerialNumber -match "TDI15")) {
        Start-Process control.exe -ArgumentList "/name Microsoft.PowerOptions"
        $results = $wshell.Popup("Verifying that the current Windows power settings is set to:`r`nTurn off the display never(on battery) and never(plugged in)`r`nPut the computer to sleep after never(on battery) and never(plugged in)`r`n", 0, "Windows power settings Verification", 4+48)
    } elseif ($SerialNumber -match "TEM12") {
        Start-Process control.exe -ArgumentList "/name Microsoft.PowerOptions"
        $results = $wshell.Popup("Verifying that the current Windows power settings is set to:`r`nTurn off the display 15 minutes(on battery) and never(plugged in)`r`nPut the computer to sleep after 15 minutes(on battery) and never(plugged in)`r`n", 0, "Windows power settings Verification", 4+48)
    }
    if ($results -eq 6) {
        $outputBox.appendtext( "PASS: power settings Test`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: power settings Test"
    }
    elseif ($results -eq 7) {
        $outputBox.appendtext( "FAIL: power settings Test`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: power settings Test"
    }

}

#B11
Function Medicare {
    $results = $wshell.Popup("Verifying following apps beeing blocked:`r`nALL, Firefox, Internet Explored, Edge(offline), Windows Media Player, Command Prompt, Registry Editor, Task Manager, Device Manager`r`n", 0, "Medicare Verification", 4+48)
    if ($results -eq 6) {
        $outputBox.appendtext( "PASS: Medicare Test`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date PASS: Medicare Test"
    }
    elseif ($results -eq 7) {
        $outputBox.appendtext( "FAIL: Medicare Test`r`n")
        Add-Content -path "$fpathscript\$getSN-$date1.txt" -Value "$date FAIL: Medicare Test"
    }
}


#Windows forms
$Form = New-Object System.Windows.Forms.Form
$Form.Size = New-Object System.Drawing.Size(600, 590)
$Form.FormBorderStyle = 'Fixed3D'
$Form.MaximizeBox = $False

#Outputbox
$outputBox = New-Object System.Windows.Forms.TextBox
$outputBox.Location = New-Object System.Drawing.Size(10, 50)
$outputBox.Size = New-Object System.Drawing.Size(350, 440)
$outputBox.MultiLine = $True
$outputBox.ScrollBars = "Vertical"
$Form.Controls.Add($outputBox)
$outputBox.font = New-Object System.Drawing.Font ("Consolas" , 8, [System.Drawing.FontStyle]::Regular)

#B1
$Button1 = New-Object System.Windows.Forms.Button
$Button1.Location = New-Object System.Drawing.Size(400, 0)
$Button1.Size = New-Object System.Drawing.Size(160,40)
$Button1.Text = "OEM Setup"
$Button1.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button1)
$Button1.Add_Click{ OEMSetup }

#B2
$Button2 = New-Object System.Windows.Forms.Button
$Button2.Location = New-Object System.Drawing.Size(400, 40)
$Button2.Size = New-Object System.Drawing.Size(160, 40)
$Button2.Text = "Startup Wizard"
$Button2.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button2)
$Button2.Add_Click{ StartupWizard }

#B3
$Button3 = New-Object System.Windows.Forms.Button
$Button3.Location = New-Object System.Drawing.Size(400, 80)
$Button3.Size = New-Object System.Drawing.Size(160, 40)
$Button3.Text = "Configuration"
$Button3.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button3)
$Button3.Add_Click{ ConfigurationVerification }

#B4
$Button4 = New-Object System.Windows.Forms.Button
$Button4.Location = New-Object System.Drawing.Size(400, 120)
$Button4.Size = New-Object System.Drawing.Size(160, 40)
$Button4.Text = "Apps Version"
$Button4.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button4)
$Button4.Add_Click{ ApplicationV }

#B5
$Button5 = New-Object System.Windows.Forms.Button
$Button5.Location = New-Object System.Drawing.Size(400, 160)
$Button5.Size = New-Object System.Drawing.Size(160, 40)
$Button5.Text = "C5 Content"
$Button5.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button5)
$Button5.Add_Click{ C5Content }

#B6
$Button6 = New-Object System.Windows.Forms.Button
$Button6.Location = New-Object System.Drawing.Size(400, 200)
$Button6.Size = New-Object System.Drawing.Size(160, 40)
$Button6.Text = "C5 Voices"
$Button6.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button6)
$Button6.Add_Click{ C5Voices }

#B7
$Button7 = New-Object System.Windows.Forms.Button
$Button7.Location = New-Object System.Drawing.Size(400, 240)
$Button7.Size = New-Object System.Drawing.Size(160, 40)
$Button7.Text = "Apps Verification"
$Button7.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button7)
$Button7.Add_Click{ ApplicationVerification }

#B8
$Button8 = New-Object System.Windows.Forms.Button
$Button8.Location = New-Object System.Drawing.Size(400, 280)
$Button8.Size = New-Object System.Drawing.Size(160, 40)
$Button8.Text = "HW Verification"
$Button8.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button8)
$Button8.Add_Click{ HWVerification }

#B9
$Button9 = New-Object System.Windows.Forms.Button
$Button9.Location = New-Object System.Drawing.Size(400, 320)
$Button9.Size = New-Object System.Drawing.Size(160, 40)
$Button9.Text = "Windows Settings"
$Button9.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button9)
$Button9.Add_Click{ WindowsSettings }

#B10
$Button10 = New-Object System.Windows.Forms.Button
$Button10.Location = New-Object System.Drawing.Size(400, 360)
$Button10.Size = New-Object System.Drawing.Size(160, 40)
$Button10.Text = "Power Settings"
$Button10.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button10)
$Button10.Add_Click{ PowerSettings }

#B11
$Button11 = New-Object System.Windows.Forms.Button
$Button11.Location = New-Object System.Drawing.Size(400, 400)
$Button11.Size = New-Object System.Drawing.Size(160, 40)
$Button11.Text = "Medicare"
$Button11.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button11)
$Button11.Add_Click{ Medicare }


#Form name + activate form.
$Form.Text = $fileversion
$Form.Add_Shown( { $Form.Activate() })
$Form.ShowDialog()