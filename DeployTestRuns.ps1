$fileversion = "DeployTestRuns.ps1" #$fileversion = "v1.2"
#Author: AMMAR ELYAS (ammar.elyas@tobiidynavox.com)

#Forces powershell to run as an admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{ Start-Process powershell.exe "-NoProfile -Windowstyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

#Imports Windowsforms and Drawing from system and Allows the use of wshell for confirmation popups
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
$wshell = New-Object -ComObject Wscript.Shell

$PSScriptRoot
$fpathscript = Get-ChildItem -Path $PSScriptRoot -Filter "$fileversion" -Recurse -erroraction SilentlyContinue | Select-Object -expand Fullname | Split-Path
$date = get-date -f "yyyy-MM-dd hh:mm:ss"
$date1 = get-date -f "yyyy-MM-dd"

Function Convert-LanguageIDToName {
    param(
        [int]$languageID
    )
    # Define a hashtable with language IDs and their corresponding names
    $languageNames = @{
        1028 = "Chinese"
        1030 = "Danish"
        1031 = "German"
        1033 = "US-English"
        1035 = "Finnish"
        1036 = "French (Fr)"
        3084 = "French (Ca)"
        1040 = "Italian"
        1041 = "Japanese"
        1043 = "Dutch"
        1044 = "Norwegian"
        1046 = "Portugul(Br)"
        1053 = "Swedish"
        2057 = "UK-English"
        3082 = "Spanish (Sp)"
        2058 = "Spanish (Mx)"
    }

    # Convert language ID to name using the hashtable
    $languageName = $languageNames[$languageID]

    # Return the language name
    return $languageName
}

$csproduct = Get-CimInstance -Class Win32_ComputerSystemProduct
$model = $csproduct.IdentifyingNumber.SubString(0, 5)
$Model2 = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation").Model

if ((($model -eq "TDG13") -or ($model -eq "TDG16")) -and ($Model2 -eq "I-Series")) {
    $DeviceModel = "ISeries"

} else {
    $DeviceModel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation").Model
}
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
$languageID = [convert]::ToInt32($osInfo.Locale, 16)
$languageName = Convert-LanguageIDToName -languageID $languageID
$osedition = $osInfo.Caption
$osVersion = $osInfo.Version
$windowsEdition = if ($osedition -match "Pro") { "Pro" } else { "Other" }
$versionMappings = @{ 
                '18362' = '1903'
                '18363' = '1909'
                '19041' = '2004'
                '19042' = '20H2'
                '19043' = '21H1'
                '19044' = '21H2'
                '19045' = '22H2'
                '22000' = '21H2'
                '22621' = '22H2'
                }
$matchingKey = $versionMappings.Keys | Where-Object { $osVersion -like "*$_*" }
$windowsVersion = if ($matchingKey) { $versionMappings[$matchingKey] } 

Function LogPass {
    param (
        [string]$message,
        [System.Windows.Forms.TextBox]$outputBox,
        [System.Windows.Forms.Button]$button,
        [System.Drawing.Color]$backgroundColor
    )
    $logFilePath = "$fpathscript\$DeviceModel-$model-$languageName-$date1.txt"
    
    if ($outputBox -ne $null) {
        $outputBox.appendtext("$message")
    }
    
    Add-Content -Path $logFilePath -Value "$date $message"

    if ($button -ne $null -and $backgroundColor -ne $null) {
        $button.BackColor = $backgroundColor
    }
}

LogPass -message "DeviceModel: $DeviceModel`r`nLanguageID: $languageID($languageName)`r`nOSEdition: $osedition`r`nOSVersion: $osVersion`r`n" -outputBox $outputBox

#Save config file
$Configpath = "C:\Users\Qa\AppData\Local\Temp\TdxConfigurationManager.log"
if (Test-Path $Configpath) {
    Copy-Item -Path $Configpath -Destination $fpathscript 
#Rename-Item -Path "$fpathscript\TdxConfigurationManager.log" -NewName "$DeviceModel-$model-$languageName-TdxConfigurationManager.log" -Force
    $sourceFilePath = "$fpathscript\TdxConfigurationManager.log"
    $newFileName = "$DeviceModel-$model-$languageName-TdxConfigurationManager.log"
    $destinationFilePath = Join-Path -Path $fpathscript -ChildPath $newFileName
    # Check if the destination file already exists and delete it if it does
    if (Test-Path -Path $destinationFilePath -PathType Leaf) {
        Remove-Item -Path $destinationFilePath -Force
    }

    # Rename the source file to the new name
    Rename-Item -Path $sourceFilePath -NewName $newFileName -Force
}

# Load the XML file and Select all software requirements
$xmlFilePath = "$fpathscript\file.xml"
$encoding = [System.Text.Encoding]::UTF8
$xmlContent = [System.IO.File]::ReadAllText($xmlFilePath, $encoding)
$xml = [xml]$xmlContent
$allRequirements = $xml.SelectNodes("//SoftwareRequirement")
$allC5Nodes = $xml.SelectNodes("//C5")
$allC5VoiceNodes = $xml.SelectNodes("//C5voice")

#Application versions
$reqSWResult = $null
$installedSWResult = $null

#B1 Function listapps - outputs all installed apps with the publisher Tobii
Function OEMSetup {
    $results = $wshell.Popup("Verify that device starts to screen to start OEM Setup.`r`nVerify remaining OEM Setup runs and continues.`r`nVerify that the QR Scanner opens through the TD Config Mgr.`r`nFinish Tobii Dynavox Configuration Steps.`r`nVerify the Windows is in the Language that was selected.`r`n", 0, "OEM Setup test", 4+48)

    if ($results -eq 6) {
        LogPass -message "PASS: OEM Setup Test`r`n" -outputBox $outputBox
    }
    elseif ($results -eq 7) {
        LogPass -message "FAIL: OEM Setup Test`r`n" -outputBox $outputBox
    } 
}

#B2
Function StartupWizard {
    $results = $wshell.Popup("Once the Configuration Manager completes, the device should restart and open the Startup Wizard.`r`nSelect 'Help Me Choose'.`r`nSelect 'Go Back'.`r`nSelect one of the two applications, then select the 'Select' button.`r`nFollow the Steps to complete the setup for the application you had selected. Then restart the device.`r`n", 0, "Startup Wizard test", 4+48)
    
    if ($results -eq 6) {
        LogPass -message "PASS: Startup Wizard Test`r`n" -outputBox $outputBox
    }
    elseif ($results -eq 7) {
        LogPass -message "FAIL: Startup Wizard Test`r`n" -outputBox $outputBox
    } 
}

Function xmlReqSW {
    # Array to store all requirements
    $ModelEmpty = @()
    $ModelTDISeries = @()
    $ModelISeries = @()
    $ModelISeriesPlus = @()
    $ModelTEM12 = @()
    $ModelIndi = @()
    $ModelIndi7 = @()
    $ModelI110 = @()
    $ModelI110850 = @()

    foreach ($requirement in $allRequirements) {
        $modelNode = $requirement.SelectSingleNode("Model")
        $model = $requirement.SelectSingleNode("Model").InnerText -split ', '
        $os = $requirement.SelectSingleNode("OS").InnerText
        $langIDNode = $requirement.SelectSingleNode("LanguageID")
        $langIDs = $requirement.SelectSingleNode("LanguageID").InnerText -split ', '

        if ((($modelNode -eq $null) -and ($langIDNode -eq $null)) -or (($langIDNode -ne $null) -and ($langIDs -eq $languageID) -and ($modelNode -eq $null))) {
            $ModelEmpty += $requirement.SelectSingleNode("Name").InnerText
        }
        
        if ($model -contains 'I-Series') {
            $ModelTDISeries += $requirement.SelectSingleNode("Name").InnerText
        }
        if  ((($model -contains 'ISeries') -and ($os -eq $null)) -or (($os -ne $null) -and ($os -eq $windowsEdition))) {
            $ModelISeries += $requirement.SelectSingleNode("Name").InnerText
        }
        if ($model -contains 'I-Series+') {
            $ModelISeriesPlus += $requirement.SelectSingleNode("Name").InnerText
        }
        if ($model -contains 'TEM12') {
            $ModelTEM12 += $requirement.SelectSingleNode("Name").InnerText
        }
        if ($model -contains 'Indi') {
            $ModelIndi += $requirement.SelectSingleNode("Name").InnerText
        }
        if ($model -contains 'Indi 7') {
            $ModelIndi7 += $requirement.SelectSingleNode("Name").InnerText
        }
        if ($model -contains 'I-110') {
            $ModelI110 += $requirement.SelectSingleNode("Name").InnerText
        }
        if ($model -contains 'I-110-850') {
            $ModelI110850 += $requirement.SelectSingleNode("Name").InnerText
        }
    }

    if ($DeviceModel -eq 'I-Series'){
        $reqSW = $ModelTDISeries + $ModelEmpty
    }
    elseif ($DeviceModel -eq 'ISeries'){
        $reqSW = $ModelISeries + $ModelEmpty
    }
    elseif ($DeviceModel -eq 'I-Series+'){
        $reqSW = $ModelISeriesPlus + $ModelEmpty
    }
    elseif ($DeviceModel -eq 'TEM12'){
        $reqSW = $ModelTEM12 + $ModelEmpty
    }
    elseif ($DeviceModel -eq 'Indi'){
        $reqSW = $ModelIndi + $ModelEmpty
    }
    elseif ($DeviceModel -eq 'Indi 7'){
        $reqSW = $ModelIndi7 + $ModelEmpty
    }
    elseif ($DeviceModel -eq 'I-110'){
        $reqSW = $ModelI110 + $ModelEmpty
    }
    elseif ($DeviceModel -eq "I-110-850"){
        $reqSW = $ModelI110850 + $ModelEmpty
    } 
    $global:reqSWResult = $reqSW

}

Function DeviceInstalledSW {
$uninstallKeys = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
    $TobiiVer += Get-ItemProperty -Path $uninstallKeys | Where-Object { 
        ($_.Displayname -eq "Accessible Literacy Learning (ALL)") -or
        ($_.Displayname -match ".*Tobii.*") -or
        ($_.Displayname -match ".*Join-in.*") -or
        ($_.Displayname -match ".*Mirror.*") -or
        ($_.Displayname -match ".*I-Series.*") -or
        ($_.Displayname -match ".*TD Snap.*") -or
        ($_.Displayname -match ".*Compass.*") -or
        ($_.Displayname -match ".*Boardmaker.*") -or
        ($_.Displayname -match ".*Eye FX.*") -or
        ($_.Displayname -match ".*Startup.*") -or
        ($_.Displayname -match ".*ONYX.*") -or
        ($_.Displayname -match ".*I-110.*") -or
        ($_.Displayname -match ".*Windows Control.*") -or
        ($_.Displayname -match ".*HID.*") -or
        ($_.Displayname -match ".*Gaze Interaction Software.*") -or
        ($_.Displayname -match ".*Hardware Service.*") -or
        ($_.Displayname -match ".*Diagnostic Tool.*") -or
        ($_.Displayname -match ".*Discover.*") -or
        ($_.Displayname -match ".*Pathways.*")-or
        ($_.Displayname -match ".*ISeries.*")-or
        ($_.Displayname -match ".*Zoom.*")-or
        ($_.Name -match ".*Eye FX.*") -or
        ($_.Name -match ".*Snap.*")
        } | Select-Object Displayname, UninstallString, Name

    $TobiiVer += Get-AppxPackage -Name *Snap*| Select-Object Name, Version
    $TobiiVer += Get-AppxPackage -Name *Discover*| Select-Object Name, Version
    $installedSW = @()
    foreach ($entry in $TobiiVer) {
        if ($entry.DisplayName) {
            $installedSW += $entry.DisplayName
        }
        if ($entry.Name) {
            $installedSW += $entry.Name
        }
    }
    $installedSW = $installedSW | Select-Object -Unique
    $global:installedSWResult = $installedSW
}

#B3
Function ConfigurationVerification {
    $results = $wshell.Popup("Each Configuration will deploy specific Applications based on the licensing and by the Language in which it is configured to.`r`n", 0, "Configuration Verification", 0x0)
    xmlReqSW
    $1 = $global:reqSWResult
    DeviceInstalledSW
    $2 = $global:installedSWResult

    #SW that required but not installed:
    $Uninstnames = (Compare-Object -DifferenceObject $1 -ReferenceObject $2 -CaseSensitive | 
        Where-Object { $_.InputObject -notlike "*Updater Service*" -and $_.InputObject -notlike "*Launcher*" -and $_.SideIndicator -eq "=>" } | 
        Select-Object -ExpandProperty InputObject)
    #SW that installed but not required:
    $Uninstnames2 = (Compare-Object -DifferenceObject $1 -ReferenceObject $2 -CaseSensitive | 
        Where-Object { $_.InputObject -notlike "*Updater Service*" -and $_.InputObject -notlike "*Launcher*" -and $_.SideIndicator -eq "<=" } | 
        Select-Object -ExpandProperty InputObject)

    if ($Uninstnames -gt $null){
        foreach ($Uninstname in $Uninstnames){
            LogPass -message "FAIL: Configuration Verification: $Uninstname is not installed`r`n" -outputBox $outputBox
        }
    } 
    if ($Uninstnames2 -gt $null){
        foreach ($Uninstname2 in $Uninstnames2){
            LogPass -message "FAIL: Configuration Verification: $Uninstname2 installed but not required`r`n" -outputBox $outputBox
        }
    } 
    if (($Uninstnames -eq $null) -or ($Uninstnames2 -eq $null)){
        LogPass -message "PASS: all required SW are installed.`r`n" -outputBox $outputBox
    }
}

#B4
Function ApplicationVersions {
    $results = $wshell.Popup("Verifying that necessary Applications are deployed in the correct version.`r`n", 0, "Application Version test", 0x0)
    DeviceInstalledSW
    
    $xmlinstalledSWs = $global:installedSWResult  | Where-Object { $_ -notlike "*Updater Service*" -and $_ -notlike "*Launcher*" -and $_ -notlike "*Tobii Dynavox Hardware Service*"} | Sort-Object
    Foreach ($xmlswName in $xmlinstalledSWs) {
        $softwareNode = $xml.SelectSingleNode("//SoftwareRequirement[Name=""$xmlswName""]")

        if ($softwareNode -ne $null) {
            $xmlversion = $softwareNode.SelectSingleNode("Version").InnerText
        }
        $uninstallKeys = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $installedswversion = (Get-ItemProperty -Path $uninstallKeys | Where-Object { 
            ($_.DisplayName -eq "$xmlswName") 
             } | Select-Object -ExpandProperty DisplayVersion)
        if ($xmlswName -match "TDSnapKioskTool") {
            $installedswversion = (Get-AppxPackage -Name *SnapKioskTool*| Select-Object Version).Version
        
        } elseif ($xmlswName -match "TobiiDynavox.Snap") {
            $installedswversion = (Get-AppxPackage -Name *TobiiDynavox.Snap*| Select-Object Version).Version
        
        } elseif ($xmlswName -match "Discover") {
            $installedswversion = (Get-AppxPackage -Name *TobiiDynavox.DiscoverTobiiDynavox*| Select-Object Version).Version
        
        }                 
        $installedswversion = $installedswversion | Select-Object -Unique
        $CompareVersions = Compare-Object -DifferenceObject $xmlversion -ReferenceObject $installedswversion -CaseSensitive
        
        if ($CompareVersions -ne $null) {
            LogPass -message "FAIL: $xmlswName installed version is $installedswversion while it should be $xmlversion according to XML file`r`n" -outputBox $outputBox
        } 
    }

    #chech for TD HW Service that has two diffiernet versions:
    $xmlswName = "Tobii Dynavox Hardware Service"

    if ($DeviceModel -eq "I-110"){
        $xmlversion = ($xml.SelectSingleNode("//SoftwareRequirement[Name=""Tobii Dynavox Hardware Service"" and Model='I-110' ]")).version
    } else {
        $xmlversion = ($xml.SelectSingleNode("//SoftwareRequirement[Name=""Tobii Dynavox Hardware Service""]")).version
    }

    $uninstallKeys = @(
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $installedswversion = (Get-ItemProperty -Path $uninstallKeys | Where-Object { 
        ($_.DisplayName -eq "$xmlswName") 
        } | Select-Object -ExpandProperty DisplayVersion) | Select-Object -Unique
                         
    $CompareVersions = Compare-Object -DifferenceObject $xmlversion -ReferenceObject $installedswversion -CaseSensitive
        
    if ($CompareVersions -ne $null) {
        LogPass -message "FAIL: $xmlswName installed version is $installedswversion while it shoule be $xmlversion according to XML file`r`n" -outputBox $outputBox
    }
}

#B5
Function C5Content {
    $results = $wshell.Popup("Verifying that the proper content is available for Communicator.`r`n", 0, "C5 Content test", 0x0)
    foreach ($node in $allC5Nodes) {
        $C5Name = $node.SelectSingleNode("C5Name").InnerText
        $C5LanguageIDs = $node.SelectSingleNode("LanguageID").InnerText -split ', '
        if ($C5LanguageIDs -contains $languageID) {
            $installedC5SW = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { 
                ($_.Displayname -match "$C5Name") } | Select-Object DisplayName).DisplayName
            if (!($installedC5SW)) {
                LogPass -message "FAIL: $C5Name is not installed but required`r`n" -outputBox $outputBox
            } else {
                LogPass -message "PASS: $C5Name is installed`r`n" -outputBox $outputBox
            }
        }
    }
}

#B6
Function C5Voices {
    foreach ($node in $allC5VoiceNodes) {
        $C5VoiceLanguageID = [int]$node.SelectSingleNode("LanguageID").InnerText
        if ($C5VoiceLanguageID -eq $languageID) {
            $C5Voices = $node.SelectSingleNode("C5Voices").InnerText -split ', '
        }
    }
    $results = $wshell.Popup("Verifying that the proper voices are available.`r`n$C5Voices`r`n Press YES or NO`r`n", 0, "C5 Voices test", 4+48)
    if ($results -eq 6) {
        LogPass -message "PASS: C5 Voices Test`r`n" -outputBox $outputBox
    }
    elseif ($results -eq 7) {
        LogPass -message "FAIL: C5 Voices Test`r`n" -outputBox $outputBox
    } 
}

#B7
Function ApplicationVerification {
    Add-Type -AssemblyName System.Windows.Forms    
    Add-Type -AssemblyName System.Drawing
    # Build Form
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Application Verification"
    $Form.Size = New-Object System.Drawing.Size(410, 730)
    $Form.StartPosition = "CenterScreen"
    
    # Button configuration data
    $buttonsConfig = @(
        @{ Text = "Snap Setup";           Message = "Verifying that the Setup Wizard can be completed successfully, as well as having the correct content and voices available." }
        @{ Text = "Snap";                 Message = "A quick Sanity Check of Snap should be run to make sure all major components are working as expected. This is just a quick test." }
        @{ Text = "C5";                   Message = "A quick Sanity Check of Communicator should be run to make sure all major components are working as expected. This is just a quick test." }
        @{ Text = "C5 Join-in";           Message = "A quick Sanity Check of Join-in apps should be run and working as expected." }
        @{ Text = "HS";                   Message = "Verifying that the Hardware Settings Application works as expected." }
        @{ Text = "Diagnostic tool";      Message = "Verifying that the Diagnostic tool works as expected." }
        @{ Text = "ALL";                  Message = "Running a quick Sanity Check for ALL. ALL will be installed on a Locked device, however it is blocked by In-Touch Lock." }
        @{ Text = "UN";                   Message = "Running a quick Sanity Check for Update Notifier." }
        @{ Text = "Snap Scene";           Message = "Running a quick Sanity Check on Snap Scene." }
        @{ Text = "BM7/BM";               Message = "Running a quick Sanity Check on Student Center." }
        @{ Text = "TD Control";           Message = "Verifying that Control works as expected." }
        @{ Text = "TD Browse";            Message = "Verifying that TD Browse is deployed and working as expected." }
        @{ Text = "TD Phone";             Message = "Verifying the TD Phone is installed and working as expected." }
        @{ Text = "TD Talk";              Message = "Verifying that TD Talk is deployed properly and is working as expected." }
        @{ Text = "Switcher";             Message = "Verifying that TD Switcher works as expected." }
        @{ Text = "Gaze Viewer";          Message = "Verifying that the Gaze Viewer launches and Eye Tracking can be used." }
        @{ Text = "ETS";                  Message = "Verifying that the Eye Tracking Settings Application is working as expected." }
        @{ Text = "EyeFX";                Message = "Verifying that the Sensory Eye FX 2 Demo launches and Eye Tracking can be used." }
        @{ Text = "Learning Curve";       Message = "Verifying that the Eye Gaze Learning Curve launches and L2L can be installed." }
        @{ Text = "User Manual";          Message = "Verifying that the I-Series User's Manual App has been installed and opens as expected." }
        @{ Text = "Control Center";       Message = "Verifying that the Control Center has been installed and works as expected." }
        @{ Text = "TGIS";                 Message = "Verifying that the TGIS has been installed and works as expected." }
        @{ Text = "WC2";                  Message = "Verifying that the WC2 has been installed and works as expected." }
    )
    # Add Button1
    $Button1 = New-Object System.Windows.Forms.Button
    $Button1.Location = New-Object System.Drawing.Size(40, 40)
    $Button1.Size = New-Object System.Drawing.Size(150, 50)
    $Button1.Text = $buttonsConfig[0].Text
    $Button1.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button1)
    
    # Add Button2
    $Button2 = New-Object System.Windows.Forms.Button
    $Button2.Location = New-Object System.Drawing.Size(190, 40)
    $Button2.Size = New-Object System.Drawing.Size(150, 50)
    $Button2.Text = $buttonsConfig[1].Text
    $Button2.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button2)

    # Add Button3
    $Button3 = New-Object System.Windows.Forms.Button
    $Button3.Location = New-Object System.Drawing.Size(40, 90)
    $Button3.Size = New-Object System.Drawing.Size(150, 50)
    $Button3.Text = $buttonsConfig[2].Text
    $Button3.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button3)
    
    # Add Button4
    $Button4 = New-Object System.Windows.Forms.Button
    $Button4.Location = New-Object System.Drawing.Size(190, 90)
    $Button4.Size = New-Object System.Drawing.Size(150, 50)
    $Button4.Text = $buttonsConfig[3].Text
    $Button4.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button4)

    # Add Button5
    $Button5 = New-Object System.Windows.Forms.Button
    $Button5.Location = New-Object System.Drawing.Size(40, 140)
    $Button5.Size = New-Object System.Drawing.Size(150, 50)
    $Button5.Text = $buttonsConfig[4].Text
    $Button5.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button5)
    
    # Add Button6
    $Button6 = New-Object System.Windows.Forms.Button
    $Button6.Location = New-Object System.Drawing.Size(190, 140)
    $Button6.Size = New-Object System.Drawing.Size(150, 50)
    $Button6.Text = $buttonsConfig[5].Text
    $Button6.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button6)

    # Add Button7
    $Button7 = New-Object System.Windows.Forms.Button
    $Button7.Location = New-Object System.Drawing.Size(40, 190)
    $Button7.Size = New-Object System.Drawing.Size(150, 50)
    $Button7.Text = $buttonsConfig[6].Text
    $Button7.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button7)
    
    # Add Button8
    $Button8 = New-Object System.Windows.Forms.Button
    $Button8.Location = New-Object System.Drawing.Size(190, 190)
    $Button8.Size = New-Object System.Drawing.Size(150, 50)
    $Button8.Text = $buttonsConfig[7].Text
    $Button8.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button8)

    # Add Button9
    $Button9 = New-Object System.Windows.Forms.Button
    $Button9.Location = New-Object System.Drawing.Size(40, 240)
    $Button9.Size = New-Object System.Drawing.Size(150, 50)
    $Button9.Text = $buttonsConfig[8].Text
    $Button9.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button9)
    
    # Add Button10
    $Button10 = New-Object System.Windows.Forms.Button
    $Button10.Location = New-Object System.Drawing.Size(190, 240)
    $Button10.Size = New-Object System.Drawing.Size(150, 50)
    $Button10.Text = $buttonsConfig[9].Text
    $Button10.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button10)

    # Add Button11
    $Button11 = New-Object System.Windows.Forms.Button
    $Button11.Location = New-Object System.Drawing.Size(40, 290)
    $Button11.Size = New-Object System.Drawing.Size(150, 50)
    $Button11.Text = $buttonsConfig[10].Text
    $Button11.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button11)
    
    # Add Button12
    $Button12 = New-Object System.Windows.Forms.Button
    $Button12.Location = New-Object System.Drawing.Size(190, 290)
    $Button12.Size = New-Object System.Drawing.Size(150, 50)
    $Button12.Text = $buttonsConfig[11].Text
    $Button12.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button12)

    # Add Button13
    $Button13 = New-Object System.Windows.Forms.Button
    $Button13.Location = New-Object System.Drawing.Size(40, 340)
    $Button13.Size = New-Object System.Drawing.Size(150, 50)
    $Button13.Text = $buttonsConfig[12].Text
    $Button13.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button13)
    
    # Add Button14
    $Button14 = New-Object System.Windows.Forms.Button
    $Button14.Location = New-Object System.Drawing.Size(190, 340)
    $Button14.Size = New-Object System.Drawing.Size(150, 50)
    $Button14.Text = $buttonsConfig[13].Text
    $Button14.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button14)

    # Add Button15
    $Button15 = New-Object System.Windows.Forms.Button
    $Button15.Location = New-Object System.Drawing.Size(40, 390)
    $Button15.Size = New-Object System.Drawing.Size(150, 50)
    $Button15.Text = $buttonsConfig[14].Text
    $Button15.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button15)
    
    # Add Button16
    $Button16 = New-Object System.Windows.Forms.Button
    $Button16.Location = New-Object System.Drawing.Size(190, 390)
    $Button16.Size = New-Object System.Drawing.Size(150, 50)
    $Button16.Text = $buttonsConfig[15].Text
    $Button16.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button16)

    # Add Button17
    $Button17 = New-Object System.Windows.Forms.Button
    $Button17.Location = New-Object System.Drawing.Size(40, 440)
    $Button17.Size = New-Object System.Drawing.Size(150, 50)
    $Button17.Text = $buttonsConfig[16].Text
    $Button17.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button17)
    
    # Add Button18
    $Button18 = New-Object System.Windows.Forms.Button
    $Button18.Location = New-Object System.Drawing.Size(190, 440)
    $Button18.Size = New-Object System.Drawing.Size(150, 50)
    $Button18.Text = $buttonsConfig[17].Text
    $Button18.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button18)

    # Add Button19
    $Button19 = New-Object System.Windows.Forms.Button
    $Button19.Location = New-Object System.Drawing.Size(40, 490)
    $Button19.Size = New-Object System.Drawing.Size(150, 50)
    $Button19.Text = $buttonsConfig[18].Text
    $Button19.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button19)

    # Add Button20
    $Button20 = New-Object System.Windows.Forms.Button
    $Button20.Location = New-Object System.Drawing.Size(190, 490)
    $Button20.Size = New-Object System.Drawing.Size(150, 50)
    $Button20.Text = $buttonsConfig[19].Text
    $Button20.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button20)

    # Add Button21
    $Button21 = New-Object System.Windows.Forms.Button
    $Button21.Location = New-Object System.Drawing.Size(40, 540)
    $Button21.Size = New-Object System.Drawing.Size(150, 50)
    $Button21.Text = $buttonsConfig[20].Text
    $Button21.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button21)

    # Add Button22
    $Button22 = New-Object System.Windows.Forms.Button
    $Button22.Location = New-Object System.Drawing.Size(190, 540)
    $Button22.Size = New-Object System.Drawing.Size(150, 50)
    $Button22.Text = $buttonsConfig[21].Text
    $Button22.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button22)

    # Add Button23
    $Button23 = New-Object System.Windows.Forms.Button
    $Button23.Location = New-Object System.Drawing.Size(40, 590)
    $Button23.Size = New-Object System.Drawing.Size(150, 50)
    $Button23.Text = $buttonsConfig[22].Text
    $Button23.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button23)


    $Button1.Add_Click({
        $results = $wshell.Popup($buttonsConfig[0].Message, 0, $buttonsConfig[0].Text + "Test" , 0x0)
    })
    $Button2.Add_Click({
        $results = $wshell.Popup($buttonsConfig[1].Message, 0, $buttonsConfig[1].Text + "Test" , 0x0)
    })
    $Button3.Add_Click({
        $results = $wshell.Popup($buttonsConfig[2].Message, 0, $buttonsConfig[2].Text + "Test" , 0x0)
    })
    $Button4.Add_Click({
        $results = $wshell.Popup($buttonsConfig[3].Message, 0, $buttonsConfig[3].Text + "Test" , 0x0)
    })
    $Button5.Add_Click({
        $results = $wshell.Popup($buttonsConfig[4].Message, 0, $buttonsConfig[4].Text + "Test" , 0x0)
    })
    $Button6.Add_Click({
        $results = $wshell.Popup($buttonsConfig[5].Message, 0, $buttonsConfig[5].Text + "Test" , 0x0)
    })
    $Button7.Add_Click({
        $results = $wshell.Popup($buttonsConfig[6].Message, 0, $buttonsConfig[6].Text + "Test" , 0x0)
    })
    $Button8.Add_Click({
        $results = $wshell.Popup($buttonsConfig[7].Message, 0, $buttonsConfig[7].Text + "Test" , 0x0)
    })
    $Button9.Add_Click({
        $results = $wshell.Popup($buttonsConfig[8].Message, 0, $buttonsConfig[8].Text + "Test" , 0x0)
    })
    $Button10.Add_Click({
        $results = $wshell.Popup($buttonsConfig[9].Message, 0, $buttonsConfig[9].Text + "Test" , 0x0)
    })
    $Button11.Add_Click({
        $results = $wshell.Popup($buttonsConfig[10].Message, 0, $buttonsConfig[10].Text + "Test" , 0x0)
    })
    $Button12.Add_Click({
        $results = $wshell.Popup($buttonsConfig[11].Message, 0, $buttonsConfig[11].Text + "Test" , 0x0)
    })
    $Button13.Add_Click({
        $results = $wshell.Popup($buttonsConfig[12].Message, 0, $buttonsConfig[12].Text + "Test" , 0x0)
    })
    $Button14.Add_Click({
        $results = $wshell.Popup($buttonsConfig[13].Message, 0, $buttonsConfig[13].Text + "Test" , 0x0)
    })
    $Button15.Add_Click({
        $results = $wshell.Popup($buttonsConfig[14].Message, 0, $buttonsConfig[14].Text + "Test" , 0x0)
    })
    $Button16.Add_Click({
        $results = $wshell.Popup($buttonsConfig[15].Message, 0, $buttonsConfig[15].Text + "Test" , 0x0)
    })
    $Button17.Add_Click({
        $results = $wshell.Popup($buttonsConfig[16].Message, 0, $buttonsConfig[16].Text + "Test" , 0x0)
    })
    $Button18.Add_Click({
        $results = $wshell.Popup($buttonsConfig[17].Message, 0, $buttonsConfig[17].Text + "Test" , 0x0)
    })
    $Button19.Add_Click({
        $results = $wshell.Popup($buttonsConfig[18].Message, 0, $buttonsConfig[18].Text + "Test" , 0x0)
    })
    $Button20.Add_Click({
        $results = $wshell.Popup($buttonsConfig[19].Message, 0, $buttonsConfig[19].Text + "Test" , 0x0)
    })
    $Button21.Add_Click({
        $results = $wshell.Popup($buttonsConfig[20].Message, 0, $buttonsConfig[20].Text + "Test" , 0x0)
    })
    $Button22.Add_Click({
        $results = $wshell.Popup($buttonsConfig[21].Message, 0, $buttonsConfig[21].Text + "Test" , 0x0)
    })
    $Button23.Add_Click({
        $results = $wshell.Popup($buttonsConfig[22].Message, 0, $buttonsConfig[22].Text + "Test" , 0x0)
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
    if (($DeviceModel -eq "I-Series") -or ($DeviceModel -eq "ISeries")) {

        # Add Button1
        $Button1 = New-Object System.Windows.Forms.Button
        $Button1.Location = New-Object System.Drawing.Size(40, 40)
        $Button1.Size = New-Object System.Drawing.Size(150, 50)
        $Button1.Text = "Adaptive Volume Buttons"
        $Button1.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
        $Form.Controls.Add($Button1)
    
        # Add Button2
        $Button2 = New-Object System.Windows.Forms.Button
        $Button2.Location = New-Object System.Drawing.Size(190, 40)
        $Button2.Size = New-Object System.Drawing.Size(150, 50)
        $Button2.Text = "Partner Window"
        $Button2.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
        $Form.Controls.Add($Button2)
    }
    if (($DeviceModel -eq "I-Series") -or ($DeviceModel -eq "ISeries") -or ($DeviceModel -eq "I-110-850")) {

        # Add Button3
        $Button3 = New-Object System.Windows.Forms.Button
        $Button3.Location = New-Object System.Drawing.Size(40, 90)
        $Button3.Size = New-Object System.Drawing.Size(150, 50)
        $Button3.Text = "Switch Ports"
        $Button3.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
        $Form.Controls.Add($Button3)    
    
        # Add Button4
        $Button4 = New-Object System.Windows.Forms.Button
        $Button4.Location = New-Object System.Drawing.Size(190, 90)
        $Button4.Size = New-Object System.Drawing.Size(150, 50)
        $Button4.Text = "IR"
        $Button4.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
        $Form.Controls.Add($Button4)
    }
    # Add Button5
    $Button5 = New-Object System.Windows.Forms.Button
    $Button5.Location = New-Object System.Drawing.Size(40, 140)
    $Button5.Size = New-Object System.Drawing.Size(150, 50)
    $Button5.Text = "Bluetooth"
    $Button5.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button5)

    # Add Button6
    $Button6 = New-Object System.Windows.Forms.Button
    $Button6.Location = New-Object System.Drawing.Size(190, 140)
    $Button6.Size = New-Object System.Drawing.Size(150, 50)
    $Button6.Text = "Camera"
    $Button6.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button6)

    # Add Button7
    $Button7 = New-Object System.Windows.Forms.Button
    $Button7.Location = New-Object System.Drawing.Size(40, 190)
    $Button7.Size = New-Object System.Drawing.Size(150, 50)
    $Button7.Text = "Microphone"
    $Button7.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button7)
    
    # Add Button8
    $Button8 = New-Object System.Windows.Forms.Button
    $Button8.Location = New-Object System.Drawing.Size(190, 190)
    $Button8.Size = New-Object System.Drawing.Size(150, 50)
    $Button8.Text = "Headphones Port"
    $Button8.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button8)

    # Add Button9
    $Button9 = New-Object System.Windows.Forms.Button
    $Button9.Location = New-Object System.Drawing.Size(40, 240)
    $Button9.Size = New-Object System.Drawing.Size(150, 50)
    $Button9.Text = "Charging Port"
    $Button9.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button9)

    # Add Button10
    $Button10 = New-Object System.Windows.Forms.Button
    $Button10.Location = New-Object System.Drawing.Size(190, 240)
    $Button10.Size = New-Object System.Drawing.Size(150, 50)
    $Button10.Text = "USB Port"
    $Button10.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
    $Form.Controls.Add($Button10)

    # Add Button11 New
    $Button11 = New-Object System.Windows.Forms.Button
    $Button11.Location = New-Object System.Drawing.Size(40, 290)
    $Button11.Size = New-Object System.Drawing.Size(150, 50)
    $Button11.Text = "WiFi"
    $Button11.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
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

    if (($DeviceModel -eq "I-Series") -or ($DeviceModel -eq "ISeries")) {
        #Adaptive Buttons
        $Button1.Add_Click({
            $results = $wshell.Popup("Verifying that the Adaptive Buttons on the front of the device work as expected.", 0, "Adaptive Buttons test", 0x0)
        
            if (Test-Path -Path $HWUtilityPath) {
                # 3: executes tests of physical buttons
                Start-Process -FilePath "TobiiDynavox.Hardware.Tests.TestRunner.exe" -ArgumentList 3
                Start-Sleep -s 4
                $ProcessID = (Get-Process Platforms.GibbonGaze.TesterUI).Id
                Wait-Process -ID $ProcessID
            } else {
                $outputBox.appendtext( "The specified path does not exist.`r`n")
            }

            $results = $wshell.Popup("Press Yes if Pass or No if Fail", 0, "Adaptive Buttons test", 4+48)
            if ($results -eq 6) {
                LogPass -message "PASS: Adaptive Button Test`r`n" -outputBox $outputBox -button $Button1 -backgroundColor ([System.Drawing.Color]::Green)
            }
            elseif ($results -eq 7) {
                LogPass -message "FAIL: Adaptive Button Test`r`n" -outputBox $outputBox -button $Button1 -backgroundColor ([System.Drawing.Color]::Red)
            }
            
        })
    
        #Partner Window
        $Button2.Add_Click({
            $results = $wshell.Popup("Verifying that the Partner Window on the back of the device is working as expected.`r`n", 0, "Partner Window test", 0x0)
            if (Test-Path -Path $HWUtilityPath) {
                # 12: executes secondary display tests
                Start-Process -FilePath "TobiiDynavox.Hardware.Tests.TestRunner.exe" -ArgumentList 12
                Start-Sleep -s 3
                $ProcessID = (Get-Process Platforms.GibbonGaze.TesterUI).Id
                Wait-Process -ID $ProcessID
            } else {
                $outputBox.appendtext( "The specified path does not exist.`r`n")
            }
            $results = $wshell.Popup("Press Yes if Pass or No if Fail", 0, "Partner Window test", 4+48)

            if ($results -eq 6) {
                LogPass -message "PASS: Partner Window Test`r`n" -outputBox $outputBox -button $Button2 -backgroundColor ([System.Drawing.Color]::Green)
            }
            elseif ($results -eq 7) {
                LogPass -message "FAIL: Partner Window Test`r`n" -outputBox $outputBox -button $Button2 -backgroundColor ([System.Drawing.Color]::Red)
            }
        })
    }
    
    if (($DeviceModel -eq "I-Series") -or ($DeviceModel -eq "ISeries") -or ($DeviceModel -eq "I-110-850")) {
        #Switch Port
        $Button3.Add_Click({
            $results = $wshell.Popup("Switch functionallity Test result.", 0, "Switch Port test", 0X0)
            if (Test-Path -Path $HWUtilityPath) {
                # 8: executes tests of switches
                Start-Process -FilePath "TobiiDynavox.Hardware.Tests.TestRunner.exe" -ArgumentList 8
                Start-Sleep -s 3
                $ProcessID = (Get-Process Platforms.GibbonGaze.TesterUI).Id
                Wait-Process -ID $ProcessID
            } else {
                $outputBox.appendtext( "The specified path does not exist.`r`n")
            }
        
            $results = $wshell.Popup("Press Yes if Pass or No if Fail", 0, "Switch Port test", 4+48)
        
            if ($results -eq 6) {
                LogPass -message "PASS: Switch Test`r`n" -outputBox $outputBox -button $Button3 -backgroundColor ([System.Drawing.Color]::Green)
            }
            elseif ($results -eq 7) {
                LogPass -message "FAIL: Switch Test`r`n" -outputBox $outputBox -button $Button3 -backgroundColor ([System.Drawing.Color]::Red)
            }
        })
    
        #IR Port   
        $Button4.Add_Click({
            $results = $wshell.Popup("Verify that IR is working as expected.`r`n", 0, "IR test", 0x0)
            if (Test-Path -Path $HWUtilityPath) {
                # 2: executes IR tests
                Start-Process -FilePath "TobiiDynavox.IRUtility.exe"
                Start-Sleep -s 6
                $ProcessID = (Get-Process TobiiDynavox.IRUtility).Id
                Wait-Process -ID $ProcessID
            } else {
                $outputBox.appendtext( "The specified path does not exist.`r`n")
            }
        
            $results = $wshell.Popup("Press Yes if Pass or No if Fail", 0, "IR test", 4+48)
    
            if ($results -eq 6) {
                LogPass -message "PASS: IR Test`r`n" -outputBox $outputBox -button $Button4 -backgroundColor ([System.Drawing.Color]::Green)
            }
            elseif ($results -eq 7) {
                LogPass -message "FAIL: IR Test`r`n" -outputBox $outputBox -button $Button4 -backgroundColor ([System.Drawing.Color]::Red)
            }
        })
    }
    $Button5.Add_Click({
        $results1 = $wshell.Popup("Verifying that the I-13/I-16 can be connected to a Bluetooth device and used, especially with Scanning or Audio for the Communication Applications.`r`n", 0, "Bluetooth test",  0x0)
        start-process devicepairingwizard.exe
        $ProcessID = (Get-Process devicepairingwizard).Id
        Wait-Process -ID $ProcessID
        $results = $wshell.Popup("Press Yes if Pass or No if Fail", 0, "Bluetooth test",  4+48)

        if ($results -eq 6) {
            LogPass -message "PASS: Bluetooth Test`r`n" -outputBox $outputBox -button $Button5 -backgroundColor ([System.Drawing.Color]::Green)
        }
        elseif ($results -eq 7) {
            LogPass -message "FAIL: Bluetooth Test`r`n" -outputBox $outputBox -button $Button5 -backgroundColor ([System.Drawing.Color]::Red)
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
            LogPass -message "PASS: Camera Test`r`n" -outputBox $outputBox -button $Button6 -backgroundColor ([System.Drawing.Color]::Green)
        }
        elseif ($results -eq 7) {
            LogPass -message "FAIL: Camera Test`r`n" -outputBox $outputBox -button $Button6 -backgroundColor ([System.Drawing.Color]::Red)
        }
    })
    
    $Button7.Add_Click({
        $results = $wshell.Popup("Verify that the microphone is working as expected.`r`n", 0, "Mic test", 0x0)
        explorer.exe shell:appsFolder\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe!App
        Start-Sleep -s 2
        
        $ProcessID = (Get-Process -Name "SoundRec" -ErrorAction SilentlyContinue).Id
        if (-not $ProcessID) {
            $ProcessID = (Get-Process -Name "VoiceRecorder" -ErrorAction Stop).Id
        }
        
        #$ProcessID = (Get-Process SoundRec).Id
        Wait-Process -ID $ProcessID

        $results = $wshell.Popup("Verify voice recorde capture your sound test Mic test 1 2 3...`r`nPress Yes if Pass or No if Fail", 0, "Display test", 4+48)

        if ($results -eq 6) {
            LogPass -message "PASS: Mic Test`r`n" -outputBox $outputBox -button $Button7 -backgroundColor ([System.Drawing.Color]::Green)
        }
        elseif ($results -eq 7) {
            LogPass -message "FAIL: Mic Test`r`n" -outputBox $outputBox -button $Button7 -backgroundColor ([System.Drawing.Color]::Red)
        }
    })
    
    $Button8.Add_Click({
        $results = $wshell.Popup("Verifying that the Headphones Port is working as expected.`r`nPress Yes if Pass or No if Fail", 0, "Headphones port test", 4+48)
        if ($results -eq 6) {
            LogPass -message "PASS: Headphones port Test`r`n" -outputBox $outputBox -button $Button8 -backgroundColor ([System.Drawing.Color]::Green)
        }
        elseif ($results -eq 7) {
            LogPass -message "FAIL: Headphones port Test`r`n" -outputBox $outputBox -button $Button8 -backgroundColor ([System.Drawing.Color]::Red)
        }
   })
    
    $Button9.Add_Click({
        $results = $wshell.Popup("Verifying that the Charging Port works as expected.`r`n", 0, "Charging port test", 0x0)
        $battery = Get-CimInstance -ClassName Win32_Battery

        if ($battery.BatteryStatus -eq 2) {
            LogPass -message "PASS: Charging port Test. The device is charging`r`n" -outputBox $outputBox -button $Button9 -backgroundColor ([System.Drawing.Color]::Green)
        } elseif ($battery.BatteryStatus -eq 1) {
            LogPass -message "FAIL: Charging port Test. The device is not charging`r`n" -outputBox $outputBox -button $Button9 -backgroundColor ([System.Drawing.Color]::Red)
        } else {
            LogPass -message "FAIL: Charging port Test. The device is not charging`r`n" -outputBox $outputBox -button $Button9 -backgroundColor ([System.Drawing.Color]::Red)
        }
    })
    
    $Button10.Add_Click({
        $results = $wshell.Popup("Verify that the USB Port is working as expected, plugin kb mouse/Hub or a USB and find connection`r`n", 0, "USB test", 0x0)
        $USBDrive = get-volume | Where-Object DriveType -eq Removable
        if ($USBDrive -ne $null) {
            LogPass -message "PASS: USB Test`r`n" -outputBox $outputBox -button $Button10 -backgroundColor ([System.Drawing.Color]::Green)
        }
        elseif ($USBDrive -eq $null) {
            LogPass -message "FAIL: USB Test`r`n" -outputBox $outputBox -button $Button10 -backgroundColor ([System.Drawing.Color]::Red)
        }
    })
    
    $Button11.Add_Click({
        $results = $wshell.Popup("Verify that the WiFi is working as expected.`r`n", 0, "WiFi test", 0x0)
        $pingCount = 5
        $server = '192.168.0.1' #'192.168.50.1'
        $pingStatus = Test-Connection $server -Count $pingCount -ErrorAction SilentlyContinue
        $pingsLost = $pingCount - ($pingStatus).Count
        $Messagerecived = ($pingStatus).count 
        LogPass -message "Message sent:$pingCount  Message recived: $Messagerecived   Message lost: $pingsLost`r`n" -outputBox $outputBox

        if ($pingsLost -eq 0) {
            LogPass -message "PASS: WiFi Test`r`n" -outputBox $outputBox -button $Button11 -backgroundColor ([System.Drawing.Color]::Green)
        }
        else {
            LogPass -message "FAIL: WiFi Test`r`n" -outputBox $outputBox -button $Button11 -backgroundColor ([System.Drawing.Color]::Red)
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
                LogPass -message "PASS: Display Scale: ${dpiPercentage}%`r`n" -outputBox $outputBox -backgroundColor ([System.Drawing.Color]::Green)
           } else {
                LogPass -message "FAIL: Display Scale: ${dpiPercentage}% and it should be 125%`r`n" -outputBox $outputBox -backgroundColor ([System.Drawing.Color]::Red)
            }
        } elseif (($SerialNumber -match "TD13L") -or ($SerialNumber -match "TDG13") -or ($SerialNumber -match "TDH10") -or ($SerialNumber -match "TD110") -or ($SerialNumber -match "TDG10") -or ($SerialNumber -match "TDI12") -or ($SerialNumber -match "TDI15")) {
            if ($dpiPercentage -eq "150") {
                LogPass -message "PASS: Display Scale: ${dpiPercentage}%`r`n" -outputBox $outputBox -backgroundColor ([System.Drawing.Color]::Green)
            } else {
                LogPass -message "FAIL: Display Scale: ${dpiPercentage}% and it should be 150%`r`n" -outputBox $outputBox -backgroundColor ([System.Drawing.Color]::Red)
            }
        } elseif (($SerialNumber -match "TDTW7") -or ($SerialNumber -match "TEM12")) {
            if ($dpiPercentage -eq "200") {
                LogPass -message "PASS: Display Scale: ${dpiPercentage}%`r`n" -outputBox $outputBox -backgroundColor ([System.Drawing.Color]::Green)
            } else {
                LogPass -message "FAIL: Display Scale: ${dpiPercentage}% and it should be 200%`r`n" -outputBox $outputBox -backgroundColor ([System.Drawing.Color]::Red)
            }
        }
    }
  
    # Get Display Resolution
    $screen = Get-WmiObject Win32_VideoController | Select-Object CurrentHorizontalResolution, CurrentVerticalResolution
    $horizontalResolution = $screen.CurrentHorizontalResolution
    $verticalResolution = $screen.CurrentVerticalResolution

    if (($SerialNumber -match "TD16L") -or ($SerialNumber -match "TDG16") -or ($SerialNumber -match "TD13L") -or ($SerialNumber -match "TDG13")) {
        if (($horizontalResolution -eq "1920") -and ($verticalResolution -eq "1080")) {
            LogPass -message "PASS: Display Resolution: $horizontalResolution x $verticalResolution`r`n" -outputBox $outputBox
        } else {
            LogPass -message "FAIL: Display Resolution $horizontalResolution x $verticalResolution and it should be 1920x1080`r`n" -outputBox $outputBox
        }
    } elseif (($SerialNumber -match "TDH10") -or ($SerialNumber -match "TD110") -or ($SerialNumber -match "TDG10") -or ($SerialNumber -match "TDTW7")) {
        if (($horizontalResolution -eq "1920") -and ($verticalResolution -eq "1200")) {
            LogPass -message "PASS: Display Resolution: $horizontalResolution x $verticalResolution`r`n" -outputBox $outputBox
        } else {
            LogPass -message "FAIL: Display Resolution $horizontalResolution x $verticalResolution and it should be 1920x1200`r`n" -outputBox $outputBox
        }
    } elseif ($SerialNumber -match "TEM12") {
        if (($horizontalResolution -eq "2736") -and ($verticalResolution -eq "1824")) {
            LogPass -message "PASS: Display Resolution: $horizontalResolution x $verticalResolution`r`n" -outputBox $outputBox
        } else {
            LogPass -message "FAIL: Display Resolution $horizontalResolution x $verticalResolution and it should be 2736x1824`r`n" -outputBox $outputBox
        }
    } elseif (($SerialNumber -match "TDI12") -or ($SerialNumber -match "TDI15")) {
        if (($horizontalResolution -eq "1024") -and ($verticalResolution -eq "768")) {
            LogPass -message "PASS: Display Resolution: $horizontalResolution x $verticalResolution`r`n" -outputBox $outputBox
        } else {
            LogPass -message "FAIL: Display Resolution $horizontalResolution x $verticalResolution and it should be 1024x768`r`n" -outputBox $outputBox
        }
    }
    #Display Orientation, Specify the registry key path and Get the current display orientation from the registry
    $registryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration"
    $displayOrientation = (Get-ChildItem -Recurse -Path $registryKeyPath | Get-ItemProperty | Select-Object -Property Rotation).Rotation | Select-Object -Unique

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
        LogPass -message "PASS: Display orientation: $orientationText`r`n" -outputBox $outputBox
    } else {
        LogPass -message "FAIL: Display orientation: $orientationText`r`n" -outputBox $outputBox
    }

    #Device Mode, Check if Tablet Mode is enabled or disabled
    $tabletModeValue = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "TabletMode" -ErrorAction SilentlyContinue
    if ($tabletModeValue.TabletMode -eq 1) {
        if ($SerialNumber -match "TDTW7") {
            LogPass -message "PASS: Device Mode: Enabled`r`n" -outputBox $outputBox
        } else { 
            LogPass -message "FAIL: Device Mode: Enabled`r`n" -outputBox $outputBox
        }
    } elseif ($tabletModeValue.TabletMode -eq 0) {
         if (($SerialNumber -match "TDG16") -or ($SerialNumber -match "TDG13") -or ($SerialNumber -match "TD13L")-or ($SerialNumber -match "TD16L")-or ($SerialNumber -match "TDH10")-or ($SerialNumber -match "TD110")-or ($SerialNumber -match "TDG10")-or ($SerialNumber -match "TEM12")-or ($SerialNumber -match "TDI12")){
            LogPass -message "PASS: Device Mode: Disabled`r`n" -outputBox $outputBox
        } else { 
            LogPass -message "FAIL: Device Mode: Disabled`r`n" -outputBox $outputBox
        }
    } else {
        LogPass -message "FAIL: Tablet Mode status: Disabled" -outputBox $outputBox
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
        LogPass -message "PASS: power settings Test`r`n" -outputBox $outputBox
    }
    elseif ($results -eq 7) {
        LogPass -message "FAIL: power settings Test`r`n" -outputBox $outputBox
    }
}

#B11
Function Medicare {
    <#$results = $wshell.Popup("Verifying following apps beeing blocked:`r`nALL, Firefox, Internet Explored, Edge(offline), Windows Media Player, Command Prompt, Registry Editor, Task Manager, Device Manager`r`n", 0, "Medicare Verification", 4+48)
    if ($results -eq 6) {
        LogPass -message "PASS: Medicare Test`r`n" -outputBox $outputBox
    }
    elseif ($results -eq 7) {
        LogPass -message "FAIL: Medicare Test`r`n" -outputBox $outputBox
    }
    #>
    $processList = @{
    #Allowed TD Apps 
    "Snap.Windows.WinUI.OEM" = "C:\Program Files\WindowsApps\TobiiDynavox.Snap_1.27.0.3385_x64__626b2w651dr5w\Snap.Windows.WinUI.OEM.exe"
    "Communicator" = "C:\Program Files (x86)\Tobii Dynavox\Communicator 5\Communicator.exe"
    "TobiiDynavox.EyeTrackingSettings" = "C:\Program Files (x86)\Tobii Dynavox\Eye Tracking Settings\TobiiDynavox.EyeTrackingSettings.exe"
    "Tobii.GazeViewer.Startup" = "C:\Program Files (x86)\Tobii Dynavox\Gaze Viewer\Tobii.GazeViewer.Startup.exe"
    "TobiiDynavox.HardwareSettings" = "C:\Program Files (x86)\Tobii Dynavox\Hardware Settings\TobiiDynavox.HardwareSettings.exe"
    "TobiiDynavox.StartupWizard" = "C:\Program Files (x86)\Tobii Dynavox\Startup Wizard\TobiiDynavox.StartupWizard.exe"
    "Tdx.ComputerControl" = "C:\Program Files (x86)\Tobii Dynavox\Computer Control\Tdx.ComputerControl.exe"
    "SnapScene" = "C:\Program Files (x86)\Tobii Dynavox\Snap Scene\SnapScene.exe"
    "TobiiDynavox.UpdateNotifier" = "C:\Program Files (x86)\Tobii Dynavox\Update Notifier\TobiiDynavox.UpdateNotifier.exe"
    "Tdx.Switcher" = "C:\Program Files\Tobii Dynavox\Switcher\Tdx.Switcher.exe"
    
    #Allowed MS Apps 
    "CalculatorApp" = "C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2210.0.0_x64__8wekyb3d8bbwe\CalculatorApp.exe"
    "WindowsCamera" = "C:\Program Files\WindowsApps\Microsoft.WindowsCamera_2023.2305.4.0_x64__8wekyb3d8bbwe\WindowsCamera.exe"
    "InLock" = "C:\Program Files (x86)\InTouchLock\InLock.exe"
    "Sensory Eye FX Demo" = "C:\Program Files (x86)\SensoryEyeFXDemo\Sensory Eye FX Demo.exe"
    "msedge" = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    "SystemSettings" = "C:\Windows\ImmersiveControlPanel\SystemSettings.exe"
    "SoundRec" = "C:\Program Files\WindowsApps\Microsoft.WindowsSoundRecorder_10.2103.28.0_x64__8wekyb3d8bbwe\SoundRec.exe"
    "mip" = "C:\Program Files\Common Files\microsoft shared\ink\mip.exe"
    "Notepad" = "C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2306.15.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe"
    "mspaint" = "C:\Program Files\WindowsApps\Microsoft.Paint_11.2302.19.0_x64__8wekyb3d8bbwe\PaintApp\mspaint.exe"
    "QuickAssist" = "C:\Program Files\WindowsApps\MicrosoftCorporationII.QuickAssist_2.0.21.0_x64__8wekyb3d8bbwe\Microsoft.RemoteAssistance.QuickAssist\QuickAssist.exe"
    "mstsc" = "C:\Windows\System32\mstsc.exe"
    "SnippingTool" = "C:\Program Files\WindowsApps\Microsoft.ScreenSketch_11.2305.26.0_x64__8wekyb3d8bbwe\SnippingTool\SnippingTool.exe"
    "psr" = "C:\Windows\System32\psr.exe"
    "WFS" = "C:\Windows\System32\WFS.exe"
    "wordpad" = "C:\Program Files\Windows NT\Accessories\wordpad.exe"
}

foreach ($processName in $processList.Keys) {
    $processPath = $processList[$processName]

    try {
        # Start the process
        Start-Process -FilePath $processPath -ErrorAction Stop

        # Wait for the process to start
        Start-Sleep -Seconds 2

        # Check if the process is running
        $process = Get-Process -Name $processName -ErrorAction SilentlyContinue

        if ($process -ne $null) {
            $processId = $process.Id
            Write-Host "PASS: Process '$processName' started with ID: $processId"
        } else {
            Write-Host "FAIL: Process '$processName' not found"
        }

        # Wait for a while
        Start-Sleep -Seconds 2

        # Stop the process if it's running
        if ($process -ne $null) {
            Stop-Process -Id $process.Id -Force
        }
    } catch {
        Write-Host "FAIL: An error occurred while starting '$processName': $_"
    }
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
$Button1.Add_Click{ 
    OEMSetup 
    $Button1.BackColor = [System.Drawing.Color]::Green 
}



#B2
$Button2 = New-Object System.Windows.Forms.Button
$Button2.Location = New-Object System.Drawing.Size(400, 40)
$Button2.Size = New-Object System.Drawing.Size(160, 40)
$Button2.Text = "Startup Wizard"
$Button2.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button2)
$Button2.Add_Click{ 
    StartupWizard 
    $Button2.BackColor = [System.Drawing.Color]::Green
}

#B3
$Button3 = New-Object System.Windows.Forms.Button
$Button3.Location = New-Object System.Drawing.Size(400, 80)
$Button3.Size = New-Object System.Drawing.Size(160, 40)
$Button3.Text = "Configuration"
$Button3.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button3)
$Button3.Add_Click{ 
    ConfigurationVerification 
    $Button3.BackColor = [System.Drawing.Color]::Green
}

#B4
$Button4 = New-Object System.Windows.Forms.Button
$Button4.Location = New-Object System.Drawing.Size(400, 120)
$Button4.Size = New-Object System.Drawing.Size(160, 40)
$Button4.Text = "Apps Version"
$Button4.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button4)
$Button4.Add_Click{ 
    ApplicationVersions 
    $Button4.BackColor = [System.Drawing.Color]::Green
}

#B5
$Button5 = New-Object System.Windows.Forms.Button
$Button5.Location = New-Object System.Drawing.Size(400, 160)
$Button5.Size = New-Object System.Drawing.Size(160, 40)
$Button5.Text = "C5 Content"
$Button5.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button5)
$Button5.Add_Click{ 
    C5Content 
    $Button5.BackColor = [System.Drawing.Color]::Green
}

#B6
$Button6 = New-Object System.Windows.Forms.Button
$Button6.Location = New-Object System.Drawing.Size(400, 200)
$Button6.Size = New-Object System.Drawing.Size(160, 40)
$Button6.Text = "C5 Voices"
$Button6.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button6)
$Button6.Add_Click{ 
    C5Voices 
    $Button6.BackColor = [System.Drawing.Color]::Green
}

#B7
$Button7 = New-Object System.Windows.Forms.Button
$Button7.Location = New-Object System.Drawing.Size(400, 240)
$Button7.Size = New-Object System.Drawing.Size(160, 40)
$Button7.Text = "Apps Verification"
$Button7.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button7)
$Button7.Add_Click{ 
    ApplicationVerification 
    $Button7.BackColor = [System.Drawing.Color]::Green
}

#B8
$Button8 = New-Object System.Windows.Forms.Button
$Button8.Location = New-Object System.Drawing.Size(400, 280)
$Button8.Size = New-Object System.Drawing.Size(160, 40)
$Button8.Text = "HW Verification"
$Button8.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button8)
$Button8.Add_Click{ 
    HWVerification 
    $Button8.BackColor = [System.Drawing.Color]::Green
}

#B9
$Button9 = New-Object System.Windows.Forms.Button
$Button9.Location = New-Object System.Drawing.Size(400, 320)
$Button9.Size = New-Object System.Drawing.Size(160, 40)
$Button9.Text = "Windows Settings"
$Button9.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button9)
$Button9.Add_Click{ 
    WindowsSettings 
    $Button9.BackColor = [System.Drawing.Color]::Green
}

#B10
$Button10 = New-Object System.Windows.Forms.Button
$Button10.Location = New-Object System.Drawing.Size(400, 360)
$Button10.Size = New-Object System.Drawing.Size(160, 40)
$Button10.Text = "Power Settings"
$Button10.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button10)
$Button10.Add_Click{ 
    PowerSettings 
    $Button10.BackColor = [System.Drawing.Color]::Green
}

#B11
$Button11 = New-Object System.Windows.Forms.Button
$Button11.Location = New-Object System.Drawing.Size(400, 400)
$Button11.Size = New-Object System.Drawing.Size(160, 40)
$Button11.Text = "Medicare"
$Button11.Font = New-Object System.Drawing.Font ("" , 8, [System.Drawing.FontStyle]::Regular)
$form.Controls.add($Button11)
$Button11.Add_Click{ 
    Medicare 
    $Button11.BackColor = [System.Drawing.Color]::Green
}

#Form name + activate form.
$Form.Text = $fileversion
$Form.Add_Shown( { $Form.Activate() })
$Form.ShowDialog()