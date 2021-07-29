################################################################################
# MIT License
#
# © 2021, Microsoft Corporation. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Filename: CheckMsiOverride.ps1
# Version: 1.0.2107.2911
# Description: Script to check for and applies Teams msiOverride updates
# Owner: Teams Client Tools Support <tctsupport@microsoft.com>
#################################################################################

#Requires -RunAsAdministrator

Param(
    [Parameter(Mandatory=$true)]
    [string] $BaseShare,
    [Parameter(Mandatory=$false)]
    [Switch] $AllowInstallOvertopExisting = $false,
    [Parameter(Mandatory=$false)]
    [Switch] $OverwritePolicyKey = $false,
####### VDIModeFeature #######
    [Parameter(Mandatory=$false)]
    [Switch] $OverwriteVDIKey = $false,
    [Parameter(Mandatory=$false)]
    [Switch] $VDIMode = $false,
    [Parameter(Mandatory=$false)]
    [Switch] $ForceVDIInstall = $false
####### VDIModeFeature #######
    )

$ScriptName  = "Microsoft Teams MsiOverride Checker"
$Version     = "1.0.2107.2911"

# Trace functions
function InitTracing([string]$traceName, [string]$tracePath = $env:TEMP)
{
    $script:TracePath = Join-Path $tracePath $traceName
    WriteTrace("")
    WriteTrace("Start Trace $(Get-Date)")
}

function WriteTrace([string]$line, [string]$function = "")
{
    $output = $line
    if($function -ne "")
    {
        $output = "[$function] " + $output
    }
    Write-Verbose $output
    $output | Out-File $script:TracePath -Append
}

function WriteInfo([string]$line, [string]$function = "")
{
    $output = $line
    if($function -ne "")
    {
        $output = "[$function] " + $output
    }
    Write-Host $output
    $output | Out-File $script:TracePath -Append
}

function WriteWarning([string]$line)
{
    Write-Host $line -ForegroundColor Yellow
    $line | Out-File $script:TracePath -Append
}

function WriteError([string]$line)
{
    Write-Host $line  -ForegroundColor Red
    $line | Out-File $script:TracePath -Append
}

function WriteSuccess([string]$line)
{
    Write-Host $line  -ForegroundColor Green
    $line | Out-File $script:TracePath -Append
}

# Removes temp folder
function Cleanup
{
    WriteTrace "Removing temp folder $TempPath"
    Remove-Item $TempPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
}

# Runs cleanup and exits
function CleanExit($code = 0)
{
    Cleanup
    WriteTrace("End Trace $(Get-Date)")
    Exit $code
}

function ErrorExit($line, $code)
{
    WriteError($line)
    Write-EventLog -LogName Application -Source $EventLogSource -Category 0 -EntryType Error -EventId ([Math]::Abs($code)) -Message $line
    CleanExit($code)
}

function IsRunningUnderSystem
{
    if(($env:COMPUTERNAME + "$") -eq $env:USERNAME)
    {
        return $true
    }
    return $false
}

function GetFileVersionString($Path)
{
    if (Test-Path $Path)
    {
        $item = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        if ($item)
        {
            return $item.FileVersion
        }
    }
    return ""
}

function HasReg($Path, $Name)
{
    if (Test-Path $Path)
    {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if (!$item)
        {
            return $false
        }
        if ($item.$Name)
        {
            return $true
        }
    }
    return $false
}

function GetReg($Path, $Name, $DefaultValue)
{
    if (HasReg -Path $Path -Name $Name)
    {
        $item = Get-ItemProperty -Path $Path -Name $Name
        return $item.$Name
    }
    return $DefaultValue
}

function SetDwordReg($Path, $Name, $Value)
{
    if (!(Test-Path $Path))
    {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWORD -ErrorAction SilentlyContinue
}

function GetInstallerVersion
{
    if($([Environment]::Is64BitOperatingSystem))
    {
        return GetFileVersionString -Path (${env:ProgramFiles(x86)} + "\Teams Installer\Teams.exe")
    }
    else
    {
        return GetFileVersionString -Path ($env:ProgramFiles + "\Teams Installer\Teams.exe")
    }
}

function GetTargetVersion
{
    $versionFile = Join-Path $BaseShare "Version.txt"
    $fileVersion = Get-Content $versionFile -ErrorAction SilentlyContinue
    if($fileVersion -match $versionRegex)
    {
        return $Matches.version
    }
    return $null
}

function GetUninstallKey
{
    $UninstallReg1 = Get-ChildItem -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue  | Get-ItemProperty | Where-Object { $_ -match 'Teams Machine-Wide Installer' }
    $UninstallReg2 = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_ -match 'Teams Machine-Wide Installer' }

    WriteTrace("UninstallReg1: $($UninstallReg1.PSChildName)")
    WriteTrace("UninstallReg2: $($UninstallReg2.PSChildName)")

    if($UninstallReg1) { return $UninstallReg1 }
    elseif($UninstallReg2) { return $UninstallReg2 }
    return $null
}

function GetProductsKey
{
    $ProductsRegLM = Get-ChildItem -Path HKLM:\SOFTWARE\Classes\Installer\Products -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_ -match 'Teams Machine-Wide Installer' } # ALLUSERS Install
    $ProductsRegCU = Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Installer\Products -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_ -match 'Teams Machine-Wide Installer' } # Local User Install

    WriteTrace("ProductsRegLM: $($ProductsRegLM.PSChildName)")
    WriteTrace("ProductsRegCU: $($ProductsRegCU.PSChildName)")

    if($ProductsRegLM) { return $ProductsRegLM }
    elseif($ProductsRegCU) { return $ProductsRegCU }
    return $null
}

function GetPackageKey()
{
    $msiKey = GetProductsKey
    if($msiKey)
    {
        $msiPkgReg = (Get-ChildItem -Path $msiKey.PSPath -Recurse | Get-ItemProperty | Where-Object { $_ -match 'PackageName' })

        if ($msiPkgReg.PackageName)
        {
            WriteTrace("PackageName: $($msiPkgReg.PackageName)")
            return $msiPkgReg
        }
    }
    return $null
}

function GetInstallBitnessFromUninstall()
{
    $uninstallReg = GetUninstallKey
    if($uninstallReg)
    {
        if ($uninstallReg.PSPath | Select-String -Pattern $MsiPkg32Guid)
        {
            return "x86"
        }
        elseif ($uninstallReg.PSPath | Select-String -Pattern $MsiPkg64Guid)
        {
            return "x64"
        }
    }
    return $null
}

function GetInstallBitnessFromSource()
{
    $msiPkgReg = GetPackageKey
    if($msiPkgReg)
    {
        WriteTrace("LastUsedSource: $($msiPkgReg.LastUsedSource)")
        if ($msiPkgReg.LastUsedSource | Select-String -Pattern ${env:ProgramFiles(x86)})
        {
            $installBitness = "x86"           
            return $installBitness #2 Bugfix - add return value
        }
        elseif ($msiPkgReg.LastUsedSource | Select-String -Pattern $env:ProgramFiles)
        {
            if($([Environment]::Is64BitOperatingSystem))
            {
                $installBitness = "x64"
            }
            else
            {
                $installBitness = "x86"
            }
            return $installBitness #2 Bugfix - add return value
        }
    }
    return $null
}

function GetInstallBitnessForOS()
{
    if($([Environment]::Is64BitOperatingSystem))
    {
        return "x64"
    }
    else
    {
        return "x86"
    }
}

####### VDIModeFeature #######
#------ Additional functions for VDImode version -----
function KeyExists($Path, $Name) # fix for "hasreg" function - which returns false if the key exists but is set to "0"
{
    if (Test-Path $Path)
    {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $item) #Check if Key does not exist
        {
            return $false #Key does not exist
        }
        return $true #Key does exist
    }
    return $false #Key does not exist
}

function GetKeyValue($Path, $Name, $ErrorValue) # alternative "GetReg" function, which uses "KeyExists" instead of "HasReg"
{
    if (KeyExists -Path $Path -Name $Name)
    {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        return $item.$Name #return key value
    }
    return $ErrorValue #key does not exist - return default value given
}

function GetInstalledVDIVersion # get version information of teams.exe in "current" folder in programfiles directory
{
    if($([Environment]::Is64BitOperatingSystem))
    {
        return GetFileVersionString -Path (${env:ProgramFiles(x86)} + "\Microsoft\Teams\Current\Teams.exe")
    }
    else
    {
        return GetFileVersionString -Path ($env:ProgramFiles + "\Microsoft\Teams\Current\Teams.exe")
    }
}
#------ Additional functions for VDImode version END -----
####### VDIModeFeature #######



# ----- Constants -----

$versionRegex = "(?<version>\d+\.\d+\.\d+\.\d+)"

$AllowMsiRegPath = "HKLM:\Software\Policies\Microsoft\Office\16.0\Teams"
$AllowMsiRegName = "AllowMsiOverride"

$MsiPkg32Guid = "{39AF0813-FA7B-4860-ADBE-93B9B214B914}"
$MsiPkg64Guid = "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}"

####### VDIModeFeature #######
$VDIRegPath = "HKLM:\Software\Microsoft\Teams"
$VDIRegName = "IsWVDEnvironment" # key needed for Teams installer to accept ALLUSER=1 parameter
####### VDIModeFeature #######

$TempPath     = $env:TEMP + "\TeamsMsiOverrideCheck"

$EventLogSource = "TeamsMsiOverride"

#----- Main Script -----

# Set the default error action preference
$ErrorActionPreference = "Continue"

InitTracing("TeamsMsiOverrideTrace.txt")

WriteTrace("Script Version $Version")
WriteTrace("Parameters AllowInstallOvertopExisting: $AllowInstallOvertopExisting, OverwritePolicyKey: $OverwritePolicyKey")
WriteTrace("Environment IsSystemAccount: $(IsRunningUnderSystem), IsOS64Bit: $([Environment]::Is64BitOperatingSystem)")

# Create event log source
New-EventLog -LogName Application -Source $EventLogSource -ErrorAction SilentlyContinue

# Delete the temp directory
Cleanup

####### VDIModeFeature #######
#Security Check for VDI Mode
if ($VDIMode -and $AllowInstallOvertopExisting)
{
    WriteWarning "The Parameter [AllowInstallOvertopExisting] is not allowed in VDI Mode. Use [ForceVDIInstall] to force VDI overwrite. Script will abort..."
    ErrorExit "ERROR: Incompatible Parameters found!!" -1 
}

if ($VDIMode -and $OverwritePolicyKey)
{
    WriteWarning "The OverwritePolicyKey Parameter was detected in VDI Mode. The AllowMsiOverride Key is normally only used by per-user installs."
}
####### VDIModeFeature #######


# Set AllowMsiOverride key if needed
####### VDIModeFeature #######
if (-not $VDIMode) # check if we are running in VDI mode
{
    $AllowMsiExists = (HasReg -Path $AllowMsiRegPath -Name $AllowMsiRegName)
    if ((-not $AllowMsiExists) -or $OverwritePolicyKey)
    {
        WriteInfo "The policy key AllowMsiOverride is not set, setting $AllowMsiRegPath\$AllowMsiRegName to 1..."
        SetDwordReg -Path $AllowMsiRegPath -Name $AllowMsiRegName -Value 1 | Out-Null
    }
    $AllowMsiValue = !!(GetReg -Path $AllowMsiRegPath -Name $AllowMsiRegName -DefaultValue 0)
    WriteInfo "AllowMsiOverride policy is set to $AllowMsiValue"

    if(-not $AllowMsiValue)
    {
        ErrorExit "ERROR: AllowMsiOverride is not enabled by policy!" -1
    }
}
else
{
    WriteWarning "Skipping AllowMsiOverride policy Check, because the Script is running in VDI Mode!"
}
####### VDIModeFeature #######

####### VDIModeFeature #######
# Set IsWVDEnvironment key if needed
$VDIKeyExists = (KeyExists -Path $VDIRegPath -Name $VDIRegName)

if ($VDImode)
{
    WriteInfo "Script running in VDI Mode."
    WriteWarning "The VDI key IsWVDEnvironment is needed to let the Teams installer know it is a VDI instance."
    WriteWarning "Without it, the installer will error out, stating: [Installation has failed. Cannot install for all users when a VDI environment is not detected.]"
    WriteInfo "Checking VDI Reg Key..."
    if ((-not $VDIKeyExists) -or $OverwriteVDIKey)
    {
        WriteInfo "The VDI key IsWVDEnvironment is not set or force overwrite is triggered, setting $VDIRegPath\$VDIRegName to 1..."
        SetDwordReg -Path $VDIRegPath -Name $VDIRegName -Value 1 | Out-Null
    }
    $VDIKeyValue = GetKeyValue -Path $VDIRegPath -Name $VDIRegName -ErrorValue -1
    WriteInfo "IsWVDEnvironment Reg Key is set to $VDIKeyValue"

    if ($VDIKeyValue -eq 0)
    {
        WriteWarning "VDI key [IsWVDEnvironment] was detected but is disabled. Script will abort..."
        WriteWarning "You may want to check if the IsWVDEnvironment Key is configured in the way you want it."
        WriteWarning "Or run the Script again with the -OverwriteVDIKey parameter, to set it to 1"
        ErrorExit "ERROR: Script Exit to prevent inconsistency between USER and VDI Mode!" -1

    }
    elseif ($VDIKeyValue -ne 1)
    {
         WriteWarning "VDI key [IsWVDEnvironment] was detected but is not set as expected. Script will abort..."
         WriteWarning "You may want to check if the IsWVDEnvironment Key is configured in the way you want it."
         WriteWarning "Or run the Script again with the -OverwriteVDIKey parameter, to set it to 1"
         ErrorExit "ERROR: Script Exit to prevent inconsistency between USER and VDI Mode!" -1
    }
}
else
{
    if ($VDIKeyExists)
    {
        $VDIKeyValue = (GetKeyValue -Path $VDIRegPath -Name $VDIRegName -ErrorValue -1)
        if ($VDIKeyValue -eq 1)
        {
            WriteWarning "VDI key IsWVDEnvironment was detected but VDI Mode is not set! Please restart with [-VDImode] Flag"
            ErrorExit "ERROR: Script Exit to prevent inconsistency between USER and VDI Mode!" -1
        }
        elseif ($VDIKeyValue -eq 0)
        {
            WriteWarning "VDI key [IsWVDEnvironment] was detected but is disabled. Script will continue with User Mode..."
            WriteWarning "You may want to check if the IsWVDEnvironment Key is configured in the way you want it."
        }
        else
        {
            WriteWarning "VDI key [IsWVDEnvironment] was detected but is not set as expected. Script will abort..."
            WriteWarning "You may want to check if the IsWVDEnvironment Key is configured in the way you want it."
            WriteWarning "IsWVDEnvironment Reg Key is set to $VDIKeyValue"
            ErrorExit "ERROR: Script Exit to prevent inconsistency between USER and VDI Mode!" -1
        }

    }
}

# Get the existing Teams Machine Wide VDI version installed
$currentVDIVersion = GetInstalledVDIVersion
if($currentVDIVersion)
{
    WriteInfo "Current Teams Machine Wide VDI version installed is $currentVDIVersion"
    if (-not $VDImode) 
    {
        WriteWarning "WARNING: VDI Version detected but VDI Mode is not set! Please restart with [-VDImode] Flag"
        ErrorExit "ERROR: Script Exit to prevent inconsistency between USER and VDI Mode!" -1 
    }
}
else
{
    WriteInfo "Current Teams Machine-Wide VDI Installation was not found."
}
####### VDIModeFeature #######

# Get the existing Teams Machine Installer version
$currentVersion = GetInstallerVersion
if($currentVersion)
{
    WriteInfo "Current Teams Machine-Wide Installer version is $currentVersion"
}
else
{
    WriteInfo "Teams Machine-Wide Installer was not found."
}

# Get the target Teams Machine Installer version from the share
$targetVersion = GetTargetVersion
if($targetVersion)
{
    WriteInfo "Target Teams Machine-Wide Installer version is $targetVersion"
}
else
{
    ErrorExit "ERROR: Unable to read the target version from the share!" -2
}

####### VDIModeFeature #######
if (-not $VDImode) #check if we are running in VDI mode
{
    if($currentVersion -eq $targetVersion)
    {
        WriteSuccess "Target version already installed!"
        CleanExit
    }
}
else
{
    if(($currentVDIVersion -eq $targetVersion) -and ($currentVersion -eq $targetVersion)) #add "Current" Folder to version check
    {
        WriteSuccess "Target VDI version already installed!"
        if (-not $ForceVDIInstall) 
        {
           CleanExit
        }
        else
        {
           WriteWarning "Force VDI Installation Flag is set! The Script will continue..."
        }       
    }
    #Teams Current Version needs to be updated
    if(($currentVDIVersion -ne $targetVersion) -and ($currentVersion -eq $targetVersion)) # check if "Current" Folder is up2date, even if Installer version is on target version.
    {
        WriteWarning "Teams Machine Wide Installer has the Target Version, but the current Folder is not at Target Version"
        WriteWarning "The Script will continue with forced VDI Mode Update for the current Folder..."
    }
}
####### VDIModeFeature #######

$MsiLocation32   = "$BaseShare\$targetVersion\Teams_windows.msi"       # x86 MSI
$MsiLocation64   = "$BaseShare\$targetVersion\Teams_windows_x64.msi"   # x64 MSI

$installBitness = GetInstallBitnessFromUninstall
$packageKey = GetPackageKey
$packageName = $packageKey.PackageName
$mode = ""

# Determine the install bitness and mode
if($installBitness)
{
    # Uninstall key existed and we matched to known GUID
    if($packageKey)
    {
        # Update Scenario, Package key existed (meaning MSI was installed by this user, or as ALLUSERS).
        $mode = "update"
    }
    else
    {
        # Install Scenario, Package key did not exist (meaning MSI is installed, but not by this user and not as ALLUSERS).
        $mode = "installovertop"
    }
}
else
{
    # Uninstall key did not exist or we did not match a known GUID
    if($packageKey)
    {
        # Update Scenario, we do have a package key, so we must not have matched a known GUID, so try to read LastUsedSource path (Office installation scenario).
        $mode = "update"
        $installBitness = GetInstallBitnessFromSource
        if(-not $installBitness)
        {
            # Fall back to OS bitness as a last resort.
            $installBitness = GetInstallBitnessForOS
        }
    }
    else
    {
        # Install Scenario, Neither Uninstall key or Package key existed, so it will be a fresh install
        $mode = "install"
        $installBitness = GetInstallBitnessForOS
    }
}

####### VDIModeFeature #######
#Check if Current VDI Mode Installation needs to be updated
if (($VDIMode -and ($mode -eq "update")) -or ($VDIMode -and $ForceVDIInstall))
{
    $mode = "updatecurrent" # new install mode for VDI installs -> does a clean uninstall first, then an install afterwards
}
####### VDIModeFeature #######

$fromMsi = ""
$msiExecFlags = ""

# Select MSI based on the bitness
if ($installBitness -eq "x86")
{
    WriteInfo "Using 32-bit MSI"
    $fromMsi = $MsiLocation32
}
elseif ($installBitness -eq "x64")
{
    WriteInfo "Using 64-bit MSI"
    $fromMsi = $MsiLocation64
}
else 
{ 
    ErrorExit "UNEXPECTED ERROR! Unknown installBitness" -3
}

# Set msiExec flags based on our mode
if ($mode -eq "install")
{
    WriteInfo "This will be an install"
    $msiExecFlags = "/i" # new install flag
}
elseif ($mode -eq "update")
{
    WriteInfo "This will be an override update"
    $msiExecFlags = "/fav" # override flag
}
elseif ($mode -eq "installovertop")
{
    if($AllowInstallOvertopExisting)
    {
        WriteInfo "This will be an install overtop an existing install"
        $msiExecFlags = "/i" # new install flag
    }
    else
    {
        ErrorExit "ERROR: Existing Teams Machine-Wide Installer is present but it was not installed by the current user or as an ALLUSERS=1 install" -4
    }
}
####### VDIModeFeature #######
elseif ($mode -eq "updatecurrent") # new install mode -> uninstalls "Teams Machine Wide installer" and resets msi flag to "install"
{
    WriteInfo "This will be an update install for the teams VDI version"
    WriteWarning "Attention: To update the current Teams Folder, we need to uninstall the installer first and then do a fresh install afterwards..."
    WriteInfo "Preparing Uninstallation of Teams Machine Wide Installer - VDI Mode..."
    $msiExecFlags = "/x" # uninstall flag
    $checkuninstallkey = GetInstallBitnessFromUninstall
    
    if ($checkuninstallkey -eq "x64")
    {
        $msiName = $MsiPkg64Guid
    }
    elseif ($checkuninstallkey -eq "x86")
    {
        $msiName = $MsiPkg32Guid
    }
    else
    {
        ErrorExit "Could not get product code for uninstall!" -6    
    }
    
    $msiExecArgs = "$msiExecFlags `"$msiName`" /qn /l*v $env:TEMP\msiOverrideCheck_msiexec.log"
    
    # Output our action
    WriteInfo "About to perform uninstall using this msiexec command:"
    WriteInfo " msiexec.exe $msiExecArgs"

    # Do the install or upgrade
    $res = Start-Process "msiexec.exe" -ArgumentList $msiExecArgs -Wait -PassThru -WindowStyle Hidden
    if ($res.ExitCode -eq 0)
    {
        WriteInfo "MsiExec completed successfully."
    }
    else
    {
        ErrorExit "ERROR: MsiExec failed with exit code $($res.ExitCode)" $res.ExitCode
    }
    # Get final confirmation we actually did uinstall the installer
    WriteInfo "checking uninstall results..."
    $currentVersion = GetInstallerVersion
    #$currentversion = $null
    
    if ($currentVersion)
    {
        ErrorExit "ERROR: Teams Machine Wide Installer is still present with Version $currentversion - uninstall failed!" -7
    }
    else
    {
        WriteInfo "Teams Machine Wide Installer was uninstalled successfully. Preparing install..."
        $msiExecFlags = "/i" # install flag
    }
}
####### VDIModeFeature #######
else
{
    ErrorExit "UNEXPECTED ERROR! Unknown mode" -5
}

# Check that we can reach and find this MSI version
if (-not (Test-Path $fromMsi))
{
    ErrorExit "ERROR: Unable to access the MSI at $fromMsi" -6
}

$msiName = $packageName
if (-not $msiName)
{
    # If this is a new install, or we don't know the MSI name, use the original MSI name
    $msiName = Split-Path $fromMsi -Leaf
}

# Copy MSI to our temp folder
$toMsi = Join-Path $TempPath $msiName
WriteInfo "Copying $fromMsi to $toMsi..."
New-Item -ItemType File -Path $toMsi -Force | Out-Null
Copy-Item -Path $fromMsi -Destination $toMsi | Out-Null

####### VDIModeFeature #######
if ($VDIMode) #check if we are running in VDI Mode
{
    WriteWarning "Attention: This will be a VDI Install..."
    WriteInfo "Preparing Installation of Teams Machine Wide Installer - VDI Mode..."  
    # use ALLUSER=1 parameter for install
    $msiExecArgs = "$msiExecFlags `"$toMsi`" /quiet ALLUSER=1 ALLUSERS=1 /l*v $env:TEMP\msiOverrideCheck_msiexec.log"
    
}
else
{
    WriteWarning "Attention: This will be a nonVDI Install..."
    WriteInfo "Preparing Installation of Teams Machine Wide Installer - USER Mode..."
    $msiExecArgs = "$msiExecFlags `"$toMsi`" /quiet ALLUSERS=1 /l*v $env:TEMP\msiOverrideCheck_msiexec.log"
}
####### VDIModeFeature #######

# Output our action
WriteInfo "About to perform deployment using this msiexec command:"
WriteInfo " msiexec.exe $msiExecArgs"

# Do the install or upgrade
$res = Start-Process "msiexec.exe" -ArgumentList $msiExecArgs -Wait -PassThru -WindowStyle Hidden
if ($res.ExitCode -eq 0)
{
    WriteInfo "MsiExec completed successfully."
}
else
{
    ErrorExit "ERROR: MsiExec failed with exit code $($res.ExitCode)" $res.ExitCode
}

# Get final confirmation we actually did update the installer
$currentVersion = GetInstallerVersion
if($currentVersion)
{
    WriteInfo "New Teams Machine Installer version is $currentVersion"
}
if($currentVersion -eq $targetVersion)
{
    WriteSuccess "Deployment successful, installer is now at target version!"
    Write-EventLog -LogName Application -Source $EventLogSource -Category 0 -EntryType Information -EventId 0 -Message "Successfully updated Teams Machine-Wide Installer to $targetVersion"
    CleanExit
}
else
{
    ErrorExit "ERROR: Script completed, however the Teams Machine-Wide Installer is still not at the target version!" -7
}

# Signature removed due to changes