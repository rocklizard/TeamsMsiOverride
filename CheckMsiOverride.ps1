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
# Version: 1.0.2103.3102
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
    [Switch] $OverwritePolicyKey = $false
    )

$ScriptName  = "Microsoft Teams MsiOverride Checker"
$Version     = "1.0.2103.3102"

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
    Write-Host $line -ForegroundColor DarkYellow
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
            return $installBitness #2 - fix for issue 2
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
            return $installBitness #2 - fix for issue 2
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

# ----- Constants -----

$versionRegex = "(?<version>\d+\.\d+\.\d+\.\d+)"

$AllowMsiRegPath = "HKLM:\Software\Policies\Microsoft\Office\16.0\Teams"
$AllowMsiRegName = "AllowMsiOverride"

$MsiPkg32Guid = "{39AF0813-FA7B-4860-ADBE-93B9B214B914}"
$MsiPkg64Guid = "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}"

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

# Set AllowMsiOverride key if needed
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

if($currentVersion -eq $targetVersion)
{
    WriteSuccess "Target version already installed!"
    CleanExit
}

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

$msiExecArgs = "$msiExecFlags `"$toMsi`" /quiet ALLUSERS=1 /l*v $env:TEMP\msiOverrideCheck_msiexec.log"

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

# SIG # Begin signature block
# MIIjnwYJKoZIhvcNAQcCoIIjkDCCI4wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCggyCScD3VLtsu
# MyDOwvtV0zRtFHi4LQaevqth0l8Q0aCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVdDCCFXACAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgRCNLm5L9
# mMC/HxTTouX7XGIumpkI4siElN/igZrLJXMwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAN6dAOxZTYq3/LcV7H9aNqUyiszf5P/qkxmnpALDVi
# uCYqnpTOh2Uxi+3UOFfZGHU7Fd6YFkX97Smf8zAPhMVNnRaNJQMVtdSv/ou7Sb5r
# L7/GBYvjMNB0cgjnCWnKY03B2CjoiFIZzMQhM2uvHtjWCnDLjIWXD6BhdcFUI8Fs
# QZbkAQBOAhZfM6YkYgYOZ28uJwWV9nHsyNFDU4k7U4kpE468P3940mIEwsEYQoxs
# nqQ5wfT58r6QuD2bP/rSDr1Ww5TQ6sVLXR/oLkrwmjtAWWOQ9yXdkZBp3qw5o9ch
# tPgRdaJy/FldLSg+jZfbNaOFmlSCr7xdgfLsqHQp6KVXoYIS/jCCEvoGCisGAQQB
# gjcDAwExghLqMIIS5gYJKoZIhvcNAQcCoIIS1zCCEtMCAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIKcQf2oIslXqlCEYR2EfqVleFLoWbLr1BHF0cKzw
# eSImAgZgY0qsj34YEzIwMjEwMzMxMTU1OTQ1Ljc2N1owBIACAfSggdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046RTA0MS00QkVFLUZBN0UxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2Wggg5NMIIE+TCCA+GgAwIBAgITMwAAATdBj0PnWltv
# pwAAAAABNzANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMDEwMTUxNzI4MTRaFw0yMjAxMTIxNzI4MTRaMIHSMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkUwNDEtNEJFRS1GQTdFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxBHuadEl
# m3G5tikhTzjSDB0+9sXmUhUyDVRj0Y4vz9rZ9sykNobL5/6At5zOkeB2bl9IXvVd
# yS/ZJNZT373knzrQ347z30Mmw7++VU/CE+4x4w9kb5bqQHfSzbJQt6KmWsuMmJLz
# g4R5MeJs5MY5YdPLxoMoDRcTi//KoMFR0KzS1/324D2/4KkHD1Xt+s0xY0DICUOK
# 1RbmJCKEgBP1/GDZjuZQBS9Di89yTnvLJV+Lr1QtriH4EqmRoAdmV3zJ0GJsr5vh
# GPmKfOPCRSk7Q8igX7goFnCLzpYcfHGCqoR/mw95gfQpwymVwxZB0PkGMrQw+LKV
# Pa/FHP4C4KO+QQIDAQABo4IBGzCCARcwHQYDVR0OBBYEFA1gsHMM+udgY7rEne66
# OyzxlE9lMB8GA1UdIwQYMBaAFNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRP
# ME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEww
# SgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMv
# TWljVGltU3RhUENBXzIwMTAtMDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggEBAJ32U9d90RVuAUb9NsnX
# BG1K42qjhU+jHvwBdbipIcX4Wg7dH5ZduQZj3gWgKADZ5z+TehX7GnBbi265VI7x
# DRsFe2CjkTm4JIoisdKwYBDruS+YRRBG4B1ERuWi54XGwx+lSA+iQNrIi6Jm0CL/
# MfQLvwsqPJSGP69OEHCyaExos486+X3JTuGV11CBl/BO7r8UHbx/rE6fZrlZZYab
# IF6aeahvTL14LvZLV/bMzYSODsbjHHsTm9QaGm1ijhagCdbkAqr8+7HAgYEar8XP
# lzxUhVI4ShVB5ZGd9gZ2yBkwxdA0oFc745TdOPrbP79vd0ePqgvJDH5tkOhTRNI5
# 5XQwggZxMIIEWaADAgECAgphCYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNy
# b3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEy
# MTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwT
# l/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4J
# E458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhg
# RvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchoh
# iq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajy
# eioKMfDaTgaRtogINeh4HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwB
# BU8iTQIDAQABo4IB5jCCAeIwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVj
# OlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsG
# A1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJc
# YmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9z
# b2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIz
# LmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0
# MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYx
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0
# bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMA
# dABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCY
# P4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1r
# VFcIK1GCRBL7uVOMzPRgEop2zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3
# fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2
# /QThcJ8ySif9Va8v/rbljjO7Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFj
# nXshbcOco6I8+n99lmqQeKZt0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjgg
# tSXlZOz39L9+Y1klD3ouOVd2onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7
# cQnfXXSYIghh2rBQHm+98eEA3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwms
# ObvsxsvYgrRyzR30uIUBHoD7G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAv
# VCch98isTtoouLGp25ayp0Kiyc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGv
# WbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA1
# 2u8JJxzVs341Hgi62jbb01+P3nSISRKhggLXMIICQAIBATCCAQChgdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046RTA0MS00QkVFLUZBN0UxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAOq7qDk4iVz8ITuZbUFr
# AG7ecxqcoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJ
# KoZIhvcNAQEFBQACBQDkDxqlMCIYDzIwMjEwMzMxMjM1ODI5WhgPMjAyMTA0MDEy
# MzU4MjlaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOQPGqUCAQAwCgIBAAICGvoC
# Af8wBwIBAAICEVIwCgIFAOQQbCUCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYB
# BAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOB
# gQBe3tCfICKw4gSuBBCRdE276fWvYMT+H27nlGItgIjtBYQTV9+KpFZIk8lg6P2i
# c5TLxRqToIsZW5Zu+U32yP0YPOPqwd7sSCZA+70y6QsBKVkHEAhhZBg31PQIiICz
# 7/B1nUxaAg9WT6RcEotwS/2kggsuSKG6c5nrW/07QUlePDGCAw0wggMJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABN0GPQ+daW2+nAAAA
# AAE3MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIB75E4rXuI4Sv80VzwEGM+McIw8qAoj0xVLJLbFp
# OarEMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgHVl+r8CeBJ0iyX/aGZD2
# YbQ7gk+U7N7BQiTDKAYSHBAwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAATdBj0PnWltvpwAAAAABNzAiBCC4MNO2ACRNhLpZesNs8Tag
# higFP7BzgZJGPX8zd7Y3/zANBgkqhkiG9w0BAQsFAASCAQB4vto+eynWpUVaEp3k
# 5+yZH62SW3nwNeghL4DGNXrTQVhThmWBGL0mK0vEK7iD/0myAifwH7or5QHhaeH5
# 0X7jJTnJCuxDC6I3fEdkyKpGpd7VRNwlQtmgowc2ZQOBQvWd54CTcKFI780PNrZb
# l3IBErGT+OtS4PWaO1Aq6pd16ts/919PZ/gse8rGF3jHtnPfI/mm2gDvniDBWbvr
# TN5Sz+zJ2JGl5aut0NhB4Tqja+klK2KywRee+/tPTRBof7X0KIgeWBFdZWaR49w3
# 66uM4b8Sf5HQN+MAekc4owpcnIdcOQXIx+sGM0feWzPWQmyOmasv1Ss/g+jv/WQT
# sN8v
# SIG # End signature block
