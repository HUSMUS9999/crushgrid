<#
.SYNOPSIS
  Network stack tuning script for squiz-archive Windows nodes.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\tune-windows.ps1
  powershell -ExecutionPolicy Bypass -File .\scripts\tune-windows.ps1 -Firewall -Port 7878
  powershell -ExecutionPolicy Bypass -File .\scripts\tune-windows.ps1 -Wifi -WifiAdapter "Wi-Fi"
  powershell -ExecutionPolicy Bypass -File .\scripts\tune-windows.ps1 -Jumbo "Ethernet"
  powershell -ExecutionPolicy Bypass -File .\scripts\tune-windows.ps1 -Revert -Firewall
  powershell -ExecutionPolicy Bypass -File .\scripts\tune-windows.ps1 -Status
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Status,
    [switch]$Revert,
    [switch]$Wifi,
    [string]$WifiAdapter = "Wi-Fi",
    [string]$Jumbo = "",
    [switch]$Firewall,
    [ValidateRange(1, 65535)]
    [int]$Port = 7878
)

$ErrorActionPreference = "Stop"

function Invoke-Netsh {
    param([string[]]$Arguments)
    & netsh @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "netsh $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

if ($Status) {
    netsh int tcp show global
    netsh int ipv4 show subinterfaces
    exit 0
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Run this script from an elevated (Administrator) PowerShell prompt."
    exit 1
}

$ruleName = "squiz-archive-tcp-$Port"

if ($Revert) {
    if ($PSCmdlet.ShouldProcess("Windows TCP stack", "Reset timestamps and heuristics to defaults")) {
        Invoke-Netsh @("int", "tcp", "set", "global", "timestamps=default")
        Invoke-Netsh @("int", "tcp", "set", "heuristics", "default")
    }
    if ($Firewall) {
        $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if ($existing -and $PSCmdlet.ShouldProcess($ruleName, "Remove firewall rule")) {
            Remove-NetFirewallRule -Name $ruleName
            Write-Host "Removed firewall rule '$ruleName'."
        }
    }
    if ($Jumbo -ne "") {
        Get-NetAdapter -Name $Jumbo -ErrorAction Stop | Out-Null
        if ($PSCmdlet.ShouldProcess($Jumbo, "Reset *JumboPacket to 1514")) {
            Set-NetAdapterAdvancedProperty -Name $Jumbo -RegistryKeyword "*JumboPacket" -RegistryValue 1514
            Write-Host "Reset JumboPacket on '$Jumbo' to 1514."
        }
    }
    Write-Host "Reverted requested Windows settings."
    exit 0
}

if ($PSCmdlet.ShouldProcess("Windows TCP stack", "Enable RFC 1323 timestamps, normal autotuning, disable heuristics")) {
    Invoke-Netsh @("int", "tcp", "set", "global", "timestamps=enabled")
    Invoke-Netsh @("int", "tcp", "set", "global", "autotuninglevel=normal")
    Invoke-Netsh @("int", "tcp", "set", "heuristics", "disabled")
    Write-Host "Applied Windows TCP globals (timestamps=enabled, autotuning=normal, heuristics=disabled)."
}

if ($Firewall) {
    $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        if ($PSCmdlet.ShouldProcess($ruleName, "Create inbound LocalSubnet TCP/$Port rule")) {
            New-NetFirewallRule -Name $ruleName -DisplayName "squiz-archive LAN (TCP $Port)" -Direction Inbound -Protocol TCP -LocalPort $Port -RemoteAddress LocalSubnet -Action Allow | Out-Null
            Write-Host "Created Windows Firewall inbound rule '$ruleName' (LocalSubnet -> TCP/$Port)."
        }
    } else {
        if ($PSCmdlet.ShouldProcess($ruleName, "Enable existing firewall rule")) {
            Enable-NetFirewallRule -Name $ruleName
            Write-Host "Firewall rule '$ruleName' already exists (ensured enabled)."
        }
    }
}

if ($Jumbo -ne "") {
    Get-NetAdapter -Name $Jumbo -ErrorAction Stop | Out-Null
    $prop = Get-NetAdapterAdvancedProperty -Name $Jumbo -RegistryKeyword "*JumboPacket" -ErrorAction Stop
    $maxVal = ($prop.ValidRegistryValues | ForEach-Object { [int]$_ } | Measure-Object -Maximum).Maximum
    if (-not $maxVal -or $maxVal -le 1514) {
        throw "Adapter '$Jumbo' does not advertise jumbo frame values above 1514."
    }
    if ($PSCmdlet.ShouldProcess($Jumbo, "Set *JumboPacket to $maxVal")) {
        Set-NetAdapterAdvancedProperty -Name $Jumbo -RegistryKeyword "*JumboPacket" -RegistryValue $maxVal
        Write-Host "Set *JumboPacket=$maxVal on '$Jumbo' (ensure switch and peers match)."
    }
}

if ($Wifi) {
    Get-NetAdapter -Name $WifiAdapter -ErrorAction Stop | Out-Null
    $changed = $false
    $tb = Get-NetAdapterAdvancedProperty -Name $WifiAdapter -RegistryKeyword "ThroughputBoosterEnabled" -ErrorAction SilentlyContinue
    if ($tb -and $PSCmdlet.ShouldProcess($WifiAdapter, "Set ThroughputBoosterEnabled=1")) {
        Set-NetAdapterAdvancedProperty -Name $WifiAdapter -RegistryKeyword "ThroughputBoosterEnabled" -RegistryValue 1 -NoRestart
        $changed = $true
    }
    $mimo = Get-NetAdapterAdvancedProperty -Name $WifiAdapter -RegistryKeyword "MIMOPowerSaveMode" -ErrorAction SilentlyContinue
    if ($mimo) {
        $noSmpsVal = ($mimo.ValidRegistryValues | ForEach-Object { [int]$_ } | Measure-Object -Maximum).Maximum
        if ($noSmpsVal -and $PSCmdlet.ShouldProcess($WifiAdapter, "Set MIMOPowerSaveMode=$noSmpsVal")) {
            Set-NetAdapterAdvancedProperty -Name $WifiAdapter -RegistryKeyword "MIMOPowerSaveMode" -RegistryValue $noSmpsVal -NoRestart
            $changed = $true
        }
    }
    if ($changed -and $PSCmdlet.ShouldProcess($WifiAdapter, "Restart adapter (drops active network connections briefly)")) {
        Restart-NetAdapter -Name $WifiAdapter -Confirm:$false
        Write-Host "Restarted '$WifiAdapter' with updated Wi-Fi driver settings."
    }
}

netsh int tcp show global
