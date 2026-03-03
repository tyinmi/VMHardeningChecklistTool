# Windows 11 VM Hardening Checklist Tool
# Simple read-only assessment tool for Windows 11 VMs

[int]$checkCount = 0

$reportLines = [System.Collections.Generic.List[string]]::new()

function Write-ReportLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host $Message
    $script:reportLines.Add($Message)
}

Write-ReportLine "Windows 11 VM Hardening Checklist Report"
Write-ReportLine "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-ReportLine ""


# Check 1: Windows Version & Build Number
$os = Get-WmiObject Win32_OperatingSystem
$build = $os.BuildNumber
if ($build -ge 22000) {
    Write-ReportLine "1. Windows Version & Build Number: $build (Status: OK)"
} else {
    Write-ReportLine "1. Windows Version & Build Number: $build (Status: Issue)"
}
$checkCount++

# Check 2: System Uptime
$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Write-ReportLine "2. System Uptime: $($uptime.Days) days, $($uptime.Hours) hours"
$checkCount++

# Check 3: Hostname & Domain Status
$hostname = $env:COMPUTERNAME
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
Write-ReportLine "3. Hostname: $hostname, Domain: $domain"
$checkCount++

# Check 4: Windows Update Service Status
$wu = Get-Service wuauserv
if ($wu.Status -eq 'Running') {
    Write-ReportLine "4. Windows Update Service: Running (Status: OK)"
} else {
    Write-ReportLine "4. Windows Update Service: Not Running (Status: Issue)"
}
$checkCount++

# Check 5: Pending Updates
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $pending = $updateSession.CreateUpdateSearcher().Search("IsInstalled=0").Updates.Count
    if ($pending -eq 0) {
        Write-ReportLine "5. Pending Updates: None (Status: OK)"
    } else {
        Write-ReportLine "5. Pending Updates: $pending (Status: Issue)"
    }
}
catch {
    Write-ReportLine "5. Pending Updates: Unable to determine (Status: Issue)"
}
finally {
    $checkCount++
}

# Check 6: Automatic Updates Enabled
$auPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$au = Get-ItemProperty -Path $auPath -Name AUOptions -ErrorAction SilentlyContinue
if ($null -ne $au -and $au.AUOptions -ge 3) {
    Write-ReportLine "6. Automatic Updates: Enabled (Status: OK)"
} else {
    Write-ReportLine "6. Automatic Updates: Disabled (Status: Issue)"
}
$checkCount++

# Check 7: Firewall Enabled
$fw = Get-NetFirewallProfile
$allEnabled = $fw | Where-Object { $_.Enabled -eq $true } | Measure-Object | Select-Object -ExpandProperty Count
if ($allEnabled -ge 3) {
    Write-ReportLine "7. Firewall Enabled: Yes (Status: OK)"
} else {
    Write-ReportLine "7. Firewall Enabled: No (Status: Issue)"
}
$checkCount++

# Check 8: Firewall Inbound Policy
$inboundBlock = ($fw | Where-Object { $_.DefaultInboundAction -eq 'Block' } | Measure-Object).Count
if ($inboundBlock -eq 3) {
    Write-ReportLine "8. Firewall Inbound Policy: Block (Status: OK)"
} else {
    Write-ReportLine "8. Firewall Inbound Policy: Not All Blocked (Status: Issue)"
}
$checkCount++

# Check 9: Network Connections
$established = (Get-NetTCPConnection -State Established | Measure-Object).Count
$listening = (Get-NetTCPConnection -State Listen | Measure-Object).Count
Write-ReportLine "9. Network Connections: Established=$established, Listening=$listening"
$checkCount++

# Check 10: Listening Ports
$ports = @(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -ne '::1' -and $_.LocalAddress -ne '127.0.0.1' })
Write-ReportLine "10. Listening Ports: $($ports.Count) external ports"
$checkCount++

# Check 11: Local Accounts
$accounts = @(Get-LocalUser | Where-Object { $_.Enabled -eq $true })
Write-ReportLine "11. Local Accounts: $($accounts.Count) enabled"
$checkCount++

# Check 12: Guest Account Disabled
$guest = Get-LocalUser -Name Guest
if ($guest.Enabled -eq $false) {
    Write-ReportLine "12. Guest Account: Disabled (Status: OK)"
} else {
    Write-ReportLine "12. Guest Account: Enabled (Status: Issue)"
}
$checkCount++

# Check 13: Password Complexity
secedit /export /cfg $env:temp\secpol.inf
$complexityCheck = Select-String -Path "$env:temp\secpol.inf" -Pattern "PasswordComplexity = 1"
if ($complexityCheck) {
    Write-ReportLine "13. Password Complexity: Enabled (Status: OK)"
} else {
    Write-ReportLine "13. Password Complexity: Disabled (Status: Issue)"
}
$checkCount++

# Check 14: Account Lockout Policy
$lockout = Select-String -Path "$env:temp\secpol.inf" -Pattern "LockoutBadCount = (\d+)"
if ($lockout.Matches.Groups[1].Value -gt 0) {
    Write-ReportLine "14. Account Lockout: Enabled - $($lockout.Matches.Groups[1].Value) attempts (Status: OK)"
} else {
    Write-ReportLine "14. Account Lockout: Disabled (Status: Issue)"
}
$checkCount++
Remove-Item "$env:temp\secpol.inf"

# Check 15: Windows Defender Status
$defender = Get-MpComputerStatus
if ($defender.AMServiceEnabled) {
    Write-ReportLine "15. Windows Defender: Enabled (Status: OK)"
} else {
    Write-ReportLine "15. Windows Defender: Disabled (Status: Issue)"
}
$checkCount++

# Check 16: Real-time Protection
if ($defender.RealTimeProtectionEnabled) {
    Write-ReportLine "16. Real-time Protection: Enabled (Status: OK)"
} else {
    Write-ReportLine "16. Real-time Protection: Disabled (Status: Issue)"
}
$checkCount++

# Check 17: Security Event Logging
Get-EventLog -LogName Security -Newest 1 | Out-Null
Write-ReportLine "17. Security Event Logging: Active"
$checkCount++

# Check 18: Log Retention
try {
    $logConfig = Get-WinEvent -ListLog Security -ErrorAction Stop
    if ($null -ne $logConfig.MaximumSizeInBytes -and $logConfig.MaximumSizeInBytes -gt 0) {
        $maxLogSizeKB = [math]::Round($logConfig.MaximumSizeInBytes / 1KB, 0)
        Write-ReportLine "18. Log Retention: $maxLogSizeKB KB"
    }
    elseif ($null -ne $logConfig.MaximumKilobytes -and $logConfig.MaximumKilobytes -gt 0) {
        Write-ReportLine "18. Log Retention: $($logConfig.MaximumKilobytes) KB"
    }
    else {
        Write-ReportLine "18. Log Retention: Unable to determine"
    }
}
catch {
    Write-ReportLine "18. Log Retention: Unable to determine"
}
$checkCount++

# Summary
Write-ReportLine ""
Write-ReportLine "===== ASSESSMENT SUMMARY ====="
Write-ReportLine "Checks completed: $checkCount"

$desktopPath = [Environment]::GetFolderPath('Desktop')
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportPath = Join-Path $desktopPath "WindowsVMChecklist_$timestamp.txt"

try {
    $reportLines | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "Report saved to: $reportPath"
}
catch {
    Write-Host "Report save failed: $($_.Exception.Message)"
}
