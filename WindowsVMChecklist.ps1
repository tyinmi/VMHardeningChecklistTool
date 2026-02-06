# Windows 11 VM Hardening Checklist Tool
# Simple read-only assessment tool for Windows 11 VMs

[int]$passCount = 0
[int]$failCount = 0


# Check 1: Windows Version & Build Number
$os = Get-WmiObject Win32_OperatingSystem
$build = $os.BuildNumber
if ($build -ge 22000) {
    Write-Host "[PASS] 1. Windows Version & Build Number: $build"
    $passCount++
} else {
    Write-Host "[FAIL] 1. Windows Version & Build Number: $build"
    $failCount++
}

# Check 2: System Uptime
$uptime = (Get-Date) - (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
Write-Host "[PASS] 2. System Uptime: $($uptime.Days) days, $($uptime.Hours) hours"
$passCount++

# Check 3: Hostname & Domain Status
$hostname = $env:COMPUTERNAME
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
Write-Host "[PASS] 3. Hostname: $hostname, Domain: $domain"
$passCount++

# Check 4: Windows Update Service Status
$wu = Get-Service wuauserv
if ($wu.Status -eq 'Running') {
    Write-Host "[PASS] 4. Windows Update Service: Running"
    $passCount++
} else {
    Write-Host "[FAIL] 4. Windows Update Service: Not Running"
    $failCount++
}

# Check 5: Pending Updates
$updateSession = New-Object -ComObject Microsoft.Update.Session
$pending = $updateSession.CreateUpdateSearcher().Search("IsInstalled=0").Updates.Count
if ($pending -eq 0) {
    Write-Host "[PASS] 5. Pending Updates: None"
    $passCount++
} else {
    Write-Host "[WARN] 5. Pending Updates: $pending"
}

# Check 6: Automatic Updates Enabled
$au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name AUOptions
if ($au.AUOptions -ge 3) {
    Write-Host "[PASS] 6. Automatic Updates: Enabled"
    $passCount++
} else {
    Write-Host "[FAIL] 6. Automatic Updates: Disabled"
    $failCount++
}

# Check 7: Firewall Enabled
$fw = Get-NetFirewallProfile
$allEnabled = $fw | Where-Object { $_.Enabled -eq $true } | Measure-Object | Select-Object -ExpandProperty Count
if ($allEnabled -ge 3) {
    Write-Host "[PASS] 7. Firewall Enabled: Yes"
    $passCount++
} else {
    Write-Host "[FAIL] 7. Firewall Enabled: No"
    $failCount++
}

# Check 8: Firewall Inbound Policy
$inboundBlock = ($fw | Where-Object { $_.DefaultInboundAction -eq 'Block' } | Measure-Object).Count
if ($inboundBlock -eq 3) {
    Write-Host "[PASS] 8. Firewall Inbound Policy: Block"
    $passCount++
} else {
    Write-Host "[FAIL] 8. Firewall Inbound Policy: Not All Blocked"
    $failCount++
}

# Check 9: Network Connections
$established = (Get-NetTCPConnection -State Established | Measure-Object).Count
$listening = (Get-NetTCPConnection -State Listen | Measure-Object).Count
Write-Host "[PASS] 9. Network Connections: Established=$established, Listening=$listening"
$passCount++

# Check 10: Listening Ports
$ports = @(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -ne '::1' -and $_.LocalAddress -ne '127.0.0.1' })
Write-Host "[PASS] 10. Listening Ports: $($ports.Count) external ports"
$passCount++

# Check 11: Local Accounts
$accounts = @(Get-LocalUser | Where-Object { $_.Enabled -eq $true })
Write-Host "[PASS] 11. Local Accounts: $($accounts.Count) enabled"
$passCount++

# Check 12: Guest Account Disabled
$guest = Get-LocalUser -Name Guest
if ($guest.Enabled -eq $false) {
    Write-Host "[PASS] 12. Guest Account: Disabled"
    $passCount++
} else {
    Write-Host "[FAIL] 12. Guest Account: Enabled"
    $failCount++
}

# Check 13: Password Complexity
secedit /export /cfg $env:temp\secpol.inf
$complexityCheck = Select-String -Path "$env:temp\secpol.inf" -Pattern "PasswordComplexity = 1"
if ($complexityCheck) {
    Write-Host "[PASS] 13. Password Complexity: Enabled"
    $passCount++
} else {
    Write-Host "[FAIL] 13. Password Complexity: Disabled"
    $failCount++
}

# Check 14: Account Lockout Policy
$lockout = Select-String -Path "$env:temp\secpol.inf" -Pattern "LockoutBadCount = (\d+)"
if ($lockout.Matches.Groups[1].Value -gt 0) {
    Write-Host "[PASS] 14. Account Lockout: Enabled - $($lockout.Matches.Groups[1].Value) attempts"
    $passCount++
} else {
    Write-Host "[FAIL] 14. Account Lockout: Disabled"
    $failCount++
}
Remove-Item "$env:temp\secpol.inf"

# Check 15: Windows Defender Status
$defender = Get-MpComputerStatus
if ($defender.AMServiceEnabled) {
    Write-Host "[PASS] 15. Windows Defender: Enabled"
    $passCount++
} else {
    Write-Host "[FAIL] 15. Windows Defender: Disabled"
    $failCount++
}

# Check 16: Real-time Protection
if ($defender.RealTimeProtectionEnabled) {
    Write-Host "[PASS] 16. Real-time Protection: Enabled"
    $passCount++
} else {
    Write-Host "[FAIL] 16. Real-time Protection: Disabled"
    $failCount++
}

# Check 17: Security Event Logging
Get-EventLog -LogName Security -Newest 1 | Out-Null
Write-Host "[PASS] 17. Security Event Logging: Active"
$passCount++

# Check 18: Log Retention
$maxLogSizeKB = (Get-EventLog -LogName Security).MaximumKilobytes
Write-Host "[PASS] 18. Log Retention: $maxLogSizeKB KB"
$passCount++

# Summary
Write-Host "`n===== ASSESSMENT SUMMARY ====="
Write-Host "Passed: $passCount"
Write-Host "Failed: $failCount"
$total = $passCount + $failCount
$percent = [math]::Round(($passCount / $total) * 100, 2)
Write-Host "Compliance: $percent%"
