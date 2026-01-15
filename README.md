# VMHardeningChecklistTool

This script will assess the security posture of a local Virtual Machine and produce a readable output file that details what all is checked on the VM.

## Description

A Python-based security assessment tool that runs security checks on Ubuntu Linux virtual machines. The tool generates a comprehensive report showing pass/fail status for each security check. This script **only performs checks** and does **NOT** automate fixes for any vulnerabilities found.

## Features

The tool checks for:
- **Firewall Status**: Verifies that UFW or iptables is active
- **OS Updates**: Checks for pending security updates
- **Unnecessary Services**: Detects potentially vulnerable services (telnet, FTP, etc.)
- **SSH Security**: Verifies SSH configuration (root login disabled)
- **Automatic Updates**: Checks if automatic security updates are configured
- **Password Policy**: Verifies password aging and complexity policies

## Requirements

- Python 3.6 or higher
- Ubuntu Linux (tested on Ubuntu 18.04+)
- Root/sudo privileges (recommended for complete checks)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/tyinmi/VMHardeningChecklistTool.git
cd VMHardeningChecklistTool
```

2. Make the script executable (optional):
```bash
chmod +x vm_hardening_check.py
```

## Usage

### Basic Usage (limited checks)
```bash
python3 vm_hardening_check.py
```

### Recommended Usage (with sudo for complete checks)
```bash
sudo python3 vm_hardening_check.py
```

### Output

The script will:
1. Display results in the console in real-time
2. Generate a timestamped report file: `vm_hardening_report_YYYYMMDD_HHMMSS.txt`

### Example Output

```
======================================================================
VM Hardening Security Checklist Tool
======================================================================
Starting security checks at 2026-01-15 22:45:00
======================================================================

Running checks...

Results:
----------------------------------------------------------------------
[PASS] Firewall Status: Verify that a firewall is enabled and active
       Details: UFW firewall is active
----------------------------------------------------------------------
[FAIL] OS Updates: Verify that the system has no pending security updates
       Details: 5 package(s) available for update
----------------------------------------------------------------------
...

======================================================================
SUMMARY: 4 checks passed, 2 checks failed
======================================================================

Report saved to: vm_hardening_report_20260115_224500.txt
```

## Understanding the Results

- **[PASS]**: The security check passed successfully
- **[FAIL]**: The security check failed and requires attention
- **Details**: Additional information about the check result

## Limitations

- Currently supports Ubuntu Linux only (expansion to other distributions planned)
- Some checks require root privileges for complete assessment
- This tool only identifies security issues and does not fix them
- Checks are based on common security best practices and may need customization for specific environments

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is open source and available for use and modification.
