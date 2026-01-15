#!/usr/bin/env python3
"""
VM Hardening Checklist Tool
Performs security checks on Ubuntu Linux VMs and generates a readable report.
This script only performs checks and does NOT automate fixes.
"""

import subprocess
import datetime
import sys
import os
import re


# Configuration constants
PASSWORD_MAX_DAYS_THRESHOLD = 90  # Maximum acceptable password age in days


class SecurityCheck:
    """Represents a single security check with its result."""
    
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.passed = False
        self.details = ""
    
    def set_result(self, passed, details=""):
        """Set the result of the security check."""
        self.passed = passed
        self.details = details
    
    def __str__(self):
        status = "PASS" if self.passed else "FAIL"
        result = f"[{status}] {self.name}: {self.description}"
        if self.details:
            result += f"\n       Details: {self.details}"
        return result


class VMHardeningChecker:
    """Main class for running VM hardening security checks."""
    
    def __init__(self):
        self.checks = []
        self.report_file = f"vm_hardening_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    def run_command(self, command):
        """Run a system command and return the output."""
        try:
            result = subprocess.run(command, capture_output=True, text=True, 
                                   timeout=30)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)
    
    def check_firewall_status(self):
        """Check if firewall (UFW or iptables) is active."""
        check = SecurityCheck("Firewall Status", "Verify that a firewall is enabled and active")
        
        # First try UFW (Ubuntu's default firewall)
        returncode, stdout, stderr = self.run_command(["ufw", "status"])
        
        if returncode == 0:
            if "Status: active" in stdout:
                check.set_result(True, "UFW firewall is active")
            else:
                check.set_result(False, "UFW is installed but not active")
        else:
            # Check iptables as fallback
            returncode, stdout, stderr = self.run_command(["iptables", "-L", "-n"])
            if returncode == 0 and stdout.strip():
                # Check if there are meaningful rules beyond default empty chains
                # Default empty output has 3 chains (INPUT, FORWARD, OUTPUT) with headers only
                lines = [l for l in stdout.split('\n') if l.strip() and not l.startswith('Chain') 
                        and not l.startswith('target')]
                if len(lines) > 0:  # Has actual rules
                    check.set_result(True, "iptables rules are configured")
                else:
                    check.set_result(False, "No firewall rules configured")
            else:
                check.set_result(False, "No firewall found (UFW or iptables)")
        
        self.checks.append(check)
    
    def check_os_updates(self):
        """Check if the operating system is up to date."""
        check = SecurityCheck("OS Updates", "Verify that the system has no pending security updates")
        
        # Check for available updates without modifying system state
        # Note: This relies on existing package cache; run 'apt update' separately if needed
        returncode, stdout, stderr = self.run_command(["apt", "list", "--upgradable"])
        
        if returncode == 0 and stdout.strip():
            # Filter out the 'Listing...' header and empty lines
            updates = [line for line in stdout.strip().split('\n') 
                      if line.strip() and not line.startswith('Listing')]
            num_updates = len(updates)
            if num_updates > 0:
                check.set_result(False, f"{num_updates} package(s) available for update")
            else:
                check.set_result(True, "System is up to date")
        else:
            check.set_result(True, "System is up to date")
        
        self.checks.append(check)
    
    def check_unnecessary_services(self):
        """Check for potentially unnecessary or vulnerable services."""
        check = SecurityCheck("Unnecessary Services", 
                            "Check for potentially vulnerable or unnecessary services")
        
        # List of services that are often unnecessary and potentially vulnerable
        risky_services = [
            "telnet",
            "rsh",
            "rlogin",
            "vsftpd",
            "ftpd",
            "xinetd",
            "rpcbind",
            "nis",
            "tftp"
        ]
        
        running_risky = []
        
        for service in risky_services:
            returncode, stdout, stderr = self.run_command(
                ["systemctl", "is-active", service]
            )
            if returncode == 0 and "active" in stdout:
                running_risky.append(service)
        
        if running_risky:
            check.set_result(False, 
                           f"Potentially risky services running: {', '.join(running_risky)}")
        else:
            check.set_result(True, "No known risky services are running")
        
        self.checks.append(check)
    
    def check_ssh_configuration(self):
        """Check SSH security configuration."""
        check = SecurityCheck("SSH Security", 
                            "Verify SSH is properly configured (root login disabled)")
        
        ssh_config_file = "/etc/ssh/sshd_config"
        
        if not os.path.exists(ssh_config_file):
            check.set_result(True, "SSH not installed (check not applicable)")
            self.checks.append(check)
            return
        
        try:
            with open(ssh_config_file, 'r') as f:
                content = f.read()
                
                # Check if root login is disabled
                root_login_disabled = False
                for line in content.split('\n'):
                    # Remove comments
                    line = line.split('#')[0].strip()
                    if line.startswith('PermitRootLogin'):
                        # Extract the value after PermitRootLogin
                        parts = line.split()
                        if len(parts) >= 2:
                            value = parts[1].lower()
                            if value in ('no', 'prohibit-password', 'without-password'):
                                root_login_disabled = True
                            break
                
                if root_login_disabled:
                    check.set_result(True, "SSH root login is disabled")
                else:
                    check.set_result(False, "SSH root login may be enabled")
        except PermissionError:
            check.set_result(False, "Unable to read SSH config (requires root privileges)")
        except Exception as e:
            check.set_result(False, f"Error checking SSH config: {str(e)}")
        
        self.checks.append(check)
    
    def check_automatic_updates(self):
        """Check if automatic security updates are enabled."""
        check = SecurityCheck("Automatic Updates", 
                            "Verify automatic security updates are configured")
        
        # Check for unattended-upgrades package
        returncode, stdout, stderr = self.run_command(
            ["dpkg", "-l", "unattended-upgrades"]
        )
        
        if returncode == 0 and "ii" in stdout:
            # Package is installed, check if it's configured
            config_file = "/etc/apt/apt.conf.d/20auto-upgrades"
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                        # Use regex to match the config line with flexible formatting
                        pattern = r'APT::Periodic::Unattended-Upgrade\s+"?1"?'
                        if re.search(pattern, content):
                            check.set_result(True, "Automatic security updates are enabled")
                        else:
                            check.set_result(False, "unattended-upgrades installed but not configured")
                except PermissionError:
                    check.set_result(False, "Cannot verify config (requires root privileges)")
            else:
                check.set_result(False, "unattended-upgrades installed but not configured")
        else:
            check.set_result(False, "Automatic updates not configured (unattended-upgrades not installed)")
        
        self.checks.append(check)
    
    def check_password_policy(self):
        """Check password policy configuration."""
        check = SecurityCheck("Password Policy", 
                            "Verify password aging and complexity policies are set")
        
        login_defs = "/etc/login.defs"
        
        if not os.path.exists(login_defs):
            check.set_result(False, "Password policy file not found")
            self.checks.append(check)
            return
        
        try:
            with open(login_defs, 'r') as f:
                content = f.read()
                
                has_max_days = False
                max_days_value = None
                
                for line in content.split('\n'):
                    # Remove comments
                    line = line.split('#')[0].strip()
                    if line.startswith('PASS_MAX_DAYS'):
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                max_days_value = int(parts[1])
                                if max_days_value <= PASSWORD_MAX_DAYS_THRESHOLD:
                                    has_max_days = True
                            except ValueError:
                                pass
                
                if has_max_days:
                    check.set_result(True, f"Password max age is set to {max_days_value} days")
                else:
                    check.set_result(False, "Password aging policy not properly configured")
        except PermissionError:
            check.set_result(False, "Unable to read password policy (requires root privileges)")
        except Exception as e:
            check.set_result(False, f"Error checking password policy: {str(e)}")
        
        self.checks.append(check)
    
    def run_all_checks(self):
        """Run all security checks."""
        print("=" * 70)
        print("VM Hardening Security Checklist Tool")
        print("=" * 70)
        print(f"Starting security checks at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        print()
        
        # Run all checks
        print("Running checks...")
        self.check_firewall_status()
        self.check_os_updates()
        self.check_unnecessary_services()
        self.check_ssh_configuration()
        self.check_automatic_updates()
        self.check_password_policy()
        
        # Display results to console
        print("\nResults:")
        print("-" * 70)
        for check in self.checks:
            print(check)
            print("-" * 70)
        
        # Calculate summary
        passed = sum(1 for c in self.checks if c.passed)
        failed = len(self.checks) - passed
        
        print()
        print("=" * 70)
        print(f"SUMMARY: {passed} checks passed, {failed} checks failed")
        print("=" * 70)
        
        return passed, failed
    
    def generate_report(self):
        """Generate a text report file with all check results."""
        try:
            with open(self.report_file, 'w') as f:
                f.write("=" * 70 + "\n")
                f.write("VM Hardening Security Checklist Report\n")
                f.write("=" * 70 + "\n")
                f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"System: Ubuntu Linux\n")
                f.write("=" * 70 + "\n\n")
                
                f.write("SECURITY CHECKS RESULTS:\n")
                f.write("-" * 70 + "\n")
                
                for check in self.checks:
                    f.write(str(check) + "\n")
                    f.write("-" * 70 + "\n")
                
                passed = sum(1 for c in self.checks if c.passed)
                failed = len(self.checks) - passed
                
                f.write("\n" + "=" * 70 + "\n")
                f.write(f"SUMMARY: {passed} checks passed, {failed} checks failed\n")
                f.write("=" * 70 + "\n")
                
                f.write("\nNOTE: This tool only performs checks and does NOT automate fixes.\n")
                f.write("Please review failed checks and remediate manually.\n")
            
            print(f"\nReport saved to: {self.report_file}")
            return True
        except Exception as e:
            print(f"Error generating report: {str(e)}")
            return False


def main():
    """Main entry point for the script."""
    print("VM Hardening Checklist Tool - Ubuntu Linux")
    print()
    
    # Check if running as root (recommended for full checks)
    if os.geteuid() != 0:
        print("WARNING: Not running as root. Some checks may be limited.")
        print("For complete results, run with: sudo python3 vm_hardening_check.py")
        print()
    
    checker = VMHardeningChecker()
    checker.run_all_checks()
    checker.generate_report()
    
    # Exit with appropriate code
    failed = sum(1 for c in checker.checks if not c.passed)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
