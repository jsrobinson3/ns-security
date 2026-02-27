"""Security audit checks for NetSapiens systems.

All checks are designed to be read-only and should not require sudo privileges.
Where possible, checks read config files directly rather than running commands.
"""

from __future__ import annotations

from pathlib import Path

from nssec.core.cache import cached_ufw_rules
from nssec.core.checklist import (
    BaseCheck,
    CheckResult,
    Severity,
    file_contains,
    get_file_value,
    package_installed,
    run_command,
    service_active,
    service_enabled,
)
from nssec.core.ssh import file_exists, is_directory, read_file

# NetSapiens documentation base URL
NS_DOCS = "https://documentation.netsapiens.com"


# =============================================================================
# APIBAN Checks
# =============================================================================


class APIBANInstalledCheck(BaseCheck):
    """Check if APIBAN package is installed."""

    check_id = "APIBAN-001"
    name = "APIBAN Package Installed"
    description = "Verify netsapiens-apiban package is installed for SIP scanner protection"
    severity = Severity.HIGH
    applies_to = ["core", "combo"]
    reference = f"{NS_DOCS} - search 'NetSapiens-APIBAN Package'"

    def run(self) -> CheckResult:
        if package_installed("netsapiens-apiban"):
            return self._pass("APIBAN package is installed")
        return self._fail(
            "APIBAN package is not installed",
            details="SIP scanners can probe your system without APIBAN protection",
            remediation="Install via: apt install netsapiens-apiban",
        )


class APIBANCronCheck(BaseCheck):
    """Check if APIBAN cron job is configured."""

    check_id = "APIBAN-002"
    name = "APIBAN Cron Active"
    description = "Verify APIBAN cron job exists to update blocklist"
    severity = Severity.MEDIUM
    applies_to = ["core", "combo"]
    reference = f"{NS_DOCS} - search 'NetSapiens-APIBAN Package'"

    def run(self) -> CheckResult:
        # Check for APIBAN cron files (read-only)
        cron_paths = [
            "/etc/cron.d/ns_apiban",
            "/etc/cron.d/netsapiens-apiban",
            "/etc/cron.d/apiban",
        ]

        for path in cron_paths:
            if file_exists(path):
                return self._pass(f"APIBAN cron found at {path}")

        return self._fail(
            "APIBAN cron job not found",
            details="APIBAN needs a cron job to regularly update the blocklist",
            remediation="Reinstall netsapiens-apiban or check /etc/cron.d/",
        )


class APIBANUFWRulesCheck(BaseCheck):
    """Check if APIBAN rules are present in UFW."""

    check_id = "APIBAN-003"
    name = "APIBAN UFW Rules"
    description = "Verify APIBAN is actively blocking IPs via UFW"
    severity = Severity.MEDIUM
    applies_to = ["core", "combo"]
    reference = f"{NS_DOCS} - search 'NetSapiens-APIBAN Package'"

    def run(self) -> CheckResult:
        ufw_content = cached_ufw_rules()
        if ufw_content is None:
            return self._skip("Could not read UFW rules")

        if "APIBAN" in ufw_content:
            count = ufw_content.count("APIBAN")
            return self._pass(
                "APIBAN rules active in UFW",
                details=f"Found {count} APIBAN-related rules",
            )

        return self._warn(
            "No APIBAN rules found in UFW",
            details="APIBAN may not be syncing properly or hasn't run yet",
            remediation="Check /var/log/syslog for APIBAN errors",
        )


# =============================================================================
# Firewall Checks
# =============================================================================


class UFWEnabledCheck(BaseCheck):
    """Check if UFW firewall is enabled."""

    check_id = "FW-001"
    name = "UFW Firewall Enabled"
    description = "Verify UFW firewall is active"
    severity = Severity.CRITICAL
    applies_to = ["core", "ndp", "recording", "conferencing", "combo"]
    reference = f"{NS_DOCS} - search 'Securing Your NetSapiens System'"

    def run(self) -> CheckResult:
        # Check UFW config file for enabled status (SSH-aware)
        content = read_file("/etc/ufw/ufw.conf")
        if content:
            if "ENABLED=yes" in content:
                return self._pass("UFW firewall is enabled")
            elif "ENABLED=no" in content:
                return self._fail(
                    "UFW firewall is disabled",
                    remediation="Enable with: sudo ufw enable",
                )

        # Fallback to checking if ufw service is active
        if service_active("ufw"):
            return self._pass("UFW service is active")

        return self._warn(
            "Could not determine UFW status",
            details="Check UFW status manually with: sudo ufw status",
        )


class UFWDefaultDenyCheck(BaseCheck):
    """Check if UFW default policy is deny incoming."""

    check_id = "FW-002"
    name = "UFW Default Deny Incoming"
    description = "Verify UFW denies incoming connections by default"
    severity = Severity.HIGH
    applies_to = ["core", "ndp", "recording", "conferencing", "combo"]
    reference = f"{NS_DOCS} - search 'Securing Your NetSapiens System'"

    def run(self) -> CheckResult:
        # Check UFW config for default policy (SSH-aware)
        content = read_file("/etc/ufw/ufw.conf")
        if content:
            if "DEFAULT_INPUT_POLICY=" in content:
                if 'DEFAULT_INPUT_POLICY="DROP"' in content:
                    return self._pass("UFW default incoming policy is DROP")
                elif 'DEFAULT_INPUT_POLICY="REJECT"' in content:
                    return self._pass("UFW default incoming policy is REJECT")
                elif 'DEFAULT_INPUT_POLICY="ACCEPT"' in content:
                    return self._fail(
                        "UFW default incoming policy is ACCEPT",
                        details="All incoming traffic is allowed by default",
                        remediation="Set default deny with: sudo ufw default deny incoming",
                    )

        # Try reading before.rules for default policy
        before_rules = Path("/etc/ufw/before.rules")
        if file_contains(before_rules, "-P INPUT DROP"):
            return self._pass("UFW default incoming policy is DROP")

        return self._skip("Could not determine UFW default policy")


class SIPPortsCheck(BaseCheck):
    """Check SIP port access rules."""

    check_id = "FW-003"
    name = "SIP Ports Configuration"
    description = "Verify SIP ports (5060/5061) are properly configured"
    severity = Severity.MEDIUM
    applies_to = ["core", "combo"]
    reference = f"{NS_DOCS} - search 'Securing Your NetSapiens System'"

    def run(self) -> CheckResult:
        ufw_content = cached_ufw_rules()
        if ufw_content is None:
            return self._skip("Could not read UFW rules")

        has_5060 = "5060" in ufw_content
        has_5061 = "5061" in ufw_content

        if has_5060 or has_5061:
            details = []
            if has_5060:
                details.append("5060 (SIP UDP/TCP)")
            if has_5061:
                details.append("5061 (SIP TLS)")
            return self._pass(
                "SIP ports configured in firewall",
                details=f"Found rules for: {', '.join(details)}",
            )

        return self._warn(
            "SIP ports not explicitly configured in UFW",
            details="SIP traffic may be blocked or allowed by default policy",
        )


# =============================================================================
# SSH Checks
# =============================================================================


class SSHRootLoginCheck(BaseCheck):
    """Check if SSH root login is disabled."""

    check_id = "SSH-001"
    name = "SSH Root Login Disabled"
    description = "Verify SSH does not permit direct root login"
    severity = Severity.HIGH
    applies_to = ["core", "ndp", "recording", "conferencing", "combo"]
    reference = f"{NS_DOCS} - search 'Securing Your NetSapiens System'"

    def run(self) -> CheckResult:
        sshd_config = Path("/etc/ssh/sshd_config")

        if not file_exists(str(sshd_config)):
            return self._skip("sshd_config not found")

        value = get_file_value(sshd_config, "PermitRootLogin")

        if value is None:
            return self._warn(
                "PermitRootLogin not explicitly set",
                details="Default behavior varies by SSH version",
                remediation="Add 'PermitRootLogin no' to /etc/ssh/sshd_config",
            )

        if value.lower() in ("no", "prohibit-password"):
            return self._pass(f"Root login restricted: {value}")

        return self._fail(
            f"Root login permitted: {value}",
            remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
        )


class SSHPasswordAuthCheck(BaseCheck):
    """Check SSH password authentication settings."""

    check_id = "SSH-002"
    name = "SSH Password Authentication"
    description = "Check if SSH password authentication is configured securely"
    severity = Severity.MEDIUM
    applies_to = ["core", "ndp", "recording", "conferencing", "combo"]

    def run(self) -> CheckResult:
        sshd_config = Path("/etc/ssh/sshd_config")

        if not file_exists(str(sshd_config)):
            return self._skip("sshd_config not found")

        value = get_file_value(sshd_config, "PasswordAuthentication")

        if value and value.lower() == "no":
            return self._pass("Password authentication disabled (key-only)")

        return self._warn(
            "Password authentication is enabled",
            details=(
                "NetSapiens requires SSH password authentication for "
                "system management. This is expected, but ensure strong "
                "passwords and consider restricting SSH access by IP"
            ),
            remediation=(
                "Restrict SSH access via UFW to trusted IPs only "
                "(e.g., 'ufw allow from <IP> to any port 22'). "
                "Use strong, unique passwords and consider fail2ban "
                "to mitigate brute-force attacks"
            ),
        )


class SSHPortCheck(BaseCheck):
    """Check if SSH is on non-standard port."""

    check_id = "SSH-003"
    name = "SSH Port Configuration"
    description = "Check SSH port configuration"
    severity = Severity.LOW
    applies_to = ["core", "ndp", "recording", "conferencing", "combo"]

    def run(self) -> CheckResult:
        sshd_config = Path("/etc/ssh/sshd_config")

        if not file_exists(str(sshd_config)):
            return self._skip("sshd_config not found")

        value = get_file_value(sshd_config, "Port")

        if value is None or value == "22":
            return self._warn(
                "SSH running on default port 22",
                details="Non-standard port reduces automated scanning attempts",
            )

        return self._pass(f"SSH on non-standard port: {value}")


class SSHUFWRestrictedCheck(BaseCheck):
    """Check if SSH is restricted to specific IPs in UFW."""

    check_id = "SSH-004"
    name = "SSH Firewall Restrictions"
    description = "Verify SSH is not open to all IPs"
    severity = Severity.HIGH
    applies_to = ["core", "ndp", "recording", "conferencing", "combo"]
    reference = f"{NS_DOCS} - search 'Securing Your NetSapiens System'"

    def run(self) -> CheckResult:
        ufw_content = cached_ufw_rules()
        if ufw_content is None:
            return self._skip("Could not read UFW rules")

        lines = ufw_content.split("\n")

        # Match SSH rules precisely to avoid false positives from APIBAN
        # deny rules whose IPs happen to contain "22".
        #
        # user.rules tuple format:
        #   ### tuple ### allow any 22 0.0.0.0/0 any 0.0.0.0/0 in
        #   ### tuple ### allow any 22 0.0.0.0/0 any 10.0.0.1 in
        # ufw status format:
        #   22/tcp  ALLOW  Anywhere
        #   22/tcp  ALLOW  10.0.0.1
        #   OpenSSH  ALLOW  Anywhere
        ssh_lines = []
        for line in lines:
            lower = line.lower().strip()
            # user.rules tuple: action proto dport ...
            if lower.startswith("### tuple ###") and " allow " in lower:
                parts = lower.split()
                # parts: [###, tuple, ###, allow, <proto>, <dport>, ...]
                if len(parts) >= 6 and parts[5] == "22":
                    ssh_lines.append(line)
            # ufw status output: "22/tcp", "22/udp", "22 ", or "OpenSSH"
            elif lower.startswith("22/") or lower.startswith("22 ") or "openssh" in lower:
                ssh_lines.append(line)

        if not ssh_lines:
            return self._warn(
                "No explicit SSH allow rules found in UFW",
                details="SSH access depends on default policy",
            )

        # Check if any allow rule is unrestricted
        for line in ssh_lines:
            lower = line.lower()
            # user.rules: source 0.0.0.0/0 or ::/0 means open to all
            if "### tuple ###" in lower:
                parts = lower.split()
                # source is field index 7 (### tuple ### allow proto dport dst sport src dir)
                if len(parts) >= 8 and parts[7] in ("0.0.0.0/0", "::/0"):
                    return self._fail(
                        "SSH appears open to all IPs",
                        details="SSH should be restricted to specific admin IPs",
                        remediation="Restrict SSH access to specific IPs in UFW",
                    )
            # ufw status: "Anywhere" means open to all
            elif "anywhere" in lower and "allow" in lower:
                return self._fail(
                    "SSH appears open to all IPs",
                    details="SSH should be restricted to specific admin IPs",
                    remediation="Restrict SSH access to specific IPs in UFW",
                )

        return self._pass(
            "SSH has firewall restrictions configured",
            details="Review rules to ensure only trusted IPs are allowed",
        )


# =============================================================================
# MySQL Checks
# =============================================================================


class MySQLRunningCheck(BaseCheck):
    """Check if MySQL/MariaDB is running."""

    check_id = "MYSQL-001"
    name = "MySQL Service Status"
    description = "Verify MySQL/MariaDB service status"
    severity = Severity.CRITICAL
    applies_to = ["core", "combo"]

    def run(self) -> CheckResult:
        # Check for mysql or mariadb service (read-only check)
        if service_active("mysql") or service_active("mariadb"):
            return self._pass("MySQL/MariaDB service is running")

        # Check if service exists but isn't running
        if service_enabled("mysql") or service_enabled("mariadb"):
            return self._fail(
                "MySQL/MariaDB service is not running",
                remediation="Start with: sudo systemctl start mysql",
            )

        return self._skip("MySQL/MariaDB not installed")


class MySQLBindAddressCheck(BaseCheck):
    """Check MySQL bind-address configuration."""

    check_id = "MYSQL-002"
    name = "MySQL Bind Address"
    description = "Verify MySQL is not exposed to all interfaces"
    severity = Severity.HIGH
    applies_to = ["core", "combo"]
    reference = f"{NS_DOCS} - search 'Securing Your NetSapiens System'"

    def run(self) -> CheckResult:
        mysql_configs = [
            "/etc/mysql/mysql.conf.d/mysqld.cnf",
            "/etc/mysql/mariadb.conf.d/50-server.cnf",
            "/etc/mysql/my.cnf",
        ]

        for config_path in mysql_configs:
            if file_exists(config_path):
                config = Path(config_path)
                value = get_file_value(config, "bind-address", "=")
                if value:
                    value = value.strip()
                    if value in ("127.0.0.1", "localhost", "::1"):
                        return self._pass(f"MySQL bound to localhost ({value})")
                    elif value == "0.0.0.0":
                        return self._warn(
                            "MySQL bound to all interfaces (0.0.0.0)",
                            details=(
                                "NetSapiens requires MySQL to bind to "
                                "0.0.0.0 for multi-server deployments. "
                                "Ensure UFW or iptables restricts port "
                                "3306 to only trusted NetSapiens server IPs"
                            ),
                            remediation=(
                                "Verify firewall rules limit MySQL access "
                                "to known NS server IPs only. "
                                "Run 'ufw status' or 'iptables -L -n' to "
                                "confirm port 3306 is restricted"
                            ),
                        )
                    else:
                        return self._warn(
                            f"MySQL bound to specific IP: {value}",
                            details="Ensure this is intended and firewall protected",
                        )

        return self._warn(
            "Could not determine MySQL bind-address",
            details="Check MySQL configuration manually",
        )


class MySQLRemoteRootCheck(BaseCheck):
    """Check for remote root access indicators."""

    check_id = "MYSQL-003"
    name = "MySQL Remote Root Access"
    description = "Check configuration indicates potential remote root access"
    severity = Severity.CRITICAL
    applies_to = ["core", "combo"]
    reference = f"{NS_DOCS} - search 'Securing Your NetSapiens System'"

    def run(self) -> CheckResult:
        # We can't query MySQL without credentials, so check bind-address instead
        mysql_configs = [
            "/etc/mysql/mysql.conf.d/mysqld.cnf",
            "/etc/mysql/mariadb.conf.d/50-server.cnf",
            "/etc/mysql/my.cnf",
        ]

        for config_path in mysql_configs:
            if file_exists(config_path):
                config = Path(config_path)
                bind_addr = get_file_value(config, "bind-address", "=")
                if bind_addr and bind_addr.strip() == "127.0.0.1":
                    return self._pass(
                        "MySQL bound to localhost - remote root access not possible",
                    )
                elif bind_addr and bind_addr.strip() == "0.0.0.0":
                    return self._warn(
                        "MySQL accessible remotely - verify root has no remote access",
                        details="Run: SELECT Host FROM mysql.user WHERE User='root';",
                        remediation=(
                            "Remove remote root: DELETE FROM mysql.user "
                            "WHERE User='root' AND Host NOT IN "
                            "('localhost', '127.0.0.1');"
                        ),
                    )

        return self._skip("Could not check MySQL configuration")


# =============================================================================
# Apache Security Checks
# =============================================================================


class ApacheServerTokensCheck(BaseCheck):
    """Check if Apache hides version information."""

    check_id = "APACHE-001"
    name = "Apache Version Hidden"
    description = "Verify Apache does not expose version information"
    severity = Severity.MEDIUM
    applies_to = ["core", "ndp", "recording", "combo"]

    def run(self) -> CheckResult:
        configs_to_check = [
            "/etc/apache2/conf-enabled/security.conf",
            "/etc/apache2/apache2.conf",
        ]
        server_tokens = None
        server_signature = None

        for config_path in configs_to_check:
            if file_exists(config_path):
                config = Path(config_path)
                tokens_val = get_file_value(config, "ServerTokens", " ")
                sig_val = get_file_value(config, "ServerSignature", " ")
                if tokens_val:
                    server_tokens = tokens_val
                if sig_val:
                    server_signature = sig_val

        issues = []

        if server_tokens is None:
            issues.append("ServerTokens not configured")
        elif server_tokens.lower() not in ("prod", "productonly"):
            issues.append(f"ServerTokens is '{server_tokens}' (should be 'Prod')")

        if server_signature is None:
            issues.append("ServerSignature not configured")
        elif server_signature.lower() != "off":
            issues.append(f"ServerSignature is '{server_signature}' (should be 'Off')")

        if issues:
            return self._warn(
                "Apache may expose version information",
                details="; ".join(issues),
                remediation=(
                    "Set 'ServerTokens Prod' and 'ServerSignature Off' "
                    "in /etc/apache2/conf-enabled/security.conf"
                ),
            )

        return self._pass("Apache version information is hidden")


class ApacheHtaccessCheck(BaseCheck):
    """Check if .htaccess is enabled for protected routes."""

    check_id = "APACHE-002"
    name = "Apache AllowOverride"
    description = "Verify Apache allows .htaccess for directory-level security"
    severity = Severity.MEDIUM
    applies_to = ["core", "ndp", "recording", "combo"]

    def run(self) -> CheckResult:
        configs = [
            "/etc/apache2/apache2.conf",
            "/etc/apache2/sites-enabled/000-default.conf",
            "/etc/apache2/sites-enabled/default-ssl.conf",
        ]

        for config_path in configs:
            if file_exists(config_path):
                config = Path(config_path)
                if file_contains(config, "AllowOverride", ignore_comments=True):
                    content = read_file(config_path)
                    if content:
                        if "AllowOverride None" in content and "AllowOverride All" not in content:
                            return self._warn(
                                "AllowOverride may be set to None",
                                details=f"Check {config_path} - .htaccess files may be disabled",
                                remediation=(
                                    "Set 'AllowOverride AuthConfig "
                                    "Limit' to enable .htaccess "
                                    "security"
                                ),
                            )
                        return self._pass("Apache AllowOverride is configured")

        return self._skip("Could not check Apache configuration")


class ProtectedRoutesCheck(BaseCheck):
    """Check if sensitive NetSapiens routes have .htaccess protection."""

    check_id = "APACHE-003"
    name = "Protected Routes Configuration"
    description = "Verify sensitive admin routes have IP restrictions"
    severity = Severity.HIGH
    applies_to = ["core", "ndp", "recording", "combo"]
    reference = f"{NS_DOCS} - search 'Securing Your NetSapiens System'"

    def run(self) -> CheckResult:
        protected_paths = [
            ("/usr/local/NetSapiens/SiPbx/html/SiPbx", "Admin UI"),
            ("/usr/local/NetSapiens/SiPbx/html/ns-api", "API"),
            ("/usr/local/NetSapiens/ndp", "NDP"),
            ("/usr/local/NetSapiens/LiCf/html/LiCf", "LiCf Recording"),
        ]

        unprotected = []
        protected = []

        for path_str, name in protected_paths:
            htaccess_path = f"{path_str}/.htaccess"
            if is_directory(path_str):
                if file_exists(htaccess_path):
                    htaccess = Path(htaccess_path)
                    has_ip_restrict = (
                        file_contains(htaccess, "Allow from", ignore_comments=True)
                        or file_contains(htaccess, "Require ip", ignore_comments=True)
                        or file_contains(htaccess, "Deny from", ignore_comments=True)
                    )
                    if has_ip_restrict:
                        protected.append(name)
                    else:
                        unprotected.append(f"{name} (no IP restrictions in .htaccess)")
                else:
                    unprotected.append(f"{name} (no .htaccess)")

        if not protected and not unprotected:
            return self._skip("NetSapiens web directories not found")

        if unprotected:
            return self._fail(
                f"Unprotected routes: {', '.join(unprotected)}",
                details="Admin routes should restrict access by IP",
                remediation="Run 'nssec waf restrict init' to create .htaccess IP restrictions",
            )

        return self._pass(f"Protected routes: {', '.join(protected)}")


# =============================================================================
# WAF/ModSecurity Checks
# =============================================================================


class ModSecurityInstalledCheck(BaseCheck):
    """Check if ModSecurity WAF is installed."""

    check_id = "WAF-001"
    name = "ModSecurity Installed"
    description = "Verify ModSecurity WAF package is installed"
    severity = Severity.MEDIUM
    applies_to = ["core", "ndp", "recording", "combo"]

    def run(self) -> CheckResult:
        if package_installed("libapache2-mod-security2"):
            return self._pass("ModSecurity is installed (libapache2-mod-security2)")

        if package_installed("modsecurity-crs"):
            return self._pass("ModSecurity CRS is installed")

        return self._warn(
            "ModSecurity WAF is not installed",
            details="WAF provides additional protection beyond .htaccess",
            remediation="Install with: apt install libapache2-mod-security2 modsecurity-crs",
        )


class ModSecurityEnabledCheck(BaseCheck):
    """Check if ModSecurity is enabled in Apache."""

    check_id = "WAF-002"
    name = "ModSecurity Enabled"
    description = "Verify ModSecurity module is enabled in Apache"
    severity = Severity.MEDIUM
    applies_to = ["core", "ndp", "recording", "combo"]

    def run(self) -> CheckResult:
        # Check loaded modules via apachectl (read-only, no sudo needed)
        stdout, _, rc = run_command(["apachectl", "-M"])
        if rc != 0:
            stdout, _, rc = run_command(["apache2ctl", "-M"])

        if rc == 0 and stdout:
            if "security2_module" in stdout:
                return self._pass("ModSecurity module is loaded in Apache")

        # Fallback: check if module symlink exists
        mods_enabled = "/etc/apache2/mods-enabled/security2.load"
        mods_available = "/etc/apache2/mods-available/security2.load"

        if file_exists(mods_enabled):
            return self._pass("ModSecurity module is enabled in Apache")

        if file_exists(mods_available):
            return self._fail(
                "ModSecurity installed but not enabled",
                remediation="Enable with: sudo a2enmod security2 && sudo systemctl restart apache2",
            )

        return self._skip("ModSecurity not installed")


class ModSecurityModeCheck(BaseCheck):
    """Check if ModSecurity is in blocking mode."""

    check_id = "WAF-003"
    name = "ModSecurity Detection Mode"
    description = "Verify ModSecurity is actively blocking (not just detecting)"
    severity = Severity.MEDIUM
    applies_to = ["core", "ndp", "recording", "combo"]

    def run(self) -> CheckResult:
        config_paths = [
            "/etc/modsecurity/modsecurity.conf",
            "/etc/modsecurity/modsecurity.conf-recommended",
            "/etc/apache2/mods-enabled/security2.conf",
        ]

        for config_path in config_paths:
            if file_exists(config_path):
                config = Path(config_path)
                value = get_file_value(config, "SecRuleEngine", " ")
                if value:
                    value = value.strip().lower()
                    if value == "on":
                        return self._pass("ModSecurity is in blocking mode (SecRuleEngine On)")
                    elif value == "detectiononly":
                        return self._warn(
                            "ModSecurity is in detection-only mode",
                            details="Attacks are logged but not blocked",
                            remediation=(
                                "Set 'SecRuleEngine On' in /etc/modsecurity/modsecurity.conf"
                            ),
                        )
                    elif value == "off":
                        return self._fail(
                            "ModSecurity is disabled (SecRuleEngine Off)",
                            remediation=(
                                "Set 'SecRuleEngine On' in /etc/modsecurity/modsecurity.conf"
                            ),
                        )

        return self._skip("Could not determine ModSecurity mode")


class ModSecurityCRSCheck(BaseCheck):
    """Check if OWASP Core Rule Set is installed."""

    check_id = "WAF-004"
    name = "OWASP Core Rule Set"
    description = "Verify OWASP CRS rules are installed"
    severity = Severity.LOW
    applies_to = ["core", "ndp", "recording", "combo"]

    def run(self) -> CheckResult:
        crs_paths = [
            "/usr/share/modsecurity-crs",
            "/etc/modsecurity/crs",
            "/etc/apache2/modsecurity-crs",
        ]

        for path in crs_paths:
            if is_directory(path):
                return self._pass(f"OWASP CRS found at {path}")

        if package_installed("modsecurity-crs"):
            return self._pass("OWASP CRS package is installed")

        return self._warn(
            "OWASP Core Rule Set not found",
            details="CRS provides protection against common web attacks",
            remediation="Install with: apt install modsecurity-crs",
        )


# =============================================================================
# SBUS Checks
# =============================================================================


class SBUSPasswordCheck(BaseCheck):
    """Check if SBUS password has been changed from default."""

    check_id = "SBUS-001"
    name = "SBUS Password Changed"
    description = "Verify SBUS password is not the default 'bus:bus'"
    severity = Severity.CRITICAL
    applies_to = ["core", "recording", "combo"]
    reference = f"{NS_DOCS} - search 'How do I change the SBus password'"

    def run(self) -> CheckResult:
        sbus_ini_path = "/usr/local/NetSapiens/Sbus/bin/sbus.ini"

        if not file_exists(sbus_ini_path):
            return self._skip("SBUS config not found")

        sbus_ini = Path(sbus_ini_path)
        value = get_file_value(sbus_ini, "SBusBasicAuth", " ")
        if value is None:
            # Check if we could read the file at all
            content = read_file(sbus_ini_path)
            if content is None:
                return self._skip("Cannot read SBUS config (permission denied)")

        if value is None:
            return self._warn(
                "SBusBasicAuth not found in config",
                details="Could not determine SBUS authentication settings",
            )

        # Check for default password
        if value == "bus:bus":
            return self._fail(
                "SBUS using default password 'bus:bus'",
                details=(
                    "Default credentials expose system to remote "
                    "attacks. Check current password in "
                    "/usr/local/NetSapiens/Sbus/bin/sbus.ini "
                    "(SBusBasicAuth setting)"
                ),
                remediation=(
                    "Change the SBUS password in all three "
                    "locations: "
                    "1) /usr/local/NetSapiens/Sbus/bin/sbus.ini "
                    "(SBusBasicAuth), "
                    "2) /usr/local/NetSapiens/nfr/bin/nfr.ini "
                    "(SBusBasicAuth), "
                    "3) Admin UI under Reseller > Parameters > "
                    "SBus Password. See " + NS_DOCS + " - search "
                    "'How do I change the SBus password'"
                ),
            )

        # Check password complexity
        if ":" in value:
            password = value.split(":", 1)[1]
            issues = []

            if len(password) < 12:
                issues.append("less than 12 characters")
            if password.isalpha():
                issues.append("no numbers")
            if password.isalnum():
                issues.append("no special characters")

            if issues:
                return self._warn(
                    "SBUS password may be weak",
                    details=f"Issues: {', '.join(issues)}",
                    remediation=(
                        "Use a strong password with 12+ chars, "
                        "mixed case, numbers, and special characters"
                    ),
                )

        return self._pass("SBUS password has been changed from default")


# =============================================================================
# NFR Checks
# =============================================================================


class NFRSecureAccessCheck(BaseCheck):
    """Check if NFR is using non-root user for file sync."""

    check_id = "NFR-001"
    name = "NFR Secure Access"
    description = "Verify NFR uses low-privileged 'nfr' user instead of root"
    severity = Severity.HIGH
    applies_to = ["core", "combo"]
    reference = f"{NS_DOCS} - search 'NFR Configuration'"

    def run(self) -> CheckResult:
        nfr_ini_path = "/usr/local/NetSapiens/SiPbx/bin/nfr.ini"

        if not file_exists(nfr_ini_path):
            return self._skip("NFR config not found")

        nfr_ini = Path(nfr_ini_path)
        value = get_file_value(nfr_ini, "ScpUser", " ")
        # Check if we could read the file at all
        if value is None:
            content = read_file(nfr_ini_path)
            if content is None:
                return self._skip("Cannot read NFR config (permission denied)")

        if value is None or value.strip() == "":
            return self._warn(
                "NFR ScpUser not configured (defaults to root)",
                details="NFR file replication uses root SSH access by default",
                remediation=(
                    f"Set 'ScpUser nfr' in nfr.ini. See {NS_DOCS} - search 'NFR Configuration'"
                ),
            )

        value = value.strip().lower()
        if value == "root":
            return self._fail(
                "NFR explicitly configured to use root",
                details="Root SSH access is overprivileged for file sync",
                remediation=(
                    "Set 'ScpUser nfr' and configure nfr user "
                    f"SSH keys. See {NS_DOCS} - search "
                    "'NFR Configuration'"
                ),
            )

        if value == "nfr":
            return self._pass("NFR using low-privileged 'nfr' user for file sync")

        return self._warn(
            f"NFR using custom ScpUser: {value}",
            details="Verify this user has minimal required permissions",
        )


# =============================================================================
# mTLS Checks
# =============================================================================


class MTLSConfiguredCheck(BaseCheck):
    """Check if mTLS is configured for device provisioning."""

    check_id = "MTLS-001"
    name = "mTLS Device Provisioning"
    description = "Verify mTLS is configured for secure device provisioning"
    severity = Severity.HIGH
    applies_to = ["ndp", "combo"]
    reference = "https://github.com/OITApps/mTLSProtect"

    def run(self) -> CheckResult:
        if not package_installed("netsapiens-ndp"):
            return self._skip("NDP not installed")

        mtls_paths = [
            "/etc/apache2/conf.d/ndp_mtls.conf",
            "/etc/apache2/conf-enabled/ndp_mtls.conf",
            "/etc/apache2/sites-available/mtls.conf",
            "/etc/apache2/sites-enabled/mtls.conf",
            "/etc/nginx/sites-available/mtls",
            "/etc/nginx/conf.d/mtls.conf",
            "/opt/mtlsprotect",
            "/usr/local/mtlsprotect",
        ]

        for path in mtls_paths:
            if file_exists(path) or is_directory(path):
                return self._pass(f"mTLS configuration found at {path}")

        # Check Apache configs for SSL client verification
        ssl_conf_paths = [
            "/etc/apache2/sites-enabled/default-ssl.conf",
            "/etc/apache2/conf.d/default-ssl.conf",
        ]
        for ssl_conf_path in ssl_conf_paths:
            if file_exists(ssl_conf_path):
                ssl_conf = Path(ssl_conf_path)
                if file_contains(ssl_conf, "SSLVerifyClient", ignore_comments=True):
                    return self._pass("SSL client verification configured in Apache")

        return self._warn(
            "mTLS not configured for device provisioning",
            details="Device provisioning may be vulnerable to unauthorized access",
            remediation="Deploy mTLSProtect: https://github.com/OITApps/mTLSProtect",
        )


# =============================================================================
# Update Checks
# =============================================================================


class NetSapiensUpdatesCheck(BaseCheck):
    """Check for available NetSapiens package updates."""

    check_id = "UPDATE-001"
    name = "NetSapiens Updates Available"
    description = "Check if NetSapiens packages have pending updates"
    severity = Severity.MEDIUM
    applies_to = ["core", "ndp", "recording", "conferencing", "combo"]
    reference = f"{NS_DOCS} - search 'Self Upgrade Manual'"

    def run(self) -> CheckResult:
        # Check apt list --upgradable (doesn't require sudo)
        stdout, stderr, rc = run_command(
            ["apt", "list", "--upgradable"],
            timeout=60,
        )

        if rc != 0:
            return self._skip("Could not check for updates")

        if not stdout:
            return self._pass("Package lists retrieved, no updates shown")

        # Filter for netsapiens packages
        ns_updates = []
        for line in stdout.splitlines():
            if "netsapiens" in line.lower():
                pkg_name = line.split("/")[0] if "/" in line else line.split()[0]
                ns_updates.append(pkg_name)

        if not ns_updates:
            return self._pass("All NetSapiens packages are up to date")

        pkg_list = ", ".join(ns_updates[:5])
        if len(ns_updates) > 5:
            pkg_list += f" (+{len(ns_updates) - 5} more)"

        return self._warn(
            f"NetSapiens updates available: {len(ns_updates)} packages",
            details=f"Upgradable: {pkg_list}",
            remediation=f"Review and apply updates. See {NS_DOCS} - search 'Self Upgrade Manual'",
        )


# =============================================================================
# AJP Checks
# =============================================================================


class AJPSecretConfiguredCheck(BaseCheck):
    """Check if Apache AJP connector has a secret configured."""

    check_id = "AJP-001"
    name = "AJP Connector Secret"
    description = "Verify AJP connector has authentication secret configured"
    severity = Severity.HIGH
    applies_to = ["ndp", "recording", "conferencing", "combo"]
    reference = "https://httpd.apache.org/docs/2.4/mod/mod_proxy_ajp.html"

    def run(self) -> CheckResult:
        # Common locations for AJP proxy config
        ajp_config_paths = [
            "/etc/apache2/conf-enabled",
            "/etc/apache2/sites-enabled",
            "/etc/apache2/conf-available",
        ]

        found_ajp = False
        has_secret = False
        ajp_files = []

        for config_dir in ajp_config_paths:
            if not is_directory(config_dir):
                continue
            # Read directory listing to find config files
            stdout, _, rc = run_command(["ls", config_dir])
            if rc != 0 or not stdout:
                continue
            for filename in stdout.strip().splitlines():
                if not filename.endswith(".conf"):
                    continue
                filepath = f"{config_dir}/{filename}"
                content = read_file(filepath)
                if content and "ajp://" in content.lower():
                    found_ajp = True
                    ajp_files.append(filepath)
                    if "secret=" in content.lower():
                        has_secret = True

        if not found_ajp:
            return self._skip("No AJP proxy configuration found")

        files_list = ", ".join(ajp_files)
        if has_secret:
            return self._pass(
                "AJP connector has secret configured",
                details=f"AJP config found in: {files_list}",
            )

        return self._fail(
            "AJP connector has no secret configured",
            details=(
                f"AJP proxy without authentication found in: "
                f"{files_list}. An unauthenticated AJP connector "
                "can allow request smuggling "
                "(Ghostcat CVE-2020-1938)"
            ),
            remediation=(
                "Add 'secret=<strong_password>' to ProxyPass "
                "ajp:// directives in Apache config and set the "
                "matching requiredSecret in Tomcat's AJP connector"
            ),
        )


class AJPPortRestrictedCheck(BaseCheck):
    """Check if AJP port 8009 is restricted in the firewall."""

    check_id = "AJP-002"
    name = "AJP Port Firewall Restriction"
    description = "Verify AJP port 8009 is not exposed externally"
    severity = Severity.HIGH
    applies_to = ["ndp", "recording", "conferencing", "combo"]

    def run(self) -> CheckResult:
        ufw_content = cached_ufw_rules()
        if ufw_content is None:
            return self._skip(
                "Could not read UFW rules (requires root). "
                "Run 'sudo ufw status | grep 8009' to check manually"
            )

        if "8009" not in ufw_content:
            return self._pass(
                "AJP port 8009 not open in firewall",
                details="Port 8009 has no explicit UFW allow rule (blocked by default deny)",
            )

        # Port is mentioned — check if it's restricted to specific IPs or wide open
        has_anywhere = False
        for line in ufw_content.splitlines():
            if "8009" in line and "ALLOW" in line.upper():
                if "Anywhere" in line or "0.0.0.0/0" in line or "::/0" in line:
                    has_anywhere = True

        if has_anywhere:
            return self._fail(
                "AJP port 8009 is open to all IPs in firewall",
                details=(
                    "AJP should only be accessible from localhost or trusted application servers"
                ),
                remediation=(
                    "Remove the open rule and restrict: "
                    "'sudo ufw delete allow 8009' then "
                    "'sudo ufw allow from <trusted_ip> "
                    "to any port 8009'"
                ),
            )

        return self._warn(
            "AJP port 8009 has UFW rules — verify they are restricted to trusted IPs",
            details="Ensure only localhost or trusted application server IPs can reach port 8009",
        )


# =============================================================================
# MySQL Firewall Check
# =============================================================================


class MySQLPortFirewallCheck(BaseCheck):
    """Check if MySQL port 3306 is restricted in the firewall."""

    check_id = "MYSQL-004"
    name = "MySQL Port Firewall Restriction"
    description = "Verify MySQL port 3306 is not open to the world"
    severity = Severity.CRITICAL
    applies_to = ["core", "combo"]

    def run(self) -> CheckResult:
        ufw_content = cached_ufw_rules()
        if ufw_content is None:
            return self._skip(
                "Could not read UFW rules (requires root). "
                "Run 'sudo ufw status | grep 3306' to check manually"
            )

        if "3306" not in ufw_content:
            return self._pass(
                "MySQL port 3306 not open in firewall",
                details="Port 3306 has no explicit UFW allow rule (blocked by default deny)",
            )

        # Port is mentioned — check if it's open to the world
        has_anywhere = False
        restricted_lines = []
        for line in ufw_content.splitlines():
            if "3306" in line and "ALLOW" in line.upper():
                if "Anywhere" in line or "0.0.0.0/0" in line or "::/0" in line:
                    has_anywhere = True
                else:
                    restricted_lines.append(line.strip())

        if has_anywhere:
            return self._fail(
                "MySQL port 3306 is open to ALL IPs in firewall",
                details=(
                    "Database is accessible from any IP address. "
                    "Even with MySQL bound to 0.0.0.0 (required "
                    "by NS), the firewall must restrict access"
                ),
                remediation="Restrict MySQL to trusted NS server IPs only: "
                "'sudo ufw delete allow 3306' then "
                "'sudo ufw allow from <ns_server_ip> to any port 3306' for each NS server",
            )

        if restricted_lines:
            return self._pass(
                "MySQL port 3306 is restricted to specific IPs in firewall",
                details=(
                    f"Found {len(restricted_lines)} restricted "
                    "rule(s) — verify these are only trusted "
                    "NS server IPs"
                ),
            )

        return self._warn(
            "MySQL port 3306 has UFW rules — verify they are properly restricted",
            details="Ensure only trusted NetSapiens server IPs can reach port 3306",
        )


# =============================================================================
# NetSapiens-specific Checks
# =============================================================================


class AdminUIProtectionCheck(BaseCheck):
    """Check if Admin UI has IP restrictions."""

    check_id = "NS-002"
    name = "Admin UI IP Restrictions"
    description = "Verify Admin UI access is restricted by IP"
    severity = Severity.HIGH
    applies_to = ["core", "combo"]
    reference = f"{NS_DOCS} - search 'Securing Your NetSapiens System'"

    def run(self) -> CheckResult:
        htaccess_path = "/usr/local/NetSapiens/SiPbx/html/SiPbx/.htaccess"

        if not file_exists(htaccess_path):
            return self._warn(
                ".htaccess file not found for Admin UI",
                details="Admin UI may not have IP restrictions configured",
            )

        htaccess = Path(htaccess_path)
        has_legacy = file_contains(htaccess, "Allow from", ignore_comments=True)
        has_modern = file_contains(htaccess, "Require ip", ignore_comments=True)
        if has_legacy or has_modern:
            return self._pass("Admin UI has IP restrictions configured")

        return self._fail(
            "Admin UI does not have IP restrictions",
            remediation=(
                "Run 'nssec waf restrict init' to create IP restrictions, "
                f"or see {NS_DOCS} - search 'Securing Your NetSapiens System'"
            ),
        )


class InsightAgentCheck(BaseCheck):
    """Check if Insight monitoring agent is installed."""

    check_id = "NS-003"
    name = "Insight Agent Status"
    description = "Verify monitoring agent is available for observability"
    severity = Severity.LOW
    applies_to = ["core", "ndp", "recording", "conferencing", "combo"]

    def run(self) -> CheckResult:
        if service_active("netsapiens-insight-agent"):
            return self._pass("Insight agent is running")

        if package_installed("netsapiens-insight-agent"):
            return self._warn(
                "Insight agent installed but not running",
                remediation="Start with: sudo systemctl start netsapiens-insight-agent",
            )

        return self._warn(
            "Insight agent not installed",
            details="Monitoring via insight.netsapiens.com unavailable",
            remediation="Install with: apt install netsapiens-insight-agent",
        )


# =============================================================================
# Check Registry
# =============================================================================


ALL_CHECKS: list[BaseCheck] = [
    # APIBAN
    APIBANInstalledCheck(),
    APIBANCronCheck(),
    APIBANUFWRulesCheck(),
    # Firewall
    UFWEnabledCheck(),
    UFWDefaultDenyCheck(),
    SIPPortsCheck(),
    # SSH
    SSHRootLoginCheck(),
    SSHPasswordAuthCheck(),
    SSHPortCheck(),
    SSHUFWRestrictedCheck(),
    # MySQL
    MySQLRunningCheck(),
    MySQLBindAddressCheck(),
    MySQLRemoteRootCheck(),
    # Apache Security
    ApacheServerTokensCheck(),
    ApacheHtaccessCheck(),
    ProtectedRoutesCheck(),
    # WAF/ModSecurity
    ModSecurityInstalledCheck(),
    ModSecurityEnabledCheck(),
    ModSecurityModeCheck(),
    ModSecurityCRSCheck(),
    # AJP
    AJPSecretConfiguredCheck(),
    AJPPortRestrictedCheck(),
    # SBUS
    SBUSPasswordCheck(),
    # MySQL Firewall
    MySQLPortFirewallCheck(),
    # NFR
    NFRSecureAccessCheck(),
    # mTLS
    MTLSConfiguredCheck(),
    # Updates
    NetSapiensUpdatesCheck(),
    # NetSapiens
    AdminUIProtectionCheck(),
    InsightAgentCheck(),
]


def get_checks_for_server_type(server_type: str) -> list[BaseCheck]:
    """Get checks applicable to a server type."""
    basic_prefixes = ("FW-", "SSH-")

    return [
        check
        for check in ALL_CHECKS
        if not check.applies_to
        or server_type in check.applies_to
        or (server_type == "unknown" and check.check_id.startswith(basic_prefixes))
    ]
