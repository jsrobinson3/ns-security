# ModSecurity WAF Setup Guide for NetSapiens

Manual installation and configuration of ModSecurity v2 with OWASP CRS v4 on Apache2 for NetSapiens servers.

> If you have `nssec` installed, you can run `sudo nssec waf init` instead of following these manual steps.

## Overview

ModSecurity v2 is the only production-ready native WAF for Apache2. Combined with OWASP Core Rule Set (CRS) v4, it protects the NetSapiens web portal, admin UI, and API endpoints against common web attacks (SQL injection, XSS, request smuggling, etc.).

**Important:** ModSecurity protects HTTP traffic only. SIP traffic on ports 5060/5061 requires separate tools (APIBAN, fail2ban, CrowdSec). See the [complementary security tools](#complementary-security-tools) section.

## Prerequisites

- Ubuntu 20.04+ with Apache2 installed and running
- Root access
- NetSapiens v43.x or v44.x

Verify Apache is running before starting:

```bash
systemctl status apache2
```

## Step 1: Install ModSecurity

```bash
sudo apt-get update
sudo apt-get install -y libapache2-mod-security2
```

Optionally install mod_evasive for HTTP flood protection alongside ModSecurity:

```bash
sudo apt-get install -y libapache2-mod-evasive
```

> **Note:** mod_evasive has **no detection-only mode**. When enabled it will block IPs that exceed request thresholds (HTTP 403). See [mod_evasive Configuration](#mod_evasive-configuration) for details on threshold tuning.

## Step 2: Enable the Apache Module

```bash
sudo a2enmod security2
```

If you installed mod_evasive:

```bash
sudo a2enmod evasive
```

## Step 3: Configure ModSecurity

Copy the recommended config as your starting point:

```bash
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
```

Edit `/etc/modsecurity/modsecurity.conf` and replace the entire contents with:

```apache
# ModSecurity Configuration for NetSapiens


# -- Rule engine initialization ----------------------------------------------

# Start in DetectionOnly mode. This logs threats without blocking them.
# Switch to "On" after you have reviewed the audit log for false positives.
SecRuleEngine DetectionOnly


# -- Request body handling ---------------------------------------------------

SecRequestBodyAccess On

# Enable XML request body parser
SecRule REQUEST_HEADERS:Content-Type "(?:application(?:/soap\+|/)|text/)xml" \
     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"

# Enable JSON request body parser
SecRule REQUEST_HEADERS:Content-Type "application/json" \
     "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"

# Body size limits - 25MB for NetSapiens (file uploads, recordings)
SecRequestBodyLimit 26214400
SecRequestBodyNoFilesLimit 26214400
SecRequestBodyInMemoryLimit 26214400

SecRequestBodyLimitAction Reject

# Verify request body was parsed correctly
SecRule REQBODY_ERROR "!@eq 0" \
"id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"

# Strict multipart/form-data validation
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
"id:'200003',phase:2,t:none,log,deny,status:400, \
msg:'Multipart request body failed strict validation: \
PE %{REQBODY_PROCESSOR_ERROR}, \
BQ %{MULTIPART_BOUNDARY_QUOTED}, \
BW %{MULTIPART_BOUNDARY_WHITESPACE}, \
DB %{MULTIPART_DATA_BEFORE}, \
DA %{MULTIPART_DATA_AFTER}, \
HF %{MULTIPART_HEADER_FOLDING}, \
LF %{MULTIPART_LF_LINE}, \
SM %{MULTIPART_MISSING_SEMICOLON}, \
IQ %{MULTIPART_INVALID_QUOTING}, \
IP %{MULTIPART_INVALID_PART}, \
IH %{MULTIPART_INVALID_HEADER_FOLDING}, \
FL %{MULTIPART_FILE_LIMIT_EXCEEDED}'"

# Detect possible unmatched boundary
SecRule MULTIPART_UNMATCHED_BOUNDARY "!@eq 0" \
"id:'200004',phase:2,t:none,log,deny,msg:'Multipart parser detected a possible unmatched boundary.'"

# PCRE tuning - avoid regex DoS
SecPcreMatchLimit 100000
SecPcreMatchLimitRecursion 100000

# Flag internal ModSecurity errors
SecRule TX:/^MSC_/ "!@streq 0" \
        "id:'200005',phase:2,t:none,deny,msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'"


# -- Response body handling --------------------------------------------------

SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml
SecResponseBodyLimit 524288
SecResponseBodyLimitAction ProcessPartial


# -- Filesystem configuration ------------------------------------------------

SecTmpDir /tmp/
SecDataDir /tmp/


# -- Audit log configuration -------------------------------------------------

SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABDEFHIJZ
SecAuditLogType Serial
SecAuditLog /var/log/apache2/modsec_audit.log


# -- Miscellaneous -----------------------------------------------------------

SecArgumentSeparator &
SecCookieFormat 0
SecUnicodeMapFile unicode.mapping 20127
SecStatusEngine On
```

### NetSapiens-specific settings

- **25MB body limits** — NetSapiens admin UI and recording uploads need larger limits than the default 13MB.
- **JSON/XML body parsers** — The NS API sends JSON payloads that ModSecurity needs to parse for inspection.
- **Response body inspection** — Enabled for data leakage detection on text responses.
- **PCRE limits** — Prevents regex-based denial of service against the WAF itself.

## Step 4: Install OWASP CRS v4

Check what version apt provides:

```bash
apt-cache show modsecurity-crs 2>/dev/null | grep Version
```

If the version starts with `4.`, install from apt:

```bash
sudo apt-get install -y modsecurity-crs
```

If apt has version 3.x (common on Ubuntu 22.04), download CRS v4 from GitHub:

```bash
CRS_VERSION="4.8.0"
cd /tmp
curl -sL -o crs.tar.gz \
    "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz"
sudo mkdir -p /etc/modsecurity/crs
sudo tar xzf crs.tar.gz --strip-components=1 -C /etc/modsecurity/crs
rm crs.tar.gz
```

## Step 5: Configure CRS for NetSapiens

Create the CRS setup file. If you installed from apt, the CRS path is `/usr/share/modsecurity-crs`. If you downloaded from GitHub, it's `/etc/modsecurity/crs`.

```bash
# Set this to your actual CRS path
CRS_PATH="/etc/modsecurity/crs"

# If the CRS ships an example, use it as a base
sudo cp "${CRS_PATH}/crs-setup.conf.example" "${CRS_PATH}/crs-setup.conf"
```

Edit `${CRS_PATH}/crs-setup.conf` and verify these settings are present:

```apache
# Paranoia level 1 = conservative, low false positives
# Increase after tuning. See https://coreruleset.org/docs/concepts/paranoia_levels/
SecAction \
    "id:900000,\
     phase:1,\
     nolog,\
     pass,\
     t:none,\
     setvar:tx.crs_setup_version=400,\
     setvar:tx.paranoia_level=1,\
     setvar:tx.blocking_paranoia_level=1,\
     setvar:tx.detection_paranoia_level=1"

# Anomaly scoring thresholds (defaults)
SecAction \
    "id:900110,\
     phase:1,\
     nolog,\
     pass,\
     t:none,\
     setvar:tx.inbound_anomaly_score_threshold=5,\
     setvar:tx.outbound_anomaly_score_threshold=4"

# Allowed HTTP methods for NetSapiens admin UI and API
SecAction \
    "id:900200,\
     phase:1,\
     nolog,\
     pass,\
     t:none,\
     setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"
```

A complete reference file is available in this repository at `rules/crs/crs-setup-netsapiens.conf`.

## Step 6: Install NetSapiens Exclusions

These rules prevent false positives on the NetSapiens admin UI and API without weakening CRS protection for everything else.

Create `/etc/modsecurity/netsapiens-exclusions.conf`:

```apache
# NetSapiens-specific ModSecurity Exclusions
# Rule ID range: 1000001-1000999

# Admin UI form submissions trigger SQL injection false positives.
# The search/filter fields send SQL-like syntax that CRS flags incorrectly.
SecRuleUpdateTargetById 942100 "!REQUEST_COOKIES"
SecRuleUpdateTargetById 942200 "!REQUEST_COOKIES"

# NS API endpoints use base64 in query strings
SecRule REQUEST_URI "@beginsWith /ns-api/" \
    "id:1000001,\
     phase:1,\
     pass,\
     nolog,\
     ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:filter"

# Admin UI session handling
# Rule 921180 (HTTP Parameter Pollution) false-positives on NS session cookies.
SecRule REQUEST_URI "@beginsWith /SiPbx/" \
    "id:1000002,\
     phase:1,\
     pass,\
     nolog,\
     ctl:ruleRemoveById=921180"

# QoS proxy (NqsProxy) sends multipart/mixed which triggers rule 920420
# (content type not allowed by policy). This is normal NS internal traffic.
SecRule REQUEST_URI "@beginsWith /NqsProxy/" \
    "id:1000003,\
     phase:1,\
     pass,\
     nolog,\
     ctl:ruleRemoveById=920420"

# iNSight health checks — bypass CRS for monitoring endpoint
SecRule REQUEST_URI "@beginsWith /cfg/insight_healthcheck" \
    "id:1000004,\
     phase:1,\
     pass,\
     nolog,\
     ctl:ruleRemoveByTag=OWASP_CRS"

# Localhost internal traffic — NS services (NmsSBus, ns-api, cfg) communicate
# over 127.0.0.1. Internal calls trigger false positives on rules 921110
# (SIP "connect" field matches HTTP smuggling pattern), 920180 (POSTs without
# Content-Length), and 920350 (numeric IP in Host header).
SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" \
    "id:1000005,\
     phase:1,\
     pass,\
     nolog,\
     ctl:ruleRemoveByTag=OWASP_CRS"
```

A canonical copy of this file is maintained at `rules/netsapiens/netsapiens-exclusions.conf` in this repository.

### Optional: Allowlist admin IPs

To bypass WAF rules for trusted admin IPs, add to the exclusions file:

```apache
# Allowlisted admin IP - bypasses CRS rules
SecRule REMOTE_ADDR "@ipMatch 203.0.113.10" \
    "id:1000100,\
     phase:1,\
     pass,\
     nolog,\
     ctl:ruleRemoveByTag=OWASP_CRS"
```

Repeat with incrementing rule IDs (1000101, 1000102, etc.) for additional IPs.

## Step 7: Configure Apache to Load Everything

Edit `/etc/apache2/mods-available/security2.conf`:

```apache
<IfModule security2_module>
    # Main ModSecurity config
    IncludeOptional /etc/modsecurity/modsecurity.conf

    # NetSapiens-specific exclusions
    IncludeOptional /etc/modsecurity/netsapiens-exclusions.conf

    # OWASP CRS setup and rules
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/crs/plugins/*-config.conf
    IncludeOptional /etc/modsecurity/crs/plugins/*-before.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf
    IncludeOptional /etc/modsecurity/crs/plugins/*-after.conf
</IfModule>
```

Adjust the path if your CRS is installed elsewhere (e.g., `/usr/share/modsecurity-crs`).

## Step 8: Test and Reload Apache

Always test the config before reloading:

```bash
sudo apache2ctl configtest
```

If you see `Syntax OK`, reload:

```bash
sudo systemctl reload apache2
```

If the config test fails, review the error message. Common issues:
- Missing CRS files (wrong path in security2.conf)
- Duplicate rule IDs (happens if loading CRS from multiple paths)
- Missing `unicode.mapping` file

## Step 9: Verify It's Working

Check that ModSecurity is loaded:

```bash
apache2ctl -M | grep security2
```

Expected output:
```
 security2_module (shared)
```

Verify the audit log is being written:

```bash
ls -la /var/log/apache2/modsec_audit.log
```

Browse to the NetSapiens admin UI and confirm everything works normally. Check the audit log for any entries:

```bash
tail -f /var/log/apache2/modsec_audit.log
```

## Step 10: Switch to Blocking Mode

After running in DetectionOnly for at least a few days (ideally 1-2 weeks):

1. Review the audit log for false positives:
   ```bash
   grep -c "ModSecurity" /var/log/apache2/modsec_audit.log
   ```

2. Add exclusions for any false positives (see [Tuning False Positives](#tuning-false-positives))

3. Switch to blocking mode by editing `/etc/modsecurity/modsecurity.conf`:
   ```apache
   SecRuleEngine On
   ```

4. Test and reload:
   ```bash
   sudo apache2ctl configtest && sudo systemctl reload apache2
   ```

Or if you have `nssec` installed:
```bash
sudo nssec waf enable
```

## Tuning False Positives

When you see a false positive in the audit log, identify the rule ID and add a targeted exclusion to `/etc/modsecurity/netsapiens-exclusions.conf`.

### Find which rules are triggering

```bash
grep -oP 'id "\K[0-9]+' /var/log/apache2/modsec_audit.log | sort | uniq -c | sort -rn | head 20
```

### Common exclusion patterns

**Disable a rule for a specific URL path:**
```apache
SecRule REQUEST_URI "@beginsWith /some/path/" \
    "id:1000010,phase:1,pass,nolog,ctl:ruleRemoveById=RULE_ID"
```

**Disable a rule for a specific parameter:**
```apache
SecRuleUpdateTargetById RULE_ID "!ARGS:parameter_name"
```

**Disable a rule entirely (use sparingly):**
```apache
SecRuleRemoveById RULE_ID
```

### Resources for CRS tuning

- [OWASP CRS Documentation](https://coreruleset.org/docs/)
- [Christian Folini's CRS Tuning Tutorials](https://www.netnea.com/cms/apache-tutorials/)
- [CRS Paranoia Levels Explained](https://coreruleset.org/docs/concepts/paranoia_levels/)

## mod_evasive Configuration

mod_evasive provides application-layer HTTP flood and DDoS protection. Unlike ModSecurity, it has **no detection-only mode** — when enabled it will return HTTP 403 to IPs that exceed thresholds.

### Understanding the thresholds

| Directive | Description |
|-----------|-------------|
| `DOSPageCount` | Max requests to the same page per IP per interval |
| `DOSSiteCount` | Max total requests from one IP per interval |
| `DOSPageInterval` / `DOSSiteInterval` | Sliding window in seconds |
| `DOSBlockingPeriod` | How long (seconds) an IP is blocked |
| `DOSWhitelist` | IPs excluded from blocking (RFC 1918 ranges by default) |

### Threshold profiles

If using `nssec`, two profiles are available:

| Profile | DOSPageCount | DOSSiteCount | DOSBlockingPeriod | Use Case |
|---------|:---:|:---:|:---:|------|
| `standard` (default) | 100 | 500 | 10s | Safe default — only catches extreme floods |
| `strict` | 15 | 60 | 60s | Tuned for NetSapiens traffic (~270 req/s sustained) |

```bash
# Enable with standard profile (recommended starting point)
sudo nssec waf evasive enable

# Switch to strict after reviewing traffic
sudo nssec waf evasive enable --profile strict
```

### Manual configuration

If configuring manually, edit `/etc/apache2/mods-available/evasive.conf`:

```apache
<IfModule mod_evasive20.c>
    DOSHashTableSize        3097
    DOSPageCount            100
    DOSSiteCount            500
    DOSPageInterval         1
    DOSSiteInterval         1
    DOSBlockingPeriod       10
    DOSLogDir               /var/log/apache2/mod_evasive

    # Structured logging for Loki/Grafana
    DOSSystemCommand        "/bin/sh -c 'echo $(date -Is) action=blocked src_ip=%s >> /var/log/apache2/mod_evasive.log'"

    # Whitelist internal traffic
    DOSWhitelist            127.0.0.1
    DOSWhitelist            10.*.*.*
    DOSWhitelist            192.168.*.*
</IfModule>
```

Create the log directory:

```bash
sudo mkdir -p /var/log/apache2/mod_evasive
```

### Tuning recommendations

1. **Start with the standard profile** (or high thresholds manually) to avoid blocking legitimate traffic
2. **Review traffic patterns** using the Apache API Usage dashboard (`insight/apacheApiUsage.json`) or access logs
3. **Monitor block events** in `/var/log/apache2/mod_evasive.log` and the mod_evasive dashboard (`insight/modEvasive.json`)
4. **Lower thresholds gradually** once you understand your traffic baseline
5. **Always whitelist** internal service IPs and monitoring endpoints

### Enabling and disabling

mod_evasive is managed independently from ModSecurity. Enabling/disabling the WAF (`nssec waf enable`/`nssec waf disable`) does **not** affect mod_evasive.

```bash
# Check status
nssec waf evasive status

# Enable/disable independently
sudo nssec waf evasive enable
sudo nssec waf evasive disable
```

## Path Restrictions (.htaccess)

NetSapiens recommends restricting access to sensitive directories using `.htaccess` IP allowlists. This limits who can reach the admin login page, API, and provisioning endpoints.

### Which paths to protect

| Target | .htaccess Path | Server Types |
|--------|---------------|:------------:|
| SiPbx Admin UI | `/usr/local/NetSapiens/SiPbx/html/SiPbx/.htaccess` | Core, Combo |
| ns-api | `/usr/local/NetSapiens/SiPbx/html/ns-api/.htaccess` | Core, Combo |
| NDP Endpoints | `/usr/local/NetSapiens/ndp/.htaccess` | NDP, Combo |
| LiCf Recording | `/usr/local/NetSapiens/LiCf/html/LiCf/.htaccess` | Recording, Combo |

### .htaccess format

Each `.htaccess` file should follow this format:

```apache
<Files "adminlogin.php">
    Order allow,deny
    Allow from 127.0.0.1
    Allow from X.X.X.X
    Allow from 1.1.1.1
    Allow from 2.2.2.2
</Files>
```

**IPs to include:**
- `127.0.0.1` — required for internal NS service communication
- NetSapiens support IPs — so support can access your admin UI for support
- Your admin office IP(s) — for your own management access

### Using nssec

```bash
# Show current restriction status across all applicable paths
nssec waf restrict show

# Create/update .htaccess restrictions interactively
# Shows existing IPs and asks whether to keep or overwrite them
sudo nssec waf restrict init

# Or specify IPs directly on the command line
sudo nssec waf restrict init --ip 1.1.1.1 --ip 1.2.3.0/22

# Add a single IP to all managed .htaccess files
sudo nssec waf restrict add 1.1.1.1

# Remove an IP (cannot remove 127.0.0.1)
sudo nssec waf restrict remove 2.2.2.2

# Re-deploy after a NetSapiens package upgrade overwrites .htaccess files
sudo nssec waf restrict reapply
```

### Surviving NS package upgrades

NetSapiens package upgrades can overwrite `.htaccess` files. The `nssec waf restrict init` command saves the IP list to `/etc/nssec/restrict-ips.json`. After an upgrade, run:

```bash
sudo nssec waf restrict reapply
```

This re-creates all `.htaccess` files from the cached IP list.

### Manual configuration

If configuring manually, create the `.htaccess` file in each applicable directory with the format shown above. Ensure `127.0.0.1` is always included.

After creating or modifying `.htaccess` files, test and reload Apache:

```bash
sudo apache2ctl configtest && sudo systemctl reload apache2
```

## File Summary

| File | Purpose |
|------|---------|
| `/etc/modsecurity/modsecurity.conf` | Main ModSecurity configuration |
| `/etc/modsecurity/netsapiens-exclusions.conf` | NS-specific false positive exclusions |
| `/etc/modsecurity/crs/crs-setup.conf` | CRS settings (paranoia level, thresholds) |
| `/etc/modsecurity/crs/rules/*.conf` | CRS rule files (do not edit) |
| `/etc/apache2/mods-available/security2.conf` | Apache Include directives |
| `/etc/apache2/mods-available/evasive.conf` | mod_evasive threshold configuration |
| `/var/log/apache2/modsec_audit.log` | Audit log for triggered rules |
| `/var/log/apache2/mod_evasive.log` | mod_evasive block event log |
| `/var/log/apache2/mod_evasive/` | Per-IP block files (native mod_evasive) |

## Complementary Security Tools

ModSecurity only protects HTTP traffic. For a complete NetSapiens security posture, also deploy:

- **APIBAN** (apiban.org) - Real-time SIP attacker blocklist. Free, minutes to deploy.
- **fail2ban** - Reactive brute-force protection for SIP and SSH.
- **CrowdSec** - Crowd-sourced threat intelligence with VoIP blocklists.
- **UFW** - Firewall restricting access to only required ports and IPs.

See the [ns-security README](../README.md) for the full list of tools and audit checks.
