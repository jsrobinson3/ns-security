"""WAF configuration constants and Jinja2 templates."""

# Package names
MODSEC_PACKAGE = "libapache2-mod-security2"
CRS_APT_PACKAGE = "modsecurity-crs"
EVASIVE_PACKAGE = "libapache2-mod-evasive"
EVASIVE_CONF = "/etc/apache2/mods-available/evasive.conf"
EVASIVE_LOAD = "/etc/apache2/mods-enabled/evasive.load"
EVASIVE_LOG_DIR = "/var/log/apache2/mod_evasive"
EVASIVE_LOG_FILE = "/var/log/apache2/mod_evasive.log"

# mod_evasive threshold profiles
# "standard" — high thresholds, safe default that only catches extreme floods.
# "strict"   — tighter thresholds tuned for NetSapiens traffic patterns.
EVASIVE_PROFILES = {
    "standard": {
        "hash_table_size": 3097,
        "page_count": 100,
        "site_count": 500,
        "page_interval": 1,
        "site_interval": 1,
        "blocking_period": 10,
    },
    "strict": {
        "hash_table_size": 3097,
        "page_count": 15,
        "site_count": 60,
        "page_interval": 1,
        "site_interval": 1,
        "blocking_period": 60,
    },
}
EVASIVE_DEFAULT_PROFILE = "standard"

# CRS version pinning (used when apt ships v3.x)
PINNED_CRS_VERSION = "4.8.0"
CRS_GITHUB_DOWNLOAD = (
    f"https://github.com/coreruleset/coreruleset/archive/refs/tags/v{PINNED_CRS_VERSION}.tar.gz"
)

# File paths
MODSEC_CONF = "/etc/modsecurity/modsecurity.conf"
MODSEC_CONF_RECOMMENDED = "/etc/modsecurity/modsecurity.conf-recommended"
MODSEC_DIR = "/etc/modsecurity"
CRS_INSTALL_DIR = "/etc/modsecurity/crs"
SECURITY2_CONF = "/etc/apache2/mods-available/security2.conf"
SECURITY2_LOAD = "/etc/apache2/mods-enabled/security2.load"
NS_EXCLUSIONS_CONF = "/etc/modsecurity/netsapiens-exclusions.conf"
MODSEC_AUDIT_LOG = "/var/log/apache2/modsec_audit.log"
MODSEC_TMP_DIR = "/tmp/"
MODSEC_DATA_DIR = "/tmp/"

# CRS locations to check (apt-installed or manual)
CRS_SEARCH_PATHS = [
    "/usr/share/modsecurity-crs",
    "/etc/modsecurity/crs",
    "/etc/apache2/modsecurity-crs",
]

# Backup suffix for nssec-managed files
BACKUP_SUFFIX = ".bak.nssec"

# ---------------------------------------------------------------------------
# Jinja2 Templates
# ---------------------------------------------------------------------------

MODSEC_CONF_TEMPLATE = """\
# ModSecurity Configuration
# Managed by nssec — do not edit the SecRuleEngine line manually.
# Use 'nssec waf enable' to switch to blocking mode.
# Generated: {{ timestamp }}


# -- Rule engine initialization ----------------------------------------------

SecRuleEngine {{ mode }}


# -- Request body handling ---------------------------------------------------

SecRequestBodyAccess On

# Enable XML request body parser
SecRule REQUEST_HEADERS:Content-Type "(?:application(?:/soap\\+|/)|text/)xml" \\
     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"

# Enable JSON request body parser
SecRule REQUEST_HEADERS:Content-Type "application/json" \\
     "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"

# Body size limits — 25MB for NetSapiens (file uploads, recordings)
SecRequestBodyLimit 26214400
SecRequestBodyNoFilesLimit 26214400
SecRequestBodyInMemoryLimit 26214400

SecRequestBodyLimitAction Reject

# Verify request body was parsed correctly
SecRule REQBODY_ERROR "!@eq 0" \\
"id:'200002',phase:2,t:none,log,deny,status:400,\\
msg:'Failed to parse request body.',\\
logdata:'%{reqbody_error_msg}',severity:2"

# Strict multipart/form-data validation
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \\
"id:'200003',phase:2,t:none,log,deny,status:400, \\
msg:'Multipart request body failed strict validation: \\
PE %{REQBODY_PROCESSOR_ERROR}, \\
BQ %{MULTIPART_BOUNDARY_QUOTED}, \\
BW %{MULTIPART_BOUNDARY_WHITESPACE}, \\
DB %{MULTIPART_DATA_BEFORE}, \\
DA %{MULTIPART_DATA_AFTER}, \\
HF %{MULTIPART_HEADER_FOLDING}, \\
LF %{MULTIPART_LF_LINE}, \\
SM %{MULTIPART_MISSING_SEMICOLON}, \\
IQ %{MULTIPART_INVALID_QUOTING}, \\
IP %{MULTIPART_INVALID_PART}, \\
IH %{MULTIPART_INVALID_HEADER_FOLDING}, \\
FL %{MULTIPART_FILE_LIMIT_EXCEEDED}'"

# Detect possible unmatched boundary
SecRule MULTIPART_UNMATCHED_BOUNDARY "!@eq 0" \\
"id:'200004',phase:2,t:none,log,deny,\\
msg:'Multipart parser detected a possible unmatched boundary.'"

# PCRE tuning — avoid regex DoS
SecPcreMatchLimit 100000
SecPcreMatchLimitRecursion 100000

# Flag internal ModSecurity errors
SecRule TX:/^MSC_/ "!@streq 0" \\
        "id:'200005',phase:2,t:none,deny,\\
msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'"


# -- Response body handling --------------------------------------------------

SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml
SecResponseBodyLimit 524288
SecResponseBodyLimitAction ProcessPartial


# -- Filesystem configuration ------------------------------------------------

SecTmpDir {{ tmp_dir }}
SecDataDir {{ data_dir }}


# -- Audit log configuration -------------------------------------------------

SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABDEFHIJZ
SecAuditLogType Serial
SecAuditLog {{ audit_log }}


# -- Miscellaneous -----------------------------------------------------------

SecArgumentSeparator &
SecCookieFormat 0
SecUnicodeMapFile unicode.mapping 20127
SecStatusEngine On
"""

SECURITY2_CONF_TEMPLATE = """\
# ModSecurity Apache Configuration
# Managed by nssec
# Generated: {{ timestamp }}
<IfModule security2_module>
    # Main ModSecurity config
    IncludeOptional /etc/modsecurity/modsecurity.conf

    # NetSapiens-specific exclusions
    IncludeOptional /etc/modsecurity/netsapiens-exclusions.conf

    # OWASP CRS setup and rules
    IncludeOptional {{ crs_path }}/crs-setup.conf
    IncludeOptional {{ crs_path }}/plugins/*-config.conf
    IncludeOptional {{ crs_path }}/plugins/*-before.conf
    IncludeOptional {{ crs_path }}/rules/*.conf
    IncludeOptional {{ crs_path }}/plugins/*-after.conf
</IfModule>
"""

NS_EXCLUSIONS_TEMPLATE = """\
# NetSapiens-specific ModSecurity Exclusions
# Managed by nssec
# Generated: {{ timestamp }}
#
# These rules prevent false positives on the NetSapiens management UI
# and API endpoints while keeping CRS protection active for everything else.

# ---- Admin UI form submissions trigger SQL injection false positives ----
SecRuleUpdateTargetById 942100 "!REQUEST_COOKIES"
SecRuleUpdateTargetById 942200 "!REQUEST_COOKIES"

# ---- Third-party tracking cookies trigger RCE false positives ----
# Reddit (_rdt_*), Google (_ga, _gid), Facebook (_fbp) etc. use delimiters
# that match shell patterns like ~N (directory stack) or command separators.
SecRuleUpdateTargetById 932270 "!REQUEST_COOKIES"

# ---- NS API endpoints use base64 in query strings ----
SecRule REQUEST_URI "@beginsWith /ns-api/" \\
    "id:1000001,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:filter"

# ---- Admin UI session handling ----
SecRule REQUEST_URI "@beginsWith /SiPbx/" \\
    "id:1000002,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveById=921180"

# ---- QoS proxy (NqsProxy) ----
SecRule REQUEST_URI "@beginsWith /NqsProxy/" \\
    "id:1000003,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveById=920420"

# ---- Phone provisioning config files (.cfg, .xml) ----
# Phones fetch config files from /cfg/ - this is expected NDP behavior.
# 920440: blocks .cfg extension by policy
# 951xxx: SQL leakage response rules hit PCRE limits on directory contact data
# Disable response body scanning for /cfg/ to avoid PCRE overhead on config responses.
SecRule REQUEST_URI "@beginsWith /cfg/" \\
    "id:1000004,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveById=920440,\\
     ctl:responseBodyAccess=Off"

# ---- Firmware downloads ----
# Phones fetch firmware from /frm/ - binary files must not be scanned.
SecRule REQUEST_URI "@beginsWith /frm/" \\
    "id:1000007,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:responseBodyAccess=Off"

# ---- iNSight health checks ----
SecRule REQUEST_URI "@beginsWith /cfg/insight_healthcheck" \\
    "id:1000006,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveByTag=OWASP_CRS"

# ---- Localhost internal traffic ----
# NS services (NmsSBus, ns-api, cfg) communicate over localhost.
# Rules 921110, 920180, 920350 false-positive on internal SIP/API calls.
SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" \\
    "id:1000005,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveByTag=OWASP_CRS"

{% if admin_ips %}
# ---- Allowlisted admin IPs (reduced WAF strictness) ----
{% for ip in admin_ips %}
SecRule REMOTE_ADDR "@ipMatch {{ ip }}" \\
    "id:{{ 1000100 + loop.index }},\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveByTag=OWASP_CRS"
{% endfor %}
{% endif %}
"""

CRS_SETUP_OVERRIDES_TEMPLATE = """\
# OWASP CRS Setup Overrides for NetSapiens
# Managed by nssec
# Generated: {{ timestamp }}
#
# Copy of crs-setup.conf.example with NetSapiens-appropriate defaults.
# Paranoia level 1 is conservative — increase after tuning false positives.

SecAction \\
    "id:900000,\\
     phase:1,\\
     nolog,\\
     pass,\\
     t:none,\\
     setvar:tx.crs_setup_version=400,\\
     setvar:tx.paranoia_level={{ paranoia_level }},\\
     setvar:tx.blocking_paranoia_level={{ paranoia_level }},\\
     setvar:tx.detection_paranoia_level={{ paranoia_level }}"

# Anomaly scoring thresholds
SecAction \\
    "id:900110,\\
     phase:1,\\
     nolog,\\
     pass,\\
     t:none,\\
     setvar:tx.inbound_anomaly_score_threshold={{ inbound_threshold }},\\
     setvar:tx.outbound_anomaly_score_threshold={{ outbound_threshold }}"

# Allowed HTTP methods
SecAction \\
    "id:900200,\\
     phase:1,\\
     nolog,\\
     pass,\\
     t:none,\\
     setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"

# Allowed content types
SecAction \\
    "id:900220,\\
     phase:1,\\
     nolog,\\
     pass,\\
     t:none,\\
     setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |multipart/mixed| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json|'"
"""

EVASIVE_CONF_TEMPLATE = """\
# mod_evasive Configuration
# Managed by nssec
# Generated: {{ timestamp }}
# Profile: {{ profile }}
#
# HTTP flood / DDoS protection for Apache.
# WARNING: mod_evasive has no detection-only mode. When enabled it WILL
# return HTTP 403 to clients that exceed the thresholds below.
# Review your traffic with 'nssec waf status' and the Apache API Usage
# dashboard before switching to the strict profile.

<IfModule mod_evasive20.c>
    # Hash table size — prime number with headroom above expected unique IPs
    DOSHashTableSize        {{ hash_table_size }}

    # Max requests to the same page per interval before blocking
    DOSPageCount            {{ page_count }}

    # Max total requests from one IP per interval before blocking
    DOSSiteCount            {{ site_count }}

    # Sliding window intervals (seconds)
    DOSPageInterval         {{ page_interval }}
    DOSSiteInterval         {{ site_interval }}

    # How long (seconds) an IP is blocked once a threshold is hit
    DOSBlockingPeriod       {{ blocking_period }}

    # Log blocked IPs here (one file per IP)
    DOSLogDir               {{ log_dir }}

    # Log block events to a structured log file for Loki/Grafana ingestion
    DOSSystemCommand        "/bin/sh -c 'echo $(date -Is) action=blocked src_ip=%s >> {{ log_file }}'"

    # Whitelist RFC 1918 private ranges and loopback to avoid false positives
    # on internal NS service traffic and cluster communication
    DOSWhitelist            127.0.0.1
    DOSWhitelist            10.*.*.*
    DOSWhitelist            172.16.*.*
    DOSWhitelist            172.17.*.*
    DOSWhitelist            172.18.*.*
    DOSWhitelist            172.19.*.*
    DOSWhitelist            172.20.*.*
    DOSWhitelist            172.21.*.*
    DOSWhitelist            172.22.*.*
    DOSWhitelist            172.23.*.*
    DOSWhitelist            172.24.*.*
    DOSWhitelist            172.25.*.*
    DOSWhitelist            172.26.*.*
    DOSWhitelist            172.27.*.*
    DOSWhitelist            172.28.*.*
    DOSWhitelist            172.29.*.*
    DOSWhitelist            172.30.*.*
    DOSWhitelist            172.31.*.*
    DOSWhitelist            192.168.*.*
</IfModule>
"""
