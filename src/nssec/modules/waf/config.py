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

# CRS rule files that require ModSecurity >= 2.9.6 (MULTIPART_PART_HEADERS).
# These are renamed to .conf.disabled on older ModSecurity versions.
CRS_RULES_REQUIRE_296 = [
    "REQUEST-922-MULTIPART-ATTACK.conf",
]
DIGITALWAVE_REPO_URL = "http://modsecurity.digitalwave.hu/ubuntu/"
DIGITALWAVE_KEY_URL = "https://modsecurity.digitalwave.hu/archive.key"
DIGITALWAVE_KEYRING = "/usr/share/keyrings/digitalwave-modsecurity.gpg"
DIGITALWAVE_LIST = "/etc/apt/sources.list.d/digitalwave-modsecurity.list"
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

# CRS locations to check — nssec-managed path first so v4 is preferred
# over the apt v3 package when both exist.
CRS_SEARCH_PATHS = [
    "/etc/modsecurity/crs",
    "/usr/share/modsecurity-crs",
    "/etc/apache2/modsecurity-crs",
]

# Backup suffix for nssec-managed files
BACKUP_SUFFIX = ".bak.nssec"

# Exclusions template version — human-readable label for the template revision.
NS_EXCLUSIONS_VERSION = "9"

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

    # OWASP CRS setup
    IncludeOptional {{ crs_path }}/crs-setup.conf
    IncludeOptional {{ crs_path }}/plugins/*-config.conf
    IncludeOptional {{ crs_path }}/plugins/*-before.conf

    # NetSapiens-specific exclusions (MUST load before the CRS rules: the
    # exclusions are runtime ctl directives, which only suppress rules that
    # execute later in the transaction. Within a phase, execution order is
    # load order — loaded after the rules, the phase-1 exclusions such as
    # the localhost and admin-IP allowlists run after phase-1 CRS rules
    # like 920350/920180 have already fired.)
    IncludeOptional /etc/modsecurity/netsapiens-exclusions.conf

    # API scrape protection ('nssec waf scrape-protection'). Optional: the
    # file only exists while enabled.
    IncludeOptional /etc/modsecurity/netsapiens-scrape-protection.conf

    # OWASP CRS rules
    IncludeOptional {{ crs_path }}/rules/*.conf
    IncludeOptional {{ crs_path }}/plugins/*-after.conf
</IfModule>
"""

NS_EXCLUSIONS_TEMPLATE = """\
# NetSapiens-specific ModSecurity Exclusions
# Managed by nssec
# Generated: {{ timestamp }}
# nssec-exclusions-version: {{ version }}
# nssec-exclusions-hash: {{ template_hash }}
#
# These rules prevent false positives on the NetSapiens management UI
# and API endpoints while keeping CRS protection active for everything else.
#
# Almost all exclusions are runtime ctl directives, which only suppress rules
# that execute later in the same transaction. This file must therefore be
# loaded BEFORE the CRS rules — otherwise the phase-1 exclusions (localhost and
# IP allowlists) run after phase-1 CRS rules have already fired. The one
# exception is the sanitiseArg rule (1000015): it is a logging-time action, not
# a rule suppression, so its load order relative to the CRS rules is immaterial.

# ---- Redact credential-bearing arguments from the audit log ----
# ModSecurity writes matched requests to the audit log verbatim, including
# query-string and body arguments. OAuth2 password-grant and portal-token
# requests carry secrets in named arguments; sanitiseArg replaces every byte of
# the named argument's value with an asterisk in the audit log (parts A/B/C/I).
# Masking is by argument NAME, so `password` is caught on every endpoint that
# uses it, not just the token endpoint. This is non-disruptive and never blocks.
#
# Scope note: this only covers the ModSecurity audit log. The Apache access_log
# records the request line (%r) independently and still stores query-string
# secrets in cleartext — that needs a separate LogFormat/SetEnvIf fix in the
# vhost, outside nssec's control.
#
# `ctl:sanitiseArg` does not exist in ModSecurity 2.x (not in the ctl option
# list), so this is an unconditional SecAction. phase:2 matches the documented
# pattern in the reference manual and guarantees arguments are fully parsed.
SecAction \\
    "id:1000015,\\
     phase:2,\\
     t:none,\\
     nolog,\\
     pass,\\
     sanitiseArg:password,\\
     sanitiseArg:client_secret,\\
     sanitiseArg:refresh_token,\\
     sanitiseArg:access_token,\\
     sanitiseArg:auth_code,\\
     sanitiseArg:nsToken,\\
     sanitiseArg:ns_t"

# ---- Admin UI form submissions and third-party tracking cookies ----
# Cookies from admin UI sessions trigger SQL injection false positives (942100,
# 942200).  Reddit (_rdt_*), Google (_ga, _gid), Facebook (_fbp) etc. use
# delimiters that match shell patterns like ~N (directory stack), triggering
# RCE false positives (932270).  High-entropy CDN tokens — notably Cloudflare's
# cf_clearance / __cf_bm — contain random substrings that match OS file
# extensions in the LFI phrase list (e.g. ".nsr"), triggering 930120.
#
# Cookies are opaque server/CDN-issued tokens, not user-supplied file paths or
# query values, so scanning them for these attack classes is all noise.  Scope
# the removals to REQUEST_COOKIES so request bodies and args stay protected.
#
# Uses runtime ctl:ruleRemoveTargetById so this works regardless of whether
# the exclusions file loads before or after the CRS rules (e.g. when the
# default Debian wildcard IncludeOptional /etc/modsecurity/*.conf picks up
# this file alphabetically before the CRS rules are loaded).
SecAction \
    "id:1000009,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveTargetById=942100;REQUEST_COOKIES,\\
     ctl:ruleRemoveTargetById=942200;REQUEST_COOKIES,\\
     ctl:ruleRemoveTargetById=932270;REQUEST_COOKIES,\\
     ctl:ruleRemoveTargetById=930120;REQUEST_COOKIES"

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

# ---- Portal login password false positives ----
# Passwords with shell metacharacters ($, ~, ^, |) trigger RCE rule 932270.
SecRule REQUEST_URI "@beginsWith /portal/login/login" \\
    "id:1000008,\\
     phase:2,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveTargetById=932270;ARGS:data[Login][password]"

# ---- Portal paths with domain names in URL segments ----
# NetSapiens portal URLs embed tenant domain names as path segments, e.g.:
#   /portal/stats/billable/example.com
#   /portal/users/mask/user@example.com
# Rule 920440 interprets the TLD (.com, .net, .org) as a restricted file
# extension.  These are not file downloads — suppress 920440 for all /portal/
# paths.
SecRule REQUEST_URI "@beginsWith /portal/" \\
    "id:1000010,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveById=920440"

# ---- Subscription webhook URLs (post-url / post_url) ----
# Event subscriptions take a webhook delivery URL that the API posts data
# back to, e.g.:
#   post-url=https://webhook.example.com:45222/onecloudhook?tenant_id=...
# libinjection (941100) and the other attack-xss rules routinely misclassify
# legitimate URLs — with their scheme, query string and separators — as XSS,
# scoring 5 anomaly points and blocking every subscription create/update.
# Two API generations, two spellings of the argument:
#   v2 REST   -> POST /ns-api/v2/subscriptions   arg "post-url"  (hyphen)
#   v1 legacy -> POST /ns-api/?object=event&action=create  arg "post_url" (underscore)
# The v1 dispatch endpoint is just /ns-api/, so it can't be scoped by path;
# instead we scope by the distinctive argument names, which only appear on
# subscription creates/updates.  Removing a target that isn't present in a
# request is a no-op, so listing both is safe for every /ns-api/ call.
SecRule REQUEST_URI "@beginsWith /ns-api/" \\
    "id:1000011,\\
     phase:2,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveTargetByTag=attack-xss;ARGS:post-url,\\
     ctl:ruleRemoveTargetByTag=attack-xss;ARGS:post_url"

# ---- OAuth2 token endpoint empty-body POSTs ----
# OAuth2 clients (e.g. client-credentials token refresh) routinely POST to the
# token endpoint with an empty body and omit the Content-Length header.  Rule
# 920180 flags any POST lacking both Content-Length and Transfer-Encoding,
# adding 3 anomaly points on every token request — harmless noise on its own,
# but it erodes the margin before the blocking threshold.  Scope the removal to
# the token endpoint so protocol enforcement stays active everywhere else.
SecRule REQUEST_URI "@beginsWith /ns-api/oauth2/token" \\
    "id:1000012,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveById=920180"

# ---- Pagination limit sentinel (legacy mobile clients) ----
# Older mobile clients request "everything" by sending the 32-bit signed
# integer maximum as the page size, e.g.:
#   GET /ns-api/?object=call&action=read&limit=2147483647
# Rule 942220 matches a fixed list of integer-overflow sentinels (2147483647,
# 4294967295, the 2.2250738585072011e-308 "magic number" crash, ...) against
# every argument.  In a pagination bound these are a client idiom, not an
# attack: the value is consumed as an integer row limit, never interpolated
# into SQL.  At CRITICAL severity it scores 5 anomaly points on its own, which
# equals the inbound blocking threshold, so every such request 403s.
#
# Drop only ARGS:limit from 942220.  The rule still inspects every other
# argument, and every other SQLi rule (libinjection 942100 included) still
# inspects ARGS:limit.
SecRule REQUEST_URI "@beginsWith /ns-api/" \\
    "id:1000013,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveTargetById=942220;ARGS:limit"

# ---- Configuration keys named after PHP functions ----
# The v2 configuration API addresses each setting by key as a path segment:
#   GET /ns-api/v2/configurations/PORTAL_AGENT_SCREEN_POP_URL_NUMBER_FORMAT
# Rule 933150 matches high-risk PHP function names against REQUEST_FILENAME,
# and the key above ends in ...NUMBER_FORMAT, which case-insensitively contains
# the PHP builtin "number_format".  Any config key whose name happens to embed
# a function name (number_format, compact, extract, ...) hits this the same
# way, scoring 5 anomaly points and blocking a plain read of a setting.
#
# Drop only REQUEST_FILENAME from 933150, and only under the configurations
# namespace where keys become path segments.  Request bodies and arguments are
# still scanned for PHP injection here, and REQUEST_FILENAME is still scanned
# everywhere else.
SecRule REQUEST_URI "@beginsWith /ns-api/v2/configurations/" \\
    "id:1000014,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveTargetById=933150;REQUEST_FILENAME"

# ---- iNSight health checks ----
SecRule REQUEST_URI "@beginsWith /cfg/insight_healthcheck" \\
    "id:1000006,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveByTag=OWASP_CRS"

# ---- Localhost internal traffic ----
# NS services (NmsSBus, ns-api, cfg) communicate over localhost and must
# never be flagged or blocked. Rules 921110, 920180, 920350 false-positive
# on internal SIP/API calls.
SecRule REMOTE_ADDR "@ipMatch 127.0.0.1,::1" \\
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

{% if nodeping_ips %}
# ---- NodePing monitoring probe IPs ----
# Health check probes should bypass CRS to avoid false positives.
# Source: https://nodeping.com/content/txt/pinghosts.txt
{% for ip in nodeping_ips %}
SecRule REMOTE_ADDR "@ipMatch {{ ip }}" \\
    "id:{{ 1000200 + loop.index }},\\
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
     setvar:tx.crs_setup_version=480,\\
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

# ---------------------------------------------------------------------------
# Admin-UI IP Restriction Constants
# ---------------------------------------------------------------------------

RESTRICT_MANAGED_MARKER = "# Managed by nssec"

# Single Apache config that restricts the admin UIs by IP. Living under
# /etc/apache2/conf.d/ (outside the NetSapiens package tree) means it survives
# NS package upgrades and is honored under PHP-FPM — unlike the legacy per-app
# .htaccess files this replaces. Matches the mTLS module's convention.
RESTRICT_CONF_PATH = "/etc/apache2/conf.d/nssec-restrict.conf"

# Admin-UI components whose URL paths get IP-restricted. The <LocationMatch>
# regex is built from the `segment` of each component that applies to the
# detected server type and is actually installed on disk. ns-api is
# intentionally excluded — it serves the REST API and must stay reachable.
RESTRICT_COMPONENTS = [
    {
        "name": "SiPbx Admin UI",
        "segment": "SiPbx",
        "directory": "/usr/local/NetSapiens/SiPbx/html/SiPbx",
        "server_types": ["core", "combo"],
    },
    {
        "name": "NDP",
        "segment": "ndp",
        "directory": "/usr/local/NetSapiens/ndp",
        "server_types": ["ndp", "combo"],
    },
    {
        "name": "LiCf Recording",
        "segment": "LiCf",
        "directory": "/usr/local/NetSapiens/LiCf/html/LiCf",
        "server_types": ["recording", "combo"],
    },
]

# Legacy per-directory .htaccess files written by older nssec versions. Retained
# only so migration can detect IPs to carry forward and clean up the files it
# previously created (those bearing RESTRICT_MANAGED_MARKER).
LEGACY_HTACCESS_PATHS = [
    "/usr/local/NetSapiens/SiPbx/html/SiPbx/.htaccess",
    "/usr/local/NetSapiens/SiPbx/html/ns-api/.htaccess",
    "/usr/local/NetSapiens/ndp/.htaccess",
    "/usr/local/NetSapiens/LiCf/html/LiCf/.htaccess",
]

RESTRICT_CONF_TEMPLATE = """\
{{ managed_marker }}
# Generated by nssec waf restrict — do not edit by hand.
# Restricts the NetSapiens admin UIs to the allowlisted IPs below.
# Manage with: nssec waf restrict add|remove|show|reapply
<LocationMatch "^/({{ segments }})/">
    <RequireAny>
{%- for ip in ips %}
        Require ip {{ ip }}
{%- endfor %}
    </RequireAny>
</LocationMatch>
"""

# Cache file so restrictions survive NS package upgrades and can be re-applied.
RESTRICT_CACHE_PATH = "/etc/nssec/restrict-ips.json"

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


def _exclusions_template_hash() -> str:
    """Compute MD5 hash of NS_EXCLUSIONS_TEMPLATE source.

    Any change to the template (new rules, modified rules, structural changes)
    automatically produces a different hash. Deployed files embed this hash
    so 'waf status' can detect drift without manual version bumping.
    """
    import hashlib

    return hashlib.md5(NS_EXCLUSIONS_TEMPLATE.encode()).hexdigest()[:12]


NS_EXCLUSIONS_HASH = _exclusions_template_hash()


# ---------------------------------------------------------------------------
# API Scrape Protection
# ---------------------------------------------------------------------------

SCRAPE_CONF = "/etc/modsecurity/netsapiens-scrape-protection.conf"

# detect: log matches only.  block: HTTP 429 over-limit clients (403 for
# scraper user agents).
SCRAPE_MODES = ("detect", "block")
SCRAPE_DEFAULT_MODE = "detect"

# Threshold profiles. Both counters share one fixed window.
#   window        seconds per counting window
#   max_requests  /ns-api/ requests allowed per client IP per window
#   max_domains   distinct tenant domains one client IP may READ per window
#   block_period  seconds a client stays flagged (blocked in block mode)
#
# The domain limit is the primary signal: a harvester walking tenants trips it
# within seconds, while its request rate can look like an ordinary integration.
SCRAPE_PROFILES = {
    "standard": {
        "window": 600,
        "max_requests": 3000,
        "max_domains": 50,
        "block_period": 1800,
    },
    "strict": {
        "window": 600,
        "max_requests": 1000,
        "max_domains": 15,
        "block_period": 3600,
    },
}
SCRAPE_DEFAULT_PROFILE = "standard"

# Case-insensitive substrings (@pm) of the User-Agent header.
SCRAPE_BAD_USER_AGENTS = ["harvest/"]

SCRAPE_CONF_TEMPLATE = """\
# NetSapiens API Scrape Protection
# Managed by nssec — change with 'nssec waf scrape-protection enable', do not edit by hand.
# Generated: {{ timestamp }}
# nssec-scrape-hash: {{ template_hash }}
# nssec-scrape-settings: {{ settings_json }}
#
# Detects bulk harvesting of tenant data through /ns-api/: one client walking
# every domain reading devices, users, etc. mod_evasive cannot see this — it
# counts per second and keys on the URI path without the query string, so a
# steady crawl of /ns-api/?object=device&action=read&domain=<each tenant>
# never trips it.
#
# Mode:     {{ mode }} ({% if mode == "block" %}over-limit clients get HTTP 429{% else %}log only, nothing is blocked{% endif %})
# Profile:  {{ profile }}
# Window:   {{ window }}s: max {{ max_requests }} requests, max {{ max_domains }} distinct domains read
# Flagged:  {{ block_period }}s once over a limit
#
# Blocking also requires SecRuleEngine On: under DetectionOnly the deny actions
# are logged but not enforced.
#
# Counters live in ModSecurity persistent collections under SecDataDir, local
# to this node, so each node enforces its own budget. Behind a reverse proxy or
# load balancer every client shares the proxy's address unless mod_remoteip is
# configured; fix that (or exempt the proxy) before switching to block mode.
#
# Rule IDs: 1002001-1002099. Every rule except the exemption carries the tag
# nssec-scrape so the exemption's runtime ctl removes them all; it must load
# after netsapiens-exclusions.conf and stay first in this file.
{% set over_limit = "deny,status:429" if mode == "block" else "pass" %}

# ---- Exempt sources ----
SecRule REMOTE_ADDR "@ipMatch {{ exempt_ips | join(',') }}" \\
    "id:1002001,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveByTag=nssec-scrape"

{% if bad_user_agents %}
# ---- Known scraper user agents (all paths) ----
SecRule REQUEST_HEADERS:User-Agent "@pm {{ bad_user_agents | join(' ') }}" \\
    "id:1002002,\\
     phase:1,\\
     {{ "deny,status:403" if mode == "block" else "pass" }},\\
     log,\\
     tag:'nssec-scrape',\\
     msg:'nssec: known scraper user agent',\\
     logdata:'%{MATCHED_VAR}'"
{% endif %}

# ---- Identify /ns-api/ requests and load this client's counters ----
SecRule REQUEST_FILENAME "@beginsWith /ns-api/" \\
    "id:1002010,\\
     phase:1,\\
     pass,\\
     nolog,\\
     t:none,t:urlDecodeUni,t:normalizePath,\\
     tag:'nssec-scrape',\\
     initcol:ip=%{REMOTE_ADDR},\\
     setvar:tx.nssec_api=1"

{% if mode == "block" %}
# ---- Enforce: flagged clients are refused until the flag expires ----
SecRule TX:nssec_api "@eq 1" \\
    "id:1002011,\\
     phase:1,\\
     deny,\\
     status:429,\\
     nolog,\\
     tag:'nssec-scrape',\\
     chain"
    SecRule IP:nssec_flagged "@eq 1" \\
        "t:none"
{% endif %}

# ---- Request budget ----
# Fixed window: expirevar is issued only when a counter is created. Issuing it
# on every hit pushes the expiry back each time, turning the window into an
# idle timeout; a slow but steady integration would then climb past the budget
# over a few hours.
SecRule TX:nssec_api "@eq 1" \\
    "id:1002020,\\
     phase:1,\\
     pass,\\
     nolog,\\
     tag:'nssec-scrape',\\
     chain"
    SecRule &IP:nssec_requests "@eq 0" \\
        "setvar:ip.nssec_requests=0,\\
         expirevar:ip.nssec_requests={{ window }}"

SecRule TX:nssec_api "@eq 1" \\
    "id:1002021,\\
     phase:1,\\
     pass,\\
     nolog,\\
     tag:'nssec-scrape',\\
     setvar:ip.nssec_requests=+1"

# Flagging also serves as de-duplication: each rule logs once per flag period
# instead of on every request past the limit.
SecRule IP:nssec_requests "@gt {{ max_requests }}" \\
    "id:1002022,\\
     phase:1,\\
     {{ over_limit }},\\
     log,\\
     tag:'nssec-scrape',\\
     msg:'nssec: ns-api request budget exceeded',\\
     logdata:'%{ip.nssec_requests} requests in {{ window }}s window',\\
     setvar:ip.nssec_flagged=1,\\
     expirevar:ip.nssec_flagged={{ block_period }},\\
     chain"
    SecRule &IP:nssec_flagged "@eq 0" \\
        "t:none"

# ---- Cross-domain enumeration ----
# Normal API clients work inside one tenant or a handful. Reading many distinct
# tenant domains in a short window is the bulk-harvest signature.
#
# Tenant domain named by the request: the v1 "domain" argument (query string or
# form body) or the v2 /ns-api/v2/domains/<domain>/ path segment. The character
# class bounds what reaches a collection key.
SecRule TX:nssec_api "@eq 1" \\
    "id:1002030,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-scrape',\\
     chain"
    SecRule ARGS:domain "@rx ^([a-z0-9][a-z0-9._-]{0,127})$" \\
        "t:none,t:lowercase,\\
         capture,\\
         setvar:tx.nssec_domain=%{tx.1}"

SecRule TX:nssec_api "@eq 1" \\
    "id:1002031,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-scrape',\\
     chain"
    SecRule REQUEST_FILENAME "@rx ^/+ns-api/v2/domains/([a-z0-9][a-z0-9._-]{0,127})(?:/|$)" \\
        "t:none,t:urlDecodeUni,t:lowercase,\\
         capture,\\
         setvar:tx.nssec_domain=%{tx.1}"

# Only reads count: provisioning across tenants is a normal reseller workflow,
# reading across them is how data leaves. v1 names the operation in "action";
# requests without one (v2) are classified by method.
SecRule &TX:nssec_domain "@eq 1" \\
    "id:1002032,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-scrape',\\
     chain"
    SecRule ARGS:action "@rx ^(?:read|count|list)$" \\
        "t:none,t:lowercase,\\
         setvar:tx.nssec_read=1"

SecRule &TX:nssec_domain "@eq 1" \\
    "id:1002033,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-scrape',\\
     chain"
    SecRule &ARGS:action "@eq 0" \\
        "chain"
        SecRule REQUEST_METHOD "@streq GET" \\
            "setvar:tx.nssec_read=1"

# One RESOURCE record per (client, domain) marks that domain as already counted
# for the window, so re-reading the same tenant costs nothing. Made-up domain
# names count as distinct domains too, so a client inflating the key space
# trips the limit itself. (The seen-marker and the IP counter start their
# windows at different times, which can only under-count, never over-count.)
SecRule TX:nssec_read "@eq 1" \\
    "id:1002040,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-scrape',\\
     initcol:resource=nssec_%{REMOTE_ADDR}_%{tx.nssec_domain},\\
     setvar:tx.nssec_resource=1"

SecRule TX:nssec_resource "@eq 1" \\
    "id:1002041,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-scrape',\\
     chain"
    SecRule &RESOURCE:nssec_seen "@eq 0" \\
        "setvar:resource.nssec_seen=1,\\
         expirevar:resource.nssec_seen={{ window }},\\
         setvar:tx.nssec_new_domain=1"

SecRule TX:nssec_new_domain "@eq 1" \\
    "id:1002042,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-scrape',\\
     chain"
    SecRule &IP:nssec_domains "@eq 0" \\
        "setvar:ip.nssec_domains=0,\\
         expirevar:ip.nssec_domains={{ window }}"

SecRule TX:nssec_new_domain "@eq 1" \\
    "id:1002043,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-scrape',\\
     setvar:ip.nssec_domains=+1"

SecRule IP:nssec_domains "@gt {{ max_domains }}" \\
    "id:1002044,\\
     phase:2,\\
     {{ over_limit }},\\
     log,\\
     tag:'nssec-scrape',\\
     msg:'nssec: ns-api cross-domain enumeration',\\
     logdata:'%{ip.nssec_domains} distinct domains read in {{ window }}s window (latest: %{tx.nssec_domain})',\\
     setvar:ip.nssec_flagged=1,\\
     expirevar:ip.nssec_flagged={{ block_period }},\\
     chain"
    SecRule &IP:nssec_flagged "@eq 0" \\
        "t:none"
"""


def _scrape_template_hash() -> str:
    """MD5 of SCRAPE_CONF_TEMPLATE, embedded in deployed files for drift detection."""
    import hashlib

    return hashlib.md5(SCRAPE_CONF_TEMPLATE.encode()).hexdigest()[:12]


SCRAPE_TEMPLATE_HASH = _scrape_template_hash()
