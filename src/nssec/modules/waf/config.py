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
NS_EXCLUSIONS_VERSION = "10"

# Optional features of the exclusions file, with their defaults.  The deployed
# file records each one as a "# nssec-toggle: <name>=on|off" header line, so a
# re-render keeps whatever was chosen; a file without the line (older
# version) gets the default.
EXCLUSION_TOGGLE_DEFAULTS = {
    "block_harvest_ua": True,
    "device_read_allowlist_only": False,
    "device_walk": True,
    "token_audit": False,
}

# Abuse-protection limits (seconds unless noted).  Applies per client IP;
# allowlisted admin/NodePing IPs and localhost are exempt.
ABUSE_LIMITS = {
    # Device walking (v1 and v2 API): reading devices (which carry SIP credentials)
    # across many tenant domains is credential harvesting.
    "max_domains": 2,  # distinct domains before a short block...
    "domain_window": 300,  # ...within this window
    "max_reads": 60,  # device reads before a short block...
    "read_window": 60,  # ...within this window
    "block_period": 600,  # short block
    "repeat_window": 86400,  # a second offence within this window...
    "long_block_period": 86400,  # ...gets the long block
    # Slow walk: distinct domains within a long window.  Must stay well below
    # ~15: ModSecurity stores the whole per-IP domain list in one ~1KB DBM
    # record and silently stops saving it once the record is too large.
    "slow_max_domains": 10,
    "slow_window": 86400,
    # Harvesting user agent: ban the source IP from /ns-api/ for this long.
    "ua_ban_period": 86400,
}

# SBUS cluster peers (see nssec.core.cluster).  ModSecurity allowlist rules
# are numbered CLUSTER_RULE_ID_BASE + n over the sorted peer IPs, so they stay
# stable when the manifest is reordered; room for 999 addresses.
CLUSTER_RULE_ID_BASE = 1001000
CLUSTER_BLOCK_END = "# ---- end cluster peers ----"
RESTRICT_CLUSTER_BEGIN = "# BEGIN nssec cluster peers (managed by nssec waf cluster refresh)"
RESTRICT_CLUSTER_END = "# END nssec cluster peers"

# User agents of known bulk-harvesting tools (matched case-insensitively as a
# substring of User-Agent).
BLOCKED_USER_AGENTS = ["harvest/"]

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
{% for name, on in toggles.items() | sort -%}
# nssec-toggle: {{ name }}={{ 'on' if on else 'off' }}
{% endfor -%}#
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
# The Authorization and Cookie request headers are masked too: they carry
# Bearer tokens, the portal's Basic client_id:client_secret on token
# requests, and session cookies, and would otherwise sit in part B of every
# audited request.
#
# Scope note: ModSecurity 2.9 masks the arguments in place while it writes an
# audit-log entry, and Apache writes the access_log (%r) afterwards, so the
# access_log line is masked too -- but only for requests that get an audit-log
# entry (relevant status, a matched rule with auditlog, or token audit on).
# Every other request still stores query-string secrets in the access_log in
# cleartext; a guaranteed fix needs a LogFormat/SetEnvIf change in the vhost,
# outside nssec's control.
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
     sanitiseArg:ns_t,\\
     sanitiseArg:passcode,\\
     sanitiseRequestHeader:Authorization,\\
     sanitiseRequestHeader:Cookie"

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
     ctl:ruleRemoveByTag=OWASP_CRS,\\
     ctl:ruleRemoveByTag=nssec-abuse"

{% if admin_ips %}
# ---- Allowlisted admin IPs (reduced WAF strictness) ----
{% for ip in admin_ips %}
SecRule REMOTE_ADDR "@ipMatch {{ ip }}" \\
    "id:{{ 1000100 + loop.index }},\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveByTag=OWASP_CRS,\\
     ctl:ruleRemoveByTag=nssec-abuse"
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
     ctl:ruleRemoveByTag=OWASP_CRS,\\
     ctl:ruleRemoveByTag=nssec-abuse"
{% endfor %}
{% endif %}

{% if cluster_peers %}
# ---- SBUS cluster peers (reduced WAF strictness) ----
# Every cluster member delivers SBUS events to this server over HTTP; CRS
# must not score them and the abuse limits must not count them.
# Source: SBUS manifest {{ cluster_manifest_url }}, {{ cluster_host_count }} host(s), discovered {{ cluster_discovered_at }}.
# Manage with: nssec waf cluster show|refresh
{% for ip, host in cluster_peers %}
# {{ host }}
SecRule REMOTE_ADDR "@ipMatch {{ ip }}" \\
    "id:{{ cluster_rule_id_base + loop.index }},\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:ruleRemoveByTag=OWASP_CRS,\\
     ctl:ruleRemoveByTag=nssec-abuse"
{% endfor %}
{% endif %}

# ===========================================================================
# Abuse protection
# ===========================================================================
# Unlike everything above, these rules deny.  They follow the WAF engine
# mode: under DetectionOnly they only log (state is still tracked, so the
# log shows what would have been blocked); after 'nssec waf enable' they
# block.  Toggle with 'nssec waf update-exclusions --[no-]device-walk' and
# '--[no-]block-harvest-ua'.
#
# Per-IP state is kept in two persistent collections (SecDataDir):
#   RESOURCE "nssec_abuse_<ip>"   counters, block flags, 5-minute domain list
#   USER     "nssec_walk24_<ip>"  24-hour domain list
# CRS owns IP (keyed on IP + User-Agent hash, which a scraper could rotate)
# and GLOBAL, and never touches RESOURCE or USER.  Each collection is stored
# as a single ~1KB DBM record, so domains are stored as 8-hex-char hashes and
# no new domains are recorded while an IP is blocked; that keeps both
# records far below the size at which ModSecurity can no longer save them.
#
# Stateful rules carry tag nssec-abuse, which the localhost and IP allowlist
# rules above remove, so those sources are never counted or banned.
{% if toggles.device_walk or toggles.block_harvest_ua %}

SecRule REQUEST_FILENAME "@beginsWith /ns-api/" \\
    "id:1000320,\\
     phase:1,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     initcol:resource=nssec_abuse_%{REMOTE_ADDR}"
{% endif %}
{% if toggles.block_harvest_ua %}

# ---- Bulk-harvesting user agents ----
# A matching request is denied, and the source IP is banned from /ns-api/
# for {{ limits.ua_ban_period }}s so switching to an innocuous User-Agent does not help.
{% for ua in blocked_user_agents %}
SecRule REQUEST_HEADERS:User-Agent "@contains {{ ua }}" \\
    "id:{{ 1000300 + loop.index0 }},\\
     phase:1,\\
     pass,\\
     nolog,\\
     t:none,t:lowercase,\\
     setvar:tx.nssec_bad_ua=1"
{% endfor %}

SecRule TX:nssec_bad_ua "@eq 1" \\
    "id:1000330,\\
     phase:1,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     initcol:resource=nssec_abuse_%{REMOTE_ADDR},\\
     setvar:resource.ua_ban=1,\\
     expirevar:resource.ua_ban={{ limits.ua_ban_period }}"

SecRule TX:nssec_bad_ua "@eq 1" \\
    "id:1000331,\\
     phase:1,\\
     deny,\\
     status:403,\\
     log,\\
     msg:'nssec: blocked harvesting user agent',\\
     logdata:'%{REQUEST_HEADERS.User-Agent}',\\
     tag:'nssec',\\
     tag:'nssec-harvest-ua',\\
     severity:'CRITICAL'"

SecRule RESOURCE:ua_ban "@eq 1" \\
    "id:1000332,\\
     phase:1,\\
     deny,\\
     status:403,\\
     log,\\
     msg:'nssec: ns-api request denied, IP is banned for a harvesting user agent',\\
     tag:'nssec',\\
     tag:'nssec-abuse',\\
     tag:'nssec-harvest-ua',\\
     severity:'CRITICAL',\\
     chain"
    SecRule REQUEST_FILENAME "@beginsWith /ns-api/" "t:none"
{% endif %}
{% if toggles.device_walk or toggles.device_read_allowlist_only %}

# ---- Device walking (v1 and v2 API) ----
# Device records include SIP registration and provisioning passwords.  They
# are read with:
#   v1  GET/POST /ns-api/?object=device&action=read   (domain in domain=)
#   v2  GET /ns-api/v2/domains/{domain}/devices
#       GET /ns-api/v2/domains/{domain}/users/{user}/devices[/{device}]
#                                                     (domain in the path)
#       GET .../devices/count, .../devices/{device}/count and
#           /ns-api/v2/resellers/{reseller}/devices/count
# Counts are included: grabbing the count is the usual first step before
# pulling a domain's devices.
# A scraper walks tenant after tenant reading devices;
# legitimate users stay inside their own domain.  Per IP:
#   * more than {{ limits.max_domains }} distinct domains within {{ limits.domain_window }}s, or more than {{ limits.max_reads }}
#     device reads within {{ limits.read_window }}s: blocked for {{ limits.block_period }}s.  Tripping again within
#     {{ limits.repeat_window }}s of an earlier block: blocked for {{ limits.long_block_period }}s.
#   * more than {{ limits.slow_max_domains }} distinct domains within {{ limits.slow_window }}s (a slow walk that stays
#     under the short-window limit): blocked for {{ limits.long_block_period }}s.
# A read without a usable domain (no domain= on v1; "~" for the token's own
# domain or "*" for all domains on v2) counts as one extra domain, so it
# cannot be used to read outside the counted domains for free.
# A block only denies device reads.  Phase 2 so POSTed form bodies are
# inspected as well as query strings.
# Device reads are identified once here for both the allowlist-only rule and
# the walk limits.
SecRule REQUEST_FILENAME "@rx ^/ns-api/(?:index\\.php)?$" \\
    "id:1000340,\\
     phase:2,\\
     pass,\\
     nolog,\\
     t:none,\\
     tag:'nssec-abuse',\\
     chain"
    SecRule ARGS:object "@streq device" \\
        "t:none,t:lowercase,\\
         chain"
        SecRule ARGS:action "@streq read" \\
            "t:none,t:lowercase,\\
             setvar:tx.nssec_device_read=1{% if toggles.device_walk %},\\
             initcol:user=nssec_walk24_%{REMOTE_ADDR}{% endif %}"

SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" \\
    "id:1000339,\\
     phase:2,\\
     pass,\\
     nolog,\\
     t:none,\\
     tag:'nssec-abuse',\\
     chain"
    SecRule REQUEST_FILENAME "@rx ^/ns-api/v2/domains/([^/]+)/(?:users/[^/]+/)?devices(?:/[^/]+)?(?:/count)?/?$" \\
        "t:none,t:urlDecodeUni,t:lowercase,\\
         capture,\\
         setvar:tx.nssec_device_read=1,\\
         setvar:'tx.nssec_v2_domain=%{TX.1}'{% if toggles.device_walk %},\\
         initcol:user=nssec_walk24_%{REMOTE_ADDR}{% endif %}"

# Reseller-wide device count: no domain in the path, so it is recorded as a
# read without a usable domain.
SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" \\
    "id:1000335,\\
     phase:2,\\
     pass,\\
     nolog,\\
     t:none,\\
     tag:'nssec-abuse',\\
     chain"
    SecRule REQUEST_FILENAME "@rx ^/ns-api/v2/resellers/[^/]+/devices/count/?$" \\
        "t:none,t:urlDecodeUni,t:lowercase,\\
         setvar:tx.nssec_device_read=1,\\
         setvar:tx.nssec_v2_domain=*{% if toggles.device_walk %},\\
         initcol:user=nssec_walk24_%{REMOTE_ADDR}{% endif %}"

{% endif %}
{% if toggles.device_read_allowlist_only %}

# ---- Bulk device reads (v1 and v2 API): allowlisted sources only ----
# Enabled with 'nssec waf update-exclusions --device-read-allowlist-only'.
# A domain-wide device list is denied unless it comes from localhost, an
# allowlisted admin IP, a NodePing probe or an SBUS cluster peer (all of
# which remove tag nssec-abuse above).  Reads of one device or of one user's
# devices are allowed; they still count toward the walk limits.  Bulk means:
#   v1  object=device&action=read with no real user= or device= value
#       (empty or wildcard values do not count as scoping the read)
#   v2  GET /ns-api/v2/domains/{domain}/devices or .../users/*/devices
# Device counts are never bulk reads (they return numbers only), but like
# every device read they still count toward the walk limits.
SecRule TX:nssec_device_read "@eq 1" \\
    "id:1000336,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     chain"
    SecRule &TX:nssec_v2_domain "@eq 0" \\
        "chain"
        SecRule ARGS:user|ARGS:device "@rx ^[A-Za-z0-9._@+-]+$" \\
            "t:none,\\
             setvar:tx.nssec_device_scoped=1"

SecRule TX:nssec_device_read "@eq 1" \\
    "id:1000337,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     chain"
    SecRule &TX:nssec_v2_domain "@eq 0" \\
        "chain"
        SecRule &TX:nssec_device_scoped "@eq 0" \\
            "setvar:tx.nssec_device_bulk=1"

SecRule TX:nssec_device_read "@eq 1" \\
    "id:1000338,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     chain"
    SecRule REQUEST_FILENAME "@rx ^/ns-api/v2/domains/[^/]+/(?:users/\\*/)?devices/?$" \\
        "t:none,t:urlDecodeUni,t:lowercase,\\
         setvar:tx.nssec_device_bulk=1"

SecRule TX:nssec_device_bulk "@eq 1" \\
    "id:1000360,\\
     phase:2,\\
     deny,\\
     status:403,\\
     log,\\
     msg:'nssec: bulk device read denied, source IP is not allowlisted',\\
     logdata:'domain=%{ARGS.domain}%{TX.nssec_v2_domain}',\\
     tag:'nssec',\\
     tag:'nssec-abuse',\\
     severity:'CRITICAL'"
{% endif %}
{% if toggles.device_walk %}

# Snapshot whether the IP was already blocked, so reads made during a block
# are neither recorded nor counted as new offences.
SecRule TX:nssec_device_read "@eq 1" \\
    "id:1000341,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     chain"
    SecRule RESOURCE:walk_block "@eq 1" \\
        "setvar:tx.nssec_was_blocked=1"

SecRule TX:nssec_device_read "@eq 1" \\
    "id:1000342,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     chain"
    SecRule &TX:nssec_was_blocked "@eq 0" \\
        "chain"
        SecRule ARGS:domain|TX:nssec_v2_domain "@rx ^[a-z0-9][a-z0-9._-]{0,252}$" \\
            "t:none,t:lowercase,\\
             setvar:tx.nssec_domain_ok=1"

# Record the domain (as a hash) in both windows.
SecRule TX:nssec_domain_ok "@eq 1" \\
    "id:1000343,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     chain"
    SecRule ARGS:domain|TX:nssec_v2_domain "@rx ^([0-9a-f]{8})" \\
        "t:none,t:lowercase,t:sha1,t:hexEncode,\\
         capture,\\
         setvar:'resource.w_%{TX.1}=1',\\
         expirevar:'resource.w_%{TX.1}={{ limits.domain_window }}',\\
         setvar:'user.w_%{TX.1}=1',\\
         expirevar:'user.w_%{TX.1}={{ limits.slow_window }}'"

SecRule TX:nssec_device_read "@eq 1" \\
    "id:1000344,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     chain"
    SecRule &TX:nssec_was_blocked "@eq 0" \\
        "chain"
        SecRule &TX:nssec_domain_ok "@eq 0" \\
            "setvar:resource.w_none=1,\\
             expirevar:resource.w_none={{ limits.domain_window }},\\
             setvar:user.w_none=1,\\
             expirevar:user.w_none={{ limits.slow_window }}"

# Read counter: the fixed window starts on the first read only, so steady
# traffic cannot keep pushing the expiry out.
SecRule TX:nssec_device_read "@eq 1" \\
    "id:1000345,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     chain"
    SecRule &RESOURCE:device_reads "@eq 0" \\
        "setvar:resource.device_reads=0,\\
         expirevar:resource.device_reads={{ limits.read_window }}"

SecRule TX:nssec_device_read "@eq 1" \\
    "id:1000346,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     setvar:resource.device_reads=+1"

# ---- Offence detection (only for IPs not already blocked) ----
SecRule TX:nssec_device_read "@eq 1" \\
    "id:1000347,\\
     phase:2,\\
     pass,\\
     log,\\
     msg:'nssec: device walking across %{MATCHED_VAR} domains in {{ limits.domain_window }}s',\\
     logdata:'domain=%{ARGS.domain}%{TX.nssec_v2_domain}',\\
     tag:'nssec',\\
     tag:'nssec-abuse',\\
     severity:'CRITICAL',\\
     chain"
    SecRule &TX:nssec_was_blocked "@eq 0" \\
        "chain"
        SecRule &RESOURCE:/^w_/ "@gt {{ limits.max_domains }}" \\
            "setvar:tx.nssec_walk_trip=1"

SecRule TX:nssec_device_read "@eq 1" \\
    "id:1000348,\\
     phase:2,\\
     pass,\\
     log,\\
     msg:'nssec: device read rate exceeded (%{MATCHED_VAR} reads in {{ limits.read_window }}s)',\\
     tag:'nssec',\\
     tag:'nssec-abuse',\\
     severity:'CRITICAL',\\
     chain"
    SecRule &TX:nssec_was_blocked "@eq 0" \\
        "chain"
        SecRule RESOURCE:device_reads "@gt {{ limits.max_reads }}" \\
            "setvar:tx.nssec_walk_trip=1"

SecRule TX:nssec_device_read "@eq 1" \\
    "id:1000349,\\
     phase:2,\\
     pass,\\
     log,\\
     msg:'nssec: slow device walk across %{MATCHED_VAR} domains in {{ limits.slow_window }}s',\\
     logdata:'domain=%{ARGS.domain}%{TX.nssec_v2_domain}',\\
     tag:'nssec',\\
     tag:'nssec-abuse',\\
     severity:'CRITICAL',\\
     chain"
    SecRule &TX:nssec_was_blocked "@eq 0" \\
        "chain"
        SecRule &USER:/^w_/ "@gt {{ limits.slow_max_domains }}" \\
            "setvar:tx.nssec_slow_trip=1"

# ---- Block and escalation ----
SecRule TX:nssec_walk_trip "@eq 1" \\
    "id:1000350,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     setvar:resource.walk_strikes=+1,\\
     expirevar:resource.walk_strikes={{ limits.repeat_window }},\\
     setvar:resource.walk_block=1,\\
     expirevar:resource.walk_block={{ limits.block_period }}"

SecRule TX:nssec_walk_trip "@eq 1" \\
    "id:1000351,\\
     phase:2,\\
     pass,\\
     log,\\
     msg:'nssec: repeat device-walk offender (%{MATCHED_VAR} strikes), blocked for {{ limits.long_block_period }}s',\\
     tag:'nssec',\\
     tag:'nssec-abuse',\\
     severity:'CRITICAL',\\
     chain"
    SecRule RESOURCE:walk_strikes "@gt 1" \\
        "expirevar:resource.walk_block={{ limits.long_block_period }}"

SecRule TX:nssec_slow_trip "@eq 1" \\
    "id:1000352,\\
     phase:2,\\
     pass,\\
     nolog,\\
     tag:'nssec-abuse',\\
     setvar:resource.walk_strikes=+1,\\
     expirevar:resource.walk_strikes={{ limits.repeat_window }},\\
     setvar:resource.walk_block=1,\\
     expirevar:resource.walk_block={{ limits.long_block_period }}"

SecRule TX:nssec_device_read "@eq 1" \\
    "id:1000353,\\
     phase:2,\\
     deny,\\
     status:403,\\
     log,\\
     msg:'nssec: device read denied, IP is blocked for device walking',\\
     tag:'nssec',\\
     tag:'nssec-abuse',\\
     severity:'CRITICAL',\\
     chain"
    SecRule RESOURCE:walk_block "@eq 1" "t:none"
{% endif %}
{% if toggles.token_audit %}

# ---- Token endpoint audit logging (verbose mode) ----
# Enabled with 'nssec waf update-exclusions --token-audit'.  Writes every
# token request to the audit log regardless of status.
# Credential values (password, client_secret, tokens) are masked by the
# sanitiseArg rule (1000015) in form and JSON bodies alike; usernames and
# every other field are logged as sent.
SecRule REQUEST_URI "@rx ^/ns-api/(?:oauth2/token|v2/tokens)" \\
    "id:1000400,\\
     phase:1,\\
     pass,\\
     nolog,\\
     ctl:auditEngine=On"

# One summary line per token request, written after the response so the
# status separates successful logins from failed ones.  The fields come from
# ModSecurity's parsed ARGS, so they read the same whether the client sent
# them in the query string or in a urlencoded, multipart or JSON body -- the
# raw bodies spell them differently (name="grant_type", grant%5ftype=,
# "grant_type":...), which makes the audit entries hard to search.  Lands in
# the Apache error log and in part H of the audit entry; ip= and txid= are in
# the line itself so it stands alone when the audit log is shipped line by
# line (txid is the audit entry's id).  Portal logins reach ns-api from
# 127.0.0.1 with the browser's address in X-NetSapiens-Remote-Addr, logged as
# fwd= (trust it only when ip= is 127.0.0.1; any client can send the header).
# Refresh-token grants carry no username.  Search for: nssec: token request
#
# Matches on REQUEST_URI, not REQUEST_FILENAME: /ns-api/ is served by PHP,
# and REQUEST_FILENAME reflects the path after Apache's rewrite (which is
# the script, not the request), so the pattern never matched there and the
# rule silently never fired.  1000400 above matches on REQUEST_URI for the
# same reason -- keep the two in step.
SecRule REQUEST_URI "@rx ^/ns-api/(?:oauth2/token|v2/tokens)" \\
    "id:1000401,\\
     phase:5,\\
     pass,\\
     log,\\
     msg:'nssec: token request',\\
     logdata:'status=%{RESPONSE_STATUS} ip=%{REMOTE_ADDR} fwd=%{REQUEST_HEADERS.X-NetSapiens-Remote-Addr} grant_type=%{ARGS.grant_type} username=%{ARGS.username} client_id=%{ARGS.client_id} txid=%{UNIQUE_ID}',\\
     tag:'nssec',\\
     tag:'nssec-token-audit',\\
     severity:'NOTICE'"
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
{%- if cluster_peers %}
        {{ restrict_cluster_begin }}
{%- for ip, host in cluster_peers %}
        # {{ host }}
        Require ip {{ ip }}
{%- endfor %}
        {{ restrict_cluster_end }}
{%- endif %}
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
{%- if cluster_peers %}

    # ---- Cluster peers (SBUS manifest: {{ cluster_manifest_url }}, {{ cluster_host_count }} hosts, {{ cluster_discovered_at }}) ----
    # Cluster members deliver SBUS events to each other over public IPs; a
    # burst of events must not be mistaken for a flood (SBUS retries denied
    # deliveries, so a block keeps itself going).  Manage with:
    # nssec waf cluster show|refresh
{%- for ip, host in cluster_ipv4 %}
    # {{ host }}
    DOSWhitelist            {{ ip }}
{%- endfor %}
{%- if cluster_ipv6 %}
    # Not listed: {{ cluster_ipv6 | length }} IPv6 peer address(es) - DOSWhitelist is IPv4-only.
{%- endif %}
    {{ cluster_block_end }}
{%- endif %}
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
