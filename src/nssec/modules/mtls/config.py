"""mTLS module configuration constants."""

# NodePing IP list URL
NODEPING_URL = "https://nodeping.com/content/txt/pinghosts.txt"

# Target configuration file
NDP_MTLS_CONF = "/etc/apache2/conf.d/ndp_mtls.conf"

# Backup suffix (consistent with WAF module)
BACKUP_SUFFIX = ".bak.nssec"

# Marker comments for managed section
NODEPING_BEGIN_MARKER = "# BEGIN nssec-managed NodePing IPs (do not edit)"
NODEPING_END_MARKER = "# END nssec-managed NodePing IPs"
