# External Scripts

Third-party tools referenced by ns-security. These are maintained by their
respective owners and cloned here for convenience -- we do not modify or
redistribute them.

## mTLSProtect

**Repo:** https://github.com/OITApps/mTLSProtect
**Maintainer:** OIT, LLC

Mutual TLS protection for VoIP phone provisioning on NDP servers. Validates
device certificates during config downloads so only legitimate phones with
matching MAC addresses can pull their configuration files.

Thank you to OIT for building and maintaining the mTLS certificate bundles and
Apache configuration that the NetSapiens community depends on.

### Supported Devices

| Vendor      | mTLS Level                          |
|-------------|-------------------------------------|
| Poly        | Full mTLS with CN (MAC) validation  |
| Yealink     | Full mTLS with CN validation        |
| Grandstream | Gen 1 and Gen 2 device certificates |
| Panasonic   | Certificate validation (no CN match)|
| Algo        | Client cert optional (newer units)  |

### Quick Setup (NDP servers only)

```bash
# 1. Clone into this directory
cd /path/to/ns-security/scripts/external
git clone https://github.com/OITApps/mTLSProtect.git

# 2. Extract device CA certificates
#    The tarball contains a device_ca/ directory, so use --strip-components
#    to extract directly into the target path
sudo mkdir -p /etc/ssl/certs/device_ca
sudo tar -xvf /path/to/mTLSProtect/device_ca.tgz --strip-components=1 -C /etc/ssl/certs/device_ca
sudo c_rehash .

# 3. Download Poly certificates (optional, for latest certs)
sudo /path/to/mTLSProtect/polycerts.sh

# 4. Install Apache config
sudo cp /path/to/mTLSProtect/ndp_mtls.conf /etc/apache2/conf.d/

# 5. Edit the config -- replace placeholder IPs with your allowed subnets
sudo vi /etc/apache2/conf.d/ndp_mtls.conf
#    Find: Require ip xxx.xxx.xxx.xxx/x
#    Replace with your network CIDR(s)

# 6. Test and reload Apache
sudo apache2ctl configtest
sudo systemctl reload apache2
```

### Grandstream Notes

Grandstream Gen 1 devices require lowering the SSL security level. In
`/etc/apache2/mods-enabled/ssl.conf`, change:

```
SSLCipherSuite DEFAULT@SECLEVEL=0:!aNULL
SSLProtocol all -SSLv3
```

The Gen 1 certificate expires June 11, 2027. See the mTLSProtect README for
details on migrating devices to Gen 2 certificates.

### Verifying

```bash
# Check that device CAs are loaded (echo closes the connection cleanly)
echo | openssl s_client -connect localhost:443 2>/dev/null | grep -A99 "Acceptable client certificate CA names"
```

### Troubleshooting

- **403 on phone provisioning** - Check that your NDP's IP is in the allowed
  subnets in `ndp_mtls.conf` (the `Require ip` lines). Localhost (127.0.0.1)
  and the NetSapiens IP are included by default.
- **apache2ctl configtest fails** - Verify `mod_ssl` is enabled and
  `/etc/ssl/certs/device_ca/` contains `.pem` files. Run `c_rehash` again
  if certs were added manually.
- **Phones not sending client certs** - Ensure the NDP is using HTTPS for
  provisioning. Phones on HTTP will never present a client certificate.
- **Grandstream cert errors** - Older devices may need the Gen 1 SSL
  security level adjustment described above.
