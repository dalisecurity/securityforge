# WordPress Security Testing Payloads

Payloads for testing WAF protection of WordPress installations. These cover three common WordPress attack surfaces: REST API abuse, file upload bypass, and XML-RPC exploitation.

> **Note**: These are generic WordPress security testing patterns, not tied to any specific CVE. They are useful for validating that your WAF blocks common WordPress attack vectors.

## Files

| File | Category | Description |
|------|----------|-------------|
| `rest-api-auth.txt` | REST API | User enumeration, auth bypass, privilege escalation via wp-json |
| `file-upload-bypass.txt` | File Upload | Plugin upload bypass, double extensions, null bytes, web shells |
| `xmlrpc-abuse.txt` | XML-RPC | Pingback amplification, multicall brute force, XXE |

## Usage

```bash
# Test all WordPress payloads
securityforge test https://your-wordpress-site.com -c wordpress

# Or test a specific file
securityforge test https://your-wordpress-site.com -p securityforge/payloads/wordpress/rest-api-auth.txt
```

## Mitigation

**REST API**: Disable for unauthenticated users or restrict with WAF rules on `/wp-json/` endpoints.

**File Upload**: Use `define('DISALLOW_FILE_MODS', true);` in production. Validate extensions and MIME types.

**XML-RPC**: Disable entirely with `add_filter('xmlrpc_enabled', '__return_false');` or block at web server level.

## References

- [WordPress REST API Handbook](https://developer.wordpress.org/rest-api/)
- [OWASP WordPress Security](https://owasp.org/www-project-wordpress-security/)

**Only test systems you own or have explicit permission to test.**
