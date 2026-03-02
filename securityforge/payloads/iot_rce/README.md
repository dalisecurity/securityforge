# IoT Remote Code Execution Payloads

Payloads for testing WAF/IDS detection of IoT and robotics exploitation patterns. These target real-world vulnerabilities in connected devices.

## CVE Coverage

| CVE | Product | Attack Vector | Payloads | CVSS |
|-----|---------|--------------|----------|------|
| CVE-2026-27509 | Unitree Go2 Robot | Unauthenticated DDS protocol injection | 25 | 8.5 (High) |
| CVE-2026-27510 | Unitree Go2 Robot | Mobile SQLite DB tampering → root RCE | 20 | 8.5 (High) |

## Files

| File | Description |
|------|-------------|
| `CVE-2026-27509-dds-rce.json` | DDS (Data Distribution Service) protocol payloads — unauthenticated code injection via CycloneDDS |
| `CVE-2026-27510-mobile-db-rce.json` | Mobile app SQLite database tampering + community marketplace poisoning |

## Why These Matter for WAF Testing

These CVEs demonstrate attack patterns increasingly relevant to network security:

- **Protocol-level injection**: DDS is used in autonomous vehicles, drones, and industrial robotics. WAFs and IDS systems need to detect malicious code in non-HTTP protocols.
- **Supply chain poisoning**: The marketplace vector mirrors npm/PyPI supply chain attacks — trojanized packages with hidden backdoors.
- **IoT lateral movement**: Compromised robots on a network become pivot points for attacking other devices.

## Usage

```bash
securityforge test <target> -c iot_rce
```

## References

- [NVD: CVE-2026-27509](https://nvd.nist.gov/vuln/detail/CVE-2026-27509)
- [NVD: CVE-2026-27510](https://nvd.nist.gov/vuln/detail/CVE-2026-27510)
- [Boschko: From DDS Packets to Robot Shells](https://boschko.ca/unitree-go2-rce/)
- [VulnCheck Advisory: DDS Auth](https://www.vulncheck.com/advisories/unitree-go2-missing-dds-authentication-enables-adjacent-rce)
- [VulnCheck Advisory: Mobile Tampering](https://www.vulncheck.com/advisories/unitree-go2-mobile-program-tampering-enables-root-rce)

**Only test systems you own or have explicit permission to test.**
