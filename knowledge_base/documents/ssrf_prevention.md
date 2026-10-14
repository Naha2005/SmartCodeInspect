# OWASP Server-Side Request Forgery (SSRF) Prevention Cheat Sheet

Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
Retrieved: 2026-10-12
Author: OWASP Cheat Sheet Series Team
Topic: Server-Side Request Forgery (SSRF)

## Introduction
Server-Side Request Forgery (SSRF) occurs when a web application fetches a remote resource without validating the user-supplied URL. An attacker can coerce the application to send crafted requests to unexpected destinations, typically bypassing network firewalls to target internal cloud metadata services, loopback interfaces, or intranets.

## Attack Scenarios
1. **Cloud Metadata Exploitation:** An attacker submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/` to harvest cloud infrastructure keys.
2. **Internal Port Scanning & Service Pivoting:** Probing internal services running on `http://127.0.0.1:8080`, `http://localhost:6379` (Redis), or internal microservices that assume trusted intranet boundaries.
3. **Protocol Smuggling:** Supplying schemes like `file:///etc/passwd`, `gopher://`, or `dict://` where HTTP libraries allow alternate URL schemes.

## Prevention & Defense Strategies

### 1. Enforce Strict Allow-lists for Domains and Schemes
Only permit explicitly approved domain names and HTTP/HTTPS schemes. Never accept raw arbitrary user URLs directly.

### 2. Validate IP Addresses and Block Private CIDR Blocks
Before making an outbound request, resolve the domain to its IPv4/IPv6 address and verify it does not fall into private, loopback, or link-local ranges:
- `127.0.0.0/8` (Loopback)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (Private networks RFC 1918)
- `169.254.0.0/16` (Link-local / Cloud metadata)
- `::1`, `fc00::/7`, `fe80::/10` (IPv6 Private / Link-local)

### Secure Python Validation Pattern
```python
import ipaddress
import socket
from urllib.parse import urlparse

def is_safe_external_url(url: str, allowed_schemes={"https"}) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in allowed_schemes:
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    try:
        # Resolve all addresses
        addr_info = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addr_info:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        return True
    except (socket.gaierror, ValueError):
        return False
```

## Remediation Checklist
- Disable HTTP redirects or re-validate redirect target URLs prior to following them.
- Restrict outbound egress traffic at the firewall or network security group layer.
