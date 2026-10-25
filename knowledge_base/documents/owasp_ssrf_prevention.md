# OWASP Server-Side Request Forgery (SSRF) Prevention Cheat Sheet (2026 Edition)

Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
Retrieved: 2026-10-25
Author: OWASP Cheat Sheet Series Global Security Committee
Status: Active Standard (2026 Revision)
Classification: CWE-918 (Server-Side Request Forgery), OWASP Top 10 A10:2025 / A10:2026

---

## 1. Executive Summary & Threat Architecture
Server-Side Request Forgery (SSRF) is a structural security vulnerability that occurs when a web application or backend service fetches a remote network resource (via HTTP/HTTPS, WebSockets, or raw TCP sockets) using a user-controllable URL or network locator without rigorous validation of the destination scheme, target hostname, resolved IP address, and subsequent network redirection hops.

In modern cloud environments, microservice meshes, and containerized architectures, SSRF allows adversaries to abuse the server as an internal proxy. Because the outgoing request originates from the trusted server identity, it bypasses perimeter firewalls, NAT boundaries, and internal access control lists (ACLs).

### Primary Impact Vectors:
1. **Cloud Infrastructure Compromise**: Accessing cloud instance metadata services (IMDS) on AWS, Azure, Google Cloud, and Alibaba Cloud to harvest temporary IAM security credentials, OAuth tokens, and virtual machine bootstrap configuration scripts.
2. **Internal Network Reconnaissance & Port Scanning**: Mapping internal network topologies, identifying active hosts, probing non-routable microservices, and locating unauthenticated administrative interfaces (e.g., Kubernetes API, Consul, etcd, Redis, Memcached).
3. **Internal Remote Code Execution (RCE)**: Interacting with internal unauthenticated RPC interfaces, management consoles, or databases (such as Redis `CONFIG SET` or fastcgi/gopher payloads) to execute unauthorized commands.
4. **Data Exfiltration**: Reading internal document repositories, Elasticsearch clusters, or object storage buckets that trust requests originating from internal IP subnets.

---

## 2. SSRF Attack Taxonomy & Exploitation Techniques

### 2.1 Cloud Instance Metadata Exploitation (IMDS)
Cloud providers configure hypervisor link-local IP addresses (`169.254.169.254` or `fd00:ec2::254`) accessible to instances to supply metadata:
- **AWS IMDSv1**: `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` yields full access keys and session tokens.
- **AWS IMDSv2**: Requires a `PUT` request with `X-aws-ec2-metadata-token-ttl-seconds` to acquire a session token; however, SSRF vectors allowing arbitrary headers or HTTP methods may still compromise IMDSv2.
- **Google Cloud Platform (GCP)**: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` with header `Metadata-Flavor: Google`.
- **Azure Instance Metadata Service**: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with header `Metadata: true`.
- **DigitalOcean & Oracle Cloud**: Similar link-local metadata endpoints exposing sensitive droplet/instance initialization data.

### 2.2 DNS Rebinding Attacks (TOCTOU)
DNS Rebinding exploits the time difference between domain name validation and actual socket connection:
1. The application receives a domain name (e.g., `attacker-domain.com`).
2. The application validates the domain by calling `gethostbyname()` or `socket.getaddrinfo()`. The attacker's authoritative nameserver responds with a legitimate public IP address (e.g., `93.184.216.34`), passing the IP whitelist/blacklist check.
3. The application initiates the actual HTTP request using an HTTP client library (`requests.get()` or `HttpClient.send()`).
4. The client library resolves the domain again because the DNS TTL was set to 0 seconds.
5. The attacker's nameserver now returns an internal private IP (e.g., `169.254.169.254` or `127.0.0.1`), causing the request to strike the internal target.

### 2.3 Obfuscated and Alternative IP Formats
Attackers bypass naive string-matching filters (such as checking `url.startswith("http://127.0.0.1")`) using valid alternative IP representations:
- **Dotted Decimal with Leading Zeroes (Octal)**: `http://0177.0.0.1/` (evaluates to `127.0.0.1`).
- **Integer (Decimal) Notation**: `http://2130706433/` (`127.0.0.1`) or `http://2852039166/` (`169.254.169.254`).
- **Hexadecimal Notation**: `http://0x7f000001/` (`127.0.0.1`) or `http://0xa9fea9fe/` (`169.254.169.254`).
- **Mixed Formats**: `http://127.1/` or `http://0x7f.1`.
- **IPv6 Mapped IPv4**: `http://[::ffff:127.0.0.1]/` or `http://[0:0:0:0:0:ffff:a9fe:a9fe]/`.
- **Localhost Encodings**: `http://localhost/`, `http://127.0.0.1.nip.io`, `http://spoofed.localtest.me`.

### 2.4 Scheme and Protocol Smuggling
When HTTP client libraries accept non-HTTP schemes or fail to enforce strict protocol parsing:
- `file:///etc/passwd` (Local file inclusion via URL parsing library).
- `gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a` (Arbitrary multi-line TCP payload injection into internal services).
- `dict://127.0.0.1:11211/stat` (Memcached manipulation).
- `ldap://` or `jar://` protocols.

### 2.5 HTTP Redirection Chaining
An attacker supplies a public URL on a domain they control (e.g., `https://attacker.com/redirect`). When the server requests this URL, the attacker's server responds with an HTTP 301, 302, or 307 redirect pointing to `http://169.254.169.254/latest/meta-data/`. If the application HTTP client follows redirects automatically without re-evaluating the destination IP, SSRF succeeds.

---

## 3. Defense-in-Depth Mitigation Framework

```
[ User-Supplied Webhook / URL ]
               │
               ▼
┌────────────────────────────────────────────────────────┐
│ 1. Scheme Validation                                   │ -> Permit only 'https' (or 'http' if required)
└────────────────────────────────────────────────────────┘
               │
               ▼
┌────────────────────────────────────────────────────────┐
│ 2. Domain / Host Allowlist                             │ -> Strict exact matches or verified regex
└────────────────────────────────────────────────────────┘
               │
               ▼
┌────────────────────────────────────────────────────────┐
│ 3. Safe DNS Resolution & IP Block Verification         │ -> Discard loopback, private RFC 1918,
│    (Inspect all A and AAAA records)                    │    link-local, cloud metadata, multicast
└────────────────────────────────────────────────────────┘
               │
               ▼
┌────────────────────────────────────────────────────────┐
│ 4. IP-Pinned Socket Connection (Anti-DNS Rebinding)    │ -> Connect strictly to verified IP address,
│                                                        │    passing original Host header
└────────────────────────────────────────────────────────┘
               │
               ▼
┌────────────────────────────────────────────────────────┐
│ 5. Redirect Guard & Response Size Caps                 │ -> Re-validate all 3xx redirect locations;
│                                                        │    limit max response bytes & timeout
└────────────────────────────────────────────────────────┘
               │
               ▼
┌────────────────────────────────────────────────────────┐
│ 6. Network Layer Isolation (Egress Firewall / IMDSv2)  │ -> Block egress to 169.254.0.0/16, VPC ACLs
└────────────────────────────────────────────────────────┘
```

### Prohibited IP Subnets (IPv4 and IPv6):
Before establishing any outbound connection, applications must verify that resolved IP addresses do not intersect with:
- `0.0.0.0/8` (Current network)
- `10.0.0.0/8` (Private network RFC 1918)
- `100.64.0.0/10` (Shared Address Space / CGNAT RFC 6598)
- `127.0.0.0/8` (Loopback addresses)
- `169.254.0.0/16` (Link-Local / Cloud Instance Metadata)
- `172.16.0.0/12` (Private network RFC 1918)
- `192.0.0.0/24` (IETF Protocol Assignments)
- `192.0.2.0/24` (TEST-NET-1 documentation)
- `192.168.0.0/16` (Private network RFC 1918)
- `198.18.0.0/15` (Network benchmark testing)
- `198.51.100.0/24` (TEST-NET-2 documentation)
- `203.0.113.0/24` (TEST-NET-3 documentation)
- `224.0.0.0/4` (Multicast addresses RFC 5771)
- `240.0.0.0/4` (Reserved for future use RFC 1112)
- `255.255.255.255/32` (Limited Broadcast)
- `::1/128` (IPv6 Loopback)
- `::/128` (IPv6 Unspecified)
- `fc00::/7` (IPv6 Unique Local Addresses)
- `fe80::/10` (IPv6 Link-Local Unicast)
- `ff00::/8` (IPv6 Multicast)

---

## 4. Vulnerable vs. Secure Implementations in Python

### 4.1 Vulnerable Python Patterns

```python
# ==============================================================================
# VULNERABLE PYTHON PATTERNS -- DO NOT USE IN PRODUCTION
# ==============================================================================
import requests
import urllib.request
from flask import Flask, request

app = Flask(__name__)

@app.route("/fetch_avatar_bad")
def fetch_avatar():
    url = request.args.get("url")
    # Flaw 1: Direct requests.get allows attacker to target http://169.254.169.254
    # Flaw 2: Automatic redirect following (requests follows up to 30 redirects)
    resp = requests.get(url, timeout=5)
    return resp.content

@app.route("/webhook_bad")
def trigger_webhook():
    webhook_url = request.args.get("webhook")
    # Flaw 3: urllib.request.urlopen supports file:// and other schemes
    response = urllib.request.urlopen(webhook_url)
    return response.read()
```

### 4.2 Secure Enterprise Python Implementation (Anti-Rebinding & IP Pinning)

```python
"""
Enterprise SSRF-Resistant HTTP Client Service (Python 3.11+)
Compliant with OWASP SSRF Prevention Cheat Sheet (2026 Edition).
Protects against DNS rebinding, IPv4/IPv6 obfuscation, and redirect attacks.
"""

import ipaddress
import socket
from urllib.parse import urlparse, urljoin
from typing import Set, Tuple, Optional
import httpx

# List of prohibited IPv4 and IPv6 networks
PROHIBITED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 networks
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

ALLOWED_SCHEMES: Set[str] = {"https", "http"}
MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB maximum


def is_ip_prohibited(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Verifies whether an IP address is internal, loopback, private, or link-local."""
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return True
    return any(ip in network for network in PROHIBITED_NETWORKS)


def resolve_and_validate_hostname(hostname: str, port: int) -> Tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """
    Performs safe DNS resolution and validates that all returned A/AAAA records
    are strictly publicly routable addresses.
    """
    try:
        addr_info = socket.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for hostname '{hostname}': {e}")

    if not addr_info:
        raise ValueError(f"No DNS records found for hostname '{hostname}'")

    verified_ip = None
    for family, _, _, _, sockaddr in addr_info:
        ip_str = sockaddr[0]
        ip_obj = ipaddress.ip_address(ip_str)
        if is_ip_prohibited(ip_obj):
            raise PermissionError(f"Access to prohibited address '{ip_str}' is denied")
        if verified_ip is None:
            verified_ip = ip_obj

    return hostname, verified_ip


class SafeHttpClient:
    """
    HTTP Client with built-in SSRF defense, IP pinning, and manual redirect validation.
    """
    def __init__(self, timeout_seconds: float = 8.0):
        self._timeout = timeout_seconds

    def fetch_url(self, raw_url: str) -> bytes:
        current_url = raw_url

        for redirect_hop in range(MAX_REDIRECTS + 1):
            parsed = urlparse(current_url)

            if parsed.scheme.lower() not in ALLOWED_SCHEMES:
                raise ValueError(f"Prohibited URL scheme '{parsed.scheme}'. Only HTTPS and HTTP allowed.")

            hostname = parsed.hostname
            if not hostname:
                raise ValueError("URL does not specify a valid hostname")

            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

            # Resolve DNS and verify all records against prohibited subnets
            _, target_ip = resolve_and_validate_hostname(hostname, port)

            # Perform HTTP request without automatic redirects
            with httpx.Client(timeout=self._timeout, follow_redirects=False) as client:
                # Set Host header explicitly for virtual hosting
                headers = {"Host": hostname}
                # Connect directly to the validated IP to defeat DNS rebinding attacks
                ip_formatted = f"[{target_ip}]" if target_ip.version == 6 else str(target_ip)
                pinned_url = f"{parsed.scheme}://{ip_formatted}:{port}{parsed.path or '/'}"
                if parsed.query:
                    pinned_url += f"?{parsed.query}"

                response = client.get(pinned_url, headers=headers)

                # Check for redirects
                if response.status_code in (301, 302, 303, 307, 308):
                    redirect_location = response.headers.get("Location")
                    if not redirect_location:
                        raise ValueError("Received redirect status with no Location header")
                    current_url = urljoin(current_url, redirect_location)
                    continue

                if response.status_code != 200:
                    raise RuntimeError(f"Server responded with non-200 HTTP code: {response.status_code}")

                # Enforce response payload size ceiling
                content = response.content
                if len(content) > MAX_RESPONSE_BYTES:
                    raise ValueError("Response payload exceeds maximum allowed size")

                return content

        raise RuntimeError(f"Exceeded maximum permitted redirects ({MAX_REDIRECTS})")
```

---

## 5. Vulnerable vs. Secure Implementations in Java

### 5.1 Vulnerable Java Patterns

```java
// ==============================================================================
// VULNERABLE JAVA PATTERNS -- DO NOT USE IN PRODUCTION
// ==============================================================================
import java.io.InputStream;
import java.net.URL;
import java.net.HttpURLConnection;

public class VulnerableUrlFetcher {
    public byte[] fetchUrl(String userInputUrl) throws Exception {
        // Flaw 1: URL accepts file://, gopher://, and connects to internal 169.254.169.254
        URL url = new URL(userInputUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        // Flaw 2: Automatic redirect following blindly trusts 302 responses to private IPs
        conn.setInstanceFollowRedirects(true);
        try (InputStream is = conn.getInputStream()) {
            return is.readAllBytes();
        }
    }
}
```

### 5.2 Secure Enterprise Java Implementation (Java 17/21+)

```java
package com.enterprise.security.ssrf;

import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * Enterprise SSRF-Resistant HTTP Client Service (Java 17/21+)
 * Compliant with OWASP SSRF Prevention Standards (2026 Edition).
 */
public final class SecureSsrfHttpClient {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("https", "http");
    private static final Duration TIMEOUT = Duration.ofSeconds(8);
    private static final int MAX_RESPONSE_SIZE = 5 * 1024 * 1024; // 5 MB

    private final HttpClient httpClient;

    public SecureSsrfHttpClient() {
        // Build client with redirects explicitly DISABLED to prevent redirect bypasses
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(TIMEOUT)
                .build();
    }

    /**
     * Checks if an IP address belongs to loopback, private, link-local, or multicast subnets.
     */
    public static boolean isProhibitedIp(InetAddress address) {
        if (address.isLoopbackAddress() || address.isSiteLocalAddress() || 
            address.isLinkLocalAddress() || address.isMulticastAddress() ||
            address.isAnyLocalAddress()) {
            return true;
        }

        byte[] bytes = address.getAddress();

        // Check IPv4 link-local range: 169.254.0.0/16 (AWS/Azure/GCP metadata)
        if (bytes.length == 4) {
            int b0 = bytes[0] & 0xFF;
            int b1 = bytes[1] & 0xFF;
            if (b0 == 169 && b1 == 254) return true; // Metadata
            if (b0 == 100 && (b1 >= 64 && b1 <= 127)) return true; // CGNAT
            if (b0 == 0) return true; // Current network
        }

        return false;
    }

    /**
     * Validates URL scheme and resolves all DNS records to ensure no internal IPs are targeted.
     */
    public void validateUrl(URI uri) throws SecurityException, UnknownHostException {
        String scheme = uri.getScheme();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase())) {
            throw new SecurityException("Prohibited URI scheme: " + scheme);
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new SecurityException("URI host cannot be empty");
        }

        // Resolve all IP addresses (A and AAAA records)
        InetAddress[] addresses = InetAddress.getAllByName(host);
        if (addresses.length == 0) {
            throw new SecurityException("Could not resolve host: " + host);
        }

        for (InetAddress addr : addresses) {
            if (isProhibitedIp(addr)) {
                throw new SecurityException("Target host resolves to prohibited IP address: " + addr.getHostAddress());
            }
        }
    }

    /**
     * Performs validated HTTP request with strict payload size caps.
     */
    public byte[] fetchRemoteResource(String rawUrl) throws IOException, InterruptedException {
        URI targetUri = URI.create(rawUrl);
        validateUrl(targetUri);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(targetUri)
                .timeout(TIMEOUT)
                .header("User-Agent", "EnterpriseSecureCrawler/2026")
                .GET()
                .build();

        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());

        // Handle redirect status manually if needed
        int status = response.statusCode();
        if (status >= 300 && status < 400) {
            throw new SecurityException("Unpermitted redirect detected from target server");
        }

        if (status != 200) {
            throw new IOException("Remote server returned non-200 status code: " + status);
        }

        byte[] body = response.body();
        if (body.length > MAX_RESPONSE_SIZE) {
            throw new SecurityException("Remote response size exceeds allowable limit");
        }

        return body;
    }
}
```

---

## 6. Static Code Analysis (SAST) Detection Rules

| Engine Rule ID | Language | Severity | Trigger Condition / Heuristic |
|---|---|---|---|
| `SSRF-PY-001` | Python | High | `requests.get()`, `urllib.request.urlopen()`, `httpx.get()` with dynamic arguments and no IP verification |
| `SSRF-PY-002` | Python | Medium | HTTP request call with `follow_redirects=True` or `allow_redirects=True` on dynamic user input |
| `SSRF-JV-001` | Java | High | `new URL(dynamicUrl).openConnection()` or `HttpClient.send()` without prior `InetAddress` check |
| `SSRF-JV-002` | Java | Medium | `HttpClient.newBuilder().followRedirects(Redirect.ALWAYS)` used with untrusted external URLs |

---

## 7. OWASP 2026 SSRF Verification Checklist

- [ ] **Strict Scheme Whitelisting**: Does the application only permit `https://` (and explicitly reject `file://`, `gopher://`, `dict://`, `ftp://`)?
- [ ] **Pre-Flight DNS Resolution**: Does the resolver evaluate all returned IPv4 and IPv6 addresses against private and link-local ranges?
- [ ] **Cloud Metadata Protection**: Is egress traffic to `169.254.169.254` blocked by host-level firewall rules (iptables / Windows Firewall) or cloud VPC security groups?
- [ ] **IMDSv2 Enforcement**: Are cloud instances configured to require IMDSv2 (`http-tokens=required`) with a maximum hop limit of 1?
- [ ] **Anti-DNS Rebinding**: Is the connection pinned to the validated IP, or is DNS caching strictly enforced to prevent TOCTOU race conditions?
- [ ] **Redirect Controls**: Are automatic HTTP redirects disabled or re-evaluated through the full validation pipeline before each follow hop?
- [ ] **Response Limits**: Are response size caps (e.g., 5 MB) and strict timeouts (e.g., 5-10s) enforced to prevent memory exhaustion and hanging workers?
