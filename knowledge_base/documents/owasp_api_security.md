# OWASP API Security Best Practices & Defense Cheat Sheet (2026 Edition)

Source: https://owasp.org/www-project-api-security/
Retrieved: 2026-10-25
Author: OWASP API Security Project Global Committee
Status: Active Standard (2026 Revision)
Classification: OWASP API Security Top 10 (2026), CWE-284, CWE-285, CWE-639, CWE-918

---

## 1. Executive Summary & Modern API Threat Landscape
Application Programming Interfaces (APIs)—spanning RESTful HTTP, GraphQL, gRPC, and WebSockets—form the communication backbone of modern cloud-native architectures, single-page applications (SPAs), mobile clients, and partner integrations. 

Because APIs directly expose underlying business logic, database structures, internal microservices, and serialized object state to client applications, they bypass traditional presentation-tier security controls. Attackers systematically target API endpoints to bypass business logic, perform unauthorized mass data exfiltration, abuse business workflows, and manipulate object properties.

Securing modern APIs requires architectural discipline across all tiers: strict object-level authorization, defensive schema serialization, resilient token authentication, granular rate limiting, and continuous API inventory hygiene.

---

## 2. OWASP API Security Top 10 (2026 Standard)

| Vulnerability Category | Description & Attack Mechanics | Common Impact |
|---|---|---|
| **API1: Broken Object Level Authorization (BOLA / IDOR)** | Endpoints consume entity identifiers (e.g., `/api/orders/{id}`) without verifying that the authenticated user possesses permission to read or modify that specific entity. | Mass unauthorized data leakage, lateral account takeover, sensitive document exfiltration. |
| **API2: Broken Authentication** | Compromised authentication mechanisms, missing rate limiting on login/credential endpoints, acceptance of unsigned or weakly signed JWTs (`alg: "none"`), or lack of brute-force lockouts. | Credential stuffing, account compromise, session hijacking. |
| **API3: Broken Object Property Level Authorization (Mass Assignment & Excessive Data Exposure)** | Binding raw incoming client JSON payloads directly to internal database entity classes, or serializing entire database entities into JSON responses without property masking. | Privilege escalation (`is_admin: true`), sensitive field modification, credit balance manipulation, PII leakage. |
| **API4: Unrestricted Resource Consumption** | Omission of API rate limits, lack of paging caps (`limit`, `offset`, `page_size`), or unbounded payload processing allowing resource starvation. | API Denial of Service (DoS), database CPU exhaustion, excessive cloud billing costs. |
| **API5: Broken Function Level Authorization (BFLA)** | Failure to enforce role-based access control (RBAC) on administrative endpoints (e.g., standard users accessing `/api/v1/admin/users/export`). | Unauthorized system configuration alterations, administrative privilege escalation. |
| **API6: Unrestricted Access to Sensitive Business Flows** | Legitimate API endpoints abused by automated bots without human-like interaction velocity caps (e.g., automated ticket scalping, high-velocity bulk inventory reservations). | Financial loss, artificial inventory scarcity, automated abuse. |
| **API7: Server-Side Request Forgery (SSRF)** | API features accepting remote URLs (e.g., webhook notifications, document import URLs) without validating destination IP addresses against internal metadata services. | Cloud IAM credential theft, intranet service manipulation. |
| **API8: Security Misconfiguration** | Overly permissive Cross-Origin Resource Sharing (CORS) headers (`*` with credentials), debug/swagger documentation exposed in production, unhandled verbose stack traces. | Cross-origin token theft, architectural reconnaissance. |
| **API9: Improper Inventory Management** | Shadow APIs, zombie APIs (unsupported, outdated v1 endpoints lingering without patches), unversioned legacy routes, and lack of API contract governance. | Exploitation of unpatched legacy vulnerabilities. |
| **API10: Unsafe Consumption of APIs** | Trusting data received from third-party APIs or microservices without thorough validation, sanitization, and output encoding. | Second-order injection, data poisoning, cascading microservice failures. |

---

## 3. Defense-in-Depth Architectural Patterns for APIs

```
[ Incoming API Request (Mobile/SPA/Partner) ]
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ 1. API Gateway / Ingress Controller                     │ -> TLS 1.3 Termination, Global Rate Limiting,
│                                                        │    WAF, CORS Allowlist, IP Reputation
└────────────────────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ 2. Authentication & JWT Validation Layer               │ -> Cryptographic signature verification,
│                                                        │    expiry, audience, issuer assertion
└────────────────────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ 3. Request Schema Validation (Strict DTOs)             │ -> Reject unexpected fields (no mass assignment),
│                                                        │    strict data types, regex validation
└────────────────────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ 4. Contextual Object-Level Authorization (BOLA Defense)│ -> Assert caller ownership:
│                                                        │    WHERE id = :id AND tenant_id = :tenantId
└────────────────────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ 5. Response Filtering & Selective Projection           │ -> Data Transfer Objects (DTOs) preventing
│                                                        │    excessive data exposure
└────────────────────────────────────────────────────────┘
```

### Core Architecture Directives:
1. **Contextual Object-Level Authorization (Anti-BOLA)**: Never rely on client-provided IDs alone. Query the database using compound filters that include the authenticated user's ID or organization identifier: `SELECT * FROM invoices WHERE id = :id AND user_id = :currentUserId`.
2. **Strict Separation of Entity Models and DTOs**: Never bind incoming HTTP request bodies directly to database entities (JPA, SQLAlchemy, Django ORM). Always bind to explicit, purpose-built Data Transfer Objects (DTOs) configured to strictly forbid extra properties.
3. **Defensive JWT Verification**: Reject the insecure `none` algorithm; verify signatures using asymmetric algorithms (RS256, ES256); validate standard claims (`exp`, `nbf`, `iss`, `aud`); enforce short token lifetimes (15 minutes or less).
4. **Enforce Response Projections**: Return only the specific data fields required by the client UI. Never serialize full database records containing password hashes, internal IDs, or administrative flags.
5. **Multi-Tiered Rate Limiting**: Apply rate limiting globally per IP address, per authenticated user/account, and per specific sensitive endpoint (such as password reset, OTP verification, or payment checkout).

---

## 4. Vulnerable vs. Secure Implementations in Python

### 4.1 Vulnerable Python Patterns

```python
# ==============================================================================
# VULNERABLE PYTHON PATTERNS -- DO NOT USE IN PRODUCTION
# ==============================================================================
from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

@app.route("/api/order/<int:order_id>", methods=["GET"])
def get_order_bad(order_id):
    # Flaw 1: BOLA / IDOR vulnerability - no check verifying ownership of order_id
    order = db.session.query(Order).filter_by(id=order_id).first()
    return jsonify(order.to_dict())

@app.route("/api/profile/update", methods=["POST"])
def update_profile_bad():
    # Flaw 2: Mass Assignment (API3) - raw request dict updates database model directly
    # Attacker can send {"is_admin": true, "account_balance": 999999}
    user_data = request.get_json()
    current_user = get_authenticated_user()
    for key, value in user_data.items():
        setattr(current_user, key, value)
    db.session.commit()
    return jsonify({"status": "updated"})

@app.route("/api/token/verify", methods=["POST"])
def verify_token_bad():
    raw_token = request.headers.get("Authorization", "").replace("Bearer ", "")
    # Flaw 3: Disabling signature verification allows arbitrary forged tokens
    payload = jwt.decode(raw_token, options={"verify_signature": False})
    return jsonify(payload)
```

### 4.2 Secure Enterprise Python Implementation (FastAPI / Pydantic v2)

```python
"""
Enterprise Secure API Architecture Service (Python 3.11+ / FastAPI / Pydantic v2)
Compliant with OWASP API Security Top 10 Guidelines (2026 Edition).
Demonstrates BOLA defense, mass assignment prevention, and cryptographic JWT verification.
"""

from typing import Optional, List
import os
import time
from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
import jwt
from jwt.exceptions import PyJWTError

app = FastAPI(title="SecureEnterpriseApi", version="2026.1")
security_bearer = HTTPBearer()

JWT_SECRET_KEY = os.environ.get("JWT_VERIFICATION_KEY", "prod-cryptographic-jwt-secret-min-256-bits")
JWT_ALGORITHM = "HS256"


# ------------------------------------------------------------------------------
# 1. Strict Schema Definitions (Anti-Mass Assignment / API3)
# ------------------------------------------------------------------------------
class ProfileUpdateRequest(BaseModel):
    """Explicit DTO: Only user-modifiable fields are permitted."""
    display_name: str = Field(..., min_length=2, max_length=50, pattern=r"^[a-zA-Z0-9 _\-]+$")
    contact_email: EmailStr
    bio: Optional[str] = Field(None, max_length=250)

    class Config:
        # Strictly reject any injected attributes (e.g. is_admin, role, balance)
        extra = "forbid"


class UserProfileResponse(BaseModel):
    """Projection DTO: Never exposes password hashes, internal flags, or secrets."""
    user_id: str
    display_name: str
    contact_email: str
    bio: Optional[str]


class AuthenticatedUser(BaseModel):
    user_id: str
    tenant_id: str
    roles: List[str]


# ------------------------------------------------------------------------------
# 2. Cryptographic Token Verification Dependency
# ------------------------------------------------------------------------------
def get_current_authenticated_user(
    credentials: HTTPAuthorizationCredentials = Security(security_bearer)
) -> AuthenticatedUser:
    """
    Validates incoming JWT token with strict signature verification,
    expiration check, and required claim assertions.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "require": ["sub", "tenant_id", "exp"]
            }
        )
        return AuthenticatedUser(
            user_id=payload["sub"],
            tenant_id=payload["tenant_id"],
            roles=payload.get("roles", [])
        )
    except PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ------------------------------------------------------------------------------
# 3. Secure BOLA-Protected Endpoint Implementation
# ------------------------------------------------------------------------------
@app.get("/api/v1/invoices/{invoice_id}", response_model=dict)
def get_invoice_by_id(
    invoice_id: str,
    user: AuthenticatedUser = Depends(get_current_authenticated_user)
):
    """
    Retrieves invoice with contextual authorization check (Anti-BOLA).
    Asserts both invoice_id AND tenant_id/user_id match the caller.
    """
    # Contextual query: Never query solely by invoice_id
    invoice = db_lookup_invoice(invoice_id=invoice_id, tenant_id=user.tenant_id)
    if not invoice:
        # Return generic 404 to avoid revealing the existence of other users' resources
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")

    return invoice


@app.put("/api/v1/users/me", response_model=UserProfileResponse)
def update_my_profile(
    payload: ProfileUpdateRequest,
    user: AuthenticatedUser = Depends(get_current_authenticated_user)
):
    """
    Updates profile safely using strict DTO; immune to mass assignment attacks.
    """
    # Only validated fields from ProfileUpdateRequest are updated
    updated_profile = db_update_user_profile(
        user_id=user.user_id,
        display_name=payload.display_name,
        contact_email=payload.contact_email,
        bio=payload.bio
    )
    return UserProfileResponse.model_validate(updated_profile)
```

---

## 5. Vulnerable vs. Secure Implementations in Java

### 5.1 Vulnerable Java Patterns

```java
// ==============================================================================
// VULNERABLE JAVA PATTERNS -- DO NOT USE IN PRODUCTION
// ==============================================================================
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

@RestController
@RequestMapping("/api/invoices")
public class VulnerableInvoiceController {

    @Autowired
    private InvoiceRepository invoiceRepository;

    @GetMapping("/{id}")
    public Invoice getInvoice(@PathVariable Long id) {
        // Flaw 1: Broken Object Level Authorization (BOLA)
        // Any user can enumerate /api/invoices/1, /api/invoices/2, etc.
        return invoiceRepository.findById(id).orElseThrow();
    }

    @PostMapping("/user/update")
    public void updateUser(@RequestBody UserEntity user) {
        // Flaw 2: Mass Assignment (API3)
        // Binding directly to JPA entity allows client to set isAdmin = true
        invoiceRepository.save(user);
    }
}
```

### 5.2 Secure Enterprise Java Implementation (Spring Security & Contextual Data Access)

```java
package com.enterprise.security.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Enterprise Secure REST Controller (Java 17/21+ / Spring Boot 3+)
 * Compliant with OWASP API Security Top 10 Standards (2026 Edition).
 * Demonstrates BOLA defense and explicit DTO separation.
 */
@RestController
@RequestMapping("/api/v1/invoices")
@Validated
public class SecureInvoiceController {

    private final SecureInvoiceService invoiceService;

    public SecureInvoiceController(SecureInvoiceService invoiceService) {
        this.invoiceService = invoiceService;
    }

    /**
     * DTO for Profile Update: Excludes all administrative and privileged fields.
     */
    public record ProfileUpdateDTO(
            @NotBlank @Size(min = 2, max = 50) String displayName,
            @NotBlank @Email String email
    ) {}

    /**
     * BOLA Defense: Service query requires both resource ID and caller's tenant ID.
     */
    @GetMapping("/{invoiceId}")
    @PreAuthorize("hasAuthority('SCOPE_read:invoices')")
    public ResponseEntity<InvoiceResponseDTO> getInvoiceSecurely(
            @PathVariable Long invoiceId,
            @AuthenticationPrincipal Jwt jwtPrincipal
    ) {
        String tenantId = jwtPrincipal.getClaimAsString("tenant_id");
        String userId = jwtPrincipal.getSubject();

        // Query database with compound predicate (invoiceId AND tenantId)
        InvoiceResponseDTO invoice = invoiceService.findInvoiceByIdAndTenant(invoiceId, tenantId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Invoice not found"));

        return ResponseEntity.ok(invoice);
    }

    /**
     * Mass Assignment Defense: Accepts explicit DTO, never a raw JPA entity.
     */
    @PutMapping("/profile")
    public ResponseEntity<Void> updateProfileSecurely(
            @Valid @RequestBody ProfileUpdateDTO requestDto,
            @AuthenticationPrincipal Jwt jwtPrincipal
    ) {
        String userId = jwtPrincipal.getSubject();
        invoiceService.updateUserProfile(userId, requestDto.displayName(), requestDto.email());
        return ResponseEntity.noContent().build();
    }
}
```

---

## 6. Static Code Analysis (SAST) Detection Rules

| Engine Rule ID | Language | Severity | Trigger Condition / Heuristic |
|---|---|---|---|
| `API-PY-001` | Python | High | Endpoint path parameter (e.g. `order_id`) used in DB query without user/tenant filter |
| `API-PY-002` | Python | High | Request body dictionary unpacked directly into ORM model (`Model(**request.json)`) |
| `API-PY-003` | Python | Critical | `jwt.decode()` with `verify_signature=False` or `algorithms=['none']` |
| `API-JV-001` | Java | High | `@PathVariable` query in Spring repository without ownership validation logic |
| `API-JV-002` | Java | High | Spring `@RequestBody` binding directly to `@Entity` class instead of a dedicated DTO |
| `API-JV-003` | Java | Medium | Controller lacking `@CrossOrigin` restrictions or using wildcard `origins = "*"` with credentials |

---

## 7. OWASP 2026 API Security Verification Checklist

- [ ] **Contextual BOLA Prevention**: Do all entity read/write endpoints verify caller ownership using compound database queries (`id` + `tenant_id`)?
- [ ] **Strict DTO Binding (Anti-Mass Assignment)**: Are all HTTP request bodies mapped to purpose-built DTOs with unexpected properties forbidden?
- [ ] **Defensive JWT Verification**: Are JWT signatures verified using strong algorithms (RS256/ES256), with `none` explicitly rejected, and expiration checked?
- [ ] **Selective Response Projections**: Do API responses return tailored DTOs rather than full database entities, preventing sensitive field exposure?
- [ ] **Rate Limiting & Tiered Throttling**: Are rate limits enforced at the gateway and application level for both anonymous and authenticated endpoints?
- [ ] **Restrictive CORS Policies**: Is `Access-Control-Allow-Origin: *` eliminated on endpoints supporting cookie or Authorization header credentials?
- [ ] **API Inventory & Versioning**: Are active API routes cataloged and authenticated, with deprecated zombie API versions formally retired?
- [ ] **Error Sanitization**: Are HTTP error responses standardized to avoid leaking database schemas, stack traces, or internal server details?
